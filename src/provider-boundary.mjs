import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  renderWorkloadTemplate,
  validateReleaseLock,
  validateWorkloadManifest,
} from "./contracts.mjs";

export const OPENROUTER_CHAT_COMPLETIONS_ROUTE = "/api/v1/chat/completions";
export const OPENROUTER_COST_MICROUSD_RULE =
  "exact_json_decimal_usd_ceiling_to_microusd";

const BOUNDARY_SCHEMA = "aionis_openrouter_provider_boundary_v1";
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const SHA256_RE = /^[a-f0-9]{64}$/;
const contracts = new WeakSet();
const parsedBoundaries = new WeakSet();

function fail(message) {
  throw new Error(message);
}

function object(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${field} must be an object`);
  }
  return value;
}

function exactKeys(value, keys, field) {
  object(value, field);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (!isDeepStrictEqual(actual, expected)) {
    fail(`${field} keys must be exactly ${expected.join(", ")}; got ${actual.join(", ")}`);
  }
}

function nonEmptyString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    fail(`${field} must be a non-empty trimmed string`);
  }
  return value;
}

function exactBytes(value, field) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    fail(`${field} must be exact bytes`);
  }
  const bytes = Buffer.from(value);
  if (bytes.length === 0 || bytes.length > MAX_JSON_BYTES) {
    fail(`${field} byte length is invalid`);
  }
  return bytes;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function pointerSegment(value) {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

// JSON.parse silently accepts duplicate object keys and discards the earlier
// value. Provider evidence cannot tolerate that ambiguity, so the boundary uses
// this small strict parser and retains the exact source lexeme for every number.
class StrictJsonParser {
  constructor(source, field) {
    this.source = source;
    this.field = field;
    this.index = 0;
    this.numberLexemes = new Map();
  }

  parse() {
    this.whitespace();
    const value = this.value("", 0);
    this.whitespace();
    if (this.index !== this.source.length) this.error("contains trailing data");
    return { value, number_lexemes: this.numberLexemes };
  }

  error(message) {
    fail(`${this.field} ${message} at character ${this.index}`);
  }

  whitespace() {
    while (/\s/u.test(this.source[this.index] ?? "") && /[\u0009\u000a\u000d\u0020]/u.test(this.source[this.index])) {
      this.index += 1;
    }
  }

  value(path, depth) {
    if (depth > 128) this.error("exceeds the maximum JSON nesting depth");
    const token = this.source[this.index];
    if (token === "{") return this.object(path, depth + 1);
    if (token === "[") return this.array(path, depth + 1);
    if (token === '"') return this.string();
    if (token === "t" && this.literal("true")) return true;
    if (token === "f" && this.literal("false")) return false;
    if (token === "n" && this.literal("null")) return null;
    if (token === "-" || (token >= "0" && token <= "9")) return this.number(path);
    this.error("is not valid JSON");
  }

  literal(expected) {
    if (this.source.slice(this.index, this.index + expected.length) !== expected) return false;
    this.index += expected.length;
    return true;
  }

  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (code < 0x20) this.error("contains an unescaped control character");
      const token = this.source[this.index];
      if (token === '"') {
        this.index += 1;
        try {
          return JSON.parse(this.source.slice(start, this.index));
        } catch (error) {
          this.error(`contains an invalid JSON string (${error.message})`);
        }
      }
      if (token === "\\") {
        this.index += 1;
        const escape = this.source[this.index];
        if (escape === "u") {
          const digits = this.source.slice(this.index + 1, this.index + 5);
          if (!/^[a-fA-F0-9]{4}$/.test(digits)) this.error("contains an invalid Unicode escape");
          this.index += 5;
          continue;
        }
        if (!/["\\/bfnrt]/.test(escape ?? "")) this.error("contains an invalid escape");
        this.index += 1;
        continue;
      }
      this.index += 1;
    }
    this.error("contains an unterminated string");
  }

  number(path) {
    const remainder = this.source.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(remainder);
    if (!match) this.error("contains an invalid number");
    const lexeme = match[0];
    this.index += lexeme.length;
    const next = this.source[this.index];
    if (next !== undefined && !/[\u0009\u000a\u000d\u0020,}\]]/.test(next)) {
      this.error("contains an invalid number terminator");
    }
    const value = Number(lexeme);
    if (!Number.isFinite(value)) this.error("contains a non-finite number");
    this.numberLexemes.set(path, lexeme);
    return value;
  }

  object(path, depth) {
    const value = {};
    const keys = new Set();
    this.index += 1;
    this.whitespace();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return value;
    }
    while (true) {
      if (this.source[this.index] !== '"') this.error("contains a non-string object key");
      const key = this.string();
      if (keys.has(key)) this.error(`contains duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.whitespace();
      if (this.source[this.index] !== ":") this.error("is missing an object colon");
      this.index += 1;
      this.whitespace();
      const childPath = `${path}/${pointerSegment(key)}`;
      const child = this.value(childPath, depth);
      Object.defineProperty(value, key, {
        value: child,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.whitespace();
      const separator = this.source[this.index];
      if (separator === "}") {
        this.index += 1;
        return value;
      }
      if (separator !== ",") this.error("is missing an object separator");
      this.index += 1;
      this.whitespace();
    }
  }

  array(path, depth) {
    const value = [];
    this.index += 1;
    this.whitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return value;
    }
    let item = 0;
    while (true) {
      value.push(this.value(`${path}/${item}`, depth));
      item += 1;
      this.whitespace();
      const separator = this.source[this.index];
      if (separator === "]") {
        this.index += 1;
        return value;
      }
      if (separator !== ",") this.error("is missing an array separator");
      this.index += 1;
      this.whitespace();
    }
  }
}

function parseExactJsonBytes(value, field) {
  const bytes = exactBytes(value, field);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail(`${field} must not contain a UTF-8 BOM`);
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch (error) {
    fail(`${field} is not valid UTF-8: ${error.message}`);
  }
  const parsed = new StrictJsonParser(source, field).parse();
  return { ...parsed, bytes, sha256: sha256(bytes) };
}

function assertUnicodeScalarString(value, field) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail(`${field} contains an unpaired UTF-16 surrogate`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`${field} contains an unpaired UTF-16 surrogate`);
    }
  }
}

function canonicalJson(value, field = "provider request") {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    assertUnicodeScalarString(value, field);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail(`${field} contains a non-finite number`);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry, index) => canonicalJson(entry, `${field}[${index}]`)).join(",")}]`;
  }
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(`${field} contains a non-JSON value`);
  }
  const keys = Object.keys(value).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return `{${keys.map((key) => {
    assertUnicodeScalarString(key, `${field} key`);
    return `${JSON.stringify(key)}:${canonicalJson(value[key], `${field}.${key}`)}`;
  }).join(",")}}`;
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function bindingHash(bindings, key) {
  object(bindings, "ledger frozen bindings");
  const value = bindings[key];
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    fail(`ledger frozen bindings.${key} must be a lowercase SHA-256`);
  }
  return value;
}

function documentHash(value, field) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    fail(`${field} must be a lowercase SHA-256`);
  }
  return value;
}

function decodeExactBase64(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    fail(`${field} must be canonical padded base64`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) fail(`${field} must be canonical padded base64`);
  return bytes;
}

function validateProviderRouteContract(lock, workload) {
  const provider = workload.execution_templates.provider_request;
  if (provider.method !== "POST" || provider.route !== OPENROUTER_CHAT_COMPLETIONS_ROUTE) {
    fail("provider execution route is not the frozen OpenRouter chat-completions route");
  }
  if (Object.hasOwn(provider.request_template.provider, "order")
    || Object.hasOwn(provider.request_template.provider, "only")) {
    fail("provider.order and provider.only require newly frozen authority");
  }
  if (lock.providers.agent.provider !== "openrouter") {
    fail("provider execution contract must freeze OpenRouter");
  }
}

export function hydrateProviderExecutionContract(value, frozenBindings) {
  exactKeys(value, [
    "schema_version",
    "release_lock_sha256",
    "workload_manifest_sha256",
    "release_lock_source_base64",
    "workload_manifest_source_base64",
    "release_lock",
    "workload",
  ], "serialized provider execution contract");
  if (value.schema_version !== "aionis_provider_execution_contract_v1") {
    fail("serialized provider execution contract schema_version is invalid");
  }
  const releaseLockBytes = decodeExactBase64(
    value.release_lock_source_base64,
    "serialized provider execution contract.release_lock_source_base64",
  );
  const workloadBytes = decodeExactBase64(
    value.workload_manifest_source_base64,
    "serialized provider execution contract.workload_manifest_source_base64",
  );
  const lockDocument = parseExactJsonBytes(releaseLockBytes, "serialized provider execution contract release lock source");
  const workloadDocument = parseExactJsonBytes(workloadBytes, "serialized provider execution contract workload source");
  if (lockDocument.sha256 !== documentHash(
    value.release_lock_sha256,
    "serialized provider execution contract.release_lock_sha256",
  )) fail("serialized provider execution contract release lock source hash drifted");
  if (workloadDocument.sha256 !== documentHash(
    value.workload_manifest_sha256,
    "serialized provider execution contract.workload_manifest_sha256",
  )) fail("serialized provider execution contract workload source hash drifted");
  if (lockDocument.sha256 !== bindingHash(frozenBindings, "release_lock_sha256")) {
    fail("release lock source does not match the ledger-owned frozen binding");
  }
  if (workloadDocument.sha256 !== bindingHash(frozenBindings, "workload_manifest_sha256")) {
    fail("workload manifest source does not match the ledger-owned frozen binding");
  }
  if (!isDeepStrictEqual(lockDocument.value, value.release_lock)) {
    fail("serialized provider execution contract release lock object drifted from its exact source bytes");
  }
  if (!isDeepStrictEqual(workloadDocument.value, value.workload)) {
    fail("serialized provider execution contract workload object drifted from its exact source bytes");
  }
  const lock = validateReleaseLock(lockDocument.value);
  const workload = validateWorkloadManifest(workloadDocument.value, lock);
  if (workloadDocument.sha256 !== lock.protocol_artifacts.workload_manifest.sha256) {
    fail("workload manifest source does not match the release-lock binding");
  }
  validateProviderRouteContract(lock, workload);
  const contract = {
    schema_version: "aionis_provider_execution_contract_v1",
    release_lock_sha256: lockDocument.sha256,
    workload_manifest_sha256: workloadDocument.sha256,
    release_lock_source_base64: releaseLockBytes.toString("base64"),
    workload_manifest_source_base64: workloadBytes.toString("base64"),
    release_lock: structuredClone(lock),
    workload: structuredClone(workload),
  };
  deepFreeze(contract);
  contracts.add(contract);
  return contract;
}

export function createProviderExecutionContract({
  releaseLockSource,
  workloadSource,
  frozenBindings,
}) {
  const lockDocument = parseExactJsonBytes(releaseLockSource, "release lock source");
  const workloadDocument = parseExactJsonBytes(workloadSource, "workload manifest source");
  return hydrateProviderExecutionContract({
    schema_version: "aionis_provider_execution_contract_v1",
    release_lock_sha256: lockDocument.sha256,
    workload_manifest_sha256: workloadDocument.sha256,
    release_lock_source_base64: lockDocument.bytes.toString("base64"),
    workload_manifest_source_base64: workloadDocument.bytes.toString("base64"),
    release_lock: lockDocument.value,
    workload: workloadDocument.value,
  }, frozenBindings);
}

function executionContract(value) {
  if (!contracts.has(value)) fail("provider execution contract must come from createProviderExecutionContract");
  return value;
}

function trialIdentity(trial, workload) {
  object(trial, "ledger trial");
  const trialId = nonEmptyString(trial.trial_id, "ledger trial.trial_id");
  const group = nonEmptyString(trial.group, "ledger trial.group");
  const scenarioId = nonEmptyString(trial.scenario, "ledger trial.scenario");
  if (!workload.groups.includes(group)) fail("ledger trial.group is outside the frozen workload");
  if (!workload.scenarios.includes(scenarioId)) fail("ledger trial.scenario is outside the frozen workload");
  const match = /^(pilot|soak):w([1-9][0-9]*):([^:]+):([^:]+):r([1-9][0-9]*)$/.exec(trialId);
  if (!match || match[3] !== group || match[4] !== scenarioId) {
    fail("ledger trial identity does not match its frozen group and scenario");
  }
  const phase = match[1];
  const wave = Number(match[2]);
  const repetition = Number(match[5]);
  if (phase === "pilot") {
    if (wave !== 1 || repetition > workload.pilot.repetitions_per_cell) {
      fail("ledger pilot trial identity is outside the frozen workload");
    }
  } else if (wave > workload.soak.waves || repetition > workload.soak.repetitions_per_cell_per_wave) {
    fail("ledger soak trial identity is outside the frozen workload");
  }
  const preclaim = object(trial.preclaim, "ledger trial.preclaim");
  nonEmptyString(preclaim.guide_operation_id, "ledger trial.preclaim.guide_operation_id");
  return { trialId, group, scenarioId, preclaim };
}

function providerRenderContext(contract, ledgerContext) {
  exactKeys(ledgerContext, ["trial", "guide_response"], "ledger provider render context");
  const { workload } = contract;
  const identity = trialIdentity(ledgerContext.trial, workload);
  const scenario = workload.scenario_definitions.find((entry) => entry.id === identity.scenarioId);
  let guideResponse;
  if (identity.group === "aionis") {
    guideResponse = object(ledgerContext.guide_response, "ledger provider render context.guide_response");
    if (guideResponse.operation_id !== identity.preclaim.guide_operation_id) {
      fail("Aionis guide response does not echo the ledger-owned guide operation ID");
    }
    const agentContext = object(guideResponse.agent_context, "Aionis guide response.agent_context");
    nonEmptyString(agentContext.prompt_text, "Aionis guide response.agent_context.prompt_text");
    if (Object.hasOwn(agentContext, "agent_prompt")) {
      fail("Aionis guide response.agent_context.agent_prompt must remain absent");
    }
  } else {
    if (ledgerContext.guide_response !== null) {
      fail(`${identity.group} provider rendering must not accept an Aionis guide response`);
    }
    guideResponse = undefined;
  }
  return {
    identity,
    renderer: {
      group: identity.group,
      guide_response: guideResponse,
      release_lock: contract.release_lock,
      scenario,
      tool_protocol: workload.tool_protocol,
    },
    scenario,
  };
}

function requestBody(contract, ledgerContext) {
  const provider = contract.workload.execution_templates.provider_request;
  const context = providerRenderContext(contract, ledgerContext);
  const body = renderWorkloadTemplate(provider.request_template, context.renderer);
  exactKeys(body, provider.request_exact_keys, "rendered provider request");
  exactKeys(body.provider, ["allow_fallbacks", "require_parameters"], "rendered provider request.provider");
  if (Object.hasOwn(body.provider, "order") || Object.hasOwn(body.provider, "only")) {
    fail("provider.order and provider.only require newly frozen authority");
  }
  if (body.model !== contract.release_lock.providers.agent.requested_model) {
    fail("rendered provider request model drifted from the frozen release lock");
  }
  return { body, ...context };
}

export function createCanonicalProviderRequest({ contract: inputContract, ledgerContext }) {
  const contract = executionContract(inputContract);
  const rendered = requestBody(contract, ledgerContext);
  const bytes = Buffer.from(canonicalJson(rendered.body), "utf8");
  return {
    method: "POST",
    route: OPENROUTER_CHAT_COMPLETIONS_ROUTE,
    content_type: "application/json",
    trial_id: rendered.identity.trialId,
    body: structuredClone(rendered.body),
    bytes,
    sha256: sha256(bytes),
  };
}

export function assertCanonicalProviderRequest({ contract: inputContract, ledgerContext, requestBytes }) {
  const contract = executionContract(inputContract);
  const observed = parseExactJsonBytes(requestBytes, "provider request bytes");
  const observedBody = object(observed.value, "provider request body");
  const observedProvider = object(observedBody.provider, "provider request body.provider");
  if (Object.hasOwn(observedProvider, "order") || Object.hasOwn(observedProvider, "only")) {
    fail("provider.order and provider.only require newly frozen authority");
  }
  const expected = createCanonicalProviderRequest({ contract, ledgerContext });
  if (!isDeepStrictEqual(observedBody, expected.body)) {
    fail("provider request body drifted from the frozen execution contract and ledger context");
  }
  if (!observed.bytes.equals(expected.bytes)) {
    fail("provider request bytes are not the exact canonical compact UTF-8 body");
  }
  return expected;
}

function exactDecimalMicrousd(lexeme) {
  const match = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(lexeme);
  if (!match) fail("OpenRouter usage.cost must be a JSON decimal number");
  if (match[1] === "-") fail("OpenRouter usage.cost must be non-negative");
  const digits = `${match[2]}${match[3] ?? ""}`.replace(/^0+(?=[0-9])/, "");
  if (/^0+$/.test(digits)) return 0;
  const exponent = Number(match[4] ?? "0");
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 1_000) {
    fail("OpenRouter usage.cost exponent is outside the exact conversion bound");
  }
  const shift = exponent - (match[3]?.length ?? 0) + 6;
  const coefficient = BigInt(digits);
  let microusd;
  if (shift >= 0) {
    if (shift > 1_000) fail("OpenRouter usage.cost is outside the exact conversion bound");
    microusd = coefficient * (10n ** BigInt(shift));
  } else {
    // The coefficient is known non-zero. Values smaller than 10^-1000 still
    // consume budget, and the frozen rule therefore ceilings them to 1 µUSD.
    if (shift < -1_000) return 1;
    const divisor = 10n ** BigInt(-shift);
    const quotient = coefficient / divisor;
    const remainder = coefficient % divisor;
    microusd = quotient + (remainder > 0n ? 1n : 0n);
  }
  if (microusd > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail("OpenRouter usage.cost exceeds the safe microusd range");
  }
  return Number(microusd);
}

export function openRouterCostToMicrousd(rawJsonNumber) {
  if (typeof rawJsonNumber !== "string" || rawJsonNumber.length === 0) {
    fail("OpenRouter usage.cost conversion requires its exact JSON number lexeme");
  }
  return exactDecimalMicrousd(rawJsonNumber);
}

function positiveUsageInteger(value, lexeme, field) {
  if (!/^(?:0|[1-9][0-9]*)$/.test(lexeme ?? "") || !Number.isSafeInteger(value) || value < 1) {
    fail(`${field} must be a positive JSON integer`);
  }
  return value;
}

function providerUsage(response, numberLexemes, maximumCostUsd) {
  const usage = object(response.usage, "OpenRouter response.usage");
  const inputTokens = positiveUsageInteger(
    usage.prompt_tokens,
    numberLexemes.get("/usage/prompt_tokens"),
    "OpenRouter response.usage.prompt_tokens",
  );
  const outputTokens = positiveUsageInteger(
    usage.completion_tokens,
    numberLexemes.get("/usage/completion_tokens"),
    "OpenRouter response.usage.completion_tokens",
  );
  const totalTokens = positiveUsageInteger(
    usage.total_tokens,
    numberLexemes.get("/usage/total_tokens"),
    "OpenRouter response.usage.total_tokens",
  );
  if (totalTokens !== inputTokens + outputTokens) {
    fail("OpenRouter response.usage.total_tokens must equal prompt_tokens + completion_tokens");
  }
  if (typeof usage.cost !== "number" || !Number.isFinite(usage.cost)) {
    fail("OpenRouter response.usage.cost must be a finite JSON number");
  }
  const costMicrousd = openRouterCostToMicrousd(numberLexemes.get("/usage/cost"));
  const maximumMicrousd = maximumCostUsd * 1_000_000;
  if (!Number.isSafeInteger(maximumMicrousd) || costMicrousd > maximumMicrousd) {
    fail("OpenRouter response.usage.cost exceeds the frozen whole-campaign ceiling");
  }
  return {
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: totalTokens,
    cost_microusd: costMicrousd,
  };
}

function toolResult(contract, scenario, toolCall) {
  object(toolCall, "OpenRouter response native tool call");
  nonEmptyString(toolCall.id, "OpenRouter response native tool call.id");
  if (toolCall.type !== "function") fail("OpenRouter response tool call must be a native function call");
  const fn = object(toolCall.function, "OpenRouter response native tool call.function");
  if (fn.name !== contract.workload.tool_protocol.function.name) {
    fail("OpenRouter response native tool call name does not match the frozen tool");
  }
  if (typeof fn.arguments !== "string" || fn.arguments.length === 0) {
    fail("OpenRouter response native tool arguments must be a non-empty JSON string");
  }
  let parsed;
  try {
    parsed = new StrictJsonParser(fn.arguments, "OpenRouter response native tool arguments").parse().value;
  } catch (error) {
    throw error;
  }
  exactKeys(parsed, ["scenario_id", "choice"], "OpenRouter response native tool arguments");
  const schema = contract.workload.tool_protocol.function.arguments_schema;
  if (!schema.properties.scenario_id.enum.includes(parsed.scenario_id)) {
    fail("OpenRouter response native tool scenario is outside the frozen schema");
  }
  if (parsed.scenario_id !== scenario.id) {
    fail("OpenRouter response native tool scenario does not match the ledger trial");
  }
  if (!schema.properties.choice.enum.includes(parsed.choice)
    || !scenario.allowed_choices.includes(parsed.choice)) {
    fail("OpenRouter response native tool choice is not allowed for the ledger scenario");
  }
  return {
    tool_call_id: toolCall.id,
    result: {
      schema_version: contract.workload.tool_protocol.result_contract.schema_version,
      scenario_id: scenario.id,
      choice: parsed.choice,
      expected_choice: scenario.expected_choice,
      passed: parsed.choice === scenario.expected_choice,
      unsafe_direct_use: parsed.choice === scenario.unsafe_choice,
    },
  };
}

export function parseOpenRouterChatCompletion({
  contract: inputContract,
  ledgerContext,
  requestBytes,
  httpStatus,
  responseBytes,
}) {
  const contract = executionContract(inputContract);
  const request = assertCanonicalProviderRequest({ contract, ledgerContext, requestBytes });
  if (httpStatus !== 200) fail("OpenRouter chat completion HTTP status must be exactly 200");
  const responseDocument = parseExactJsonBytes(responseBytes, "OpenRouter exact raw response bytes");
  const response = object(responseDocument.value, "OpenRouter response");
  const providerRequestId = nonEmptyString(response.id, "OpenRouter response.id");
  const returnedModel = nonEmptyString(response.model, "OpenRouter response.model");
  const allowedModels = contract.release_lock.providers.agent.allowed_returned_models;
  if (!allowedModels.includes(returnedModel)) {
    fail("OpenRouter response.model is outside the frozen returned-model allowlist");
  }
  if (!Array.isArray(response.choices) || response.choices.length !== 1) {
    fail("OpenRouter response must contain exactly one choice");
  }
  const choice = object(response.choices[0], "OpenRouter response.choices[0]");
  const message = object(choice.message, "OpenRouter response.choices[0].message");
  if (message.content !== null && message.content !== "") {
    fail("OpenRouter response message.content must be null or exactly empty; prose is forbidden");
  }
  if (Object.hasOwn(message, "function_call") && message.function_call !== null) {
    fail("OpenRouter response legacy function_call is forbidden");
  }
  if (!Array.isArray(message.tool_calls) || message.tool_calls.length !== 1) {
    fail("OpenRouter response must contain exactly one native function tool call");
  }
  const rendered = providerRenderContext(contract, ledgerContext);
  const derivedTool = toolResult(contract, rendered.scenario, message.tool_calls[0]);
  const usage = providerUsage(
    response,
    responseDocument.number_lexemes,
    contract.release_lock.execution_limits.maximum_cost_usd,
  );
  const boundary = deepFreeze({
    schema_version: BOUNDARY_SCHEMA,
    response_contract: "openrouter_nonstreaming_chat_completion_native_tool_v1",
    route: OPENROUTER_CHAT_COMPLETIONS_ROUTE,
    http_status: 200,
    trial_id: rendered.identity.trialId,
    request_sha256: request.sha256,
    response_sha256: responseDocument.sha256,
    provider_request_id: providerRequestId,
    requested_model: contract.release_lock.providers.agent.requested_model,
    returned_model: returnedModel,
    fallback_used: false,
    tool_call_id: derivedTool.tool_call_id,
    tool_result: derivedTool.result,
    provider_usage: usage,
    cost_microusd_rule: OPENROUTER_COST_MICROUSD_RULE,
  });
  parsedBoundaries.add(boundary);
  return boundary;
}

export function assertParsedOpenRouterBoundary(value) {
  if (!parsedBoundaries.has(value)) {
    fail("provider boundary must come directly from parseOpenRouterChatCompletion");
  }
  return value;
}
