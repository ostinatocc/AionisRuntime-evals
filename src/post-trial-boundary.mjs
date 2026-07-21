import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  captureWorkloadRawResponseIdentity,
  renderWorkloadTemplate,
  selectWorkloadServedMemory,
} from "./contracts.mjs";
import {
  assertParsedOpenRouterBoundary,
  createCanonicalProviderRequest,
} from "./provider-boundary.mjs";

export const POST_TRIAL_ROUTE_ORDER = Object.freeze([
  "/v1/observe",
  "/v1/feedback",
  "/v1/measure",
  "/v1/operator/snapshot",
  "/v1/audit/flight-recorder",
]);

export const POST_TRIAL_STAGES = Object.freeze([
  "outcome_observe",
  "feedback",
  "measure",
  "measure_replay",
  "operator_snapshot",
  "flight_recorder",
]);

const EXECUTION_SCHEMA = "aionis_post_trial_execution_v1";
const CHECKPOINT_SCHEMA = "aionis_post_trial_response_checkpoint_v1";
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const SHA256_RE = /^[a-f0-9]{64}$/;
const LEARNING_ATTRIBUTION_STATUSES = new Set([
  "not_attributed",
  "legacy_unverified",
  "verified_host_receipt",
]);
const executionRecords = new WeakMap();
const checkpointRecords = new WeakMap();

const STAGE_TEMPLATE = Object.freeze({
  outcome_observe: "outcome_observe",
  feedback: "feedback",
  measure: "measure",
  measure_replay: "measure",
  operator_snapshot: "operator_snapshot",
  flight_recorder: "flight_recorder",
});

const REQUIRED_PRIOR_STAGES = Object.freeze({
  outcome_observe: Object.freeze([]),
  feedback: Object.freeze(["outcome_observe"]),
  measure: Object.freeze(["outcome_observe", "feedback"]),
  measure_replay: Object.freeze(["outcome_observe", "feedback", "measure"]),
  operator_snapshot: Object.freeze(["outcome_observe", "feedback", "measure"]),
  flight_recorder: Object.freeze(["outcome_observe", "feedback", "measure", "operator_snapshot"]),
});

const ALLOWED_PRIOR_STAGES = Object.freeze({
  outcome_observe: new Set(),
  feedback: new Set(["outcome_observe"]),
  measure: new Set(["outcome_observe", "feedback"]),
  measure_replay: new Set(["outcome_observe", "feedback", "measure"]),
  operator_snapshot: new Set(["outcome_observe", "feedback", "measure", "measure_replay"]),
  flight_recorder: new Set([
    "outcome_observe",
    "feedback",
    "measure",
    "measure_replay",
    "operator_snapshot",
  ]),
});

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

function sha256Hex(value, field) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    fail(`${field} must be a lowercase SHA-256`);
  }
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
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

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function assertUnicodeScalarString(value, field) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail(`${field} contains an unpaired UTF-16 surrogate`);
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`${field} contains an unpaired UTF-16 surrogate`);
    }
  }
}

function canonicalJson(value, field = "post-trial request") {
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

function pointerSegment(value) {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

// Runtime evidence is parsed from exact bytes. JSON.parse alone is unsuitable
// because it silently accepts duplicate keys and keeps only the last value.
class StrictJsonParser {
  constructor(source, field) {
    this.source = source;
    this.field = field;
    this.index = 0;
  }

  parse() {
    this.whitespace();
    const value = this.value("", 0);
    this.whitespace();
    if (this.index !== this.source.length) this.error("contains trailing data");
    return value;
  }

  error(message) {
    fail(`${this.field} ${message} at character ${this.index}`);
  }

  whitespace() {
    while (/\s/u.test(this.source[this.index] ?? "")
      && /[\u0009\u000a\u000d\u0020]/u.test(this.source[this.index])) {
      this.index += 1;
    }
  }

  value(path, depth) {
    if (depth > 128) this.error("exceeds the maximum JSON nesting depth");
    const token = this.source[this.index];
    if (token === "{") return this.object(path, depth + 1);
    if (token === "[") return this.array(path, depth + 1);
    if (token === "\"") return this.string();
    if (token === "t" && this.literal("true")) return true;
    if (token === "f" && this.literal("false")) return false;
    if (token === "n" && this.literal("null")) return null;
    if (token === "-" || (token >= "0" && token <= "9")) return this.number();
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
      if (token === "\"") {
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

  number() {
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
      if (this.source[this.index] !== "\"") this.error("contains a non-string object key");
      const key = this.string();
      if (keys.has(key)) this.error(`contains duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.whitespace();
      if (this.source[this.index] !== ":") this.error("is missing an object colon");
      this.index += 1;
      this.whitespace();
      const child = this.value(`${path}/${pointerSegment(key)}`, depth);
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
  // The digest is deliberately captured before UTF-8 decoding and JSON parse.
  const responseSha256 = sha256(bytes);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail(`${field} must not contain a UTF-8 BOM`);
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch (error) {
    fail(`${field} is not valid UTF-8: ${error.message}`);
  }
  return {
    bytes,
    sha256: responseSha256,
    value: new StrictJsonParser(source, field).parse(),
  };
}

function stageName(value) {
  if (typeof value !== "string" || !POST_TRIAL_STAGES.includes(value)) {
    fail(`post-trial stage must be one of ${POST_TRIAL_STAGES.join(", ")}`);
  }
  return value;
}

function executionRecord(value) {
  const record = executionRecords.get(value);
  if (!record) fail("post-trial execution must come from createPostTrialExecution");
  return record;
}

function checkpointRecord(value, execution, field) {
  const record = checkpointRecords.get(value);
  if (!record) fail(`${field} must be a module-issued post-trial response checkpoint`);
  if (record.execution !== execution) fail(`${field} belongs to another post-trial execution`);
  return record;
}

function validateProviderBoundary(contract, ledgerContext, providerBoundary) {
  const canonicalProviderRequest = createCanonicalProviderRequest({ contract, ledgerContext });
  assertParsedOpenRouterBoundary(providerBoundary);
  const boundary = object(providerBoundary, "parsed provider boundary");
  exactKeys(boundary, [
    "schema_version",
    "response_contract",
    "route",
    "http_status",
    "trial_id",
    "request_sha256",
    "response_sha256",
    "provider_request_id",
    "requested_model",
    "returned_model",
    "fallback_used",
    "tool_call_id",
    "tool_result",
    "provider_usage",
    "cost_microusd_rule",
  ], "parsed provider boundary");
  if (boundary.schema_version !== "aionis_openrouter_provider_boundary_v1"
    || boundary.response_contract !== "openrouter_nonstreaming_chat_completion_native_tool_v1"
    || boundary.route !== "/api/v1/chat/completions"
    || boundary.http_status !== 200) {
    fail("parsed provider boundary contract identity is invalid");
  }
  if (boundary.trial_id !== ledgerContext.trial.trial_id) {
    fail("parsed provider boundary trial does not match the ledger trial");
  }
  if (boundary.request_sha256 !== canonicalProviderRequest.sha256) {
    fail("parsed provider boundary request does not match the frozen canonical request");
  }
  sha256Hex(boundary.response_sha256, "parsed provider boundary.response_sha256");
  nonEmptyString(boundary.provider_request_id, "parsed provider boundary.provider_request_id");
  nonEmptyString(boundary.tool_call_id, "parsed provider boundary.tool_call_id");
  if (boundary.requested_model !== contract.release_lock.providers.agent.requested_model
    || !contract.release_lock.providers.agent.allowed_returned_models.includes(boundary.returned_model)
    || boundary.fallback_used !== false) {
    fail("parsed provider boundary model authority is invalid");
  }

  const scenario = contract.workload.scenario_definitions
    .find((entry) => entry.id === ledgerContext.trial.scenario);
  if (!scenario) fail("ledger trial scenario is missing from the frozen workload");
  const toolResult = object(boundary.tool_result, "parsed provider boundary.tool_result");
  exactKeys(toolResult, [
    "schema_version",
    "scenario_id",
    "choice",
    "expected_choice",
    "passed",
    "unsafe_direct_use",
  ], "parsed provider boundary.tool_result");
  const expectedToolResult = {
    schema_version: contract.workload.tool_protocol.result_contract.schema_version,
    scenario_id: scenario.id,
    choice: toolResult.choice,
    expected_choice: scenario.expected_choice,
    passed: toolResult.choice === scenario.expected_choice,
    unsafe_direct_use: toolResult.choice === scenario.unsafe_choice,
  };
  if (!scenario.allowed_choices.includes(toolResult.choice)
    || !isDeepStrictEqual(toolResult, expectedToolResult)) {
    fail("parsed provider boundary tool result is not derivable from the frozen scenario");
  }
  const usage = object(boundary.provider_usage, "parsed provider boundary.provider_usage");
  exactKeys(usage, [
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cost_microusd",
  ], "parsed provider boundary.provider_usage");
  for (const key of ["input_tokens", "output_tokens", "total_tokens"]) {
    if (!Number.isSafeInteger(usage[key]) || usage[key] < 1) {
      fail(`parsed provider boundary.provider_usage.${key} must be a positive safe integer`);
    }
  }
  if (usage.total_tokens !== usage.input_tokens + usage.output_tokens
    || !Number.isSafeInteger(usage.cost_microusd)
    || usage.cost_microusd < 0) {
    fail("parsed provider boundary usage is invalid");
  }
  return { boundary, scenario };
}

export function createPostTrialExecution({ contract, ledgerContext, providerBoundary }) {
  object(ledgerContext, "post-trial ledger context");
  const trial = object(ledgerContext.trial, "post-trial ledger trial");
  if (trial.group !== "aionis") fail("post-trial Runtime execution is defined only for Aionis trials");
  const guideResponse = object(ledgerContext.guide_response, "post-trial guide response");
  const preclaim = object(trial.preclaim, "post-trial ledger trial.preclaim");
  const provider = validateProviderBoundary(contract, ledgerContext, providerBoundary);
  const trialId = nonEmptyString(trial.trial_id, "post-trial ledger trial.trial_id");
  const tenantId = nonEmptyString(preclaim.tenant_id, "post-trial ledger trial.preclaim.tenant_id");
  const scope = nonEmptyString(preclaim.scope, "post-trial ledger trial.preclaim.scope");
  if (tenantId !== contract.workload.schedule.scope.tenant_id) {
    fail("post-trial tenant does not match the frozen workload schedule");
  }
  for (const key of [
    "guide_operation_id",
    "outcome_operation_id",
    "feedback_operation_id",
    "measure_operation_id",
  ]) nonEmptyString(preclaim[key], `post-trial ledger trial.preclaim.${key}`);
  if (guideResponse.operation_id !== preclaim.guide_operation_id) {
    fail("post-trial guide response does not echo the ledger-owned guide operation ID");
  }
  const guideTraceId = nonEmptyString(guideResponse.guide_trace_id, "post-trial guide response.guide_trace_id");
  object(guideResponse.agent_context, "post-trial guide response.agent_context");
  object(guideResponse.guide_packet, "post-trial guide response.guide_packet");
  const servedMemorySelection = selectWorkloadServedMemory(
    guideResponse,
    contract.workload.execution_templates.post_trial_runtime_contract.feedback.served_memory_selection,
  );
  if (!isDeepStrictEqual(
    contract.workload.execution_templates.post_trial_runtime_contract.route_order,
    POST_TRIAL_ROUTE_ORDER,
  )) fail("frozen post-trial route order is not supported by this boundary");

  const execution = deepFreeze({
    schema_version: EXECUTION_SCHEMA,
    trial_id: trialId,
    tenant_id: tenantId,
    scope,
    guide_operation_id: preclaim.guide_operation_id,
    guide_trace_id: guideTraceId,
    provider_request_id: provider.boundary.provider_request_id,
    provider_request_sha256: provider.boundary.request_sha256,
    provider_response_sha256: provider.boundary.response_sha256,
    tool_result: structuredClone(provider.boundary.tool_result),
    served_memory_selection: structuredClone(servedMemorySelection),
    route_order: [...POST_TRIAL_ROUTE_ORDER],
  });
  executionRecords.set(execution, {
    contract,
    ledgerContext: structuredClone(ledgerContext),
    trial: structuredClone(trial),
    preclaim: structuredClone(preclaim),
    scenario: structuredClone(provider.scenario),
    guideResponse: structuredClone(guideResponse),
    providerBoundary: structuredClone(provider.boundary),
    servedMemorySelection: structuredClone(servedMemorySelection),
  });
  return execution;
}

function priorCheckpointMap(execution, priorResponses, targetStage) {
  if (!Array.isArray(priorResponses)) fail("post-trial priorResponses must be an array");
  const values = new Map();
  for (const [index, checkpoint] of priorResponses.entries()) {
    const record = checkpointRecord(checkpoint, execution, `post-trial priorResponses[${index}]`);
    if (!ALLOWED_PRIOR_STAGES[targetStage].has(record.stage)) {
      fail(`post-trial ${targetStage} request cannot consume a ${record.stage} checkpoint`);
    }
    if (values.has(record.stage)) fail(`post-trial priorResponses contains duplicate ${record.stage} checkpoints`);
    values.set(record.stage, record);
  }
  for (const required of REQUIRED_PRIOR_STAGES[targetStage]) {
    if (!values.has(required)) fail(`post-trial ${targetStage} request requires the ${required} checkpoint`);
  }
  return values;
}

function renderContext(record, prior) {
  const feedback = prior.get("feedback");
  const measure = prior.get("measure");
  const snapshot = prior.get("operator_snapshot");
  return {
    preclaim: record.preclaim,
    schedule: record.contract.workload.schedule,
    trial_id: record.trial.trial_id,
    scenario: record.scenario,
    guide_response: record.guideResponse,
    provider_response: { id: record.providerBoundary.provider_request_id },
    tool_result: record.providerBoundary.tool_result,
    served_memory_selection: record.servedMemorySelection,
    ...(feedback ? { feedback_response: feedback.responseBody } : {}),
    ...(measure ? { measure_request: measure.requestBody } : {}),
    ...(snapshot ? { operator_snapshot_response: snapshot.responseBody } : {}),
  };
}

export function createCanonicalPostTrialRequest({ execution, stage: inputStage, priorResponses = [] }) {
  const record = executionRecord(execution);
  const stage = stageName(inputStage);
  const prior = priorCheckpointMap(execution, priorResponses, stage);
  const postTrial = record.contract.workload.execution_templates.post_trial_runtime_contract;
  const template = postTrial[STAGE_TEMPLATE[stage]];
  const body = renderWorkloadTemplate(template.request_template, renderContext(record, prior));
  exactKeys(body, template.request_exact_keys, `rendered ${stage} request`);
  if (template.method !== "POST") fail(`frozen ${stage} request method must be POST`);
  const expectedRoute = stage === "measure_replay"
    ? POST_TRIAL_ROUTE_ORDER[2]
    : POST_TRIAL_ROUTE_ORDER[[
      "outcome_observe",
      "feedback",
      "measure",
      "operator_snapshot",
      "flight_recorder",
    ].indexOf(stage)];
  if (template.route !== expectedRoute) fail(`frozen ${stage} request route is invalid`);
  const bytes = Buffer.from(canonicalJson(body), "utf8");
  if (stage === "measure_replay") {
    const original = prior.get("measure");
    if (!bytes.equals(original.requestBytes)) {
      fail("measure replay request bytes differ from the original canonical measure request");
    }
  }
  return {
    stage,
    method: "POST",
    route: template.route,
    content_type: "application/json",
    trial_id: record.trial.trial_id,
    body: deepFreeze(structuredClone(body)),
    bytes,
    sha256: sha256(bytes),
  };
}

export function assertCanonicalPostTrialRequest({
  execution,
  stage,
  priorResponses = [],
  requestBytes,
}) {
  const observed = parseExactJsonBytes(requestBytes, `${stage} request bytes`);
  const observedBody = object(observed.value, `${stage} request body`);
  const expected = createCanonicalPostTrialRequest({ execution, stage, priorResponses });
  if (!isDeepStrictEqual(observedBody, expected.body)) {
    fail(`${stage} request body drifted from the frozen post-trial contract and prior Runtime responses`);
  }
  if (!observed.bytes.equals(expected.bytes)) {
    fail(`${stage} request bytes are not the exact canonical compact UTF-8 body`);
  }
  return expected;
}

function runtimeCommon(response, record, contractVersion, field) {
  object(response, field);
  if (response.contract_version !== contractVersion) {
    fail(`${field}.contract_version must be ${contractVersion}`);
  }
  if (response.tenant_id !== record.preclaim.tenant_id || response.scope !== record.preclaim.scope) {
    fail(`${field} tenant/scope does not match the ledger-owned Runtime identity`);
  }
}

function runtimeOperation(response, expectedOperationId, field) {
  if (response.operation_id !== expectedOperationId) {
    fail(`${field}.operation_id does not echo the ledger-owned operation ID`);
  }
  return response.operation_id;
}

function outcomeMemoryBinding(value, field) {
  if (!Array.isArray(value) || value.length !== 1) {
    fail(`${field} must contain exactly one outcome memory node`);
  }
  const node = object(value[0], `${field}[0]`);
  return {
    client_id: nonEmptyString(node.client_id, `${field}[0].client_id`),
    memory_id: nonEmptyString(node.id, `${field}[0].id`),
  };
}

function validateOutcomeResponse(response, record) {
  const field = "Runtime outcome response";
  runtimeCommon(response, record, "aionis_observe_result_v1", field);
  const operationId = runtimeOperation(response, record.preclaim.outcome_operation_id, field);
  const observed = object(response.observed, `${field}.observed`);
  if (observed.memory_written !== true) fail(`${field} did not write outcome memory`);
  const projections = object(response.post_commit_projections, `${field}.post_commit_projections`);
  if (projections.semantic_commit !== "committed") fail(`${field} semantic commit was not committed`);
  const memoryWrite = object(response.memory_write, `${field}.memory_write`);
  if (memoryWrite.tenant_id !== record.preclaim.tenant_id || memoryWrite.scope !== record.preclaim.scope) {
    fail(`${field}.memory_write tenant/scope is invalid`);
  }
  const memoryBinding = outcomeMemoryBinding(
    memoryWrite.nodes,
    `${field}.memory_write.nodes`,
  );
  return { operationId, memoryBinding };
}

function validateFeedbackResponse(response, record) {
  const field = "Runtime feedback response";
  runtimeCommon(response, record, "aionis_feedback_result_v1", field);
  const operationId = runtimeOperation(response, record.preclaim.feedback_operation_id, field);
  if (response.product_action !== "feedback"
    || response.operation !== "activate"
    || response.target !== "memory") {
    fail(`${field} is not the memory-feedback result produced by the frozen request`);
  }
  const learningAttributionStatus = nonEmptyString(
    response.learning_attribution_status,
    `${field}.learning_attribution_status`,
  );
  if (!LEARNING_ATTRIBUTION_STATUSES.has(learningAttributionStatus)) {
    fail(`${field}.learning_attribution_status is not a supported memory-feedback attribution status`);
  }
  nonEmptyString(response.learning_episode_id, `${field}.learning_episode_id`);
  const feedbackId = nonEmptyString(
    response.learning_feedback_event_id,
    `${field}.learning_feedback_event_id`,
  );
  return { operationId, feedbackId, learningAttributionStatus };
}

function validateMeasureResponse(response, record, field = "Runtime measure response") {
  runtimeCommon(response, record, "aionis_measure_result_v1", field);
  const operationId = runtimeOperation(response, record.preclaim.measure_operation_id, field);
  const measureId = nonEmptyString(response.measurement_id, `${field}.measurement_id`);
  const measurementDigest = sha256Hex(response.measurement_digest, `${field}.measurement_digest`);
  if (response.measurement_persisted !== true) fail(`${field}.measurement_persisted must be true`);
  return { operationId, measureId, measurementDigest };
}

function validateSnapshotResponse(response, record) {
  const field = "Runtime operator snapshot response";
  runtimeCommon(response, record, "aionis_operator_snapshot_result_v1", field);
  object(response.operator_snapshot, `${field}.operator_snapshot`);
  if (Object.hasOwn(response, "markdown")) fail(`${field}.markdown must remain absent`);
}

function validateRecorderResponse(response, record) {
  const field = "Runtime flight recorder response";
  runtimeCommon(response, record, "aionis_agent_flight_recorder_result_v1", field);
  object(response.agent_flight_recorder, `${field}.agent_flight_recorder`);
}

function checkpointValue({ stage, execution, request, document, response, stageFacts, rawIdentity }) {
  const record = executionRecord(execution);
  const common = {
    schema_version: CHECKPOINT_SCHEMA,
    stage,
    trial_id: record.trial.trial_id,
    method: request.method,
    route: request.route,
    http_status: 200,
    request_sha256: request.sha256,
    response_sha256: document.sha256,
    runtime_tenant_id: record.preclaim.tenant_id,
    runtime_scope: record.preclaim.scope,
  };
  let checkpoint;
  if (stage === "outcome_observe") {
    checkpoint = {
      ...common,
      runtime_echoed_operation_id: stageFacts.operationId,
      outcome_memory_ids: [stageFacts.memoryBinding.memory_id],
      outcome_memory_bindings: [{ ...stageFacts.memoryBinding }],
    };
  } else if (stage === "feedback") {
    checkpoint = {
      ...common,
      runtime_echoed_operation_id: stageFacts.operationId,
      feedback_id: stageFacts.feedbackId,
      learning_attribution_status: stageFacts.learningAttributionStatus,
    };
  } else if (stage === "measure") {
    checkpoint = {
      ...common,
      runtime_echoed_operation_id: stageFacts.operationId,
      measure_id: stageFacts.measureId,
      measurement_digest: stageFacts.measurementDigest,
    };
  } else if (stage === "measure_replay") {
    checkpoint = {
      ...common,
      runtime_echoed_operation_id: stageFacts.operationId,
      measure_id: stageFacts.measureId,
      measurement_digest: stageFacts.measurementDigest,
      original_response_sha256: stageFacts.originalResponseSha256,
    };
  } else if (stage === "operator_snapshot") {
    checkpoint = {
      ...common,
      snapshot_response_sha256: rawIdentity.snapshot_response_sha256,
      snapshot_id: rawIdentity.snapshot_id,
    };
  } else {
    checkpoint = {
      ...common,
      recorder_response_sha256: rawIdentity.recorder_response_sha256,
      recorder_id: rawIdentity.recorder_id,
    };
  }
  const value = deepFreeze(checkpoint);
  checkpointRecords.set(value, {
    execution,
    stage,
    requestBody: structuredClone(request.body),
    requestBytes: Buffer.from(request.bytes),
    responseBody: deepFreeze(structuredClone(response)),
    responseBytes: Buffer.from(document.bytes),
  });
  return value;
}

export function parsePostTrialRuntimeResponse({
  execution,
  stage: inputStage,
  priorResponses = [],
  requestBytes,
  httpStatus,
  responseBytes,
}) {
  const record = executionRecord(execution);
  const stage = stageName(inputStage);
  const request = assertCanonicalPostTrialRequest({ execution, stage, priorResponses, requestBytes });
  if (httpStatus !== 200) fail(`${stage} Runtime HTTP status must be exactly 200`);
  const rawBytes = exactBytes(responseBytes, `${stage} exact raw Runtime response bytes`);
  const rawIdentity = stage === "operator_snapshot"
    ? captureWorkloadRawResponseIdentity("snapshot", record.trial.trial_id, rawBytes)
    : stage === "flight_recorder"
      ? captureWorkloadRawResponseIdentity("recorder", record.trial.trial_id, rawBytes)
      : null;
  const document = parseExactJsonBytes(rawBytes, `${stage} exact raw Runtime response bytes`);
  const response = object(document.value, `${stage} Runtime response`);
  let stageFacts;
  if (stage === "outcome_observe") stageFacts = validateOutcomeResponse(response, record);
  else if (stage === "feedback") stageFacts = validateFeedbackResponse(response, record);
  else if (stage === "measure") stageFacts = validateMeasureResponse(response, record);
  else if (stage === "measure_replay") {
    stageFacts = validateMeasureResponse(response, record, "Runtime measure replay response");
    const prior = priorCheckpointMap(execution, priorResponses, stage);
    const original = prior.get("measure");
    if (!rawBytes.equals(original.responseBytes)) {
      fail("measure replay response bytes differ from the original exact Runtime response bytes");
    }
    stageFacts.originalResponseSha256 = sha256(original.responseBytes);
  } else if (stage === "operator_snapshot") validateSnapshotResponse(response, record);
  else validateRecorderResponse(response, record);
  return checkpointValue({
    stage,
    execution,
    request,
    document,
    response,
    stageFacts,
    rawIdentity,
  });
}

export function verifyMeasureExactReplay({ execution, measure, replay }) {
  executionRecord(execution);
  const original = checkpointRecord(measure, execution, "original measure checkpoint");
  const repeated = checkpointRecord(replay, execution, "measure replay checkpoint");
  if (original.stage !== "measure" || repeated.stage !== "measure_replay") {
    fail("measure exact replay requires measure and measure_replay checkpoints");
  }
  if (!original.requestBytes.equals(repeated.requestBytes)) {
    fail("measure exact replay request bytes are not identical");
  }
  if (!original.responseBytes.equals(repeated.responseBytes)) {
    fail("measure exact replay response bytes are not identical");
  }
  if (measure.runtime_echoed_operation_id !== replay.runtime_echoed_operation_id
    || measure.measure_id !== replay.measure_id
    || measure.measurement_digest !== replay.measurement_digest) {
    fail("measure exact replay derived Runtime facts changed");
  }
  return deepFreeze({
    replayed_operation_id: measure.runtime_echoed_operation_id,
    original_request_sha256: measure.request_sha256,
    replay_request_sha256: replay.request_sha256,
    original_response_sha256: measure.response_sha256,
    replay_response_sha256: replay.response_sha256,
  });
}

function completeCheckpointMap(execution, responses) {
  if (!Array.isArray(responses)) fail("post-trial responses must be an array");
  const values = new Map();
  for (const [index, checkpoint] of responses.entries()) {
    const record = checkpointRecord(checkpoint, execution, `post-trial responses[${index}]`);
    if (values.has(record.stage)) fail(`post-trial responses contains duplicate ${record.stage} checkpoints`);
    values.set(record.stage, { record, checkpoint });
  }
  for (const stage of POST_TRIAL_STAGES) {
    if (!values.has(stage)) fail(`post-trial settlement facts require the ${stage} checkpoint`);
  }
  if (values.size !== POST_TRIAL_STAGES.length) fail("post-trial responses contains an unknown checkpoint stage");
  return values;
}

export function derivePostTrialSettlementFacts({ execution, responses }) {
  const record = executionRecord(execution);
  const checkpoints = completeCheckpointMap(execution, responses);
  const outcome = checkpoints.get("outcome_observe").checkpoint;
  const feedback = checkpoints.get("feedback").checkpoint;
  const measure = checkpoints.get("measure").checkpoint;
  const replay = checkpoints.get("measure_replay").checkpoint;
  const snapshot = checkpoints.get("operator_snapshot").checkpoint;
  const recorder = checkpoints.get("flight_recorder").checkpoint;
  const replayEvidence = verifyMeasureExactReplay({ execution, measure, replay });
  return deepFreeze({
    runtime_echoed_outcome_operation_id: outcome.runtime_echoed_operation_id,
    runtime_echoed_feedback_operation_id: feedback.runtime_echoed_operation_id,
    runtime_echoed_measure_operation_id: measure.runtime_echoed_operation_id,
    feedback_id: feedback.feedback_id,
    learning_attribution_status: feedback.learning_attribution_status,
    measure_id: measure.measure_id,
    snapshot_id: snapshot.snapshot_id,
    snapshot_response_sha256: snapshot.snapshot_response_sha256,
    recorder_id: recorder.recorder_id,
    recorder_response_sha256: recorder.recorder_response_sha256,
    runtime_tenant_id: record.preclaim.tenant_id,
    runtime_scope: record.preclaim.scope,
    outcome_response_sha256: outcome.response_sha256,
    feedback_response_sha256: feedback.response_sha256,
    measure_response_sha256: measure.response_sha256,
    outcome_memory_ids: [...outcome.outcome_memory_ids],
    outcome_memory_bindings: outcome.outcome_memory_bindings.map((binding) => ({ ...binding })),
    replay_evidence: {
      replayed_operation_id: replayEvidence.replayed_operation_id,
      original_response_sha256: replayEvidence.original_response_sha256,
      replay_response_sha256: replayEvidence.replay_response_sha256,
    },
  });
}
