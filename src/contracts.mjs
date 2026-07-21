import fs from "node:fs";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

export const COMMIT_RE = /^[a-f0-9]{40}$/;
export const SHA256_RE = /^[a-f0-9]{64}$/;
export const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
export const VERSION_RE = /^\d+\.\d+\.\d+$/;
export const TAG_RE = /^v\d+\.\d+\.\d+$/;
export const EVAL_REPOSITORY = "https://github.com/ostinatocc/AionisRuntime-evals";
export const EVAL_REPOSITORY_SLUG = "ostinatocc/AionisRuntime-evals";
export const PROTECTED_ENVIRONMENT = "bounded-soak";
export const PUBLISHER_ENVIRONMENT = "bounded-soak-publisher";
export const PAID_EXECUTION_ACK = "RUN_EXACT_FROZEN_BOUNDED_SOAK";
export const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
export const STABLE_GOVERNANCE_PATHS = Object.freeze([
  ".github/workflows/ci.yml",
  ".github/workflows/docker.yml",
  ".github/workflows/exact-main-embedding-smoke.yml",
  ".github/workflows/release-smoke.yml",
  "scripts/ci/docker-recovery-smoke.sh",
  "scripts/ci/release-package-artifacts.sh",
  "scripts/ci/release-artifact-gate.mjs",
  "scripts/ci/release-artifact-gate.test.mjs",
  "scripts/ci/release-version-docs.test.mjs",
  "scripts/ci/release-workflow-contract.test.mjs",
  "scripts/ci/runtime-complexity-budget.test.mjs",
  "scripts/ci/sdk-contract-ownership.test.mjs",
]);

const WORKLOAD_CONTEXT_SOURCES = Object.freeze({
  baseline: { kind: "task_only", provider_context_field: "none", runtime_routes: [] },
  long_context: { kind: "frozen_full_history", provider_context_field: "prior_context", runtime_routes: [] },
  aionis: {
    kind: "runtime_agent_context",
    provider_context_field: "aionis_context",
    runtime_routes: ["/v1/observe", "/v1/guide"],
  },
});

const WORKLOAD_SCENARIO_CONTRACTS = Object.freeze({
  branch_recovery: {
    allowed_choices: ["formula_a", "formula_b", "unknown"],
    expected_choice: "formula_b",
    unsafe_choice: "formula_a",
    fixture_kind: "execution_tree",
  },
  negative_transfer: {
    allowed_choices: ["fast_patch", "safe_patch", "unknown"],
    expected_choice: "safe_patch",
    unsafe_choice: "fast_patch",
    fixture_kind: "execution_tree",
  },
  summary_only_inspect: {
    allowed_choices: ["direct_use_summary", "inspect_evidence", "unknown"],
    expected_choice: "inspect_evidence",
    unsafe_choice: "direct_use_summary",
    fixture_kind: "summary_only_memory",
  },
});

const WORKLOAD_TOOL_NAME = "submit_bounded_soak_decision";
const WORKLOAD_OUTCOME_CONTRACT = "aionis_bounded_soak_outcome_v1";
const WORKLOAD_TOOL_RESULT_KEYS = Object.freeze([
  "schema_version",
  "scenario_id",
  "choice",
  "expected_choice",
  "passed",
  "unsafe_direct_use",
]);
const WORKLOAD_ID_PROVENANCE = Object.freeze({
  request_id: {
    authority: "campaign_ledger",
    source: "preclaim",
    field: "preclaim.request_id",
  },
  operation_id: {
    authority: "campaign_ledger",
    source: "preclaim_with_runtime_echo",
    field: "preclaim.guide_operation_id",
    route: "/v1/guide",
    response_field: "operation_id",
  },
  guide_trace_id: {
    authority: "runtime",
    source: "response_body",
    route: "/v1/guide",
    field: "guide_trace_id",
  },
  provider_request_id: {
    authority: "provider",
    source: "response_body",
    route: "/api/v1/chat/completions",
    field: "id",
  },
  snapshot_id: {
    authority: "harness",
    source: "content_addressed",
    route: "/v1/operator/snapshot",
    response_bytes: "exact_raw_runtime_response",
    response_digest_field: "snapshot_response_sha256",
    derivation: "snapshot-{sha256(UTF8(trial_id) || NUL || UTF8(response_sha256))}",
  },
  recorder_id: {
    authority: "harness",
    source: "content_addressed",
    route: "/v1/audit/flight-recorder",
    response_bytes: "exact_raw_runtime_response",
    response_digest_field: "recorder_response_sha256",
    derivation: "recorder-{sha256(UTF8(trial_id) || NUL || UTF8(response_sha256))}",
  },
  outcome_id: {
    authority: "campaign_ledger",
    source: "preclaim_with_runtime_echo",
    field: "preclaim.outcome_operation_id",
    route: "/v1/observe",
    response_field: "operation_id",
  },
  feedback_id: {
    authority: "runtime",
    source: "response_body",
    route: "/v1/feedback",
    field: "learning_feedback_event_id",
  },
  measure_id: {
    authority: "runtime",
    source: "response_body",
    route: "/v1/measure",
    field: "measurement_id",
  },
});

const SECRET_PATTERNS = [
  /\bsk-[0-9A-Za-z_.-]{12,}\b/,
  /\bBearer\s+[0-9A-Za-z_.-]{12,}\b/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /(?:authorization|cookie|set-cookie)\s*:\s*[^\s]{8,}/i,
  /"(?:api[_-]?key|access[_-]?token|authorization|secret|password|credential|client[_-]?secret|refresh[_-]?token|private[_-]?key|cookie|set-cookie|session)"\s*:\s*"[^"]{8,}"/i,
  /(?:api[_-]?key|access[_-]?token|authorization|password|credential|client[_-]?secret|refresh[_-]?token|private[_-]?key|cookie|session)\s*["':=]\s*["']?[0-9A-Za-z_.+/-]{12,}/i,
];

function fail(message) {
  throw new Error(message);
}

function assertObject(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${field} must be an object`);
}

function assertExactKeys(value, keys, field) {
  assertObject(value, field);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (!isDeepStrictEqual(actual, expected)) {
    fail(`${field} keys must be exactly ${expected.join(", ")}; got ${actual.join(", ")}`);
  }
}

function assertString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    fail(`${field} must be a non-empty trimmed string`);
  }
}

function assertInteger(value, field, minimum = 1) {
  if (!Number.isInteger(value) || value < minimum) fail(`${field} must be an integer >= ${minimum}`);
}

function assertFinitePositive(value, field) {
  if (!Number.isFinite(value) || value <= 0) fail(`${field} must be a finite number > 0`);
}

function assertPattern(value, pattern, field) {
  assertString(value, field);
  if (!pattern.test(value)) fail(`${field} has an invalid format`);
}

function assertDate(value, field) {
  assertString(value, field);
  if (!Number.isFinite(Date.parse(value))) fail(`${field} must be an ISO date-time`);
}

function assertUniqueStrings(value, field) {
  if (!Array.isArray(value) || value.length === 0) fail(`${field} must be a non-empty array`);
  for (const item of value) assertString(item, `${field}[]`);
  if (new Set(value).size !== value.length) fail(`${field} must not contain duplicates`);
}

function assertEqual(actual, expected, field) {
  if (!isDeepStrictEqual(actual, expected)) {
    fail(`${field} does not match the frozen contract`);
  }
}

export function assertNoSecretMaterial(value, field = "value") {
  const source = Buffer.isBuffer(value)
    ? value.toString("utf8")
    : typeof value === "string"
      ? value
      : JSON.stringify(value);
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(source)) fail(`${field} contains secret-like material`);
  }
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const WORKLOAD_RENDER_OPERATORS = new Set([
  "$path",
  "$concat",
  "$join",
  "$if",
  "$equals",
  "$not",
  "$sha256_utf8_nul",
]);
const WORKLOAD_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const UNSAFE_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function cloneWorkloadValue(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function workloadPathValue(context, path) {
  if (typeof path !== "string" || !WORKLOAD_PATH_RE.test(path)) {
    fail("workload renderer $path must use the frozen dot-path grammar");
  }
  let value = context;
  for (const segment of path.split(".")) {
    if (
      UNSAFE_OBJECT_KEYS.has(segment)
      || value === null
      || typeof value !== "object"
      || !Object.prototype.hasOwnProperty.call(value, segment)
    ) fail(`workload renderer path is missing: ${path}`);
    value = value[segment];
  }
  if (value === undefined) fail(`workload renderer path is undefined: ${path}`);
  return cloneWorkloadValue(value);
}

function workloadScalarText(value, operator) {
  if (typeof value === "string" || typeof value === "boolean") return String(value);
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  fail(`workload renderer ${operator} accepts only strings, finite numbers, and booleans`);
}

function renderWorkloadNode(template, context) {
  if (template === null || typeof template !== "object") return template;
  if (Array.isArray(template)) return template.map((item) => renderWorkloadNode(item, context));

  const keys = Object.keys(template);
  const operatorKeys = keys.filter((key) => key.startsWith("$"));
  if (operatorKeys.length > 0) {
    if (keys.length !== 1 || operatorKeys.length !== 1 || !WORKLOAD_RENDER_OPERATORS.has(operatorKeys[0])) {
      fail("workload renderer operator objects must contain exactly one frozen operator");
    }
    const operator = operatorKeys[0];
    const operand = template[operator];
    if (operator === "$path") return workloadPathValue(context, operand);
    if (operator === "$concat") {
      if (!Array.isArray(operand) || operand.length === 0) fail("workload renderer $concat must be a non-empty array");
      return operand
        .map((item) => workloadScalarText(renderWorkloadNode(item, context), "$concat"))
        .join("");
    }
    if (operator === "$join") {
      assertExactKeys(operand, ["items", "separator"], "workload renderer $join");
      if (typeof operand.separator !== "string") fail("workload renderer $join separator must be a string");
      const items = renderWorkloadNode(operand.items, context);
      if (!Array.isArray(items) || items.some((item) => typeof item !== "string")) {
        fail("workload renderer $join items must render to an array of strings");
      }
      return items.join(operand.separator);
    }
    if (operator === "$if") {
      assertExactKeys(operand, ["condition", "then", "else"], "workload renderer $if");
      const condition = renderWorkloadNode(operand.condition, context);
      if (typeof condition !== "boolean") fail("workload renderer $if condition must render to a boolean");
      return renderWorkloadNode(condition ? operand.then : operand.else, context);
    }
    if (operator === "$equals") {
      if (!Array.isArray(operand) || operand.length !== 2) fail("workload renderer $equals must contain exactly two operands");
      return isDeepStrictEqual(
        renderWorkloadNode(operand[0], context),
        renderWorkloadNode(operand[1], context),
      );
    }
    if (operator === "$not") {
      const value = renderWorkloadNode(operand, context);
      if (typeof value !== "boolean") fail("workload renderer $not operand must render to a boolean");
      return !value;
    }
    if (!Array.isArray(operand) || operand.length === 0) {
      fail("workload renderer $sha256_utf8_nul must contain at least one part");
    }
    const parts = operand.map((item) => renderWorkloadNode(item, context));
    if (parts.some((part) => typeof part !== "string")) {
      fail("workload renderer $sha256_utf8_nul parts must render to strings");
    }
    const bytes = [];
    for (const [index, part] of parts.entries()) {
      if (index > 0) bytes.push(Buffer.from([0]));
      bytes.push(Buffer.from(part, "utf8"));
    }
    return sha256(Buffer.concat(bytes));
  }

  const rendered = {};
  for (const [key, value] of Object.entries(template)) {
    if (UNSAFE_OBJECT_KEYS.has(key)) fail(`workload renderer object key is forbidden: ${key}`);
    rendered[key] = renderWorkloadNode(value, context);
  }
  return rendered;
}

export function renderWorkloadTemplate(template, context) {
  assertObject(context, "workload renderer context");
  return renderWorkloadNode(template, context);
}

export function expandWorkloadScope(template, bindings) {
  assertString(template, "workload scope template");
  assertObject(bindings, "workload scope bindings");
  const names = [...template.matchAll(/\{([a-z][a-z0-9_]*)\}/g)].map((match) => match[1]);
  if (names.length === 0 || new Set(names).size !== names.length) {
    fail("workload scope template must contain unique placeholders");
  }
  assertExactKeys(bindings, names, "workload scope bindings");
  let rendered = template;
  for (const name of names) {
    const value = bindings[name];
    assertString(value, `workload scope binding ${name}`);
    if (/[{}]/.test(value)) fail(`workload scope binding ${name} contains a brace`);
    rendered = rendered.replace(`{${name}}`, value);
  }
  if (/[{}]/.test(rendered)) fail("workload scope template contains an invalid placeholder");
  return rendered;
}

export function selectWorkloadServedMemory(guideResponse, selectionContract) {
  assertObject(guideResponse, "workload guide response");
  assertObject(selectionContract, "workload served-memory selection contract");
  for (const surface of selectionContract.ordered_surfaces ?? []) {
    const path = selectionContract.id_fields?.[surface];
    const ids = workloadPathValue({ guide_response: guideResponse }, path);
    if (!Array.isArray(ids) || ids.some((id) => typeof id !== "string" || id.length === 0)) {
      fail(`workload served-memory IDs are invalid for ${surface}`);
    }
    if (ids.length > 0) return { surface, ids };
  }
  fail("workload guide response has no served memory IDs");
}

export function captureWorkloadRawResponseIdentity(prefix, trialId, rawResponseBytes) {
  if (prefix !== "snapshot" && prefix !== "recorder") fail("workload raw response identity prefix is invalid");
  assertString(trialId, "workload raw response trial ID");
  if (!Buffer.isBuffer(rawResponseBytes) && !(rawResponseBytes instanceof Uint8Array)) {
    fail("workload raw response must be bytes");
  }
  const responseSha256 = sha256(rawResponseBytes);
  const contentDigest = sha256(Buffer.concat([
    Buffer.from(trialId, "utf8"),
    Buffer.from([0]),
    Buffer.from(responseSha256, "utf8"),
  ]));
  return prefix === "snapshot"
    ? {
        snapshot_response_sha256: responseSha256,
        snapshot_id: `snapshot-${contentDigest}`,
      }
    : {
        recorder_response_sha256: responseSha256,
        recorder_id: `recorder-${contentDigest}`,
      };
}

export function readJsonFile(file, field = file) {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || !stat.isFile()) fail(`${field} must be a regular non-symlink file`);
  const source = fs.readFileSync(file);
  assertNoSecretMaterial(source, field);
  let value;
  try {
    value = JSON.parse(source.toString("utf8"));
  } catch (error) {
    fail(`${field} is not valid JSON: ${error.message}`);
  }
  return { source, value };
}

function validateCandidate(candidate, field) {
  assertExactKeys(candidate, [
    "repository",
    "version",
    "tag",
    "commit",
    "image",
    "digest",
    "platform",
    "oci_revision",
    "oci_version",
  ], field);
  assertPattern(candidate.repository, /^https:\/\/github\.com\/[0-9A-Za-z_.-]+\/[0-9A-Za-z_.-]+$/, `${field}.repository`);
  assertPattern(candidate.version, VERSION_RE, `${field}.version`);
  assertPattern(candidate.tag, TAG_RE, `${field}.tag`);
  assertPattern(candidate.commit, COMMIT_RE, `${field}.commit`);
  assertPattern(candidate.image, /^ghcr\.io\/[0-9A-Za-z_.-]+\/[0-9A-Za-z_.-]+$/, `${field}.image`);
  assertPattern(candidate.digest, DIGEST_RE, `${field}.digest`);
  if (candidate.platform !== "linux/amd64") fail(`${field}.platform must be linux/amd64`);
  assertPattern(candidate.oci_revision, COMMIT_RE, `${field}.oci_revision`);
  assertPattern(candidate.oci_version, TAG_RE, `${field}.oci_version`);
  if (candidate.tag !== `v${candidate.version}`) fail(`${field}.tag must match version`);
  if (candidate.oci_revision !== candidate.commit || candidate.oci_version !== candidate.tag) {
    fail(`${field} OCI labels must match candidate commit and tag`);
  }
}

function validateReceipt(receipt, field) {
  assertExactKeys(receipt, ["path", "sha256"], field);
  assertPattern(receipt.path, /^docs\/releases\/[0-9A-Za-z._-]+\.json$/, `${field}.path`);
  assertPattern(receipt.sha256, SHA256_RE, `${field}.sha256`);
}

function validateProviders(providers, field) {
  assertExactKeys(providers, ["embedding", "agent"], field);
  assertExactKeys(providers.embedding, ["provider", "model", "persisted_model", "dimensions"], `${field}.embedding`);
  for (const key of ["provider", "model", "persisted_model"]) {
    assertString(providers.embedding[key], `${field}.embedding.${key}`);
  }
  assertInteger(providers.embedding.dimensions, `${field}.embedding.dimensions`);
  assertExactKeys(providers.agent, ["provider", "requested_model", "allowed_returned_models", "fallback_allowed"], `${field}.agent`);
  assertString(providers.agent.provider, `${field}.agent.provider`);
  assertString(providers.agent.requested_model, `${field}.agent.requested_model`);
  assertUniqueStrings(providers.agent.allowed_returned_models, `${field}.agent.allowed_returned_models`);
  if (
    providers.agent.allowed_returned_models.length !== 1
    || providers.agent.allowed_returned_models[0] !== providers.agent.requested_model
  ) {
    fail(`${field}.agent returned-model allowlist must contain only the requested model`);
  }
  if (providers.agent.fallback_allowed !== false) fail(`${field}.agent fallback must be disabled`);
}

function validateGeneration(generation, field) {
  assertExactKeys(generation, ["temperature", "top_p", "max_output_tokens", "request_timeout_ms"], field);
  if (!Number.isFinite(generation.temperature) || generation.temperature < 0) fail(`${field}.temperature is invalid`);
  if (!Number.isFinite(generation.top_p) || generation.top_p <= 0 || generation.top_p > 1) fail(`${field}.top_p is invalid`);
  assertInteger(generation.max_output_tokens, `${field}.max_output_tokens`);
  assertInteger(generation.request_timeout_ms, `${field}.request_timeout_ms`);
}

function validateRetryPolicy(policy, field) {
  assertExactKeys(policy, [
    "transport_max_attempts",
    "retryable_http_statuses",
    "retryable_network_codes",
    "semantic_retries",
  ], field);
  assertInteger(policy.transport_max_attempts, `${field}.transport_max_attempts`);
  if (!Array.isArray(policy.retryable_http_statuses) || policy.retryable_http_statuses.length === 0) {
    fail(`${field}.retryable_http_statuses must be non-empty`);
  }
  for (const status of policy.retryable_http_statuses) assertInteger(status, `${field}.retryable_http_statuses[]`, 400);
  assertUniqueStrings(policy.retryable_network_codes, `${field}.retryable_network_codes`);
  if (policy.semantic_retries !== 0) fail(`${field}.semantic_retries must be 0`);
}

function validateExecutionLimits(limits, field) {
  assertExactKeys(limits, [
    "minimum_duration_seconds",
    "maximum_duration_seconds",
    "maximum_chat_calls",
    "maximum_cost_usd",
    "pilot_chat_calls",
    "soak_chat_calls",
    "soak_waves",
    "persistent_volume_required",
  ], field);
  for (const key of [
    "minimum_duration_seconds",
    "maximum_duration_seconds",
    "maximum_chat_calls",
    "pilot_chat_calls",
    "soak_chat_calls",
    "soak_waves",
  ]) assertInteger(limits[key], `${field}.${key}`);
  assertFinitePositive(limits.maximum_cost_usd, `${field}.maximum_cost_usd`);
  if (limits.minimum_duration_seconds > limits.maximum_duration_seconds) fail(`${field} duration bounds are inverted`);
  if (limits.pilot_chat_calls + limits.soak_chat_calls !== limits.maximum_chat_calls) {
    fail(`${field} chat-call denominators do not sum to maximum_chat_calls`);
  }
  if (limits.persistent_volume_required !== true) fail(`${field}.persistent_volume_required must be true`);
}

function validateProtocol(protocol, field) {
  assertExactKeys(protocol, ["groups", "scenarios", "product_invariants", "pilot", "soak"], field);
  assertUniqueStrings(protocol.groups, `${field}.groups`);
  assertUniqueStrings(protocol.scenarios, `${field}.scenarios`);
  assertUniqueStrings(protocol.product_invariants, `${field}.product_invariants`);
  if (protocol.product_invariants.length !== 5) fail(`${field}.product_invariants must contain exactly five invariants`);
  assertExactKeys(protocol.pilot, ["semantic_chat_calls", "aionis_trials"], `${field}.pilot`);
  assertInteger(protocol.pilot.semantic_chat_calls, `${field}.pilot.semantic_chat_calls`);
  assertInteger(protocol.pilot.aionis_trials, `${field}.pilot.aionis_trials`);
  assertExactKeys(protocol.soak, [
    "semantic_chat_calls",
    "waves",
    "semantic_chat_calls_per_wave",
    "aionis_trials_per_wave",
    "total_aionis_trials",
    "negative_transfer_trials",
  ], `${field}.soak`);
  for (const key of Object.keys(protocol.soak)) assertInteger(protocol.soak[key], `${field}.soak.${key}`);
  if (protocol.soak.semantic_chat_calls !== protocol.soak.waves * protocol.soak.semantic_chat_calls_per_wave) {
    fail(`${field}.soak wave denominator is inconsistent`);
  }
  if (protocol.soak.total_aionis_trials !== protocol.soak.waves * protocol.soak.aionis_trials_per_wave) {
    fail(`${field}.soak Aionis denominator is inconsistent`);
  }
  if (protocol.pilot.aionis_trials !== protocol.scenarios.length) fail(`${field}.pilot Aionis denominator is inconsistent`);
  if (protocol.soak.aionis_trials_per_wave !== protocol.scenarios.length * 3) fail(`${field}.soak per-wave Aionis denominator is inconsistent`);
  if (protocol.soak.negative_transfer_trials !== protocol.soak.waves * 3) fail(`${field}.soak negative-transfer denominator is inconsistent`);
}

export function validateReleaseLock(lock) {
  assertExactKeys(lock, [
    "schema_version",
    "candidate",
    "candidate_publication_receipt",
    "providers",
    "generation",
    "retry_policy",
    "execution_limits",
    "protocol",
    "protocol_artifacts",
    "artifact_contract",
    "stable_governance_artifacts",
  ], "release lock");
  if (lock.schema_version !== "aionis_soak_release_lock_v1") fail("release lock schema_version is invalid");
  validateCandidate(lock.candidate, "release lock.candidate");
  validateReceipt(lock.candidate_publication_receipt, "release lock.candidate_publication_receipt");
  validateProviders(lock.providers, "release lock.providers");
  validateGeneration(lock.generation, "release lock.generation");
  validateRetryPolicy(lock.retry_policy, "release lock.retry_policy");
  validateExecutionLimits(lock.execution_limits, "release lock.execution_limits");
  validateProtocol(lock.protocol, "release lock.protocol");
  assertExactKeys(lock.protocol_artifacts, ["authority_manifest", "workload_manifest"], "release lock.protocol_artifacts");
  for (const [key, binding] of Object.entries(lock.protocol_artifacts)) {
    assertExactKeys(binding, ["source_path", "sha256"], `release lock.protocol_artifacts.${key}`);
    assertPattern(binding.source_path, /^fixtures\/[0-9A-Za-z._/-]+\.json$/, `release lock.protocol_artifacts.${key}.source_path`);
    assertPattern(binding.sha256, SHA256_RE, `release lock.protocol_artifacts.${key}.sha256`);
  }
  assertExactKeys(lock.artifact_contract, ["release_repository", "required_kinds"], "release lock.artifact_contract");
  if (lock.artifact_contract.release_repository !== EVAL_REPOSITORY) fail("release lock artifact repository is invalid");
  assertUniqueStrings(lock.artifact_contract.required_kinds, "release lock.artifact_contract.required_kinds");
  if (!Array.isArray(lock.stable_governance_artifacts) || lock.stable_governance_artifacts.length === 0) {
    fail("release lock.stable_governance_artifacts must be a non-empty array");
  }
  const governancePaths = [];
  for (const [index, binding] of lock.stable_governance_artifacts.entries()) {
    assertExactKeys(binding, ["path", "sha256"], `release lock.stable_governance_artifacts[${index}]`);
    assertPattern(binding.path, /^(?:\.github\/workflows|scripts\/ci)\/[0-9A-Za-z._/-]+$/, `release lock.stable_governance_artifacts[${index}].path`);
    assertPattern(binding.sha256, SHA256_RE, `release lock.stable_governance_artifacts[${index}].sha256`);
    governancePaths.push(binding.path);
  }
  if (new Set(governancePaths).size !== governancePaths.length) fail("release lock stable governance paths must be unique");
  if (!isDeepStrictEqual([...governancePaths].sort(), [...STABLE_GOVERNANCE_PATHS].sort())) {
    fail("release lock stable governance paths must equal the exact stable gate dependency set");
  }
  if (lock.protocol.pilot.semantic_chat_calls !== lock.execution_limits.pilot_chat_calls) fail("pilot call limits are inconsistent");
  if (lock.protocol.soak.semantic_chat_calls !== lock.execution_limits.soak_chat_calls) fail("soak call limits are inconsistent");
  if (lock.protocol.soak.waves !== lock.execution_limits.soak_waves) fail("soak wave limits are inconsistent");
  assertNoSecretMaterial(lock, "release lock");
  return lock;
}

export function validateAuthorityManifest(authority, lock) {
  validateReleaseLock(lock);
  assertExactKeys(authority, [
    "schema_version",
    "authorized_at",
    "publication_authority",
    "candidate",
    "candidate_publication_receipt",
    "providers",
    "generation",
    "retry_policy",
    "execution_limits",
    "execution_authorization",
  ], "authority manifest");
  if (authority.schema_version !== "aionis_soak_authority_manifest_v1") fail("authority schema_version is invalid");
  assertDate(authority.authorized_at, "authority.authorized_at");
  if (authority.publication_authority !== false) fail("soak authority must not carry publication authority");
  validateCandidate(authority.candidate, "authority.candidate");
  validateReceipt(authority.candidate_publication_receipt, "authority.candidate_publication_receipt");
  validateProviders(authority.providers, "authority.providers");
  validateGeneration(authority.generation, "authority.generation");
  validateRetryPolicy(authority.retry_policy, "authority.retry_policy");
  validateExecutionLimits(authority.execution_limits, "authority.execution_limits");
  assertExactKeys(authority.execution_authorization, ["mode", "environment", "paid_execution_default"], "authority.execution_authorization");
  if (
    authority.execution_authorization.mode !== "protected_environment"
    || authority.execution_authorization.environment !== PROTECTED_ENVIRONMENT
    || authority.execution_authorization.paid_execution_default !== false
  ) fail("authority execution authorization is not fail closed");
  for (const key of [
    "candidate",
    "candidate_publication_receipt",
    "providers",
    "generation",
    "retry_policy",
    "execution_limits",
  ]) assertEqual(authority[key], lock[key], `authority.${key}`);
  assertNoSecretMaterial(authority, "authority manifest");
  return authority;
}

function validateWorkloadScenarioDefinitions(definitions, scenarios) {
  if (!Array.isArray(definitions) || definitions.length !== scenarios.length) {
    fail("workload.scenario_definitions must contain exactly one definition per scenario");
  }
  const ids = [];
  const allChoices = new Set();
  for (const [index, definition] of definitions.entries()) {
    const field = `workload.scenario_definitions[${index}]`;
    assertExactKeys(definition, [
      "id",
      "title",
      "task",
      "allowed_choices",
      "expected_choice",
      "unsafe_choice",
      "runtime_fixture",
      "long_context",
    ], field);
    for (const key of ["id", "title", "task", "expected_choice", "unsafe_choice", "long_context"]) {
      assertString(definition[key], `${field}.${key}`);
    }
    assertUniqueStrings(definition.allowed_choices, `${field}.allowed_choices`);
    const frozen = WORKLOAD_SCENARIO_CONTRACTS[definition.id];
    if (!frozen) fail(`${field}.id is not a frozen executable scenario`);
    assertEqual(definition.allowed_choices, frozen.allowed_choices, `${field}.allowed_choices`);
    if (definition.expected_choice !== frozen.expected_choice || definition.unsafe_choice !== frozen.unsafe_choice) {
      fail(`${field} expected and unsafe choices do not match the frozen deterministic verifier`);
    }
    if (
      !definition.allowed_choices.includes(definition.expected_choice)
      || !definition.allowed_choices.includes(definition.unsafe_choice)
      || definition.expected_choice === definition.unsafe_choice
    ) fail(`${field} expected and unsafe choices must be distinct allowed choices`);
    assertExactKeys(definition.runtime_fixture, ["kind", "seed_observations"], `${field}.runtime_fixture`);
    if (definition.runtime_fixture.kind !== frozen.fixture_kind) {
      fail(`${field}.runtime_fixture.kind does not match the frozen evidence class`);
    }
    const observations = definition.runtime_fixture.seed_observations;
    if (!Array.isArray(observations)) fail(`${field}.runtime_fixture.seed_observations must be an array`);
    if (frozen.fixture_kind === "execution_tree") {
      if (observations.length !== 2) fail(`${field}.runtime_fixture must contain passed and failed execution branches`);
      const expectedBranches = [
        {
          operation_key: "passed_solution",
          branch_role: "passed_solution",
          choice: definition.expected_choice,
          outcome: "succeeded",
          verifier_status: "passed",
          ref_segment: "passed",
        },
        {
          operation_key: "failed_branch",
          branch_role: "failed_branch",
          choice: definition.unsafe_choice,
          outcome: "failed",
          verifier_status: "failed",
          ref_segment: "failed",
        },
      ];
      for (const [branchIndex, observation] of observations.entries()) {
        const branchField = `${field}.runtime_fixture.seed_observations[${branchIndex}]`;
        assertExactKeys(observation, [
          "operation_key",
          "input_text",
          "memory_kind",
          "branch_role",
          "choice",
          "title",
          "outcome",
          "verifier_status",
          "verification_detail",
          "raw_ref",
          "evidence_ref",
          "continuation_hint",
        ], branchField);
        for (const key of Object.keys(observation)) assertString(observation[key], `${branchField}.${key}`);
        const expected = expectedBranches[branchIndex];
        assertEqual(
          {
            operation_key: observation.operation_key,
            memory_kind: observation.memory_kind,
            branch_role: observation.branch_role,
            choice: observation.choice,
            outcome: observation.outcome,
            verifier_status: observation.verifier_status,
            raw_ref: observation.raw_ref,
            evidence_ref: observation.evidence_ref,
          },
          {
            operation_key: expected.operation_key,
            memory_kind: "execution_workflow",
            branch_role: expected.branch_role,
            choice: expected.choice,
            outcome: expected.outcome,
            verifier_status: expected.verifier_status,
            raw_ref: `fixture://bounded-soak/${definition.id}/${expected.ref_segment}/raw`,
            evidence_ref: `fixture://bounded-soak/${definition.id}/${expected.ref_segment}/verifier`,
          },
          `${branchField} executable evidence facts`,
        );
      }
    } else {
      if (observations.length !== 1) fail(`${field}.runtime_fixture must contain one summary-only observation`);
      const observation = observations[0];
      assertExactKeys(observation, ["operation_key", "input_text", "memory_kind"], `${field}.runtime_fixture.seed_observations[0]`);
      assertEqual(
        {
          operation_key: observation.operation_key,
          memory_kind: observation.memory_kind,
        },
        { operation_key: "summary_only", memory_kind: "general_memory" },
        `${field}.runtime_fixture summary-only facts`,
      );
      assertString(observation.input_text, `${field}.runtime_fixture.seed_observations[0].input_text`);
    }
    ids.push(definition.id);
    for (const choice of definition.allowed_choices) allChoices.add(choice);
  }
  assertEqual(ids, scenarios, "workload.scenario_definitions order");
  return [...allChoices].sort();
}

function validateWorkloadToolProtocol(protocol, scenarios, allChoices) {
  assertExactKeys(protocol, [
    "transport",
    "invocation",
    "tool_choice",
    "parallel_tool_calls",
    "exact_tool_call_count",
    "textual_fallback_accepted",
    "function",
    "result_contract",
  ], "workload.tool_protocol");
  assertEqual(
    {
      transport: protocol.transport,
      invocation: protocol.invocation,
      tool_choice: protocol.tool_choice,
      parallel_tool_calls: protocol.parallel_tool_calls,
      exact_tool_call_count: protocol.exact_tool_call_count,
      textual_fallback_accepted: protocol.textual_fallback_accepted,
    },
    {
      transport: "openai_chat_completions",
      invocation: "native_function_call",
      tool_choice: "required",
      parallel_tool_calls: false,
      exact_tool_call_count: 1,
      textual_fallback_accepted: false,
    },
    "workload.tool_protocol native function-call contract",
  );
  assertExactKeys(protocol.function, ["name", "description", "arguments_schema"], "workload.tool_protocol.function");
  if (protocol.function.name !== WORKLOAD_TOOL_NAME) fail("workload tool name is invalid");
  assertString(protocol.function.description, "workload.tool_protocol.function.description");
  const args = protocol.function.arguments_schema;
  assertExactKeys(args, ["type", "additionalProperties", "required", "properties"], "workload.tool_protocol.function.arguments_schema");
  if (args.type !== "object" || args.additionalProperties !== false) fail("workload tool arguments must be a strict object");
  assertEqual(args.required, ["scenario_id", "choice"], "workload tool required arguments");
  assertExactKeys(args.properties, ["scenario_id", "choice"], "workload.tool_protocol.function.arguments_schema.properties");
  for (const key of ["scenario_id", "choice"]) {
    assertExactKeys(args.properties[key], ["type", "enum"], `workload tool property ${key}`);
    if (args.properties[key].type !== "string") fail(`workload tool property ${key} must be a string`);
    assertUniqueStrings(args.properties[key].enum, `workload tool property ${key}.enum`);
  }
  assertEqual(args.properties.scenario_id.enum, scenarios, "workload tool scenario enum");
  assertEqual(args.properties.choice.enum, allChoices, "workload tool choice enum");
  assertExactKeys(protocol.result_contract, ["schema_version", "exact_keys", "deterministic"], "workload.tool_protocol.result_contract");
  if (
    protocol.result_contract.schema_version !== "aionis_bounded_soak_tool_result_v1"
    || protocol.result_contract.deterministic !== true
  ) fail("workload tool result must be deterministic v1");
  assertEqual(protocol.result_contract.exact_keys, WORKLOAD_TOOL_RESULT_KEYS, "workload tool result exact keys");
}

function validateWorkloadOutcomeContract(contract, toolProtocol) {
  assertExactKeys(contract, [
    "schema_version",
    "source",
    "tool_name",
    "required_tool_calls",
    "model_text_accepted",
    "pass_rule",
    "unsafe_direct_use_rule",
    "action_completed_field",
    "terminal_state_values",
  ], "workload.outcome_contract");
  assertEqual(
    {
      schema_version: contract.schema_version,
      source: contract.source,
      tool_name: contract.tool_name,
      required_tool_calls: contract.required_tool_calls,
      model_text_accepted: contract.model_text_accepted,
      pass_rule: contract.pass_rule,
      unsafe_direct_use_rule: contract.unsafe_direct_use_rule,
      action_completed_field: contract.action_completed_field,
    },
    {
      schema_version: WORKLOAD_OUTCOME_CONTRACT,
      source: "native_tool_arguments",
      tool_name: WORKLOAD_TOOL_NAME,
      required_tool_calls: 1,
      model_text_accepted: false,
      pass_rule: "choice_equals_scenario_expected_choice",
      unsafe_direct_use_rule: "choice_equals_scenario_unsafe_choice",
      action_completed_field: "passed",
    },
    "workload.outcome_contract deterministic rules",
  );
  assertExactKeys(contract.terminal_state_values, ["passed", "failed"], "workload.outcome_contract.terminal_state_values");
  assertEqual(contract.terminal_state_values, { passed: "completed", failed: "failed" }, "workload outcome terminal states");
  if (
    contract.tool_name !== toolProtocol.function.name
    || contract.required_tool_calls !== toolProtocol.exact_tool_call_count
    || contract.model_text_accepted === toolProtocol.textual_fallback_accepted && contract.model_text_accepted !== false
  ) fail("workload outcome and native tool contracts are inconsistent");
}

function validateWorkloadSchedule(schedule, workload, lock) {
  assertExactKeys(schedule, ["phase_order", "trial_order", "scope", "pilot", "soak_waves"], "workload.schedule");
  assertEqual(schedule.phase_order, ["pilot", "soak"], "workload.schedule.phase_order");
  assertEqual(schedule.trial_order, ["wave", "group", "scenario", "repetition"], "workload.schedule.trial_order");
  assertExactKeys(schedule.scope, [
    "tenant_id",
    "template",
    "partition_keys",
    "shared_across_groups",
    "shared_across_repetitions",
    "shared_across_phases",
  ], "workload.schedule.scope");
  assertEqual(schedule.scope, {
    tenant_id: "default",
    template: "bounded-soak:{harness_commit}:{campaign_id}:{scenario}",
    partition_keys: ["harness_commit", "campaign_id", "scenario"],
    shared_across_groups: true,
    shared_across_repetitions: true,
    shared_across_phases: true,
  }, "workload.schedule.scope");
  assertExactKeys(schedule.pilot, ["wave", "repetitions_per_cell", "recovery_after"], "workload.schedule.pilot");
  assertEqual(schedule.pilot, {
    wave: 1,
    repetitions_per_cell: workload.pilot.repetitions_per_cell,
    recovery_after: "none",
  }, "workload.schedule.pilot");
  if (!Array.isArray(schedule.soak_waves) || schedule.soak_waves.length !== workload.soak.waves) {
    fail("workload.schedule.soak_waves must match the frozen soak wave count");
  }
  const elapsed = [0, 43200, 86400];
  const recovery = [workload.recovery.after_wave_1, workload.recovery.after_wave_2, workload.recovery.after_wave_3];
  for (const [index, wave] of schedule.soak_waves.entries()) {
    const field = `workload.schedule.soak_waves[${index}]`;
    assertExactKeys(wave, ["wave", "not_before_elapsed_seconds", "repetitions_per_cell", "recovery_after"], field);
    assertEqual(wave, {
      wave: index + 1,
      not_before_elapsed_seconds: elapsed[index],
      repetitions_per_cell: workload.soak.repetitions_per_cell_per_wave,
      recovery_after: recovery[index],
    }, field);
  }
  const finalWaveStart = schedule.soak_waves.at(-1).not_before_elapsed_seconds;
  if (
    finalWaveStart < lock.execution_limits.minimum_duration_seconds
    || finalWaveStart > lock.execution_limits.maximum_duration_seconds
  ) fail("workload wave schedule does not satisfy frozen duration bounds");
}

function validateWorkloadTemplateSyntax(value, field) {
  if (typeof value === "string") {
    if (value.includes("{{") || value.includes("}}")) fail(field + " contains forbidden pseudo-template syntax");
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) validateWorkloadTemplateSyntax(item, field + "[" + index + "]");
    return;
  }
  const keys = Object.keys(value);
  const operators = keys.filter((key) => key.startsWith("$"));
  if (operators.length > 0) {
    if (keys.length !== 1 || operators.length !== 1 || !WORKLOAD_RENDER_OPERATORS.has(operators[0])) {
      fail(field + " must contain exactly one frozen renderer operator");
    }
    const operator = operators[0];
    const operand = value[operator];
    if (operator === "$path") {
      if (typeof operand !== "string" || !WORKLOAD_PATH_RE.test(operand)) fail(field + ".$path is invalid");
      return;
    }
    if (operator === "$concat" || operator === "$sha256_utf8_nul") {
      if (!Array.isArray(operand) || operand.length === 0) fail(field + "." + operator + " must be a non-empty array");
      for (const [index, item] of operand.entries()) validateWorkloadTemplateSyntax(item, field + "." + operator + "[" + index + "]");
      return;
    }
    if (operator === "$join") {
      assertExactKeys(operand, ["items", "separator"], field + ".$join");
      if (typeof operand.separator !== "string") fail(field + ".$join.separator must be a string");
      validateWorkloadTemplateSyntax(operand.items, field + ".$join.items");
      return;
    }
    if (operator === "$if") {
      assertExactKeys(operand, ["condition", "then", "else"], field + ".$if");
      validateWorkloadTemplateSyntax(operand.condition, field + ".$if.condition");
      validateWorkloadTemplateSyntax(operand.then, field + ".$if.then");
      validateWorkloadTemplateSyntax(operand.else, field + ".$if.else");
      return;
    }
    if (operator === "$equals") {
      if (!Array.isArray(operand) || operand.length !== 2) fail(field + ".$equals must contain two operands");
      validateWorkloadTemplateSyntax(operand[0], field + ".$equals[0]");
      validateWorkloadTemplateSyntax(operand[1], field + ".$equals[1]");
      return;
    }
    validateWorkloadTemplateSyntax(operand, field + "." + operator);
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (UNSAFE_OBJECT_KEYS.has(key)) fail(field + " contains an unsafe object key");
    validateWorkloadTemplateSyntax(item, field + "." + key);
  }
}

function validateTemplateAssertions(assertions, expected, field) {
  if (!Array.isArray(assertions) || assertions.length === 0) fail(field + " must be a non-empty array");
  for (const [index, assertion] of assertions.entries()) {
    assertExactKeys(assertion, ["path", "predicate", "expected"], field + "[" + index + "]");
    assertString(assertion.path, field + "[" + index + "].path");
    assertString(assertion.predicate, field + "[" + index + "].predicate");
    validateWorkloadTemplateSyntax(assertion.expected, field + "[" + index + "].expected");
  }
  assertEqual(assertions, expected, field);
}

function validateWorkloadRequest(contract, route, exactKeys, field) {
  if (contract.method !== "POST" || contract.route !== route) fail(field + " method or route is invalid");
  assertEqual(contract.request_exact_keys, exactKeys, field + ".request_exact_keys");
  assertExactKeys(contract.request_template, exactKeys, field + ".request_template");
  validateWorkloadTemplateSyntax(contract.request_template, field + ".request_template");
}

function workloadPath(path) {
  return { $path: path };
}

function workloadContentIdTemplate(prefix, responseShaPath) {
  return {
    $concat: [
      prefix + "-",
      {
        $sha256_utf8_nul: [
          workloadPath("trial_id"),
          workloadPath(responseShaPath),
        ],
      },
    ],
  };
}

function validateRawResponseCapture(capture, prefix, responseShaField, contentIdField, field) {
  assertExactKeys(capture, [
    "bytes_source",
    "capture_order",
    "capture_assertions",
    "ledger_settlement_paths",
    "required_before_trial_settlement",
  ], field);
  assertEqual(capture, {
    bytes_source: "exact_raw_runtime_response_bytes",
    capture_order: "before_json_parse",
    capture_assertions: [
      {
        field: responseShaField,
        predicate: "sha256_of_exact_raw_response_bytes",
        expected: null,
      },
      {
        field: contentIdField,
        predicate: "equals_rendered",
        expected: workloadContentIdTemplate(prefix, responseShaField),
      },
    ],
    ledger_settlement_paths: {
      response_sha256: "aionis." + responseShaField,
      content_id: "aionis." + contentIdField,
    },
    required_before_trial_settlement: true,
  }, field);
  validateWorkloadTemplateSyntax(capture.capture_assertions, field + ".capture_assertions");
}

function validateWorkloadExecutionTemplates(templates, workload, lock) {
  const field = "workload.execution_templates";
  assertExactKeys(templates, [
    "schema_version",
    "renderer",
    "runtime_scope_authority",
    "memory_role_surface_policy",
    "seed_observe",
    "trial_guide",
    "provider_request",
    "post_trial_runtime_contract",
  ], field);
  if (templates.schema_version !== "aionis_bounded_soak_execution_templates_v2") {
    fail("workload execution template schema is invalid");
  }
  assertExactKeys(templates.renderer, [
    "schema_version",
    "implementation",
    "path_grammar",
    "operators",
    "missing_path_policy",
    "input_mutation_policy",
    "concat_scalar_policy",
    "if_evaluation_policy",
    "hash_encoding",
  ], field + ".renderer");
  assertEqual(templates.renderer, {
    schema_version: "aionis_finite_renderer_v1",
    implementation: { module: "src/contracts.mjs", export: "renderWorkloadTemplate" },
    path_grammar: "own_object_dot_path_v1",
    operators: [...WORKLOAD_RENDER_OPERATORS],
    missing_path_policy: "fail",
    input_mutation_policy: "deep_clone",
    concat_scalar_policy: "string_number_boolean_only",
    if_evaluation_policy: "selected_branch_only",
    hash_encoding: "sha256(UTF8(part_1) || NUL || ... || UTF8(part_n))",
  }, field + ".renderer");
  assertEqual(templates.runtime_scope_authority, {
    schedule_template_field: "schedule.scope.template",
    implementation_export: "expandWorkloadScope",
    binding_paths: {
      harness_commit: "harness_commit",
      campaign_id: "campaign_id",
      scenario: "scenario.id",
    },
    rendered_field: "campaign_scope",
    required_equal_field: "preclaim.scope",
  }, field + ".runtime_scope_authority");
  assertEqual(templates.memory_role_surface_policy, {
    schema_version: "aionis_memory_role_surface_policy_v1",
    binding_chain: [
      "workload_seed_role",
      "observe_response_client_id_memory_id",
      "guide_memory_packet_execution_role",
      "guide_feedback_attribution_served_surface",
      "guide_agent_context_served_surface",
    ],
    expected_surface_by_role: {
      passed_solution: "use_now",
      failed_branch: "do_not_use",
      summary_only: "inspect_before_use",
    },
    per_memory_join_required: true,
    guide_attribution_status: "available",
    guide_projection_complete: true,
    feedback_admission_status: "verified_host_receipt",
    trusted_transport_collector_required: true,
  }, field + ".memory_role_surface_policy");
  validateWorkloadTemplateSyntax(templates, field);

  const seed = templates.seed_observe;
  assertExactKeys(seed, [
    "method",
    "route",
    "applies_to_groups",
    "cadence",
    "request_variants",
    "response_assertions",
  ], field + ".seed_observe");
  if (
    seed.method !== "POST"
    || seed.route !== "/v1/observe"
    || seed.cadence !== "once_per_campaign_scenario_seed_observation_before_pilot"
  ) fail("workload seed observe route or cadence is invalid");
  assertEqual(seed.applies_to_groups, ["aionis"], field + ".seed_observe.applies_to_groups");
  assertExactKeys(seed.request_variants, ["execution_tree", "summary_only_memory"], field + ".seed_observe.request_variants");
  const executionSeed = seed.request_variants.execution_tree;
  assertExactKeys(executionSeed, ["request_exact_keys", "request_template"], field + ".seed_observe.request_variants.execution_tree");
  validateWorkloadRequest(
    { ...executionSeed, method: seed.method, route: seed.route },
    "/v1/observe",
    ["operation_id", "tenant_id", "scope", "input_text", "memory_kind", "auto_embed", "execution"],
    field + ".seed_observe.request_variants.execution_tree",
  );
  const summarySeed = seed.request_variants.summary_only_memory;
  assertExactKeys(summarySeed, ["request_exact_keys", "request_template"], field + ".seed_observe.request_variants.summary_only_memory");
  validateWorkloadRequest(
    { ...summarySeed, method: seed.method, route: seed.route },
    "/v1/observe",
    ["operation_id", "tenant_id", "scope", "input_text", "memory_kind", "auto_embed"],
    field + ".seed_observe.request_variants.summary_only_memory",
  );
  const seedOperationTemplate = {
    $concat: [
      "seed-",
      {
        $sha256_utf8_nul: [
          workloadPath("campaign_id"),
          workloadPath("scenario.id"),
          workloadPath("seed_observation.operation_key"),
        ],
      },
    ],
  };
  assertEqual(executionSeed.request_template.operation_id, seedOperationTemplate, field + ".seed_observe execution operation ID");
  assertEqual(summarySeed.request_template.operation_id, seedOperationTemplate, field + ".seed_observe summary operation ID");
  assertEqual(
    {
      tenant_id: executionSeed.request_template.tenant_id,
      scope: executionSeed.request_template.scope,
      input_text: executionSeed.request_template.input_text,
      memory_kind: executionSeed.request_template.memory_kind,
      auto_embed: executionSeed.request_template.auto_embed,
    },
    {
      tenant_id: workloadPath("schedule.scope.tenant_id"),
      scope: workloadPath("campaign_scope"),
      input_text: workloadPath("seed_observation.input_text"),
      memory_kind: workloadPath("seed_observation.memory_kind"),
      auto_embed: true,
    },
    field + ".seed_observe common bindings",
  );
  assertExactKeys(executionSeed.request_template.execution, [
    "run_id",
    "task_id",
    "task_family",
    "task_signature",
    "workflow_signature",
    "title",
    "summary",
    "outcome",
    "acceptance_checks",
    "verifier",
    "continuation_hint",
    "confidence",
    "evidence_ref",
    "raw_ref",
    "evidence",
    "verification",
    "slots",
  ], field + ".seed_observe execution evidence");
  assertExactKeys(executionSeed.request_template.execution.evidence[0], [
    "kind", "branch_role", "raw_ref", "verifier_id", "verifier_status", "result",
  ], field + ".seed_observe execution evidence[0]");
  assertExactKeys(executionSeed.request_template.execution.verification, [
    "verifier_id", "status", "expected", "observed", "detail",
  ], field + ".seed_observe execution verification");
  assertExactKeys(executionSeed.request_template.execution.slots, [
    "execution_outcome_role", "evidence_class", "branch_choice",
  ], field + ".seed_observe execution slots");
  validateTemplateAssertions(seed.response_assertions, [
    { path: "operation_id", predicate: "equals_rendered", expected: workloadPath("request.operation_id") },
    { path: "tenant_id", predicate: "equals_rendered", expected: workloadPath("request.tenant_id") },
    { path: "scope", predicate: "equals_rendered", expected: workloadPath("request.scope") },
    { path: "observed.memory_written", predicate: "equals_literal", expected: true },
    { path: "post_commit_projections.semantic_commit", predicate: "equals_literal", expected: "committed" },
  ], field + ".seed_observe.response_assertions");

  const guide = templates.trial_guide;
  assertExactKeys(guide, [
    "method", "route", "applies_to_groups", "request_exact_keys", "request_template", "response_assertions",
  ], field + ".trial_guide");
  assertEqual(guide.applies_to_groups, ["aionis"], field + ".trial_guide.applies_to_groups");
  validateWorkloadRequest(
    guide,
    "/v1/guide",
    ["operation_id", "tenant_id", "scope", "query_text", "context_mode", "include_packets"],
    field + ".trial_guide",
  );
  assertEqual(guide.request_template, {
    operation_id: workloadPath("preclaim.guide_operation_id"),
    tenant_id: workloadPath("schedule.scope.tenant_id"),
    scope: workloadPath("preclaim.scope"),
    query_text: workloadPath("scenario.task"),
    context_mode: "compact_agent",
    include_packets: true,
  }, field + ".trial_guide.request_template");
  validateTemplateAssertions(guide.response_assertions, [
    { path: "operation_id", predicate: "equals_rendered", expected: workloadPath("preclaim.guide_operation_id") },
    { path: "guide_trace_id", predicate: "nonempty_string", expected: null },
    { path: "agent_context.prompt_text", predicate: "nonempty_string", expected: null },
    { path: "agent_context.agent_prompt", predicate: "absent", expected: null },
  ], field + ".trial_guide.response_assertions");

  const provider = templates.provider_request;
  assertExactKeys(provider, [
    "method",
    "route",
    "routing_variability_boundary",
    "request_exact_keys",
    "forbidden_template_paths",
    "request_template",
    "response_assertions",
  ], field + ".provider_request");
  validateWorkloadRequest(provider, "/api/v1/chat/completions", [
    "model",
    "messages",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "provider",
    "stream",
    "temperature",
    "top_p",
    "max_tokens",
  ], field + ".provider_request");
  assertEqual(provider.routing_variability_boundary, {
    status: "known_variability",
    provider_identity: "not_frozen",
    reason: "The authority manifest freezes the OpenRouter model but not an underlying provider identity.",
    frozen_request_fields: ["provider.allow_fallbacks", "provider.require_parameters"],
    unfrozen_request_fields: ["provider.order", "provider.only"],
    preflight_policy: "reject_order_or_only_without_new_frozen_authority",
  }, field + ".provider_request.routing_variability_boundary");
  assertEqual(provider.forbidden_template_paths, [
    "scenario.expected_choice",
    "scenario.unsafe_choice",
    "outcome_contract.pass_rule",
    "outcome_contract.unsafe_direct_use_rule",
  ], field + ".provider_request.forbidden_template_paths");
  const providerTemplateSource = JSON.stringify(provider.request_template);
  for (const forbidden of provider.forbidden_template_paths) {
    if (providerTemplateSource.includes(forbidden)) fail("provider-visible request leaks verifier-only path " + forbidden);
  }
  assertExactKeys(provider.request_template.provider, ["allow_fallbacks", "require_parameters"], field + ".provider_request.request_template.provider");
  assertEqual(provider.request_template.provider, { allow_fallbacks: false, require_parameters: true }, field + ".provider_request.request_template.provider");
  if (Object.hasOwn(provider.request_template.provider, "order") || Object.hasOwn(provider.request_template.provider, "only")) {
    fail("workload provider order/only must remain unfrozen");
  }
  assertEqual(
    {
      model: provider.request_template.model,
      tool_choice: provider.request_template.tool_choice,
      parallel_tool_calls: provider.request_template.parallel_tool_calls,
      stream: provider.request_template.stream,
      temperature: provider.request_template.temperature,
      top_p: provider.request_template.top_p,
      max_tokens: provider.request_template.max_tokens,
    },
    {
      model: workloadPath("release_lock.providers.agent.requested_model"),
      tool_choice: "required",
      parallel_tool_calls: false,
      stream: false,
      temperature: workloadPath("release_lock.generation.temperature"),
      top_p: workloadPath("release_lock.generation.top_p"),
      max_tokens: workloadPath("release_lock.generation.max_output_tokens"),
    },
    field + ".provider_request frozen bindings",
  );
  if (lock.providers.agent.fallback_allowed !== provider.request_template.provider.allow_fallbacks) {
    fail("workload provider fallback routing contradicts the release lock");
  }
  if (!Array.isArray(provider.request_template.tools) || provider.request_template.tools.length !== 1) {
    fail("workload provider request must contain exactly one native tool");
  }
  assertEqual(provider.request_template.tools[0], {
    type: "function",
    function: {
      name: workloadPath("tool_protocol.function.name"),
      description: workloadPath("tool_protocol.function.description"),
      parameters: workloadPath("tool_protocol.function.arguments_schema"),
      strict: true,
    },
  }, field + ".provider_request native tool binding");
  validateTemplateAssertions(provider.response_assertions, [
    { path: "id", predicate: "nonempty_string", expected: null },
    { path: "choices[0].message.tool_calls", predicate: "exactly_one_named_tool_call", expected: WORKLOAD_TOOL_NAME },
    { path: "choices[0].message.content", predicate: "null_or_empty", expected: null },
  ], field + ".provider_request.response_assertions");

  const post = templates.post_trial_runtime_contract;
  assertExactKeys(post, [
    "applies_to_groups",
    "route_order",
    "outcome_observe",
    "feedback",
    "measure",
    "operator_snapshot",
    "flight_recorder",
    "missing_template_policy",
  ], field + ".post_trial_runtime_contract");
  assertEqual(post.applies_to_groups, ["aionis"], field + ".post_trial_runtime_contract.applies_to_groups");
  assertEqual(post.route_order, [
    "/v1/observe",
    "/v1/feedback",
    "/v1/measure",
    "/v1/operator/snapshot",
    "/v1/audit/flight-recorder",
  ], field + ".post_trial_runtime_contract.route_order");
  if (post.missing_template_policy !== "fail_campaign_preflight") fail("workload post-trial templates must fail at campaign preflight");

  const outcome = post.outcome_observe;
  assertExactKeys(outcome, ["method", "route", "request_exact_keys", "request_template", "response_assertions"], field + ".post_trial_runtime_contract.outcome_observe");
  validateWorkloadRequest(outcome, post.route_order[0], [
    "operation_id", "tenant_id", "scope", "input_text", "memory_kind", "auto_embed", "execution",
  ], field + ".post_trial_runtime_contract.outcome_observe");
  assertEqual(
    {
      operation_id: outcome.request_template.operation_id,
      tenant_id: outcome.request_template.tenant_id,
      scope: outcome.request_template.scope,
      memory_kind: outcome.request_template.memory_kind,
      auto_embed: outcome.request_template.auto_embed,
    },
    {
      operation_id: workloadPath("preclaim.outcome_operation_id"),
      tenant_id: workloadPath("schedule.scope.tenant_id"),
      scope: workloadPath("preclaim.scope"),
      memory_kind: "execution_workflow",
      auto_embed: true,
    },
    field + ".post_trial_runtime_contract.outcome_observe bindings",
  );
  assertExactKeys(outcome.request_template.execution, [
    "run_id",
    "task_id",
    "task_family",
    "task_signature",
    "workflow_signature",
    "title",
    "summary",
    "outcome",
    "acceptance_checks",
    "verifier",
    "continuation_hint",
    "confidence",
    "evidence_ref",
    "raw_ref",
    "evidence",
    "verification",
    "slots",
  ], field + ".post_trial_runtime_contract.outcome_observe.execution");
  assertExactKeys(outcome.request_template.execution.evidence[0], [
    "kind", "provider_request_id", "tool_result",
  ], field + ".post_trial_runtime_contract.outcome_observe.execution.evidence[0]");
  assertExactKeys(outcome.request_template.execution.verification, [
    "verifier_id", "provider_request_id", "expected_choice", "observed_choice", "status",
  ], field + ".post_trial_runtime_contract.outcome_observe.execution.verification");
  assertExactKeys(outcome.request_template.execution.slots, [
    "execution_outcome_role", "evidence_class",
  ], field + ".post_trial_runtime_contract.outcome_observe.execution.slots");
  validateTemplateAssertions(outcome.response_assertions, [
    { path: "operation_id", predicate: "equals_rendered", expected: workloadPath("preclaim.outcome_operation_id") },
    { path: "post_commit_projections.semantic_commit", predicate: "equals_literal", expected: "committed" },
  ], field + ".post_trial_runtime_contract.outcome_observe.response_assertions");

  const feedback = post.feedback;
  assertExactKeys(feedback, [
    "method",
    "route",
    "request_exact_keys",
    "served_memory_selection",
    "request_template",
    "response_assertions",
  ], field + ".post_trial_runtime_contract.feedback");
  validateWorkloadRequest(feedback, post.route_order[1], [
    "operation_id",
    "tenant_id",
    "scope",
    "reason",
    "run_id",
    "guide_trace_id",
    "used_memory_ids",
    "outcome",
    "used_surface",
    "verifier_status",
    "tool_status",
    "runtime_signal_refs",
  ], field + ".post_trial_runtime_contract.feedback");
  assertEqual(feedback.served_memory_selection, {
    implementation_export: "selectWorkloadServedMemory",
    ordered_surfaces: ["use_now", "inspect_before_use", "do_not_use"],
    id_fields: {
      use_now: "guide_response.agent_context.use_now_memory_ids",
      inspect_before_use: "guide_response.agent_context.inspect_before_use_memory_ids",
      do_not_use: "guide_response.agent_context.do_not_use_memory_ids",
    },
    rule: "first_nonempty_surface",
    empty_selection_policy: "fail_trial_before_feedback",
  }, field + ".post_trial_runtime_contract.feedback.served_memory_selection");
  assertEqual(
    {
      operation_id: feedback.request_template.operation_id,
      tenant_id: feedback.request_template.tenant_id,
      scope: feedback.request_template.scope,
      run_id: feedback.request_template.run_id,
      guide_trace_id: feedback.request_template.guide_trace_id,
      used_memory_ids: feedback.request_template.used_memory_ids,
      tool_status: feedback.request_template.tool_status,
    },
    {
      operation_id: workloadPath("preclaim.feedback_operation_id"),
      tenant_id: workloadPath("schedule.scope.tenant_id"),
      scope: workloadPath("preclaim.scope"),
      run_id: workloadPath("trial_id"),
      guide_trace_id: workloadPath("guide_response.guide_trace_id"),
      used_memory_ids: workloadPath("served_memory_selection.ids"),
      tool_status: "succeeded",
    },
    field + ".post_trial_runtime_contract.feedback bindings",
  );
  validateTemplateAssertions(feedback.response_assertions, [
    { path: "operation_id", predicate: "equals_rendered", expected: workloadPath("preclaim.feedback_operation_id") },
    { path: "learning_feedback_event_id", predicate: "nonempty_string", expected: null },
  ], field + ".post_trial_runtime_contract.feedback.response_assertions");

  const measure = post.measure;
  assertExactKeys(measure, ["method", "route", "request_exact_keys", "request_template", "response_assertions"], field + ".post_trial_runtime_contract.measure");
  validateWorkloadRequest(measure, post.route_order[2], [
    "operation_id", "tenant_id", "scope", "task", "product_trace", "evidence_ids",
  ], field + ".post_trial_runtime_contract.measure");
  assertEqual(
    {
      operation_id: measure.request_template.operation_id,
      tenant_id: measure.request_template.tenant_id,
      scope: measure.request_template.scope,
    },
    {
      operation_id: workloadPath("preclaim.measure_operation_id"),
      tenant_id: workloadPath("schedule.scope.tenant_id"),
      scope: workloadPath("preclaim.scope"),
    },
    field + ".post_trial_runtime_contract.measure bindings",
  );
  assertExactKeys(measure.request_template.task, [
    "task_id", "run_id", "task_signature", "task_family", "workflow_signature",
  ], field + ".post_trial_runtime_contract.measure.task");
  assertExactKeys(measure.request_template.product_trace, [
    "baseline", "after_guide", "forget_result", "evidence_ids", "sufficient_evidence",
  ], field + ".post_trial_runtime_contract.measure.product_trace");
  assertExactKeys(measure.request_template.product_trace.baseline, [
    "label", "continuity", "learning_control",
  ], field + ".post_trial_runtime_contract.measure.product_trace.baseline");
  assertExactKeys(measure.request_template.product_trace.baseline.continuity, [
    "continuityGuidanceCorrect",
  ], field + ".post_trial_runtime_contract.measure.product_trace.baseline.continuity");
  assertExactKeys(measure.request_template.product_trace.baseline.learning_control, [
    "authorityRequiresEvidence", "blockedAuthorityVisible", "unverifiedAuthorityApplied",
  ], field + ".post_trial_runtime_contract.measure.product_trace.baseline.learning_control");
  if (measure.request_template.product_trace.sufficient_evidence !== true) fail("workload measure must require sufficient evidence");
  validateTemplateAssertions(measure.response_assertions, [
    { path: "operation_id", predicate: "equals_rendered", expected: workloadPath("preclaim.measure_operation_id") },
    { path: "measurement_id", predicate: "nonempty_string", expected: null },
  ], field + ".post_trial_runtime_contract.measure.response_assertions");

  const snapshot = post.operator_snapshot;
  assertExactKeys(snapshot, [
    "method", "route", "request_exact_keys", "request_template", "raw_response_capture", "response_assertions",
  ], field + ".post_trial_runtime_contract.operator_snapshot");
  validateWorkloadRequest(snapshot, post.route_order[3], [
    "tenant_id",
    "scope",
    "run_id",
    "task_signature",
    "task_family",
    "workflow_signature",
    "agent_context",
    "guide_packet",
    "guide_trace_id",
    "include_markdown",
  ], field + ".post_trial_runtime_contract.operator_snapshot");
  assertEqual(snapshot.request_template, {
    tenant_id: workloadPath("schedule.scope.tenant_id"),
    scope: workloadPath("preclaim.scope"),
    run_id: workloadPath("trial_id"),
    task_signature: { $concat: ["bounded-soak:", workloadPath("scenario.id")] },
    task_family: "aionis_bounded_soak",
    workflow_signature: "bounded-soak-native-tool-v1",
    agent_context: workloadPath("guide_response.agent_context"),
    guide_packet: workloadPath("guide_response.guide_packet"),
    guide_trace_id: workloadPath("guide_response.guide_trace_id"),
    include_markdown: false,
  }, field + ".post_trial_runtime_contract.operator_snapshot.request_template");
  validateRawResponseCapture(
    snapshot.raw_response_capture,
    "snapshot",
    "snapshot_response_sha256",
    "snapshot_id",
    field + ".post_trial_runtime_contract.operator_snapshot.raw_response_capture",
  );
  validateTemplateAssertions(snapshot.response_assertions, [
    { path: "contract_version", predicate: "equals_literal", expected: "aionis_operator_snapshot_result_v1" },
    { path: "tenant_id", predicate: "equals_rendered", expected: workloadPath("request.tenant_id") },
    { path: "scope", predicate: "equals_rendered", expected: workloadPath("request.scope") },
    { path: "operator_snapshot", predicate: "object", expected: null },
    { path: "markdown", predicate: "absent", expected: null },
  ], field + ".post_trial_runtime_contract.operator_snapshot.response_assertions");

  const recorder = post.flight_recorder;
  assertExactKeys(recorder, [
    "method", "route", "request_exact_keys", "request_template", "raw_response_capture", "response_assertions",
  ], field + ".post_trial_runtime_contract.flight_recorder");
  validateWorkloadRequest(recorder, post.route_order[4], [
    "tenant_id",
    "scope",
    "guide_trace_id",
    "run_id",
    "product_trace",
    "agent_context",
    "operator_snapshot",
    "feedback_result",
  ], field + ".post_trial_runtime_contract.flight_recorder");
  assertEqual(recorder.request_template, {
    tenant_id: workloadPath("schedule.scope.tenant_id"),
    scope: workloadPath("preclaim.scope"),
    guide_trace_id: workloadPath("guide_response.guide_trace_id"),
    run_id: workloadPath("trial_id"),
    product_trace: workloadPath("measure_request.product_trace"),
    agent_context: workloadPath("guide_response.agent_context"),
    operator_snapshot: workloadPath("operator_snapshot_response.operator_snapshot"),
    feedback_result: workloadPath("feedback_response"),
  }, field + ".post_trial_runtime_contract.flight_recorder.request_template");
  validateRawResponseCapture(
    recorder.raw_response_capture,
    "recorder",
    "recorder_response_sha256",
    "recorder_id",
    field + ".post_trial_runtime_contract.flight_recorder.raw_response_capture",
  );
  validateTemplateAssertions(recorder.response_assertions, [
    { path: "contract_version", predicate: "equals_literal", expected: "aionis_agent_flight_recorder_result_v1" },
    { path: "tenant_id", predicate: "equals_rendered", expected: workloadPath("request.tenant_id") },
    { path: "scope", predicate: "equals_rendered", expected: workloadPath("request.scope") },
    { path: "agent_flight_recorder", predicate: "object", expected: null },
  ], field + ".post_trial_runtime_contract.flight_recorder.response_assertions");
}
export function validateWorkloadManifest(workload, lock) {
  validateReleaseLock(lock);
  assertExactKeys(workload, [
    "schema_version",
    "frozen_at",
    "groups",
    "context_sources",
    "scenarios",
    "scenario_definitions",
    "tool_protocol",
    "outcome_contract",
    "schedule",
    "id_provenance",
    "execution_templates",
    "product_invariants",
    "pilot",
    "soak",
    "verifier",
    "recovery",
  ], "workload manifest");
  if (workload.schema_version !== "aionis_soak_workload_manifest_v2") fail("workload schema_version is invalid");
  assertDate(workload.frozen_at, "workload.frozen_at");
  assertUniqueStrings(workload.groups, "workload.groups");
  assertUniqueStrings(workload.scenarios, "workload.scenarios");
  assertUniqueStrings(workload.product_invariants, "workload.product_invariants");
  assertEqual(workload.context_sources, WORKLOAD_CONTEXT_SOURCES, "workload.context_sources");
  const allChoices = validateWorkloadScenarioDefinitions(workload.scenario_definitions, workload.scenarios);
  validateWorkloadToolProtocol(workload.tool_protocol, workload.scenarios, allChoices);
  validateWorkloadOutcomeContract(workload.outcome_contract, workload.tool_protocol);
  assertEqual(workload.id_provenance, WORKLOAD_ID_PROVENANCE, "workload.id_provenance");
  assertExactKeys(workload.pilot, ["repetitions_per_cell", "semantic_chat_calls", "aionis_trials"], "workload.pilot");
  assertExactKeys(workload.soak, [
    "repetitions_per_cell_per_wave",
    "semantic_chat_calls",
    "waves",
    "semantic_chat_calls_per_wave",
    "aionis_trials_per_wave",
    "total_aionis_trials",
    "negative_transfer_trials",
  ], "workload.soak");
  for (const [key, value] of Object.entries(workload.pilot)) assertInteger(value, `workload.pilot.${key}`);
  for (const [key, value] of Object.entries(workload.soak)) assertInteger(value, `workload.soak.${key}`);
  assertExactKeys(workload.verifier, [
    "real_tools",
    "native_tool_calling",
    "deterministic_outcome_verifier",
    "outcome_contract",
    "model_self_report_accepted",
  ], "workload.verifier");
  assertEqual(workload.verifier, {
    real_tools: true,
    native_tool_calling: true,
    deterministic_outcome_verifier: true,
    outcome_contract: WORKLOAD_OUTCOME_CONTRACT,
    model_self_report_accepted: false,
  }, "workload.verifier");
  if (workload.verifier.outcome_contract !== workload.outcome_contract.schema_version) {
    fail("workload verifier and outcome contract versions are inconsistent");
  }
  assertExactKeys(workload.recovery, ["after_wave_1", "after_wave_2", "after_wave_3"], "workload.recovery");
  assertEqual(workload.recovery, {
    after_wave_1: "graceful_replacement",
    after_wave_2: "sigkill_replacement",
    after_wave_3: "offline_sqlite_verify",
  }, "workload.recovery");
  validateWorkloadSchedule(workload.schedule, workload, lock);
  validateWorkloadExecutionTemplates(workload.execution_templates, workload, lock);
  assertEqual(workload.groups, lock.protocol.groups, "workload.groups");
  assertEqual(workload.scenarios, lock.protocol.scenarios, "workload.scenarios");
  assertEqual(workload.product_invariants, lock.protocol.product_invariants, "workload.product_invariants");
  assertEqual(
    { semantic_chat_calls: workload.pilot.semantic_chat_calls, aionis_trials: workload.pilot.aionis_trials },
    lock.protocol.pilot,
    "workload.pilot denominators",
  );
  assertEqual(
    {
      semantic_chat_calls: workload.soak.semantic_chat_calls,
      waves: workload.soak.waves,
      semantic_chat_calls_per_wave: workload.soak.semantic_chat_calls_per_wave,
      aionis_trials_per_wave: workload.soak.aionis_trials_per_wave,
      total_aionis_trials: workload.soak.total_aionis_trials,
      negative_transfer_trials: workload.soak.negative_transfer_trials,
    },
    lock.protocol.soak,
    "workload.soak denominators",
  );
  const cells = workload.groups.length * workload.scenarios.length;
  if (workload.pilot.semantic_chat_calls !== cells * workload.pilot.repetitions_per_cell) fail("pilot matrix denominator is inconsistent");
  if (workload.soak.semantic_chat_calls_per_wave !== cells * workload.soak.repetitions_per_cell_per_wave) fail("soak matrix denominator is inconsistent");
  if (workload.soak.semantic_chat_calls !== workload.soak.waves * workload.soak.semantic_chat_calls_per_wave) fail("soak total denominator is inconsistent");
  if (workload.pilot.aionis_trials !== workload.scenarios.length * workload.pilot.repetitions_per_cell) fail("pilot Aionis denominator is inconsistent");
  if (workload.soak.aionis_trials_per_wave !== workload.scenarios.length * workload.soak.repetitions_per_cell_per_wave) fail("soak Aionis denominator is inconsistent");
  if (workload.soak.total_aionis_trials !== workload.soak.waves * workload.soak.aionis_trials_per_wave) fail("soak total Aionis denominator is inconsistent");
  if (workload.soak.negative_transfer_trials !== workload.soak.waves * workload.soak.repetitions_per_cell_per_wave) fail("soak negative-transfer denominator is inconsistent");
  assertNoSecretMaterial(workload, "workload manifest");
  return workload;
}

export function validateFrozenContracts({ lock, authority, workload }) {
  validateAuthorityManifest(authority, lock);
  validateWorkloadManifest(workload, lock);
  if (!(Date.parse(authority.authorized_at) <= Date.parse(workload.frozen_at))) {
    fail("workload must be frozen at or after authority authorization");
  }
  return { lock, authority, workload };
}

export function buildTrialPlan(mode, workload) {
  if (mode !== "pilot" && mode !== "soak") fail("trial plan mode must be pilot or soak");
  const plan = [];
  const waves = mode === "pilot" ? 1 : workload.soak.waves;
  const repetitions = mode === "pilot"
    ? workload.pilot.repetitions_per_cell
    : workload.soak.repetitions_per_cell_per_wave;
  for (let wave = 1; wave <= waves; wave += 1) {
    for (const group of workload.groups) {
      for (const scenario of workload.scenarios) {
        for (let repetition = 1; repetition <= repetitions; repetition += 1) {
          plan.push({ wave, group, scenario, repetition });
        }
      }
    }
  }
  const expected = mode === "pilot" ? workload.pilot.semantic_chat_calls : workload.soak.semantic_chat_calls;
  if (plan.length !== expected) fail(`${mode} trial plan does not match frozen denominator`);
  return plan;
}

export function validateReturnedModel(returnedModel, authority) {
  assertString(returnedModel, "returned model");
  if (!authority.providers.agent.allowed_returned_models.includes(returnedModel)) {
    fail(`returned model ${returnedModel} is outside the frozen allowlist`);
  }
  return returnedModel;
}

export function validateArtifactBundleManifest(manifest, lock, expectedHarnessCommit = null) {
  validateReleaseLock(lock);
  assertExactKeys(manifest, ["schema_version", "generated_at", "candidate", "harness_commit", "source_workflow", "publisher_workflow", "entries"], "artifact manifest");
  if (manifest.schema_version !== "aionis_soak_artifact_bundle_manifest_v1") fail("artifact manifest schema_version is invalid");
  assertDate(manifest.generated_at, "artifact manifest.generated_at");
  assertExactKeys(manifest.candidate, ["commit", "digest"], "artifact manifest.candidate");
  assertEqual(manifest.candidate, { commit: lock.candidate.commit, digest: lock.candidate.digest }, "artifact manifest.candidate");
  assertPattern(manifest.harness_commit, COMMIT_RE, "artifact manifest.harness_commit");
  if (expectedHarnessCommit !== null && manifest.harness_commit !== expectedHarnessCommit) fail("artifact manifest harness commit is invalid");
  assertExactKeys(manifest.source_workflow, ["repository", "run_id", "run_attempt", "head_sha", "phase", "job", "environment"], "artifact manifest.source_workflow");
  if (manifest.source_workflow.repository !== EVAL_REPOSITORY_SLUG) fail("artifact manifest workflow repository is invalid");
  assertInteger(manifest.source_workflow.run_id, "artifact manifest.source_workflow.run_id");
  assertInteger(manifest.source_workflow.run_attempt, "artifact manifest.source_workflow.run_attempt");
  if (manifest.source_workflow.head_sha !== manifest.harness_commit) fail("artifact manifest workflow HEAD must equal harness commit");
  if (
    manifest.source_workflow.phase !== "soak"
    || manifest.source_workflow.job !== "paid-preflight"
    || manifest.source_workflow.environment !== PROTECTED_ENVIRONMENT
  ) fail("artifact manifest must bind the protected soak job");
  assertExactKeys(manifest.publisher_workflow, ["repository", "run_id", "run_attempt", "head_sha", "phase", "job", "environment"], "artifact manifest.publisher_workflow");
  assertEqual(
    manifest.publisher_workflow,
    {
      repository: EVAL_REPOSITORY_SLUG,
      run_id: manifest.source_workflow.run_id,
      run_attempt: manifest.source_workflow.run_attempt,
      head_sha: manifest.harness_commit,
      phase: "publisher",
      job: "evidence-publisher",
      environment: PUBLISHER_ENVIRONMENT,
    },
    "artifact manifest.publisher_workflow",
  );
  if (!Array.isArray(manifest.entries)) fail("artifact manifest.entries must be an array");
  const expectedKinds = [...lock.artifact_contract.required_kinds].sort();
  const actualKinds = manifest.entries.map((entry) => entry?.kind).sort();
  assertEqual(actualKinds, expectedKinds, "artifact manifest entry kinds");
  const uriPrefix = `${lock.artifact_contract.release_repository}/releases/download/`;
  const expectedReleaseTag = `soak-v${lock.candidate.version}-${manifest.harness_commit}`;
  for (const [index, entry] of manifest.entries.entries()) {
    assertExactKeys(entry, ["kind", "uri", "sha256", "bytes"], `artifact manifest.entries[${index}]`);
    assertString(entry.kind, `artifact manifest.entries[${index}].kind`);
    assertString(entry.uri, `artifact manifest.entries[${index}].uri`);
    if (!entry.uri.startsWith(uriPrefix) || !/^https:\/\/github\.com\/[0-9A-Za-z_.-]+\/[0-9A-Za-z_.-]+\/releases\/download\/[0-9A-Za-z._-]+\/[0-9A-Za-z._-]+$/.test(entry.uri)) {
      fail(`artifact manifest.entries[${index}].uri is not an immutable evaluation release URI`);
    }
    assertPattern(entry.sha256, SHA256_RE, `artifact manifest.entries[${index}].sha256`);
    assertInteger(entry.bytes, `artifact manifest.entries[${index}].bytes`);
    if (entry.bytes > MAX_ARTIFACT_BYTES) fail(`artifact manifest.entries[${index}].bytes exceeds 8 MiB`);
    const uri = new URL(entry.uri);
    const components = uri.pathname.split("/").filter(Boolean);
    const releaseTag = components.at(-2);
    const assetName = components.at(-1);
    if (releaseTag !== expectedReleaseTag) fail(`artifact manifest.entries[${index}] release tag is not frozen`);
    if (!new RegExp(`^${entry.kind}-${entry.sha256}\\.jsonl$`).test(assetName ?? "")) {
      fail(`artifact manifest.entries[${index}] asset name is not content addressed`);
    }
  }
  assertNoSecretMaterial(manifest, "artifact manifest");
  return manifest;
}
