import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  COMMIT_RE,
  DIGEST_RE,
  EVAL_REPOSITORY_SLUG,
  PROTECTED_ENVIRONMENT,
  buildTrialPlan,
  expandWorkloadScope,
  renderWorkloadTemplate,
  selectWorkloadServedMemory,
  validateFrozenContracts,
} from "./contracts.mjs";
import {
  putEvidenceJsonBody,
  parseStrictJsonBytes,
  readEvidenceJsonBody,
  validateEvidenceCasRef,
  verifyEvidenceJsonBody,
} from "./evidence-cas.mjs";
import {
  assertCanonicalProviderRequest,
  createCanonicalProviderRequest,
  createProviderExecutionContract,
  hydrateProviderExecutionContract,
  OPENROUTER_COST_MICROUSD_RULE,
  parseOpenRouterChatCompletion,
} from "./provider-boundary.mjs";
import {
  POST_TRIAL_STAGES,
  createCanonicalPostTrialRequest,
  createPostTrialExecution,
  derivePostTrialSettlementFacts,
  parsePostTrialRuntimeResponse,
} from "./post-trial-boundary.mjs";
import { acquireExclusiveLock } from "./exclusive-lock.mjs";
import {
  OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER,
  assertOfflineSqliteLedgerFacts,
  assertRecoveryEvidenceBoundary,
  deriveRecoveryCheckpointEvidence,
  inspectOfflineSqliteEvidence,
} from "./recovery-evidence-boundary.mjs";

const ENVELOPE_SCHEMA = "aionis_campaign_ledger_envelope_v1";
const PAYLOAD_SCHEMA = "aionis_campaign_ledger_v3";
const LEDGER_NAME = "campaign-ledger.json";
const LOCK_NAME = ".campaign-ledger.lock";
const MAX_LEDGER_BYTES = 8 * 1024 * 1024;
const MAX_CONTRACT_SOURCE_BYTES = 8 * 1024 * 1024;
const SOAK_WAVES = 3;
const PILOT_ADMISSION_SCHEMA = "aionis_pilot_admission_receipt_v4";
const WAVE_ADMISSION_SCHEMA = "aionis_wave_admission_receipt_v3";
const FINAL_SOAK_ADMISSION_SCHEMA = "aionis_final_soak_admission_receipt_v1";
const TRIAL_SUCCESS_SCHEMA = "aionis_trial_settlement_receipt_v2";
const TRIAL_FAILURE_SCHEMA = "aionis_trial_failure_receipt_v1";
const PROVIDER_RESPONSE_SCHEMA = "aionis_provider_response_checkpoint_v3";
const GUIDE_RESPONSE_SCHEMA = "aionis_guide_runtime_response_checkpoint_v2";
const POST_TRIAL_DURABLE_SCHEMA = "aionis_post_trial_durable_checkpoint_v1";
const TOOL_RESULT_SCHEMA = "aionis_bounded_soak_tool_result_v1";
const OUTCOME_CONTRACT_SCHEMA = "aionis_bounded_soak_outcome_v1";
const SEED_CONTRACT_SCHEMA = "aionis_campaign_seed_contract_v1";
const SEED_RESPONSE_SCHEMA = "aionis_seed_runtime_response_checkpoint_v1";
const RECOVERY_CHECKPOINT_SCHEMA = "aionis_worker_state_v2";
const OFFLINE_SQLITE_SCHEMA = "aionis_offline_sqlite_verify_v2";
const PRODUCT_INVARIANTS = Object.freeze([
  "golden_product_loop",
  "product_loop",
  "ordinary_memory_loop",
  "single_agent_loop",
  "multi_agent_loop",
]);
const ZERO_BACKLOG = Object.freeze({ dead_letter: 0, provider_mismatch: 0, exhausted: 0 });
export const TRUSTED_TRANSPORT_COLLECTOR_BLOCKER = "trusted_transport_collector_unavailable";
const BLOCKED_TRANSPORT_AUTHORITY = Object.freeze({
  schema_version: "aionis_transport_authority_v1",
  status: "blocked",
  reason_code: TRUSTED_TRANSPORT_COLLECTOR_BLOCKER,
});
const campaignOfflineInspectionBindings = new WeakMap();
const SERVED_SURFACES = Object.freeze(["use_now", "inspect_before_use", "do_not_use"]);
const EXECUTION_OUTCOME_ROLES = new Set(["passed_solution", "failed_branch"]);
const FAILURE_REASONS = new Set([
  "transport_exhausted",
  "provider_mismatch",
  "runtime_rejected",
  "verification_failed",
  "interrupted_ambiguous",
]);
const FAILURE_STAGES = new Set([
  "pre_request",
  "guide",
  "provider_request",
  "outcome",
  "feedback",
  "measure",
  "operator_snapshot",
  "flight_recorder",
  "verification",
]);

function fail(message) {
  throw new Error(message);
}

function expect(actual, expected, field) {
  if (!isDeepStrictEqual(actual, expected)) fail(`${field} does not match the campaign ledger contract`);
}

function exactKeys(value, keys, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${field} must be an object`);
  expect(Object.keys(value).sort(), [...keys].sort(), `${field} keys`);
}

function nonEmptyString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    fail(`${field} must be a non-empty trimmed string`);
  }
  return value;
}

function positiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${field} must be a positive safe integer`);
  return value;
}

function nonNegativeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be a non-negative safe integer`);
  return value;
}

function boolean(value, field) {
  if (typeof value !== "boolean") fail(`${field} must be a boolean`);
  return value;
}

function sha256Hex(value, field) {
  if (!/^[a-f0-9]{64}$/.test(value ?? "")) fail(`${field} must be a lowercase SHA-256`);
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("canonical JSON cannot contain a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonical(entry)).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("canonical JSON contains a non-JSON value");
  }
  const keys = Object.keys(value).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function clone(value) {
  return structuredClone(value);
}

function isoTimestamp(value, field) {
  nonEmptyString(value, field);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    fail(`${field} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

function secondsBetween(start, end) {
  return (Date.parse(end) - Date.parse(start)) / 1000;
}

function parseContractSource(source, field) {
  if (!Buffer.isBuffer(source) && !(source instanceof Uint8Array)) {
    fail(`${field} must be supplied as exact source bytes`);
  }
  const bytes = Buffer.from(source);
  if (bytes.length === 0) fail(`${field} must not be empty`);
  if (bytes.length > MAX_CONTRACT_SOURCE_BYTES) fail(`${field} exceeds the 8 MiB source limit`);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail(`${field} must not contain a UTF-8 BOM`);
  }
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${field} is not valid UTF-8`);
  }
  try {
    const parsed = parseStrictJsonBytes(bytes, field);
    return { bytes, value: parsed.value, sha256: sha256(bytes) };
  } catch (error) {
    fail(`${field} is not valid JSON: ${error.message}`);
  }
}

function canonicalJsonBytes(value) {
  return Buffer.from(canonical(value), "utf8");
}

function exactEvidenceRef(value, field) {
  try {
    return validateEvidenceCasRef(value);
  } catch (error) {
    fail(`${field} is invalid: ${error.message}`);
  }
}

function putExactJsonEvidence(directory, source, field) {
  const parsed = parseContractSource(source, field);
  const ref = putEvidenceJsonBody({ campaignRoot: directory, body: parsed.bytes });
  expect(ref.sha256, parsed.sha256, `${field} CAS SHA-256`);
  return { ...parsed, ref };
}

function exactMode(stat, mode, field) {
  if ((stat.mode & 0o777) !== mode) fail(`${field} permissions must be ${mode.toString(8)}`);
}

function ledgerPaths(directory) {
  const root = path.resolve(nonEmptyString(directory, "campaign ledger directory"));
  return {
    root,
    ledger: path.join(root, LEDGER_NAME),
    lock: path.join(root, LOCK_NAME),
  };
}

function ensureDirectory(root, create = false) {
  if (create) fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail("campaign ledger directory must be a real directory");
  exactMode(stat, 0o700, "campaign ledger directory");
}

function syncDirectory(root) {
  const descriptor = fs.openSync(root, "r");
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function withExclusiveLock(paths, operation) {
  let handle;
  try {
    handle = acquireExclusiveLock(paths.lock);
  } catch (error) {
    fail(`campaign ledger lock acquisition failed: ${error.message}`);
  }
  try {
    return operation();
  } finally {
    handle.release();
  }
}

function writeEnvelope(paths, payload) {
  const payloadSha256 = sha256(Buffer.from(canonical(payload)));
  const envelope = { schema_version: ENVELOPE_SCHEMA, payload_sha256: payloadSha256, payload };
  const source = `${JSON.stringify(envelope, null, 2)}\n`;
  const temporary = path.join(paths.root, `.${LEDGER_NAME}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, "wx", 0o600);
    fs.writeFileSync(descriptor, source);
    fs.fsyncSync(descriptor);
    exactMode(fs.fstatSync(descriptor), 0o600, "campaign ledger envelope");
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, paths.ledger);
    syncDirectory(paths.root);
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try {
      fs.unlinkSync(temporary);
    } catch (cleanupError) {
      if (cleanupError?.code !== "ENOENT") throw cleanupError;
    }
    throw error;
  }
  return payloadSha256;
}

function readEnvelope(paths) {
  ensureDirectory(paths.root);
  const stat = fs.lstatSync(paths.ledger);
  if (stat.isSymbolicLink() || !stat.isFile()) fail("campaign ledger envelope must be a regular non-symlink file");
  exactMode(stat, 0o600, "campaign ledger envelope");
  if (stat.size < 1 || stat.size > MAX_LEDGER_BYTES) fail("campaign ledger envelope size is invalid");
  const source = fs.readFileSync(paths.ledger, "utf8");
  let envelope;
  try {
    envelope = JSON.parse(source);
  } catch (error) {
    fail(`campaign ledger envelope is not valid JSON: ${error.message}`);
  }
  exactKeys(envelope, ["schema_version", "payload_sha256", "payload"], "campaign ledger envelope");
  if (envelope.schema_version !== ENVELOPE_SCHEMA) fail("campaign ledger envelope schema is invalid");
  if (!/^[a-f0-9]{64}$/.test(envelope.payload_sha256 ?? "")) fail("campaign ledger payload SHA-256 is invalid");
  if (source !== `${JSON.stringify(envelope, null, 2)}\n`) fail("campaign ledger envelope is not canonical");
  const actual = sha256(Buffer.from(canonical(envelope.payload)));
  if (actual !== envelope.payload_sha256) fail("campaign ledger payload SHA-256 mismatch");
  const state = replayPayload(envelope.payload);
  verifyCampaignEvidence(paths.root, envelope.payload, state);
  return { payload: envelope.payload, payloadSha256: actual, state };
}

function validateCandidate(candidate) {
  exactKeys(candidate, ["commit", "digest"], "campaign candidate");
  if (!COMMIT_RE.test(candidate.commit ?? "")) fail("campaign candidate commit must be immutable");
  if (!DIGEST_RE.test(candidate.digest ?? "")) fail("campaign candidate digest is invalid");
}

function validateFrozenBindings(bindings) {
  exactKeys(bindings, [
    "release_lock_sha256",
    "authority_manifest_sha256",
    "workload_manifest_sha256",
    "candidate",
  ], "campaign frozen bindings");
  for (const key of ["release_lock_sha256", "authority_manifest_sha256", "workload_manifest_sha256"]) {
    if (!/^[a-f0-9]{64}$/.test(bindings[key] ?? "")) fail(`campaign frozen bindings.${key} must be a lowercase SHA-256`);
  }
  exactKeys(bindings.candidate, ["repository", "version", "tag", "image", "platform"], "campaign frozen candidate");
  if (!/^https:\/\/github\.com\/[0-9A-Za-z_.-]+\/[0-9A-Za-z_.-]+$/.test(bindings.candidate.repository ?? "")) {
    fail("campaign frozen candidate repository is invalid");
  }
  if (!/^\d+\.\d+\.\d+$/.test(bindings.candidate.version ?? "")) fail("campaign frozen candidate version is invalid");
  if (bindings.candidate.tag !== `v${bindings.candidate.version}`) fail("campaign frozen candidate tag/version binding is invalid");
  if (!/^ghcr\.io\/[0-9a-z_.-]+\/[0-9a-z_.-]+$/.test(bindings.candidate.image ?? "")) {
    fail("campaign frozen candidate image is invalid");
  }
  if (!/^linux\/(?:amd64|arm64)$/.test(bindings.candidate.platform ?? "")) {
    fail("campaign frozen candidate platform is invalid");
  }
  return clone(bindings);
}

function validateScheduleScope(scope) {
  exactKeys(scope, [
    "tenant_id",
    "template",
    "partition_keys",
    "shared_across_groups",
    "shared_across_repetitions",
    "shared_across_phases",
  ], "campaign schedule scope");
  nonEmptyString(scope.tenant_id, "campaign schedule scope tenant_id");
  expect(
    [scope.template, scope.partition_keys],
    [
      "bounded-soak:{harness_commit}:{campaign_id}:{scenario}",
      ["harness_commit", "campaign_id", "scenario"],
    ],
    "campaign schedule scope template/partitions",
  );
  expect(
    [scope.shared_across_groups, scope.shared_across_repetitions, scope.shared_across_phases],
    [true, true, true],
    "campaign schedule scope sharing policy",
  );
  return clone(scope);
}

function uniqueStrings(values, field) {
  if (!Array.isArray(values) || values.length === 0) fail(`${field} must be a non-empty array`);
  for (const value of values) nonEmptyString(value, `${field} entry`);
  if (new Set(values).size !== values.length) fail(`${field} entries must be unique`);
  return [...values];
}

function memoryIds(values, field) {
  const normalized = uniqueStrings(values, field);
  for (const [index, value] of normalized.entries()) {
    if (value.length > 256) fail(`${field} entry ${index + 1} exceeds 256 characters`);
  }
  return normalized;
}

function validateCampaignSchedule(schedule, pilotRepetitions, soakRepetitions) {
  exactKeys(schedule, ["phase_order", "trial_order", "scope", "pilot", "soak_waves"], "campaign schedule");
  expect(schedule.phase_order, ["pilot", "soak"], "campaign schedule phase order");
  expect(schedule.trial_order, ["wave", "group", "scenario", "repetition"], "campaign schedule trial order");
  exactKeys(schedule.pilot, ["wave", "repetitions_per_cell", "recovery_after"], "campaign pilot schedule");
  expect(
    schedule.pilot,
    { wave: 1, repetitions_per_cell: pilotRepetitions, recovery_after: "none" },
    "campaign pilot schedule",
  );
  if (!Array.isArray(schedule.soak_waves) || schedule.soak_waves.length !== SOAK_WAVES) {
    fail(`campaign schedule must contain exactly ${SOAK_WAVES} soak waves`);
  }
  const recoveries = ["graceful_replacement", "sigkill_replacement", "offline_sqlite_verify"];
  const offsets = [0, 43_200, 86_400];
  schedule.soak_waves.forEach((wave, index) => {
    exactKeys(
      wave,
      ["wave", "not_before_elapsed_seconds", "repetitions_per_cell", "recovery_after"],
      `campaign soak wave ${index + 1} schedule`,
    );
    expect(
      wave,
      {
        wave: index + 1,
        not_before_elapsed_seconds: offsets[index],
        repetitions_per_cell: soakRepetitions,
        recovery_after: recoveries[index],
      },
      `campaign soak wave ${index + 1} schedule`,
    );
  });
  return {
    phase_order: [...schedule.phase_order],
    trial_order: [...schedule.trial_order],
    scope: validateScheduleScope(schedule.scope),
    pilot: clone(schedule.pilot),
    soak_waves: clone(schedule.soak_waves),
  };
}

function validateRecoveryContract(recovery) {
  exactKeys(recovery, ["after_wave_1", "after_wave_2", "after_wave_3"], "campaign recovery contract");
  expect(
    recovery,
    {
      after_wave_1: "graceful_replacement",
      after_wave_2: "sigkill_replacement",
      after_wave_3: "offline_sqlite_verify",
    },
    "campaign recovery contract",
  );
  return clone(recovery);
}

function validateOutcomeContract(contract) {
  exactKeys(contract, [
    "schema_version",
    "source",
    "tool_name",
    "required_tool_calls",
    "model_text_accepted",
    "pass_rule",
    "unsafe_direct_use_rule",
    "action_completed_field",
    "terminal_state_values",
  ], "campaign outcome contract");
  exactKeys(contract.terminal_state_values, ["passed", "failed"], "campaign outcome terminal states");
  expect(
    contract,
    {
      schema_version: OUTCOME_CONTRACT_SCHEMA,
      source: "native_tool_arguments",
      tool_name: "submit_bounded_soak_decision",
      required_tool_calls: 1,
      model_text_accepted: false,
      pass_rule: "choice_equals_scenario_expected_choice",
      unsafe_direct_use_rule: "choice_equals_scenario_unsafe_choice",
      action_completed_field: "passed",
      terminal_state_values: { passed: "completed", failed: "failed" },
    },
    "campaign outcome contract",
  );
  return clone(contract);
}

function scenarioVerifiersFromWorkload(workload, scenarios) {
  if (!Array.isArray(workload.scenario_definitions)) fail("campaign workload scenario_definitions must be an array");
  const definitions = new Map();
  for (const [index, definition] of workload.scenario_definitions.entries()) {
    if (!definition || typeof definition !== "object" || Array.isArray(definition)) {
      fail(`campaign workload scenario_definitions[${index}] must be an object`);
    }
    const scenarioId = nonEmptyString(definition.id, `campaign workload scenario_definitions[${index}].id`);
    if (definitions.has(scenarioId)) fail("campaign workload scenario definition IDs must be unique");
    const allowedChoices = uniqueStrings(
      definition.allowed_choices,
      `campaign workload scenario_definitions[${index}].allowed_choices`,
    );
    const expectedChoice = nonEmptyString(
      definition.expected_choice,
      `campaign workload scenario_definitions[${index}].expected_choice`,
    );
    const unsafeChoice = nonEmptyString(
      definition.unsafe_choice,
      `campaign workload scenario_definitions[${index}].unsafe_choice`,
    );
    if (!allowedChoices.includes(expectedChoice) || !allowedChoices.includes(unsafeChoice) || expectedChoice === unsafeChoice) {
      fail(`campaign workload scenario_definitions[${index}] verifier choices are inconsistent`);
    }
    definitions.set(scenarioId, {
      scenario_id: scenarioId,
      allowed_choices: allowedChoices,
      expected_choice: expectedChoice,
      unsafe_choice: unsafeChoice,
    });
  }
  expect([...definitions.keys()], scenarios, "campaign scenario verifier order");
  return scenarios.map((scenario) => definitions.get(scenario));
}

function validateScenarioVerifiers(values, scenarios) {
  if (!Array.isArray(values) || values.length !== scenarios.length) {
    fail("campaign scenario verifier count is invalid");
  }
  const normalized = values.map((value, index) => {
    exactKeys(value, ["scenario_id", "allowed_choices", "expected_choice", "unsafe_choice"], `campaign scenario verifier ${index + 1}`);
    expect(value.scenario_id, scenarios[index], `campaign scenario verifier ${index + 1} ID`);
    const allowedChoices = uniqueStrings(value.allowed_choices, `campaign scenario verifier ${index + 1} allowed choices`);
    nonEmptyString(value.expected_choice, `campaign scenario verifier ${index + 1} expected choice`);
    nonEmptyString(value.unsafe_choice, `campaign scenario verifier ${index + 1} unsafe choice`);
    if (
      !allowedChoices.includes(value.expected_choice)
      || !allowedChoices.includes(value.unsafe_choice)
      || value.expected_choice === value.unsafe_choice
    ) fail(`campaign scenario verifier ${index + 1} choices are inconsistent`);
    return clone(value);
  });
  return normalized;
}

function expectedSeedResponseAssertions() {
  return [
    { path: "operation_id", predicate: "equals_rendered", expected: { $path: "request.operation_id" } },
    { path: "tenant_id", predicate: "equals_rendered", expected: { $path: "request.tenant_id" } },
    { path: "scope", predicate: "equals_rendered", expected: { $path: "request.scope" } },
    { path: "observed.memory_written", predicate: "equals_literal", expected: true },
    {
      path: "post_commit_projections.semantic_commit",
      predicate: "equals_literal",
      expected: "committed",
    },
  ];
}

function validateSeedContract(contract) {
  exactKeys(contract, [
    "schema_version",
    "workload_templates_schema_version",
    "renderer_schema_version",
    "method",
    "route",
    "applies_to_groups",
    "cadence",
    "request_exact_keys",
    "response_assertions",
  ], "campaign seed contract");
  exactKeys(
    contract.request_exact_keys,
    ["execution_tree", "summary_only_memory"],
    "campaign seed contract request variants",
  );
  const expected = {
    schema_version: SEED_CONTRACT_SCHEMA,
    workload_templates_schema_version: "aionis_bounded_soak_execution_templates_v2",
    renderer_schema_version: "aionis_finite_renderer_v1",
    method: "POST",
    route: "/v1/observe",
    applies_to_groups: ["aionis"],
    cadence: "once_per_campaign_scenario_seed_observation_before_pilot",
    request_exact_keys: {
      execution_tree: [
        "operation_id",
        "tenant_id",
        "scope",
        "input_text",
        "memory_kind",
        "auto_embed",
        "execution",
      ],
      summary_only_memory: [
        "operation_id",
        "tenant_id",
        "scope",
        "input_text",
        "memory_kind",
        "auto_embed",
      ],
    },
    response_assertions: expectedSeedResponseAssertions(),
  };
  expect(contract, expected, "campaign seed contract");
  return clone(contract);
}

function validateSeedObservation(value, field) {
  exactKeys(value, ["scenario_id", "runtime_fixture_kind", "observation"], field);
  nonEmptyString(value.scenario_id, `${field}.scenario_id`);
  if (!/^[0-9A-Za-z._-]+$/.test(value.scenario_id)) fail(`${field}.scenario_id is not scope-safe`);
  if (!new Set(["execution_tree", "summary_only_memory"]).has(value.runtime_fixture_kind)) {
    fail(`${field}.runtime_fixture_kind is invalid`);
  }
  const observationField = `${field}.observation`;
  if (value.runtime_fixture_kind === "summary_only_memory") {
    exactKeys(value.observation, ["operation_key", "input_text", "memory_kind"], observationField);
    expect(value.observation.memory_kind, "general_memory", `${observationField}.memory_kind`);
  } else {
    exactKeys(value.observation, [
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
    ], observationField);
    expect(value.observation.memory_kind, "execution_workflow", `${observationField}.memory_kind`);
    if (!new Set(["passed_solution", "failed_branch"]).has(value.observation.branch_role)) {
      fail(`${observationField}.branch_role is invalid`);
    }
    const passed = value.observation.branch_role === "passed_solution";
    expect(
      [value.observation.outcome, value.observation.verifier_status],
      passed ? ["succeeded", "passed"] : ["failed", "failed"],
      `${observationField} outcome/verifier status`,
    );
    for (const key of [
      "branch_role",
      "choice",
      "title",
      "outcome",
      "verifier_status",
      "verification_detail",
      "raw_ref",
      "evidence_ref",
      "continuation_hint",
    ]) nonEmptyString(value.observation[key], `${observationField}.${key}`);
  }
  nonEmptyString(value.observation.operation_key, `${observationField}.operation_key`);
  if (!/^[0-9A-Za-z._-]+$/.test(value.observation.operation_key)) {
    fail(`${observationField}.operation_key is invalid`);
  }
  nonEmptyString(value.observation.input_text, `${observationField}.input_text`);
  nonEmptyString(value.observation.memory_kind, `${observationField}.memory_kind`);
  return clone(value);
}

function validateSeedObservations(values, scenarios) {
  if (!Array.isArray(values) || values.length !== 5) {
    fail("campaign seed observations must contain exactly five workload-v2 observations");
  }
  const normalized = values.map((value, index) => validateSeedObservation(value, `campaign seed observation ${index + 1}`));
  const seenScenarios = [];
  let priorScenarioIndex = -1;
  const pairs = [];
  for (const value of normalized) {
    const scenarioIndex = scenarios.indexOf(value.scenario_id);
    if (scenarioIndex < 0 || scenarioIndex < priorScenarioIndex) {
      fail("campaign seed observations must follow the frozen scenario order");
    }
    priorScenarioIndex = scenarioIndex;
    if (!seenScenarios.includes(value.scenario_id)) seenScenarios.push(value.scenario_id);
    pairs.push(`${value.scenario_id}\0${value.observation.operation_key}`);
  }
  expect(seenScenarios, scenarios, "campaign seed observation scenario coverage");
  if (new Set(pairs).size !== pairs.length) fail("campaign seed observation operation keys must be unique per scenario");
  return normalized;
}

function seedOperationId(campaignId, scenarioId, operationKey) {
  return `seed-${sha256(Buffer.from(`${campaignId}\0${scenarioId}\0${operationKey}`, "utf8"))}`;
}

function renderSeedRequest({ campaignId, harnessCommit, schedule, seed, expectedChoice }) {
  const observation = seed.observation;
  const scope = expandWorkloadScope(schedule.scope.template, {
    harness_commit: harnessCommit,
    campaign_id: campaignId,
    scenario: seed.scenario_id,
  });
  const request = {
    operation_id: seedOperationId(campaignId, seed.scenario_id, observation.operation_key),
    tenant_id: schedule.scope.tenant_id,
    scope,
    input_text: observation.input_text,
    memory_kind: observation.memory_kind,
    auto_embed: true,
  };
  if (seed.runtime_fixture_kind === "summary_only_memory") return request;
  request.execution = {
    run_id: `fixture-${seed.scenario_id}-${observation.operation_key}`,
    task_id: seed.scenario_id,
    task_family: "aionis_bounded_soak_fixture",
    task_signature: `bounded-soak:${seed.scenario_id}`,
    workflow_signature: "bounded-soak-fixture-v1",
    title: observation.title,
    summary: observation.input_text,
    outcome: observation.outcome,
    acceptance_checks: ["fixture_branch_has_raw_ref", "fixture_branch_has_deterministic_verifier"],
    verifier: [`bounded-soak-fixture-verifier-v1:${observation.verifier_status}`],
    continuation_hint: observation.continuation_hint,
    confidence: 1,
    evidence_ref: observation.evidence_ref,
    raw_ref: observation.raw_ref,
    evidence: [{
      kind: "deterministic_fixture_execution",
      branch_role: observation.branch_role,
      raw_ref: observation.raw_ref,
      verifier_id: "bounded-soak-fixture-verifier-v1",
      verifier_status: observation.verifier_status,
      result: observation.choice,
    }],
    verification: {
      verifier_id: "bounded-soak-fixture-verifier-v1",
      status: observation.verifier_status,
      expected: expectedChoice,
      observed: observation.choice,
      detail: observation.verification_detail,
    },
    slots: {
      execution_outcome_role: observation.branch_role,
      evidence_class: "raw_and_verifier",
      branch_choice: observation.choice,
    },
  };
  return request;
}

function seedInputsFromWorkload(workload, scenarios, schedule) {
  const templates = workload.execution_templates;
  if (!templates || typeof templates !== "object" || Array.isArray(templates)) {
    fail("campaign workload execution_templates must be an object");
  }
  const seedTemplate = templates.seed_observe;
  exactKeys(seedTemplate, [
    "method",
    "route",
    "applies_to_groups",
    "cadence",
    "request_variants",
    "response_assertions",
  ], "campaign workload seed_observe template");
  exactKeys(
    seedTemplate.request_variants,
    ["execution_tree", "summary_only_memory"],
    "campaign workload seed_observe request variants",
  );
  for (const [kind, expectedKeys] of Object.entries({
    execution_tree: [
      "operation_id",
      "tenant_id",
      "scope",
      "input_text",
      "memory_kind",
      "auto_embed",
      "execution",
    ],
    summary_only_memory: [
      "operation_id",
      "tenant_id",
      "scope",
      "input_text",
      "memory_kind",
      "auto_embed",
    ],
  })) {
    exactKeys(
      seedTemplate.request_variants[kind],
      ["request_exact_keys", "request_template"],
      `campaign workload seed_observe ${kind}`,
    );
    expect(
      seedTemplate.request_variants[kind].request_exact_keys,
      expectedKeys,
      `campaign workload seed_observe ${kind} request keys`,
    );
  }
  const contract = validateSeedContract({
    schema_version: SEED_CONTRACT_SCHEMA,
    workload_templates_schema_version: templates.schema_version,
    renderer_schema_version: templates.renderer?.schema_version,
    method: seedTemplate.method,
    route: seedTemplate.route,
    applies_to_groups: clone(seedTemplate.applies_to_groups),
    cadence: seedTemplate.cadence,
    request_exact_keys: {
      execution_tree: clone(seedTemplate.request_variants.execution_tree.request_exact_keys),
      summary_only_memory: clone(seedTemplate.request_variants.summary_only_memory.request_exact_keys),
    },
    response_assertions: clone(seedTemplate.response_assertions),
  });
  if (!Array.isArray(workload.scenario_definitions)) fail("campaign workload scenario_definitions must be an array");
  const definitions = new Map(workload.scenario_definitions.map((definition) => [definition.id, definition]));
  expect([...definitions.keys()], scenarios, "campaign seed definition order");
  const observations = [];
  for (const scenarioId of scenarios) {
    const definition = definitions.get(scenarioId);
    const fixture = definition?.runtime_fixture;
    if (!fixture || typeof fixture !== "object" || Array.isArray(fixture)) {
      fail(`campaign workload scenario ${scenarioId} runtime fixture is missing`);
    }
    exactKeys(fixture, ["kind", "seed_observations"], `campaign workload scenario ${scenarioId} runtime fixture`);
    if (!Array.isArray(fixture.seed_observations) || fixture.seed_observations.length === 0) {
      fail(`campaign workload scenario ${scenarioId} seed observations must be non-empty`);
    }
    for (const observation of fixture.seed_observations) {
      observations.push(validateSeedObservation({
        scenario_id: scenarioId,
        runtime_fixture_kind: fixture.kind,
        observation: clone(observation),
      }, `campaign workload scenario ${scenarioId} seed observation`));
    }
  }
  const normalized = validateSeedObservations(observations, scenarios);
  const sentinelCampaignId = `campaign-${"0".repeat(40)}`;
  const sentinelHarnessCommit = "0".repeat(40);
  for (const seed of normalized) {
    const definition = definitions.get(seed.scenario_id);
    const campaignScope = expandWorkloadScope(schedule.scope.template, {
      harness_commit: sentinelHarnessCommit,
      campaign_id: sentinelCampaignId,
      scenario: seed.scenario_id,
    });
    const rendered = renderWorkloadTemplate(
      seedTemplate.request_variants[seed.runtime_fixture_kind].request_template,
      {
        campaign_id: sentinelCampaignId,
        harness_commit: sentinelHarnessCommit,
        scenario: definition,
        seed_observation: seed.observation,
        schedule,
        campaign_scope: campaignScope,
      },
    );
    exactKeys(
      rendered,
      contract.request_exact_keys[seed.runtime_fixture_kind],
      `campaign workload ${seed.scenario_id}/${seed.observation.operation_key} rendered seed request`,
    );
    expect(rendered, renderSeedRequest({
      campaignId: sentinelCampaignId,
      harnessCommit: sentinelHarnessCommit,
      schedule,
      seed,
      expectedChoice: definition.expected_choice,
    }), `campaign workload ${seed.scenario_id}/${seed.observation.operation_key} seed renderer`);
  }
  return { contract, observations: normalized };
}

function trialContractFromWorkload(workload, providerExecutionContract) {
  if (!workload || typeof workload !== "object" || Array.isArray(workload)) fail("campaign workload must be an object");
  const groups = uniqueStrings(workload.groups, "campaign workload groups");
  const scenarios = uniqueStrings(workload.scenarios, "campaign workload scenarios");
  const pilotRepetitions = positiveInteger(workload.pilot?.repetitions_per_cell, "campaign pilot repetitions");
  const pilotCalls = positiveInteger(workload.pilot?.semantic_chat_calls, "campaign pilot calls");
  const soakWaves = positiveInteger(workload.soak?.waves, "campaign soak waves");
  const soakRepetitions = positiveInteger(workload.soak?.repetitions_per_cell_per_wave, "campaign soak repetitions");
  const soakCalls = positiveInteger(workload.soak?.semantic_chat_calls, "campaign soak calls");
  if (soakWaves !== SOAK_WAVES) fail(`campaign soak must contain exactly ${SOAK_WAVES} waves`);
  buildTrialPlan("pilot", workload);
  buildTrialPlan("soak", workload);
  const productInvariants = uniqueStrings(workload.product_invariants, "campaign workload product invariants");
  expect(productInvariants, PRODUCT_INVARIANTS, "campaign workload product invariants");
  const schedule = validateCampaignSchedule(workload.schedule, pilotRepetitions, soakRepetitions);
  const scenarioVerifiers = scenarioVerifiersFromWorkload(workload, scenarios);
  const seedInputs = seedInputsFromWorkload(workload, scenarios, schedule);
  return {
    groups,
    scenarios,
    pilot_repetitions_per_cell: pilotRepetitions,
    pilot_semantic_chat_calls: pilotCalls,
    soak_waves: soakWaves,
    soak_repetitions_per_cell_per_wave: soakRepetitions,
    soak_semantic_chat_calls: soakCalls,
    scenario_verifiers: scenarioVerifiers,
    provider_execution_contract: clone(providerExecutionContract),
    seed_contract: seedInputs.contract,
    seed_observations: seedInputs.observations,
    outcome_contract: validateOutcomeContract(workload.outcome_contract),
    product_invariants: productInvariants,
    schedule,
    recovery: validateRecoveryContract(workload.recovery),
  };
}

function workloadFromTrialContract(contract) {
  exactKeys(contract, [
    "groups",
    "scenarios",
    "pilot_repetitions_per_cell",
    "pilot_semantic_chat_calls",
    "soak_waves",
    "soak_repetitions_per_cell_per_wave",
    "soak_semantic_chat_calls",
    "scenario_verifiers",
    "provider_execution_contract",
    "seed_contract",
    "seed_observations",
    "outcome_contract",
    "product_invariants",
    "schedule",
    "recovery",
  ], "campaign trial contract");
  const groups = uniqueStrings(contract.groups, "campaign trial contract groups");
  const scenarios = uniqueStrings(contract.scenarios, "campaign trial contract scenarios");
  const pilotRepetitions = positiveInteger(contract.pilot_repetitions_per_cell, "campaign trial contract pilot repetitions");
  const soakRepetitions = positiveInteger(contract.soak_repetitions_per_cell_per_wave, "campaign trial contract soak repetitions");
  const productInvariants = uniqueStrings(contract.product_invariants, "campaign trial contract product invariants");
  expect(productInvariants, PRODUCT_INVARIANTS, "campaign trial contract product invariants");
  validateScenarioVerifiers(contract.scenario_verifiers, scenarios);
  if (!contract.provider_execution_contract || typeof contract.provider_execution_contract !== "object") {
    fail("campaign provider execution contract is missing");
  }
  validateSeedContract(contract.seed_contract);
  validateSeedObservations(contract.seed_observations, scenarios);
  validateOutcomeContract(contract.outcome_contract);
  validateRecoveryContract(contract.recovery);
  return {
    groups,
    scenarios,
    pilot: {
      repetitions_per_cell: pilotRepetitions,
      semantic_chat_calls: positiveInteger(contract.pilot_semantic_chat_calls, "campaign trial contract pilot calls"),
    },
    soak: {
      waves: positiveInteger(contract.soak_waves, "campaign trial contract soak waves"),
      repetitions_per_cell_per_wave: soakRepetitions,
      semantic_chat_calls: positiveInteger(contract.soak_semantic_chat_calls, "campaign trial contract soak calls"),
    },
    schedule: validateCampaignSchedule(contract.schedule, pilotRepetitions, soakRepetitions),
  };
}

function executionLimitsFromLock(lock) {
  const limits = clone(lock.execution_limits);
  exactKeys(limits, [
    "minimum_duration_seconds",
    "maximum_duration_seconds",
    "maximum_chat_calls",
    "maximum_cost_usd",
    "pilot_chat_calls",
    "soak_chat_calls",
    "soak_waves",
    "persistent_volume_required",
  ], "campaign execution limits");
  for (const key of [
    "minimum_duration_seconds",
    "maximum_duration_seconds",
    "maximum_chat_calls",
    "pilot_chat_calls",
    "soak_chat_calls",
    "soak_waves",
  ]) positiveInteger(limits[key], `campaign execution limits.${key}`);
  if (!Number.isFinite(limits.maximum_cost_usd) || limits.maximum_cost_usd <= 0) {
    fail("campaign execution limits.maximum_cost_usd must be positive");
  }
  boolean(limits.persistent_volume_required, "campaign execution limits.persistent_volume_required");
  if (
    limits.minimum_duration_seconds !== 86_400
    || limits.maximum_duration_seconds !== 129_600
    || limits.maximum_chat_calls !== 90
    || limits.maximum_cost_usd !== 50
    || limits.pilot_chat_calls !== 9
    || limits.soak_chat_calls !== 81
    || limits.soak_waves !== SOAK_WAVES
    || limits.persistent_volume_required !== true
  ) fail("campaign execution limits do not match the bounded soak contract");
  return limits;
}

function providerContractFromAuthority(authority) {
  const provider = authority?.providers?.agent;
  if (!provider || typeof provider !== "object" || Array.isArray(provider)) fail("campaign provider contract is missing");
  const contract = {
    provider: provider.provider,
    requested_model: provider.requested_model,
    allowed_returned_models: clone(provider.allowed_returned_models),
    fallback_allowed: provider.fallback_allowed,
  };
  exactKeys(contract, ["provider", "requested_model", "allowed_returned_models", "fallback_allowed"], "campaign provider contract");
  nonEmptyString(contract.provider, "campaign provider contract.provider");
  nonEmptyString(contract.requested_model, "campaign provider contract.requested_model");
  uniqueStrings(contract.allowed_returned_models, "campaign provider contract.allowed_returned_models");
  boolean(contract.fallback_allowed, "campaign provider contract.fallback_allowed");
  if (contract.provider !== "openrouter" || contract.fallback_allowed !== false) {
    fail("campaign provider contract must freeze OpenRouter without fallbacks");
  }
  if (!contract.allowed_returned_models.includes(contract.requested_model)) {
    fail("campaign provider requested model must be present in the returned-model allowlist");
  }
  return contract;
}

function validateProviderContract(contract) {
  return providerContractFromAuthority({ providers: { agent: contract } });
}

function retryPolicyFromLock(lock) {
  const policy = clone(lock.retry_policy);
  exactKeys(policy, [
    "transport_max_attempts",
    "retryable_http_statuses",
    "retryable_network_codes",
    "semantic_retries",
  ], "campaign retry policy");
  positiveInteger(policy.transport_max_attempts, "campaign retry policy.transport_max_attempts");
  if (!Array.isArray(policy.retryable_http_statuses) || policy.retryable_http_statuses.length === 0) {
    fail("campaign retry policy.retryable_http_statuses must be non-empty");
  }
  for (const status of policy.retryable_http_statuses) {
    if (!Number.isSafeInteger(status) || status < 400 || status > 599) {
      fail("campaign retry policy retryable HTTP status is invalid");
    }
  }
  uniqueStrings(policy.retryable_network_codes, "campaign retry policy.retryable_network_codes");
  nonNegativeInteger(policy.semantic_retries, "campaign retry policy.semantic_retries");
  if (policy.semantic_retries !== 0) fail("campaign retry policy must prohibit semantic retries");
  return policy;
}

function validatePhaseSource(source, phase, harnessCommit, field = `${phase} source`) {
  exactKeys(source, ["repository", "run_id", "run_attempt", "head_sha", "phase", "job", "environment"], field);
  expect(
    [source.repository, source.head_sha, source.phase, source.job, source.environment],
    [EVAL_REPOSITORY_SLUG, harnessCommit, phase, "paid-preflight", PROTECTED_ENVIRONMENT],
    `${field} identity`,
  );
  positiveInteger(source.run_id, `${field}.run_id`);
  positiveInteger(source.run_attempt, `${field}.run_attempt`);
  return clone(source);
}

function preclaim(campaignId, harnessCommit, trialId, scenario, scheduleScope) {
  const id = (kind, prefix) => `${prefix}-${sha256(Buffer.from(`${campaignId}\0${trialId}\0${kind}`)).slice(0, 32)}`;
  if (!/^[0-9A-Za-z._-]+$/.test(scenario)) fail("campaign scenario cannot be represented by the frozen scope template");
  const scope = scheduleScope.template
    .replace("{harness_commit}", harnessCommit)
    .replace("{campaign_id}", campaignId)
    .replace("{scenario}", scenario);
  if (scope.length > 256) fail("campaign scope exceeds 256 characters");
  return {
    tenant_id: scheduleScope.tenant_id,
    request_id: id("request", "request"),
    guide_operation_id: id("guide-operation", "guide"),
    outcome_operation_id: id("outcome-operation", "outcome"),
    feedback_operation_id: id("feedback-operation", "feedback"),
    measure_operation_id: id("measure-operation", "measure"),
    scope,
  };
}

function trialId(phase, trial) {
  return `${phase}:w${trial.wave}:${trial.group}:${trial.scenario}:r${trial.repetition}`;
}

function deterministicTrials(campaignId, harnessCommit, contract) {
  const workload = workloadFromTrialContract(contract);
  if (workload.soak.waves !== SOAK_WAVES) fail(`campaign soak must contain exactly ${SOAK_WAVES} waves`);
  const values = [];
  for (const phase of ["pilot", "soak"]) {
    for (const trial of buildTrialPlan(phase, workload)) {
      const id = trialId(phase, trial);
      values.push({
        trial_id: id,
        phase,
        wave: trial.wave,
        group: trial.group,
        scenario: trial.scenario,
        repetition: trial.repetition,
        preclaim: preclaim(campaignId, harnessCommit, id, trial.scenario, workload.schedule.scope),
      });
    }
  }
  const requestIds = values.map((trial) => trial.preclaim.request_id);
  if (new Set(requestIds).size !== requestIds.length) fail("campaign preclaim request IDs must be unique");
  const operationIds = values.flatMap((trial) => [
    trial.preclaim.guide_operation_id,
    trial.preclaim.outcome_operation_id,
    trial.preclaim.feedback_operation_id,
    trial.preclaim.measure_operation_id,
  ]);
  if (new Set(operationIds).size !== operationIds.length) fail("campaign preclaim operation IDs must be unique");
  if (new Set([...requestIds, ...operationIds]).size !== requestIds.length + operationIds.length) {
    fail("campaign preclaim request and operation ID namespaces must not collide");
  }
  return values;
}

function deterministicSeeds(campaignId, harnessCommit, contract, trials) {
  const workload = workloadFromTrialContract(contract);
  const seedContract = validateSeedContract(contract.seed_contract);
  const observations = validateSeedObservations(contract.seed_observations, workload.scenarios);
  const values = observations.map((seed) => {
    const verifier = scenarioVerifier(contract, seed.scenario_id);
    const request = renderSeedRequest({
      campaignId,
      harnessCommit,
      schedule: workload.schedule,
      seed,
      expectedChoice: verifier.expected_choice,
    });
    exactKeys(
      request,
      seedContract.request_exact_keys[seed.runtime_fixture_kind],
      `campaign seed ${seed.scenario_id}/${seed.observation.operation_key} request`,
    );
    return {
      seed_id: `seed:${seed.scenario_id}:${seed.observation.operation_key}`,
      scenario_id: seed.scenario_id,
      runtime_fixture_kind: seed.runtime_fixture_kind,
      operation_key: seed.observation.operation_key,
      expected_execution_outcome_role: seed.runtime_fixture_kind === "execution_tree"
        ? seed.observation.branch_role
        : null,
      expected_served_surface: seed.runtime_fixture_kind === "execution_tree"
        ? (seed.observation.branch_role === "passed_solution" ? "use_now" : "do_not_use")
        : "inspect_before_use",
      operation_id: request.operation_id,
      request,
    };
  });
  const preclaimIds = trials.flatMap((trial) => [
    trial.preclaim.request_id,
    trial.preclaim.guide_operation_id,
    trial.preclaim.outcome_operation_id,
    trial.preclaim.feedback_operation_id,
    trial.preclaim.measure_operation_id,
  ]);
  const seedIds = values.flatMap((seed) => [seed.seed_id, seed.operation_id]);
  if (new Set(seedIds).size !== seedIds.length) fail("campaign seed ID namespaces must be unique");
  if (new Set([...preclaimIds, ...seedIds]).size !== preclaimIds.length + seedIds.length) {
    fail("campaign seed IDs must not collide with preclaim request or operation IDs");
  }
  return values;
}

function campaignId({ harnessCommit, candidate, frozenBindings, trialContract, pilotSource }) {
  const digest = sha256(Buffer.from(canonical({
    harness_commit: harnessCommit,
    candidate,
    frozen_bindings: frozenBindings,
    trial_contract: trialContract,
    pilot_source: pilotSource,
  })));
  return `campaign-${digest.slice(0, 40)}`;
}

function validatePreclaim(value, expected, field) {
  exactKeys(value, [
    "request_id",
    "tenant_id",
    "guide_operation_id",
    "outcome_operation_id",
    "feedback_operation_id",
    "measure_operation_id",
    "scope",
  ], field);
  expect(value, expected, field);
}

function scenarioVerifier(contract, scenario) {
  const verifier = contract.scenario_verifiers.find((entry) => entry.scenario_id === scenario);
  if (!verifier) fail(`campaign scenario ${scenario} has no frozen verifier`);
  return verifier;
}

function providerExecutionScenario(contract, scenarioId) {
  const scenario = contract.workload.scenario_definitions.find((entry) => entry.id === scenarioId);
  if (!scenario) fail(`campaign provider execution scenario ${scenarioId} is missing`);
  return scenario;
}

function renderGuideRequest(providerExecutionContract, trial) {
  if (trial.group !== "aionis") fail("only Aionis trials may render a Runtime guide request");
  const workload = providerExecutionContract.workload;
  const template = workload.execution_templates.trial_guide;
  const request = renderWorkloadTemplate(template.request_template, {
    preclaim: trial.preclaim,
    schedule: workload.schedule,
    scenario: providerExecutionScenario(providerExecutionContract, trial.scenario),
  });
  exactKeys(request, template.request_exact_keys, "rendered campaign guide request");
  expect(
    [template.method, template.route, template.applies_to_groups],
    ["POST", "/v1/guide", ["aionis"]],
    "campaign guide route contract",
  );
  return request;
}

function guideAgentContextSurfaceMap(agentContext) {
  const values = new Map();
  for (const surface of SERVED_SURFACES) {
    const field = `${surface}_memory_ids`;
    const ids = agentContext[field];
    if (!Array.isArray(ids) || ids.length > 256) {
      fail(`guide Runtime response agent_context.${field} must be a bounded array`);
    }
    for (const [index, memoryId] of ids.entries()) {
      nonEmptyString(memoryId, `guide Runtime response agent_context.${field}[${index}]`);
      if (values.has(memoryId)) {
        fail("guide Runtime response AgentContext memory IDs must be unique across served surfaces");
      }
      values.set(memoryId, surface);
    }
  }
  if (values.size === 0) fail("guide Runtime response has no served memory IDs");
  return values;
}

function guideAttributionSurfaceMap(responseValue, guideTraceId) {
  const attribution = responseValue.feedback_attribution_v1;
  exactKeys(attribution, [
    "contract_version",
    "status",
    "guide_trace_id",
    "episode_id",
    "exposure_event_id",
    "item_set_sha256",
    "served_surface_sha256",
    "projection_complete",
    "projection_incomplete_reason_codes",
    "items",
  ], "guide Runtime response feedback attribution");
  expect(
    [attribution.contract_version, attribution.status, attribution.guide_trace_id],
    ["aionis_guide_feedback_attribution_v1", "available", guideTraceId],
    "guide Runtime response feedback attribution identity",
  );
  for (const key of ["episode_id", "exposure_event_id"]) {
    nonEmptyString(attribution[key], `guide Runtime response feedback attribution.${key}`);
  }
  sha256Hex(attribution.item_set_sha256, "guide Runtime response feedback attribution item-set SHA-256");
  sha256Hex(attribution.served_surface_sha256, "guide Runtime response feedback attribution surface SHA-256");
  if (attribution.projection_complete !== true
    || !Array.isArray(attribution.projection_incomplete_reason_codes)
    || attribution.projection_incomplete_reason_codes.length !== 0) {
    fail("guide Runtime response feedback attribution projection must be complete");
  }
  if (!Array.isArray(attribution.items) || attribution.items.length === 0 || attribution.items.length > 256) {
    fail("guide Runtime response feedback attribution items must be a non-empty bounded array");
  }
  const values = new Map();
  for (const [index, item] of attribution.items.entries()) {
    exactKeys(item, ["memory_id", "served_surface"], `guide Runtime response attribution item ${index + 1}`);
    nonEmptyString(item.memory_id, `guide Runtime response attribution item ${index + 1} memory ID`);
    if (!SERVED_SURFACES.includes(item.served_surface)) {
      fail(`guide Runtime response attribution item ${index + 1} served surface is invalid`);
    }
    if (values.has(item.memory_id)) fail("guide Runtime response attribution contains duplicate memory IDs");
    values.set(item.memory_id, item.served_surface);
  }
  return values;
}

function guidePacketRoleMap(responseValue) {
  const relevant = responseValue.memory_packet?.relevant_memories;
  if (!Array.isArray(relevant) || relevant.length === 0 || relevant.length > 256) {
    fail("guide Runtime response memory_packet.relevant_memories must be a non-empty bounded array");
  }
  const values = new Map();
  for (const [index, memory] of relevant.entries()) {
    if (!memory || typeof memory !== "object" || Array.isArray(memory)) {
      fail(`guide Runtime response relevant memory ${index + 1} must be an object`);
    }
    const memoryId = nonEmptyString(memory.id, `guide Runtime response relevant memory ${index + 1} ID`);
    if (values.has(memoryId)) fail("guide Runtime response memory packet contains duplicate memory IDs");
    const role = memory.execution_state?.execution_outcome_role ?? null;
    if (role !== null && !EXECUTION_OUTCOME_ROLES.has(role)) {
      fail(`guide Runtime response relevant memory ${index + 1} execution outcome role is invalid`);
    }
    values.set(memoryId, role);
  }
  return values;
}

function deriveGuideResponseCheckpoint({
  providerExecutionContract,
  trial,
  httpStatus,
  requestEvidence,
  responseEvidence,
  responseValue,
}) {
  if (!responseValue || typeof responseValue !== "object" || Array.isArray(responseValue)) {
    fail("guide Runtime response source must contain a JSON object");
  }
  if (!responseValue.agent_context || typeof responseValue.agent_context !== "object"
    || Array.isArray(responseValue.agent_context)) {
    fail("guide Runtime response agent_context must be an object");
  }
  nonEmptyString(responseValue.agent_context.prompt_text, "guide Runtime response agent_context.prompt_text");
  if (Object.hasOwn(responseValue.agent_context, "agent_prompt")) {
    fail("guide Runtime response agent_context.agent_prompt must remain absent");
  }
  if (!responseValue.guide_packet || typeof responseValue.guide_packet !== "object"
    || Array.isArray(responseValue.guide_packet)) {
    fail("guide Runtime response guide_packet must be an object");
  }
  const selectionContract = providerExecutionContract.workload.execution_templates
    .post_trial_runtime_contract.feedback.served_memory_selection;
  const selection = selectWorkloadServedMemory(responseValue, selectionContract);
  const agentContextSurfaces = guideAgentContextSurfaceMap(responseValue.agent_context);
  const attributionSurfaces = guideAttributionSurfaceMap(responseValue, responseValue.guide_trace_id);
  const packetRoles = guidePacketRoleMap(responseValue);
  expect(
    [...attributionSurfaces.entries()].sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right))),
    [...agentContextSurfaces.entries()].sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right))),
    "guide Runtime response attribution/AgentContext surface projection",
  );
  const memorySurfaceEvidence = [...agentContextSurfaces.entries()]
    .map(([memoryId, surface]) => {
      if (!packetRoles.has(memoryId)) {
        fail("guide Runtime response served memory is absent from memory_packet.relevant_memories");
      }
      return {
        memory_id: memoryId,
        packet_execution_outcome_role: packetRoles.get(memoryId),
        attribution_served_surface: attributionSurfaces.get(memoryId),
        agent_context_served_surface: surface,
      };
    })
    .sort((left, right) => Buffer.compare(Buffer.from(left.memory_id), Buffer.from(right.memory_id)));
  return {
    schema_version: GUIDE_RESPONSE_SCHEMA,
    route: "/v1/guide",
    http_status: httpStatus,
    response_contract_version: responseValue.contract_version,
    trial_id: trial.trial_id,
    operation_id: responseValue.operation_id,
    tenant_id: responseValue.tenant_id,
    scope: responseValue.scope,
    guide_trace_id: responseValue.guide_trace_id,
    request_evidence: clone(requestEvidence),
    response_evidence: clone(responseEvidence),
    inspect_evidence: {
      served_surface: selection.surface,
      served_memory_ids: memoryIds(selection.ids, "guide Runtime response served memory IDs"),
    },
    memory_surface_evidence: memorySurfaceEvidence,
  };
}

function validateGuideResponseCheckpoint(checkpoint, trial, availableScenarioMemoryEvidence, field) {
  exactKeys(checkpoint, [
    "schema_version",
    "route",
    "http_status",
    "response_contract_version",
    "trial_id",
    "operation_id",
    "tenant_id",
    "scope",
    "guide_trace_id",
    "request_evidence",
    "response_evidence",
    "inspect_evidence",
    "memory_surface_evidence",
  ], field);
  if (checkpoint.schema_version !== GUIDE_RESPONSE_SCHEMA) fail(`${field} schema is invalid`);
  expect(
    [checkpoint.route, checkpoint.http_status, checkpoint.response_contract_version],
    ["/v1/guide", 200, "aionis_guide_result_v1"],
    `${field} route identity`,
  );
  expect(checkpoint.trial_id, trial.trial_id, `${field} trial ID`);
  expect(checkpoint.operation_id, trial.preclaim.guide_operation_id, `${field} operation ID`);
  expect(
    [checkpoint.tenant_id, checkpoint.scope],
    [trial.preclaim.tenant_id, trial.preclaim.scope],
    `${field} tenant/scope`,
  );
  nonEmptyString(checkpoint.guide_trace_id, `${field} guide trace ID`);
  exactEvidenceRef(checkpoint.request_evidence, `${field} request evidence`);
  exactEvidenceRef(checkpoint.response_evidence, `${field} response evidence`);
  exactKeys(checkpoint.inspect_evidence, ["served_surface", "served_memory_ids"], `${field} inspect evidence`);
  if (!new Set(["use_now", "inspect_before_use", "do_not_use"]).has(checkpoint.inspect_evidence.served_surface)) {
    fail(`${field} served surface is invalid`);
  }
  const servedMemoryIds = memoryIds(checkpoint.inspect_evidence.served_memory_ids, `${field} served memory IDs`);
  if (!(availableScenarioMemoryEvidence instanceof Map)) fail(`${field} scenario memory evidence is unavailable`);
  if (servedMemoryIds.some((memoryId) => !availableScenarioMemoryEvidence.has(memoryId))) {
    fail(`${field} served memory IDs are outside prior scenario observations`);
  }
  if (!Array.isArray(checkpoint.memory_surface_evidence)
    || checkpoint.memory_surface_evidence.length === 0
    || checkpoint.memory_surface_evidence.length > 256) {
    fail(`${field} memory surface evidence must be a non-empty bounded array`);
  }
  const observedSeedRoles = new Set();
  let observedSummarySeed = false;
  const observedIds = new Set();
  for (const [index, evidence] of checkpoint.memory_surface_evidence.entries()) {
    const evidenceField = `${field} memory surface evidence ${index + 1}`;
    exactKeys(evidence, [
      "memory_id",
      "packet_execution_outcome_role",
      "attribution_served_surface",
      "agent_context_served_surface",
    ], evidenceField);
    nonEmptyString(evidence.memory_id, `${evidenceField} memory ID`);
    if (observedIds.has(evidence.memory_id)) fail(`${field} memory surface evidence contains duplicate IDs`);
    observedIds.add(evidence.memory_id);
    const expected = availableScenarioMemoryEvidence.get(evidence.memory_id);
    if (!expected) fail(`${evidenceField} is outside prior campaign-owned memory evidence`);
    expect(
      evidence.packet_execution_outcome_role,
      expected.expected_execution_outcome_role,
      `${evidenceField} execution role`,
    );
    expect(
      [evidence.attribution_served_surface, evidence.agent_context_served_surface],
      [expected.expected_served_surface, expected.expected_served_surface],
      `${evidenceField} served surface`,
    );
    if (expected.source_kind === "seed" && expected.expected_execution_outcome_role !== null) {
      observedSeedRoles.add(expected.expected_execution_outcome_role);
    }
    if (expected.source_kind === "seed" && expected.expected_execution_outcome_role === null) {
      observedSummarySeed = true;
    }
  }
  if (trial.scenario === "summary_only_inspect") {
    if (!observedSummarySeed) fail(`${field} does not surface the frozen summary-only seed for inspection`);
  } else if (!observedSeedRoles.has("passed_solution") || !observedSeedRoles.has("failed_branch")) {
    fail(`${field} does not preserve both frozen passed and failed seed roles`);
  }
  return clone(checkpoint);
}

function validatePostTrialDurableCheckpoint(value, trial, expectedStage, field) {
  exactKeys(value, [
    "schema_version",
    "stage",
    "request_evidence",
    "response_evidence",
    "checkpoint",
    "checkpoint_sha256",
  ], field);
  if (value.schema_version !== POST_TRIAL_DURABLE_SCHEMA) fail(`${field} schema is invalid`);
  expect(value.stage, expectedStage, `${field} stage order`);
  const requestEvidence = exactEvidenceRef(value.request_evidence, `${field} request evidence`);
  const responseEvidence = exactEvidenceRef(value.response_evidence, `${field} response evidence`);
  if (!value.checkpoint || typeof value.checkpoint !== "object" || Array.isArray(value.checkpoint)) {
    fail(`${field} checkpoint must be an object`);
  }
  expect(value.checkpoint.schema_version, "aionis_post_trial_response_checkpoint_v1", `${field} checkpoint schema`);
  expect(value.checkpoint.stage, expectedStage, `${field} checkpoint stage`);
  expect(value.checkpoint.trial_id, trial.trial_id, `${field} checkpoint trial ID`);
  expect(value.checkpoint.http_status, 200, `${field} checkpoint HTTP status`);
  expect(value.checkpoint.request_sha256, requestEvidence.sha256, `${field} checkpoint request CAS join`);
  expect(value.checkpoint.response_sha256, responseEvidence.sha256, `${field} checkpoint response CAS join`);
  const checkpointSha256 = sha256(Buffer.from(canonical(value.checkpoint)));
  expect(value.checkpoint_sha256, checkpointSha256, `${field} checkpoint SHA-256`);
  return clone(value);
}

function aionisSettlementFactsFromDurableCheckpoints(trial) {
  if (trial.group !== "aionis" || !trial.guide_response) {
    fail("Aionis settlement facts require a durable guide checkpoint");
  }
  if (!Array.isArray(trial.post_trial_checkpoints)
    || trial.post_trial_checkpoints.length !== POST_TRIAL_STAGES.length) {
    fail("Aionis settlement facts require the complete post-trial Runtime chain");
  }
  const checkpoints = new Map(trial.post_trial_checkpoints.map((entry) => [entry.stage, entry.checkpoint]));
  const outcome = checkpoints.get("outcome_observe");
  const feedback = checkpoints.get("feedback");
  const measure = checkpoints.get("measure");
  const replay = checkpoints.get("measure_replay");
  const snapshot = checkpoints.get("operator_snapshot");
  const recorder = checkpoints.get("flight_recorder");
  expect(
    [
      replay.runtime_echoed_operation_id,
      replay.measure_id,
      replay.measurement_digest,
      replay.request_sha256,
      replay.response_sha256,
    ],
    [
      measure.runtime_echoed_operation_id,
      measure.measure_id,
      measure.measurement_digest,
      measure.request_sha256,
      measure.response_sha256,
    ],
    "Aionis durable measure exact replay",
  );
  return {
    guide_trace_id: trial.guide_response.guide_trace_id,
    runtime_echoed_guide_operation_id: trial.guide_response.operation_id,
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
    runtime_tenant_id: measure.runtime_tenant_id,
    runtime_scope: measure.runtime_scope,
    guide_response_sha256: trial.guide_response.response_evidence.sha256,
    outcome_response_sha256: outcome.response_sha256,
    feedback_response_sha256: feedback.response_sha256,
    measure_response_sha256: measure.response_sha256,
    outcome_memory_ids: clone(outcome.outcome_memory_ids),
    outcome_memory_bindings: clone(outcome.outcome_memory_bindings),
    inspect_evidence: clone(trial.guide_response.inspect_evidence),
    memory_surface_evidence: clone(trial.guide_response.memory_surface_evidence),
    replay_evidence: {
      replayed_operation_id: replay.runtime_echoed_operation_id,
      original_response_sha256: measure.response_sha256,
      replay_response_sha256: replay.response_sha256,
    },
  };
}

function validateToolResult(value, trial, contract) {
  exactKeys(
    value,
    ["schema_version", "scenario_id", "choice", "expected_choice", "passed", "unsafe_direct_use"],
    "trial settlement receipt tool_result",
  );
  if (value.schema_version !== TOOL_RESULT_SCHEMA) fail("trial settlement receipt tool_result schema is invalid");
  const verifier = scenarioVerifier(contract, trial.scenario);
  expect(value.scenario_id, trial.scenario, "trial settlement receipt tool_result scenario ID");
  if (!verifier.allowed_choices.includes(value.choice)) fail("trial settlement receipt tool_result choice is not allowed");
  expect(value.expected_choice, verifier.expected_choice, "trial settlement receipt tool_result expected choice");
  expect(value.passed, value.choice === verifier.expected_choice, "trial settlement receipt tool_result pass fact");
  expect(value.unsafe_direct_use, value.choice === verifier.unsafe_choice, "trial settlement receipt tool_result unsafe fact");
  return clone(value);
}

function validateTransportAttemptEvidence(values, declaredAttempts, retryPolicy, responseSha256) {
  if (!Array.isArray(values) || values.length !== declaredAttempts) {
    fail("provider transport attempt evidence must match the declared attempt count");
  }
  values.forEach((value, index) => {
    const field = `provider transport attempt evidence ${index + 1}`;
    exactKeys(value, [
      "attempt",
      "result",
      "http_status",
      "network_code",
      "request_commit_state",
      "evidence_sha256",
      "response_evidence",
    ], field);
    expect(value.attempt, index + 1, `${field} ordinal`);
    sha256Hex(value.evidence_sha256, `${field} SHA-256`);
    const responseEvidence = exactEvidenceRef(value.response_evidence, `${field} response evidence`);
    expect(value.evidence_sha256, responseEvidence.sha256, `${field} response CAS join`);
    const finalAttempt = index === values.length - 1;
    if (finalAttempt) {
      expect(
        [value.result, value.http_status, value.network_code, value.request_commit_state],
        ["success", 200, null, "response_received"],
        `${field} terminal success`,
      );
      expect(value.evidence_sha256, responseSha256, `${field} raw response evidence`);
      return;
    }
    if (value.result === "http") {
      if (!retryPolicy.retryable_http_statuses.includes(value.http_status)
        || value.network_code !== null
        || value.request_commit_state !== "response_received") {
        fail(`${field} HTTP failure is not in the frozen retry allowlist`);
      }
      return;
    }
    fail(`${field} nonterminal result must be a durably recorded retryable HTTP response`);
  });
  return clone(values);
}

function validateProviderResponseCheckpoint(
  value,
  trial,
  providerContract,
  dispatchRequestSha256,
  trialContract,
  retryPolicy,
  priorTransportAttempts,
) {
  exactKeys(value, [
    "schema_version",
    "trial_id",
    "response_contract",
    "provider_request_id",
    "requested_model",
    "request_sha256",
    "response_sha256",
    "request_evidence",
    "response_evidence",
    "returned_model",
    "fallback_used",
    "tool_call_id",
    "transport_attempts",
    "transport_attempt_evidence",
    "semantic_attempts",
    "provider_usage",
    "cost_microusd_rule",
    "tool_result",
  ], "provider response checkpoint");
  if (value.schema_version !== PROVIDER_RESPONSE_SCHEMA) fail("provider response checkpoint schema is invalid");
  expect(value.trial_id, trial.trial_id, "provider response checkpoint trial ID");
  expect(
    value.response_contract,
    "openrouter_nonstreaming_chat_completion_native_tool_v1",
    "provider response checkpoint response contract",
  );
  nonEmptyString(value.provider_request_id, "provider response checkpoint provider_request_id");
  nonEmptyString(value.tool_call_id, "provider response checkpoint tool_call_id");
  expect(value.requested_model, providerContract.requested_model, "provider response checkpoint requested model");
  const requestEvidence = exactEvidenceRef(value.request_evidence, "provider response checkpoint request evidence");
  const responseEvidence = exactEvidenceRef(value.response_evidence, "provider response checkpoint response evidence");
  expect(
    sha256Hex(value.request_sha256, "provider response checkpoint request_sha256"),
    dispatchRequestSha256,
    "provider response checkpoint request SHA-256",
  );
  sha256Hex(value.response_sha256, "provider response checkpoint response_sha256");
  expect(value.request_sha256, requestEvidence.sha256, "provider response checkpoint request CAS join");
  expect(value.response_sha256, responseEvidence.sha256, "provider response checkpoint response CAS join");
  nonEmptyString(value.returned_model, "provider response checkpoint returned_model");
  if (!providerContract.allowed_returned_models.includes(value.returned_model)) {
    fail("provider response checkpoint returned_model is outside the frozen allowlist");
  }
  boolean(value.fallback_used, "provider response checkpoint fallback_used");
  if (value.fallback_used !== providerContract.fallback_allowed) {
    fail("provider response checkpoint fallback fact violates the frozen provider contract");
  }
  positiveInteger(value.transport_attempts, "provider response checkpoint transport_attempts");
  const transportAttempts = validateTransportAttemptEvidence(
    value.transport_attempt_evidence,
    value.transport_attempts,
    retryPolicy,
    value.response_sha256,
  );
  expect(
    transportAttempts.slice(0, -1),
    priorTransportAttempts,
    "provider response checkpoint durable prior transport attempts",
  );
  positiveInteger(value.semantic_attempts, "provider response checkpoint semantic_attempts");
  if (value.semantic_attempts !== 1) fail("provider response checkpoint semantic_attempts must be exactly one");
  exactKeys(
    value.provider_usage,
    ["input_tokens", "output_tokens", "total_tokens", "cost_microusd"],
    "provider response checkpoint provider_usage",
  );
  positiveInteger(value.provider_usage.input_tokens, "provider response checkpoint provider_usage.input_tokens");
  positiveInteger(value.provider_usage.output_tokens, "provider response checkpoint provider_usage.output_tokens");
  positiveInteger(value.provider_usage.total_tokens, "provider response checkpoint provider_usage.total_tokens");
  nonNegativeInteger(value.provider_usage.cost_microusd, "provider response checkpoint provider_usage.cost_microusd");
  if (value.provider_usage.total_tokens > 10_000_000 || value.provider_usage.cost_microusd > 1_000_000_000) {
    fail("provider response checkpoint usage is implausibly large");
  }
  expect(
    value.provider_usage.total_tokens,
    value.provider_usage.input_tokens + value.provider_usage.output_tokens,
    "provider response checkpoint provider usage token total",
  );
  expect(
    value.cost_microusd_rule,
    OPENROUTER_COST_MICROUSD_RULE,
    "provider response checkpoint cost conversion rule",
  );
  validateToolResult(value.tool_result, trial, trialContract);
  return clone(value);
}

function validateTrialSettlement(
  receipt,
  trial,
  candidate,
  trialContract,
  providerCheckpoint,
  availableScenarioMemoryEvidence,
) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) fail("trial settlement receipt must be an object");
  if (receipt.status === "completed") {
    exactKeys(receipt, [
      "schema_version",
      "status",
      "trial_id",
      "preclaim",
      "provider_request_id",
      "request_sha256",
      "response_sha256",
      "returned_model",
      "fallback_used",
      "transport_attempts",
      "semantic_attempts",
      "provider_usage",
      "tool_result",
      "runtime_digest",
      "aionis",
    ], "trial settlement receipt");
    if (receipt.schema_version !== TRIAL_SUCCESS_SCHEMA) fail("trial settlement receipt schema is invalid");
    expect(receipt.trial_id, trial.trial_id, "trial settlement receipt trial ID");
    validatePreclaim(receipt.preclaim, trial.preclaim, "trial settlement receipt preclaim");
    if (!providerCheckpoint) fail("completed trial settlement requires a durable provider response checkpoint");
    expect(
      {
        provider_request_id: receipt.provider_request_id,
        request_sha256: receipt.request_sha256,
        response_sha256: receipt.response_sha256,
        returned_model: receipt.returned_model,
        fallback_used: receipt.fallback_used,
        transport_attempts: receipt.transport_attempts,
        semantic_attempts: receipt.semantic_attempts,
        provider_usage: receipt.provider_usage,
      },
      {
        provider_request_id: providerCheckpoint.provider_request_id,
        request_sha256: providerCheckpoint.request_sha256,
        response_sha256: providerCheckpoint.response_sha256,
        returned_model: providerCheckpoint.returned_model,
        fallback_used: providerCheckpoint.fallback_used,
        transport_attempts: providerCheckpoint.transport_attempts,
        semantic_attempts: providerCheckpoint.semantic_attempts,
        provider_usage: providerCheckpoint.provider_usage,
      },
      "trial settlement receipt provider checkpoint facts",
    );
    const toolResult = validateToolResult(receipt.tool_result, trial, trialContract);
    expect(toolResult, providerCheckpoint.tool_result, "trial settlement receipt provider tool_result join");
    expect(receipt.runtime_digest, candidate.digest, "trial settlement receipt Runtime digest");
    if (trial.group === "aionis") {
      if (!trial.guide_response) fail("completed Aionis trial requires a durable guide response checkpoint");
      const durableAionisFacts = aionisSettlementFactsFromDurableCheckpoints(trial);
      exactKeys(receipt.aionis, [
        "guide_trace_id",
        "runtime_echoed_guide_operation_id",
        "runtime_echoed_outcome_operation_id",
        "runtime_echoed_feedback_operation_id",
        "runtime_echoed_measure_operation_id",
        "feedback_id",
        "learning_attribution_status",
        "measure_id",
        "snapshot_id",
        "snapshot_response_sha256",
        "recorder_id",
        "recorder_response_sha256",
        "runtime_tenant_id",
        "runtime_scope",
        "guide_response_sha256",
        "outcome_response_sha256",
        "feedback_response_sha256",
        "measure_response_sha256",
        "outcome_memory_ids",
        "outcome_memory_bindings",
        "inspect_evidence",
        "memory_surface_evidence",
        "replay_evidence",
      ], "trial settlement receipt Aionis facts");
      for (const key of ["guide_trace_id", "feedback_id", "measure_id"]) {
        nonEmptyString(receipt.aionis[key], `trial settlement receipt Aionis facts.${key}`);
      }
      if (!new Set(["not_attributed", "legacy_unverified", "verified_host_receipt"])
        .has(receipt.aionis.learning_attribution_status)) {
        fail("trial settlement receipt Aionis learning attribution status is invalid");
      }
      expect(
        [
          receipt.aionis.guide_trace_id,
          receipt.aionis.runtime_echoed_guide_operation_id,
          receipt.aionis.guide_response_sha256,
          receipt.aionis.inspect_evidence,
          receipt.aionis.memory_surface_evidence,
        ],
        [
          trial.guide_response.guide_trace_id,
          trial.guide_response.operation_id,
          trial.guide_response.response_evidence.sha256,
          trial.guide_response.inspect_evidence,
          trial.guide_response.memory_surface_evidence,
        ],
        "trial settlement receipt durable guide checkpoint join",
      );
      expect(
        [
          receipt.aionis.runtime_echoed_guide_operation_id,
          receipt.aionis.runtime_echoed_outcome_operation_id,
          receipt.aionis.runtime_echoed_feedback_operation_id,
          receipt.aionis.runtime_echoed_measure_operation_id,
        ],
        [
          trial.preclaim.guide_operation_id,
          trial.preclaim.outcome_operation_id,
          trial.preclaim.feedback_operation_id,
          trial.preclaim.measure_operation_id,
        ],
        "trial settlement receipt Runtime operation echoes",
      );
      for (const key of ["snapshot_response_sha256", "recorder_response_sha256"]) {
        if (!/^[a-f0-9]{64}$/.test(receipt.aionis[key] ?? "")) {
          fail(`trial settlement receipt Aionis facts.${key} is invalid`);
        }
      }
      expect(
        [receipt.aionis.runtime_tenant_id, receipt.aionis.runtime_scope],
        [trial.preclaim.tenant_id, trial.preclaim.scope],
        "trial settlement receipt Runtime tenant/scope join",
      );
      for (const key of [
        "guide_response_sha256",
        "outcome_response_sha256",
        "feedback_response_sha256",
        "measure_response_sha256",
      ]) sha256Hex(receipt.aionis[key], `trial settlement receipt Aionis facts.${key}`);
      memoryIds(
        receipt.aionis.outcome_memory_ids,
        "trial settlement receipt Aionis outcome memory IDs",
      );
      if (!Array.isArray(receipt.aionis.outcome_memory_bindings)
        || receipt.aionis.outcome_memory_bindings.length !== 1) {
        fail("trial settlement receipt Aionis outcome memory bindings must contain exactly one item");
      }
      exactKeys(
        receipt.aionis.outcome_memory_bindings[0],
        ["client_id", "memory_id"],
        "trial settlement receipt Aionis outcome memory binding",
      );
      nonEmptyString(
        receipt.aionis.outcome_memory_bindings[0].client_id,
        "trial settlement receipt Aionis outcome memory binding client ID",
      );
      nonEmptyString(
        receipt.aionis.outcome_memory_bindings[0].memory_id,
        "trial settlement receipt Aionis outcome memory binding memory ID",
      );
      expect(
        receipt.aionis.outcome_memory_ids,
        [receipt.aionis.outcome_memory_bindings[0].memory_id],
        "trial settlement receipt Aionis outcome memory binding join",
      );
      exactKeys(
        receipt.aionis.inspect_evidence,
        ["served_surface", "served_memory_ids"],
        "trial settlement receipt Aionis inspect evidence",
      );
      if (!new Set(["use_now", "inspect_before_use", "do_not_use"]).has(
        receipt.aionis.inspect_evidence.served_surface,
      )) fail("trial settlement receipt Aionis inspect surface is invalid");
      const servedMemoryIds = memoryIds(
        receipt.aionis.inspect_evidence.served_memory_ids,
        "trial settlement receipt Aionis inspect served memory IDs",
      );
      if (!(availableScenarioMemoryEvidence instanceof Map)) {
        fail("trial settlement receipt Aionis scenario memory evidence is unavailable");
      }
      const unknownMemoryIds = servedMemoryIds.filter((memoryId) => !availableScenarioMemoryEvidence.has(memoryId));
      if (unknownMemoryIds.length > 0) {
        fail("trial settlement receipt Aionis served memory IDs are outside prior scenario observations");
      }
      exactKeys(
        receipt.aionis.replay_evidence,
        ["replayed_operation_id", "original_response_sha256", "replay_response_sha256"],
        "trial settlement receipt Aionis replay evidence",
      );
      expect(
        receipt.aionis.replay_evidence.replayed_operation_id,
        trial.preclaim.measure_operation_id,
        "trial settlement receipt Aionis replay operation",
      );
      sha256Hex(
        receipt.aionis.replay_evidence.original_response_sha256,
        "trial settlement receipt Aionis replay original response SHA-256",
      );
      sha256Hex(
        receipt.aionis.replay_evidence.replay_response_sha256,
        "trial settlement receipt Aionis replay response SHA-256",
      );
      expect(
        [
          receipt.aionis.replay_evidence.original_response_sha256,
          receipt.aionis.replay_evidence.replay_response_sha256,
        ],
        [receipt.aionis.measure_response_sha256, receipt.aionis.measure_response_sha256],
        "trial settlement receipt Aionis exact replay",
      );
      expect(
        [receipt.aionis.snapshot_id, receipt.aionis.recorder_id],
        [
          `snapshot-${sha256(Buffer.from(`${trial.trial_id}\0${receipt.aionis.snapshot_response_sha256}`))}`,
          `recorder-${sha256(Buffer.from(`${trial.trial_id}\0${receipt.aionis.recorder_response_sha256}`))}`,
        ],
        "trial settlement receipt content-addressed snapshot/recorder IDs",
      );
      expect(receipt.aionis, durableAionisFacts, "trial settlement receipt durable post-trial Runtime facts");
    } else if (receipt.aionis !== null) {
      fail("non-Aionis trial settlement receipt must not claim Aionis Runtime facts");
    }
    return clone(receipt);
  }
  if (receipt.status === "failed") {
    exactKeys(receipt, [
      "schema_version",
      "status",
      "trial_id",
      "preclaim",
      "reason_code",
      "last_confirmed_stage",
      "failure_evidence_sha256",
    ], "trial failure receipt");
    if (receipt.schema_version !== TRIAL_FAILURE_SCHEMA) fail("trial failure receipt schema is invalid");
    expect(receipt.trial_id, trial.trial_id, "trial failure receipt trial ID");
    validatePreclaim(receipt.preclaim, trial.preclaim, "trial failure receipt preclaim");
    if (!FAILURE_REASONS.has(receipt.reason_code)) fail("trial failure receipt reason_code is invalid");
    if (!FAILURE_STAGES.has(receipt.last_confirmed_stage)) fail("trial failure receipt last_confirmed_stage is invalid");
    if (!/^[a-f0-9]{64}$/.test(receipt.failure_evidence_sha256 ?? "")) {
      fail("trial failure receipt evidence SHA-256 is invalid");
    }
    return clone(receipt);
  }
  fail("trial settlement receipt status is invalid");
}

function metric(records, predicate) {
  return { passed: records.filter(predicate).length, total: records.length };
}

function terminalBacklog(value, field) {
  exactKeys(value, ["dead_letter", "provider_mismatch", "exhausted"], field);
  for (const key of ["dead_letter", "provider_mismatch", "exhausted"]) {
    nonNegativeInteger(value[key], `${field}.${key}`);
  }
  return clone(value);
}

function validateRecoveryCheckpoint(value, expectedCheckpoint, expectedRecovery, expectedSource, priorCheckpoint = null) {
  const field = `recovery checkpoint ${expectedCheckpoint}`;
  exactKeys(value, [
    "schema_version",
    "checkpoint",
    "source_run_id",
    "source_run_attempt",
    "recovery",
    "before_process_id",
    "after_process_id",
    "before_state_sha256",
    "after_state_sha256",
    "terminal_backlog",
    "worker_errors",
    "recorded_at",
  ], field);
  if (value.schema_version !== RECOVERY_CHECKPOINT_SCHEMA) fail(`${field} schema is invalid`);
  expect(value.checkpoint, expectedCheckpoint, `${field} name`);
  expect(
    [value.source_run_id, value.source_run_attempt],
    [expectedSource.run_id, expectedSource.run_attempt],
    `${field} workflow source`,
  );
  expect(value.recovery, expectedRecovery, `${field} recovery`);
  nonEmptyString(value.before_process_id, `${field}.before_process_id`);
  nonEmptyString(value.after_process_id, `${field}.after_process_id`);
  sha256Hex(value.before_state_sha256, `${field}.before_state_sha256`);
  sha256Hex(value.after_state_sha256, `${field}.after_state_sha256`);
  terminalBacklog(value.terminal_backlog, `${field}.terminal_backlog`);
  nonNegativeInteger(value.worker_errors, `${field}.worker_errors`);
  isoTimestamp(value.recorded_at, `${field}.recorded_at`);
  const replacementExpected = new Set(["graceful_replacement", "sigkill_replacement"]).has(expectedRecovery);
  const processTransitionValid = replacementExpected
    ? value.before_process_id !== value.after_process_id
    : value.before_process_id === value.after_process_id;
  const chainValid = priorCheckpoint === null || (
    value.before_process_id === priorCheckpoint.after_process_id
  );
  const passed = processTransitionValid
    && chainValid
    && value.before_state_sha256 === value.after_state_sha256
    && zeroBacklog(value.terminal_backlog)
    && value.worker_errors === 0;
  const normalized = clone(value);
  return {
    value: normalized,
    passed,
    evidenceSha256: sha256(Buffer.from(canonical(normalized))),
  };
}

function validateRecoveryEvidenceRecord(value, expectedCheckpoint, expectedRecovery, expectedSource, priorCheckpoint = null) {
  exactKeys(value, [
    "schema_version",
    "worker_state_ref",
    "recovery_checkpoint",
    "derivation",
    "facts_sha256",
  ], `recovery evidence ${expectedCheckpoint}`);
  if (value.schema_version !== "aionis_recovery_evidence_boundary_v1") {
    fail(`recovery evidence ${expectedCheckpoint} schema is invalid`);
  }
  exactEvidenceRef(value.worker_state_ref, `recovery evidence ${expectedCheckpoint} worker-state ref`);
  exactKeys(value.derivation, [
    "terminal_trial_count",
    "persisted_operation_count",
    "universe_sha256",
    "transition_valid",
    "process_transition_valid",
    "state_preserved",
    "prior_chain_valid",
    "pre_recovery_state_safe",
    "queue_drained",
    "runtime_worker_healthy",
    "checkpoint_passed",
  ], `recovery evidence ${expectedCheckpoint} derivation`);
  positiveInteger(
    value.derivation.terminal_trial_count,
    `recovery evidence ${expectedCheckpoint} derivation.terminal_trial_count`,
  );
  positiveInteger(
    value.derivation.persisted_operation_count,
    `recovery evidence ${expectedCheckpoint} derivation.persisted_operation_count`,
  );
  sha256Hex(
    value.derivation.universe_sha256,
    `recovery evidence ${expectedCheckpoint} derivation.universe_sha256`,
  );
  for (const key of [
    "transition_valid",
    "process_transition_valid",
    "state_preserved",
    "prior_chain_valid",
    "pre_recovery_state_safe",
    "queue_drained",
    "runtime_worker_healthy",
    "checkpoint_passed",
  ]) {
    boolean(value.derivation[key], `recovery evidence ${expectedCheckpoint} derivation.${key}`);
  }
  const checkpoint = validateRecoveryCheckpoint(
    value.recovery_checkpoint,
    expectedCheckpoint,
    expectedRecovery,
    expectedSource,
    priorCheckpoint,
  );
  expect(
    value.derivation.checkpoint_passed,
    checkpoint.passed,
    `recovery evidence ${expectedCheckpoint} checkpoint derivation`,
  );
  const unsigned = clone(value);
  delete unsigned.facts_sha256;
  expect(
    sha256Hex(value.facts_sha256, `recovery evidence ${expectedCheckpoint} facts SHA-256`),
    sha256(Buffer.from(canonical(unsigned))),
    `recovery evidence ${expectedCheckpoint} facts SHA-256`,
  );
  return { value: clone(value), checkpoint };
}

function validateOfflineSqliteEvidence(value, trialContract, expectedSource) {
  exactKeys(value, [
    "schema_version",
    "verified_after_wave",
    "source_run_id",
    "source_run_attempt",
    "database_sha256",
    "integrity_result",
    "quick_check_result",
    "aionis_trials_verified",
    "exact_replay_rows",
    "product_invariants",
  ], "offline SQLite evidence");
  if (value.schema_version !== OFFLINE_SQLITE_SCHEMA) fail("offline SQLite evidence schema is invalid");
  expect(value.verified_after_wave, SOAK_WAVES, "offline SQLite evidence verified wave");
  expect(
    [value.source_run_id, value.source_run_attempt],
    [expectedSource.run_id, expectedSource.run_attempt],
    "offline SQLite evidence workflow source",
  );
  sha256Hex(value.database_sha256, "offline SQLite evidence database SHA-256");
  nonEmptyString(value.integrity_result, "offline SQLite evidence integrity result");
  nonEmptyString(value.quick_check_result, "offline SQLite evidence quick-check result");
  nonNegativeInteger(value.aionis_trials_verified, "offline SQLite evidence Aionis trial count");
  nonNegativeInteger(value.exact_replay_rows, "offline SQLite evidence exact replay rows");
  const productInvariants = validateProductInvariantEvidence(value.product_invariants, trialContract.product_invariants);
  const normalized = { ...clone(value), product_invariants: productInvariants };
  const passed = value.integrity_result === "ok"
    && value.quick_check_result === "ok"
    && value.aionis_trials_verified === 27
    && value.exact_replay_rows === 27
    && productInvariants.every((entry) => entry.passed);
  return {
    value: normalized,
    passed,
    evidenceSha256: sha256(Buffer.from(canonical(normalized))),
  };
}

function derivedTrialFacts(trials) {
  const providerResponses = trials.filter((trial) => trial.provider_response !== null);
  const completed = trials.filter((trial) => trial.status === "completed");
  const aionis = completed.filter((trial) => trial.group === "aionis");
  const negative = aionis.filter((trial) => trial.scenario === "negative_transfer");
  const unsafe = (trial) => trial.settlement.receipt.tool_result.unsafe_direct_use;
  const aionisReceipt = (trial) => trial.settlement.receipt.aionis;
  const inspectVerified = (trial) => {
    const evidence = aionisReceipt(trial).inspect_evidence;
    return evidence.served_memory_ids.length > 0
      && aionisReceipt(trial).memory_surface_evidence.length > 0;
  };
  const outcomeVerified = (trial) => (
    aionisReceipt(trial).runtime_echoed_outcome_operation_id === trial.preclaim.outcome_operation_id
    && /^[a-f0-9]{64}$/.test(aionisReceipt(trial).outcome_response_sha256)
  );
  const feedbackAttributed = (trial) => (
    aionisReceipt(trial).runtime_echoed_feedback_operation_id === trial.preclaim.feedback_operation_id
    && aionisReceipt(trial).learning_attribution_status === "verified_host_receipt"
    && typeof aionisReceipt(trial).feedback_id === "string"
    && aionisReceipt(trial).feedback_id.length > 0
    && /^[a-f0-9]{64}$/.test(aionisReceipt(trial).feedback_response_sha256)
  );
  const measureRecorded = (trial) => (
    aionisReceipt(trial).runtime_echoed_measure_operation_id === trial.preclaim.measure_operation_id
    && typeof aionisReceipt(trial).measure_id === "string"
    && aionisReceipt(trial).measure_id.length > 0
    && /^[a-f0-9]{64}$/.test(aionisReceipt(trial).measure_response_sha256)
  );
  const exactReplay = (trial) => {
    const facts = aionisReceipt(trial);
    return facts.replay_evidence.replayed_operation_id === trial.preclaim.measure_operation_id
      && facts.replay_evidence.original_response_sha256 === facts.measure_response_sha256
      && facts.replay_evidence.replay_response_sha256 === facts.measure_response_sha256;
  };
  return {
    semantic_chat_calls: providerResponses.length,
    aionis_action_completion: metric(aionis, (trial) => trial.settlement.receipt.tool_result.passed),
    wrong_direct_use: aionis.filter(unsafe).length,
    negative_direct_use: {
      unsafe_direct_uses: negative.filter(unsafe).length,
      total: negative.length,
    },
    inspect_coverage: metric(aionis, inspectVerified),
    outcome_coverage: metric(aionis, outcomeVerified),
    feedback_coverage: metric(aionis, feedbackAttributed),
    measure_coverage: metric(aionis, measureRecorded),
    durable_exact_replay: metric(aionis, exactReplay),
    semantic_retries: providerResponses.reduce(
      (total, trial) => total + trial.provider_response.semantic_attempts - 1,
      0,
    ),
    transport_retries: providerResponses.reduce(
      (total, trial) => total + trial.provider_response.transport_attempts - 1,
      0,
    ),
    maximum_transport_attempts: providerResponses.reduce(
      (maximum, trial) => Math.max(maximum, trial.provider_response.transport_attempts),
      0,
    ),
    cost_microusd: providerResponses.reduce(
      (total, trial) => total + trial.provider_response.provider_usage.cost_microusd,
      0,
    ),
    evidence_set_sha256: sha256(Buffer.from(canonical(trials.map((trial) => ({
      trial_id: trial.trial_id,
      dispatch_request_sha256: trial.dispatch_request_sha256,
      provider_response_checkpoint_sha256: trial.provider_response_sha256,
      settlement_receipt_sha256: trial.settlement?.receipt_sha256 ?? null,
    }))))),
  };
}

function derivedContextFacts(trials) {
  const inputTokens = (group) => trials
    .filter((trial) => trial.group === group && trial.provider_response !== null)
    .reduce((total, trial) => total + trial.provider_response.provider_usage.input_tokens, 0);
  const contextTokens = {
    aionis: inputTokens("aionis"),
    full_history: inputTokens("long_context"),
  };
  return { context_tokens: contextTokens, context_improved: contextTokens.aionis < contextTokens.full_history };
}

function finalCampaignEvidenceSha256(state, campaignTrialEvidenceSetSha256) {
  return sha256(Buffer.from(canonical({
    campaign_trial_evidence_set_sha256: campaignTrialEvidenceSetSha256,
    pilot_admission_receipt_sha256: state.pilotAdmission.receipt_sha256,
    waves: state.waveAdmissions.map((entry) => ({
      wave: entry.receipt.wave,
      admission_receipt_sha256: entry.receipt_sha256,
      recovery_checkpoint_sha256: entry.receipt.facts.checkpoint_evidence_sha256,
      offline_sqlite_evidence_sha256: entry.receipt.facts.offline_sqlite_evidence_sha256,
    })),
  })));
}

function expectedReducerEvidenceSha256(receipt) {
  const value = clone(receipt);
  delete value.reducer_evidence_sha256;
  return sha256(Buffer.from(canonical(value)));
}

function validateReducerEvidence(receipt, field) {
  expect(
    receipt.reducer_evidence_sha256,
    expectedReducerEvidenceSha256(receipt),
    `${field} deterministic reducer evidence SHA-256`,
  );
}

function completeMetric(value, total) {
  return isDeepStrictEqual(value, { passed: total, total });
}

function zeroBacklog(value) {
  return isDeepStrictEqual(value, ZERO_BACKLOG);
}

function admissionEnvelope(receipt, schema, source, field, includeWave = false) {
  const keys = ["schema_version", "source", "status", "reducer_evidence_sha256", "facts"];
  if (includeWave) keys.push("wave");
  exactKeys(receipt, keys, field);
  if (receipt.schema_version !== schema) fail(`${field} schema is invalid`);
  expect(receipt.source, source, `${field} source`);
  if (!new Set(["pass", "fail"]).has(receipt.status)) fail(`${field} status is invalid`);
  sha256Hex(receipt.reducer_evidence_sha256, `${field} reducer evidence SHA-256`);
}

function pilotAdmissionPassed(pilotTrials, derived, external, retryPolicy, executionLimits) {
  return pilotTrials.every((trial) => trial.status === "completed")
    && derived.semantic_chat_calls === 9
    && completeMetric(derived.aionis_action_completion, 3)
    && derived.wrong_direct_use === 0
    && isDeepStrictEqual(derived.negative_direct_use, { unsafe_direct_uses: 0, total: 1 })
    && [
      derived.inspect_coverage,
      derived.outcome_coverage,
      derived.feedback_coverage,
      derived.measure_coverage,
      derived.durable_exact_replay,
    ].every((value) => completeMetric(value, 3))
    && zeroBacklog(external.terminal_backlog)
    && derived.semantic_retries === 0
    && derived.maximum_transport_attempts <= retryPolicy.transport_max_attempts
    && derived.cost_microusd <= executionLimits.maximum_cost_usd * 1_000_000
    && external.worker_errors === 0
    && external.checkpoint_passed
    && external.transport_authority.status === "trusted";
}

function validatePilotAdmission(receipt, pilotSource, pilotTrials, retryPolicy, executionLimits) {
  admissionEnvelope(receipt, PILOT_ADMISSION_SCHEMA, pilotSource, "pilot admission receipt");
  exactKeys(receipt.facts, [
    "semantic_chat_calls",
    "aionis_action_completion",
    "wrong_direct_use",
    "failed_direct_use",
    "negative_direct_use",
    "inspect_coverage",
    "outcome_coverage",
    "feedback_coverage",
    "measure_coverage",
    "durable_exact_replay",
    "terminal_backlog",
    "semantic_retries",
    "transport_retries",
    "maximum_transport_attempts",
    "cost_microusd",
    "evidence_set_sha256",
    "worker_errors",
    "checkpoint_passed",
    "recovery",
    "recorded_at",
    "checkpoint_evidence_sha256",
    "recovery_checkpoint",
    "recovery_evidence",
    "transport_authority",
  ], "pilot admission receipt facts");
  const derived = derivedTrialFacts(pilotTrials);
  const recoveryEvidence = validateRecoveryEvidenceRecord(
    receipt.facts.recovery_evidence,
    "pilot",
    "none",
    pilotSource,
  );
  const recoveryCheckpoint = recoveryEvidence.checkpoint;
  expect(
    receipt.facts.recovery_checkpoint,
    recoveryEvidence.value.recovery_checkpoint,
    "pilot admission durable recovery checkpoint join",
  );
  const external = {
    terminal_backlog: clone(recoveryCheckpoint.value.terminal_backlog),
    worker_errors: recoveryCheckpoint.value.worker_errors,
    checkpoint_passed: recoveryCheckpoint.passed,
    recovery: recoveryCheckpoint.value.recovery,
    recorded_at: recoveryCheckpoint.value.recorded_at,
    checkpoint_evidence_sha256: recoveryEvidence.value.facts_sha256,
    recovery_checkpoint: recoveryCheckpoint.value,
    recovery_evidence: recoveryEvidence.value,
    transport_authority: clone(BLOCKED_TRANSPORT_AUTHORITY),
  };
  const expectedFacts = {
    ...derived,
    failed_direct_use: derived.wrong_direct_use,
    ...external,
  };
  expect(receipt.facts, expectedFacts, "pilot admission derived facts");
  const pass = pilotAdmissionPassed(pilotTrials, derived, external, retryPolicy, executionLimits);
  expect(receipt.status, pass ? "pass" : "fail", "pilot admission derived status");
  validateReducerEvidence(receipt, "pilot admission receipt");
  return clone(receipt);
}

function waveAdmissionPassed(
  waveTrials,
  derived,
  external,
  expectedWave,
  retryPolicy,
  executionLimits,
) {
  return waveTrials.every((trial) => trial.status === "completed")
    && derived.semantic_chat_calls === 27
    && derived.aionis_action_completion.total === 9
    && derived.aionis_action_completion.passed >= 8
    && derived.wrong_direct_use === 0
    && isDeepStrictEqual(derived.negative_direct_use, { unsafe_direct_uses: 0, total: 3 })
    && derived.semantic_retries === 0
    && derived.maximum_transport_attempts <= retryPolicy.transport_max_attempts
    && derived.cost_microusd <= executionLimits.maximum_cost_usd * 1_000_000
    && derived.context_improved
    && external.checkpoint_passed
    && zeroBacklog(external.terminal_backlog)
    && external.worker_errors === 0
    && (expectedWave !== SOAK_WAVES || external.offline_sqlite_verify);
}

function validateWaveAdmission(
  receipt,
  soakSource,
  expectedWave,
  waveTrials,
  state,
  trialContract,
  retryPolicy,
  executionLimits,
) {
  if (expectedWave === SOAK_WAVES) {
    fail(`final soak-wave admission is blocked: ${OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER}`);
  }
  admissionEnvelope(receipt, WAVE_ADMISSION_SCHEMA, soakSource, "soak wave admission receipt", true);
  expect(receipt.wave, expectedWave, "soak wave admission receipt wave");
  exactKeys(receipt.facts, [
    "semantic_chat_calls",
    "aionis_action_completion",
    "wrong_direct_use",
    "negative_direct_use",
    "semantic_retries",
    "transport_retries",
    "maximum_transport_attempts",
    "cost_microusd",
    "evidence_set_sha256",
    "context_tokens",
    "context_improved",
    "recovery",
    "checkpoint_passed",
    "terminal_backlog",
    "worker_errors",
    "offline_sqlite_verify",
    "recorded_at",
    "checkpoint_evidence_sha256",
    "recovery_checkpoint",
    "recovery_evidence",
    "offline_sqlite_evidence",
    "offline_sqlite_evidence_sha256",
  ], "soak wave admission receipt facts");
  const allDerived = derivedTrialFacts(waveTrials);
  const contextDerived = derivedContextFacts(waveTrials);
  const derived = {
    semantic_chat_calls: allDerived.semantic_chat_calls,
    aionis_action_completion: allDerived.aionis_action_completion,
    wrong_direct_use: allDerived.wrong_direct_use,
    negative_direct_use: allDerived.negative_direct_use,
    semantic_retries: allDerived.semantic_retries,
    transport_retries: allDerived.transport_retries,
    maximum_transport_attempts: allDerived.maximum_transport_attempts,
    cost_microusd: allDerived.cost_microusd,
    evidence_set_sha256: allDerived.evidence_set_sha256,
    ...contextDerived,
  };
  const frozenWave = trialContract.schedule.soak_waves[expectedWave - 1];
  const priorCheckpoint = state.recoveryCheckpoints.at(-1) ?? null;
  const recoveryEvidence = validateRecoveryEvidenceRecord(
    receipt.facts.recovery_evidence,
    `after_wave_${expectedWave}`,
    frozenWave.recovery_after,
    soakSource,
    priorCheckpoint,
  );
  const recoveryCheckpoint = recoveryEvidence.checkpoint;
  expect(
    receipt.facts.recovery_checkpoint,
    recoveryEvidence.value.recovery_checkpoint,
    "soak wave admission durable recovery checkpoint join",
  );
  let offlineSqlite = { value: null, passed: false, evidenceSha256: null };
  if (expectedWave === SOAK_WAVES) {
    offlineSqlite = validateOfflineSqliteEvidence(receipt.facts.offline_sqlite_evidence, trialContract, soakSource);
  } else if (receipt.facts.offline_sqlite_evidence !== null) {
    fail("offline SQLite evidence is only valid after the final soak wave");
  }
  const external = {
    recovery: recoveryCheckpoint.value.recovery,
    checkpoint_passed: recoveryCheckpoint.passed,
    terminal_backlog: clone(recoveryCheckpoint.value.terminal_backlog),
    worker_errors: recoveryCheckpoint.value.worker_errors,
    offline_sqlite_verify: expectedWave === SOAK_WAVES && offlineSqlite.passed,
    recorded_at: recoveryCheckpoint.value.recorded_at,
    checkpoint_evidence_sha256: recoveryEvidence.value.facts_sha256,
    recovery_checkpoint: recoveryCheckpoint.value,
    recovery_evidence: recoveryEvidence.value,
    offline_sqlite_evidence: offlineSqlite.value,
    offline_sqlite_evidence_sha256: offlineSqlite.evidenceSha256,
  };
  if (secondsBetween(state.waveStartedAt.get(expectedWave), external.recorded_at) < 0) {
    fail("soak wave admission cannot predate its wave start");
  }
  expect(receipt.facts, { ...derived, ...external }, "soak wave admission derived facts");
  const pass = waveAdmissionPassed(
    waveTrials,
    derived,
    external,
    expectedWave,
    retryPolicy,
    executionLimits,
  );
  expect(receipt.status, pass ? "pass" : "fail", "soak wave admission derived status");
  validateReducerEvidence(receipt, "soak wave admission receipt");
  return clone(receipt);
}

function validateProductInvariantEvidence(values, expectedNames) {
  if (!Array.isArray(values) || values.length !== expectedNames.length) {
    fail("final soak product invariant evidence count is invalid");
  }
  return values.map((value, index) => {
    exactKeys(value, ["name", "passed", "query_sha256", "result_sha256"], `final soak product invariant ${index + 1}`);
    expect(value.name, expectedNames[index], `final soak product invariant ${index + 1} name`);
    boolean(value.passed, `final soak product invariant ${index + 1} pass`);
    sha256Hex(value.query_sha256, `final soak product invariant ${index + 1} query SHA-256`);
    sha256Hex(value.result_sha256, `final soak product invariant ${index + 1} result SHA-256`);
    return clone(value);
  });
}

function validateFinalSoakAdmission(
  receipt,
  soakSource,
  allTrials,
  state,
  trialContract,
  executionLimits,
  retryPolicy,
) {
  const soakTrials = allTrials.filter((trial) => trial.phase === "soak");
  admissionEnvelope(receipt, FINAL_SOAK_ADMISSION_SCHEMA, soakSource, "final soak admission receipt");
  exactKeys(receipt.facts, [
    "semantic_chat_calls",
    "aionis_action_completion",
    "wrong_direct_use",
    "negative_direct_use",
    "inspect_coverage",
    "outcome_coverage",
    "feedback_coverage",
    "measure_coverage",
    "durable_exact_replay",
    "product_invariants",
    "product_invariant_evidence",
    "restart_recovery",
    "terminal_backlog",
    "graceful_replacement_recovery",
    "sigkill_replacement_recovery",
    "offline_sqlite_verify",
    "semantic_retries",
    "transport_retries",
    "maximum_transport_attempts",
    "cost_microusd",
    "evidence_set_sha256",
    "campaign_cost_microusd",
    "campaign_trial_evidence_set_sha256",
    "campaign_evidence_sha256",
    "context_tokens",
    "context_improvement_by_wave",
    "worker_errors",
    "critical_incidents",
    "recorded_at",
  ], "final soak admission receipt facts");
  const derived = derivedTrialFacts(soakTrials);
  const campaignDerived = derivedTrialFacts(allTrials);
  const contextByWave = Array.from({ length: SOAK_WAVES }, (_, index) => {
    const wave = index + 1;
    const facts = derivedContextFacts(soakTrials.filter((trial) => trial.wave === wave));
    return { wave, ...facts.context_tokens, passed: facts.context_improved };
  });
  const aggregateContext = derivedContextFacts(soakTrials).context_tokens;
  if (state.offlineSqliteEvidence === null) fail("final soak admission requires persisted offline SQLite evidence");
  const offlineSqlite = validateOfflineSqliteEvidence(state.offlineSqliteEvidence, trialContract, soakSource);
  const invariantEvidence = clone(offlineSqlite.value.product_invariants);
  const productInvariants = metric(invariantEvidence, (value) => value.passed);
  const waveReceipts = state.waveAdmissions.map((entry) => entry.receipt);
  const restartRecovery = metric(waveReceipts, (value) => value.facts.checkpoint_passed);
  const finalWaveFacts = waveReceipts.at(-1).facts;
  const recoveryFacts = {
    product_invariants: productInvariants,
    product_invariant_evidence: invariantEvidence,
    restart_recovery: restartRecovery,
    terminal_backlog: clone(finalWaveFacts.terminal_backlog),
    graceful_replacement_recovery: waveReceipts[0].facts.checkpoint_passed,
    sigkill_replacement_recovery: waveReceipts[1].facts.checkpoint_passed,
    offline_sqlite_verify: waveReceipts[2].facts.offline_sqlite_verify,
    worker_errors: waveReceipts.reduce((total, value) => total + value.facts.worker_errors, 0),
    campaign_cost_microusd: campaignDerived.cost_microusd,
    campaign_trial_evidence_set_sha256: campaignDerived.evidence_set_sha256,
    campaign_evidence_sha256: finalCampaignEvidenceSha256(state, campaignDerived.evidence_set_sha256),
    context_tokens: aggregateContext,
    context_improvement_by_wave: contextByWave,
  };
  if (!Array.isArray(receipt.facts.critical_incidents)) fail("final soak critical incidents must be an array");
  for (const [index, incident] of receipt.facts.critical_incidents.entries()) {
    nonEmptyString(incident, `final soak critical incident ${index + 1}`);
  }
  const recordedAt = isoTimestamp(receipt.facts.recorded_at, "final soak admission recorded_at");
  if (secondsBetween(finalWaveFacts.recorded_at, recordedAt) < 0) {
    fail("final soak admission cannot predate the final recovery checkpoint");
  }
  const elapsed = secondsBetween(state.soakStartedAt, recordedAt);
  if (elapsed < executionLimits.minimum_duration_seconds || elapsed > executionLimits.maximum_duration_seconds) {
    fail("final soak admission is outside the frozen 24-36 hour execution window");
  }
  const expectedFacts = {
    ...derived,
    ...recoveryFacts,
    critical_incidents: clone(receipt.facts.critical_incidents),
    recorded_at: recordedAt,
  };
  expect(receipt.facts, expectedFacts, "final soak admission derived facts");
  const pass = soakTrials.every((trial) => trial.status === "completed")
    && derived.semantic_chat_calls === 81
    && derived.aionis_action_completion.total === 27
    && derived.aionis_action_completion.passed >= 26
    && derived.wrong_direct_use === 0
    && isDeepStrictEqual(derived.negative_direct_use, { unsafe_direct_uses: 0, total: 9 })
    && [
      derived.inspect_coverage,
      derived.outcome_coverage,
      derived.feedback_coverage,
      derived.measure_coverage,
      derived.durable_exact_replay,
    ].every((value) => completeMetric(value, 27))
    && completeMetric(productInvariants, PRODUCT_INVARIANTS.length)
    && completeMetric(restartRecovery, SOAK_WAVES)
    && zeroBacklog(recoveryFacts.terminal_backlog)
    && recoveryFacts.graceful_replacement_recovery
    && recoveryFacts.sigkill_replacement_recovery
    && recoveryFacts.offline_sqlite_verify
    && derived.semantic_retries === 0
    && derived.maximum_transport_attempts <= retryPolicy.transport_max_attempts
    && campaignDerived.cost_microusd <= executionLimits.maximum_cost_usd * 1_000_000
    && contextByWave.every((value) => value.passed)
    && recoveryFacts.worker_errors === 0
    && receipt.facts.critical_incidents.length === 0;
  expect(receipt.status, pass ? "pass" : "fail", "final soak admission derived status");
  validateReducerEvidence(receipt, "final soak admission receipt");
  return clone(receipt);
}

function eventKeys(event, keys, field) {
  exactKeys(event, ["revision", "type", ...keys], field);
  positiveInteger(event.revision, `${field}.revision`);
}

function ensureTrialActive(trial, state) {
  if (trial.phase === "pilot") {
    if (state.status !== "pilot_running") fail("pilot trial is not active");
    return;
  }
  if (state.status !== `soak_wave_${trial.wave}_running` || state.activeWave !== trial.wave) {
    fail(`soak wave ${trial.wave} trial is not active`);
  }
}

function ensureTrialClaimOrder(trial, state) {
  const ordered = [...state.trials.values()].filter((entry) =>
    entry.phase === trial.phase && (entry.phase === "pilot" || entry.wave === trial.wave));
  const next = ordered.find((entry) => !new Set(["completed", "failed"]).has(entry.status));
  if (!next || next.trial_id !== trial.trial_id) {
    fail("trial claim violates the frozen deterministic trial order");
  }
}

function ensureSeedClaimOrder(seed, state) {
  const next = [...state.seeds.values()].find((entry) => entry.status !== "completed");
  if (!next || next.seed_id !== seed.seed_id) {
    fail("seed claim violates the frozen deterministic seed order");
  }
}

function addUnique(set, value, field) {
  if (set.has(value)) fail(`${field} must be unique across the campaign`);
  set.add(value);
}

function collectionValues(value) {
  return value instanceof Map ? [...value.values()] : [...value];
}

function persistedOperationIdentity(tenantId, scope, operationKind, operationId) {
  return {
    tenant_id: tenantId,
    scope,
    operation_kind: operationKind,
    operation_id: operationId,
  };
}

function persistedOperationIdentityKey(value) {
  return [value.tenant_id, value.scope, value.operation_kind, value.operation_id].join("\0");
}

function recoveryUniverseForCheckpoint(state, checkpoint) {
  if (!new Set(["pilot", "after_wave_1", "after_wave_2", "after_wave_3"]).has(checkpoint)) {
    fail("recovery universe checkpoint is outside the frozen campaign");
  }
  const throughWave = checkpoint === "pilot" ? 0 : Number(checkpoint.slice("after_wave_".length));
  const trials = collectionValues(state.trials).filter((trial) =>
    trial.phase === "pilot" || (trial.phase === "soak" && trial.wave <= throughWave)
  );
  if (trials.some((trial) => !new Set(["completed", "failed"]).has(trial.status))) {
    fail(`recovery universe ${checkpoint} contains a nonterminal trial`);
  }
  const terminalTrialIds = trials.map((trial) => trial.trial_id).sort((left, right) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right))
  );
  const operations = [];
  for (const seed of collectionValues(state.seeds)) {
    if (seed.status !== "completed" || !seed.runtime_response) {
      fail(`recovery universe ${checkpoint} requires every campaign seed operation`);
    }
    operations.push(persistedOperationIdentity(
      seed.request.tenant_id,
      seed.request.scope,
      "product_observe_v1",
      seed.operation_id,
    ));
  }
  for (const trial of trials) {
    if (trial.group !== "aionis") continue;
    if (trial.guide_response) {
      operations.push(persistedOperationIdentity(
        trial.preclaim.tenant_id,
        trial.preclaim.scope,
        "product_guide_v1",
        trial.preclaim.guide_operation_id,
      ));
    }
    const stages = new Set(trial.post_trial_checkpoints.map((entry) => entry.stage));
    if (stages.has("outcome_observe")) {
      operations.push(persistedOperationIdentity(
        trial.preclaim.tenant_id,
        trial.preclaim.scope,
        "product_observe_v1",
        trial.preclaim.outcome_operation_id,
      ));
    }
    if (stages.has("feedback")) {
      operations.push(persistedOperationIdentity(
        trial.preclaim.tenant_id,
        trial.preclaim.scope,
        "product_feedback_v1",
        trial.preclaim.feedback_operation_id,
      ));
    }
    if (stages.has("measure")) {
      operations.push(persistedOperationIdentity(
        trial.preclaim.tenant_id,
        trial.preclaim.scope,
        "product_measure_v1",
        trial.preclaim.measure_operation_id,
      ));
    }
  }
  operations.sort((left, right) =>
    Buffer.compare(Buffer.from(persistedOperationIdentityKey(left)), Buffer.from(persistedOperationIdentityKey(right)))
  );
  if (new Set(operations.map(persistedOperationIdentityKey)).size !== operations.length) {
    fail(`recovery universe ${checkpoint} contains a duplicate persisted operation identity`);
  }
  return {
    terminal_trial_ids: terminalTrialIds,
    persisted_operation_identities: operations,
  };
}

function recoveryExpectedBinding(ledger, checkpoint) {
  const pilot = checkpoint === "pilot";
  const wave = pilot ? 0 : Number(checkpoint.slice("after_wave_".length));
  const source = pilot ? ledger.phase_sources.pilot : ledger.phase_sources.soak;
  if (!source) fail(`recovery checkpoint ${checkpoint} requires its protected workflow source`);
  return {
    checkpoint,
    source_run_id: source.run_id,
    source_run_attempt: source.run_attempt,
    recovery: pilot ? "none" : ledger.trial_contract.schedule.soak_waves[wave - 1].recovery_after,
    runtime_image_digest: ledger.candidate.digest,
    ...recoveryUniverseForCheckpoint(ledger, checkpoint),
  };
}

function validateSeedRuntimeResponseCheckpoint(checkpoint, seed, dispatchRequestSha256, field) {
  exactKeys(checkpoint, [
    "schema_version",
    "route",
    "http_status",
    "response_contract_version",
    "seed_id",
    "operation_id",
    "request_sha256",
    "response_sha256",
    "request_evidence",
    "response_evidence",
    "tenant_id",
    "scope",
    "runtime_echoed_operation_id",
    "memory_written",
    "semantic_commit",
    "memory_ids",
    "memory_binding",
  ], field);
  if (checkpoint.schema_version !== SEED_RESPONSE_SCHEMA) fail(`${field} schema is invalid`);
  expect(
    [checkpoint.route, checkpoint.http_status, checkpoint.response_contract_version],
    ["/v1/observe", 200, "aionis_observe_result_v1"],
    `${field} route identity`,
  );
  expect(checkpoint.seed_id, seed.seed_id, `${field} seed ID`);
  expect(checkpoint.operation_id, seed.operation_id, `${field} operation ID`);
  expect(checkpoint.request_sha256, dispatchRequestSha256, `${field} request SHA-256`);
  sha256Hex(checkpoint.request_sha256, `${field} request SHA-256`);
  sha256Hex(checkpoint.response_sha256, `${field} exact raw response SHA-256`);
  const requestEvidence = exactEvidenceRef(checkpoint.request_evidence, `${field} request evidence`);
  const responseEvidence = exactEvidenceRef(checkpoint.response_evidence, `${field} response evidence`);
  expect(checkpoint.request_sha256, requestEvidence.sha256, `${field} request CAS join`);
  expect(checkpoint.response_sha256, responseEvidence.sha256, `${field} response CAS join`);
  expect(checkpoint.tenant_id, seed.request.tenant_id, `${field} tenant echo`);
  expect(checkpoint.scope, seed.request.scope, `${field} scope echo`);
  expect(checkpoint.runtime_echoed_operation_id, seed.operation_id, `${field} Runtime operation echo`);
  expect(checkpoint.memory_written, true, `${field} memory_written`);
  expect(checkpoint.semantic_commit, "committed", `${field} semantic_commit`);
  const writtenMemoryIds = memoryIds(checkpoint.memory_ids, `${field} memory IDs`);
  if (writtenMemoryIds.length !== 1) fail(`${field} must bind exactly one frozen seed memory`);
  exactKeys(checkpoint.memory_binding, [
    "client_id",
    "memory_id",
    "expected_execution_outcome_role",
    "expected_served_surface",
  ], `${field} memory binding`);
  nonEmptyString(checkpoint.memory_binding.client_id, `${field} memory binding client ID`);
  nonEmptyString(checkpoint.memory_binding.memory_id, `${field} memory binding memory ID`);
  expect(checkpoint.memory_binding.memory_id, writtenMemoryIds[0], `${field} memory binding ID`);
  expect(
    [
      checkpoint.memory_binding.expected_execution_outcome_role,
      checkpoint.memory_binding.expected_served_surface,
    ],
    [seed.expected_execution_outcome_role, seed.expected_served_surface],
    `${field} frozen role/surface binding`,
  );
  return clone(checkpoint);
}

function validateFailureTransition(receipt, trialStatus, field) {
  if (new Set(["claimed", "guide_responded"]).has(trialStatus)) {
    if (!new Set(["pre_request", "guide"]).has(receipt.last_confirmed_stage)) {
      fail(`${field} safe-to-send failure stage is invalid`);
    }
    return;
  }
  if (new Set(["provider_request_prepared", "provider_retry_ready"]).has(trialStatus)) {
    expect(receipt.last_confirmed_stage, "provider_request", `${field} safe-to-retry failure stage`);
    return;
  }
  if (trialStatus === "provider_dispatch_started") {
    expect(receipt.last_confirmed_stage, "provider_request", `${field} ambiguous dispatch failure stage`);
    return;
  }
  if (new Set(["provider_responded", "post_trial_running"]).has(trialStatus)) {
    if (!new Set([
      "outcome",
      "feedback",
      "measure",
      "operator_snapshot",
      "flight_recorder",
      "verification",
    ]).has(receipt.last_confirmed_stage)) {
      fail(`${field} provider-response failure stage is invalid`);
    }
    return;
  }
  fail(`${field} trial is not settleable`);
}

function replayPayload(payload) {
  exactKeys(payload, [
    "schema_version",
    "campaign_id",
    "revision",
    "harness_commit",
    "candidate",
    "frozen_bindings",
    "trial_contract",
    "provider_contract",
    "retry_policy",
    "execution_limits",
    "pilot_source",
    "seeds",
    "trials",
    "events",
  ], "campaign ledger payload");
  if (payload.schema_version !== PAYLOAD_SCHEMA) fail("campaign ledger payload schema is invalid");
  if (!/^campaign-[a-f0-9]{40}$/.test(payload.campaign_id ?? "")) fail("campaign ID is invalid");
  if (!COMMIT_RE.test(payload.harness_commit ?? "")) fail("campaign harness commit must be immutable");
  validateCandidate(payload.candidate);
  const frozenBindings = validateFrozenBindings(payload.frozen_bindings);
  const workload = workloadFromTrialContract(payload.trial_contract);
  const providerExecutionContract = hydrateProviderExecutionContract(
    payload.trial_contract.provider_execution_contract,
    frozenBindings,
  );
  const expectedTrialContract = trialContractFromWorkload(
    providerExecutionContract.workload,
    providerExecutionContract,
  );
  expect(payload.trial_contract, expectedTrialContract, "campaign trial contract exact source derivation");
  expect(
    payload.candidate,
    {
      commit: providerExecutionContract.release_lock.candidate.commit,
      digest: providerExecutionContract.release_lock.candidate.digest,
    },
    "campaign candidate release-lock binding",
  );
  expect(
    frozenBindings.candidate,
    {
      repository: providerExecutionContract.release_lock.candidate.repository,
      version: providerExecutionContract.release_lock.candidate.version,
      tag: providerExecutionContract.release_lock.candidate.tag,
      image: providerExecutionContract.release_lock.candidate.image,
      platform: providerExecutionContract.release_lock.candidate.platform,
    },
    "campaign frozen candidate release-lock binding",
  );
  expect(
    frozenBindings.authority_manifest_sha256,
    providerExecutionContract.release_lock.protocol_artifacts.authority_manifest.sha256,
    "campaign authority manifest release-lock binding",
  );
  const providerContract = validateProviderContract(payload.provider_contract);
  const retryPolicy = retryPolicyFromLock({ retry_policy: payload.retry_policy });
  const executionLimits = executionLimitsFromLock({ execution_limits: payload.execution_limits });
  expect(providerExecutionContract.workload.groups, workload.groups, "provider execution workload groups");
  expect(providerExecutionContract.workload.scenarios, workload.scenarios, "provider execution workload scenarios");
  expect(providerExecutionContract.workload.schedule, workload.schedule, "provider execution workload schedule");
  expect(
    providerExecutionContract.release_lock.providers.agent,
    providerContract,
    "provider execution release-lock provider contract",
  );
  expect(
    providerExecutionContract.release_lock.retry_policy,
    retryPolicy,
    "provider execution release-lock retry policy",
  );
  expect(
    providerExecutionContract.release_lock.execution_limits,
    executionLimits,
    "provider execution release-lock limits",
  );
  if (workload.soak.waves !== SOAK_WAVES) fail(`campaign soak must contain exactly ${SOAK_WAVES} waves`);
  buildTrialPlan("pilot", workload);
  buildTrialPlan("soak", workload);
  const pilotSource = validatePhaseSource(payload.pilot_source, "pilot", payload.harness_commit, "campaign pilot source");
  const expectedCampaignId = campaignId({
    harnessCommit: payload.harness_commit,
    candidate: payload.candidate,
    frozenBindings,
    trialContract: payload.trial_contract,
    pilotSource,
  });
  expect(payload.campaign_id, expectedCampaignId, "campaign ID");
  const expectedTrials = deterministicTrials(payload.campaign_id, payload.harness_commit, payload.trial_contract);
  expect(payload.trials, expectedTrials, "campaign deterministic trial universe");
  const expectedSeeds = deterministicSeeds(
    payload.campaign_id,
    payload.harness_commit,
    payload.trial_contract,
    expectedTrials,
  );
  expect(payload.seeds, expectedSeeds, "campaign deterministic seed universe");
  if (!Array.isArray(payload.events)) fail("campaign ledger events must be an array");
  if (!Number.isSafeInteger(payload.revision) || payload.revision < 0 || payload.revision !== payload.events.length) {
    fail("campaign ledger revision must equal the append-only event count");
  }

  const trials = new Map(expectedTrials.map((trial) => [trial.trial_id, {
    ...clone(trial),
    status: "pending",
    guide_response: null,
    guide_response_sha256: null,
    provider_request_evidence: null,
    dispatch_request_sha256: null,
    active_provider_attempt: null,
    provider_transport_attempts: [],
    provider_response: null,
    provider_response_sha256: null,
    post_trial_checkpoints: [],
    settlement: null,
  }]));
  const seeds = new Map(expectedSeeds.map((seed) => [seed.seed_id, {
    ...clone(seed),
    status: "pending",
    dispatch_request_sha256: null,
    dispatch_request_evidence: null,
    dispatch_replay_count: 0,
    runtime_response: null,
    runtime_response_sha256: null,
  }]));
  const state = {
    status: "seeding",
    activeWave: null,
    completedWaves: [],
    phaseSources: { pilot: pilotSource, soak: null },
    pilotAdmission: null,
    waveAdmissions: [],
    finalSoakAdmission: null,
    recoveryCheckpoints: [],
    offlineSqliteEvidence: null,
    campaignCostMicrousd: 0,
    terminalFailure: null,
    soakStartedAt: null,
    waveStartedAt: new Map(),
    memoryEvidenceByScenario: new Map(workload.scenarios.map((scenario) => [scenario, new Map()])),
    seeds,
    trials,
  };
  const seedResponseHashes = new Set();
  const providerRequestIds = new Set();
  const providerToolCallIds = new Set();
  const providerResponseHashes = new Set();
  const providerTransportResponseHashes = new Set();
  const runtimeFactIds = new Set();
  const runtimeResponseHashes = new Set();
  const runtimeMemoryIdOwners = new Map();
  const runtimeClientIdOwners = new Map();
  for (const [index, event] of payload.events.entries()) {
    const field = `campaign event ${index + 1}`;
    if (!event || typeof event !== "object" || Array.isArray(event)) fail(`${field} must be an object`);
    if (event.revision !== index + 1) fail(`${field} revision is not monotonic`);
    if (state.status === "failed" || state.status === "soak_passed") fail(`${field} follows a terminal campaign state`);
    switch (event.type) {
      case "claim_seed": {
        eventKeys(event, ["seed_id", "operation_id"], field);
        if (state.status !== "seeding") fail(`${field} cannot claim a seed after seeding is complete`);
        const seed = state.seeds.get(event.seed_id);
        if (!seed) fail(`${field} references a seed outside the deterministic universe`);
        ensureSeedClaimOrder(seed, state);
        if (seed.status !== "pending") fail(`${field} seed was already claimed`);
        expect(event.operation_id, seed.operation_id, `${field} operation ID`);
        seed.status = "claimed";
        break;
      }
      case "seed_runtime_dispatch_started": {
        eventKeys(event, ["seed_id", "operation_id", "request_sha256", "request_evidence"], field);
        if (state.status !== "seeding") fail(`${field} cannot dispatch a seed after seeding is complete`);
        const seed = state.seeds.get(event.seed_id);
        if (!seed) fail(`${field} references a seed outside the deterministic universe`);
        if (seed.status !== "claimed") fail(`${field} requires a uniquely claimed seed`);
        expect(event.operation_id, seed.operation_id, `${field} operation ID`);
        sha256Hex(event.request_sha256, `${field} exact raw request SHA-256`);
        const requestEvidence = exactEvidenceRef(event.request_evidence, `${field} request evidence`);
        expect(event.request_sha256, requestEvidence.sha256, `${field} request CAS join`);
        seed.dispatch_request_sha256 = event.request_sha256;
        seed.dispatch_request_evidence = requestEvidence;
        seed.status = "dispatch_started";
        break;
      }
      case "seed_runtime_dispatch_replayed": {
        eventKeys(event, ["seed_id", "operation_id", "request_sha256", "request_evidence"], field);
        if (state.status !== "seeding") fail(`${field} cannot replay a seed after seeding is complete`);
        const seed = state.seeds.get(event.seed_id);
        if (!seed) fail(`${field} references a seed outside the deterministic universe`);
        if (seed.status !== "dispatch_started") fail(`${field} requires an in-flight seed dispatch`);
        expect(event.operation_id, seed.operation_id, `${field} operation ID`);
        expect(event.request_sha256, seed.dispatch_request_sha256, `${field} exact replay request SHA-256`);
        expect(
          exactEvidenceRef(event.request_evidence, `${field} request evidence`),
          seed.dispatch_request_evidence,
          `${field} exact replay request evidence`,
        );
        seed.dispatch_replay_count += 1;
        break;
      }
      case "seed_runtime_response_recorded": {
        eventKeys(event, ["seed_id", "operation_id", "checkpoint", "checkpoint_sha256"], field);
        if (state.status !== "seeding") fail(`${field} cannot record a seed after seeding is complete`);
        const seed = state.seeds.get(event.seed_id);
        if (!seed) fail(`${field} references a seed outside the deterministic universe`);
        if (seed.status !== "dispatch_started") fail(`${field} requires an in-flight seed dispatch`);
        expect(event.operation_id, seed.operation_id, `${field} operation ID`);
        const checkpoint = validateSeedRuntimeResponseCheckpoint(
          event.checkpoint,
          seed,
          seed.dispatch_request_sha256,
          `${field} Runtime response checkpoint`,
        );
        const checkpointSha256 = sha256(Buffer.from(canonical(checkpoint)));
        expect(event.checkpoint_sha256, checkpointSha256, `${field} checkpoint SHA-256`);
        addUnique(seedResponseHashes, checkpoint.response_sha256, `${field} exact raw Runtime response SHA-256`);
        const binding = checkpoint.memory_binding;
        if (runtimeMemoryIdOwners.has(binding.memory_id)) {
          fail(`${field} Runtime memory ID is reused across campaign evidence`);
        }
        if (runtimeClientIdOwners.has(binding.client_id)) {
          fail(`${field} Runtime client ID is reused across campaign evidence`);
        }
        runtimeMemoryIdOwners.set(binding.memory_id, seed.seed_id);
        runtimeClientIdOwners.set(binding.client_id, seed.seed_id);
        state.memoryEvidenceByScenario.get(seed.scenario_id).set(binding.memory_id, {
          source_kind: "seed",
          source_id: seed.seed_id,
          client_id: binding.client_id,
          expected_execution_outcome_role: binding.expected_execution_outcome_role,
          expected_served_surface: binding.expected_served_surface,
        });
        seed.runtime_response = checkpoint;
        seed.runtime_response_sha256 = checkpointSha256;
        seed.status = "completed";
        if ([...state.seeds.values()].every((entry) => entry.status === "completed")) {
          state.status = "pilot_running";
        }
        break;
      }
      case "claim_trial": {
        eventKeys(event, ["trial_id", "request_id"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        ensureTrialClaimOrder(trial, state);
        if (state.campaignCostMicrousd >= executionLimits.maximum_cost_usd * 1_000_000) {
          fail(`${field} cannot claim after the campaign cost ceiling is exhausted`);
        }
        if (trial.status !== "pending") fail(`${field} trial was already claimed`);
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        trial.status = "claimed";
        break;
      }
      case "guide_response_recorded": {
        eventKeys(event, ["trial_id", "request_id", "checkpoint", "checkpoint_sha256"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        if (trial.group !== "aionis" || trial.status !== "claimed") {
          fail(`${field} requires a uniquely claimed Aionis trial`);
        }
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        const checkpoint = validateGuideResponseCheckpoint(
          event.checkpoint,
          trial,
          state.memoryEvidenceByScenario.get(trial.scenario),
          `${field} guide response checkpoint`,
        );
        const checkpointSha256 = sha256(Buffer.from(canonical(checkpoint)));
        expect(event.checkpoint_sha256, checkpointSha256, `${field} checkpoint SHA-256`);
        addUnique(runtimeFactIds, checkpoint.guide_trace_id, `${field} guide trace ID`);
        addUnique(runtimeResponseHashes, checkpoint.response_evidence.sha256, `${field} guide response SHA-256`);
        trial.guide_response = checkpoint;
        trial.guide_response_sha256 = checkpointSha256;
        trial.status = "guide_responded";
        break;
      }
      case "provider_request_prepared": {
        eventKeys(event, ["trial_id", "request_id", "request_evidence"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        const requiredStatus = trial.group === "aionis" ? "guide_responded" : "claimed";
        if (trial.status !== requiredStatus) fail(`${field} trial is not ready to prepare a provider request`);
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        trial.provider_request_evidence = exactEvidenceRef(event.request_evidence, `${field} request evidence`);
        trial.status = "provider_request_prepared";
        break;
      }
      case "provider_dispatch_started": {
        eventKeys(event, ["trial_id", "request_id", "attempt", "request_evidence"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        if (state.campaignCostMicrousd >= executionLimits.maximum_cost_usd * 1_000_000) {
          fail(`${field} cannot dispatch after the campaign cost ceiling is exhausted`);
        }
        if (!new Set(["provider_request_prepared", "provider_retry_ready"]).has(trial.status)) {
          fail(`${field} requires a prepared provider request or a durable retryable response`);
        }
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        expect(event.attempt, trial.provider_transport_attempts.length + 1, `${field} attempt ordinal`);
        if (event.attempt > retryPolicy.transport_max_attempts) {
          fail(`${field} exceeds the frozen transport attempt ceiling before dispatch`);
        }
        const requestEvidence = exactEvidenceRef(event.request_evidence, `${field} request evidence`);
        expect(requestEvidence, trial.provider_request_evidence, `${field} prepared request evidence`);
        trial.dispatch_request_sha256 = requestEvidence.sha256;
        trial.active_provider_attempt = event.attempt;
        // This is the last durable point at which a restart may send safely. A restart in
        // provider_dispatch_started is ambiguous and must never auto-break the lock or resend.
        trial.status = "provider_dispatch_started";
        break;
      }
      case "provider_retryable_http_response_recorded": {
        eventKeys(event, ["trial_id", "request_id", "attempt_evidence", "attempt_evidence_sha256"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        if (trial.status !== "provider_dispatch_started" || trial.active_provider_attempt === null) {
          fail(`${field} requires an in-flight provider dispatch`);
        }
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        const attempt = event.attempt_evidence;
        exactKeys(attempt, [
          "attempt",
          "result",
          "http_status",
          "network_code",
          "request_commit_state",
          "evidence_sha256",
          "response_evidence",
        ], `${field} attempt evidence`);
        expect(attempt.attempt, trial.active_provider_attempt, `${field} attempt ordinal`);
        expect(
          [attempt.result, attempt.network_code, attempt.request_commit_state],
          ["http", null, "response_received"],
          `${field} HTTP transport facts`,
        );
        if (!retryPolicy.retryable_http_statuses.includes(attempt.http_status)) {
          fail(`${field} HTTP status is outside the frozen retry allowlist`);
        }
        const responseEvidence = exactEvidenceRef(attempt.response_evidence, `${field} response evidence`);
        expect(attempt.evidence_sha256, responseEvidence.sha256, `${field} response CAS join`);
        const attemptSha256 = sha256(Buffer.from(canonical(attempt)));
        expect(event.attempt_evidence_sha256, attemptSha256, `${field} attempt evidence SHA-256`);
        addUnique(
          providerTransportResponseHashes,
          attempt.evidence_sha256,
          `${field} exact raw retryable HTTP response SHA-256`,
        );
        trial.provider_transport_attempts.push(clone(attempt));
        trial.active_provider_attempt = null;
        trial.status = "provider_retry_ready";
        break;
      }
      case "provider_response_recorded": {
        eventKeys(event, ["trial_id", "request_id", "checkpoint", "checkpoint_sha256"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        if (trial.status !== "provider_dispatch_started") {
          fail(`${field} requires an ambiguous provider dispatch checkpoint`);
        }
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        expect(
          trial.active_provider_attempt,
          trial.provider_transport_attempts.length + 1,
          `${field} active attempt ordinal`,
        );
        const checkpoint = validateProviderResponseCheckpoint(
          event.checkpoint,
          trial,
          providerContract,
          trial.dispatch_request_sha256,
          payload.trial_contract,
          retryPolicy,
          trial.provider_transport_attempts,
        );
        const checkpointSha256 = sha256(Buffer.from(canonical(checkpoint)));
        expect(event.checkpoint_sha256, checkpointSha256, `${field} checkpoint SHA-256`);
        addUnique(providerRequestIds, checkpoint.provider_request_id, `${field} provider request ID`);
        addUnique(providerToolCallIds, checkpoint.tool_call_id, `${field} provider tool call ID`);
        addUnique(providerResponseHashes, checkpoint.response_sha256, `${field} provider response SHA-256`);
        trial.provider_response = checkpoint;
        trial.provider_response_sha256 = checkpointSha256;
        trial.active_provider_attempt = null;
        trial.status = "provider_responded";
        state.campaignCostMicrousd += checkpoint.provider_usage.cost_microusd;
        const costLimitMicrousd = executionLimits.maximum_cost_usd * 1_000_000;
        const remainingTrials = [...state.trials.values()].some(
          (entry) => entry.trial_id !== trial.trial_id && !new Set(["completed", "failed"]).has(entry.status),
        );
        if (checkpoint.transport_attempts > retryPolicy.transport_max_attempts) {
          state.terminalFailure = {
            reason_code: "transport_retry_ceiling_exceeded",
            trial_id: trial.trial_id,
            provider_response_checkpoint_sha256: checkpointSha256,
            observed_transport_attempts: checkpoint.transport_attempts,
            limit_transport_attempts: retryPolicy.transport_max_attempts,
          };
          state.status = "failed";
        } else if (state.campaignCostMicrousd > costLimitMicrousd
          || (state.campaignCostMicrousd === costLimitMicrousd && remainingTrials)) {
          state.terminalFailure = {
            reason_code: "campaign_cost_ceiling_exhausted",
            trial_id: trial.trial_id,
            provider_response_checkpoint_sha256: checkpointSha256,
            observed_cost_microusd: state.campaignCostMicrousd,
            limit_cost_microusd: costLimitMicrousd,
          };
          state.status = "failed";
        }
        break;
      }
      case "post_trial_runtime_response_recorded": {
        eventKeys(event, ["trial_id", "request_id", "durable_checkpoint"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        if (trial.group !== "aionis"
          || !new Set(["provider_responded", "post_trial_running"]).has(trial.status)) {
          fail(`${field} requires an Aionis trial with a durable provider response`);
        }
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        const expectedStage = POST_TRIAL_STAGES[trial.post_trial_checkpoints.length];
        if (expectedStage === undefined) fail(`${field} follows the complete post-trial Runtime chain`);
        const durable = validatePostTrialDurableCheckpoint(
          event.durable_checkpoint,
          trial,
          expectedStage,
          `${field} durable checkpoint`,
        );
        trial.post_trial_checkpoints.push(durable);
        trial.status = "post_trial_running";
        break;
      }
      case "settle_trial": {
        eventKeys(event, ["trial_id", "request_id", "receipt", "receipt_sha256"], field);
        const trial = state.trials.get(event.trial_id);
        if (!trial) fail(`${field} references a trial outside the deterministic universe`);
        ensureTrialActive(trial, state);
        if (!new Set([
          "claimed",
          "guide_responded",
          "provider_request_prepared",
          "provider_retry_ready",
          "provider_dispatch_started",
          "provider_responded",
          "post_trial_running",
        ]).has(trial.status)) {
          fail(`${field} trial must have a nonterminal durable checkpoint before settlement`);
        }
        expect(event.request_id, trial.preclaim.request_id, `${field} request ID`);
        const receipt = validateTrialSettlement(
          event.receipt,
          trial,
          payload.candidate,
          payload.trial_contract,
          trial.provider_response,
          state.memoryEvidenceByScenario.get(trial.scenario),
        );
        if (receipt.status === "completed") {
          const expectedStatus = trial.group === "aionis" ? "post_trial_running" : "provider_responded";
          if (trial.status !== expectedStatus) {
            fail(`${field} completed trial requires its complete durable execution chain`);
          }
          if (trial.group === "aionis" && trial.post_trial_checkpoints.length !== POST_TRIAL_STAGES.length) {
            fail(`${field} completed Aionis trial requires every post-trial Runtime checkpoint`);
          }
        }
        if (receipt.status === "failed") validateFailureTransition(receipt, trial.status, field);
        const expectedReceiptSha256 = sha256(Buffer.from(canonical(receipt)));
        expect(event.receipt_sha256, expectedReceiptSha256, `${field} receipt SHA-256`);
        if (receipt.aionis) {
          for (const key of ["feedback_id", "measure_id", "snapshot_id", "recorder_id"]) {
            addUnique(runtimeFactIds, receipt.aionis[key], `${field} Aionis ${key}`);
          }
          for (const key of [
            "outcome_response_sha256",
            "feedback_response_sha256",
            "measure_response_sha256",
            "snapshot_response_sha256",
            "recorder_response_sha256",
          ]) {
            addUnique(runtimeResponseHashes, receipt.aionis[key], `${field} Aionis ${key}`);
          }
          const binding = receipt.aionis.outcome_memory_bindings[0];
          if (runtimeMemoryIdOwners.has(binding.memory_id)) {
            fail(`${field} Aionis outcome memory ID is reused across campaign evidence`);
          }
          if (runtimeClientIdOwners.has(binding.client_id)) {
            fail(`${field} Aionis outcome client ID is reused across campaign evidence`);
          }
          runtimeMemoryIdOwners.set(binding.memory_id, trial.trial_id);
          runtimeClientIdOwners.set(binding.client_id, trial.trial_id);
          state.memoryEvidenceByScenario.get(trial.scenario).set(binding.memory_id, {
            source_kind: "outcome",
            source_id: trial.trial_id,
            client_id: binding.client_id,
            expected_execution_outcome_role: receipt.tool_result.passed
              ? "passed_solution"
              : "failed_branch",
            expected_served_surface: receipt.tool_result.passed ? "use_now" : "do_not_use",
          });
        }
        trial.status = receipt.status;
        trial.settlement = { receipt, receipt_sha256: expectedReceiptSha256 };
        break;
      }
      case "record_pilot_admission": {
        eventKeys(event, ["receipt", "receipt_sha256"], field);
        if (state.status !== "pilot_running") fail(`${field} cannot complete pilot from ${state.status}`);
        const pilotTrials = [...state.trials.values()].filter((trial) => trial.phase === "pilot");
        if (pilotTrials.some((trial) => !new Set(["completed", "failed"]).has(trial.status))) {
          fail(`${field} cannot complete pilot before every pilot trial is terminal`);
        }
        const receipt = validatePilotAdmission(
          event.receipt,
          state.phaseSources.pilot,
          pilotTrials,
          retryPolicy,
          executionLimits,
        );
        const expectedReceiptSha256 = sha256(Buffer.from(canonical(receipt)));
        expect(event.receipt_sha256, expectedReceiptSha256, `${field} receipt SHA-256`);
        state.pilotAdmission = { receipt, receipt_sha256: expectedReceiptSha256 };
        state.recoveryCheckpoints.push(clone(receipt.facts.recovery_checkpoint));
        state.status = receipt.status === "pass" ? "pilot_passed" : "failed";
        break;
      }
      case "begin_soak": {
        eventKeys(event, ["source", "started_at"], field);
        if (state.status !== "pilot_passed") fail(`${field} requires a passed pilot`);
        const source = validatePhaseSource(event.source, "soak", payload.harness_commit, `${field}.source`);
        if (source.run_id === state.phaseSources.pilot.run_id) {
          fail(`${field} soak source must use a distinct workflow run`);
        }
        const startedAt = isoTimestamp(event.started_at, `${field}.started_at`);
        if (secondsBetween(state.pilotAdmission.receipt.facts.recorded_at, startedAt) < 0) {
          fail(`${field} cannot predate the persisted pilot checkpoint`);
        }
        state.phaseSources.soak = source;
        state.soakStartedAt = startedAt;
        state.status = "soak_ready";
        break;
      }
      case "begin_wave": {
        eventKeys(event, ["wave", "started_at"], field);
        positiveInteger(event.wave, `${field}.wave`);
        if (event.wave > SOAK_WAVES) fail(`${field}.wave exceeds the frozen soak wave count`);
        const expectedStatus = event.wave === 1 ? "soak_ready" : `soak_wave_${event.wave - 1}_passed`;
        if (state.status !== expectedStatus) fail(`${field} violates soak wave order`);
        const startedAt = isoTimestamp(event.started_at, `${field}.started_at`);
        const frozenWave = payload.trial_contract.schedule.soak_waves[event.wave - 1];
        const waveElapsed = secondsBetween(state.soakStartedAt, startedAt);
        if (waveElapsed < frozenWave.not_before_elapsed_seconds) {
          fail(`${field} starts before its frozen not-before offset`);
        }
        if (waveElapsed > executionLimits.maximum_duration_seconds) {
          fail(`${field} starts after the frozen campaign deadline`);
        }
        if (event.wave > 1) {
          const priorRecordedAt = state.waveAdmissions.at(-1).receipt.facts.recorded_at;
          if (secondsBetween(priorRecordedAt, startedAt) < 0) {
            fail(`${field} cannot predate the prior recovery checkpoint`);
          }
        }
        state.status = `soak_wave_${event.wave}_running`;
        state.activeWave = event.wave;
        state.waveStartedAt.set(event.wave, startedAt);
        break;
      }
      case "record_wave_admission": {
        eventKeys(event, ["receipt", "receipt_sha256"], field);
        if (state.activeWave === null || state.status !== `soak_wave_${state.activeWave}_running`) {
          fail(`${field} cannot complete an inactive soak wave`);
        }
        const waveTrials = [...state.trials.values()].filter(
          (trial) => trial.phase === "soak" && trial.wave === state.activeWave,
        );
        if (waveTrials.some((trial) => !new Set(["completed", "failed"]).has(trial.status))) {
          fail(`${field} cannot complete soak wave before every trial is terminal`);
        }
        const receipt = validateWaveAdmission(
          event.receipt,
          state.phaseSources.soak,
          state.activeWave,
          waveTrials,
          state,
          payload.trial_contract,
          retryPolicy,
          executionLimits,
        );
        const expectedReceiptSha256 = sha256(Buffer.from(canonical(receipt)));
        expect(event.receipt_sha256, expectedReceiptSha256, `${field} receipt SHA-256`);
        state.activeWave = null;
        state.waveAdmissions.push({ receipt, receipt_sha256: expectedReceiptSha256 });
        state.recoveryCheckpoints.push(clone(receipt.facts.recovery_checkpoint));
        if (receipt.facts.offline_sqlite_evidence !== null) {
          state.offlineSqliteEvidence = clone(receipt.facts.offline_sqlite_evidence);
        }
        if (receipt.status !== "pass") {
          state.status = "failed";
        } else {
          state.completedWaves.push(receipt.wave);
          state.status = receipt.wave === SOAK_WAVES ? "soak_waves_passed" : `soak_wave_${receipt.wave}_passed`;
        }
        break;
      }
      case "record_final_soak_admission": {
        eventKeys(event, ["receipt", "receipt_sha256"], field);
        if (state.status !== "soak_waves_passed" || state.completedWaves.length !== SOAK_WAVES) {
          fail(`${field} requires three independently passed soak waves`);
        }
        const allTrials = [...state.trials.values()];
        const receipt = validateFinalSoakAdmission(
          event.receipt,
          state.phaseSources.soak,
          allTrials,
          state,
          payload.trial_contract,
          executionLimits,
          retryPolicy,
        );
        const expectedReceiptSha256 = sha256(Buffer.from(canonical(receipt)));
        expect(event.receipt_sha256, expectedReceiptSha256, `${field} receipt SHA-256`);
        state.finalSoakAdmission = { receipt, receipt_sha256: expectedReceiptSha256 };
        state.status = receipt.status === "pass" ? "soak_passed" : "failed";
        break;
      }
      default:
        fail(`${field} type is invalid`);
    }
  }
  return state;
}

function verifiedEvidenceBytes(directory, ref, field) {
  try {
    verifyEvidenceJsonBody({ campaignRoot: directory, ref });
    return readEvidenceJsonBody({ campaignRoot: directory, ref });
  } catch (error) {
    fail(`${field} failed verification: ${error.message}`);
  }
}

function rehydratePostTrialChain({ directory, contract, trial, guideResponse }) {
  if (trial.group !== "aionis") fail("post-trial rehydration is defined only for Aionis trials");
  if (!trial.provider_request_evidence || !trial.provider_response) {
    fail(`trial ${trial.trial_id} post-trial chain requires durable provider evidence`);
  }
  const requestBytes = verifiedEvidenceBytes(
    directory,
    trial.provider_request_evidence,
    `trial ${trial.trial_id} provider request evidence`,
  );
  const responseBytes = verifiedEvidenceBytes(
    directory,
    trial.provider_response.response_evidence,
    `trial ${trial.trial_id} provider response evidence`,
  );
  const ledgerContext = { trial, guide_response: guideResponse };
  const providerBoundary = parseOpenRouterChatCompletion({
    contract,
    ledgerContext,
    requestBytes,
    httpStatus: 200,
    responseBytes,
  });
  const execution = createPostTrialExecution({ contract, ledgerContext, providerBoundary });
  const checkpoints = [];
  for (const durable of trial.post_trial_checkpoints) {
    const requestSource = verifiedEvidenceBytes(
      directory,
      durable.request_evidence,
      `trial ${trial.trial_id} ${durable.stage} request evidence`,
    );
    const responseSource = verifiedEvidenceBytes(
      directory,
      durable.response_evidence,
      `trial ${trial.trial_id} ${durable.stage} response evidence`,
    );
    const checkpoint = parsePostTrialRuntimeResponse({
      execution,
      stage: durable.stage,
      priorResponses: checkpoints,
      requestBytes: requestSource,
      httpStatus: durable.checkpoint.http_status,
      responseBytes: responseSource,
    });
    expect(checkpoint, durable.checkpoint, `trial ${trial.trial_id} ${durable.stage} raw evidence join`);
    checkpoints.push(checkpoint);
  }
  const settlementFacts = checkpoints.length === POST_TRIAL_STAGES.length
    ? derivePostTrialSettlementFacts({ execution, responses: checkpoints })
    : null;
  return { execution, checkpoints, settlementFacts };
}

function verifyCampaignEvidence(directory, payload, state) {
  const hasSeedEvidence = [...state.seeds.values()].some((seed) => seed.dispatch_request_evidence);
  const hasTrialEvidence = [...state.trials.values()].some((trial) =>
    trial.guide_response || trial.provider_request_evidence || trial.provider_response);
  if (!hasSeedEvidence && !hasTrialEvidence) return;
  for (const seed of state.seeds.values()) {
    if (!seed.dispatch_request_evidence) continue;
    const requestBytes = verifiedEvidenceBytes(
      directory,
      seed.dispatch_request_evidence,
      `seed ${seed.seed_id} request evidence`,
    );
    const request = parseContractSource(requestBytes, `seed ${seed.seed_id} request evidence`);
    expect(request.value, seed.request, `seed ${seed.seed_id} frozen request body`);
    expect(request.sha256, seed.dispatch_request_sha256, `seed ${seed.seed_id} request SHA-256`);
    if (!seed.runtime_response) continue;
    const responseBytes = verifiedEvidenceBytes(
      directory,
      seed.runtime_response.response_evidence,
      `seed ${seed.seed_id} response evidence`,
    );
    const response = parseContractSource(responseBytes, `seed ${seed.seed_id} response evidence`);
    const responseNodes = response.value?.memory_write?.nodes;
    const responseMemoryBinding = Array.isArray(responseNodes) && responseNodes.length === 1
      ? {
          client_id: responseNodes[0]?.client_id ?? null,
          memory_id: responseNodes[0]?.id ?? null,
          expected_execution_outcome_role: seed.expected_execution_outcome_role,
          expected_served_surface: seed.expected_served_surface,
        }
      : null;
    const derived = {
      schema_version: SEED_RESPONSE_SCHEMA,
      route: "/v1/observe",
      http_status: seed.runtime_response.http_status,
      response_contract_version: response.value?.contract_version,
      seed_id: seed.seed_id,
      operation_id: seed.operation_id,
      request_sha256: request.sha256,
      response_sha256: response.sha256,
      request_evidence: seed.dispatch_request_evidence,
      response_evidence: seed.runtime_response.response_evidence,
      tenant_id: response.value?.tenant_id,
      scope: response.value?.scope,
      runtime_echoed_operation_id: response.value?.operation_id,
      memory_written: response.value?.observed?.memory_written,
      semantic_commit: response.value?.post_commit_projections?.semantic_commit,
      memory_ids: Array.isArray(responseNodes) ? responseNodes.map((node) => node?.id ?? null) : null,
      memory_binding: responseMemoryBinding,
    };
    expect(derived, seed.runtime_response, `seed ${seed.seed_id} raw response evidence join`);
  }
  if (!hasTrialEvidence) return;
  const contract = hydrateProviderExecutionContract(
    payload.trial_contract.provider_execution_contract,
    payload.frozen_bindings,
  );
  for (const trial of state.trials.values()) {
    let guideResponse = null;
    if (trial.guide_response) {
      const guideRequestBytes = verifiedEvidenceBytes(
        directory,
        trial.guide_response.request_evidence,
        `trial ${trial.trial_id} guide request evidence`,
      );
      const expectedGuideRequest = canonicalJsonBytes(renderGuideRequest(contract, trial));
      if (!guideRequestBytes.equals(expectedGuideRequest)) {
        fail(`trial ${trial.trial_id} guide request evidence drifted from the frozen workload`);
      }
      const guideResponseBytes = verifiedEvidenceBytes(
        directory,
        trial.guide_response.response_evidence,
        `trial ${trial.trial_id} guide response evidence`,
      );
      guideResponse = parseContractSource(
        guideResponseBytes,
        `trial ${trial.trial_id} guide response evidence`,
      ).value;
      const derivedGuide = deriveGuideResponseCheckpoint({
        providerExecutionContract: contract,
        trial,
        httpStatus: trial.guide_response.http_status,
        requestEvidence: trial.guide_response.request_evidence,
        responseEvidence: trial.guide_response.response_evidence,
        responseValue: guideResponse,
      });
      expect(derivedGuide, trial.guide_response, `trial ${trial.trial_id} guide raw evidence join`);
    }
    if (!trial.provider_request_evidence) continue;
    const requestBytes = verifiedEvidenceBytes(
      directory,
      trial.provider_request_evidence,
      `trial ${trial.trial_id} provider request evidence`,
    );
    const ledgerContext = { trial, guide_response: guideResponse };
    assertCanonicalProviderRequest({ contract, ledgerContext, requestBytes });
    for (const attempt of trial.provider_transport_attempts) {
      const responseBytes = verifiedEvidenceBytes(
        directory,
        attempt.response_evidence,
        `trial ${trial.trial_id} provider retry attempt ${attempt.attempt} response evidence`,
      );
      const response = parseContractSource(
        responseBytes,
        `trial ${trial.trial_id} provider retry attempt ${attempt.attempt} response evidence`,
      );
      if (!response.value?.error || typeof response.value.error !== "object" || Array.isArray(response.value.error)) {
        fail(`trial ${trial.trial_id} provider retry attempt ${attempt.attempt} lacks an OpenRouter error object`);
      }
      nonEmptyString(
        response.value.error.message,
        `trial ${trial.trial_id} provider retry attempt ${attempt.attempt} error message`,
      );
      expect(
        response.sha256,
        attempt.evidence_sha256,
        `trial ${trial.trial_id} provider retry attempt ${attempt.attempt} raw evidence join`,
      );
    }
    if (!trial.provider_response) continue;
    const responseBytes = verifiedEvidenceBytes(
      directory,
      trial.provider_response.response_evidence,
      `trial ${trial.trial_id} provider response evidence`,
    );
    const boundary = parseOpenRouterChatCompletion({
      contract,
      ledgerContext,
      requestBytes,
      httpStatus: 200,
      responseBytes,
    });
    expect(
      {
        response_contract: trial.provider_response.response_contract,
        provider_request_id: trial.provider_response.provider_request_id,
        requested_model: trial.provider_response.requested_model,
        request_sha256: trial.provider_response.request_sha256,
        response_sha256: trial.provider_response.response_sha256,
        returned_model: trial.provider_response.returned_model,
        fallback_used: trial.provider_response.fallback_used,
        tool_call_id: trial.provider_response.tool_call_id,
        provider_usage: trial.provider_response.provider_usage,
        cost_microusd_rule: trial.provider_response.cost_microusd_rule,
        tool_result: trial.provider_response.tool_result,
      },
      {
        response_contract: boundary.response_contract,
        provider_request_id: boundary.provider_request_id,
        requested_model: boundary.requested_model,
        request_sha256: boundary.request_sha256,
        response_sha256: boundary.response_sha256,
        returned_model: boundary.returned_model,
        fallback_used: boundary.fallback_used,
        tool_call_id: boundary.tool_call_id,
        provider_usage: boundary.provider_usage,
        cost_microusd_rule: boundary.cost_microusd_rule,
        tool_result: boundary.tool_result,
      },
      `trial ${trial.trial_id} provider raw evidence join`,
    );
    if (trial.group === "aionis" && trial.post_trial_checkpoints.length > 0) {
      const postTrial = rehydratePostTrialChain({ directory, contract, trial, guideResponse });
      if (postTrial.settlementFacts) {
        const expected = aionisSettlementFactsFromDurableCheckpoints(trial);
        expect(
          {
            ...postTrial.settlementFacts,
            guide_trace_id: trial.guide_response.guide_trace_id,
            runtime_echoed_guide_operation_id: trial.guide_response.operation_id,
            guide_response_sha256: trial.guide_response.response_evidence.sha256,
            inspect_evidence: trial.guide_response.inspect_evidence,
            memory_surface_evidence: trial.guide_response.memory_surface_evidence,
          },
          expected,
          `trial ${trial.trial_id} complete post-trial settlement facts`,
        );
      }
    }
  }
  let priorRecoveryCheckpoint = null;
  const recoveryAdmissions = [
    ...(state.pilotAdmission === null ? [] : [{
      receipt: state.pilotAdmission.receipt,
      expected: {
        checkpoint: "pilot",
        source_run_id: state.phaseSources.pilot.run_id,
        source_run_attempt: state.phaseSources.pilot.run_attempt,
        recovery: "none",
      },
    }]),
    ...state.waveAdmissions.map((entry) => ({
      receipt: entry.receipt,
      expected: {
        checkpoint: `after_wave_${entry.receipt.wave}`,
        source_run_id: state.phaseSources.soak.run_id,
        source_run_attempt: state.phaseSources.soak.run_attempt,
        recovery: payload.trial_contract.schedule.soak_waves[entry.receipt.wave - 1].recovery_after,
      },
    })),
  ];
  for (const admission of recoveryAdmissions) {
    const recorded = admission.receipt.facts.recovery_evidence;
    const expected = {
      ...admission.expected,
      runtime_image_digest: payload.candidate.digest,
      ...recoveryUniverseForCheckpoint(state, admission.expected.checkpoint),
    };
    const derived = deriveRecoveryCheckpointEvidence({
      campaignRoot: directory,
      workerStateRef: recorded.worker_state_ref,
      expected,
      priorCheckpoint: priorRecoveryCheckpoint,
    });
    expect(derived, recorded, `recovery evidence ${admission.expected.checkpoint} raw CAS join`);
    priorRecoveryCheckpoint = derived.recovery_checkpoint;
  }
}

function snapshot(payload, payloadSha256, state) {
  return clone({
    schema_version: payload.schema_version,
    campaign_id: payload.campaign_id,
    revision: payload.revision,
    payload_sha256: payloadSha256,
    harness_commit: payload.harness_commit,
    candidate: payload.candidate,
    frozen_bindings: payload.frozen_bindings,
    trial_contract: payload.trial_contract,
    provider_contract: payload.provider_contract,
    retry_policy: payload.retry_policy,
    execution_limits: payload.execution_limits,
    phase_sources: state.phaseSources,
    pilot_admission: state.pilotAdmission,
    wave_admissions: state.waveAdmissions,
    final_soak_admission: state.finalSoakAdmission,
    recovery_checkpoints: state.recoveryCheckpoints,
    offline_sqlite_evidence: state.offlineSqliteEvidence,
    campaign_cost_microusd: state.campaignCostMicrousd,
    terminal_failure: state.terminalFailure,
    soak_started_at: state.soakStartedAt,
    wave_started_at: Object.fromEntries(state.waveStartedAt),
    status: state.status,
    active_wave: state.activeWave,
    completed_waves: state.completedWaves,
    seeds: [...state.seeds.values()],
    trials: [...state.trials.values()],
  });
}

function appendEvent({ directory, expectedRevision, event }) {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) fail("expected revision must be a non-negative safe integer");
  const paths = ledgerPaths(directory);
  ensureDirectory(paths.root);
  return withExclusiveLock(paths, () => {
    const current = readEnvelope(paths);
    if (current.payload.revision !== expectedRevision) {
      fail(`campaign ledger CAS mismatch: expected revision ${expectedRevision}, found ${current.payload.revision}`);
    }
    const next = clone(current.payload);
    next.revision += 1;
    next.events.push({ revision: next.revision, ...event });
    const state = replayPayload(next);
    verifyCampaignEvidence(paths.root, next, state);
    const payloadSha256 = writeEnvelope(paths, next);
    return snapshot(next, payloadSha256, state);
  });
}

export function createCampaignLedger({
  directory,
  harnessCommit,
  releaseLockSource,
  authoritySource,
  workloadSource,
  pilotSource,
}) {
  if (!COMMIT_RE.test(harnessCommit ?? "")) fail("campaign harness commit must be immutable");
  const releaseLockContract = parseContractSource(releaseLockSource, "release lock source");
  const authorityContract = parseContractSource(authoritySource, "authority manifest source");
  const workloadContract = parseContractSource(workloadSource, "workload manifest source");
  const { lock, authority, workload } = validateFrozenContracts({
    lock: releaseLockContract.value,
    authority: authorityContract.value,
    workload: workloadContract.value,
  });
  expect(
    authorityContract.sha256,
    lock.protocol_artifacts.authority_manifest.sha256,
    "authority manifest exact source SHA-256",
  );
  expect(
    workloadContract.sha256,
    lock.protocol_artifacts.workload_manifest.sha256,
    "workload manifest exact source SHA-256",
  );
  const candidate = { commit: lock.candidate.commit, digest: lock.candidate.digest };
  validateCandidate(candidate);
  const bindings = validateFrozenBindings({
    release_lock_sha256: releaseLockContract.sha256,
    authority_manifest_sha256: authorityContract.sha256,
    workload_manifest_sha256: workloadContract.sha256,
    candidate: {
      repository: lock.candidate.repository,
      version: lock.candidate.version,
      tag: lock.candidate.tag,
      image: lock.candidate.image,
      platform: lock.candidate.platform,
    },
  });
  const providerExecutionContract = createProviderExecutionContract({
    releaseLockSource: releaseLockContract.bytes,
    workloadSource: workloadContract.bytes,
    frozenBindings: bindings,
  });
  const trialContract = trialContractFromWorkload(workload, providerExecutionContract);
  const providerContract = providerContractFromAuthority(authority);
  const retryPolicy = retryPolicyFromLock(lock);
  const executionLimits = executionLimitsFromLock(lock);
  const source = validatePhaseSource(pilotSource, "pilot", harnessCommit, "campaign pilot source");
  const id = campaignId({ harnessCommit, candidate, frozenBindings: bindings, trialContract, pilotSource: source });
  const trials = deterministicTrials(id, harnessCommit, trialContract);
  const payload = {
    schema_version: PAYLOAD_SCHEMA,
    campaign_id: id,
    revision: 0,
    harness_commit: harnessCommit,
    candidate: clone(candidate),
    frozen_bindings: bindings,
    trial_contract: trialContract,
    provider_contract: providerContract,
    retry_policy: retryPolicy,
    execution_limits: executionLimits,
    pilot_source: source,
    seeds: deterministicSeeds(id, harnessCommit, trialContract, trials),
    trials,
    events: [],
  };
  const state = replayPayload(payload);
  const paths = ledgerPaths(directory);
  ensureDirectory(paths.root, true);
  return withExclusiveLock(paths, () => {
    if (fs.existsSync(paths.ledger)) fail("campaign ledger already exists");
    const payloadSha256 = writeEnvelope(paths, payload);
    return snapshot(payload, payloadSha256, state);
  });
}

export function readCampaignLedger({ directory }) {
  const current = readEnvelope(ledgerPaths(directory));
  return snapshot(current.payload, current.payloadSha256, current.state);
}

export function readCampaignRecoveryExpectation({ directory, checkpoint }) {
  nonEmptyString(checkpoint, "recovery expectation checkpoint");
  return clone(recoveryExpectedBinding(readCampaignLedger({ directory }), checkpoint));
}

function campaignSeed(ledger, seedId, field = "seed ID") {
  nonEmptyString(seedId, field);
  const seed = ledger.seeds.find((entry) => entry.seed_id === seedId);
  if (!seed) fail(`${field} is outside the deterministic campaign universe`);
  return seed;
}

export function claimCampaignSeed({ directory, expectedRevision, seedId }) {
  const before = readCampaignLedger({ directory });
  const seed = campaignSeed(before, seedId);
  const ledger = appendEvent({
    directory,
    expectedRevision,
    event: { type: "claim_seed", seed_id: seed.seed_id, operation_id: seed.operation_id },
  });
  return { ledger, seed: clone(seed) };
}

function exactSeedRequestSource(source, seed, field) {
  const parsed = parseContractSource(source, field);
  expect(parsed.value, seed.request, `${field} parsed request`);
  return parsed;
}

export function markCampaignSeedRuntimeDispatch({ directory, expectedRevision, seedId, requestSource }) {
  const before = readCampaignLedger({ directory });
  const seed = campaignSeed(before, seedId);
  const request = exactSeedRequestSource(requestSource, seed, "seed Runtime request source");
  const requestEvidence = putEvidenceJsonBody({ campaignRoot: directory, body: request.bytes });
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "seed_runtime_dispatch_started",
      seed_id: seed.seed_id,
      operation_id: seed.operation_id,
      request_sha256: request.sha256,
      request_evidence: requestEvidence,
    },
  });
}

// Seed /v1/observe calls are outside the paid provider budget. After an ambiguous
// dispatch, the Runtime operation contract permits only an exact-byte replay with
// the same deterministic operation_id; the durable request hash proves both facts.
export function replayCampaignSeedRuntimeDispatch({ directory, expectedRevision, seedId, requestSource }) {
  const before = readCampaignLedger({ directory });
  const seed = campaignSeed(before, seedId);
  const request = exactSeedRequestSource(requestSource, seed, "seed Runtime replay request source");
  const requestEvidence = putEvidenceJsonBody({ campaignRoot: directory, body: request.bytes });
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "seed_runtime_dispatch_replayed",
      seed_id: seed.seed_id,
      operation_id: seed.operation_id,
      request_sha256: request.sha256,
      request_evidence: requestEvidence,
    },
  });
}

export function recordCampaignSeedRuntimeResponse({
  directory,
  expectedRevision,
  seedId,
  httpStatus,
  responseSource,
}) {
  const before = readCampaignLedger({ directory });
  const seed = campaignSeed(before, seedId);
  const response = putExactJsonEvidence(directory, responseSource, "seed Runtime response source");
  if (!response.value || typeof response.value !== "object" || Array.isArray(response.value)) {
    fail("seed Runtime response source must contain a JSON object");
  }
  const responseNodes = response.value.memory_write?.nodes;
  const writtenMemoryIds = Array.isArray(responseNodes)
    ? responseNodes.map((node) => node?.id ?? null)
    : null;
  const memoryBinding = Array.isArray(responseNodes) && responseNodes.length === 1
    ? {
        client_id: responseNodes[0]?.client_id ?? null,
        memory_id: responseNodes[0]?.id ?? null,
        expected_execution_outcome_role: seed.expected_execution_outcome_role,
        expected_served_surface: seed.expected_served_surface,
      }
    : null;
  const checkpoint = {
    schema_version: SEED_RESPONSE_SCHEMA,
    route: "/v1/observe",
    http_status: httpStatus,
    response_contract_version: response.value.contract_version,
    seed_id: seed.seed_id,
    operation_id: seed.operation_id,
    request_sha256: seed.dispatch_request_sha256,
    response_sha256: response.sha256,
    request_evidence: seed.dispatch_request_evidence,
    response_evidence: response.ref,
    tenant_id: response.value.tenant_id,
    scope: response.value.scope,
    runtime_echoed_operation_id: response.value.operation_id,
    memory_written: response.value.observed?.memory_written,
    semantic_commit: response.value.post_commit_projections?.semantic_commit,
    memory_ids: writtenMemoryIds,
    memory_binding: memoryBinding,
  };
  const ledger = appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "seed_runtime_response_recorded",
      seed_id: seed.seed_id,
      operation_id: seed.operation_id,
      checkpoint,
      checkpoint_sha256: sha256(Buffer.from(canonical(checkpoint))),
    },
  });
  return { ledger, checkpoint: clone(checkpoint) };
}

export function claimCampaignTrial({ directory, expectedRevision, trialId: selectedTrialId }) {
  nonEmptyString(selectedTrialId, "trial ID");
  const before = readCampaignLedger({ directory });
  const trial = before.trials.find((entry) => entry.trial_id === selectedTrialId);
  if (!trial) fail("trial ID is outside the deterministic campaign universe");
  const ledger = appendEvent({
    directory,
    expectedRevision,
    event: { type: "claim_trial", trial_id: selectedTrialId, request_id: trial.preclaim.request_id },
  });
  return { ledger, preclaim: clone(trial.preclaim) };
}

function campaignTrial(ledger, selectedTrialId, field = "trial ID") {
  nonEmptyString(selectedTrialId, field);
  const trial = ledger.trials.find((entry) => entry.trial_id === selectedTrialId);
  if (!trial) fail(`${field} is outside the deterministic campaign universe`);
  return trial;
}

function providerExecutionForLedger(ledger) {
  return hydrateProviderExecutionContract(
    ledger.trial_contract.provider_execution_contract,
    ledger.frozen_bindings,
  );
}

function guideResponseForProvider(directory, trial) {
  if (trial.group !== "aionis") return null;
  if (!trial.guide_response) fail("Aionis provider request requires a durable guide response checkpoint");
  const bytes = readEvidenceJsonBody({ campaignRoot: directory, ref: trial.guide_response.response_evidence });
  return parseContractSource(bytes, "durable guide response evidence").value;
}

function providerLedgerContext(directory, ledger, trial) {
  return { trial, guide_response: guideResponseForProvider(directory, trial) };
}

export function renderCampaignTrialGuideRequest({ directory, trialId: selectedTrialId }) {
  const ledger = readCampaignLedger({ directory });
  const trial = campaignTrial(ledger, selectedTrialId);
  if (trial.group !== "aionis" || trial.status !== "claimed") {
    fail("guide request rendering requires a uniquely claimed Aionis trial");
  }
  const contract = providerExecutionForLedger(ledger);
  const request = renderGuideRequest(contract, trial);
  const requestSource = canonicalJsonBytes(request);
  return {
    method: "POST",
    route: "/v1/guide",
    content_type: "application/json",
    request_source: requestSource,
    request_sha256: sha256(requestSource),
  };
}

export function recordCampaignTrialGuideResponse({
  directory,
  expectedRevision,
  trialId: selectedTrialId,
  requestSource,
  httpStatus,
  responseSource,
}) {
  const before = readCampaignLedger({ directory });
  const trial = campaignTrial(before, selectedTrialId);
  if (trial.group !== "aionis" || trial.status !== "claimed") {
    fail("guide response recording requires a uniquely claimed Aionis trial");
  }
  const contract = providerExecutionForLedger(before);
  const expectedRequest = canonicalJsonBytes(renderGuideRequest(contract, trial));
  const request = parseContractSource(requestSource, "guide Runtime request source");
  if (!request.bytes.equals(expectedRequest)) {
    fail("guide Runtime request bytes do not match the canonical frozen workload request");
  }
  const response = parseContractSource(responseSource, "guide Runtime response source");
  const requestEvidence = putEvidenceJsonBody({ campaignRoot: directory, body: request.bytes });
  const responseEvidence = putEvidenceJsonBody({ campaignRoot: directory, body: response.bytes });
  const checkpoint = deriveGuideResponseCheckpoint({
    providerExecutionContract: contract,
    trial,
    httpStatus,
    requestEvidence,
    responseEvidence,
    responseValue: response.value,
  });
  const ledger = appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "guide_response_recorded",
      trial_id: trial.trial_id,
      request_id: trial.preclaim.request_id,
      checkpoint,
      checkpoint_sha256: sha256(Buffer.from(canonical(checkpoint))),
    },
  });
  return { ledger, checkpoint: clone(checkpoint) };
}

export function prepareCampaignTrialProviderRequest({ directory, expectedRevision, trialId: selectedTrialId }) {
  const before = readCampaignLedger({ directory });
  const trial = campaignTrial(before, selectedTrialId);
  const requiredStatus = trial.group === "aionis" ? "guide_responded" : "claimed";
  if (trial.status !== requiredStatus) fail("trial is not ready to prepare its provider request");
  const contract = providerExecutionForLedger(before);
  const rendered = createCanonicalProviderRequest({
    contract,
    ledgerContext: providerLedgerContext(directory, before, trial),
  });
  const requestEvidence = putEvidenceJsonBody({ campaignRoot: directory, body: rendered.bytes });
  const ledger = appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "provider_request_prepared",
      trial_id: trial.trial_id,
      request_id: trial.preclaim.request_id,
      request_evidence: requestEvidence,
    },
  });
  return { ledger, request_source: Buffer.from(rendered.bytes), request_evidence: requestEvidence };
}

export function readCampaignTrialPreparedProviderRequest({ directory, trialId: selectedTrialId }) {
  const ledger = readCampaignLedger({ directory });
  const trial = campaignTrial(ledger, selectedTrialId);
  if (!new Set(["provider_request_prepared", "provider_retry_ready"]).has(trial.status)
    || !trial.provider_request_evidence) {
    fail("provider request bytes are available only at the durable safe-to-send checkpoint");
  }
  return readEvidenceJsonBody({ campaignRoot: directory, ref: trial.provider_request_evidence });
}

// Call this immediately before the external provider send. Only
// `provider_request_prepared` is safe to send; `provider_dispatch_started` is
// ambiguous after a crash and must never be automatically resent.
export function markCampaignTrialProviderDispatch({
  directory,
  expectedRevision,
  trialId: selectedTrialId,
  requestSource,
}) {
  const before = readCampaignLedger({ directory });
  const trial = campaignTrial(before, selectedTrialId);
  if (!new Set(["provider_request_prepared", "provider_retry_ready"]).has(trial.status)
    || !trial.provider_request_evidence) {
    fail("provider dispatch requires a durable prepared request or retryable HTTP response");
  }
  const source = parseContractSource(requestSource, "provider dispatch request source");
  const prepared = readEvidenceJsonBody({ campaignRoot: directory, ref: trial.provider_request_evidence });
  if (!source.bytes.equals(prepared)) fail("provider dispatch request bytes differ from the durable prepared request");
  const contract = providerExecutionForLedger(before);
  assertCanonicalProviderRequest({
    contract,
    ledgerContext: providerLedgerContext(directory, before, trial),
    requestBytes: source.bytes,
  });
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "provider_dispatch_started",
      trial_id: selectedTrialId,
      request_id: trial.preclaim.request_id,
      attempt: trial.provider_transport_attempts.length + 1,
      request_evidence: trial.provider_request_evidence,
    },
  });
}

export function recordCampaignTrialProviderRetryableHttpResponse(options) {
  exactKeys(options, [
    "directory",
    "expectedRevision",
    "trialId",
    "httpStatus",
    "responseSource",
  ], "retryable provider HTTP response options");
  const {
    directory,
    expectedRevision,
    trialId: selectedTrialId,
    httpStatus,
    responseSource,
  } = options;
  const before = readCampaignLedger({ directory });
  const trial = campaignTrial(before, selectedTrialId);
  if (trial.status !== "provider_dispatch_started" || trial.active_provider_attempt === null) {
    fail("retryable provider HTTP response requires an in-flight provider dispatch");
  }
  if (!before.retry_policy.retryable_http_statuses.includes(httpStatus)) {
    fail("provider HTTP status is outside the frozen retry allowlist");
  }
  const response = putExactJsonEvidence(directory, responseSource, "retryable OpenRouter HTTP response source");
  if (!response.value?.error || typeof response.value.error !== "object" || Array.isArray(response.value.error)) {
    fail("retryable OpenRouter HTTP response must contain an error object");
  }
  nonEmptyString(response.value.error.message, "retryable OpenRouter HTTP response error.message");
  const attemptEvidence = {
    attempt: trial.active_provider_attempt,
    result: "http",
    http_status: httpStatus,
    network_code: null,
    request_commit_state: "response_received",
    evidence_sha256: response.sha256,
    response_evidence: response.ref,
  };
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "provider_retryable_http_response_recorded",
      trial_id: trial.trial_id,
      request_id: trial.preclaim.request_id,
      attempt_evidence: attemptEvidence,
      attempt_evidence_sha256: sha256(Buffer.from(canonical(attemptEvidence))),
    },
  });
}

export function recordCampaignTrialProviderResponse(options) {
  exactKeys(options, [
    "directory",
    "expectedRevision",
    "trialId",
    "httpStatus",
    "responseSource",
  ], "provider response options");
  const {
    directory,
    expectedRevision,
    trialId: selectedTrialId,
    httpStatus,
    responseSource,
  } = options;
  const before = readCampaignLedger({ directory });
  const trial = campaignTrial(before, selectedTrialId);
  if (trial.status !== "provider_dispatch_started" || !trial.provider_request_evidence) {
    fail("provider response requires an ambiguous provider dispatch checkpoint");
  }
  const response = putExactJsonEvidence(directory, responseSource, "OpenRouter response source");
  const requestBytes = readEvidenceJsonBody({ campaignRoot: directory, ref: trial.provider_request_evidence });
  const contract = providerExecutionForLedger(before);
  const boundary = parseOpenRouterChatCompletion({
    contract,
    ledgerContext: providerLedgerContext(directory, before, trial),
    requestBytes,
    httpStatus,
    responseBytes: response.bytes,
  });
  const finalAttempt = {
    attempt: trial.active_provider_attempt,
    result: "success",
    http_status: 200,
    network_code: null,
    request_commit_state: "response_received",
    evidence_sha256: response.sha256,
    response_evidence: response.ref,
  };
  const transportAttemptEvidence = [...trial.provider_transport_attempts, finalAttempt];
  const checkpoint = {
    schema_version: PROVIDER_RESPONSE_SCHEMA,
    trial_id: trial.trial_id,
    response_contract: boundary.response_contract,
    provider_request_id: boundary.provider_request_id,
    requested_model: boundary.requested_model,
    request_sha256: boundary.request_sha256,
    response_sha256: boundary.response_sha256,
    request_evidence: trial.provider_request_evidence,
    response_evidence: response.ref,
    returned_model: boundary.returned_model,
    fallback_used: boundary.fallback_used,
    tool_call_id: boundary.tool_call_id,
    transport_attempts: transportAttemptEvidence.length,
    transport_attempt_evidence: clone(transportAttemptEvidence),
    semantic_attempts: 1,
    provider_usage: boundary.provider_usage,
    cost_microusd_rule: boundary.cost_microusd_rule,
    tool_result: boundary.tool_result,
  };
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "provider_response_recorded",
      trial_id: trial.trial_id,
      request_id: trial.preclaim.request_id,
      checkpoint,
      checkpoint_sha256: sha256(Buffer.from(canonical(checkpoint))),
    },
  });
}

function nextPostTrialStage(trial) {
  return POST_TRIAL_STAGES[trial.post_trial_checkpoints.length] ?? null;
}

export function renderCampaignTrialPostTrialRequest({ directory, trialId: selectedTrialId }) {
  const ledger = readCampaignLedger({ directory });
  const trial = campaignTrial(ledger, selectedTrialId);
  if (trial.group !== "aionis"
    || !new Set(["provider_responded", "post_trial_running"]).has(trial.status)) {
    fail("post-trial request rendering requires an Aionis trial with a durable provider response");
  }
  const stage = nextPostTrialStage(trial);
  if (stage === null) fail("post-trial Runtime chain is already complete");
  const contract = providerExecutionForLedger(ledger);
  const guideResponse = guideResponseForProvider(directory, trial);
  const postTrial = rehydratePostTrialChain({ directory, contract, trial, guideResponse });
  const request = createCanonicalPostTrialRequest({
    execution: postTrial.execution,
    stage,
    priorResponses: postTrial.checkpoints,
  });
  return {
    stage,
    method: request.method,
    route: request.route,
    content_type: request.content_type,
    request_source: Buffer.from(request.bytes),
    request_sha256: request.sha256,
  };
}

export function recordCampaignTrialPostTrialResponse(options) {
  exactKeys(options, [
    "directory",
    "expectedRevision",
    "trialId",
    "stage",
    "requestSource",
    "httpStatus",
    "responseSource",
  ], "post-trial Runtime response options");
  const {
    directory,
    expectedRevision,
    trialId: selectedTrialId,
    stage,
    requestSource,
    httpStatus,
    responseSource,
  } = options;
  const before = readCampaignLedger({ directory });
  const trial = campaignTrial(before, selectedTrialId);
  if (trial.group !== "aionis"
    || !new Set(["provider_responded", "post_trial_running"]).has(trial.status)) {
    fail("post-trial Runtime response requires an Aionis trial with a durable provider response");
  }
  expect(stage, nextPostTrialStage(trial), "post-trial Runtime stage order");
  const contract = providerExecutionForLedger(before);
  const guideResponse = guideResponseForProvider(directory, trial);
  const postTrial = rehydratePostTrialChain({ directory, contract, trial, guideResponse });
  const request = parseContractSource(requestSource, `${stage} Runtime request source`);
  const response = parseContractSource(responseSource, `${stage} Runtime response source`);
  const checkpoint = parsePostTrialRuntimeResponse({
    execution: postTrial.execution,
    stage,
    priorResponses: postTrial.checkpoints,
    requestBytes: request.bytes,
    httpStatus,
    responseBytes: response.bytes,
  });
  const requestEvidence = putEvidenceJsonBody({ campaignRoot: directory, body: request.bytes });
  const responseEvidence = putEvidenceJsonBody({ campaignRoot: directory, body: response.bytes });
  const durableCheckpoint = {
    schema_version: POST_TRIAL_DURABLE_SCHEMA,
    stage,
    request_evidence: requestEvidence,
    response_evidence: responseEvidence,
    checkpoint: clone(checkpoint),
    checkpoint_sha256: sha256(Buffer.from(canonical(checkpoint))),
  };
  const ledger = appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "post_trial_runtime_response_recorded",
      trial_id: trial.trial_id,
      request_id: trial.preclaim.request_id,
      durable_checkpoint: durableCheckpoint,
    },
  });
  return { ledger, checkpoint: clone(checkpoint), durable_checkpoint: clone(durableCheckpoint) };
}

export function completeCampaignTrial({ directory, expectedRevision, trialId: selectedTrialId }) {
  const before = readCampaignLedger({ directory });
  const trial = campaignTrial(before, selectedTrialId);
  if (!trial.provider_response) fail("completed trial requires a durable provider response checkpoint");
  let aionis = null;
  if (trial.group === "aionis") {
    if (trial.status !== "post_trial_running" || trial.post_trial_checkpoints.length !== POST_TRIAL_STAGES.length) {
      fail("completed Aionis trial requires the complete durable post-trial Runtime chain");
    }
    const contract = providerExecutionForLedger(before);
    const guideResponse = guideResponseForProvider(directory, trial);
    const postTrial = rehydratePostTrialChain({ directory, contract, trial, guideResponse });
    if (!postTrial.settlementFacts) fail("completed Aionis trial post-trial facts are unavailable");
    aionis = aionisSettlementFactsFromDurableCheckpoints(trial);
  } else if (trial.status !== "provider_responded") {
    fail("completed non-Aionis trial requires a durable provider response checkpoint");
  }
  const provider = trial.provider_response;
  const receipt = {
    schema_version: TRIAL_SUCCESS_SCHEMA,
    status: "completed",
    trial_id: trial.trial_id,
    preclaim: clone(trial.preclaim),
    provider_request_id: provider.provider_request_id,
    request_sha256: provider.request_sha256,
    response_sha256: provider.response_sha256,
    returned_model: provider.returned_model,
    fallback_used: provider.fallback_used,
    transport_attempts: provider.transport_attempts,
    semantic_attempts: provider.semantic_attempts,
    provider_usage: clone(provider.provider_usage),
    tool_result: clone(provider.tool_result),
    runtime_digest: before.candidate.digest,
    aionis,
  };
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "settle_trial",
      trial_id: trial.trial_id,
      request_id: trial.preclaim.request_id,
      receipt,
      receipt_sha256: sha256(Buffer.from(canonical(receipt))),
    },
  });
}

export function settleCampaignTrial({ directory, expectedRevision, receipt }) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) fail("trial settlement receipt must be an object");
  const value = clone(receipt);
  if (value.status !== "failed") {
    fail("completed trial settlement is internally derived; use completeCampaignTrial");
  }
  nonEmptyString(value.trial_id, "trial settlement receipt trial ID");
  nonEmptyString(value.preclaim?.request_id, "trial settlement receipt request ID");
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "settle_trial",
      trial_id: value.trial_id,
      request_id: value.preclaim.request_id,
      receipt: value,
      receipt_sha256: sha256(Buffer.from(canonical(value))),
    },
  });
}

export function recordCampaignPilotAdmission(options) {
  exactKeys(options, ["directory", "expectedRevision", "workerStateRef"], "pilot admission options");
  const { directory, expectedRevision, workerStateRef } = options;
  const before = readCampaignLedger({ directory });
  if (before.status !== "pilot_running") fail(`pilot admission cannot complete from ${before.status}`);
  const pilotTrials = before.trials.filter((trial) => trial.phase === "pilot");
  if (pilotTrials.some((trial) => !new Set(["completed", "failed"]).has(trial.status))) {
    fail("pilot admission cannot complete before every pilot trial is terminal");
  }
  const recoveryEvidence = deriveRecoveryCheckpointEvidence({
    campaignRoot: directory,
    workerStateRef,
    expected: recoveryExpectedBinding(before, "pilot"),
    priorCheckpoint: null,
  });
  assertRecoveryEvidenceBoundary(recoveryEvidence);
  const checkpoint = recoveryEvidence.recovery_checkpoint;
  const derived = derivedTrialFacts(pilotTrials);
  const external = {
    terminal_backlog: clone(checkpoint.terminal_backlog),
    worker_errors: checkpoint.worker_errors,
    checkpoint_passed: recoveryEvidence.derivation.checkpoint_passed,
    recovery: checkpoint.recovery,
    recorded_at: checkpoint.recorded_at,
    checkpoint_evidence_sha256: recoveryEvidence.facts_sha256,
    recovery_checkpoint: clone(checkpoint),
    recovery_evidence: clone(recoveryEvidence),
    transport_authority: clone(BLOCKED_TRANSPORT_AUTHORITY),
  };
  const facts = { ...derived, failed_direct_use: derived.wrong_direct_use, ...external };
  const value = {
    schema_version: PILOT_ADMISSION_SCHEMA,
    source: clone(before.phase_sources.pilot),
    status: pilotAdmissionPassed(pilotTrials, derived, external, before.retry_policy, before.execution_limits)
      ? "pass"
      : "fail",
    reducer_evidence_sha256: "0".repeat(64),
    facts,
  };
  value.reducer_evidence_sha256 = expectedReducerEvidenceSha256(value);
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "record_pilot_admission",
      receipt: value,
      receipt_sha256: sha256(Buffer.from(canonical(value))),
    },
  });
}

export function beginCampaignSoak({ directory, expectedRevision, source, startedAt }) {
  isoTimestamp(startedAt, "soak started_at");
  return appendEvent({
    directory,
    expectedRevision,
    event: { type: "begin_soak", source: clone(source), started_at: startedAt },
  });
}

export function beginCampaignWave({ directory, expectedRevision, wave, startedAt }) {
  positiveInteger(wave, "soak wave");
  isoTimestamp(startedAt, "soak wave started_at");
  return appendEvent({ directory, expectedRevision, event: { type: "begin_wave", wave, started_at: startedAt } });
}

export function inspectCampaignOfflineSqliteEvidence(options) {
  exactKeys(options, ["directory", "databasePath"], "campaign offline SQLite inspection options");
  const ledger = readCampaignLedger({ directory: options.directory });
  if (ledger.status !== `soak_wave_${SOAK_WAVES}_running` || ledger.active_wave !== SOAK_WAVES) {
    fail("campaign offline SQLite inspection requires the terminal soak wave in progress");
  }
  if (!ledger.phase_sources.soak) fail("campaign offline SQLite inspection requires the protected soak source");
  const trials = ledger.trials
    .filter((trial) => trial.phase === "soak" && trial.group === "aionis")
    .sort((left, right) => Buffer.compare(Buffer.from(left.trial_id), Buffer.from(right.trial_id)));
  if (trials.length !== 27 || trials.some((trial) => trial.status !== "completed")) {
    fail("campaign offline SQLite inspection requires all 27 completed soak Aionis trials");
  }
  const trialBindings = trials.map((trial) => {
    if (!trial.guide_response || trial.post_trial_checkpoints.length !== POST_TRIAL_STAGES.length) {
      fail(`campaign offline SQLite inspection trial ${trial.trial_id} lacks its durable Runtime chain`);
    }
    const checkpoints = new Map(trial.post_trial_checkpoints.map((entry) => [entry.stage, entry]));
    return {
      trial_id: trial.trial_id,
      tenant_id: trial.preclaim.tenant_id,
      scope: trial.preclaim.scope,
      guide_operation_id: trial.preclaim.guide_operation_id,
      outcome_operation_id: trial.preclaim.outcome_operation_id,
      feedback_operation_id: trial.preclaim.feedback_operation_id,
      measure_operation_id: trial.preclaim.measure_operation_id,
      guide_response_ref: clone(trial.guide_response.response_evidence),
      outcome_response_ref: clone(checkpoints.get("outcome_observe").response_evidence),
      feedback_response_ref: clone(checkpoints.get("feedback").response_evidence),
      measure_response_ref: clone(checkpoints.get("measure").response_evidence),
      measure_replay_response_ref: clone(checkpoints.get("measure_replay").response_evidence),
    };
  });
  const inspection = inspectOfflineSqliteEvidence({
    campaignRoot: options.directory,
    databasePath: options.databasePath,
    expected: {
      source_run_id: ledger.phase_sources.soak.run_id,
      source_run_attempt: ledger.phase_sources.soak.run_attempt,
      verified_after_wave: SOAK_WAVES,
      product_invariants: clone(ledger.trial_contract.product_invariants),
    },
    trialBindings,
  });
  campaignOfflineInspectionBindings.set(inspection, {
    campaign_id: ledger.campaign_id,
    revision: ledger.revision,
    payload_sha256: ledger.payload_sha256,
  });
  return inspection;
}

export function recordCampaignWaveAdmission(options) {
  exactKeys(
    options,
    ["directory", "expectedRevision", "workerStateRef", "offlineSqliteInspection"],
    "soak wave admission options",
  );
  const { directory, expectedRevision, workerStateRef, offlineSqliteInspection } = options;
  const before = readCampaignLedger({ directory });
  const wave = before.active_wave;
  if (wave === null || before.status !== `soak_wave_${wave}_running`) {
    fail("soak wave admission cannot complete an inactive wave");
  }
  const waveTrials = before.trials.filter((trial) => trial.phase === "soak" && trial.wave === wave);
  if (waveTrials.some((trial) => !new Set(["completed", "failed"]).has(trial.status))) {
    fail("soak wave admission cannot complete before every trial is terminal");
  }
  const recoveryEvidence = deriveRecoveryCheckpointEvidence({
    campaignRoot: directory,
    workerStateRef,
    expected: recoveryExpectedBinding(before, `after_wave_${wave}`),
    priorCheckpoint: before.recovery_checkpoints.at(-1) ?? null,
  });
  assertRecoveryEvidenceBoundary(recoveryEvidence);
  let offlineSqliteEvidence = null;
  if (wave === SOAK_WAVES) {
    expect(
      campaignOfflineInspectionBindings.get(offlineSqliteInspection),
      {
        campaign_id: before.campaign_id,
        revision: before.revision,
        payload_sha256: before.payload_sha256,
      },
      "campaign offline SQLite inspection ledger authority",
    );
    offlineSqliteEvidence = assertOfflineSqliteLedgerFacts(offlineSqliteInspection);
  } else if (offlineSqliteInspection !== null) {
    fail("offline SQLite inspection is only valid after the final soak wave");
  }
  const allDerived = derivedTrialFacts(waveTrials);
  const contextDerived = derivedContextFacts(waveTrials);
  const derived = {
    semantic_chat_calls: allDerived.semantic_chat_calls,
    aionis_action_completion: allDerived.aionis_action_completion,
    wrong_direct_use: allDerived.wrong_direct_use,
    negative_direct_use: allDerived.negative_direct_use,
    semantic_retries: allDerived.semantic_retries,
    transport_retries: allDerived.transport_retries,
    maximum_transport_attempts: allDerived.maximum_transport_attempts,
    cost_microusd: allDerived.cost_microusd,
    evidence_set_sha256: allDerived.evidence_set_sha256,
    ...contextDerived,
  };
  const checkpoint = recoveryEvidence.recovery_checkpoint;
  const external = {
    recovery: checkpoint.recovery,
    checkpoint_passed: recoveryEvidence.derivation.checkpoint_passed,
    terminal_backlog: clone(checkpoint.terminal_backlog),
    worker_errors: checkpoint.worker_errors,
    offline_sqlite_verify: wave === SOAK_WAVES && offlineSqliteEvidence !== null,
    recorded_at: checkpoint.recorded_at,
    checkpoint_evidence_sha256: recoveryEvidence.facts_sha256,
    recovery_checkpoint: clone(checkpoint),
    recovery_evidence: clone(recoveryEvidence),
    offline_sqlite_evidence: clone(offlineSqliteEvidence),
    offline_sqlite_evidence_sha256: offlineSqliteEvidence === null
      ? null
      : sha256(Buffer.from(canonical(offlineSqliteEvidence))),
  };
  const value = {
    schema_version: WAVE_ADMISSION_SCHEMA,
    source: clone(before.phase_sources.soak),
    wave,
    status: waveAdmissionPassed(
      waveTrials,
      derived,
      external,
      wave,
      before.retry_policy,
      before.execution_limits,
    ) ? "pass" : "fail",
    reducer_evidence_sha256: "0".repeat(64),
    facts: { ...derived, ...external },
  };
  value.reducer_evidence_sha256 = expectedReducerEvidenceSha256(value);
  return appendEvent({
    directory,
    expectedRevision,
    event: {
      type: "record_wave_admission",
      receipt: value,
      receipt_sha256: sha256(Buffer.from(canonical(value))),
    },
  });
}

export function recordCampaignFinalSoakAdmission({ directory, expectedRevision, receipt }) {
  void directory;
  void expectedRevision;
  void receipt;
  fail(`final soak admission is blocked: ${OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER}`);
}
