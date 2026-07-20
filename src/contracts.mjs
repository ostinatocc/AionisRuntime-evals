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
  "scripts/ci/docker-recovery-smoke.sh",
  "scripts/ci/release-package-artifacts.sh",
  "scripts/ci/release-artifact-gate.mjs",
  "scripts/ci/release-artifact-gate.test.mjs",
  "scripts/ci/release-version-docs.test.mjs",
  "scripts/ci/release-workflow-contract.test.mjs",
  "scripts/ci/runtime-complexity-budget.test.mjs",
  "scripts/ci/sdk-contract-ownership.test.mjs",
]);

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
    fail(`${field} does not match the frozen release lock`);
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

export function validateWorkloadManifest(workload, lock) {
  validateReleaseLock(lock);
  assertExactKeys(workload, ["schema_version", "frozen_at", "groups", "scenarios", "product_invariants", "pilot", "soak", "verifier", "recovery"], "workload manifest");
  if (workload.schema_version !== "aionis_soak_workload_manifest_v1") fail("workload schema_version is invalid");
  assertDate(workload.frozen_at, "workload.frozen_at");
  assertUniqueStrings(workload.groups, "workload.groups");
  assertUniqueStrings(workload.scenarios, "workload.scenarios");
  assertUniqueStrings(workload.product_invariants, "workload.product_invariants");
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
  assertExactKeys(workload.verifier, ["real_tools", "deterministic_outcome_verifier", "model_self_report_accepted"], "workload.verifier");
  if (
    workload.verifier.real_tools !== true
    || workload.verifier.deterministic_outcome_verifier !== true
    || workload.verifier.model_self_report_accepted !== false
  ) fail("workload must use real tools and a deterministic outcome verifier");
  assertExactKeys(workload.recovery, ["after_wave_1", "after_wave_2", "after_wave_3"], "workload.recovery");
  assertEqual(workload.recovery, {
    after_wave_1: "graceful_replacement",
    after_wave_2: "sigkill_replacement",
    after_wave_3: "offline_sqlite_verify",
  }, "workload.recovery");
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
