import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  STABLE_GOVERNANCE_PATHS,
  assertNoSecretMaterial,
  readJsonFile,
  sha256,
  validateAuthorityManifest,
  validateFrozenContracts,
  validateReleaseLock,
  validateReturnedModel,
  validateWorkloadManifest,
} from "../src/contracts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOCK_PATH = path.join(ROOT, "config/v0.3.12-release-lock.json");
const AUTHORITY_PATH = path.join(ROOT, "fixtures/v0.3.12/authority-manifest.json");
const WORKLOAD_PATH = path.join(ROOT, "fixtures/v0.3.12/workload-manifest.json");

function documents() {
  return {
    lock: readJsonFile(LOCK_PATH).value,
    authority: readJsonFile(AUTHORITY_PATH).value,
    workload: readJsonFile(WORKLOAD_PATH).value,
  };
}

function copy(value) {
  return structuredClone(value);
}

test("frozen v0.3.12 authority and workload fixtures satisfy their cross-contract", () => {
  const values = documents();
  assert.doesNotThrow(() => validateFrozenContracts(values));
  assert.equal(sha256(fs.readFileSync(AUTHORITY_PATH)), values.lock.protocol_artifacts.authority_manifest.sha256);
  assert.equal(sha256(fs.readFileSync(WORKLOAD_PATH)), values.lock.protocol_artifacts.workload_manifest.sha256);
});

test("authority rejects candidate, digest, provider, model, fallback, retry, and budget drift", () => {
  const { lock, authority } = documents();
  const mutations = [
    (value) => { value.candidate.commit = "a".repeat(40); },
    (value) => { value.candidate.digest = `sha256:${"b".repeat(64)}`; },
    (value) => { value.providers.embedding.model = "different-embedding"; },
    (value) => { value.providers.agent.requested_model = "different-agent"; },
    (value) => { value.providers.agent.allowed_returned_models.push("fallback-model"); },
    (value) => { value.providers.agent.fallback_allowed = true; },
    (value) => { value.retry_policy.semantic_retries = 1; },
    (value) => { value.execution_limits.maximum_chat_calls = 91; },
    (value) => { value.execution_limits.maximum_cost_usd = 51; },
  ];
  for (const mutate of mutations) {
    const value = copy(authority);
    mutate(value);
    assert.throws(() => validateAuthorityManifest(value, lock));
  }
});

test("workload rejects matrix inflation, denominator drift, self-report, and missing recovery", () => {
  const { lock, workload } = documents();
  const mutations = [
    (value) => { value.groups.push("duplicate"); },
    (value) => { value.pilot.semantic_chat_calls = 10; },
    (value) => { value.soak.semantic_chat_calls = 82; },
    (value) => { value.soak.aionis_trials_per_wave = 10; },
    (value) => { value.soak.negative_transfer_trials = 10; },
    (value) => { value.product_invariants.pop(); },
    (value) => { value.verifier.model_self_report_accepted = true; },
    (value) => { value.recovery.after_wave_2 = "graceful_replacement"; },
  ];
  for (const mutate of mutations) {
    const value = copy(workload);
    mutate(value);
    assert.throws(() => validateWorkloadManifest(value, lock));
  }
});

test("release lock rejects extra fields and non-singleton returned-model allowlists", () => {
  const { lock } = documents();
  const extra = copy(lock);
  extra.unfrozen = true;
  assert.throws(() => validateReleaseLock(extra), /keys must be exactly/);
  const returned = copy(lock);
  returned.providers.agent.allowed_returned_models.push("another-model");
  assert.throws(() => validateReleaseLock(returned), /only the requested model/);
});

test("release lock binds the exact stable gate governance dependency set", () => {
  const { lock } = documents();
  assert.deepEqual(
    lock.stable_governance_artifacts.map((binding) => binding.path).sort(),
    [...STABLE_GOVERNANCE_PATHS].sort(),
  );
  const missing = copy(lock);
  missing.stable_governance_artifacts.pop();
  assert.throws(() => validateReleaseLock(missing), /exact stable gate dependency set/);
  const extra = copy(lock);
  extra.stable_governance_artifacts.push({ path: "scripts/ci/untrusted-extra.mjs", sha256: "f".repeat(64) });
  assert.throws(() => validateReleaseLock(extra), /exact stable gate dependency set/);
});

test("returned provider model must exactly match the frozen singleton", () => {
  const { authority } = documents();
  assert.equal(validateReturnedModel("deepseek/deepseek-v4-pro", authority), "deepseek/deepseek-v4-pro");
  assert.throws(() => validateReturnedModel("fallback-model", authority), /outside the frozen allowlist/);
});

test("secret-like provider material fails closed even without a familiar provider prefix", () => {
  const samples = [
    "sk-" + "x".repeat(24),
    "Authorization: Bearer " + "x".repeat(24),
    JSON.stringify({ api_key: "generic-value-that-is-long" }),
    JSON.stringify({ access_token: "generic-value-that-is-long" }),
    JSON.stringify({ authorization: "generic-value-that-is-long" }),
    JSON.stringify({ secret: "generic-value-that-is-long" }),
    JSON.stringify({ password: "correct-horse-battery-staple" }),
    JSON.stringify({ credential: "generic-value-that-is-long" }),
    JSON.stringify({ client_secret: "generic-value-that-is-long" }),
    JSON.stringify({ refresh_token: "generic-value-that-is-long" }),
    JSON.stringify({ private_key: "generic-value-that-is-long" }),
    JSON.stringify({ cookie: "generic-value-that-is-long" }),
    JSON.stringify({ session: "generic-value-that-is-long" }),
    "Set-Cookie: " + "x".repeat(24),
    "-----BEGIN PRIVATE KEY-----",
  ];
  for (const sample of samples) assert.throws(() => assertNoSecretMaterial(sample), /secret-like material/);
});

test("JSON schemas are strict Draft 2020-12 documents", () => {
  for (const file of [
    "schemas/authority-manifest.schema.json",
    "schemas/workload-manifest.schema.json",
    "schemas/artifact-bundle-manifest.schema.json",
    "schemas/workflow-run-evidence.schema.json",
  ]) {
    const schema = JSON.parse(fs.readFileSync(path.join(ROOT, file), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    assert.equal(schema.additionalProperties, false);
    assert.ok(Array.isArray(schema.required) && schema.required.length > 0);
  }
});
