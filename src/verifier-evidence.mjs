import {
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign,
  verify,
} from "node:crypto";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectNonNegativeInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";

const SCHEMA_VERSION = "aionis_pilot_verifier_evidence_v1";
const SIGNATURE_PAYLOAD_SCHEMA_VERSION = "aionis_pilot_verifier_signature_payload_v1";

const BODY_KEYS = Object.freeze([
  "cell_execution_ref",
  "checks",
  "failure_class",
  "inputs",
  "metrics",
  "runtime_outcome_mapping",
  "schema_version",
  "temporal_fence",
  "verdict",
  "verifier_authority_ref",
]);

const BUILD_INPUT_KEYS = Object.freeze(
  BODY_KEYS.filter((key) => key !== "schema_version"),
);

const EVIDENCE_KEYS = Object.freeze([
  ...BODY_KEYS,
  "evidence_sha256",
  "signature",
  "signature_algorithm",
]);

const CELL_EXECUTION_REF_KEYS = Object.freeze([
  "case_id",
  "case_sha256",
  "contract_sha256",
  "decision_id",
  "exposure_event_sha256",
  "opaque_cell_id",
  "pilot_id",
  "render_result_sha256",
]);

const VERIFIER_AUTHORITY_INPUT_KEYS = Object.freeze([
  "verifier_config_sha256",
  "verifier_contract_sha256",
  "verifier_id",
  "verifier_image_digest",
]);

const VERIFIER_AUTHORITY_REF_KEYS = Object.freeze([
  "public_key_principal_sha256",
  ...VERIFIER_AUTHORITY_INPUT_KEYS,
]);

const TEMPORAL_FENCE_INPUT_KEYS = Object.freeze([
  "after_agent_exit",
  "agent_exit_authority_principal_sha256",
  "agent_exit_receipt_sha256",
  "agent_exit_sequence",
  "agent_exited_at",
  "fresh_process",
  "verifier_runner_parent_agent_exit_receipt_sha256",
  "verifier_runner_receipt_sha256",
  "verifier_runner_sequence",
  "verifier_started_at",
]);

const TEMPORAL_FENCE_KEYS = Object.freeze([
  ...TEMPORAL_FENCE_INPUT_KEYS,
  "verifier_runner_authority_principal_sha256",
]);

const FAILURE_CLASSES = new Set([
  "none",
  "product",
  "provider_or_network",
  "harness_infrastructure",
  "filesystem_infrastructure",
  "verifier_infrastructure",
]);

const CHECK_STATUSES = new Set(["passed", "failed", "indeterminate"]);

function fail(code) {
  throw new Error(`aionis_eval_verifier_${code}`);
}

function nullableBoolean(value, field) {
  if (value !== null && typeof value !== "boolean") fail(`${field}_invalid`);
}

function nullableCount(value, field) {
  if (value !== null && (!Number.isSafeInteger(value) || value < 0)) fail(`${field}_invalid`);
}

function imageDigest(value, field) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail(`${field}_invalid`);
  }
}

function asPrivateKey(value) {
  const key = value instanceof KeyObject ? value : createPrivateKey(value);
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    fail("private_key_invalid");
  }
  return key;
}

function asPublicKey(value) {
  const key = value instanceof KeyObject
    ? (value.type === "public" ? value : createPublicKey(value))
    : createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    fail("public_key_invalid");
  }
  return key;
}

function principalSha256(publicKeyInput) {
  const der = asPublicKey(publicKeyInput).export({ format: "der", type: "spki" });
  return sha256Bytes(der);
}

export function verifierPublicKeyPrincipalSha256V1(publicKeyInput) {
  return principalSha256(publicKeyInput);
}

function signaturePayload(evidenceSha256, verifierPrincipalSha256) {
  return canonicalJson({
    schema_version: SIGNATURE_PAYLOAD_SCHEMA_VERSION,
    evidence_sha256: evidenceSha256,
    verifier_principal_sha256: verifierPrincipalSha256,
  });
}

function verifyCellExecutionRef(value) {
  const record = expectExactRecord(
    value,
    CELL_EXECUTION_REF_KEYS,
    "verifier_cell_execution_ref",
  );
  for (const field of ["pilot_id", "opaque_cell_id", "case_id", "decision_id"]) {
    expectText(record[field], `verifier_cell_${field}`);
  }
  for (const field of [
    "case_sha256",
    "contract_sha256",
    "render_result_sha256",
    "exposure_event_sha256",
  ]) {
    expectSha256(record[field], `verifier_cell_${field}`);
  }
}

function verifyVerifierAuthorityRef(value) {
  const record = expectExactRecord(
    value,
    VERIFIER_AUTHORITY_REF_KEYS,
    "verifier_authority_ref",
  );
  expectText(record.verifier_id, "verifier_authority_id");
  expectSha256(
    record.public_key_principal_sha256,
    "verifier_authority_public_key_principal_sha256",
  );
  expectSha256(record.verifier_contract_sha256, "verifier_authority_contract_sha256");
  expectSha256(record.verifier_config_sha256, "verifier_authority_config_sha256");
  imageDigest(record.verifier_image_digest, "verifier_authority_image_digest");
}

function verifyTemporalFence(value, verifierPrincipalSha256) {
  const fence = expectExactRecord(value, TEMPORAL_FENCE_KEYS, "verifier_temporal_fence");
  expectCanonicalTimestamp(fence.agent_exited_at, "verifier_agent_exited_at");
  expectCanonicalTimestamp(fence.verifier_started_at, "verifier_started_at");
  expectSha256(
    fence.agent_exit_authority_principal_sha256,
    "verifier_agent_exit_authority_principal_sha256",
  );
  expectSha256(fence.agent_exit_receipt_sha256, "verifier_agent_exit_receipt_sha256");
  expectSha256(
    fence.verifier_runner_authority_principal_sha256,
    "verifier_runner_authority_principal_sha256",
  );
  expectSha256(
    fence.verifier_runner_parent_agent_exit_receipt_sha256,
    "verifier_runner_parent_agent_exit_receipt_sha256",
  );
  expectSha256(
    fence.verifier_runner_receipt_sha256,
    "verifier_runner_receipt_sha256",
  );
  expectNonNegativeInteger(fence.agent_exit_sequence, "verifier_agent_exit_sequence");
  expectNonNegativeInteger(fence.verifier_runner_sequence, "verifier_runner_sequence");

  if (fence.fresh_process !== true || fence.after_agent_exit !== true) {
    fail("temporal_fence_invalid");
  }
  if (Date.parse(fence.verifier_started_at) <= Date.parse(fence.agent_exited_at)
    || fence.verifier_runner_sequence <= fence.agent_exit_sequence) {
    fail("temporal_order_invalid");
  }
  if (fence.verifier_runner_parent_agent_exit_receipt_sha256
      !== fence.agent_exit_receipt_sha256
    || fence.verifier_runner_receipt_sha256 === fence.agent_exit_receipt_sha256) {
    fail("temporal_receipt_chain_invalid");
  }
  if (fence.verifier_runner_authority_principal_sha256 !== verifierPrincipalSha256) {
    fail("temporal_runner_authority_invalid");
  }
}

function verifyChecks(value) {
  const checks = expectArray(value, "verifier_checks", { minimum: 1, maximum: 128 });
  const checkIds = new Set();
  for (const valueCheck of checks) {
    const check = expectExactRecord(valueCheck, [
      "check_id", "command_argv_sha256", "exit_code", "status", "stderr_sha256",
      "stdout_sha256",
    ], "verifier_check");
    expectText(check.check_id, "verifier_check_id");
    if (checkIds.has(check.check_id)) fail("check_id_duplicate");
    checkIds.add(check.check_id);
    expectSha256(check.command_argv_sha256, "verifier_command_argv_sha256");
    if (check.exit_code !== null
      && (!Number.isSafeInteger(check.exit_code) || check.exit_code < 0 || check.exit_code > 255)) {
      fail("check_exit_code_invalid");
    }
    for (const field of ["stdout_sha256", "stderr_sha256"]) {
      if (check[field] !== null) expectSha256(check[field], `verifier_check_${field}`);
    }
    if (!CHECK_STATUSES.has(check.status)) fail("check_status_invalid");
    if (check.status === "passed" && check.exit_code !== 0) {
      fail("passed_check_exit_code_invalid");
    }
  }
  return checks;
}

function verifyMetrics(value) {
  const metrics = expectExactRecord(value, [
    "accepted_direction", "action_completion", "rediscovery_steps", "unsafe_direct_use",
    "wrong_branch_attention", "wrong_branch_write",
  ], "verifier_metrics");
  for (const field of [
    "accepted_direction", "action_completion", "unsafe_direct_use",
    "wrong_branch_attention", "wrong_branch_write",
  ]) {
    nullableBoolean(metrics[field], `verifier_metric_${field}`);
  }
  nullableCount(metrics.rediscovery_steps, "verifier_metric_rediscovery_steps");
  return metrics;
}

function verifyPassedVerdict(checks, metrics) {
  if (checks.some((check) => check.status !== "passed" || check.exit_code !== 0)
    || metrics.action_completion !== true
    || metrics.accepted_direction !== true
    || metrics.wrong_branch_write !== false
    || metrics.wrong_branch_attention !== false
    || metrics.unsafe_direct_use !== false) {
    fail("passed_evidence_contradiction");
  }
}

function verifyBody(value) {
  const record = expectExactRecord(value, BODY_KEYS, "verifier_evidence_body");
  if (record.schema_version !== SCHEMA_VERSION) fail("schema_invalid");

  verifyCellExecutionRef(record.cell_execution_ref);
  verifyVerifierAuthorityRef(record.verifier_authority_ref);
  const verifierPrincipalSha256 = record.verifier_authority_ref.public_key_principal_sha256;
  verifyTemporalFence(record.temporal_fence, verifierPrincipalSha256);

  const inputs = expectExactRecord(record.inputs, [
    "action_trace_sha256", "diff_sha256", "task_fixture_sha256",
    "workspace_after_sha256", "workspace_before_sha256",
  ], "verifier_inputs");
  for (const [field, digest] of Object.entries(inputs)) {
    expectSha256(digest, `verifier_${field}`);
  }

  const checks = verifyChecks(record.checks);
  const metrics = verifyMetrics(record.metrics);

  if (!new Set(["passed", "failed", "inconclusive"]).has(record.verdict)
    || !FAILURE_CLASSES.has(record.failure_class)) fail("verdict_invalid");
  if ((record.verdict === "passed" && record.failure_class !== "none")
    || (record.verdict === "failed" && record.failure_class !== "product")
    || (record.verdict === "inconclusive"
      && (record.failure_class === "none" || record.failure_class === "product"))) {
    fail("verdict_failure_class_mismatch");
  }
  if (record.verdict === "passed") verifyPassedVerdict(checks, metrics);

  const mapping = expectExactRecord(
    record.runtime_outcome_mapping,
    ["outcome", "outcome_code"],
    "runtime_outcome_mapping",
  );
  expectText(mapping.outcome_code, "runtime_outcome_code");
  const expectedOutcome = record.verdict === "passed"
    ? "succeeded"
    : record.verdict === "failed"
      ? "failed"
      : "unknown";
  if (mapping.outcome !== expectedOutcome) fail("runtime_outcome_mapping_invalid");
  return canonicalClone(record);
}

function normalizeBuildInput(input, verifierPrincipalSha256) {
  const record = expectExactRecord(input, BUILD_INPUT_KEYS, "verifier_evidence_input");
  const authority = expectExactRecord(
    record.verifier_authority_ref,
    VERIFIER_AUTHORITY_INPUT_KEYS,
    "verifier_authority_input",
  );
  const temporalFence = expectExactRecord(
    record.temporal_fence,
    TEMPORAL_FENCE_INPUT_KEYS,
    "verifier_temporal_fence_input",
  );
  return {
    ...record,
    schema_version: SCHEMA_VERSION,
    temporal_fence: {
      ...temporalFence,
      verifier_runner_authority_principal_sha256: verifierPrincipalSha256,
    },
    verifier_authority_ref: {
      ...authority,
      public_key_principal_sha256: verifierPrincipalSha256,
    },
  };
}

export function buildSignedVerifierEvidenceV1(input, privateKeyInput) {
  const privateKey = asPrivateKey(privateKeyInput);
  const publicKey = createPublicKey(privateKey);
  const expectedPrincipal = principalSha256(publicKey);
  const body = verifyBody(normalizeBuildInput(input, expectedPrincipal));
  const evidenceSha256 = canonicalSha256(body);
  const signature = sign(
    null,
    Buffer.from(signaturePayload(evidenceSha256, expectedPrincipal), "utf8"),
    privateKey,
  ).toString("base64url");
  return verifySignedVerifierEvidenceV1(canonicalClone({
    ...body,
    evidence_sha256: evidenceSha256,
    signature_algorithm: "ed25519",
    signature,
  }), publicKey);
}

export function verifySignedVerifierEvidenceV1(value, publicKeyInput) {
  const record = expectExactRecord(value, EVIDENCE_KEYS, "verifier_evidence");
  const unverifiedBody = Object.fromEntries(
    Object.entries(record).filter(([key]) => ![
      "evidence_sha256", "signature", "signature_algorithm",
    ].includes(key)),
  );
  expectSha256(record.evidence_sha256, "evidence_sha256");
  if (canonicalSha256(unverifiedBody) !== record.evidence_sha256) {
    fail("evidence_integrity_invalid");
  }
  const body = verifyBody(unverifiedBody);
  if (record.signature_algorithm !== "ed25519"
    || typeof record.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/u.test(record.signature)) {
    fail("signature_invalid");
  }
  const publicKey = asPublicKey(publicKeyInput);
  const verifierPrincipalSha256 = body.verifier_authority_ref.public_key_principal_sha256;
  if (principalSha256(publicKey) !== verifierPrincipalSha256) fail("public_key_invalid");
  let signature;
  try {
    signature = Buffer.from(record.signature, "base64url");
  } catch {
    fail("signature_invalid");
  }
  if (signature.length !== 64 || !verify(
    null,
    Buffer.from(signaturePayload(record.evidence_sha256, verifierPrincipalSha256), "utf8"),
    publicKey,
    signature,
  )) {
    fail("signature_invalid");
  }
  return canonicalClone(record);
}
