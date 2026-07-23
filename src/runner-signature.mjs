import path from "node:path";
import { lstatSync, realpathSync } from "node:fs";
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
  expectPositiveInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { verifyPilotPlanV1 } from "./pilot-contract.mjs";
import { verifyResourceCleanupReceiptV1 } from "./pilot-run-event-contract.mjs";

const SCHEMA_VERSION = "aionis_pilot_runner_execution_authorization_v1";
const SIGNATURE_PAYLOAD_SCHEMA_VERSION =
  "aionis_pilot_runner_execution_authorization_signature_payload_v1";

const RUNNER_TRANSPORT_AUTHORITY_SCHEMA_VERSION =
  "aionis_pilot_runner_transport_authority_v1";

export const RELEASE_RUNNER_TRANSPORT_AUTHORITY_V1 = Object.freeze({
  schema_version: RUNNER_TRANSPORT_AUTHORITY_SCHEMA_VERSION,
  authority_class: "release_platform_transport_v1",
  authority_marker: "aionis_release_platform_transport_and_clock_v1",
  claim_eligible: true,
  provider_transport: "node_platform_global_fetch_captured_at_module_load",
  clock_source: "node_platform_date_clock_captured_at_module_load",
  dependency_injection_policy: "forbidden",
});

export const NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1 = Object.freeze({
  schema_version: RUNNER_TRANSPORT_AUTHORITY_SCHEMA_VERSION,
  authority_class: "non_release_contract_test_transport_v1",
  authority_marker: "aionis_non_release_contract_test_transport_do_not_use_for_claims_v1",
  claim_eligible: false,
  provider_transport: "caller_injected_contract_test_transport",
  clock_source: "caller_injected_contract_test_clock",
  dependency_injection_policy: "required_non_release_contract_test_only",
});

const BUILD_INPUT_KEYS = Object.freeze([
  "executionManifest",
  "fixedLedgerAuthorityRoot",
  "issuedAt",
  "plan",
]);

const VERIFY_CONTEXT_KEYS = Object.freeze([
  ...BUILD_INPUT_KEYS.filter((key) => key !== "issuedAt"),
  "publicKey",
]);

const BODY_KEYS = Object.freeze([
  "claim_eligible",
  "execution_manifest_sha256",
  "fixed_ledger_authority_root",
  "issued_at",
  "ledger_authority_root_identity",
  "pilot_id",
  "plan_sha256",
  "runner_authority_public_key_principal_sha256",
  "runner_transport_authority",
  "schema_version",
]);

const AUTHORIZATION_KEYS = Object.freeze([
  ...BODY_KEYS,
  "execution_authorization_sha256",
  "signature",
  "signature_algorithm",
]);

const EXECUTION_MANIFEST_KEYS = Object.freeze([
  "artifact_report_sha256",
  "case_authority_set_sha256",
  "cell_authority_set_sha256",
  "cell_count",
  "cohort_installed",
  "eval_binding_sha256",
  "eval_repository_provenance_sha256",
  "evidence_authority_class",
  "manifest_report_sha256",
  "oci_runtime_authority_sha256",
  "pilot_id",
  "plan_sha256",
  "provider_authority_sha256",
  "provider_request_attempt_limit",
  "runtime_binding_sha256",
  "runner_authority",
  "schema_version",
  "status",
]);

function fail(code) {
  throw new Error(`aionis_eval_runner_signature_${code}`);
}

function asPrivateKey(value) {
  let key;
  try {
    key = value instanceof KeyObject ? value : createPrivateKey(value);
  } catch {
    fail("private_key_invalid");
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    fail("private_key_invalid");
  }
  return key;
}

function asPublicKey(value) {
  let key;
  try {
    key = value instanceof KeyObject
      ? (value.type === "public" ? value : createPublicKey(value))
      : createPublicKey(value);
  } catch {
    fail("public_key_invalid");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    fail("public_key_invalid");
  }
  return key;
}

function principalSha256(publicKeyInput) {
  const der = asPublicKey(publicKeyInput).export({ format: "der", type: "spki" });
  return sha256Bytes(der);
}

export function runnerAuthorityPublicKeyPrincipalSha256V1(publicKeyInput) {
  return principalSha256(publicKeyInput);
}

function verifyFixedLedgerAuthorityRoot(value) {
  const root = expectText(value, "runner_fixed_ledger_authority_root", {
    maximumBytes: 16_384,
  });
  if (!path.isAbsolute(root) || path.normalize(root) !== root) {
    fail("fixed_ledger_authority_root_invalid");
  }
  return root;
}

function liveLedgerAuthorityRootIdentity(rootValue) {
  const root = verifyFixedLedgerAuthorityRoot(rootValue);
  let resolved;
  let metadata;
  try {
    resolved = realpathSync(root);
    metadata = lstatSync(root);
  } catch {
    fail("fixed_ledger_authority_root_missing");
  }
  if (resolved !== root || !metadata.isDirectory() || metadata.isSymbolicLink()
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    fail("fixed_ledger_authority_root_unsafe");
  }
  return canonicalClone({
    realpath_sha256: sha256Bytes(Buffer.from(resolved, "utf8")),
    device_id: String(metadata.dev),
    inode: String(metadata.ino),
  });
}

function verifyLedgerAuthorityRootIdentity(value, root) {
  const identity = expectExactRecord(value, [
    "device_id", "inode", "realpath_sha256",
  ], "runner_ledger_authority_root_identity");
  for (const field of ["device_id", "inode"]) {
    if (typeof identity[field] !== "string" || !/^\d+$/u.test(identity[field])) {
      fail("ledger_authority_root_identity_invalid");
    }
  }
  expectSha256(identity.realpath_sha256, "runner_ledger_authority_root_realpath_sha256");
  if (canonicalJson(identity) !== canonicalJson(liveLedgerAuthorityRootIdentity(root))) {
    fail("ledger_authority_root_identity_live_mismatch");
  }
  return identity;
}

function verifyExecutionManifest(value, plan) {
  const manifest = expectExactRecord(
    value,
    EXECUTION_MANIFEST_KEYS,
    "runner_execution_manifest",
  );
  if (manifest.schema_version !== "aionis_pilot_execution_manifest_report_v1"
    || manifest.status !== "execution_manifest_verified"
    || !new Set([
      "release_authority_v1",
      "non_release_contract_test_authority_v1",
    ]).has(manifest.evidence_authority_class)) {
    fail("execution_manifest_invalid");
  }
  expectText(manifest.pilot_id, "runner_execution_manifest_pilot_id");
  for (const field of [
    "plan_sha256",
    "artifact_report_sha256",
    "eval_binding_sha256",
    "eval_repository_provenance_sha256",
    "runtime_binding_sha256",
    "provider_authority_sha256",
    "oci_runtime_authority_sha256",
    "case_authority_set_sha256",
    "cell_authority_set_sha256",
    "manifest_report_sha256",
  ]) {
    expectSha256(manifest[field], `runner_execution_manifest_${field}`);
  }
  expectPositiveInteger(manifest.cell_count, "runner_execution_manifest_cell_count");
  expectPositiveInteger(
    manifest.provider_request_attempt_limit,
    "runner_execution_manifest_provider_request_attempt_limit",
  );
  if (typeof manifest.cohort_installed !== "boolean") {
    fail("execution_manifest_cohort_invalid");
  }
  const manifestBody = Object.fromEntries(
    Object.entries(manifest).filter(([key]) => key !== "manifest_report_sha256"),
  );
  if (canonicalSha256(manifestBody) !== manifest.manifest_report_sha256) {
    fail("execution_manifest_integrity_invalid");
  }
  if (manifest.pilot_id !== plan.pilot_id
    || manifest.plan_sha256 !== plan.plan_sha256
    || manifest.cell_count !== plan.schedule.length
    || manifest.provider_request_attempt_limit
      !== plan.model_protocol.maximum_provider_request_attempt_count
    || manifest.cohort_installed !== plan.runtime_binding.cohort_installed
    || manifest.eval_repository_provenance_sha256
      !== manifest.runner_authority?.eval_repository_provenance?.provenance_sha256) {
    fail("execution_manifest_plan_binding_invalid");
  }
  return canonicalClone(manifest);
}

function verifyRunnerTransportAuthority(value) {
  const authority = expectExactRecord(value, [
    "authority_class",
    "authority_marker",
    "claim_eligible",
    "clock_source",
    "dependency_injection_policy",
    "provider_transport",
    "schema_version",
  ], "runner_transport_authority");
  const knownAuthorities = [
    RELEASE_RUNNER_TRANSPORT_AUTHORITY_V1,
    NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1,
  ];
  if (!knownAuthorities.some((expected) =>
    canonicalJson(authority) === canonicalJson(expected))) {
    fail("runner_transport_authority_invalid");
  }
  return canonicalClone(authority);
}

function signaturePayload(executionAuthorizationSha256, runnerPrincipalSha256) {
  return canonicalJson({
    schema_version: SIGNATURE_PAYLOAD_SCHEMA_VERSION,
    execution_authorization_sha256: executionAuthorizationSha256,
    runner_authority_public_key_principal_sha256: runnerPrincipalSha256,
  });
}

function verifyBody(value, { executionManifest, fixedLedgerAuthorityRoot, plan }) {
  const body = expectExactRecord(value, BODY_KEYS, "runner_execution_authorization_body");
  if (body.schema_version !== SCHEMA_VERSION) fail("schema_invalid");
  const runnerTransportAuthority = verifyRunnerTransportAuthority(
    body.runner_transport_authority,
  );
  if (body.claim_eligible !== runnerTransportAuthority.claim_eligible) {
    fail("runner_transport_claim_binding_invalid");
  }
  const expectedEvidenceAuthorityClass = runnerTransportAuthority.claim_eligible
    ? "release_authority_v1"
    : "non_release_contract_test_authority_v1";
  if (executionManifest.evidence_authority_class !== expectedEvidenceAuthorityClass) {
    fail("runner_transport_manifest_authority_mismatch");
  }
  expectText(body.pilot_id, "runner_authorization_pilot_id");
  expectSha256(body.plan_sha256, "runner_authorization_plan_sha256");
  expectSha256(
    body.runner_authority_public_key_principal_sha256,
    "runner_authorization_public_key_principal_sha256",
  );
  expectSha256(
    body.execution_manifest_sha256,
    "runner_authorization_execution_manifest_sha256",
  );
  const root = verifyFixedLedgerAuthorityRoot(body.fixed_ledger_authority_root);
  verifyLedgerAuthorityRootIdentity(body.ledger_authority_root_identity, root);
  expectCanonicalTimestamp(body.issued_at, "runner_authorization_issued_at");

  if (body.pilot_id !== plan.pilot_id || body.plan_sha256 !== plan.plan_sha256) {
    fail("plan_binding_invalid");
  }
  if (body.runner_authority_public_key_principal_sha256
    !== plan.eval_binding.runner_authority_public_key_principal_sha256) {
    fail("runner_principal_plan_binding_invalid");
  }
  if (body.execution_manifest_sha256 !== executionManifest.manifest_report_sha256) {
    fail("execution_manifest_binding_invalid");
  }
  if (root !== fixedLedgerAuthorityRoot) fail("fixed_ledger_authority_root_binding_invalid");
  return canonicalClone(body);
}

function buildSignedRunnerExecutionAuthorization(input, privateKeyInput, transportAuthority) {
  const record = expectExactRecord(input, BUILD_INPUT_KEYS, "runner_signature_input");
  const plan = verifyPilotPlanV1(record.plan);
  const executionManifest = verifyExecutionManifest(record.executionManifest, plan);
  const fixedLedgerAuthorityRoot = verifyFixedLedgerAuthorityRoot(
    record.fixedLedgerAuthorityRoot,
  );
  const ledgerAuthorityRootIdentity = liveLedgerAuthorityRootIdentity(
    fixedLedgerAuthorityRoot,
  );
  expectCanonicalTimestamp(record.issuedAt, "runner_authorization_issued_at");

  const privateKey = asPrivateKey(privateKeyInput);
  const publicKey = createPublicKey(privateKey);
  const runnerPrincipalSha256 = principalSha256(publicKey);
  if (runnerPrincipalSha256
    !== plan.eval_binding.runner_authority_public_key_principal_sha256) {
    fail("runner_principal_plan_binding_invalid");
  }

  const body = canonicalClone({
    schema_version: SCHEMA_VERSION,
    claim_eligible: transportAuthority.claim_eligible,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    runner_authority_public_key_principal_sha256: runnerPrincipalSha256,
    execution_manifest_sha256: executionManifest.manifest_report_sha256,
    fixed_ledger_authority_root: fixedLedgerAuthorityRoot,
    ledger_authority_root_identity: ledgerAuthorityRootIdentity,
    runner_transport_authority: transportAuthority,
    issued_at: record.issuedAt,
  });
  const executionAuthorizationSha256 = canonicalSha256(body);
  const signature = sign(
    null,
    Buffer.from(signaturePayload(
      executionAuthorizationSha256,
      runnerPrincipalSha256,
    ), "utf8"),
    privateKey,
  ).toString("base64url");

  return verifySignedRunnerExecutionAuthorizationV1(canonicalClone({
    ...body,
    execution_authorization_sha256: executionAuthorizationSha256,
    signature_algorithm: "ed25519",
    signature,
  }), {
    plan,
    executionManifest,
    fixedLedgerAuthorityRoot,
    publicKey,
  });
}

export function buildSignedRunnerExecutionAuthorizationV1(input, privateKeyInput) {
  return buildSignedRunnerExecutionAuthorization(
    input,
    privateKeyInput,
    RELEASE_RUNNER_TRANSPORT_AUTHORITY_V1,
  );
}

export function buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1(
  input,
  privateKeyInput,
) {
  return buildSignedRunnerExecutionAuthorization(
    input,
    privateKeyInput,
    NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1,
  );
}

export function verifySignedRunnerExecutionAuthorizationV1(value, context) {
  const binding = expectExactRecord(
    context,
    VERIFY_CONTEXT_KEYS,
    "runner_signature_verification_context",
  );
  const plan = verifyPilotPlanV1(binding.plan);
  const executionManifest = verifyExecutionManifest(binding.executionManifest, plan);
  const fixedLedgerAuthorityRoot = verifyFixedLedgerAuthorityRoot(
    binding.fixedLedgerAuthorityRoot,
  );
  const record = expectExactRecord(
    value,
    AUTHORIZATION_KEYS,
    "runner_execution_authorization",
  );
  const unverifiedBody = Object.fromEntries(
    Object.entries(record).filter(([key]) => ![
      "execution_authorization_sha256",
      "signature",
      "signature_algorithm",
    ].includes(key)),
  );
  expectSha256(
    record.execution_authorization_sha256,
    "runner_execution_authorization_sha256",
  );
  if (canonicalSha256(unverifiedBody) !== record.execution_authorization_sha256) {
    fail("execution_authorization_integrity_invalid");
  }
  const body = verifyBody(unverifiedBody, {
    executionManifest,
    fixedLedgerAuthorityRoot,
    plan,
  });
  if (record.signature_algorithm !== "ed25519"
    || typeof record.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/u.test(record.signature)) {
    fail("signature_invalid");
  }

  const publicKey = asPublicKey(binding.publicKey);
  const runnerPrincipalSha256 = principalSha256(publicKey);
  if (runnerPrincipalSha256
    !== plan.eval_binding.runner_authority_public_key_principal_sha256
    || runnerPrincipalSha256
      !== body.runner_authority_public_key_principal_sha256) {
    fail("public_key_invalid");
  }
  let signature;
  try {
    signature = Buffer.from(record.signature, "base64url");
  } catch {
    fail("signature_invalid");
  }
  if (signature.length !== 64 || !verify(
    null,
    Buffer.from(signaturePayload(
      record.execution_authorization_sha256,
      runnerPrincipalSha256,
    ), "utf8"),
    publicKey,
    signature,
  )) {
    fail("signature_invalid");
  }
  return canonicalClone(record);
}

const FINAL_SCHEMA_VERSION = "aionis_pilot_runner_final_manifest_v1";
const FINAL_SIGNATURE_PAYLOAD_SCHEMA_VERSION =
  "aionis_pilot_runner_final_manifest_signature_payload_v1";
const ABORT_SCHEMA_VERSION = "aionis_pilot_runner_abort_manifest_v1";
const ABORT_SIGNATURE_PAYLOAD_SCHEMA_VERSION =
  "aionis_pilot_runner_abort_manifest_signature_payload_v1";

const ABORT_FAILURE_STAGES = new Set([
  "ledger",
  "cell_preparation",
  "provider",
  "provider_completion",
  "agent_execution",
  "verifier",
  "runtime_settlement",
  "cell_result",
  "scoring",
  "verdict",
  "run_close",
  "eval_provenance",
  "final_signer",
  "final_manifest_persist",
  "resource_cleanup",
  "harness",
]);

const ABORT_FAILURE_CLASSES = new Set([
  "provider_or_network",
  "harness_infrastructure",
  "filesystem_infrastructure",
  "runtime_infrastructure",
  "verifier_infrastructure",
  "signature_infrastructure",
  "resource_cleanup_infrastructure",
  "provenance_invalid",
]);

const ACTIVE_PROVIDER_ATTEMPT_STATES = new Set([
  "no_active_attempt",
  "prepared_not_reserved",
  "request_may_have_started_burned",
  "provider_completed_pending_cell_result",
]);

function verifyClosedLedgerSnapshot(
  value,
  plan,
  executionAuthorization,
  executionManifest,
  verdict,
) {
  const snapshot = expectExactRecord(value, [
    "active_attempt_ordinal",
    "closed",
    "completed_cell_count",
    "event_chain_head_sha256",
    "event_count",
    "execution_authorization_sha256",
    "next_attempt_ordinal",
    "pilot_id",
    "plan_sha256",
    "restart_policy",
    "run_started_event_sha256",
    "schema_version",
    "verdict_sha256",
  ], "runner_final_ledger_snapshot");
  if (snapshot.schema_version !== "aionis_pilot_run_ledger_snapshot_v1"
    || snapshot.pilot_id !== plan.pilot_id
    || snapshot.plan_sha256 !== plan.plan_sha256
    || snapshot.execution_authorization_sha256
      !== executionAuthorization.execution_authorization_sha256
    || snapshot.completed_cell_count !== plan.schedule.length
    || snapshot.next_attempt_ordinal !== plan.schedule.length + 1
    || snapshot.active_attempt_ordinal !== null
    || snapshot.verdict_sha256 !== verdict.verdict_sha256
    || snapshot.closed !== true
    || snapshot.restart_policy
      !== "forbid_same_pilot_id_within_signed_authority_root") {
    fail("final_ledger_snapshot_invalid");
  }
  expectPositiveInteger(snapshot.event_count, "runner_final_event_count");
  if (executionManifest.evidence_authority_class === "release_authority_v1"
    && snapshot.event_count !== 58) {
    fail("final_release_event_count_invalid");
  }
  expectSha256(snapshot.event_chain_head_sha256, "runner_final_event_chain_head_sha256");
  expectSha256(snapshot.run_started_event_sha256, "runner_final_run_started_event_sha256");
  return snapshot;
}

function verifyClosedRun(value, plan, executionAuthorization, snapshot, verdict) {
  const closure = expectExactRecord(value, [
    "cleanup_receipt_sha256",
    "counts",
    "execution_authorization_sha256",
    "pilot_id",
    "plan_sha256",
    "run_closed_event_sha256",
    "schema_version",
    "state",
    "verdict_sha256",
  ], "runner_final_run_closure");
  const counts = expectExactRecord(closure.counts, [
    "cell_result_count",
    "provider_attempt_count",
    "runtime_observation_count",
    "treatment_ledger_closed_count",
  ], "runner_final_run_counts");
  for (const [field, expected] of Object.entries({
    provider_attempt_count: 9,
    cell_result_count: 9,
    runtime_observation_count: 6,
    treatment_ledger_closed_count: 3,
  })) {
    expectNonNegativeInteger(counts[field], `runner_final_${field}`);
    if (counts[field] !== expected) fail("final_run_count_invalid");
  }
  if (closure.schema_version !== "aionis_pilot_run_closed_v1"
    || closure.state !== "closed_pending_runner_seal"
    || closure.pilot_id !== plan.pilot_id
    || closure.plan_sha256 !== plan.plan_sha256
    || closure.execution_authorization_sha256
      !== executionAuthorization.execution_authorization_sha256
    || closure.verdict_sha256 !== verdict.verdict_sha256
    || closure.run_closed_event_sha256 !== snapshot.event_chain_head_sha256) {
    fail("final_run_closure_invalid");
  }
  expectSha256(closure.run_closed_event_sha256, "runner_final_run_closed_event_sha256");
  expectSha256(closure.cleanup_receipt_sha256, "runner_final_cleanup_receipt_sha256");
  return closure;
}

function verifyFinalVerdict(value, plan) {
  const verdict = value;
  if (verdict === null || typeof verdict !== "object" || Array.isArray(verdict)
    || verdict.pilot_id !== plan.pilot_id || verdict.plan_sha256 !== plan.plan_sha256
    || !new Set(["promote", "reject"]).has(verdict.verdict)) {
    fail("final_verdict_invalid");
  }
  expectSha256(verdict.verdict_sha256, "runner_final_verdict_sha256");
  const body = Object.fromEntries(
    Object.entries(verdict).filter(([key]) => key !== "verdict_sha256"),
  );
  if (canonicalSha256(body) !== verdict.verdict_sha256) fail("final_verdict_integrity_invalid");
  return verdict;
}

function verifyAbortCellRef(value, plan, field) {
  if (value === null) return null;
  const cellRef = expectExactRecord(value, [
    "cell_sha256", "opaque_cell_id", "ordinal",
  ], field);
  expectPositiveInteger(cellRef.ordinal, `${field}_ordinal`);
  expectSha256(cellRef.cell_sha256, `${field}_cell_sha256`);
  if (cellRef.ordinal > plan.schedule.length) fail(`${field}_ordinal_invalid`);
  const cell = plan.schedule[cellRef.ordinal - 1];
  if (cellRef.opaque_cell_id !== cell.opaque_cell_id
    || cellRef.cell_sha256 !== canonicalSha256(cell)) {
    fail(`${field}_plan_binding_invalid`);
  }
  return canonicalClone(cellRef);
}

function verifyRunAbort(value, plan, executionAuthorization, snapshot) {
  const abort = expectExactRecord(value, [
    "active_attempt_ordinal",
    "active_provider_attempt_state",
    "cleanup_confirmed",
    "cleanup_receipt",
    "cleanup_receipt_sha256",
    "completed_cell_count",
    "execution_authorization_sha256",
    "failing_cell_ref",
    "failure_class",
    "failure_evidence_ref_sha256",
    "failure_stage",
    "next_attempt_ordinal",
    "pilot_id",
    "plan_sha256",
    "provider_attempt_completion_count",
    "provider_attempt_reservation_count",
    "run_aborted_event_sha256",
    "schema_version",
    "state",
  ], "runner_abort_run_closure");
  const activeCell = verifyAbortCellRef(
    abort.failing_cell_ref,
    plan,
    "runner_abort_failing_cell_ref",
  );
  const cleanupReceipt = verifyResourceCleanupReceiptV1(abort.cleanup_receipt, {
    ownerKinds: executionAuthorization.claim_eligible === true
      ? ["runtime_owner", "workspace_owner"]
      : [],
    resourceCount: plan.schedule.length,
  });
  for (const field of [
    "completed_cell_count",
    "provider_attempt_reservation_count",
    "provider_attempt_completion_count",
  ]) {
    expectNonNegativeInteger(abort[field], `runner_abort_${field}`);
    if (abort[field] > plan.schedule.length) fail("abort_count_invalid");
  }
  if (abort.active_attempt_ordinal !== null) {
    expectPositiveInteger(abort.active_attempt_ordinal, "runner_abort_active_attempt_ordinal");
    if (abort.active_attempt_ordinal > plan.schedule.length) {
      fail("abort_active_attempt_ordinal_invalid");
    }
  }
  expectPositiveInteger(abort.next_attempt_ordinal, "runner_abort_next_attempt_ordinal");
  expectSha256(abort.failure_evidence_ref_sha256, "runner_abort_failure_evidence_ref_sha256");
  expectSha256(abort.cleanup_receipt_sha256, "runner_abort_cleanup_receipt_sha256");
  expectSha256(abort.run_aborted_event_sha256, "runner_abort_event_sha256");
  if (abort.schema_version !== "aionis_pilot_run_aborted_v1"
    || abort.state !== "aborted_claim_ineligible_no_resume"
    || abort.pilot_id !== plan.pilot_id
    || abort.plan_sha256 !== plan.plan_sha256
    || abort.execution_authorization_sha256
      !== executionAuthorization.execution_authorization_sha256
    || !ABORT_FAILURE_STAGES.has(abort.failure_stage)
    || !ABORT_FAILURE_CLASSES.has(abort.failure_class)
    || !ACTIVE_PROVIDER_ATTEMPT_STATES.has(abort.active_provider_attempt_state)
    || abort.cleanup_receipt_sha256 !== cleanupReceipt.cleanup_receipt_sha256
    || abort.cleanup_confirmed !== cleanupReceipt.cleanup_confirmed
    || abort.completed_cell_count !== snapshot.completed_cell_count
    || abort.next_attempt_ordinal !== snapshot.next_attempt_ordinal
    || abort.active_attempt_ordinal !== snapshot.active_attempt_ordinal
    || abort.run_aborted_event_sha256 !== snapshot.event_chain_head_sha256) {
    fail("abort_run_binding_invalid");
  }
  if (abort.completed_cell_count > abort.provider_attempt_completion_count
    || abort.provider_attempt_completion_count > abort.provider_attempt_reservation_count
    || abort.next_attempt_ordinal !== abort.completed_cell_count + 1) {
    fail("abort_run_count_invalid");
  }
  const activeExpected = abort.active_provider_attempt_state !== "no_active_attempt";
  if (activeExpected !== (abort.active_attempt_ordinal !== null)) {
    fail("abort_active_attempt_state_invalid");
  }
  if (activeCell === null && activeExpected) fail("abort_failing_cell_required");
  if (activeCell !== null && activeExpected
    && activeCell.ordinal !== abort.active_attempt_ordinal) {
    fail("abort_failing_cell_active_binding_invalid");
  }
  if (abort.active_provider_attempt_state === "prepared_not_reserved"
    && (abort.provider_attempt_reservation_count !== abort.completed_cell_count
      || abort.provider_attempt_completion_count !== abort.completed_cell_count)) {
    fail("abort_prepared_count_invalid");
  }
  if (abort.active_provider_attempt_state === "request_may_have_started_burned"
    && (abort.provider_attempt_reservation_count !== abort.completed_cell_count + 1
      || abort.provider_attempt_completion_count !== abort.completed_cell_count)) {
    fail("abort_burned_count_invalid");
  }
  if (abort.active_provider_attempt_state === "provider_completed_pending_cell_result"
    && (abort.provider_attempt_reservation_count !== abort.completed_cell_count + 1
      || abort.provider_attempt_completion_count !== abort.completed_cell_count + 1)) {
    fail("abort_completed_pending_count_invalid");
  }
  if (abort.active_provider_attempt_state === "no_active_attempt"
    && (abort.provider_attempt_reservation_count !== abort.completed_cell_count
      || abort.provider_attempt_completion_count !== abort.completed_cell_count)) {
    fail("abort_no_active_count_invalid");
  }
  return canonicalClone({ ...abort, cleanup_receipt: cleanupReceipt });
}

function verifyAbortedLedgerSnapshot(value, plan, executionAuthorization) {
  const snapshot = expectExactRecord(value, [
    "active_attempt_ordinal",
    "closed",
    "completed_cell_count",
    "event_chain_head_sha256",
    "event_count",
    "execution_authorization_sha256",
    "next_attempt_ordinal",
    "pilot_id",
    "plan_sha256",
    "restart_policy",
    "run_started_event_sha256",
    "schema_version",
    "verdict_sha256",
  ], "runner_abort_ledger_snapshot");
  if (snapshot.schema_version !== "aionis_pilot_run_ledger_snapshot_v1"
    || snapshot.pilot_id !== plan.pilot_id
    || snapshot.plan_sha256 !== plan.plan_sha256
    || snapshot.execution_authorization_sha256
      !== executionAuthorization.execution_authorization_sha256
    || snapshot.closed !== true
    || snapshot.restart_policy
      !== "forbid_same_pilot_id_within_signed_authority_root") {
    fail("abort_ledger_snapshot_invalid");
  }
  expectPositiveInteger(snapshot.event_count, "runner_abort_event_count");
  expectSha256(snapshot.event_chain_head_sha256, "runner_abort_event_chain_head_sha256");
  expectSha256(snapshot.run_started_event_sha256, "runner_abort_run_started_event_sha256");
  expectNonNegativeInteger(snapshot.completed_cell_count, "runner_abort_completed_cell_count");
  expectPositiveInteger(snapshot.next_attempt_ordinal, "runner_abort_next_attempt_ordinal");
  if (snapshot.verdict_sha256 !== null) {
    expectSha256(snapshot.verdict_sha256, "runner_abort_verdict_sha256");
  }
  if (snapshot.completed_cell_count > plan.schedule.length
    || snapshot.next_attempt_ordinal !== snapshot.completed_cell_count + 1
    || snapshot.next_attempt_ordinal > plan.schedule.length + 1) {
    fail("abort_ledger_progress_invalid");
  }
  if (snapshot.active_attempt_ordinal !== null) {
    expectPositiveInteger(snapshot.active_attempt_ordinal, "runner_abort_active_attempt_ordinal");
    if (snapshot.active_attempt_ordinal !== snapshot.next_attempt_ordinal
      || snapshot.active_attempt_ordinal > plan.schedule.length) {
      fail("abort_ledger_active_attempt_invalid");
    }
  }
  return canonicalClone(snapshot);
}

function finalSignaturePayload(manifestSha256, principal) {
  return canonicalJson({
    schema_version: FINAL_SIGNATURE_PAYLOAD_SCHEMA_VERSION,
    final_manifest_sha256: manifestSha256,
    runner_authority_public_key_principal_sha256: principal,
  });
}

function finalManifestBody(input, runnerPrincipal) {
  return canonicalClone({
    schema_version: FINAL_SCHEMA_VERSION,
    status: "completed",
    claim_eligible:
      input.executionAuthorization.claim_eligible === true
      && input.executionManifest.evidence_authority_class === "release_authority_v1"
      && input.verdict.verdict === "promote",
    evidence_authority_class: input.executionManifest.evidence_authority_class,
    pilot_id: input.plan.pilot_id,
    plan_sha256: input.plan.plan_sha256,
    execution_authorization_sha256:
      input.executionAuthorization.execution_authorization_sha256,
    execution_manifest_sha256: input.executionManifest.manifest_report_sha256,
    runner_authority_public_key_principal_sha256: runnerPrincipal,
    runner_transport_authority: input.executionAuthorization.runner_transport_authority,
    run_started_event_sha256: input.ledgerSnapshot.run_started_event_sha256,
    event_count: input.ledgerSnapshot.event_count,
    event_chain_head_sha256: input.ledgerSnapshot.event_chain_head_sha256,
    run_closed_event_sha256: input.runClosure.run_closed_event_sha256,
    cleanup_receipt_sha256: input.runClosure.cleanup_receipt_sha256,
    provider_attempt_count: input.runClosure.counts.provider_attempt_count,
    cell_result_count: input.runClosure.counts.cell_result_count,
    runtime_observation_count: input.runClosure.counts.runtime_observation_count,
    treatment_ledger_closed_count:
      input.runClosure.counts.treatment_ledger_closed_count,
    verdict_sha256: input.verdict.verdict_sha256,
    sealed_at: input.sealedAt,
  });
}

function verifyFinalContext(input, publicKeyInput) {
  const plan = verifyPilotPlanV1(input.plan);
  const executionManifest = verifyExecutionManifest(input.executionManifest, plan);
  const publicKey = asPublicKey(publicKeyInput);
  const executionAuthorization = verifySignedRunnerExecutionAuthorizationV1(
    input.executionAuthorization,
    {
      plan,
      executionManifest,
      fixedLedgerAuthorityRoot: input.fixedLedgerAuthorityRoot,
      publicKey,
    },
  );
  const verdict = verifyFinalVerdict(input.verdict, plan);
  const ledgerSnapshot = verifyClosedLedgerSnapshot(
    input.ledgerSnapshot,
    plan,
    executionAuthorization,
    executionManifest,
    verdict,
  );
  const runClosure = verifyClosedRun(
    input.runClosure,
    plan,
    executionAuthorization,
    ledgerSnapshot,
    verdict,
  );
  expectCanonicalTimestamp(input.sealedAt, "runner_final_sealed_at");
  return {
    executionAuthorization,
    executionManifest,
    ledgerSnapshot,
    plan,
    publicKey,
    runClosure,
    verdict,
  };
}

export function verifySignedRunnerFinalManifestV1(value, contextValue) {
  const contextInput = expectExactRecord(contextValue, [
    "executionAuthorization",
    "executionManifest",
    "fixedLedgerAuthorityRoot",
    "ledgerSnapshot",
    "plan",
    "publicKey",
    "runClosure",
    "sealedAt",
    "verdict",
  ], "runner_final_manifest_verification_context");
  const context = verifyFinalContext(contextInput, contextInput.publicKey);
  const record = expectExactRecord(value, [
    "cell_result_count",
    "claim_eligible",
    "cleanup_receipt_sha256",
    "event_chain_head_sha256",
    "event_count",
    "evidence_authority_class",
    "execution_authorization_sha256",
    "execution_manifest_sha256",
    "final_manifest_sha256",
    "pilot_id",
    "plan_sha256",
    "provider_attempt_count",
    "run_closed_event_sha256",
    "run_started_event_sha256",
    "runner_authority_public_key_principal_sha256",
    "runner_transport_authority",
    "runtime_observation_count",
    "schema_version",
    "sealed_at",
    "signature",
    "signature_algorithm",
    "status",
    "treatment_ledger_closed_count",
    "verdict_sha256",
  ], "runner_final_manifest");
  const principal = principalSha256(context.publicKey);
  const expectedBody = finalManifestBody({ ...contextInput, ...context }, principal);
  const actualBody = Object.fromEntries(
    Object.entries(record).filter(([key]) => ![
      "final_manifest_sha256", "signature", "signature_algorithm",
    ].includes(key)),
  );
  if (canonicalJson(actualBody) !== canonicalJson(expectedBody)
    || record.final_manifest_sha256 !== canonicalSha256(expectedBody)
    || record.signature_algorithm !== "ed25519"
    || typeof record.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/u.test(record.signature)) {
    fail("final_manifest_binding_invalid");
  }
  const signatureBytes = Buffer.from(record.signature, "base64url");
  if (signatureBytes.length !== 64 || !verify(
    null,
    Buffer.from(finalSignaturePayload(record.final_manifest_sha256, principal), "utf8"),
    context.publicKey,
    signatureBytes,
  )) fail("final_manifest_signature_invalid");
  return canonicalClone(record);
}

function abortSignaturePayload(manifestSha256, principal) {
  return canonicalJson({
    schema_version: ABORT_SIGNATURE_PAYLOAD_SCHEMA_VERSION,
    abort_manifest_sha256: manifestSha256,
    runner_authority_public_key_principal_sha256: principal,
  });
}

function abortManifestBody(input, runnerPrincipal) {
  const abort = input.runAbort;
  return canonicalClone({
    schema_version: ABORT_SCHEMA_VERSION,
    status: "aborted",
    outcome: "aborted_inconclusive",
    claim_eligible: false,
    resumable: false,
    evidence_authority_class: input.executionManifest.evidence_authority_class,
    pilot_id: input.plan.pilot_id,
    plan_sha256: input.plan.plan_sha256,
    execution_authorization_sha256:
      input.executionAuthorization.execution_authorization_sha256,
    execution_manifest_sha256: input.executionManifest.manifest_report_sha256,
    runner_authority_public_key_principal_sha256: runnerPrincipal,
    runner_transport_authority: input.executionAuthorization.runner_transport_authority,
    run_started_event_sha256: input.ledgerSnapshot.run_started_event_sha256,
    event_count: input.ledgerSnapshot.event_count,
    event_chain_head_sha256: input.ledgerSnapshot.event_chain_head_sha256,
    run_aborted_event_sha256: abort.run_aborted_event_sha256,
    abort_payload_sha256: canonicalSha256(Object.fromEntries(
      Object.entries(abort).filter(([key]) => key !== "run_aborted_event_sha256"),
    )),
    failure_stage: abort.failure_stage,
    failure_class: abort.failure_class,
    failure_evidence_ref_sha256: abort.failure_evidence_ref_sha256,
    failing_cell_ref: abort.failing_cell_ref,
    completed_cell_count: abort.completed_cell_count,
    next_attempt_ordinal: abort.next_attempt_ordinal,
    active_attempt_ordinal: abort.active_attempt_ordinal,
    active_provider_attempt_state: abort.active_provider_attempt_state,
    provider_attempt_reservation_count: abort.provider_attempt_reservation_count,
    provider_attempt_completion_count: abort.provider_attempt_completion_count,
    cleanup_receipt_sha256: abort.cleanup_receipt_sha256,
    cleanup_confirmed: abort.cleanup_confirmed,
    pre_abort_verdict_sha256: input.ledgerSnapshot.verdict_sha256,
    sealed_at: input.sealedAt,
  });
}

function verifyAbortContext(input, publicKeyInput) {
  const plan = verifyPilotPlanV1(input.plan);
  const executionManifest = verifyExecutionManifest(input.executionManifest, plan);
  const publicKey = asPublicKey(publicKeyInput);
  const executionAuthorization = verifySignedRunnerExecutionAuthorizationV1(
    input.executionAuthorization,
    {
      plan,
      executionManifest,
      fixedLedgerAuthorityRoot: input.fixedLedgerAuthorityRoot,
      publicKey,
    },
  );
  const ledgerSnapshot = verifyAbortedLedgerSnapshot(
    input.ledgerSnapshot,
    plan,
    executionAuthorization,
  );
  const runAbort = verifyRunAbort(
    input.runAbort,
    plan,
    executionAuthorization,
    ledgerSnapshot,
  );
  expectCanonicalTimestamp(input.sealedAt, "runner_abort_sealed_at");
  return {
    executionAuthorization,
    executionManifest,
    ledgerSnapshot,
    plan,
    publicKey,
    runAbort,
  };
}

export function verifySignedRunnerAbortManifestV1(value, contextValue) {
  const contextInput = expectExactRecord(contextValue, [
    "executionAuthorization",
    "executionManifest",
    "fixedLedgerAuthorityRoot",
    "ledgerSnapshot",
    "plan",
    "publicKey",
    "runAbort",
    "sealedAt",
  ], "runner_abort_manifest_verification_context");
  const context = verifyAbortContext(contextInput, contextInput.publicKey);
  const record = expectExactRecord(value, [
    "abort_manifest_sha256",
    "abort_payload_sha256",
    "active_attempt_ordinal",
    "active_provider_attempt_state",
    "claim_eligible",
    "cleanup_confirmed",
    "cleanup_receipt_sha256",
    "completed_cell_count",
    "event_chain_head_sha256",
    "event_count",
    "evidence_authority_class",
    "execution_authorization_sha256",
    "execution_manifest_sha256",
    "failing_cell_ref",
    "failure_class",
    "failure_evidence_ref_sha256",
    "failure_stage",
    "next_attempt_ordinal",
    "outcome",
    "pilot_id",
    "plan_sha256",
    "pre_abort_verdict_sha256",
    "provider_attempt_completion_count",
    "provider_attempt_reservation_count",
    "resumable",
    "run_aborted_event_sha256",
    "run_started_event_sha256",
    "runner_authority_public_key_principal_sha256",
    "runner_transport_authority",
    "schema_version",
    "sealed_at",
    "signature",
    "signature_algorithm",
    "status",
  ], "runner_abort_manifest");
  const principal = principalSha256(context.publicKey);
  const expectedBody = abortManifestBody({ ...contextInput, ...context }, principal);
  const actualBody = Object.fromEntries(
    Object.entries(record).filter(([key]) => ![
      "abort_manifest_sha256", "signature", "signature_algorithm",
    ].includes(key)),
  );
  if (canonicalJson(actualBody) !== canonicalJson(expectedBody)
    || record.abort_manifest_sha256 !== canonicalSha256(expectedBody)
    || record.signature_algorithm !== "ed25519"
    || typeof record.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/u.test(record.signature)) {
    fail("abort_manifest_binding_invalid");
  }
  const signatureBytes = Buffer.from(record.signature, "base64url");
  if (signatureBytes.length !== 64 || !verify(
    null,
    Buffer.from(abortSignaturePayload(record.abort_manifest_sha256, principal), "utf8"),
    context.publicKey,
    signatureBytes,
  )) fail("abort_manifest_signature_invalid");
  return canonicalClone(record);
}

export function buildSignedRunnerAbortManifestForSignerV1(inputValue, privateKeyInput) {
  const input = expectExactRecord(inputValue, [
    "executionAuthorization",
    "executionManifest",
    "fixedLedgerAuthorityRoot",
    "ledgerSnapshot",
    "plan",
    "runAbort",
    "sealedAt",
  ], "runner_abort_manifest_signer_input");
  const privateKey = asPrivateKey(privateKeyInput);
  const publicKey = createPublicKey(privateKey);
  const context = verifyAbortContext(input, publicKey);
  const principal = principalSha256(publicKey);
  const body = abortManifestBody({ ...input, ...context }, principal);
  const abortManifestSha256 = canonicalSha256(body);
  const signature = sign(
    null,
    Buffer.from(abortSignaturePayload(abortManifestSha256, principal), "utf8"),
    privateKey,
  ).toString("base64url");
  return verifySignedRunnerAbortManifestV1(canonicalClone({
    ...body,
    abort_manifest_sha256: abortManifestSha256,
    signature_algorithm: "ed25519",
    signature,
  }), {
    ...input,
    publicKey,
  });
}
