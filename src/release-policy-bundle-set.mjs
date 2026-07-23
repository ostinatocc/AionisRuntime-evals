import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectPositiveInteger,
  expectSha256,
  expectText,
} from "./canonical.mjs";
import {
  cellPolicyBundleSetSha256V1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";

const SIGNED_ARTIFACT_KEYS = Object.freeze([
  "artifact_id",
  "artifact_kind",
  "artifact_revision",
  "artifact_schema",
  "artifact_sha256",
  "authority_subject_sha256",
  "created_at",
  "expires_at",
  "payload",
  "payload_sha256",
  "signature",
  "signature_algorithm",
  "signer_principal_sha256",
  "tenant_id",
  "trust_root_sha256",
  "valid_from",
]);

function fail(code) {
  throw new Error(`aionis_eval_release_policy_bundle_set_${code}`);
}

function artifactRef(value, field) {
  const ref = expectExactRecord(value, [
    "artifact_sha256", "payload_sha256",
  ], field);
  expectSha256(ref.artifact_sha256, `${field}_artifact_sha256`);
  expectSha256(ref.payload_sha256, `${field}_payload_sha256`);
  return canonicalClone(ref);
}

function verifySignedPolicyArtifact(value, expected, field) {
  const artifact = expectExactRecord(value, SIGNED_ARTIFACT_KEYS, field);
  expectText(artifact.artifact_id, `${field}_artifact_id`);
  expectPositiveInteger(artifact.artifact_revision, `${field}_artifact_revision`);
  if (artifact.artifact_kind !== expected.kind
    || artifact.artifact_schema !== expected.schema
    || artifact.tenant_id !== expected.tenantId
    || artifact.authority_subject_sha256 !== expected.authoritySubjectSha256
    || artifact.trust_root_sha256 !== expected.trustRootSha256
    || artifact.signature_algorithm !== "ed25519") {
    fail(`${field}_binding_invalid`);
  }
  for (const name of [
    "artifact_sha256", "payload_sha256", "signer_principal_sha256",
  ]) expectSha256(artifact[name], `${field}_${name}`);
  for (const name of ["created_at", "valid_from"]) {
    expectCanonicalTimestamp(artifact[name], `${field}_${name}`);
  }
  if (artifact.expires_at !== null) {
    expectCanonicalTimestamp(artifact.expires_at, `${field}_expires_at`);
  }
  if (typeof artifact.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/u.test(artifact.signature)
    || Buffer.from(artifact.signature, "base64url").length !== 64) {
    fail(`${field}_signature_invalid`);
  }
  const payload = artifact.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)
    || payload.tenant_id !== expected.tenantId
    || payload.authority_subject_sha256 !== expected.authoritySubjectSha256) {
    fail(`${field}_payload_binding_invalid`);
  }
  return artifact;
}

function verifyCommand(value, expected, field) {
  const command = expectExactRecord(value, [
    "actor_kind",
    "actor_principal_sha256",
    "authority_subject_sha256",
    "kind",
    "operation_id",
    "policy_bundle",
    "schema_version",
    "scope",
    "task_family",
    "tenant_id",
  ], field);
  if (command.schema_version !== "offline_provisioning_command_v1"
    || command.kind !== "policy_bundle_install"
    || command.actor_kind !== "operator"
    || command.tenant_id !== expected.tenantId
    || command.scope !== expected.runtimeScope
    || command.task_family !== expected.taskFamily
    || command.authority_subject_sha256 !== expected.authoritySubjectSha256) {
    fail(`${field}_binding_invalid`);
  }
  expectText(command.operation_id, `${field}_operation_id`);
  expectSha256(command.actor_principal_sha256, `${field}_actor_principal_sha256`);
  const bundle = expectExactRecord(command.policy_bundle, [
    "authority_subject_sha256",
    "compiler_policy",
    "evidence_policy",
    "schema_version",
    "tenant_id",
  ], `${field}_bundle`);
  if (bundle.schema_version !== "authority_policy_provisioning_bundle_v1"
    || bundle.tenant_id !== expected.tenantId
    || bundle.authority_subject_sha256 !== expected.authoritySubjectSha256) {
    fail(`${field}_bundle_binding_invalid`);
  }
  const compiler = verifySignedPolicyArtifact(bundle.compiler_policy, {
    ...expected,
    kind: "compiler_policy",
    schema: "continuation_compiler_policy_v1",
  }, `${field}_compiler_policy`);
  const evidence = verifySignedPolicyArtifact(bundle.evidence_policy, {
    ...expected,
    kind: "evidence_policy",
    schema: "effect_evidence_policy_v1",
  }, `${field}_evidence_policy`);
  const compilerRef = canonicalClone({
    artifact_sha256: compiler.artifact_sha256,
    payload_sha256: compiler.payload_sha256,
  });
  const evidenceRef = canonicalClone({
    artifact_sha256: evidence.artifact_sha256,
    payload_sha256: evidence.payload_sha256,
  });
  if (canonicalJson(compilerRef)
      !== canonicalJson(expected.compilerPolicyRef)
    || canonicalJson(evidenceRef)
      !== canonicalJson(expected.evidencePolicyRef)) {
    fail(`${field}_artifact_ref_invalid`);
  }
  return canonicalClone(command);
}

export function verifyReleaseCellPolicyBundleSetV1(options) {
  const input = expectExactRecord(options, [
    "plan", "policyBundleSet",
  ], "release_policy_bundle_set_input");
  const plan = verifyPilotPlanV1(input.plan);
  const value = expectExactRecord(input.policyBundleSet, [
    "bindings",
    "pilot_id",
    "policy_bundle_set_sha256",
    "schema_version",
    "task_family",
    "tenant_id",
    "trust_root_sha256",
  ], "release_policy_bundle_set");
  if (value.schema_version !== "aionis_pilot_cell_policy_bundle_set_v1"
    || value.pilot_id !== plan.pilot_id
    || value.tenant_id !== plan.runtime_binding.tenant_id
    || value.task_family !== plan.runtime_binding.task_family
    || value.trust_root_sha256 !== plan.runtime_binding.trust_root_sha256) {
    fail("header_binding_invalid");
  }
  expectSha256(value.policy_bundle_set_sha256, "release_policy_bundle_set_sha256");
  const bindings = expectArray(value.bindings, "release_policy_bundle_bindings", {
    minimum: plan.schedule.length,
    maximum: plan.schedule.length,
  }).map((bindingValue, index) => {
    const field = `release_policy_bundle_binding_${index}`;
    const binding = expectExactRecord(bindingValue, [
      "authority_subject_sha256",
      "compiler_policy_ref",
      "evidence_policy_ref",
      "opaque_cell_id",
      "ordinal",
      "provisioning_command",
      "provisioning_command_sha256",
      "runtime_scope",
    ], field);
    const cell = plan.schedule[index];
    if (binding.ordinal !== cell.ordinal
      || binding.opaque_cell_id !== cell.opaque_cell_id
      || binding.runtime_scope !== cell.isolation.runtime_scope) {
      fail(`${field}_cell_binding_invalid`);
    }
    expectSha256(
      binding.authority_subject_sha256,
      `${field}_authority_subject_sha256`,
    );
    const compilerPolicyRef = artifactRef(
      binding.compiler_policy_ref,
      `${field}_compiler_policy_ref`,
    );
    const evidencePolicyRef = artifactRef(
      binding.evidence_policy_ref,
      `${field}_evidence_policy_ref`,
    );
    const command = verifyCommand(binding.provisioning_command, {
      authoritySubjectSha256: binding.authority_subject_sha256,
      compilerPolicyRef,
      evidencePolicyRef,
      runtimeScope: binding.runtime_scope,
      taskFamily: value.task_family,
      tenantId: value.tenant_id,
      trustRootSha256: value.trust_root_sha256,
    }, `${field}_command`);
    expectSha256(
      binding.provisioning_command_sha256,
      `${field}_provisioning_command_sha256`,
    );
    if (canonicalSha256(command) !== binding.provisioning_command_sha256) {
      fail(`${field}_command_digest_invalid`);
    }
    return canonicalClone({
      ordinal: binding.ordinal,
      opaque_cell_id: binding.opaque_cell_id,
      runtime_scope: binding.runtime_scope,
      authority_subject_sha256: binding.authority_subject_sha256,
      provisioning_command_sha256: binding.provisioning_command_sha256,
      compiler_policy_ref: compilerPolicyRef,
      evidence_policy_ref: evidencePolicyRef,
      provisioning_command: command,
    });
  });
  const projectionSha256 = cellPolicyBundleSetSha256V1({
    pilotId: value.pilot_id,
    tenantId: value.tenant_id,
    taskFamily: value.task_family,
    trustRootSha256: value.trust_root_sha256,
    bindings: bindings.map(({ provisioning_command: omitted, ...binding }) => binding),
  });
  if (projectionSha256 !== value.policy_bundle_set_sha256
    || projectionSha256 !== plan.runtime_binding.cell_policy_bundle_set_sha256) {
    fail("set_digest_binding_invalid");
  }
  return canonicalClone({ ...value, bindings });
}
