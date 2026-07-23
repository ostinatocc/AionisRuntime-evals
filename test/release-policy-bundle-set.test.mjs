import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { canonicalClone, canonicalSha256 } from "../src/canonical.mjs";
import { cellPolicyBundleSetSha256V1 } from "../src/pilot-contract.mjs";
import { verifyReleaseCellPolicyBundleSetV1 } from
  "../src/release-policy-bundle-set.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import {
  buildTestCellPolicyBindingsV1,
  buildTestPilotPlanV1,
} from "./support/pilot-plan-fixture.mjs";

function signedArtifact(binding, runtime, kind) {
  const ref = kind === "compiler_policy"
    ? binding.compiler_policy_ref
    : binding.evidence_policy_ref;
  return {
    tenant_id: runtime.tenant_id,
    artifact_id: `${kind}-${binding.ordinal}`,
    artifact_revision: 1,
    artifact_kind: kind,
    artifact_schema: kind === "compiler_policy"
      ? "continuation_compiler_policy_v1"
      : "effect_evidence_policy_v1",
    authority_subject_sha256: binding.authority_subject_sha256,
    payload: {
      schema_version: kind === "compiler_policy"
        ? "continuation_compiler_policy_v1"
        : "effect_evidence_policy_v1",
      tenant_id: runtime.tenant_id,
      authority_subject_sha256: binding.authority_subject_sha256,
    },
    payload_sha256: ref.payload_sha256,
    artifact_sha256: ref.artifact_sha256,
    signer_principal_sha256: "e".repeat(64),
    trust_root_sha256: runtime.trust_root_sha256,
    signature_algorithm: "ed25519",
    valid_from: "2026-07-22T00:00:00.000Z",
    expires_at: null,
    created_at: "2026-07-21T00:00:00.000Z",
    signature: "A".repeat(86),
  };
}

function fixture() {
  const cases = [1, 2, 3].map((index) => buildTestPilotCaseV1({
    caseId: `release-policy-${index}`,
    verifierPublicKey: generateKeyPairSync("ed25519").publicKey,
  }));
  const pilotId = "release-policy-bundle-set-test";
  const initial = buildTestPilotPlanV1(cases, { pilotId });
  const baseBindings = buildTestCellPolicyBindingsV1(cases, {
    pilotId,
    tenantId: initial.runtime_binding.tenant_id,
    taskFamily: initial.runtime_binding.task_family,
  });
  const bindings = baseBindings.map((binding) => {
    const compiler = signedArtifact(binding, initial.runtime_binding, "compiler_policy");
    const evidence = signedArtifact(binding, initial.runtime_binding, "evidence_policy");
    const command = {
      schema_version: "offline_provisioning_command_v1",
      tenant_id: initial.runtime_binding.tenant_id,
      scope: binding.runtime_scope,
      task_family: initial.runtime_binding.task_family,
      operation_id: `install-policy-${binding.ordinal}`,
      actor_kind: "operator",
      actor_principal_sha256: "f".repeat(64),
      authority_subject_sha256: binding.authority_subject_sha256,
      kind: "policy_bundle_install",
      policy_bundle: {
        schema_version: "authority_policy_provisioning_bundle_v1",
        tenant_id: initial.runtime_binding.tenant_id,
        authority_subject_sha256: binding.authority_subject_sha256,
        compiler_policy: compiler,
        evidence_policy: evidence,
      },
    };
    return {
      ...binding,
      provisioning_command: command,
      provisioning_command_sha256: canonicalSha256(command),
    };
  });
  const setSha256 = cellPolicyBundleSetSha256V1({
    pilotId,
    tenantId: initial.runtime_binding.tenant_id,
    taskFamily: initial.runtime_binding.task_family,
    trustRootSha256: initial.runtime_binding.trust_root_sha256,
    bindings: bindings.map(({ provisioning_command: omitted, ...binding }) => binding),
  });
  const plan = buildTestPilotPlanV1(cases, {
    pilotId,
    runtimeBinding: {
      ...initial.runtime_binding,
      cell_policy_bundle_set_sha256: setSha256,
    },
  });
  return {
    plan,
    policyBundleSet: {
      schema_version: "aionis_pilot_cell_policy_bundle_set_v1",
      pilot_id: pilotId,
      tenant_id: plan.runtime_binding.tenant_id,
      task_family: plan.runtime_binding.task_family,
      trust_root_sha256: plan.runtime_binding.trust_root_sha256,
      bindings,
      policy_bundle_set_sha256: setSha256,
    },
  };
}

test("release policy set binds nine signed commands to exact isolated scopes", () => {
  const value = fixture();
  assert.deepEqual(
    verifyReleaseCellPolicyBundleSetV1(value),
    value.policyBundleSet,
  );
  const tampered = canonicalClone(value);
  tampered.policyBundleSet.bindings[0].provisioning_command.scope =
    tampered.policyBundleSet.bindings[1].runtime_scope;
  assert.throws(
    () => verifyReleaseCellPolicyBundleSetV1(tampered),
    /command_binding_invalid/u,
  );
});
