import { generateKeyPairSync } from "node:crypto";

import { canonicalClone, canonicalSha256 } from "../../src/canonical.mjs";
import {
  PILOT_ARMS_V1,
  buildLatinSquareScheduleV1,
  buildPilotPlanV1,
  cellPolicyBundleSetSha256V1,
  defaultPromotionGateV1,
  pilotFixtureSetSha256V1,
  pilotProtocolSha256V1,
} from "../../src/pilot-contract.mjs";
import { beginPilotRunLedgerV1 } from "../../src/pilot-run-ledger.mjs";
import {
  buildSignedRunnerExecutionAuthorizationV1,
  runnerAuthorityPublicKeyPrincipalSha256V1,
} from "../../src/runner-signature.mjs";
import { EVAL_SOURCE_CLOSURE_ENCODING_V1 } from
  "../../src/release-eval-repository-provenance.mjs";

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const GIT = "c".repeat(40);

export const TEST_RUNNER_KEYS_V1 = generateKeyPairSync("ed25519");

export function buildTestCellPolicyBindingsV1(cases, options = {}) {
  const pilotId = options.pilotId ?? "pilot-test-plan";
  const tenantId = options.tenantId ?? "tenant-pilot-test";
  const taskFamily = options.taskFamily ?? "coding";
  const refs = cases.map(({ case_id, case_sha256 }) => ({ case_id, case_sha256 }));
  return buildLatinSquareScheduleV1(pilotId, refs).map((cell) => ({
    ordinal: cell.ordinal,
    opaque_cell_id: cell.opaque_cell_id,
    runtime_scope: cell.isolation.runtime_scope,
    authority_subject_sha256: canonicalSha256({
      schema_version: "continuation_authority_subject_v1",
      tenant_id: tenantId,
      scope: cell.isolation.runtime_scope,
      task_family: taskFamily,
    }),
    provisioning_command_sha256: canonicalSha256({
      schema_version: "aionis_test_policy_command_v1",
      opaque_cell_id: cell.opaque_cell_id,
    }),
    compiler_policy_ref: {
      artifact_sha256: canonicalSha256({
        schema_version: "aionis_test_compiler_policy_artifact_v1",
        opaque_cell_id: cell.opaque_cell_id,
      }),
      payload_sha256: canonicalSha256({
        schema_version: "aionis_test_compiler_policy_payload_v1",
        opaque_cell_id: cell.opaque_cell_id,
      }),
    },
    evidence_policy_ref: {
      artifact_sha256: canonicalSha256({
        schema_version: "aionis_test_evidence_policy_artifact_v1",
        opaque_cell_id: cell.opaque_cell_id,
      }),
      payload_sha256: canonicalSha256({
        schema_version: "aionis_test_evidence_policy_payload_v1",
        opaque_cell_id: cell.opaque_cell_id,
      }),
    },
  }));
}

export function buildTestPilotPlanV1(cases, overrides = {}) {
  const pilotId = overrides.pilotId ?? "pilot-test-plan";
  const tenantId = overrides.tenantId ?? "tenant-pilot-test";
  const taskFamily = overrides.taskFamily ?? "coding";
  const trustRootSha256 = overrides.trustRootSha256 ?? SHA_A;
  const refs = cases.map(({ case_id, case_sha256 }) => ({ case_id, case_sha256 }));
  const claim = {
    primary_endpoint: "verifier_safe_action_completion",
    safety_guardrails: ["unsafe_direct_use", "wrong_branch_write", "verifier_missing"],
    scope: "verified_continuity_release_pilot",
  };
  const modelProtocol = {
    provider: "deepseek",
    endpoint: "https://api.deepseek.com/chat/completions",
    requested_model: "deepseek-v4-flash",
    thinking_mode: "enabled",
    reasoning_effort: "max",
    response_format: "json_object",
    max_tokens: 8_192,
    retries: 0,
    scored_agent_execution_count: 9,
    maximum_provider_request_attempt_count: 9,
    immutable_snapshot: false,
    provider_may_update_weights: true,
  };
  const promotionGate = defaultPromotionGateV1();
  const cellPolicyBindings = buildTestCellPolicyBindingsV1(cases, {
    pilotId,
    tenantId,
    taskFamily,
  });
  const runtimeBinding = overrides.runtimeBinding ?? {
    git_commit_sha: GIT,
    git_tree_sha: GIT,
    worktree_clean: true,
    package_lock_sha256: SHA_A,
    schema_manifest_file_sha256: SHA_B,
    schema_sha256: SHA_A,
    oci_image_digest: `sha256:${SHA_B}`,
    oci_closure_manifest_sha256: SHA_A,
    oci_closure_sha256: SHA_B,
    sdk_package_name: "@aionis/continuation-sdk",
    sdk_package_version: "1.0.0-alpha.1",
    sdk_entry_count: 19,
    sdk_tgz_sha256: SHA_A,
    sdk_tgz_sha512: "d".repeat(128),
    authority_build_closure_sha256: SHA_B,
    tenant_id: tenantId,
    task_family: taskFamily,
    trust_root_sha256: trustRootSha256,
    cell_policy_bundle_set_sha256: cellPolicyBundleSetSha256V1({
      pilotId,
      tenantId,
      taskFamily,
      trustRootSha256,
      bindings: cellPolicyBindings,
    }),
    cohort_installed: false,
  };
  const evalBinding = overrides.evalBinding ?? {
    git_commit_sha: GIT,
    git_tree_sha: GIT,
    worktree_clean: true,
    closure_sha256: SHA_A,
    git_executable_path: "/usr/bin/git",
    git_executable_sha256: SHA_B,
    git_executable_identity_sha256: SHA_A,
    fixture_set_sha256: pilotFixtureSetSha256V1(refs),
    protocol_sha256: pilotProtocolSha256V1({
      claim,
      model_protocol: modelProtocol,
      arms: PILOT_ARMS_V1,
      promotion_gate: promotionGate,
    }),
    runner_authority_public_key_principal_sha256:
      runnerAuthorityPublicKeyPrincipalSha256V1(TEST_RUNNER_KEYS_V1.publicKey),
  };
  return buildPilotPlanV1({
    pilot_id: pilotId,
    frozen_at: "2026-07-22T00:00:00.000Z",
    claim,
    runtime_binding: runtimeBinding,
    eval_binding: evalBinding,
    model_protocol: modelProtocol,
    arms: PILOT_ARMS_V1,
    cases: refs,
    schedule: buildLatinSquareScheduleV1(pilotId, refs),
    promotion_gate: promotionGate,
  });
}

export function buildTestEvalRepositoryProvenanceV1(plan, options = {}) {
  const release = options.release === true;
  const body = canonicalClone({
    schema_version: release
      ? "aionis_release_eval_repository_provenance_v1"
      : "aionis_non_release_eval_repository_provenance_v1",
    authority_class: release
      ? "live_current_eval_repository_release_authority_v1"
      : "declared_non_release_contract_test_eval_repository_authority_v1",
    claim_eligible: release,
    plan_sha256: plan.plan_sha256,
    repository_root: options.repositoryRoot ?? "/non-release/eval-repository",
    git_commit_sha: plan.eval_binding.git_commit_sha,
    git_tree_sha: plan.eval_binding.git_tree_sha,
    worktree_clean: true,
    closure_encoding: EVAL_SOURCE_CLOSURE_ENCODING_V1,
    closure_sha256: plan.eval_binding.closure_sha256,
    source_identity_epoch_sha256: SHA_B,
    tracked_file_count: options.trackedFileCount ?? 1,
    git_executable_path: plan.eval_binding.git_executable_path,
    git_executable_sha256: plan.eval_binding.git_executable_sha256,
    git_executable_identity_sha256:
      plan.eval_binding.git_executable_identity_sha256,
  });
  return canonicalClone({ ...body, provenance_sha256: canonicalSha256(body) });
}

export function buildTestExecutionManifestV1(plan, overrides = {}) {
  const body = canonicalClone({
    schema_version: "aionis_pilot_execution_manifest_report_v1",
    status: "execution_manifest_verified",
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    artifact_report_sha256: SHA_A,
    eval_binding_sha256: SHA_B,
    eval_repository_provenance_sha256: SHA_A,
    runtime_binding_sha256: SHA_A,
    provider_authority_sha256: SHA_B,
    oci_runtime_authority_sha256: SHA_A,
    case_authority_set_sha256: SHA_A,
    cell_authority_set_sha256: SHA_B,
    cell_count: plan.schedule.length,
    provider_request_attempt_limit:
      plan.model_protocol.maximum_provider_request_attempt_count,
    cohort_installed: plan.runtime_binding.cohort_installed,
    evidence_authority_class: "release_authority_v1",
    runner_authority: {
      schema_version: "aionis_test_runner_authority_v1",
      eval_repository_provenance: { provenance_sha256: SHA_A },
    },
    ...overrides,
  });
  return canonicalClone({
    ...body,
    manifest_report_sha256: canonicalSha256(body),
  });
}

export async function beginTestPilotRunLedgerV1({ authorityRoot, plan }) {
  const executionManifest = buildTestExecutionManifestV1(plan);
  const executionAuthorization = buildSignedRunnerExecutionAuthorizationV1({
    plan,
    executionManifest,
    fixedLedgerAuthorityRoot: authorityRoot,
    issuedAt: "2026-07-22T00:00:01.000Z",
  }, TEST_RUNNER_KEYS_V1.privateKey);
  const ledger = await beginPilotRunLedgerV1({
    authorityRoot,
    executionAuthorization,
    executionManifest,
    plan,
    runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
  });
  return { executionAuthorization, executionManifest, ledger };
}
