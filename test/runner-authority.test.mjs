import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, mkdir, realpath, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalClone } from "../src/canonical.mjs";
import { buildAgentExecutionAuthorityV1 } from "../src/agent-execution.mjs";
import {
  buildNonReleaseContractTestOciRuntimeAuthorityV1,
} from "../src/oci-verifier-process.mjs";
import {
  PILOT_EVIDENCE_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  preflightNonReleaseContractTestPilotExecutionManifestV1,
  preflightPilotExecutionManifestV1,
} from "../src/runner-authority.mjs";
import { captureWorkspaceEvidenceV1 } from "../src/workspace-evidence.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import {
  buildTestCellPolicyBindingsV1,
  buildTestEvalRepositoryProvenanceV1,
  buildTestPilotPlanV1,
} from "./support/pilot-plan-fixture.mjs";

async function fixture(root) {
  await mkdir(root, { recursive: true, mode: 0o700 });
  root = await realpath(root);
  const workspacePaths = [];
  for (let index = 0; index < 9; index += 1) {
    const runtimeDirectory = path.join(root, `runtime-${index}`);
    const workspacePath = path.join(root, `workspace-${index}`);
    await mkdir(runtimeDirectory, { mode: 0o700 });
    await mkdir(workspacePath, { mode: 0o700 });
    workspacePaths.push(workspacePath);
  }
  const preparedWorkspace = await captureWorkspaceEvidenceV1(workspacePaths[0]);
  const cases = ["one", "two", "three"].map((caseId) => {
    const keys = generateKeyPairSync("ed25519");
    return buildTestPilotCaseV1({
      caseId,
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
      workspaceSha256: preparedWorkspace.workspace_sha256,
    });
  });
  const plan = buildTestPilotPlanV1(cases, { pilotId: "pilot-runner-authority-test" });
  const cellPolicyBindings = buildTestCellPolicyBindingsV1(cases, {
    pilotId: plan.pilot_id,
    tenantId: plan.runtime_binding.tenant_id,
    taskFamily: plan.runtime_binding.task_family,
  });
  const caseAuthorities = cases.map((pilotCase) => ({
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    source_fixture_sha256: pilotCase.source_fixture.fixture_sha256,
    workspace_repository_url: pilotCase.workspace.repository_url,
    workspace_base_commit_sha: pilotCase.workspace.base_commit_sha,
    workspace_prepared_tree_sha256: pilotCase.workspace.prepared_tree_sha256,
    workspace_clean_status_sha256: pilotCase.workspace.clean_status_sha256,
    verifier_image_digest: pilotCase.private_verifier.verifier_image_digest,
    verifier_contract_sha256: pilotCase.private_verifier.verifier_contract_sha256,
    verifier_config_sha256: pilotCase.private_verifier.verifier_config_sha256,
    verifier_public_key_principal_sha256:
      pilotCase.private_verifier.verifier_public_key_principal_sha256,
  }));
  const cellAuthorities = [];
  const ociRuntimeAuthority = await buildNonReleaseContractTestOciRuntimeAuthorityV1({
    runtimeKind: "docker",
    executablePath: await realpath("/usr/bin/true"),
  });
  for (const [index, cell] of plan.schedule.entries()) {
    const policyBinding = cellPolicyBindings[index];
    const runtimeDirectory = path.join(root, `runtime-${index}`);
    const workspacePath = workspacePaths[index];
    cellAuthorities.push({
      opaque_cell_id: cell.opaque_cell_id,
      runtime_scope: cell.isolation.runtime_scope,
      runtime_database_id: cell.isolation.runtime_database_id,
      runtime_database_path: path.join(runtimeDirectory, "runtime.sqlite"),
      workspace_instance_id: cell.isolation.workspace_instance_id,
      workspace_path: workspacePath,
      agent_execution_authority: await buildAgentExecutionAuthorityV1({
        cell,
        workspacePath,
        gitExecutablePath: "/usr/bin/git",
      }),
      agent_process_id: cell.isolation.agent_process_id,
      agent_exit_authority_principal_sha256:
        cell.isolation.agent_exit_authority_principal_sha256,
      isolation_sha256: cell.isolation.isolation_sha256,
      authority_subject_sha256: policyBinding.authority_subject_sha256,
      provisioning_command_sha256: policyBinding.provisioning_command_sha256,
      compiler_policy_ref: policyBinding.compiler_policy_ref,
      evidence_policy_ref: policyBinding.evidence_policy_ref,
    });
  }
  return {
    plan,
    cases,
    authority: {
      schema_version: "aionis_pilot_runner_authority_v1",
      eval_binding: plan.eval_binding,
      eval_repository_provenance: buildTestEvalRepositoryProvenanceV1(plan),
      runtime_binding: plan.runtime_binding,
      oci_runtime_authority: ociRuntimeAuthority,
      provider: {
        endpoint: plan.model_protocol.endpoint,
        requested_model: plan.model_protocol.requested_model,
        maximum_provider_request_attempt_count:
          plan.model_protocol.maximum_provider_request_attempt_count,
      },
      case_authorities: caseAuthorities,
      cell_authorities: cellAuthorities,
    },
  };
}

test("non-release execution manifest preflight binds declared authorities and nine disjoint live paths", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aionis-runner-authority-"));
  try {
    const input = await fixture(root);
    await assert.rejects(
      () => preflightPilotExecutionManifestV1(input),
      /eval_repository_provenance_binding_invalid/u,
    );
    const result = await preflightNonReleaseContractTestPilotExecutionManifestV1(input);
    assert.equal(result.status, "execution_manifest_verified");
    assert.equal(
      result.evidence_authority_class,
      PILOT_EVIDENCE_AUTHORITY_CLASS_CONTRACT_TEST_V1,
    );
    assert.equal(result.cell_count, 9);
    assert.equal(result.provider_request_attempt_limit, 9);
    assert.equal(result.cohort_installed, false);
    assert.match(result.manifest_report_sha256, /^[0-9a-f]{64}$/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("execution manifest preflight fails closed on dirty declarations, missing key, or reused paths", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aionis-runner-reject-"));
  try {
    for (const mutate of [
    (value) => { value.authority.eval_binding.worktree_clean = false; },
    (value) => { value.authority.provider.endpoint = "https://invalid.example/v1"; },
    (value) => {
      value.authority.cell_authorities[1].workspace_path =
        value.authority.cell_authorities[0].workspace_path;
    },
    (value) => {
      value.authority.cell_authorities[0].runtime_database_path =
        `${value.authority.cell_authorities[0].workspace_path}/runtime.sqlite`;
    },
    (value) => { value.authority.case_authorities[0].source_fixture_sha256 = "f".repeat(64); },
    (value) => {
      value.authority.cell_authorities[0].compiler_policy_ref.artifact_sha256 =
        "f".repeat(64);
    },
    ]) {
      const input = canonicalClone(await fixture(path.join(root, `case-${Math.random()}`)));
      mutate(input);
      await assert.rejects(
        () => preflightNonReleaseContractTestPilotExecutionManifestV1(input),
        /aionis_eval_/u,
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("execution manifest preflight rejects symlink aliases", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aionis-runner-alias-"));
  try {
    const fixtureRoot = path.join(root, "fixture");
    await mkdir(fixtureRoot);
    const input = await fixture(fixtureRoot);
    const alias = path.join(root, "workspace-alias");
    await symlink(input.authority.cell_authorities[0].workspace_path, alias);
    input.authority.cell_authorities[0].workspace_path = alias;
    await assert.rejects(
      () => preflightNonReleaseContractTestPilotExecutionManifestV1(input),
      /cell_path_alias_forbidden/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
