import path from "node:path";
import { realpath } from "node:fs/promises";

import { verifyAgentExecutionAuthorityV1 } from "./agent-execution.mjs";
import {
  OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
  verifyNonReleaseContractTestOciRuntimeAuthorityLiveV1,
  verifyOciRuntimeAuthorityLiveV1,
} from "./oci-verifier-process.mjs";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectExactRecord,
  expectPositiveInteger,
  expectSha256,
  expectText,
} from "./canonical.mjs";
import {
  cellPolicyBundleSetSha256V1,
  verifyPilotCaseV1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";
import { preflightPilotArtifactsV1 } from "./pilot-preflight.mjs";
import { EVAL_SOURCE_CLOSURE_ENCODING_V1 } from
  "./release-eval-repository-provenance.mjs";

function fail(code) {
  throw new Error(`aionis_eval_runner_authority_${code}`);
}

function verifyAbsoluteNormalized(value, field) {
  const text = expectText(value, field, { maximumBytes: 16_384 });
  if (!path.isAbsolute(text) || path.normalize(text) !== text) fail(`${field}_invalid`);
  return text;
}

function overlaps(left, right) {
  const relative = path.relative(left, right);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function verifyPolicyArtifactRef(value, field) {
  const ref = expectExactRecord(value, [
    "artifact_sha256", "payload_sha256",
  ], field);
  expectSha256(ref.artifact_sha256, `${field}_artifact_sha256`);
  expectSha256(ref.payload_sha256, `${field}_payload_sha256`);
  return ref;
}

function verifyProviderAuthority(value, plan) {
  const provider = expectExactRecord(value, [
    "endpoint", "maximum_provider_request_attempt_count", "requested_model",
  ], "provider_authority");
  if (provider.endpoint !== plan.model_protocol.endpoint
    || provider.requested_model !== plan.model_protocol.requested_model
    || provider.maximum_provider_request_attempt_count
      !== plan.model_protocol.maximum_provider_request_attempt_count) {
    fail("provider_authority_invalid");
  }
  return provider;
}

function verifyEvalRepositoryProvenance(value, plan, evidenceAuthorityClass) {
  const provenance = expectExactRecord(value, [
    "authority_class", "claim_eligible", "closure_encoding", "closure_sha256",
    "git_commit_sha", "git_executable_identity_sha256", "git_executable_path",
    "git_executable_sha256", "git_tree_sha", "plan_sha256", "provenance_sha256",
    "repository_root", "schema_version", "source_identity_epoch_sha256",
    "tracked_file_count", "worktree_clean",
  ], "eval_repository_provenance");
  const release = evidenceAuthorityClass === PILOT_EVIDENCE_AUTHORITY_CLASS_RELEASE_V1;
  const expectedSchema = release
    ? "aionis_release_eval_repository_provenance_v1"
    : "aionis_non_release_eval_repository_provenance_v1";
  const expectedAuthorityClass = release
    ? "live_current_eval_repository_release_authority_v1"
    : "declared_non_release_contract_test_eval_repository_authority_v1";
  if (provenance.schema_version !== expectedSchema
    || provenance.authority_class !== expectedAuthorityClass
    || provenance.claim_eligible !== release
    || provenance.plan_sha256 !== plan.plan_sha256
    || provenance.worktree_clean !== true
    || provenance.closure_encoding !== EVAL_SOURCE_CLOSURE_ENCODING_V1
    || provenance.git_commit_sha !== plan.eval_binding.git_commit_sha
    || provenance.git_tree_sha !== plan.eval_binding.git_tree_sha
    || provenance.closure_sha256 !== plan.eval_binding.closure_sha256
    || provenance.git_executable_path !== plan.eval_binding.git_executable_path
    || provenance.git_executable_sha256 !== plan.eval_binding.git_executable_sha256
    || provenance.git_executable_identity_sha256
      !== plan.eval_binding.git_executable_identity_sha256) {
    fail("eval_repository_provenance_binding_invalid");
  }
  verifyAbsoluteNormalized(provenance.repository_root, "eval_repository_root");
  verifyAbsoluteNormalized(provenance.git_executable_path, "eval_git_executable_path");
  expectPositiveInteger(provenance.tracked_file_count, "eval_tracked_file_count");
  for (const field of [
    "closure_sha256", "git_executable_identity_sha256", "git_executable_sha256",
    "provenance_sha256", "source_identity_epoch_sha256",
  ]) expectSha256(provenance[field], `eval_repository_${field}`);
  const body = Object.fromEntries(
    Object.entries(provenance).filter(([key]) => key !== "provenance_sha256"),
  );
  if (canonicalSha256(body) !== provenance.provenance_sha256) {
    fail("eval_repository_provenance_integrity_invalid");
  }
  return provenance;
}

function verifyCaseAuthorities(value, cases) {
  const authorities = expectArray(value, "case_authorities", {
    minimum: 3,
    maximum: 3,
  });
  if (authorities.length !== cases.length) fail("case_authority_count_invalid");
  for (const [index, pilotCase] of cases.entries()) {
    const authority = expectExactRecord(authorities[index], [
      "case_id", "case_sha256", "source_fixture_sha256", "verifier_config_sha256",
      "verifier_contract_sha256", "verifier_image_digest",
      "verifier_public_key_principal_sha256", "workspace_base_commit_sha",
      "workspace_clean_status_sha256", "workspace_prepared_tree_sha256",
      "workspace_repository_url",
    ], `case_authority_${index}`);
    const expected = {
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
    };
    if (canonicalJson(authority) !== canonicalJson(expected)) {
      fail("case_authority_binding_invalid");
    }
  }
  return authorities;
}

async function verifyCellAuthorities(value, plan, cases) {
  const authorities = expectArray(value, "cell_authorities", {
    minimum: 9,
    maximum: 9,
  });
  if (authorities.length !== plan.schedule.length) fail("cell_authority_count_invalid");
  const databasePaths = [];
  const workspacePaths = [];
  for (const [index, cell] of plan.schedule.entries()) {
    const authority = expectExactRecord(authorities[index], [
      "agent_execution_authority", "agent_exit_authority_principal_sha256",
      "agent_process_id", "authority_subject_sha256", "compiler_policy_ref",
      "evidence_policy_ref", "isolation_sha256", "provisioning_command_sha256",
      "opaque_cell_id", "runtime_database_id", "runtime_database_path", "runtime_scope",
      "workspace_instance_id", "workspace_path",
    ], `cell_authority_${index}`);
    for (const field of [
      "agent_exit_authority_principal_sha256", "authority_subject_sha256",
      "isolation_sha256", "provisioning_command_sha256",
    ]) expectSha256(authority[field], `cell_authority_${index}_${field}`);
    verifyPolicyArtifactRef(
      authority.compiler_policy_ref,
      `cell_authority_${index}_compiler_policy_ref`,
    );
    verifyPolicyArtifactRef(
      authority.evidence_policy_ref,
      `cell_authority_${index}_evidence_policy_ref`,
    );
    const expected = {
      opaque_cell_id: cell.opaque_cell_id,
      runtime_scope: cell.isolation.runtime_scope,
      runtime_database_id: cell.isolation.runtime_database_id,
      workspace_instance_id: cell.isolation.workspace_instance_id,
      agent_process_id: cell.isolation.agent_process_id,
      agent_exit_authority_principal_sha256:
        cell.isolation.agent_exit_authority_principal_sha256,
      isolation_sha256: cell.isolation.isolation_sha256,
    };
    for (const [field, expectedValue] of Object.entries(expected)) {
      if (authority[field] !== expectedValue) fail("cell_authority_binding_invalid");
    }
    const expectedAuthoritySubjectSha256 = canonicalSha256({
      schema_version: "continuation_authority_subject_v1",
      tenant_id: plan.runtime_binding.tenant_id,
      scope: cell.isolation.runtime_scope,
      task_family: plan.runtime_binding.task_family,
    });
    if (authority.authority_subject_sha256 !== expectedAuthoritySubjectSha256) {
      fail("cell_policy_authority_subject_invalid");
    }
    const databasePath = verifyAbsoluteNormalized(
      authority.runtime_database_path,
      `cell_authority_${index}_database_path`,
    );
    const workspacePath = verifyAbsoluteNormalized(
      authority.workspace_path,
      `cell_authority_${index}_workspace_path`,
    );
    let canonicalDatabasePath;
    let canonicalWorkspacePath;
    try {
      canonicalWorkspacePath = await realpath(workspacePath);
      canonicalDatabasePath = path.join(
        await realpath(path.dirname(databasePath)),
        path.basename(databasePath),
      );
    } catch {
      fail("cell_path_authority_missing");
    }
    if (canonicalWorkspacePath !== workspacePath
      || canonicalDatabasePath !== databasePath) fail("cell_path_alias_forbidden");
    const executionAuthority = await verifyAgentExecutionAuthorityV1(
      authority.agent_execution_authority,
      cell,
    );
    if (executionAuthority.workspace_path !== workspacePath) {
      fail("cell_execution_workspace_binding_invalid");
    }
    const pilotCase = cases.find((candidate) => candidate.case_id === cell.case_id);
    if (pilotCase === undefined
      || executionAuthority.workspace_prepared_sha256
        !== pilotCase.workspace.prepared_tree_sha256) {
      fail("cell_execution_prepared_workspace_binding_invalid");
    }
    if (overlaps(databasePath, workspacePath) || overlaps(workspacePath, databasePath)) {
      fail("cell_database_workspace_overlap");
    }
    databasePaths.push(databasePath);
    workspacePaths.push(workspacePath);
  }
  if (new Set(databasePaths).size !== authorities.length
    || new Set(workspacePaths).size !== authorities.length) {
    fail("cell_path_reuse");
  }
  for (let left = 0; left < authorities.length; left += 1) {
    for (let right = left + 1; right < authorities.length; right += 1) {
      if (overlaps(workspacePaths[left], workspacePaths[right])
        || overlaps(workspacePaths[right], workspacePaths[left])
        || overlaps(databasePaths[left], databasePaths[right])
        || overlaps(databasePaths[right], databasePaths[left])) {
        fail("workspace_path_overlap");
      }
    }
  }
  for (const databasePath of databasePaths) {
    for (const workspacePath of workspacePaths) {
      if (overlaps(databasePath, workspacePath) || overlaps(workspacePath, databasePath)) {
        fail("cross_cell_database_workspace_overlap");
      }
    }
  }
  const policyBundleSetSha256 = cellPolicyBundleSetSha256V1({
    pilotId: plan.pilot_id,
    tenantId: plan.runtime_binding.tenant_id,
    taskFamily: plan.runtime_binding.task_family,
    trustRootSha256: plan.runtime_binding.trust_root_sha256,
    bindings: authorities.map((authority, index) => ({
      ordinal: index + 1,
      opaque_cell_id: authority.opaque_cell_id,
      runtime_scope: authority.runtime_scope,
      authority_subject_sha256: authority.authority_subject_sha256,
      provisioning_command_sha256: authority.provisioning_command_sha256,
      compiler_policy_ref: authority.compiler_policy_ref,
      evidence_policy_ref: authority.evidence_policy_ref,
    })),
  });
  if (policyBundleSetSha256 !== plan.runtime_binding.cell_policy_bundle_set_sha256) {
    fail("cell_policy_bundle_set_binding_invalid");
  }
  return authorities;
}

export const PILOT_EVIDENCE_AUTHORITY_CLASS_RELEASE_V1 = "release_authority_v1";
export const PILOT_EVIDENCE_AUTHORITY_CLASS_CONTRACT_TEST_V1 =
  "non_release_contract_test_authority_v1";

async function preflightPilotExecutionManifestForAuthorityClass(
  input,
  expectedOciAuthorityClass,
  evidenceAuthorityClass,
) {
  const record = expectExactRecord(input, [
    "authority", "cases", "plan",
  ], "runner_authorization_input");
  const plan = verifyPilotPlanV1(record.plan);
  const artifactReport = preflightPilotArtifactsV1({ plan, cases: record.cases });
  const caseById = new Map(record.cases.map((value) => {
    const pilotCase = verifyPilotCaseV1(value);
    return [pilotCase.case_id, pilotCase];
  }));
  const cases = plan.cases.map((ref) => caseById.get(ref.case_id));
  if (cases.some((value) => value === undefined)) fail("case_missing");
  const authority = expectExactRecord(record.authority, [
    "case_authorities", "cell_authorities", "eval_binding",
    "eval_repository_provenance", "provider",
    "runtime_binding", "schema_version", "oci_runtime_authority",
  ], "runner_authority");
  if (authority.schema_version !== "aionis_pilot_runner_authority_v1"
    || canonicalJson(authority.eval_binding) !== canonicalJson(plan.eval_binding)
    || canonicalJson(authority.runtime_binding) !== canonicalJson(plan.runtime_binding)) {
    fail("source_authority_binding_invalid");
  }
  const provider = verifyProviderAuthority(authority.provider, plan);
  const evalRepositoryProvenance = verifyEvalRepositoryProvenance(
    authority.eval_repository_provenance,
    plan,
    evidenceAuthorityClass,
  );
  const ociRuntimeAuthority = expectedOciAuthorityClass
    === OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1
    ? await verifyOciRuntimeAuthorityLiveV1(authority.oci_runtime_authority)
    : await verifyNonReleaseContractTestOciRuntimeAuthorityLiveV1(
      authority.oci_runtime_authority,
    );
  if (ociRuntimeAuthority.authority_class !== expectedOciAuthorityClass) {
    fail("oci_runtime_authority_class_invalid");
  }
  const caseAuthorities = verifyCaseAuthorities(authority.case_authorities, cases);
  const cellAuthorities = await verifyCellAuthorities(authority.cell_authorities, plan, cases);
  if (evidenceAuthorityClass === PILOT_EVIDENCE_AUTHORITY_CLASS_RELEASE_V1
    && cellAuthorities.some((cellAuthority) => {
      const execution = cellAuthority.agent_execution_authority;
      return execution.git_executable_path !== evalRepositoryProvenance.git_executable_path
        || execution.git_executable_sha256
          !== evalRepositoryProvenance.git_executable_sha256
        || execution.git_executable_identity_sha256
          !== evalRepositoryProvenance.git_executable_identity_sha256;
    })) fail("cell_git_executable_provenance_mismatch");
  const body = canonicalClone({
    schema_version: "aionis_pilot_execution_manifest_report_v1",
    status: "execution_manifest_verified",
    evidence_authority_class: evidenceAuthorityClass,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    artifact_report_sha256: canonicalSha256(artifactReport),
    eval_binding_sha256: canonicalSha256(authority.eval_binding),
    eval_repository_provenance_sha256: evalRepositoryProvenance.provenance_sha256,
    runtime_binding_sha256: canonicalSha256(authority.runtime_binding),
    provider_authority_sha256: canonicalSha256(provider),
    oci_runtime_authority_sha256: ociRuntimeAuthority.authority_sha256,
    case_authority_set_sha256: canonicalSha256(caseAuthorities),
    cell_authority_set_sha256: canonicalSha256(cellAuthorities),
    cell_count: cellAuthorities.length,
    provider_request_attempt_limit: provider.maximum_provider_request_attempt_count,
    cohort_installed: plan.runtime_binding.cohort_installed,
    runner_authority: authority,
  });
  return canonicalClone({
    ...body,
    manifest_report_sha256: canonicalSha256(body),
  });
}

export async function preflightPilotExecutionManifestV1(input) {
  return preflightPilotExecutionManifestForAuthorityClass(
    input,
    OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
    PILOT_EVIDENCE_AUTHORITY_CLASS_RELEASE_V1,
  );
}

export async function preflightNonReleaseContractTestPilotExecutionManifestV1(input) {
  return preflightPilotExecutionManifestForAuthorityClass(
    input,
    OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
    PILOT_EVIDENCE_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  );
}
