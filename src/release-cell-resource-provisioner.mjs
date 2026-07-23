import {
  buildAgentExecutionAuthorityV1,
} from "./agent-execution.mjs";
import {
  verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1,
} from "./release-eval-repository-provenance.mjs";
import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectExactRecord,
  expectSha256,
  expectText,
} from "./canonical.mjs";
import {
  OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
  assertExistingOciVerifierPrivateKeyFdV1,
  attestOciVerifierPrivateKeyFdV1,
  ociPrivateVerifierConfigSha256V1,
  runOciPrivateVerifierProcessV1,
} from "./oci-verifier-process.mjs";
import {
  verifyPilotCaseV1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";
import {
  verifyReleaseCellPolicyBundleSetV1,
} from "./release-policy-bundle-set.mjs";
import {
  buildOwnerCleanupReceiptV1,
} from "./pilot-run-event-contract.mjs";
import {
  claimReleaseRuntimeOciResourceOwnerV1,
  disposeReleaseRuntimeOciResourceOwnerV1,
} from "./release-runtime-oci-resource.mjs";
import {
  claimReleaseWorkspaceResourceOwnerV1,
  disposeReleaseWorkspaceResourceOwnerV1,
} from "./release-workspace-resource.mjs";
import {
  preflightPilotExecutionManifestV1,
} from "./runner-authority.mjs";
import { createRuntimeV1HostAdapter } from "./runtime-v1-host-adapter.mjs";
import {
  verifierPublicKeyPrincipalSha256V1,
} from "./verifier-evidence.mjs";

const WORKSPACE_OWNER_KEYS = Object.freeze([
  "authorities", "closeAll", "owner_id", "owner_manifest_sha256", "plan_sha256",
  "resource_root", "resources", "schema_version", "workspace_authority_set_sha256",
]);
const RUNTIME_OWNER_KEYS = Object.freeze([
  "authorities", "brokers", "closeAll", "containerAuthoritySetSha256",
  "imageAuthority", "ociRuntimeAuthority", "owner_id", "owner_manifest_sha256",
  "ownerId", "ownerManifestSha256", "plan_sha256", "resource_root", "schema_version",
]);
const AUTHORITY_CLASS = "release_cell_resource_authority_v1";
const RELEASE_RESOURCE_AUTHORITIES = new WeakMap();

function fail(code) {
  throw new Error(`aionis_eval_release_cell_resource_provisioner_${code}`);
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function verifyReleaseManifest(value, plan) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("execution_manifest_invalid");
  }
  if (value.schema_version !== "aionis_pilot_execution_manifest_report_v1"
    || value.status !== "execution_manifest_verified"
    || value.evidence_authority_class !== "release_authority_v1"
    || value.pilot_id !== plan.pilot_id
    || value.plan_sha256 !== plan.plan_sha256
    || value.cell_count !== plan.schedule.length
    || value.runner_authority?.oci_runtime_authority?.authority_class
      !== OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1) {
    fail("execution_manifest_release_binding_invalid");
  }
  expectSha256(value.manifest_report_sha256, "release_manifest_report_sha256");
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== "manifest_report_sha256"),
  );
  if (canonicalSha256(body) !== value.manifest_report_sha256) {
    fail("execution_manifest_integrity_invalid");
  }
  return deepFreeze(canonicalClone(value));
}

function captureAdapter(value, cell) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || typeof value.prepareArm !== "function"
    || (cell.arm === "treatment" && typeof value.settleTreatment !== "function")) {
    fail("adapter_invalid");
  }
  const prepareArm = value.prepareArm.bind(value);
  const settleTreatment = typeof value.settleTreatment === "function"
    ? value.settleTreatment.bind(value)
    : null;
  const close = typeof value.close === "function" ? value.close.bind(value) : null;
  return Object.freeze({
    prepareArm,
    ...(settleTreatment === null ? {} : { settleTreatment }),
    ...(close === null ? {} : { close }),
  });
}

function captureResource(value, cell, manifest, index) {
  const resource = expectExactRecord(value, [
    "adapter", "executionAuthority", "ociRuntimeAuthority", "runVerifier",
    "verifierConfig", "verifierPublicKey",
  ], `release_cell_resource_${index}`);
  if (typeof resource.runVerifier !== "function") fail("verifier_capability_invalid");
  const authority = manifest.runner_authority.cell_authorities[index];
  if (authority === undefined
    || canonicalJson(resource.executionAuthority)
      !== canonicalJson(authority.agent_execution_authority)
    || canonicalJson(resource.ociRuntimeAuthority)
      !== canonicalJson(manifest.runner_authority.oci_runtime_authority)) {
    fail("resource_manifest_binding_invalid");
  }
  return Object.freeze({
    adapter: captureAdapter(resource.adapter, cell),
    executionAuthority: canonicalClone(resource.executionAuthority),
    ociRuntimeAuthority: canonicalClone(resource.ociRuntimeAuthority),
    runVerifier: resource.runVerifier,
    verifierConfig: canonicalClone(resource.verifierConfig),
    verifierPublicKey: resource.verifierPublicKey,
  });
}

function publicHandle(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

async function disposeState(state) {
  if (state.disposePromise === null) {
    state.status = "disposing";
    state.disposePromise = Promise.resolve().then(state.disposeAll).then((receipt) => {
      state.disposalReceipt = receipt;
      state.status = "disposed";
      return receipt;
    }, (error) => {
      state.status = "disposal_failed";
      throw error;
    });
  }
  return state.disposePromise;
}

function issueReleaseCellResourceAuthority(options) {
  const input = expectExactRecord(options, [
    "disposeAll", "executionManifest", "plan", "provisionerClosureSha256", "resources",
  ], "release_cell_resource_issuer_input");
  if (typeof input.disposeAll !== "function") fail("dispose_capability_invalid");
  const plan = verifyPilotPlanV1(input.plan);
  const manifest = verifyReleaseManifest(input.executionManifest, plan);
  const provisionerClosureSha256 = expectSha256(
    input.provisionerClosureSha256,
    "release_provisioner_closure_sha256",
  );
  const values = expectArray(input.resources, "release_cell_resources", {
    minimum: plan.schedule.length,
    maximum: plan.schedule.length,
  });
  const resources = Object.freeze(plan.schedule.map((cell, index) =>
    captureResource(values[index], cell, manifest, index)));
  const closure = canonicalClone({
    schema_version: "aionis_release_cell_resource_closure_v1",
    authority_class: AUTHORITY_CLASS,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    execution_manifest_sha256: manifest.manifest_report_sha256,
    provisioner_closure_sha256: provisionerClosureSha256,
    resource_count: resources.length,
    cell_authority_set_sha256: manifest.cell_authority_set_sha256,
  });
  const handle = publicHandle({
    schema_version: "aionis_release_cell_resource_authority_handle_v1",
    authority_class: AUTHORITY_CLASS,
    claim_eligible: true,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    execution_manifest_sha256: manifest.manifest_report_sha256,
    resource_count: resources.length,
    resource_authority_closure_sha256: canonicalSha256(closure),
  });
  RELEASE_RESOURCE_AUTHORITIES.set(handle, {
    closure,
    disposalReceipt: null,
    disposeAll: input.disposeAll,
    disposePromise: null,
    executionManifest: manifest,
    resources,
    status: "ready",
  });
  return handle;
}

export function claimReleaseCellResourceAuthorityV1(options) {
  const input = expectExactRecord(options, [
    "cellResourceAuthority", "plan",
  ], "release_cell_resource_claim_input");
  const handle = input.cellResourceAuthority;
  const state = handle !== null && typeof handle === "object"
    ? RELEASE_RESOURCE_AUTHORITIES.get(handle)
    : undefined;
  if (state === undefined) fail("brand_invalid");
  const plan = verifyPilotPlanV1(input.plan);
  if (state.status !== "ready") fail("not_ready_or_already_consumed");
  if (handle.authority_class !== AUTHORITY_CLASS
    || handle.plan_sha256 !== plan.plan_sha256
    || handle.pilot_id !== plan.pilot_id
    || handle.execution_manifest_sha256 !== state.executionManifest.manifest_report_sha256
    || handle.resource_count !== plan.schedule.length
    || handle.resource_authority_closure_sha256 !== canonicalSha256(state.closure)) {
    fail("live_binding_invalid");
  }
  state.status = "claimed";
  return Object.freeze({
    executionManifest: state.executionManifest,
    resources: state.resources,
    async disposeAll() { return disposeState(state); },
    verifyDisposed() {
      if (state.status !== "disposed" || state.disposalReceipt === null) {
        fail("disposal_not_confirmed");
      }
      return canonicalClone(state.disposalReceipt);
    },
  });
}

export async function disposeReleaseCellResourceAuthorityV1(value) {
  const state = value !== null && typeof value === "object"
    ? RELEASE_RESOURCE_AUTHORITIES.get(value)
    : undefined;
  if (state === undefined) fail("brand_invalid");
  const receipt = await disposeState(state);
  if (receipt?.cleanup_confirmed !== true) fail("disposal_incomplete");
  return receipt;
}

function caseAuthorities(cases) {
  return cases.map((pilotCase) => canonicalClone({
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
}

function closeOwnersInReverse(runtimeOwner, workspaceOwner) {
  let closePromise = null;
  return () => {
    if (closePromise === null) {
      closePromise = (async () => {
        const closedOwnerKinds = [];
        const failedOwnerKinds = [];
        for (const [kind, close] of [
          ["runtime_owner", () => disposeReleaseRuntimeOciResourceOwnerV1(runtimeOwner)],
          ["workspace_owner", () => disposeReleaseWorkspaceResourceOwnerV1(workspaceOwner)],
        ]) {
          try {
            await close();
            closedOwnerKinds.push(kind);
          } catch {
            failedOwnerKinds.push(kind);
          }
        }
        return buildOwnerCleanupReceiptV1({
          ownerKinds: ["runtime_owner", "workspace_owner"],
          closedOwnerKinds,
          failedOwnerKinds,
        });
      })();
    }
    return closePromise;
  };
}

function verifyCases(plan, values) {
  const cases = expectArray(values, "release_cell_provisioner_cases", {
    minimum: plan.cases.length,
    maximum: plan.cases.length,
  }).map((value) => verifyPilotCaseV1(value));
  if (cases.length !== plan.cases.length
    || cases.some((pilotCase, index) => pilotCase.case_id !== plan.cases[index].case_id
      || pilotCase.case_sha256 !== plan.cases[index].case_sha256)) {
    fail("plan_case_binding_invalid");
  }
  return cases;
}

function verifyWorkspaceOwner(value, plan) {
  const owner = expectExactRecord(value, WORKSPACE_OWNER_KEYS, "workspace_owner");
  if (owner.schema_version !== "aionis_release_workspace_resources_v1"
    || owner.plan_sha256 !== plan.plan_sha256
    || !/^[0-9a-f]{32}$/u.test(owner.owner_id)
    || expectSha256(owner.owner_manifest_sha256, "workspace_owner_manifest_sha256")
      !== owner.owner_manifest_sha256
    || typeof owner.closeAll !== "function") fail("workspace_owner_binding_invalid");
  const resources = expectArray(owner.resources, "workspace_owner_resources", {
    minimum: plan.schedule.length,
    maximum: plan.schedule.length,
  });
  const authorities = expectArray(owner.authorities, "workspace_owner_authorities", {
    minimum: plan.schedule.length,
    maximum: plan.schedule.length,
  });
  if (resources.length !== plan.schedule.length || authorities.length !== resources.length) {
    fail("workspace_owner_count_invalid");
  }
  return owner;
}

function verifyRuntimeOwner(value, plan) {
  const owner = expectExactRecord(value, RUNTIME_OWNER_KEYS, "runtime_owner");
  if (owner.schema_version !== "aionis_release_runtime_oci_resources_v1"
    || owner.plan_sha256 !== plan.plan_sha256
    || !/^[0-9a-f]{32}$/u.test(owner.owner_id)
    || owner.owner_id !== owner.ownerId
    || owner.owner_manifest_sha256 !== owner.ownerManifestSha256
    || expectSha256(owner.owner_manifest_sha256, "runtime_owner_manifest_sha256")
      !== owner.owner_manifest_sha256
    || typeof owner.closeAll !== "function") fail("runtime_owner_binding_invalid");
  const brokers = expectArray(owner.brokers, "runtime_owner_brokers", {
    minimum: plan.schedule.length,
    maximum: plan.schedule.length,
  });
  const authorities = expectArray(owner.authorities, "runtime_owner_authorities", {
    minimum: plan.schedule.length,
    maximum: plan.schedule.length,
  });
  if (brokers.length !== plan.schedule.length || authorities.length !== brokers.length) {
    fail("runtime_owner_count_invalid");
  }
  return owner;
}

function mapWorkspaceResource(owner, cell, pilotCase, index) {
  const resource = expectExactRecord(owner.resources[index], [
    "authority", "cell", "close", "inodeSet", "pilotCase", "workspaceEvidence", "workspacePath",
  ], `workspace_resource_${index}`);
  const authority = expectExactRecord(owner.authorities[index], [
    "authority_sha256", "case_id", "case_sha256", "cell_sha256", "opaque_cell_id", "ordinal",
    "schema_version", "source_fixture_sha256", "source_template_clean_status_sha256",
    "source_template_head_sha", "source_template_realpath_sha256", "workspace_identity",
    "workspace_instance_id", "workspace_path", "workspace_prepared_inode_set_sha256",
    "workspace_prepared_sha256",
  ], `workspace_authority_${index}`);
  if (canonicalJson(resource.authority) !== canonicalJson(authority)
    || typeof resource.close !== "function"
    || resource.workspacePath !== authority.workspace_path
    || authority.schema_version !== "aionis_release_workspace_authority_v1"
    || authority.ordinal !== cell.ordinal
    || authority.opaque_cell_id !== cell.opaque_cell_id
    || authority.case_id !== pilotCase.case_id
    || authority.case_sha256 !== pilotCase.case_sha256
    || authority.workspace_instance_id !== cell.isolation.workspace_instance_id
    || authority.workspace_prepared_sha256 !== pilotCase.workspace.prepared_tree_sha256
    || authority.source_fixture_sha256 !== pilotCase.source_fixture.fixture_sha256) {
    fail("workspace_resource_binding_invalid");
  }
  return { authority, close: resource.close };
}

function mapRuntimeResource(owner, cell, policyBinding, index) {
  const broker = expectExactRecord(owner.brokers[index], [
    "client", "close", "containerAuthority", "dataPath",
  ], `runtime_broker_${index}`);
  const authority = owner.authorities[index];
  if (canonicalJson(broker.containerAuthority) !== canonicalJson(authority)
    || typeof broker.close !== "function"
    || broker.dataPath !== authority.runtime_database_path
    || authority.schema_version !== "aionis_release_runtime_container_authority_v1"
    || authority.ordinal !== cell.ordinal
    || authority.opaque_cell_id !== cell.opaque_cell_id
    || authority.runtime_scope !== cell.isolation.runtime_scope
    || authority.runtime_database_id !== cell.isolation.runtime_database_id
    || authority.isolation_sha256 !== cell.isolation.isolation_sha256
    || authority.authority_subject_sha256 !== policyBinding.authority_subject_sha256
    || authority.provisioning_command_sha256 !== policyBinding.provisioning_command_sha256
    || canonicalJson(authority.compiler_policy_ref)
      !== canonicalJson(policyBinding.compiler_policy_ref)
    || canonicalJson(authority.evidence_policy_ref)
      !== canonicalJson(policyBinding.evidence_policy_ref)
    || authority.oci_runtime_authority_sha256 !== owner.ociRuntimeAuthority.authority_sha256) {
    fail("runtime_resource_binding_invalid");
  }
  return { authority, broker };
}

function verifyVerifierResources(values, cases) {
  const entries = expectArray(values, "release_verifier_resources", {
    minimum: cases.length,
    maximum: cases.length,
  });
  if (entries.length !== cases.length) fail("verifier_resource_count_invalid");
  return entries.map((value, index) => {
    const item = expectExactRecord(value, [
      "caseId", "privateKeyFd", "verifierConfig", "verifierPublicKey",
    ], `release_verifier_resource_${index}`);
    const pilotCase = cases[index];
    if (item.caseId !== pilotCase.case_id) fail("verifier_case_order_invalid");
    const configSha256 = ociPrivateVerifierConfigSha256V1(item.verifierConfig);
    const publicPrincipal = verifierPublicKeyPrincipalSha256V1(item.verifierPublicKey);
    if (configSha256 !== pilotCase.private_verifier.verifier_config_sha256
      || publicPrincipal !== pilotCase.private_verifier.verifier_public_key_principal_sha256) {
      fail("verifier_resource_binding_invalid");
    }
    return Object.freeze({
      caseId: item.caseId,
      privateKeyFd: assertExistingOciVerifierPrivateKeyFdV1(item.privateKeyFd),
      verifierConfig: canonicalClone(item.verifierConfig),
      verifierPublicKey: item.verifierPublicKey,
      publicPrincipal,
    });
  });
}

function verifierForCase(verifiers, pilotCase) {
  const verifier = verifiers.find((entry) => entry.caseId === pilotCase.case_id);
  if (verifier === undefined) fail("verifier_case_missing");
  return verifier;
}

function provisionerClosure(
  plan,
  policyBundleSet,
  workspaceOwner,
  runtimeOwner,
  attestations,
  evalRepositoryProvenance,
) {
  return canonicalSha256({
    schema_version: "aionis_release_cell_resource_provisioner_closure_v1",
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    policy_bundle_set_sha256: policyBundleSet.policy_bundle_set_sha256,
    workspace_authority_set_sha256: workspaceOwner.workspace_authority_set_sha256,
    runtime_container_authority_set_sha256: runtimeOwner.containerAuthoritySetSha256,
    orchestration_owner_id: runtimeOwner.owner_id,
    workspace_owner_manifest_sha256: workspaceOwner.owner_manifest_sha256,
    runtime_owner_manifest_sha256: runtimeOwner.owner_manifest_sha256,
    oci_runtime_authority_sha256: runtimeOwner.ociRuntimeAuthority.authority_sha256,
    eval_repository_provenance_sha256: evalRepositoryProvenance.provenance_sha256,
    verifier_private_key_attestations: attestations.map((value) => canonicalClone(value)),
  });
}

/**
 * The formal composition boundary. Owners must already represent live Runtime
 * containers and private workspaces; this function accepts no provider, SDK,
 * fetch, clock, or adapter factory. It attests every private verifier FD
 * before constructing an adapter, then obtains the release manifest through
 * the same live verifier used by the runner.
 */
export async function provisionReleaseCellResourcesV1(options) {
  const input = expectExactRecord(options, [
    "cases", "evalProvenanceAuthority", "gitExecutablePath", "plan", "policyBundleSet",
    "runtimeOwner", "verifierResources", "workspaceOwner",
  ], "release_cell_resource_provisioner_input");
  const plan = verifyPilotPlanV1(input.plan);
  const closeOwners = closeOwnersInReverse(input.runtimeOwner, input.workspaceOwner);
  let transferred = false;
  try {
    const cases = verifyCases(plan, input.cases);
    // Validate and attest FDs before inspecting/using either prepared owner.
    // This makes a wrong verifier key fail without a Runtime client call.
    const verifiers = verifyVerifierResources(input.verifierResources, cases);
    const attestations = [];
    for (const verifier of verifiers) {
      attestations.push(await attestOciVerifierPrivateKeyFdV1({
        privateKeyFd: verifier.privateKeyFd,
        expectedPublicKeyPrincipalSha256: verifier.publicPrincipal,
      }));
    }
    const policyBundleSet = verifyReleaseCellPolicyBundleSetV1({
      plan,
      policyBundleSet: input.policyBundleSet,
    });
    const evalRepositoryProvenance =
      await verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1({
        plan,
        provenanceAuthority: input.evalProvenanceAuthority,
      });
    const workspaceOwner = verifyWorkspaceOwner(
      claimReleaseWorkspaceResourceOwnerV1({
        plan,
        workspaceOwner: input.workspaceOwner,
      }),
      plan,
    );
    const runtimeOwner = verifyRuntimeOwner(
      claimReleaseRuntimeOciResourceOwnerV1({
        plan,
        runtimeOwner: input.runtimeOwner,
      }),
      plan,
    );
    if (workspaceOwner.owner_id !== runtimeOwner.owner_id) {
      fail("orchestration_owner_cross_binding_invalid");
    }
    const gitExecutablePath = expectText(input.gitExecutablePath, "git_executable_path", {
      maximumBytes: 16_384,
    });

    const caseById = new Map(cases.map((pilotCase) => [pilotCase.case_id, pilotCase]));
    const resources = [];
    const cellAuthorities = [];
    for (const [index, cell] of plan.schedule.entries()) {
      const pilotCase = caseById.get(cell.case_id);
      const policyBinding = policyBundleSet.bindings[index];
      if (pilotCase === undefined || policyBinding === undefined
        || policyBinding.opaque_cell_id !== cell.opaque_cell_id) {
        fail("cell_composition_binding_invalid");
      }
      const workspace = mapWorkspaceResource(
        workspaceOwner,
        cell,
        pilotCase,
        index,
      );
      const runtime = mapRuntimeResource(runtimeOwner, cell, policyBinding, index);
      const executionAuthority = await buildAgentExecutionAuthorityV1({
        cell,
        pilotCase,
        workspacePath: workspace.authority.workspace_path,
        gitExecutablePath,
      });
      if (executionAuthority.git_executable_path
          !== evalRepositoryProvenance.git_executable_path
        || executionAuthority.git_executable_sha256
          !== evalRepositoryProvenance.git_executable_sha256
        || executionAuthority.git_executable_identity_sha256
          !== evalRepositoryProvenance.git_executable_identity_sha256) {
        fail("execution_authority_git_binding_invalid");
      }
      if (executionAuthority.workspace_prepared_sha256
          !== workspace.authority.workspace_prepared_sha256
        || executionAuthority.workspace_prepared_inode_set_sha256
          !== workspace.authority.workspace_prepared_inode_set_sha256) {
        fail("execution_authority_workspace_binding_invalid");
      }
      const verifier = verifierForCase(verifiers, pilotCase);
      const adapter = createRuntimeV1HostAdapter({
        cell,
        client: runtime.broker.client,
        pilotCase,
        scope: cell.isolation.runtime_scope,
        verifierPublicKey: verifier.verifierPublicKey,
      });
      let cellClosePromise = null;
      const adapterWithRuntimeClose = Object.freeze({
        prepareArm: adapter.prepareArm,
        ...(cell.arm === "treatment" ? { settleTreatment: adapter.settleTreatment } : {}),
        close() {
          if (cellClosePromise === null) {
            cellClosePromise = (async () => {
              const errors = [];
              for (const close of [runtime.broker.close, workspace.close]) {
                try { await close(); } catch (error) { errors.push(error); }
              }
              if (errors.length > 0) {
                throw new AggregateError(
                  errors,
                  "aionis_eval_release_cell_resource_provisioner_cell_cleanup_failed",
                );
              }
            })();
          }
          return cellClosePromise;
        },
      });
      resources.push({
        adapter: adapterWithRuntimeClose,
        executionAuthority,
        ociRuntimeAuthority: canonicalClone(runtimeOwner.ociRuntimeAuthority),
        verifierConfig: verifier.verifierConfig,
        verifierPublicKey: verifier.verifierPublicKey,
        runVerifier: (verifierInput) => runOciPrivateVerifierProcessV1({
          input: verifierInput,
          privateKeyFd: verifier.privateKeyFd,
        }),
      });
      cellAuthorities.push(canonicalClone({
        opaque_cell_id: cell.opaque_cell_id,
        runtime_scope: cell.isolation.runtime_scope,
        runtime_database_id: cell.isolation.runtime_database_id,
        runtime_database_path: runtime.authority.runtime_database_path,
        workspace_instance_id: cell.isolation.workspace_instance_id,
        workspace_path: workspace.authority.workspace_path,
        agent_execution_authority: executionAuthority,
        agent_process_id: cell.isolation.agent_process_id,
        agent_exit_authority_principal_sha256:
          cell.isolation.agent_exit_authority_principal_sha256,
        isolation_sha256: cell.isolation.isolation_sha256,
        authority_subject_sha256: policyBinding.authority_subject_sha256,
        provisioning_command_sha256: policyBinding.provisioning_command_sha256,
        compiler_policy_ref: policyBinding.compiler_policy_ref,
        evidence_policy_ref: policyBinding.evidence_policy_ref,
      }));
    }

    const runnerAuthority = canonicalClone({
      schema_version: "aionis_pilot_runner_authority_v1",
      eval_binding: plan.eval_binding,
      eval_repository_provenance: evalRepositoryProvenance,
      runtime_binding: plan.runtime_binding,
      oci_runtime_authority: runtimeOwner.ociRuntimeAuthority,
      provider: {
        endpoint: plan.model_protocol.endpoint,
        requested_model: plan.model_protocol.requested_model,
        maximum_provider_request_attempt_count:
          plan.model_protocol.maximum_provider_request_attempt_count,
      },
      case_authorities: caseAuthorities(cases),
      cell_authorities: cellAuthorities,
    });
    const executionManifest = await preflightPilotExecutionManifestV1({
      authority: runnerAuthority,
      cases,
      plan,
    });
    const handle = issueReleaseCellResourceAuthority({
      plan,
      executionManifest,
      resources,
      provisionerClosureSha256: provisionerClosure(
        plan,
        policyBundleSet,
        workspaceOwner,
        runtimeOwner,
        attestations,
        evalRepositoryProvenance,
      ),
      disposeAll: closeOwners,
    });
    transferred = true;
    return Object.freeze({
      schema_version: "aionis_release_cell_resource_provisioning_result_v1",
      cellResourceAuthority: handle,
      executionManifest: deepFreeze(canonicalClone(executionManifest)),
    });
  } catch (error) {
    const cleanupReceipt = await closeOwners();
    if (!cleanupReceipt.cleanup_confirmed) {
      throw new AggregateError(
        [error, new Error("aionis_eval_release_cell_resource_provisioner_cleanup_incomplete")],
        "aionis_eval_release_cell_resource_provisioner_provision_and_cleanup_failed",
      );
    }
    throw error;
  } finally {
    if (!transferred) await closeOwners();
  }
}
