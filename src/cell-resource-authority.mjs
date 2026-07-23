import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectExactRecord,
  expectSha256,
} from "./canonical.mjs";
import {
  OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  ociPrivateVerifierConfigSha256V1,
  runNonReleaseContractTestOciPrivateVerifierProcessV1,
} from "./oci-verifier-process.mjs";
import { verifyPilotPlanV1 } from "./pilot-contract.mjs";
import {
  verifierPublicKeyPrincipalSha256V1,
} from "./verifier-evidence.mjs";

const NON_RELEASE_AUTHORITY_CLASS =
  "non_release_contract_test_cell_resource_authority_v1";
const NON_RELEASE_RESOURCE_SETS = new WeakMap();

function fail(code) {
  throw new Error(`aionis_eval_cell_resource_authority_${code}`);
}

function verifyExecutionManifest(value, plan) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("execution_manifest_invalid");
  }
  if (value.schema_version !== "aionis_pilot_execution_manifest_report_v1"
    || value.status !== "execution_manifest_verified"
    || value.evidence_authority_class !== "non_release_contract_test_authority_v1"
    || value.plan_sha256 !== plan.plan_sha256
    || value.pilot_id !== plan.pilot_id
    || value.cell_count !== plan.schedule.length) {
    fail("execution_manifest_non_release_binding_invalid");
  }
  expectSha256(value.manifest_report_sha256, "cell_resource_manifest_report_sha256");
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== "manifest_report_sha256"),
  );
  if (canonicalSha256(body) !== value.manifest_report_sha256) {
    fail("execution_manifest_integrity_invalid");
  }
  const authority = value.runner_authority;
  if (authority === null || typeof authority !== "object" || Array.isArray(authority)
    || !Array.isArray(authority.cell_authorities)
    || !Array.isArray(authority.case_authorities)
    || authority.cell_authorities.length !== plan.schedule.length
    || authority.oci_runtime_authority?.authority_class
      !== OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1) {
    fail("execution_manifest_resource_closure_invalid");
  }
  return value;
}

function captureAdapter(adapterValue, cell) {
  if (adapterValue === null || typeof adapterValue !== "object"
    || Array.isArray(adapterValue)
    || typeof adapterValue.prepareArm !== "function"
    || (cell.arm === "treatment" && typeof adapterValue.settleTreatment !== "function")) {
    fail("adapter_invalid");
  }
  const prepareArm = adapterValue.prepareArm.bind(adapterValue);
  const settleTreatment = typeof adapterValue.settleTreatment === "function"
    ? adapterValue.settleTreatment.bind(adapterValue)
    : null;
  const close = typeof adapterValue.close === "function"
    ? adapterValue.close.bind(adapterValue)
    : null;
  return Object.freeze({
    prepareArm,
    ...(settleTreatment === null ? {} : { settleTreatment }),
    ...(close === null ? {} : { close }),
  });
}

function captureResource(value, cell, manifest, caseAuthoritiesById, index) {
  const resource = expectExactRecord(value, [
    "adapter",
    "executionAuthority",
    "ociRuntimeAuthority",
    "verifierConfig",
    "verifierPrivateKey",
    "verifierPublicKey",
  ], `non_release_cell_resource_${index}`);
  const cellAuthority = manifest.runner_authority.cell_authorities[index];
  const caseAuthority = caseAuthoritiesById.get(cell.case_id);
  if (cellAuthority === undefined || caseAuthority === undefined) {
    fail("manifest_cell_resource_missing");
  }
  const executionAuthority = resource.executionAuthority;
  const ociRuntimeAuthority = resource.ociRuntimeAuthority;
  if (canonicalJson(executionAuthority)
      !== canonicalJson(cellAuthority.agent_execution_authority)
    || canonicalJson(ociRuntimeAuthority)
      !== canonicalJson(manifest.runner_authority.oci_runtime_authority)) {
    fail("manifest_cell_resource_binding_invalid");
  }
  const verifierConfigSha256 = ociPrivateVerifierConfigSha256V1(
    resource.verifierConfig,
  );
  const publicKeyPrincipalSha256 = verifierPublicKeyPrincipalSha256V1(
    resource.verifierPublicKey,
  );
  const privateKeyPrincipalSha256 = verifierPublicKeyPrincipalSha256V1(
    resource.verifierPrivateKey,
  );
  if (verifierConfigSha256 !== caseAuthority.verifier_config_sha256
    || publicKeyPrincipalSha256
      !== caseAuthority.verifier_public_key_principal_sha256
    || privateKeyPrincipalSha256 !== publicKeyPrincipalSha256) {
    fail("verifier_resource_binding_invalid");
  }
  const closure = canonicalClone({
    ordinal: index + 1,
    opaque_cell_id: cell.opaque_cell_id,
    cell_sha256: canonicalSha256(cell),
    adapter_boundary: "caller_injected_non_release_contract_test_adapter",
    execution_authority_sha256: executionAuthority.authority_sha256,
    oci_runtime_authority_sha256: ociRuntimeAuthority.authority_sha256,
    verifier_config_sha256: verifierConfigSha256,
    verifier_public_key_principal_sha256: publicKeyPrincipalSha256,
  });
  return {
    closure,
    resource: Object.freeze({
      adapter: captureAdapter(resource.adapter, cell),
      executionAuthority: canonicalClone(executionAuthority),
      ociRuntimeAuthority: canonicalClone(ociRuntimeAuthority),
      verifierConfig: canonicalClone(resource.verifierConfig),
      verifierPublicKey: resource.verifierPublicKey,
      runVerifier: (input) => runNonReleaseContractTestOciPrivateVerifierProcessV1({
        input,
        privateKey: resource.verifierPrivateKey,
      }),
    }),
  };
}

export function buildNonReleaseContractTestCellResourceAuthorityV1(options) {
  const input = expectExactRecord(options, [
    "cellResources", "executionManifest", "plan",
  ], "non_release_cell_resource_authority_input");
  const plan = verifyPilotPlanV1(input.plan);
  const manifest = verifyExecutionManifest(input.executionManifest, plan);
  const values = expectArray(input.cellResources, "non_release_cell_resources", {
    minimum: plan.schedule.length,
    maximum: plan.schedule.length,
  });
  const caseAuthoritiesById = new Map(
    manifest.runner_authority.case_authorities.map((authority) => [
      authority.case_id,
      authority,
    ]),
  );
  const captured = plan.schedule.map((cell, index) => captureResource(
    values[index],
    cell,
    manifest,
    caseAuthoritiesById,
    index,
  ));
  const closure = canonicalClone({
    schema_version: "aionis_non_release_cell_resource_closure_v1",
    authority_class: NON_RELEASE_AUTHORITY_CLASS,
    claim_eligible: false,
    plan_sha256: plan.plan_sha256,
    execution_manifest_sha256: manifest.manifest_report_sha256,
    cell_resources: captured.map((entry) => entry.closure),
  });
  const handle = Object.freeze({
    schema_version: "aionis_non_release_cell_resource_authority_handle_v1",
    authority_class: NON_RELEASE_AUTHORITY_CLASS,
    claim_eligible: false,
    plan_sha256: plan.plan_sha256,
    execution_manifest_sha256: manifest.manifest_report_sha256,
    resource_count: captured.length,
    resource_authority_closure_sha256: canonicalSha256(closure),
  });
  NON_RELEASE_RESOURCE_SETS.set(handle, Object.freeze({
    closure,
    resources: Object.freeze(captured.map((entry) => entry.resource)),
  }));
  return handle;
}

export function resolveNonReleaseContractTestCellResourcesV1(
  value,
  { executionManifest, plan: planValue },
) {
  const branded = value !== null && typeof value === "object"
    ? NON_RELEASE_RESOURCE_SETS.get(value)
    : undefined;
  if (branded === undefined) fail("non_release_brand_invalid");
  const plan = verifyPilotPlanV1(planValue);
  const manifest = verifyExecutionManifest(executionManifest, plan);
  if (value.plan_sha256 !== plan.plan_sha256
    || value.execution_manifest_sha256 !== manifest.manifest_report_sha256
    || value.resource_count !== plan.schedule.length
    || value.resource_authority_closure_sha256 !== canonicalSha256(branded.closure)) {
    fail("non_release_live_binding_invalid");
  }
  return branded.resources;
}
