import { createPublicKey, randomBytes } from "node:crypto";
import { constants, fstatSync } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

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
  assertExistingDeepSeekApiKeyFdV1,
  attestDeepSeekApiKeyFdV1,
} from "./deepseek-provider.mjs";
import { runExecutablePilotWithCancellationV1 } from "./executable-pilot-runner.mjs";
import {
  assertExistingRunnerSigningKeyFdV1,
  attestRunnerSigningKeyFdV1,
  runSealedPilotExecutionAuthorizationSignerProcessV1,
} from "./final-signer-process.mjs";
import {
  assertExistingOciVerifierPrivateKeyFdV1,
  attestOciVerifierPrivateKeyFdV1,
  ociPrivateVerifierConfigSha256V1,
} from "./oci-verifier-process.mjs";
import { verifyPilotCaseV1, verifyPilotPlanV1 } from "./pilot-contract.mjs";
import { preflightPilotArtifactsV1 } from "./pilot-preflight.mjs";
import {
  RELEASE_CLEANUP_OWNER_KINDS_V1,
  verifyOwnerCleanupReceiptV1,
} from "./pilot-run-event-contract.mjs";
import {
  disposeReleaseCellResourceAuthorityV1,
  provisionReleaseCellResourcesV1,
} from "./release-cell-resource-provisioner.mjs";
import { verifyReleaseCellPolicyBundleSetV1 } from "./release-policy-bundle-set.mjs";
import {
  disposeReleaseRuntimeOciResourceOwnerV1,
  prepareReleaseRuntimeOciResourcesV1,
  reconcileReleaseRuntimeOciOwnerV1,
} from "./release-runtime-oci-resource.mjs";
import {
  readActiveReleaseRuntimeOwnerManifestV1,
} from "./release-runtime-owner-manifest.mjs";
import {
  issueCurrentReleaseEvalRepositoryProvenanceV1,
  verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1,
} from "./release-eval-repository-provenance.mjs";
import {
  assertReleasePilotCancellationAuthorityV1,
  checkpointReleasePilotCancellationV1,
  createReleasePilotCancellationAuthorityV1,
} from "./release-pilot-cancellation.mjs";
import {
  issueTrustedReleaseSdkClientAuthorityV1,
} from "./release-sdk-client-authority.mjs";
import {
  disposeReleaseWorkspaceResourceOwnerV1,
  materializeReleasePilotWorkspacesV1,
} from "./release-workspace-resource.mjs";
import {
  readActiveReleaseWorkspaceOwnerManifestV1,
  reconcileReleaseWorkspaceOwnerV1,
} from "./release-workspace-owner-manifest.mjs";
import {
  runnerAuthorityPublicKeyPrincipalSha256V1,
} from "./runner-signature.mjs";
import {
  verifierPublicKeyPrincipalSha256V1,
} from "./verifier-evidence.mjs";

const MAX_PUBLIC_ARTIFACT_BYTES = 33_554_432;
const FORBIDDEN_SECRET_ENVIRONMENT_FIELDS = Object.freeze([
  "AIONIS_DEEPSEEK_API_KEY",
  "AIONIS_RUNNER_SIGNING_KEY",
  "AIONIS_RUNNER_SIGNING_KEY_PATH",
  "DEEPSEEK_API_KEY",
  "RUNNER_SIGNING_KEY",
  "RUNNER_SIGNING_KEY_PATH",
  "VERIFIER_PRIVATE_KEY",
  "VERIFIER_PRIVATE_KEY_PATH",
]);
const FORBIDDEN_ENVIRONMENT_NAME_PATTERNS = Object.freeze([
  /^NODE_/u,
  /^(?:SSLKEYLOGFILE|OPENSSL_CONF|SSL_CERT_FILE|SSL_CERT_DIR)$/u,
  /^(?:HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$/u,
  /^DYLD_/u,
  /^(?:LD_PRELOAD|LD_LIBRARY_PATH)$/u,
]);

function fail(code) {
  throw new Error(`aionis_eval_release_pilot_orchestrator_${code}`);
}

function requireConfirmedCellCleanupReceipt(value) {
  const receipt = verifyOwnerCleanupReceiptV1(value, {
    ownerKinds: RELEASE_CLEANUP_OWNER_KINDS_V1,
  });
  if (receipt.cleanup_confirmed !== true) fail("cell_resource_cleanup_incomplete");
  return receipt;
}

export function assertReleasePilotEnvironmentV1(environment) {
  if (environment === null || typeof environment !== "object"
    || Array.isArray(environment)) fail("environment_invalid");
  const forbiddenSecretNames = new Set(
    FORBIDDEN_SECRET_ENVIRONMENT_FIELDS.map((name) => name.toUpperCase()),
  );
  for (const name of Object.keys(environment)) {
    const normalized = name.toUpperCase();
    if (forbiddenSecretNames.has(normalized)
      || FORBIDDEN_ENVIRONMENT_NAME_PATTERNS.some((pattern) => pattern.test(normalized))) {
      fail("unsafe_environment_forbidden");
    }
  }
  return true;
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function canonicalAbsolutePath(value, field) {
  const text = expectText(value, field, { maximumBytes: 16_384 });
  if (!path.isAbsolute(text) || path.normalize(text) !== text) fail(`${field}_invalid`);
  return text;
}

async function readCanonicalPublicArtifact(fileValue, field) {
  const file = canonicalAbsolutePath(fileValue, `${field}_path`);
  let resolved;
  let pathStat;
  try {
    resolved = await realpath(file);
    pathStat = await lstat(file, { bigint: true });
  } catch {
    fail(`${field}_missing`);
  }
  if (resolved !== file || !pathStat.isFile() || pathStat.isSymbolicLink()
    || pathStat.nlink !== 1n
    || (typeof process.getuid === "function" && pathStat.uid !== BigInt(process.getuid()))
    || pathStat.size < 3n || pathStat.size > BigInt(MAX_PUBLIC_ARTIFACT_BYTES)) {
    fail(`${field}_posture_invalid`);
  }
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    fail("no_follow_unsupported");
  }
  let handle;
  let bytes;
  try {
    handle = await open(
      file,
      constants.O_RDONLY | constants.O_NOFOLLOW
        | (Number.isInteger(constants.O_NONBLOCK) ? constants.O_NONBLOCK : 0),
    );
    const before = await handle.stat({ bigint: true });
    if (!sameSnapshot(pathStat, before)) fail(`${field}_identity_changed`);
    bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(file, { bigint: true });
    if (!sameSnapshot(before, after) || !sameSnapshot(after, afterPath)) {
      fail(`${field}_changed_during_read`);
    }
    let value;
    try { value = JSON.parse(bytes.toString("utf8")); } catch { fail(`${field}_invalid`); }
    if (bytes.toString("utf8") !== `${canonicalJson(value)}\n`) {
      fail(`${field}_not_canonical`);
    }
    return value;
  } finally {
    bytes?.fill(0);
    await handle?.close().catch(() => {});
  }
}

function selfHashedArtifact(value, keys, schema, field) {
  const artifact = expectExactRecord(value, [...keys, "artifact_sha256"], field);
  if (artifact.schema_version !== schema) fail(`${field}_schema_invalid`);
  expectSha256(artifact.artifact_sha256, `${field}_artifact_sha256`);
  const body = Object.fromEntries(
    Object.entries(artifact).filter(([key]) => key !== "artifact_sha256"),
  );
  if (canonicalSha256(body) !== artifact.artifact_sha256) {
    fail(`${field}_integrity_invalid`);
  }
  return artifact;
}

function decodeEd25519PublicKey(value, field) {
  const encoded = expectText(value, field, { maximumBytes: 2_048 });
  if (!/^[A-Za-z0-9_-]+$/u.test(encoded)) fail(`${field}_invalid`);
  let bytes;
  try {
    bytes = Buffer.from(encoded, "base64url");
    if (bytes.toString("base64url") !== encoded) fail(`${field}_invalid`);
    const key = createPublicKey({ key: bytes, format: "der", type: "spki" });
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      fail(`${field}_invalid`);
    }
    return key;
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_release_pilot_orchestrator_")) throw error;
    fail(`${field}_invalid`);
  } finally {
    bytes?.fill(0);
  }
}

function verifyRunnerPublicArtifact(value, plan) {
  const artifact = selfHashedArtifact(value, [
    "runner_public_key_principal_sha256",
    "runner_public_key_spki_der_base64url",
    "schema_version",
  ], "aionis_release_runner_public_authority_artifact_v1", "runner_public_artifact");
  const principal = expectSha256(
    artifact.runner_public_key_principal_sha256,
    "runner_public_key_principal_sha256",
  );
  const publicKey = decodeEd25519PublicKey(
    artifact.runner_public_key_spki_der_base64url,
    "runner_public_key_spki_der_base64url",
  );
  if (runnerAuthorityPublicKeyPrincipalSha256V1(publicKey) !== principal
    || principal !== plan.eval_binding.runner_authority_public_key_principal_sha256) {
    fail("runner_public_artifact_plan_binding_invalid");
  }
  return Object.freeze({ artifact: canonicalClone(artifact), publicKey, principal });
}

function verifyVerifierPublicArtifact(value, pilotCase) {
  const artifact = selfHashedArtifact(value, [
    "case_id",
    "schema_version",
    "verifier_config",
    "verifier_config_sha256",
    "verifier_public_key_principal_sha256",
    "verifier_public_key_spki_der_base64url",
  ], "aionis_release_verifier_public_authority_artifact_v1", "verifier_public_artifact");
  const publicKey = decodeEd25519PublicKey(
    artifact.verifier_public_key_spki_der_base64url,
    "verifier_public_key_spki_der_base64url",
  );
  const principal = expectSha256(
    artifact.verifier_public_key_principal_sha256,
    "verifier_public_key_principal_sha256",
  );
  const configSha256 = ociPrivateVerifierConfigSha256V1(artifact.verifier_config);
  if (artifact.case_id !== pilotCase.case_id
    || artifact.verifier_config_sha256 !== configSha256
    || configSha256 !== pilotCase.private_verifier.verifier_config_sha256
    || verifierPublicKeyPrincipalSha256V1(publicKey) !== principal
    || principal !== pilotCase.private_verifier.verifier_public_key_principal_sha256) {
    fail("verifier_public_artifact_case_binding_invalid");
  }
  return Object.freeze({
    artifact: canonicalClone(artifact),
    caseId: pilotCase.case_id,
    config: canonicalClone(artifact.verifier_config),
    publicKey,
    principal,
  });
}

function verifyConfig(value) {
  const config = selfHashedArtifact(value, [
    "authority_root",
    "case_artifact_paths",
    "git_executable_path",
    "oci_executable_path",
    "pilot_plan_artifact_path",
    "policy_bundle_set_artifact_path",
    "private_run_root",
    "runner_public_authority_artifact_path",
    "runtime_image_reference",
    "schema_version",
    "sdk_consumer_root",
    "sdk_tarball_path",
    "trust_root_public_key_path",
    "verifier_public_authority_artifact_paths",
    "workspace_templates",
  ], "aionis_release_pilot_orchestration_config_v1", "release_pilot_config");
  for (const field of [
    "authority_root", "git_executable_path", "oci_executable_path",
    "pilot_plan_artifact_path", "policy_bundle_set_artifact_path", "private_run_root",
    "runner_public_authority_artifact_path", "sdk_consumer_root", "sdk_tarball_path",
    "trust_root_public_key_path",
  ]) canonicalAbsolutePath(config[field], field);
  expectText(config.runtime_image_reference, "runtime_image_reference", {
    maximumBytes: 2_048,
  });
  const casePaths = expectArray(config.case_artifact_paths, "case_artifact_paths", {
    minimum: 3,
    maximum: 3,
  }).map((entry, index) => canonicalAbsolutePath(entry, `case_artifact_path_${index}`));
  const verifierPaths = expectArray(
    config.verifier_public_authority_artifact_paths,
    "verifier_public_authority_artifact_paths",
    { minimum: 3, maximum: 3 },
  ).map((entry, index) => canonicalAbsolutePath(
    entry,
    `verifier_public_authority_artifact_path_${index}`,
  ));
  if (new Set(casePaths).size !== 3 || new Set(verifierPaths).size !== 3) {
    fail("public_artifact_path_reuse");
  }
  const templates = expectArray(config.workspace_templates, "workspace_templates", {
    minimum: 3,
    maximum: 3,
  }).map((entry, index) => {
    const item = expectExactRecord(entry, [
      "case_id", "workspace_template_path",
    ], `workspace_template_${index}`);
    return {
      case_id: expectText(item.case_id, `workspace_template_${index}_case_id`),
      workspace_template_path: canonicalAbsolutePath(
        item.workspace_template_path,
        `workspace_template_${index}_path`,
      ),
    };
  });
  if (new Set(templates.map((entry) => entry.case_id)).size !== 3
    || new Set(templates.map((entry) => entry.workspace_template_path)).size !== 3) {
    fail("workspace_template_reuse");
  }
  return canonicalClone({ ...config, case_artifact_paths: casePaths,
    verifier_public_authority_artifact_paths: verifierPaths, workspace_templates: templates });
}

function decimalFd(value, field) {
  if (typeof value !== "string" || !/^[3-9][0-9]*$/u.test(value)) fail(`${field}_invalid`);
  const fd = Number(value);
  if (!Number.isSafeInteger(fd)) fail(`${field}_invalid`);
  return fd;
}

export function parseReleasePilotCliArgumentsV1(argvValue, environment = process.env) {
  const argv = expectArray(argvValue, "release_pilot_cli_argv", {
    minimum: 12,
    maximum: 13,
  });
  assertReleasePilotEnvironmentV1(environment);
  let configPath = null;
  let deepSeekApiKeyFd = null;
  let runnerSigningKeyFd = null;
  let preflightOnly = false;
  const verifierPrivateKeyFds = [];
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--preflight-only") {
      if (preflightOnly) fail("arguments_invalid");
      preflightOnly = true;
      continue;
    }
    const candidate = argv[index + 1];
    if (candidate === undefined || candidate.startsWith("--")) fail("arguments_invalid");
    index += 1;
    if (flag === "--config") {
      if (configPath !== null) fail("arguments_invalid");
      configPath = path.resolve(candidate);
    } else if (flag === "--deepseek-key-fd") {
      if (deepSeekApiKeyFd !== null) fail("arguments_invalid");
      deepSeekApiKeyFd = decimalFd(candidate, "deepseek_key_fd");
    } else if (flag === "--runner-signing-key-fd") {
      if (runnerSigningKeyFd !== null) fail("arguments_invalid");
      runnerSigningKeyFd = decimalFd(candidate, "runner_signing_key_fd");
    } else if (flag === "--verifier-private-key-fd") {
      verifierPrivateKeyFds.push(decimalFd(candidate, "verifier_private_key_fd"));
    } else {
      fail("arguments_invalid");
    }
  }
  const fds = [deepSeekApiKeyFd, runnerSigningKeyFd, ...verifierPrivateKeyFds];
  if (configPath === null || deepSeekApiKeyFd === null || runnerSigningKeyFd === null
    || verifierPrivateKeyFds.length !== 3 || new Set(fds).size !== 5) {
    fail("arguments_invalid");
  }
  return Object.freeze({
    configPath,
    deepSeekApiKeyFd,
    preflightOnly,
    runnerSigningKeyFd,
    verifierPrivateKeyFds: Object.freeze(verifierPrivateKeyFds),
  });
}

export function assertReleasePilotSecretFdSetV1(options) {
  const input = expectExactRecord(options, [
    "deepSeekApiKeyFd", "runnerSigningKeyFd", "verifierPrivateKeyFds",
  ], "release_pilot_secret_fd_set");
  const verifierFds = expectArray(
    input.verifierPrivateKeyFds,
    "release_pilot_verifier_private_key_fds",
    { minimum: 3, maximum: 3 },
  );
  const fds = [input.deepSeekApiKeyFd, input.runnerSigningKeyFd, ...verifierFds];
  if (new Set(fds).size !== fds.length) fail("secret_fd_role_reuse_forbidden");
  assertExistingDeepSeekApiKeyFdV1(input.deepSeekApiKeyFd);
  assertExistingRunnerSigningKeyFdV1(input.runnerSigningKeyFd);
  for (const fd of verifierFds) assertExistingOciVerifierPrivateKeyFdV1(fd);
  const identities = fds.map((fd) => {
    const stat = fstatSync(fd, { bigint: true });
    return `${stat.dev}:${stat.ino}`;
  });
  if (new Set(identities).size !== identities.length) {
    fail("secret_fd_file_identity_reuse_forbidden");
  }
  return Object.freeze({
    deepSeekApiKeyFd: input.deepSeekApiKeyFd,
    runnerSigningKeyFd: input.runnerSigningKeyFd,
    verifierPrivateKeyFds: Object.freeze([...verifierFds]),
  });
}

async function loadReleasePilotConfig(configPath) {
  return verifyConfig(await readCanonicalPublicArtifact(configPath, "config"));
}

async function loadPublicInputs(config) {
  const plan = verifyPilotPlanV1(await readCanonicalPublicArtifact(
    config.pilot_plan_artifact_path,
    "plan",
  ));
  const cases = [];
  for (const [index, file] of config.case_artifact_paths.entries()) {
    cases.push(verifyPilotCaseV1(await readCanonicalPublicArtifact(file, `case_${index + 1}`)));
  }
  if (cases.some((pilotCase, index) => pilotCase.case_id !== plan.cases[index].case_id
    || pilotCase.case_sha256 !== plan.cases[index].case_sha256)) {
    fail("case_artifact_order_invalid");
  }
  preflightPilotArtifactsV1({ plan, cases });
  const runnerPublic = verifyRunnerPublicArtifact(
    await readCanonicalPublicArtifact(
      config.runner_public_authority_artifact_path,
      "runner_public",
    ),
    plan,
  );
  const verifiers = [];
  for (const [index, file] of config.verifier_public_authority_artifact_paths.entries()) {
    verifiers.push(verifyVerifierPublicArtifact(
      await readCanonicalPublicArtifact(file, `verifier_public_${index + 1}`),
      cases[index],
    ));
  }
  const policyBundleSet = verifyReleaseCellPolicyBundleSetV1({
    plan,
    policyBundleSet: await readCanonicalPublicArtifact(
      config.policy_bundle_set_artifact_path,
      "policy_bundle_set",
    ),
  });
  const templateByCase = new Map(config.workspace_templates.map((entry) => [
    entry.case_id,
    entry.workspace_template_path,
  ]));
  if (plan.cases.some((ref) => !templateByCase.has(ref.case_id))) {
    fail("workspace_template_case_set_invalid");
  }
  const workspaceTemplates = Object.create(null);
  for (const ref of plan.cases) workspaceTemplates[ref.case_id] = templateByCase.get(ref.case_id);
  return { config, plan, cases, policyBundleSet, runnerPublic, verifiers,
    workspaceTemplates };
}

async function attestSecretFds(input, publicInputs) {
  await attestRunnerSigningKeyFdV1({
    expectedPublicKeyPrincipalSha256: publicInputs.runnerPublic.principal,
    runnerSigningKeyFd: input.runnerSigningKeyFd,
  });
  for (const [index, verifier] of publicInputs.verifiers.entries()) {
    await attestOciVerifierPrivateKeyFdV1({
      expectedPublicKeyPrincipalSha256: verifier.principal,
      privateKeyFd: input.verifierPrivateKeyFds[index],
    });
  }
}

function assertOrphanOwnerCrossBinding(runtimeOwner, workspaceOwner) {
  if (runtimeOwner === null || workspaceOwner === null) return;
  const runtimeManifest = runtimeOwner.manifest;
  const workspaceManifest = workspaceOwner.manifest;
  if (runtimeManifest.owner_id !== workspaceManifest.owner_id
    || runtimeManifest.plan_sha256 !== workspaceManifest.plan_sha256
    || runtimeManifest.pilot_id !== workspaceManifest.pilot_id
    || canonicalJson(runtimeManifest.scheduled_cells)
      !== canonicalJson(workspaceManifest.scheduled_cells)) {
    fail("orphan_owner_cross_binding_invalid");
  }
}

async function reconcileReleasePilotOrphans(input) {
  const runtimeOwner = await readActiveReleaseRuntimeOwnerManifestV1({
    privateRunRoot: input.privateRunRoot,
  });
  const workspaceOwner = await readActiveReleaseWorkspaceOwnerManifestV1({
    privateRunRoot: input.privateRunRoot,
  });
  assertOrphanOwnerCrossBinding(runtimeOwner, workspaceOwner);
  const runtimeReceipt = await reconcileReleaseRuntimeOciOwnerV1({
    ociExecutablePath: input.ociExecutablePath,
    privateRunRoot: input.privateRunRoot,
  });
  const workspaceReceipt = workspaceOwner === null
    ? Object.freeze({
      schema_version: "aionis_release_workspace_owner_reconciliation_v1",
      status: "no_active_owner",
      cleanup_confirmed: true,
    })
    : await reconcileReleaseWorkspaceOwnerV1({
      expectedOwnerId: workspaceOwner.manifest.owner_id,
      expectedPlanSha256: workspaceOwner.manifest.plan_sha256,
      gitExecutablePath: input.gitExecutablePath,
      privateRunRoot: input.privateRunRoot,
    });
  if (runtimeReceipt.cleanup_confirmed !== true
    || runtimeReceipt.new_pilot_permitted !== true
    || workspaceReceipt.cleanup_confirmed !== true) {
    fail("orphan_reconciliation_incomplete");
  }
  return Object.freeze({ runtimeReceipt, workspaceReceipt });
}

export async function recoverReleasePilotOrphansFromCanonicalConfigV1(options) {
  const input = expectExactRecord(options, [
    "configPath",
  ], "release_pilot_orphan_recovery_options");
  assertReleasePilotEnvironmentV1(process.env);
  const config = await loadReleasePilotConfig(input.configPath);
  const receipts = await reconcileReleasePilotOrphans({
    gitExecutablePath: config.git_executable_path,
    ociExecutablePath: config.oci_executable_path,
    privateRunRoot: config.private_run_root,
  });
  const body = canonicalClone({
    schema_version: "aionis_release_pilot_orphan_recovery_result_v1",
    status: "orphan_reconciliation_complete",
    claim_eligible: false,
    ledger_created: false,
    provider_request_count: 0,
    new_owner_created: false,
    runtime_reconciliation: receipts.runtimeReceipt,
    workspace_reconciliation: receipts.workspaceReceipt,
  });
  return canonicalClone({ ...body, result_sha256: canonicalSha256(body) });
}

/** The same reverse, idempotent cleanup used by every orchestration failure. */
export async function disposeReleasePilotOrchestrationResourcesV1(resources) {
  const input = expectExactRecord(resources, [
    "cellResourceAuthority", "runtimeOwner", "workspaceOwner",
  ], "release_pilot_orchestration_cleanup_input");
  const errors = [];
  const receipts = [];
  for (const [kind, value, dispose] of [
    ["cell_resource_authority", input.cellResourceAuthority,
      disposeReleaseCellResourceAuthorityV1],
    ["runtime_owner", input.runtimeOwner, disposeReleaseRuntimeOciResourceOwnerV1],
    ["workspace_owner", input.workspaceOwner, disposeReleaseWorkspaceResourceOwnerV1],
  ]) {
    if (value === null) continue;
    try {
      const rawReceipt = await dispose(value);
      const receipt = kind === "cell_resource_authority"
        ? requireConfirmedCellCleanupReceipt(rawReceipt)
        : rawReceipt;
      receipts.push({ kind, receipt });
    } catch (error) {
      errors.push(error);
    }
  }
  if (errors.length > 0) {
    throw new AggregateError(
      errors,
      "aionis_eval_release_pilot_orchestrator_cleanup_failed",
    );
  }
  return receipts;
}

export async function runReleasePilotFromCanonicalConfigWithCancellationV1(
  options,
  cancellationAuthorityValue,
) {
  const cancellationAuthority = assertReleasePilotCancellationAuthorityV1(
    cancellationAuthorityValue,
  );
  const input = expectExactRecord(options, [
    "configPath", "deepSeekApiKeyFd", "preflightOnly", "runnerSigningKeyFd",
    "verifierPrivateKeyFds",
  ], "release_pilot_orchestration_options");
  if (typeof input.preflightOnly !== "boolean") fail("preflight_only_invalid");
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  // Descriptor posture and role separation are checked before reading the
  // config or creating SDK/workspace/Runtime resources.
  const secretFds = assertReleasePilotSecretFdSetV1({
    deepSeekApiKeyFd: input.deepSeekApiKeyFd,
    runnerSigningKeyFd: input.runnerSigningKeyFd,
    verifierPrivateKeyFds: input.verifierPrivateKeyFds,
  });
  // Reject Node/TLS/proxy mutation surfaces before reading config. Orphan
  // reconciliation deliberately runs before credential-content attestation,
  // current-repository provenance, or any new owner is created.
  assertReleasePilotEnvironmentV1(process.env);
  const config = await loadReleasePilotConfig(input.configPath);
  await reconcileReleasePilotOrphans({
    gitExecutablePath: config.git_executable_path,
    ociExecutablePath: config.oci_executable_path,
    privateRunRoot: config.private_run_root,
  });
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  await attestDeepSeekApiKeyFdV1({ apiKeyFd: secretFds.deepSeekApiKeyFd });
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  const publicInputs = await loadPublicInputs(config);
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  // The module-fixed eval source and Git authority are live-bound before any
  // SDK, workspace, Runtime, ledger, or provider authority is created.
  const evalProvenanceAuthority =
    await issueCurrentReleaseEvalRepositoryProvenanceV1({
      configuredGitExecutablePath: publicInputs.config.git_executable_path,
      plan: publicInputs.plan,
    });
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  await attestSecretFds(secretFds, publicInputs);
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  let workspaceOwner = null;
  let runtimeOwner = null;
  let cellResourceAuthority = null;
  const orchestrationOwnerId = randomBytes(16).toString("hex");
  try {
    const sdkClientAuthority = await issueTrustedReleaseSdkClientAuthorityV1({
      consumerRoot: publicInputs.config.sdk_consumer_root,
      plan: publicInputs.plan,
      sdkTarballPath: publicInputs.config.sdk_tarball_path,
    });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    workspaceOwner = await materializeReleasePilotWorkspacesV1({
      cases: publicInputs.cases,
      gitExecutablePath: evalProvenanceAuthority.git_executable_path,
      orchestrationOwnerId,
      plan: publicInputs.plan,
      privateRunRoot: publicInputs.config.private_run_root,
      workspaceTemplates: publicInputs.workspaceTemplates,
    });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    runtimeOwner = await prepareReleaseRuntimeOciResourcesV1({
      cancellationAuthority,
      cases: publicInputs.cases,
      cellPolicyCommands: publicInputs.policyBundleSet.bindings.map(
        (binding) => binding.provisioning_command,
      ),
      ociExecutablePath: publicInputs.config.oci_executable_path,
      orchestrationOwnerId,
      plan: publicInputs.plan,
      privateRunRoot: publicInputs.config.private_run_root,
      runtimeImageReference: publicInputs.config.runtime_image_reference,
      sdkClientAuthority,
      trustRootPublicKeyPath: publicInputs.config.trust_root_public_key_path,
    });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    const provisioned = await provisionReleaseCellResourcesV1({
      cases: publicInputs.cases,
      evalProvenanceAuthority,
      gitExecutablePath: evalProvenanceAuthority.git_executable_path,
      plan: publicInputs.plan,
      policyBundleSet: publicInputs.policyBundleSet,
      runtimeOwner,
      verifierResources: publicInputs.verifiers.map((verifier, index) => ({
        caseId: verifier.caseId,
        privateKeyFd: input.verifierPrivateKeyFds[index],
        verifierConfig: verifier.config,
        verifierPublicKey: verifier.publicKey,
      })),
      workspaceOwner,
    });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    if (provisioned.schema_version
        !== "aionis_release_cell_resource_provisioning_result_v1") {
      fail("provisioning_result_invalid");
    }
    cellResourceAuthority = provisioned.cellResourceAuthority;
    // Ownership transferred into the cell authority; only the top-level
    // handle may dispose owners from this point forward.
    workspaceOwner = null;
    runtimeOwner = null;
    await verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1({
      plan: publicInputs.plan,
      provenanceAuthority: evalProvenanceAuthority,
    });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    const executionAuthorization =
      await runSealedPilotExecutionAuthorizationSignerProcessV1({
        authorityRoot: publicInputs.config.authority_root,
        executionManifest: provisioned.executionManifest,
        plan: publicInputs.plan,
        runnerPublicKey: publicInputs.runnerPublic.publicKey,
        runnerSigningKeyFd: input.runnerSigningKeyFd,
      });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    if (input.preflightOnly) {
      const cleanupReceipt = await disposeReleaseCellResourceAuthorityV1(
        cellResourceAuthority,
      );
      requireConfirmedCellCleanupReceipt(cleanupReceipt);
      cellResourceAuthority = null;
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const body = canonicalClone({
        schema_version: "aionis_release_pilot_preflight_only_result_v1",
        status: "release_resources_verified_not_executed",
        claim_eligible: false,
        provider_request_count: 0,
        ledger_created: false,
        plan_sha256: publicInputs.plan.plan_sha256,
        execution_manifest_sha256: provisioned.executionManifest.manifest_report_sha256,
        execution_authorization_sha256:
          executionAuthorization.execution_authorization_sha256,
        cleanup_receipt: cleanupReceipt,
      });
      return canonicalClone({ ...body, result_sha256: canonicalSha256(body) });
    }
    const result = await runExecutablePilotWithCancellationV1({
      apiKeyFd: input.deepSeekApiKeyFd,
      authorityRoot: publicInputs.config.authority_root,
      cases: publicInputs.cases,
      cellResourceAuthority,
      executionAuthorization,
      executionManifest: provisioned.executionManifest,
      evalProvenanceAuthority,
      plan: publicInputs.plan,
      runnerPublicKey: publicInputs.runnerPublic.publicKey,
      runnerSigningKeyFd: input.runnerSigningKeyFd,
    }, cancellationAuthority);
    cellResourceAuthority = null;
    return result;
  } catch (error) {
    try {
      await disposeReleasePilotOrchestrationResourcesV1({
        cellResourceAuthority,
        runtimeOwner,
        workspaceOwner,
      });
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "aionis_eval_release_pilot_orchestrator_run_and_cleanup_failed",
      );
    }
    throw error;
  }
}

export async function runReleasePilotFromCanonicalConfigV1(options) {
  return runReleasePilotFromCanonicalConfigWithCancellationV1(
    options,
    createReleasePilotCancellationAuthorityV1(),
  );
}
