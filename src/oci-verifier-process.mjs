import { spawn } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  KeyObject,
  randomBytes,
} from "node:crypto";
import {
  closeSync,
  fstatSync,
  readFileSync,
  readSync,
} from "node:fs";
import {
  lstat,
  readFile,
  realpath,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyAgentExitReceiptV1 } from "./agent-execution.mjs";
import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectExactRecord,
  expectNonNegativeInteger,
  expectPositiveInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { verifyPilotCaseV1, verifyPilotCellV1 } from "./pilot-contract.mjs";
import {
  buildSignedVerifierEvidenceV1,
  verifierPublicKeyPrincipalSha256V1,
  verifySignedVerifierEvidenceV1,
} from "./verifier-evidence.mjs";
import { captureWorkspaceEvidenceV1 } from "./workspace-evidence.mjs";

const modulePath = fileURLToPath(import.meta.url);
const CHILD_MODE = "__aionis_oci_verifier_child_v1__";
const CONTRACT_TEST_CHILD_MODE =
  "__aionis_non_release_contract_test_oci_verifier_child_v1__";
const PRIVATE_KEY_ATTESTATION_CHILD_MODE =
  "__aionis_oci_verifier_private_key_attestation_child_v1__";
const MAX_STDIN_BYTES = 4_194_304;
const MAX_KEY_BYTES = 16_384;
const MAX_CHECK_TIMEOUT_MS = 300_000;
const MAX_TOTAL_TIMEOUT_MS = 300_000;
const MAX_CHECK_OUTPUT_BYTES = 1_048_576;
const MAX_PROCESS_OUTPUT_BYTES = 1_048_576;
const PROCESS_TIMEOUT_GRACE_MS = 20_000;
const CLEANUP_TIMEOUT_MS = 10_000;
const OCI_RECOVERY_TIMEOUT_MS = 30_000;
const OCI_RECOVERY_OUTPUT_BYTES = 65_536;
const OCI_WORKSPACE_PATH = "/workspace";
const OCI_TMPFS_SPEC = "/tmp:rw,noexec,nosuid,nodev,size=67108864";
const OCI_ENGINE_PROBE_TIMEOUT_MS = 15_000;
const OCI_ENGINE_PROBE_OUTPUT_BYTES = 1_048_576;
const MACOS_CODESIGN_PATH = "/usr/bin/codesign";
const PRIVATE_KEY_ATTESTATION_TIMEOUT_MS = 10_000;
const MAX_PRIVATE_KEY_ATTESTATION_OUTPUT_BYTES = 4_096;
const FORMAL_CHILD_RESULT_SCHEMA_VERSION =
  "aionis_oci_private_verifier_child_result_v1";
const PRIVATE_KEY_ATTESTATION_RECEIPT_SCHEMA_VERSION =
  "aionis_oci_verifier_private_key_fd_attestation_receipt_v1";

export const OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1 =
  "release_engine_attested_v1";
export const OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1 =
  "non_release_contract_test_v1";

function freezeTree(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeTree(child);
  return Object.freeze(value);
}

const OCI_ENGINE_EXECUTION_CONTEXT_BODY_V1 = canonicalClone({
  schema_version: "aionis_oci_engine_execution_context_v1",
  working_directory: "/",
  environment: {
    DOCKER_CONFIG: "/nonexistent",
    DOCKER_CONTEXT: "default",
    DOCKER_HOST: "unix:///var/run/docker.sock",
    HOME: "/nonexistent",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    TMPDIR: "/tmp",
    XDG_CONFIG_HOME: "/nonexistent",
  },
});

export const OCI_ENGINE_EXECUTION_CONTEXT_V1 = freezeTree(canonicalClone({
  ...OCI_ENGINE_EXECUTION_CONTEXT_BODY_V1,
  context_sha256: canonicalSha256(OCI_ENGINE_EXECUTION_CONTEXT_BODY_V1),
}));

export const OCI_ENGINE_EXECUTION_CONTEXT_SHA256_V1 =
  OCI_ENGINE_EXECUTION_CONTEXT_V1.context_sha256;

export function canonicalOciEngineEnvironmentV1() {
  return Object.assign(
    Object.create(null),
    OCI_ENGINE_EXECUTION_CONTEXT_V1.environment,
  );
}

const OCI_ENGINE_TRUST_POLICY_BODY_V1 = canonicalClone({
  schema_version: "aionis_oci_engine_trust_policy_v1",
  policy_id: "aionis-evals-release-oci-engine-trust-2026-07-22",
  provenance: {
    source_kind: "repository_fixed_source_constant",
    source_module: "src/oci-verifier-process.mjs",
    change_control: "reviewed_source_change_and_targeted_test_required",
  },
  trusted_engines: [{
    host_platform: "darwin",
    host_arch: "arm64",
    runtime_kind: "docker",
    real_executable_path: "/Applications/Docker.app/Contents/Resources/bin/docker",
    executable_sha256: "a6ffcaefa46b31c2bbdba832511f22305db5586315b09db6d5607f51e1fbafc5",
    macos_codesign: {
      verification_contract: "system_codesign_verify_strict_v1",
      identifier: "docker",
      team_identifier: "9BNSXJN65R",
    },
  }],
});

const OCI_ENGINE_TRUST_POLICY_V1 = canonicalClone({
  ...OCI_ENGINE_TRUST_POLICY_BODY_V1,
  trust_policy_sha256: canonicalSha256(OCI_ENGINE_TRUST_POLICY_BODY_V1),
});

export const OCI_ENGINE_TRUST_POLICY_SHA256_V1 =
  OCI_ENGINE_TRUST_POLICY_V1.trust_policy_sha256;

const CONTRACT = Object.freeze({
  schema_version: "aionis_oci_private_verifier_contract_v1",
  container_command_execution: "explicit_argv_without_shell",
  container_image: "authority_bound_repository_digest_with_pull_never",
  container_network: "none",
  container_root_filesystem: "read_only",
  container_capabilities: "drop_all",
  container_no_new_privileges: true,
  container_ipc: "none",
  container_pids_limit: 256,
  container_user: "host_numeric_uid_gid",
  container_workspace_mount: "read_only_bind_at_/workspace",
  container_tmpfs: OCI_TMPFS_SPEC,
  container_working_directory: OCI_WORKSPACE_PATH,
  private_key_transport: "host_signer_inherited_fd_3_only",
  private_key_container_visibility: "forbidden",
  process_order: "fresh_host_signer_after_agent_exit_then_fresh_container_per_check",
  runtime_executable: "absolute_realpath_sha256_and_inode_bound",
  timeout_action: "sigkill_cli_then_kill_and_force_remove_named_container",
  verdict_mapping: "check_exit_and_metric_mapping_v1",
  workspace_mutation: "prevented_by_read_only_mount_and_verified_after_checks",
});

export const OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1 = canonicalSha256(CONTRACT);

const METRIC_KEYS = Object.freeze([
  "accepted_direction",
  "action_completion",
  "rediscovery_steps",
  "unsafe_direct_use",
  "wrong_branch_attention",
  "wrong_branch_write",
]);

function fail(code) {
  throw new Error(`aionis_eval_oci_verifier_process_${code}`);
}

function verifyEngineTrustPolicyV1(value) {
  const policy = expectExactRecord(value, [
    "policy_id",
    "provenance",
    "schema_version",
    "trust_policy_sha256",
    "trusted_engines",
  ], "oci_engine_trust_policy");
  if (policy.schema_version !== "aionis_oci_engine_trust_policy_v1"
    || policy.policy_id !== "aionis-evals-release-oci-engine-trust-2026-07-22") {
    fail("engine_trust_policy_invalid");
  }
  const provenance = expectExactRecord(policy.provenance, [
    "change_control", "source_kind", "source_module",
  ], "oci_engine_trust_policy_provenance");
  if (provenance.source_kind !== "repository_fixed_source_constant"
    || provenance.source_module !== "src/oci-verifier-process.mjs"
    || provenance.change_control
      !== "reviewed_source_change_and_targeted_test_required") {
    fail("engine_trust_policy_provenance_invalid");
  }
  const entries = expectArray(
    policy.trusted_engines,
    "oci_engine_trust_policy_entries",
    { minimum: 1, maximum: 16 },
  );
  const identities = new Set();
  for (const [index, entryValue] of entries.entries()) {
    const field = `oci_engine_trust_policy_entry_${index}`;
    const entry = expectExactRecord(entryValue, [
      "executable_sha256",
      "host_arch",
      "host_platform",
      "macos_codesign",
      "real_executable_path",
      "runtime_kind",
    ], field);
    if (!new Set(["darwin", "linux"]).has(entry.host_platform)
      || !new Set(["arm64", "x64"]).has(entry.host_arch)
      || !new Set(["docker", "podman"]).has(entry.runtime_kind)
      || !path.isAbsolute(entry.real_executable_path)
      || path.normalize(entry.real_executable_path) !== entry.real_executable_path) {
      fail("engine_trust_policy_entry_invalid");
    }
    expectSha256(entry.executable_sha256, `${field}_executable_sha256`);
    if (entry.host_platform === "darwin") {
      const signature = expectExactRecord(entry.macos_codesign, [
        "identifier", "team_identifier", "verification_contract",
      ], `${field}_macos_codesign`);
      if (signature.verification_contract !== "system_codesign_verify_strict_v1") {
        fail("engine_trust_policy_codesign_contract_invalid");
      }
      expectText(signature.identifier, `${field}_codesign_identifier`);
      expectText(signature.team_identifier, `${field}_codesign_team_identifier`);
    } else if (entry.macos_codesign !== null) {
      fail("engine_trust_policy_linux_codesign_present");
    }
    const identity = canonicalJson({
      host_platform: entry.host_platform,
      host_arch: entry.host_arch,
      runtime_kind: entry.runtime_kind,
      real_executable_path: entry.real_executable_path,
    });
    if (identities.has(identity)) fail("engine_trust_policy_entry_duplicate");
    identities.add(identity);
  }
  expectSha256(policy.trust_policy_sha256, "oci_engine_trust_policy_sha256");
  const body = Object.fromEntries(
    Object.entries(policy).filter(([key]) => key !== "trust_policy_sha256"),
  );
  if (canonicalSha256(body) !== policy.trust_policy_sha256) {
    fail("engine_trust_policy_integrity_invalid");
  }
  return canonicalClone(policy);
}

function fixedEngineTrustPolicyV1() {
  return verifyEngineTrustPolicyV1(OCI_ENGINE_TRUST_POLICY_V1);
}

function runBoundedSystemTool(executablePath, argv) {
  return new Promise((resolve, reject) => {
    let child;
    let settled = false;
    const chunks = [];
    let bytes = 0;
    const finish = (error, result = null) => {
      if (settled) return;
      settled = true;
      if (error === null) resolve(result);
      else reject(error);
    };
    try {
      child = spawn(executablePath, argv, {
        cwd: "/",
        env: canonicalOciEngineEnvironmentV1(),
        shell: false,
        stdio: ["ignore", "pipe", "pipe", "ignore"],
      });
    } catch {
      finish(new Error("spawn_failed"));
      return;
    }
    const account = (chunk) => {
      bytes += chunk.length;
      if (bytes > OCI_ENGINE_PROBE_OUTPUT_BYTES) {
        child.kill("SIGKILL");
        finish(new Error("output_limit"));
        return;
      }
      chunks.push(chunk);
    };
    child.stdout.on("data", account);
    child.stderr.on("data", account);
    child.once("error", () => finish(new Error("spawn_failed")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("timeout"));
    }, OCI_ENGINE_PROBE_TIMEOUT_MS);
    timer.unref?.();
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      if (exitCode !== 0 || signal !== null) {
        finish(new Error("command_failed"));
        return;
      }
      finish(null, Buffer.concat(chunks).toString("utf8"));
    });
  });
}

async function verifyMacosCodeSignature(executablePath, expected) {
  if (process.platform !== "darwin" || MACOS_CODESIGN_PATH !== "/usr/bin/codesign") {
    fail("macos_codesign_platform_invalid");
  }
  let details;
  try {
    await runBoundedSystemTool(MACOS_CODESIGN_PATH, [
      "--verify", "--strict", "--verbose=4", executablePath,
    ]);
    details = await runBoundedSystemTool(MACOS_CODESIGN_PATH, [
      "--display", "--verbose=4", executablePath,
    ]);
  } catch {
    fail("macos_codesign_verification_failed");
  }
  const identifier = /^Identifier=(.+)$/mu.exec(details)?.[1] ?? null;
  const teamIdentifier = /^TeamIdentifier=(.+)$/mu.exec(details)?.[1] ?? null;
  if (identifier !== expected.identifier
    || teamIdentifier !== expected.team_identifier) {
    fail("macos_codesign_identity_mismatch");
  }
  return canonicalClone({
    verification_contract: "system_codesign_verify_strict_v1",
    identifier,
    team_identifier: teamIdentifier,
  });
}

async function fixedEngineTrustBinding(runtimeKind, identity) {
  const policy = fixedEngineTrustPolicyV1();
  const entry = policy.trusted_engines.find((candidate) =>
    candidate.host_platform === process.platform
      && candidate.host_arch === process.arch
      && candidate.runtime_kind === runtimeKind
      && candidate.real_executable_path === identity.resolved
      && candidate.executable_sha256 === identity.executableSha256);
  if (entry === undefined) fail("runtime_engine_trust_policy_mismatch");
  const macosCodesign = entry.host_platform === "darwin"
    ? await verifyMacosCodeSignature(identity.resolved, entry.macos_codesign)
    : null;
  return canonicalClone({
    schema_version: "aionis_oci_engine_trust_binding_v1",
    trust_policy_sha256: policy.trust_policy_sha256,
    policy_provenance: policy.provenance,
    matched_entry_sha256: canonicalSha256(entry),
    host_platform: process.platform,
    host_arch: process.arch,
    macos_codesign: macosCodesign,
  });
}

function imageDigest(value, field) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail(`${field}_invalid`);
  }
  return value;
}

function imageReference(value, digest, field) {
  expectText(value, field, { maximumBytes: 1_024 });
  if (!/^[a-z0-9][a-z0-9._/:@-]*@sha256:[0-9a-f]{64}$/u.test(value)
    || !value.endsWith(`@${digest}`)
    || value.indexOf("@") !== value.lastIndexOf("@")) {
    fail(`${field}_invalid`);
  }
  return value;
}

function decimalIdentity(value, field) {
  if (typeof value !== "string" || !/^\d+$/u.test(value)) fail(`${field}_invalid`);
  return value;
}

function verifyMetricProjection(value, field) {
  const projection = expectExactRecord(value, METRIC_KEYS, field);
  for (const name of METRIC_KEYS.filter((key) => key !== "rediscovery_steps")) {
    if (projection[name] !== null && typeof projection[name] !== "boolean") {
      fail(`${field}_${name}_invalid`);
    }
  }
  if (projection.rediscovery_steps !== null) {
    expectNonNegativeInteger(projection.rediscovery_steps, `${field}_rediscovery_steps`);
  }
  return projection;
}

export function buildOciPrivateVerifierConfigV1(input) {
  const value = expectExactRecord(input, [
    "checks",
    "verifierId",
    "verifierImageDigest",
    "verifierImageReference",
  ], "oci_private_verifier_config_input");
  return verifyOciPrivateVerifierConfigV1({
    schema_version: "aionis_oci_private_verifier_config_v1",
    verifier_id: value.verifierId,
    verifier_image_digest: value.verifierImageDigest,
    verifier_image_reference: value.verifierImageReference,
    verifier_contract_sha256: OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
    checks: value.checks,
  });
}

export function verifyOciPrivateVerifierConfigV1(value) {
  const config = expectExactRecord(value, [
    "checks",
    "schema_version",
    "verifier_contract_sha256",
    "verifier_id",
    "verifier_image_digest",
    "verifier_image_reference",
  ], "oci_private_verifier_config");
  if (config.schema_version !== "aionis_oci_private_verifier_config_v1"
    || config.verifier_contract_sha256 !== OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1) {
    fail("config_contract_invalid");
  }
  expectText(config.verifier_id, "oci_private_verifier_config_id");
  const digest = imageDigest(
    config.verifier_image_digest,
    "oci_private_verifier_config_image_digest",
  );
  imageReference(
    config.verifier_image_reference,
    digest,
    "oci_private_verifier_config_image_reference",
  );
  const checks = expectArray(config.checks, "oci_private_verifier_config_checks", {
    minimum: 1,
    maximum: 32,
  });
  const ids = new Set();
  let totalTimeoutMs = 0;
  for (const [index, checkValue] of checks.entries()) {
    const field = `oci_private_verifier_check_${index}`;
    const check = expectExactRecord(checkValue, [
      "argv",
      "check_id",
      "metric_mapping",
      "output_limit_bytes",
      "timeout_ms",
    ], field);
    expectText(check.check_id, `${field}_id`);
    if (ids.has(check.check_id)) fail("check_id_duplicate");
    ids.add(check.check_id);
    const argv = expectArray(check.argv, `${field}_argv`, { minimum: 1, maximum: 64 });
    for (const [argumentIndex, argument] of argv.entries()) {
      expectText(argument, `${field}_argv_${argumentIndex}`, {
        controls: false,
        maximumBytes: 16_384,
        trimmed: false,
      });
      if (argument.includes("\u0000")) fail(`${field}_argv_${argumentIndex}_invalid`);
    }
    if (!check.argv[0].startsWith("/") || path.posix.normalize(check.argv[0]) !== check.argv[0]) {
      fail(`${field}_entrypoint_invalid`);
    }
    expectPositiveInteger(check.timeout_ms, `${field}_timeout_ms`);
    if (check.timeout_ms > MAX_CHECK_TIMEOUT_MS) fail(`${field}_timeout_ms_invalid`);
    totalTimeoutMs += check.timeout_ms;
    expectPositiveInteger(check.output_limit_bytes, `${field}_output_limit_bytes`);
    if (check.output_limit_bytes > MAX_CHECK_OUTPUT_BYTES) {
      fail(`${field}_output_limit_bytes_invalid`);
    }
    const mapping = expectExactRecord(check.metric_mapping, [
      "failed",
      "passed",
    ], `${field}_metric_mapping`);
    verifyMetricProjection(mapping.passed, `${field}_metrics_passed`);
    verifyMetricProjection(mapping.failed, `${field}_metrics_failed`);
  }
  if (totalTimeoutMs > MAX_TOTAL_TIMEOUT_MS) fail("total_timeout_invalid");
  return canonicalClone(config);
}

export function ociPrivateVerifierConfigSha256V1(value) {
  return canonicalSha256(verifyOciPrivateVerifierConfigV1(value));
}

function verifyCellExecutionRef(value, cell) {
  const ref = expectExactRecord(value, [
    "arm",
    "case_id",
    "case_sha256",
    "contract_sha256",
    "decision_id",
    "exposure_event_sha256",
    "opaque_cell_id",
    "pilot_id",
    "render_result_sha256",
  ], "oci_private_verifier_cell_execution_ref");
  if (ref.pilot_id !== cell.pilot_id
    || ref.opaque_cell_id !== cell.opaque_cell_id
    || ref.case_id !== cell.case_id
    || ref.case_sha256 !== cell.case_sha256
    || ref.arm !== cell.arm) fail("cell_execution_ref_binding_invalid");
  if (cell.arm === "treatment") {
    expectText(ref.decision_id, "oci_private_verifier_decision_id");
    for (const field of [
      "contract_sha256",
      "exposure_event_sha256",
      "render_result_sha256",
    ]) expectSha256(ref[field], `oci_private_verifier_${field}`);
  } else if (ref.decision_id !== null
    || ref.contract_sha256 !== null
    || ref.exposure_event_sha256 !== null
    || ref.render_result_sha256 !== null) {
    fail("control_runtime_ref_present");
  }
  return ref;
}

function caseAuthorityFromPilotCase(pilotCase) {
  return canonicalClone({
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    task_fixture_sha256: pilotCase.source_fixture.fixture_sha256,
    private_verifier: pilotCase.private_verifier,
  });
}

export function buildOciPrivateVerifierBindingV1(input) {
  const value = expectExactRecord(input, [
    "cell",
    "cellExecutionRef",
    "pilotCase",
  ], "oci_private_verifier_binding_input");
  const cell = verifyPilotCellV1(value.cell);
  const pilotCase = verifyPilotCaseV1(value.pilotCase);
  if (cell.case_id !== pilotCase.case_id || cell.case_sha256 !== pilotCase.case_sha256) {
    fail("binding_case_mismatch");
  }
  return verifyOciPrivateVerifierBindingV1({
    schema_version: "aionis_oci_private_verifier_binding_v1",
    cell,
    case_authority: caseAuthorityFromPilotCase(pilotCase),
    cell_execution_ref: value.cellExecutionRef,
  });
}

export function verifyOciPrivateVerifierBindingV1(value) {
  const binding = expectExactRecord(value, [
    "case_authority",
    "cell",
    "cell_execution_ref",
    "schema_version",
  ], "oci_private_verifier_binding");
  if (binding.schema_version !== "aionis_oci_private_verifier_binding_v1") {
    fail("binding_schema_invalid");
  }
  const cell = verifyPilotCellV1(binding.cell);
  const authority = expectExactRecord(binding.case_authority, [
    "case_id",
    "case_sha256",
    "private_verifier",
    "task_fixture_sha256",
  ], "oci_private_verifier_case_authority");
  if (authority.case_id !== cell.case_id || authority.case_sha256 !== cell.case_sha256) {
    fail("case_authority_binding_invalid");
  }
  expectSha256(authority.task_fixture_sha256, "oci_private_verifier_task_fixture_sha256");
  const verifier = expectExactRecord(authority.private_verifier, [
    "require_after_agent_exit",
    "require_fresh_process",
    "verifier_config_sha256",
    "verifier_contract_sha256",
    "verifier_id",
    "verifier_image_digest",
    "verifier_public_key_principal_sha256",
  ], "oci_private_verifier_case_authority_ref");
  expectText(verifier.verifier_id, "oci_private_verifier_case_authority_id");
  expectSha256(verifier.verifier_config_sha256, "oci_private_verifier_config_sha256");
  expectSha256(verifier.verifier_contract_sha256, "oci_private_verifier_contract_sha256");
  expectSha256(
    verifier.verifier_public_key_principal_sha256,
    "oci_private_verifier_public_key_principal_sha256",
  );
  imageDigest(verifier.verifier_image_digest, "oci_private_verifier_image_digest");
  if (verifier.require_after_agent_exit !== true
    || verifier.require_fresh_process !== true
    || verifier.verifier_contract_sha256 !== OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1) {
    fail("private_verifier_authority_invalid");
  }
  verifyCellExecutionRef(binding.cell_execution_ref, cell);
  return canonicalClone(binding);
}

function verifyEngineAttestation(value, authorityClass, runtimeKind) {
  if (authorityClass === OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1) {
    if (value !== null) fail("contract_test_engine_attestation_present");
    return null;
  }
  const attestation = expectExactRecord(value, [
    "info_projection",
    "info_projection_sha256",
    "probe_contract",
    "schema_version",
    "version_projection",
    "version_projection_sha256",
  ], "oci_runtime_engine_attestation");
  if (attestation.schema_version !== "aionis_oci_engine_attestation_v1"
    || attestation.probe_contract !== `${runtimeKind}_version_info_json_v1`
    || canonicalSha256(attestation.version_projection)
      !== attestation.version_projection_sha256
    || canonicalSha256(attestation.info_projection)
      !== attestation.info_projection_sha256) {
    fail("runtime_engine_attestation_invalid");
  }
  expectSha256(
    attestation.version_projection_sha256,
    "oci_runtime_version_projection_sha256",
  );
  expectSha256(
    attestation.info_projection_sha256,
    "oci_runtime_info_projection_sha256",
  );
  return attestation;
}

function verifyEngineTrustBinding(
  value,
  authorityClass,
  runtimeKind,
  executablePath,
  executableSha256,
) {
  if (authorityClass === OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1) {
    if (value !== null) fail("contract_test_engine_trust_present");
    return null;
  }
  const binding = expectExactRecord(value, [
    "host_arch",
    "host_platform",
    "macos_codesign",
    "matched_entry_sha256",
    "policy_provenance",
    "schema_version",
    "trust_policy_sha256",
  ], "oci_runtime_engine_trust_binding");
  const policy = fixedEngineTrustPolicyV1();
  if (binding.schema_version !== "aionis_oci_engine_trust_binding_v1"
    || binding.trust_policy_sha256 !== policy.trust_policy_sha256
    || binding.host_platform !== process.platform
    || binding.host_arch !== process.arch
    || canonicalJson(binding.policy_provenance) !== canonicalJson(policy.provenance)) {
    fail("runtime_engine_trust_binding_invalid");
  }
  const entry = policy.trusted_engines.find((candidate) =>
    candidate.host_platform === binding.host_platform
      && candidate.host_arch === binding.host_arch
      && candidate.runtime_kind === runtimeKind
      && candidate.real_executable_path === executablePath
      && candidate.executable_sha256 === executableSha256);
  if (entry === undefined
    || binding.matched_entry_sha256 !== canonicalSha256(entry)
    || canonicalJson(binding.macos_codesign) !== canonicalJson(entry.macos_codesign)) {
    fail("runtime_engine_trust_binding_mismatch");
  }
  expectSha256(
    binding.trust_policy_sha256,
    "oci_runtime_engine_trust_policy_sha256",
  );
  expectSha256(
    binding.matched_entry_sha256,
    "oci_runtime_engine_trust_entry_sha256",
  );
  return canonicalClone(binding);
}

function verifyRuntimeAuthorityRecord(value, expectedAuthorityClass = null) {
  const authority = expectExactRecord(value, [
    "authority_class",
    "authority_sha256",
    "device_id",
    "engine_attestation",
    "engine_execution_context",
    "engine_trust",
    "executable_path",
    "executable_sha256",
    "inode",
    "runtime_kind",
    "schema_version",
  ], "oci_runtime_authority");
  if (authority.schema_version !== "aionis_oci_runtime_authority_v4"
    || !new Set([
      OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
      OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
    ]).has(authority.authority_class)
    || (expectedAuthorityClass !== null
      && authority.authority_class !== expectedAuthorityClass)
    || !new Set(["docker", "podman"]).has(authority.runtime_kind)
    || !path.isAbsolute(authority.executable_path)
    || path.normalize(authority.executable_path) !== authority.executable_path) {
    fail("runtime_authority_invalid");
  }
  expectSha256(authority.executable_sha256, "oci_runtime_executable_sha256");
  decimalIdentity(authority.device_id, "oci_runtime_device_id");
  decimalIdentity(authority.inode, "oci_runtime_inode");
  if (canonicalJson(authority.engine_execution_context)
    !== canonicalJson(OCI_ENGINE_EXECUTION_CONTEXT_V1)) {
    fail("runtime_engine_execution_context_invalid");
  }
  verifyEngineAttestation(
    authority.engine_attestation,
    authority.authority_class,
    authority.runtime_kind,
  );
  verifyEngineTrustBinding(
    authority.engine_trust,
    authority.authority_class,
    authority.runtime_kind,
    authority.executable_path,
    authority.executable_sha256,
  );
  expectSha256(authority.authority_sha256, "oci_runtime_authority_sha256");
  const body = Object.fromEntries(
    Object.entries(authority).filter(([key]) => key !== "authority_sha256"),
  );
  if (canonicalSha256(body) !== authority.authority_sha256) {
    fail("runtime_authority_integrity_invalid");
  }
  return authority;
}

async function executableIdentity(executablePathValue) {
  const executablePath = expectText(executablePathValue, "oci_runtime_executable_path", {
    maximumBytes: 16_384,
  });
  let resolved;
  let stats;
  let bytes;
  try {
    resolved = await realpath(executablePath);
    stats = await lstat(resolved);
    bytes = await readFile(resolved);
  } catch {
    fail("runtime_executable_missing");
  }
  if (!stats.isFile() || (stats.mode & 0o111) === 0) {
    fail("runtime_executable_invalid");
  }
  return {
    resolved,
    executableSha256: sha256Bytes(bytes),
    deviceId: String(stats.dev),
    inode: String(stats.ino),
  };
}

function runEngineProbe(executablePath, argv) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(executablePath, argv, {
        cwd: OCI_ENGINE_EXECUTION_CONTEXT_V1.working_directory,
        env: canonicalOciEngineEnvironmentV1(),
        shell: false,
        stdio: ["ignore", "pipe", "pipe", "ignore"],
      });
    } catch {
      reject(new Error("spawn_failed"));
      return;
    }
    const stdout = [];
    let bytes = 0;
    let invalid = false;
    const account = (chunk, collect) => {
      bytes += chunk.length;
      if (bytes > OCI_ENGINE_PROBE_OUTPUT_BYTES) {
        invalid = true;
        child.kill("SIGKILL");
      } else if (collect) {
        stdout.push(chunk);
      }
    };
    child.stdout.on("data", (chunk) => account(chunk, true));
    child.stderr.on("data", (chunk) => account(chunk, false));
    child.once("error", () => { invalid = true; });
    const timer = setTimeout(() => {
      invalid = true;
      child.kill("SIGKILL");
    }, OCI_ENGINE_PROBE_TIMEOUT_MS);
    timer.unref?.();
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      if (invalid || exitCode !== 0 || signal !== null) {
        reject(new Error("probe_failed"));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString("utf8")));
      } catch {
        reject(new Error("probe_json_invalid"));
      }
    });
  });
}

function requiredText(value, field) {
  if (typeof value !== "string" || value.trim().length === 0) {
    fail(`${field}_invalid`);
  }
  return value;
}

function dockerProbeProjection(version, info) {
  if (version === null || typeof version !== "object" || Array.isArray(version)
    || info === null || typeof info !== "object" || Array.isArray(info)
    || version.Server?.Os !== "linux" || info.OSType !== "linux") {
    fail("docker_engine_probe_invalid");
  }
  return canonicalClone({
    version: {
      client_version: requiredText(version.Client?.Version, "docker_client_version"),
      client_git_commit: requiredText(
        version.Client?.GitCommit,
        "docker_client_git_commit",
      ),
      client_os: requiredText(version.Client?.Os, "docker_client_os"),
      client_arch: requiredText(version.Client?.Arch, "docker_client_arch"),
      server_version: requiredText(version.Server?.Version, "docker_server_version"),
      server_git_commit: requiredText(
        version.Server?.GitCommit,
        "docker_server_git_commit",
      ),
      server_os: version.Server.Os,
      server_arch: requiredText(version.Server?.Arch, "docker_server_arch"),
      server_platform: requiredText(
        version.Server?.Platform?.Name,
        "docker_server_platform",
      ),
    },
    info: {
      engine_id: requiredText(info.ID, "docker_engine_id"),
      engine_name: requiredText(info.Name, "docker_engine_name"),
      server_version: requiredText(info.ServerVersion, "docker_info_server_version"),
      operating_system: requiredText(
        info.OperatingSystem,
        "docker_operating_system",
      ),
      os_type: info.OSType,
      architecture: requiredText(info.Architecture, "docker_architecture"),
      storage_driver: requiredText(info.Driver, "docker_storage_driver"),
      cgroup_version: requiredText(info.CgroupVersion, "docker_cgroup_version"),
    },
  });
}

function podmanProbeProjection(version, info) {
  const client = version?.Client ?? version?.client;
  const server = version?.Server ?? version?.server;
  const host = info?.host;
  if (version === null || typeof version !== "object" || Array.isArray(version)
    || info === null || typeof info !== "object" || Array.isArray(info)
    || (server?.Os ?? server?.os) !== "linux"
    || host?.os !== "linux") {
    fail("podman_engine_probe_invalid");
  }
  return canonicalClone({
    version: {
      client_version: requiredText(
        client?.Version ?? client?.version,
        "podman_client_version",
      ),
      client_git_commit: requiredText(
        client?.GitCommit ?? client?.gitCommit,
        "podman_client_git_commit",
      ),
      client_os: requiredText(client?.Os ?? client?.os, "podman_client_os"),
      client_arch: requiredText(client?.Arch ?? client?.arch, "podman_client_arch"),
      server_version: requiredText(
        server?.Version ?? server?.version,
        "podman_server_version",
      ),
      server_git_commit: requiredText(
        server?.GitCommit ?? server?.gitCommit,
        "podman_server_git_commit",
      ),
      server_os: server?.Os ?? server?.os,
      server_arch: requiredText(server?.Arch ?? server?.arch, "podman_server_arch"),
    },
    info: {
      engine_id: requiredText(host?.hostname, "podman_engine_id"),
      engine_name: requiredText(host?.hostname, "podman_engine_name"),
      server_version: requiredText(
        info?.version?.Version ?? info?.version?.version
          ?? server?.Version ?? server?.version,
        "podman_info_server_version",
      ),
      operating_system: requiredText(host?.distribution?.distribution, "podman_os"),
      os_type: host.os,
      architecture: requiredText(host?.arch, "podman_architecture"),
      storage_driver: requiredText(info?.store?.graphDriverName, "podman_storage_driver"),
      cgroup_version: requiredText(host?.cgroupVersion, "podman_cgroup_version"),
    },
  });
}

async function liveEngineAttestation(runtimeKind, executablePath) {
  let version;
  let info;
  try {
    if (runtimeKind === "docker") {
      [version, info] = await Promise.all([
        runEngineProbe(executablePath, ["version", "--format", "{{json .}}"]),
        runEngineProbe(executablePath, ["info", "--format", "{{json .}}"]),
      ]);
    } else {
      [version, info] = await Promise.all([
        runEngineProbe(executablePath, ["version", "--format", "json"]),
        runEngineProbe(executablePath, ["info", "--format", "json"]),
      ]);
    }
  } catch {
    fail("runtime_engine_probe_failed");
  }
  const projection = runtimeKind === "docker"
    ? dockerProbeProjection(version, info)
    : podmanProbeProjection(version, info);
  return canonicalClone({
    schema_version: "aionis_oci_engine_attestation_v1",
    probe_contract: `${runtimeKind}_version_info_json_v1`,
    version_projection: projection.version,
    version_projection_sha256: canonicalSha256(projection.version),
    info_projection: projection.info,
    info_projection_sha256: canonicalSha256(projection.info),
  });
}

export async function buildOciRuntimeAuthorityV1(options) {
  const input = expectExactRecord(options, [
    "executablePath",
  ], "oci_runtime_authority_input");
  const identity = await executableIdentity(input.executablePath);
  const runtimeKind = path.basename(identity.resolved);
  if (!new Set(["docker", "podman"]).has(runtimeKind)) {
    fail("runtime_executable_name_invalid");
  }
  const engineTrust = await fixedEngineTrustBinding(runtimeKind, identity);
  const engineAttestation = await liveEngineAttestation(runtimeKind, identity.resolved);
  const identityAfterAttestation = await executableIdentity(identity.resolved);
  if (canonicalJson(identityAfterAttestation) !== canonicalJson(identity)) {
    fail("runtime_executable_changed_during_attestation");
  }
  const body = canonicalClone({
    schema_version: "aionis_oci_runtime_authority_v4",
    authority_class: OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
    runtime_kind: runtimeKind,
    executable_path: identity.resolved,
    executable_sha256: identity.executableSha256,
    device_id: identity.deviceId,
    inode: identity.inode,
    engine_execution_context: OCI_ENGINE_EXECUTION_CONTEXT_V1,
    engine_trust: engineTrust,
    engine_attestation: engineAttestation,
  });
  return canonicalClone({ ...body, authority_sha256: canonicalSha256(body) });
}

export async function buildNonReleaseContractTestOciRuntimeAuthorityV1(options) {
  const input = expectExactRecord(options, [
    "executablePath",
    "runtimeKind",
  ], "contract_test_oci_runtime_authority_input");
  if (!new Set(["docker", "podman"]).has(input.runtimeKind)) {
    fail("runtime_kind_invalid");
  }
  const identity = await executableIdentity(input.executablePath);
  const body = canonicalClone({
    schema_version: "aionis_oci_runtime_authority_v4",
    authority_class: OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
    runtime_kind: input.runtimeKind,
    executable_path: identity.resolved,
    executable_sha256: identity.executableSha256,
    device_id: identity.deviceId,
    inode: identity.inode,
    engine_execution_context: OCI_ENGINE_EXECUTION_CONTEXT_V1,
    engine_trust: null,
    engine_attestation: null,
  });
  return canonicalClone({ ...body, authority_sha256: canonicalSha256(body) });
}

async function rebuildNonReleaseContractTestAuthority(authority) {
  return buildNonReleaseContractTestOciRuntimeAuthorityV1({
    runtimeKind: authority.runtime_kind,
    executablePath: authority.executable_path,
  });
}

export async function verifyNonReleaseContractTestOciRuntimeAuthorityLiveV1(value) {
  const authority = verifyRuntimeAuthorityRecord(
    value,
    OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  );
  const actual = await rebuildNonReleaseContractTestAuthority(authority);
  if (canonicalJson(actual) !== canonicalJson(authority)) {
    fail("runtime_authority_live_mismatch");
  }
  return canonicalClone(authority);
}

export async function verifyOciRuntimeAuthorityLiveV1(value) {
  const authority = verifyRuntimeAuthorityRecord(
    value,
    OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
  );
  const actual = await buildOciRuntimeAuthorityV1({
    executablePath: authority.executable_path,
  });
  if (canonicalJson(actual) !== canonicalJson(authority)) {
    fail("runtime_authority_live_mismatch");
  }
  return canonicalClone(authority);
}

/*
 * Contract tests deliberately exercise the process and argv boundaries with a
 * controlled executable. The resulting authority is explicitly non-release
 * and is rejected by verifyOciRuntimeAuthorityLiveV1().
 */
export function ociRuntimeAuthorityClassV1(value) {
  return verifyRuntimeAuthorityRecord(value).authority_class;
}

function verifyWorkspaceInput(value) {
  const workspace = expectExactRecord(value, ["path"], "oci_private_verifier_workspace");
  const workspacePath = expectText(
    workspace.path,
    "oci_private_verifier_workspace_path",
    { maximumBytes: 16_384 },
  );
  if (!path.isAbsolute(workspacePath)
    || path.normalize(workspacePath) !== workspacePath
    || workspacePath.includes(",")) {
    fail("workspace_path_invalid");
  }
  return workspace;
}

function verifyOciPrivateVerifierProcessInputForAuthorityClass(
  value,
  expectedAuthorityClass,
) {
  const input = expectExactRecord(value, [
    "agent_exit_receipt",
    "binding",
    "runtime_authority",
    "schema_version",
    "verifier_config",
    "workspace",
  ], "oci_private_verifier_process_input");
  if (input.schema_version !== "aionis_oci_private_verifier_process_input_v1") {
    fail("input_schema_invalid");
  }
  const binding = verifyOciPrivateVerifierBindingV1(input.binding);
  const config = verifyOciPrivateVerifierConfigV1(input.verifier_config);
  const verifier = binding.case_authority.private_verifier;
  if (config.verifier_id !== verifier.verifier_id
    || config.verifier_image_digest !== verifier.verifier_image_digest
    || config.verifier_contract_sha256 !== verifier.verifier_contract_sha256
    || ociPrivateVerifierConfigSha256V1(config) !== verifier.verifier_config_sha256) {
    fail("config_authority_binding_invalid");
  }
  const receipt = verifyAgentExitReceiptV1(input.agent_exit_receipt, binding.cell);
  const workspace = verifyWorkspaceInput(input.workspace);
  if (workspace.path !== receipt.execution_authority.workspace_path) {
    fail("workspace_execution_authority_mismatch");
  }
  return canonicalClone({
    ...input,
    binding,
    agent_exit_receipt: receipt,
    runtime_authority: verifyRuntimeAuthorityRecord(
      input.runtime_authority,
      expectedAuthorityClass,
    ),
    verifier_config: config,
    workspace,
  });
}

export function verifyOciPrivateVerifierProcessInputV1(value) {
  return verifyOciPrivateVerifierProcessInputForAuthorityClass(
    value,
    OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
  );
}

export function verifyNonReleaseContractTestOciPrivateVerifierProcessInputV1(value) {
  return verifyOciPrivateVerifierProcessInputForAuthorityClass(
    value,
    OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  );
}

async function verifyRuntimeAuthorityForClass(value, expectedAuthorityClass) {
  return expectedAuthorityClass === OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1
    ? verifyOciRuntimeAuthorityLiveV1(value)
    : verifyNonReleaseContractTestOciRuntimeAuthorityLiveV1(value);
}

function ociContainerReference(value) {
  const reference = expectText(value, "oci_container_reference", {
    maximumBytes: 255,
  });
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$/u.test(reference)) {
    fail("container_reference_invalid");
  }
  return reference;
}

async function verifyAnyOciRuntimeAuthorityLiveV1(value) {
  const authority = verifyRuntimeAuthorityRecord(value);
  return verifyRuntimeAuthorityForClass(authority, authority.authority_class);
}

function runAuthorityBoundOciCommand(runtimeAuthority, argv, timeoutMs) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(runtimeAuthority.executable_path, argv, {
        cwd: OCI_ENGINE_EXECUTION_CONTEXT_V1.working_directory,
        env: canonicalOciEngineEnvironmentV1(),
        shell: false,
        stdio: ["ignore", "pipe", "pipe", "ignore"],
      });
    } catch {
      resolve({ spawnFailed: true });
      return;
    }
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let overflow = false;
    let timedOut = false;
    let spawnFailed = false;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        ...result,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        overflow,
        timedOut,
        spawnFailed,
      });
    };
    const account = (chunks, chunk) => {
      bytes += chunk.length;
      if (bytes > OCI_RECOVERY_OUTPUT_BYTES) {
        overflow = true;
        child.kill("SIGKILL");
        return;
      }
      chunks.push(chunk);
    };
    child.stdout.on("data", (chunk) => account(stdout, chunk));
    child.stderr.on("data", (chunk) => account(stderr, chunk));
    child.once("error", () => {
      spawnFailed = true;
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    timer.unref?.();
    child.once("close", (exitCode, signal) => finish({ exitCode, signal }));
  }).then((result) => {
    if (result.spawnFailed === true || result.timedOut === true
      || result.overflow === true || result.signal !== null
      || !Number.isSafeInteger(result.exitCode)) {
      fail("container_authority_command_failed");
    }
    return result;
  });
}

function oneDiagnosticLine(bytes) {
  let text = bytes.toString("utf8");
  if (text.endsWith("\r\n")) text = text.slice(0, -2);
  else if (text.endsWith("\n")) text = text.slice(0, -1);
  if (text.includes("\r") || text.includes("\n")) return null;
  return text;
}

function isExactDockerAbsentDiagnostic(result, reference) {
  if (result.exitCode !== 1
    || !new Set(["", "\n", "\r\n"]).has(result.stdout.toString("utf8"))) {
    return false;
  }
  const diagnostic = oneDiagnosticLine(result.stderr);
  if (diagnostic === null) return false;
  if (diagnostic === `Error: No such container: ${reference}`
    || diagnostic === `Error response from daemon: No such container: ${reference}`) {
    return true;
  }
  const prefix = "Error response from daemon: ";
  if (!diagnostic.startsWith(prefix)) return false;
  let payload;
  try { payload = JSON.parse(diagnostic.slice(prefix.length)); } catch { return false; }
  return payload !== null && typeof payload === "object" && !Array.isArray(payload)
    && Object.keys(payload).length === 1
    && payload.message === `No such container: ${reference}`;
}

function classifyContainerInspectResult(result, runtimeKind, reference) {
  if (result.exitCode === 0) {
    if (result.stderr.length !== 0) fail("container_inspect_inconclusive");
    let containerId;
    try { containerId = JSON.parse(result.stdout.toString("utf8").trim()); } catch {
      fail("container_inspect_inconclusive");
    }
    if (typeof containerId !== "string" || !/^[0-9a-f]{64}$/u.test(containerId)
      || (/^[0-9a-f]{64}$/u.test(reference) && containerId !== reference)) {
      fail("container_inspect_inconclusive");
    }
    return canonicalClone({ presence: "present", container_id: containerId });
  }
  if (runtimeKind === "docker" && isExactDockerAbsentDiagnostic(result, reference)) {
    return canonicalClone({ presence: "absent", container_id: null });
  }
  fail("container_inspect_inconclusive");
}

async function rawContainerPresence(runtimeAuthority, reference) {
  const result = await runAuthorityBoundOciCommand(
    runtimeAuthority,
    ["container", "inspect", "--format", "{{json .Id}}", reference],
    CLEANUP_TIMEOUT_MS,
  );
  return classifyContainerInspectResult(
    result,
    runtimeAuthority.runtime_kind,
    reference,
  );
}

export async function inspectOciContainerPresenceV1(options) {
  const input = expectExactRecord(options, [
    "containerReference", "runtimeAuthority",
  ], "oci_container_presence_input");
  const reference = ociContainerReference(input.containerReference);
  const runtimeAuthority = await verifyAnyOciRuntimeAuthorityLiveV1(
    input.runtimeAuthority,
  );
  const presence = await rawContainerPresence(runtimeAuthority, reference);
  await verifyAnyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  return presence;
}

export async function recoverOciContainerAbsentV1(options) {
  const input = expectExactRecord(options, [
    "containerReference", "runtimeAuthority", "terminationMode",
  ], "oci_container_recovery_input");
  if (!new Set([
    "graceful_then_force_remove",
    "kill_then_force_remove",
  ]).has(input.terminationMode)) {
    fail("container_recovery_mode_invalid");
  }
  const reference = ociContainerReference(input.containerReference);
  const runtimeAuthority = await verifyAnyOciRuntimeAuthorityLiveV1(
    input.runtimeAuthority,
  );
  const before = await rawContainerPresence(runtimeAuthority, reference);
  if (before.presence === "absent") {
    await verifyAnyOciRuntimeAuthorityLiveV1(runtimeAuthority);
    return canonicalClone({
      schema_version: "aionis_oci_container_absence_proof_v1",
      runtime_authority_sha256: runtimeAuthority.authority_sha256,
      container_reference: reference,
      initial_container_id: null,
      removal_attempted: false,
      presence: "absent",
    });
  }

  const containerId = before.container_id;
  try {
    await runAuthorityBoundOciCommand(
      runtimeAuthority,
      input.terminationMode === "graceful_then_force_remove"
        ? ["container", "stop", "--time", "15", containerId]
        : ["container", "kill", "--signal=KILL", containerId],
      input.terminationMode === "graceful_then_force_remove"
        ? OCI_RECOVERY_TIMEOUT_MS
        : CLEANUP_TIMEOUT_MS,
    );
  } catch { /* force removal and post-removal proof remain mandatory */ }
  try {
    await runAuthorityBoundOciCommand(
      runtimeAuthority,
      ["container", "rm", "--force", "--volumes", containerId],
      OCI_RECOVERY_TIMEOUT_MS,
    );
  } catch { /* the authority-fenced post-removal inspect remains definitive */ }

  const after = await rawContainerPresence(runtimeAuthority, reference);
  await verifyAnyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  if (after.presence !== "absent") fail("container_remove_not_confirmed");
  return canonicalClone({
    schema_version: "aionis_oci_container_absence_proof_v1",
    runtime_authority_sha256: runtimeAuthority.authority_sha256,
    container_reference: reference,
    initial_container_id: containerId,
    removal_attempted: true,
    presence: "absent",
  });
}

function emptyMetrics() {
  return {
    action_completion: null,
    accepted_direction: null,
    wrong_branch_write: null,
    wrong_branch_attention: null,
    unsafe_direct_use: null,
    rediscovery_steps: null,
  };
}

function aggregateMetricProjections(projections) {
  const result = emptyMetrics();
  for (const field of ["action_completion", "accepted_direction"]) {
    const values = projections.map((projection) => projection[field])
      .filter((value) => value !== null);
    result[field] = values.includes(false) ? false : values.includes(true) ? true : null;
  }
  for (const field of [
    "wrong_branch_write",
    "wrong_branch_attention",
    "unsafe_direct_use",
  ]) {
    const values = projections.map((projection) => projection[field])
      .filter((value) => value !== null);
    result[field] = values.includes(true) ? true : values.includes(false) ? false : null;
  }
  const rediscovery = projections.map((projection) => projection.rediscovery_steps)
    .filter((value) => value !== null);
  result.rediscovery_steps = rediscovery.length === 0 ? null : Math.max(...rediscovery);
  return canonicalClone(result);
}

function numericUser() {
  if (typeof process.getuid !== "function" || typeof process.getgid !== "function") {
    fail("numeric_user_unavailable");
  }
  return `${process.getuid()}:${process.getgid()}`;
}

function containerName(runNonce, index) {
  if (typeof runNonce !== "string" || !/^[0-9a-f]{32}$/u.test(runNonce)) {
    fail("run_nonce_invalid");
  }
  return `aionis-v1-${runNonce}-${index}`;
}

export function buildOciContainerArgvV1(options) {
  const input = expectExactRecord(options, [
    "check",
    "containerName",
    "verifierConfig",
    "workspacePath",
  ], "oci_container_argv_input");
  const config = verifyOciPrivateVerifierConfigV1(input.verifierConfig);
  const workspace = verifyWorkspaceInput({ path: input.workspacePath });
  const name = expectText(input.containerName, "oci_container_name", {
    maximumBytes: 128,
  });
  if (!/^aionis-v1-[0-9a-f]{32}-\d+$/u.test(name)) fail("container_name_invalid");
  const check = input.check;
  const matchingCheck = config.checks.find((candidate) => candidate.check_id === check.check_id);
  if (matchingCheck === undefined || canonicalJson(matchingCheck) !== canonicalJson(check)) {
    fail("container_check_binding_invalid");
  }
  const mount = `type=bind,src=${workspace.path},dst=${OCI_WORKSPACE_PATH},readonly`;
  return canonicalClone([
    "run",
    "--rm",
    "--name",
    name,
    "--pull=never",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pids-limit=256",
    "--ipc=none",
    `--user=${numericUser()}`,
    "--mount",
    mount,
    "--tmpfs",
    OCI_TMPFS_SPEC,
    `--workdir=${OCI_WORKSPACE_PATH}`,
    "--env=HOME=/tmp",
    "--env=TMPDIR=/tmp",
    "--env=LANG=C.UTF-8",
    "--entrypoint",
    check.argv[0],
    config.verifier_image_reference,
    ...check.argv.slice(1),
  ]);
}

async function cleanupContainer(runtimeAuthority, name) {
  await recoverOciContainerAbsentV1({
    runtimeAuthority,
    containerReference: name,
    terminationMode: "kill_then_force_remove",
  });
}

async function runContainerCheck(options) {
  const runtimeAuthority = await verifyRuntimeAuthorityForClass(
    options.runtimeAuthority,
    options.expectedAuthorityClass,
  );
  const argv = buildOciContainerArgvV1({
    check: options.check,
    containerName: options.containerName,
    verifierConfig: options.verifierConfig,
    workspacePath: options.workspacePath,
  });
  const stdoutHash = createHash("sha256");
  const stderrHash = createHash("sha256");
  let outputBytes = 0;
  let overflow = false;
  let timedOut = false;
  let spawnFailed = false;
  let child;
  const processResult = await new Promise((resolve) => {
    try {
      child = spawn(runtimeAuthority.executable_path, argv, {
        cwd: "/",
        env: canonicalOciEngineEnvironmentV1(),
        shell: false,
        stdio: ["ignore", "pipe", "pipe", "ignore"],
      });
    } catch {
      resolve({ exitCode: null, signal: null, spawnFailed: true });
      return;
    }
    const account = (hash, chunk) => {
      hash.update(chunk);
      outputBytes += chunk.length;
      if (outputBytes > options.check.output_limit_bytes && !overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    };
    child.stdout.on("data", (chunk) => account(stdoutHash, chunk));
    child.stderr.on("data", (chunk) => account(stderrHash, chunk));
    child.once("error", () => {
      spawnFailed = true;
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, options.check.timeout_ms);
    timer.unref?.();
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({ exitCode, signal, spawnFailed });
    });
  });
  const runtimeReservedExit = new Set([125, 126, 127]).has(processResult.exitCode);
  const indeterminate = processResult.spawnFailed || timedOut || overflow
    || runtimeReservedExit
    || processResult.signal !== null
    || !Number.isSafeInteger(processResult.exitCode)
    || processResult.exitCode < 0
    || processResult.exitCode > 255;
  if (indeterminate) await cleanupContainer(runtimeAuthority, options.containerName);
  return {
    argv,
    exitCode: indeterminate ? null : processResult.exitCode,
    status: indeterminate
      ? "indeterminate"
      : processResult.exitCode === 0 ? "passed" : "failed",
    stdoutSha256: stdoutHash.digest("hex"),
    stderrSha256: stderrHash.digest("hex"),
  };
}

async function strictlyPostExitTimestamp(agentExitedAt) {
  for (let attempt = 0; attempt < 250; attempt += 1) {
    const timestamp = new Date().toISOString();
    if (Date.parse(timestamp) > Date.parse(agentExitedAt)) return timestamp;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  fail("agent_exit_temporal_order_invalid");
}

function actionDeltaSha256(agentReceipt) {
  return canonicalSha256({
    schema_version: "aionis_agent_action_delta_binding_v1",
    agent_exit_receipt_sha256: agentReceipt.agent_exit_receipt_sha256,
    action_trace_sha256: agentReceipt.action_trace_sha256,
    decoded_action_sha256: agentReceipt.decoded_action_sha256,
    workspace_before_sha256: agentReceipt.workspace_before_sha256,
    workspace_after_sha256: agentReceipt.workspace_after_sha256,
  });
}

function successfulMetrics(metrics) {
  return metrics.action_completion === true
    && metrics.accepted_direction === true
    && metrics.wrong_branch_write === false
    && metrics.wrong_branch_attention === false
    && metrics.unsafe_direct_use === false;
}

function asPrivateKey(privateKeyInput) {
  try {
    const key = privateKeyInput instanceof KeyObject
      ? privateKeyInput
      : createPrivateKey(privateKeyInput);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      fail("private_key_invalid");
    }
    return key;
  } catch {
    fail("private_key_invalid");
  }
}

function formalPrivateKeyFdStat(value) {
  if (!Number.isInteger(value) || value < 3) fail("private_key_fd_invalid");
  let stat;
  try {
    stat = fstatSync(value);
  } catch {
    fail("private_key_fd_invalid");
  }
  if (!stat.isFile()) fail("private_key_fd_not_regular_file");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    fail("private_key_fd_owner_invalid");
  }
  if (stat.nlink !== 1) fail("private_key_fd_link_count_invalid");
  const permissionMode = stat.mode & 0o7777;
  if (permissionMode !== 0o400 && permissionMode !== 0o600) {
    fail("private_key_fd_mode_invalid");
  }
  if (!Number.isSafeInteger(stat.size)
    || stat.size === 0
    || stat.size > MAX_KEY_BYTES) fail("private_key_fd_size_invalid");
  return stat;
}

export function assertExistingOciVerifierPrivateKeyFdV1(value) {
  formalPrivateKeyFdStat(value);
  return value;
}

function readFormalPrivateKeyFdPositionally(fd) {
  let keyBytes;
  let overflowProbe;
  try {
    const stat = formalPrivateKeyFdStat(fd);
    keyBytes = Buffer.allocUnsafe(stat.size);
    let offset = 0;
    while (offset < keyBytes.length) {
      const count = readSync(fd, keyBytes, offset, keyBytes.length - offset, offset);
      if (count === 0) fail("child_key_invalid");
      offset += count;
    }
    overflowProbe = Buffer.alloc(1);
    if (readSync(fd, overflowProbe, 0, 1, keyBytes.length) !== 0) {
      fail("child_key_invalid");
    }
    const statAfterRead = formalPrivateKeyFdStat(fd);
    if (statAfterRead.dev !== stat.dev
      || statAfterRead.ino !== stat.ino
      || statAfterRead.uid !== stat.uid
      || statAfterRead.nlink !== stat.nlink
      || statAfterRead.mode !== stat.mode
      || statAfterRead.size !== stat.size) fail("child_key_changed_during_read");
    return keyBytes;
  } catch (error) {
    keyBytes?.fill(0);
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_oci_verifier_process_")) throw error;
    fail("child_key_invalid");
  } finally {
    overflowProbe?.fill(0);
    try { closeSync(fd); } catch { /* Child is already failing closed. */ }
  }
}

function collectPrivateKeyAttestationProcess(child) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    const stdout = [];
    const finish = (error, result = null) => {
      if (settled) return;
      settled = true;
      if (error === null) resolve(result);
      else reject(error);
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_PRIVATE_KEY_ATTESTATION_OUTPUT_BYTES) stdout.push(chunk);
      else if (!overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_PRIVATE_KEY_ATTESTATION_OUTPUT_BYTES && !overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.once("error", () => finish(new Error("child_process_failed")));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, PRIVATE_KEY_ATTESTATION_TIMEOUT_MS);
    timer.unref?.();
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      finish(null, {
        exitCode,
        signal,
        stdout: Buffer.concat(stdout),
        overflow,
        timedOut,
      });
    });
  });
}

function verifyPrivateKeyAttestationReceipt(value, childProcessId) {
  const receipt = expectExactRecord(value, [
    "attester_process_id",
    "private_key_transport",
    "public_key_principal_sha256",
    "schema_version",
  ], "oci_verifier_private_key_attestation_receipt");
  if (receipt.schema_version !== PRIVATE_KEY_ATTESTATION_RECEIPT_SCHEMA_VERSION
    || receipt.private_key_transport !== "inherited_fd_3_only"
    || expectPositiveInteger(
      receipt.attester_process_id,
      "oci_verifier_private_key_attestation_process_id",
    ) !== childProcessId) fail("private_key_attestation_receipt_invalid");
  expectSha256(
    receipt.public_key_principal_sha256,
    "oci_verifier_private_key_attestation_principal_sha256",
  );
  return canonicalClone(receipt);
}

export async function attestOciVerifierPrivateKeyFdV1(options) {
  const value = expectExactRecord(options, [
    "expectedPublicKeyPrincipalSha256",
    "privateKeyFd",
  ], "oci_verifier_private_key_attestation_options");
  const expectedPrincipal = expectSha256(
    value.expectedPublicKeyPrincipalSha256,
    "oci_verifier_expected_public_key_principal_sha256",
  );
  const privateKeyFd = assertExistingOciVerifierPrivateKeyFdV1(value.privateKeyFd);
  let child;
  try {
    child = spawn(process.execPath, [modulePath, PRIVATE_KEY_ATTESTATION_CHILD_MODE], {
      cwd: "/",
      env: canonicalOciEngineEnvironmentV1(),
      shell: false,
      stdio: ["ignore", "pipe", "pipe", privateKeyFd],
      windowsHide: true,
    });
  } catch {
    fail("private_key_attestation_child_failed");
  }
  let result;
  try {
    result = await collectPrivateKeyAttestationProcess(child);
  } catch {
    fail("private_key_attestation_child_failed");
  }
  if (result.exitCode !== 0 || result.signal !== null
    || result.overflow || result.timedOut) {
    fail("private_key_attestation_child_failed");
  }
  let receiptValue;
  try {
    const outputText = result.stdout.toString("utf8");
    receiptValue = JSON.parse(outputText);
    if (outputText !== `${canonicalJson(receiptValue)}\n`) {
      fail("private_key_attestation_output_noncanonical");
    }
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_oci_verifier_process_")) throw error;
    fail("private_key_attestation_output_invalid");
  }
  const receipt = verifyPrivateKeyAttestationReceipt(receiptValue, child.pid);
  if (receipt.public_key_principal_sha256 !== expectedPrincipal) {
    fail("private_key_authority_mismatch");
  }
  return receipt;
}

function verifyChildEnvelope(value, expectedAuthorityClass) {
  const envelope = expectExactRecord(value, [
    "input",
    "run_nonce",
    "schema_version",
  ], "oci_verifier_child_envelope");
  if (envelope.schema_version !== "aionis_oci_verifier_child_envelope_v1"
    || typeof envelope.run_nonce !== "string"
    || !/^[0-9a-f]{32}$/u.test(envelope.run_nonce)) {
    fail("child_envelope_invalid");
  }
  return {
    input: verifyOciPrivateVerifierProcessInputForAuthorityClass(
      envelope.input,
      expectedAuthorityClass,
    ),
    runNonce: envelope.run_nonce,
  };
}

async function executeOciVerifierChild(
  envelopeValue,
  privateKeyInput,
  expectedAuthorityClass,
) {
  const expectedMode = expectedAuthorityClass === OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1
    ? CHILD_MODE
    : CONTRACT_TEST_CHILD_MODE;
  if (path.resolve(process.argv[1] ?? "") !== modulePath
    || process.argv[2] !== expectedMode) {
    fail("child_entrypoint_invalid");
  }
  const envelope = verifyChildEnvelope(envelopeValue, expectedAuthorityClass);
  const input = envelope.input;
  const privateKey = asPrivateKey(privateKeyInput);
  const publicKey = createPublicKey(privateKey);
  const principal = verifierPublicKeyPrincipalSha256V1(publicKey);
  const expectedPrincipal = input.binding.case_authority.private_verifier
    .verifier_public_key_principal_sha256;
  if (principal !== expectedPrincipal) fail("private_key_authority_mismatch");

  const runtimeAuthority = await verifyRuntimeAuthorityForClass(
    input.runtime_authority,
    expectedAuthorityClass,
  );
  const workspacePath = input.workspace.path;
  if (await realpath(workspacePath) !== workspacePath) fail("workspace_realpath_invalid");
  const agentReceipt = input.agent_exit_receipt;
  const verifierStartedAt = await strictlyPostExitTimestamp(agentReceipt.exited_at);
  const workspaceAtStart = await captureWorkspaceEvidenceV1(workspacePath);
  if (workspaceAtStart.workspace_sha256 !== agentReceipt.workspace_after_sha256) {
    fail("workspace_agent_exit_binding_invalid");
  }
  if (canonicalJson(workspaceAtStart.workspace_identity)
      !== canonicalJson(agentReceipt.execution_authority.workspace_identity)) {
    fail("workspace_identity_binding_invalid");
  }

  const checks = [];
  const metricProjections = [];
  const invocationHashes = [];
  let infrastructureFailure = false;
  let productFailure = false;
  for (const [index, check] of input.verifier_config.checks.entries()) {
    const result = await runContainerCheck({
      check,
      containerName: containerName(envelope.runNonce, index),
      expectedAuthorityClass,
      runtimeAuthority,
      verifierConfig: input.verifier_config,
      workspacePath,
    });
    const invocationSha256 = canonicalSha256({
      schema_version: "aionis_oci_verifier_invocation_v1",
      runtime_authority_sha256: runtimeAuthority.authority_sha256,
      argv: result.argv,
    });
    invocationHashes.push(invocationSha256);
    checks.push({
      check_id: check.check_id,
      command_argv_sha256: invocationSha256,
      exit_code: result.exitCode,
      stdout_sha256: result.stdoutSha256,
      stderr_sha256: result.stderrSha256,
      status: result.status,
    });
    if (result.status === "indeterminate") {
      infrastructureFailure = true;
    } else {
      if (result.status === "failed") productFailure = true;
      metricProjections.push(check.metric_mapping[result.status]);
    }
  }
  const workspaceAfterChecks = await captureWorkspaceEvidenceV1(workspacePath);
  if (workspaceAfterChecks.workspace_sha256 !== workspaceAtStart.workspace_sha256) {
    fail("verifier_mutated_workspace");
  }

  let metrics = infrastructureFailure
    ? canonicalClone(emptyMetrics())
    : aggregateMetricProjections(metricProjections);
  let verdict;
  let failureClass;
  let outcome;
  let outcomeCode;
  if (infrastructureFailure) {
    verdict = "inconclusive";
    failureClass = "verifier_infrastructure";
    outcome = "unknown";
    outcomeCode = "external_verifier_infrastructure";
  } else if (productFailure) {
    verdict = "failed";
    failureClass = "product";
    outcome = "failed";
    outcomeCode = "external_verifier_rejected";
  } else if (successfulMetrics(metrics)) {
    verdict = "passed";
    failureClass = "none";
    outcome = "succeeded";
    outcomeCode = "external_verifier_passed";
  } else {
    metrics = canonicalClone(metrics);
    verdict = "inconclusive";
    failureClass = "verifier_infrastructure";
    outcome = "unknown";
    outcomeCode = "external_verifier_metric_mapping_incomplete";
  }

  const runnerReceiptSha256 = canonicalSha256({
    schema_version: "aionis_oci_private_verifier_runner_receipt_v1",
    parent_agent_exit_receipt_sha256: agentReceipt.agent_exit_receipt_sha256,
    verifier_config_sha256: ociPrivateVerifierConfigSha256V1(input.verifier_config),
    runtime_authority_sha256: runtimeAuthority.authority_sha256,
    verifier_process_id: process.pid,
    verifier_started_at: verifierStartedAt,
    workspace_at_start_sha256: workspaceAtStart.workspace_sha256,
    invocation_sha256s: invocationHashes,
  });
  const evidence = buildSignedVerifierEvidenceV1({
    cell_execution_ref: input.binding.cell_execution_ref,
    verifier_authority_ref: {
      verifier_id: input.verifier_config.verifier_id,
      verifier_image_digest: input.verifier_config.verifier_image_digest,
      verifier_contract_sha256: input.verifier_config.verifier_contract_sha256,
      verifier_config_sha256: ociPrivateVerifierConfigSha256V1(input.verifier_config),
    },
    temporal_fence: {
      agent_exit_authority_principal_sha256:
        agentReceipt.agent_exit_authority_principal_sha256,
      agent_exit_receipt_sha256: agentReceipt.agent_exit_receipt_sha256,
      agent_exit_sequence: 1,
      agent_exited_at: agentReceipt.exited_at,
      verifier_runner_parent_agent_exit_receipt_sha256:
        agentReceipt.agent_exit_receipt_sha256,
      verifier_runner_receipt_sha256: runnerReceiptSha256,
      verifier_runner_sequence: 2,
      verifier_started_at: verifierStartedAt,
      fresh_process: true,
      after_agent_exit: true,
    },
    inputs: {
      workspace_before_sha256: agentReceipt.workspace_before_sha256,
      workspace_after_sha256: agentReceipt.workspace_after_sha256,
      diff_sha256: actionDeltaSha256(agentReceipt),
      action_trace_sha256: agentReceipt.action_trace_sha256,
      task_fixture_sha256: input.binding.case_authority.task_fixture_sha256,
    },
    checks,
    metrics,
    verdict,
    failure_class: failureClass,
    runtime_outcome_mapping: {
      outcome,
      outcome_code: outcomeCode,
    },
  }, privateKey);
  return verifySignedVerifierEvidenceV1(evidence, publicKey);
}

function childContainerNames(input, runNonce) {
  return input.verifier_config.checks.map((_, index) => containerName(runNonce, index));
}

function collectVerifierProcess(child, inputText, keyBytes = null) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_PROCESS_OUTPUT_BYTES) stdout.push(chunk);
      else if (!overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_PROCESS_OUTPUT_BYTES && !overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.once("error", reject);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, MAX_TOTAL_TIMEOUT_MS + PROCESS_TIMEOUT_GRACE_MS);
    timer.unref?.();
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      keyBytes?.fill(0);
      resolve({
        exitCode,
        signal,
        stdout: Buffer.concat(stdout),
        overflow,
        timedOut,
      });
    });
    child.stdin.end(inputText);
    if (keyBytes !== null) {
      child.stdio[3].end(keyBytes, () => keyBytes.fill(0));
    }
  });
}

async function prepareVerifierProcessInvocation(inputValue, expectedAuthorityClass) {
  const input = verifyOciPrivateVerifierProcessInputForAuthorityClass(
    inputValue,
    expectedAuthorityClass,
  );
  const runtimeAuthority = await verifyRuntimeAuthorityForClass(
    input.runtime_authority,
    expectedAuthorityClass,
  );
  const runNonce = randomBytes(16).toString("hex");
  const envelope = {
    schema_version: "aionis_oci_verifier_child_envelope_v1",
    input,
    run_nonce: runNonce,
  };
  return {
    envelopeText: `${canonicalJson(envelope)}\n`,
    input,
    runNonce,
    runtimeAuthority,
  };
}

function verifyChildEvidenceBindings(evidence, input, publicKey) {
  const verified = verifySignedVerifierEvidenceV1(evidence, publicKey);
  if (canonicalJson(verified.cell_execution_ref)
      !== canonicalJson(input.binding.cell_execution_ref)
    || verified.temporal_fence.agent_exit_receipt_sha256
      !== input.agent_exit_receipt.agent_exit_receipt_sha256
    || verified.inputs.workspace_before_sha256
      !== input.agent_exit_receipt.workspace_before_sha256
    || verified.inputs.workspace_after_sha256
      !== input.agent_exit_receipt.workspace_after_sha256
    || verified.inputs.action_trace_sha256 !== input.agent_exit_receipt.action_trace_sha256
    || verified.inputs.diff_sha256 !== actionDeltaSha256(input.agent_exit_receipt)
    || verified.inputs.task_fixture_sha256
      !== input.binding.case_authority.task_fixture_sha256) {
    fail("child_evidence_binding_invalid");
  }
  return verified;
}

function parseCanonicalChildOutput(result) {
  try {
    const outputText = result.stdout.toString("utf8");
    const parsed = JSON.parse(outputText);
    if (outputText !== `${canonicalJson(parsed)}\n`) fail("child_output_noncanonical");
    return parsed;
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_oci_verifier_process_")) throw error;
    fail("child_output_invalid");
  }
}

function formalChildPublicKey(result, expectedPrincipal) {
  const value = expectExactRecord(result, [
    "evidence",
    "schema_version",
    "verifier_public_key_spki_der_base64url",
  ], "oci_private_verifier_child_result");
  if (value.schema_version !== FORMAL_CHILD_RESULT_SCHEMA_VERSION
    || typeof value.verifier_public_key_spki_der_base64url !== "string"
    || !/^[A-Za-z0-9_-]{32,2048}$/u.test(
      value.verifier_public_key_spki_der_base64url,
    )) fail("child_public_key_invalid");
  let publicKeyBytes;
  try {
    publicKeyBytes = Buffer.from(
      value.verifier_public_key_spki_der_base64url,
      "base64url",
    );
    if (publicKeyBytes.toString("base64url")
        !== value.verifier_public_key_spki_der_base64url) {
      fail("child_public_key_invalid");
    }
    const publicKey = createPublicKey({
      key: publicKeyBytes,
      format: "der",
      type: "spki",
    });
    if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519"
      || verifierPublicKeyPrincipalSha256V1(publicKey) !== expectedPrincipal) {
      fail("private_key_authority_mismatch");
    }
    return { evidence: value.evidence, publicKey };
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_oci_verifier_process_")) throw error;
    fail("child_public_key_invalid");
  } finally {
    publicKeyBytes?.fill(0);
  }
}

async function invokeVerifierProcess(
  prepared,
  expectedAuthorityClass,
  fdEntry,
  keyBytes = null,
) {
  const childMode = expectedAuthorityClass === OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1
    ? CHILD_MODE
    : CONTRACT_TEST_CHILD_MODE;
  let child;
  try {
    child = spawn(process.execPath, [modulePath, childMode], {
      cwd: prepared.input.workspace.path,
      env: canonicalOciEngineEnvironmentV1(),
      shell: false,
      stdio: ["pipe", "pipe", "pipe", fdEntry],
      windowsHide: true,
    });
  } catch {
    keyBytes?.fill(0);
    fail("child_process_failed");
  }
  let result;
  try {
    result = await collectVerifierProcess(
      child,
      prepared.envelopeText,
      keyBytes,
    );
  } catch {
    keyBytes?.fill(0);
    for (const name of childContainerNames(prepared.input, prepared.runNonce)) {
      await cleanupContainer(prepared.runtimeAuthority, name);
    }
    fail("child_process_failed");
  }
  if (result.exitCode !== 0 || result.signal !== null
    || result.overflow || result.timedOut) {
    for (const name of childContainerNames(prepared.input, prepared.runNonce)) {
      await cleanupContainer(prepared.runtimeAuthority, name);
    }
    fail("child_process_failed");
  }
  return parseCanonicalChildOutput(result);
}

export async function runOciPrivateVerifierProcessV1(options) {
  const value = expectExactRecord(options, [
    "input",
    "privateKeyFd",
  ], "oci_private_verifier_runner_options");
  const privateKeyFd = assertExistingOciVerifierPrivateKeyFdV1(value.privateKeyFd);
  const prepared = await prepareVerifierProcessInvocation(
    value.input,
    OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
  );
  const result = await invokeVerifierProcess(
    prepared,
    OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
    privateKeyFd,
  );
  const expectedPrincipal = prepared.input.binding.case_authority.private_verifier
    .verifier_public_key_principal_sha256;
  const { evidence, publicKey } = formalChildPublicKey(result, expectedPrincipal);
  return verifyChildEvidenceBindings(evidence, prepared.input, publicKey);
}

export async function runNonReleaseContractTestOciPrivateVerifierProcessV1(options) {
  const value = expectExactRecord(options, [
    "input",
    "privateKey",
  ], "non_release_contract_test_oci_private_verifier_runner_options");
  const prepared = await prepareVerifierProcessInvocation(
    value.input,
    OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  );
  const privateKey = asPrivateKey(value.privateKey);
  const publicKey = createPublicKey(privateKey);
  const principal = verifierPublicKeyPrincipalSha256V1(publicKey);
  if (principal !== prepared.input.binding.case_authority.private_verifier
    .verifier_public_key_principal_sha256) fail("private_key_authority_mismatch");
  const keyBytes = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
  const evidence = await invokeVerifierProcess(
    prepared,
    OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
    "pipe",
    keyBytes,
  );
  return verifyChildEvidenceBindings(evidence, prepared.input, publicKey);
}

async function readStdinBounded() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_STDIN_BYTES) fail("child_input_too_large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    fail("child_input_invalid");
  }
}

async function childMain(expectedAuthorityClass) {
  const envelope = await readStdinBounded();
  const keyBytes = expectedAuthorityClass === OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1
    ? readFormalPrivateKeyFdPositionally(3)
    : readFileSync(3);
  if (expectedAuthorityClass !== OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1) closeSync(3);
  if (keyBytes.length === 0 || keyBytes.length > MAX_KEY_BYTES) {
    keyBytes.fill(0);
    fail("child_key_invalid");
  }
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: keyBytes, format: "der", type: "pkcs8" });
  } finally {
    keyBytes.fill(0);
  }
  const evidence = await executeOciVerifierChild(
    envelope,
    privateKey,
    expectedAuthorityClass,
  );
  if (expectedAuthorityClass === OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1) {
    const publicKeyBytes = Buffer.from(
      createPublicKey(privateKey).export({ format: "der", type: "spki" }),
    );
    try {
      process.stdout.write(`${canonicalJson({
        schema_version: FORMAL_CHILD_RESULT_SCHEMA_VERSION,
        verifier_public_key_spki_der_base64url: publicKeyBytes.toString("base64url"),
        evidence,
      })}\n`);
    } finally {
      publicKeyBytes.fill(0);
    }
    return;
  }
  process.stdout.write(`${canonicalJson(evidence)}\n`);
}

async function privateKeyAttestationChildMain() {
  if (path.resolve(process.argv[1] ?? "") !== modulePath
    || process.argv[2] !== PRIVATE_KEY_ATTESTATION_CHILD_MODE) {
    fail("private_key_attestation_child_entrypoint_invalid");
  }
  const keyBytes = readFormalPrivateKeyFdPositionally(3);
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: keyBytes, format: "der", type: "pkcs8" });
    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
      fail("private_key_invalid");
    }
  } finally {
    keyBytes.fill(0);
  }
  const publicKeyPrincipalSha256 = verifierPublicKeyPrincipalSha256V1(
    createPublicKey(privateKey),
  );
  process.stdout.write(`${canonicalJson({
    schema_version: PRIVATE_KEY_ATTESTATION_RECEIPT_SCHEMA_VERSION,
    attester_process_id: process.pid,
    private_key_transport: "inherited_fd_3_only",
    public_key_principal_sha256: publicKeyPrincipalSha256,
  })}\n`);
}

if (path.resolve(process.argv[1] ?? "") === modulePath) {
  const mode = process.argv[2];
  const childPromise = mode === PRIVATE_KEY_ATTESTATION_CHILD_MODE
    ? privateKeyAttestationChildMain()
    : new Set([CHILD_MODE, CONTRACT_TEST_CHILD_MODE]).has(mode)
      ? childMain(mode === CHILD_MODE
        ? OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1
        : OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1)
      : null;
  childPromise?.catch(() => {
    process.stderr.write("aionis_eval_oci_private_verifier_process_failed\n");
    process.exitCode = 1;
  });
}
