import { spawn } from "node:child_process";
import {
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectExactRecord,
  expectPositiveInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import {
  OCI_ENGINE_EXECUTION_CONTEXT_V1,
  buildOciRuntimeAuthorityV1,
  canonicalOciEngineEnvironmentV1,
  inspectOciContainerPresenceV1,
  recoverOciContainerAbsentV1,
  verifyOciRuntimeAuthorityLiveV1,
} from "./oci-verifier-process.mjs";
import {
  cellPolicyBundleSetSha256V1,
  verifyPilotCaseV1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";
import {
  resolveReleaseSdkClientAuthorityV1,
} from "./release-sdk-client-authority.mjs";
import {
  assertReleasePilotCancellationAuthorityV1,
  checkpointReleasePilotCancellationV1,
  releasePilotCancellationSignalV1,
} from "./release-pilot-cancellation.mjs";
import {
  RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1,
  RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
  RELEASE_RUNTIME_OWNER_LABEL_V1,
  RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1,
  RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1,
  beginReleaseRuntimeOwnerManifestV1,
  confirmRecoveredReleaseRuntimeOwnerCleanupV1,
  confirmReleaseRuntimeOwnerCleanupV1,
  persistRecoveredReleaseRuntimeCleanupIncompleteV1,
  persistReleaseRuntimeCleanupIncompleteV1,
  readActiveReleaseRuntimeOwnerManifestV1,
  removeRecoveredReleaseRuntimeOwnerRootV1,
  resolveReleaseRuntimeOwnerManifestV1,
} from "./release-runtime-owner-manifest.mjs";

const COMMAND_TIMEOUT_MS = 180_000;
const READINESS_TIMEOUT_MS = 45_000;
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES = 16_384;
const CONTAINER_PORT = "3000/tcp";
const CONTAINER_DATA_PATH = "/data/runtime.sqlite";
const CONTAINER_TRUST_ROOT_PATH = "/run/aionis/trust-root-public.pem";
const CONTAINER_HOST_TOKEN_PATH = "/run/aionis/host-api-key";
const CONTAINER_OPERATOR_TOKEN_PATH = "/run/aionis/operator-api-key";
const RELEASE_RUNTIME_OWNER_CLASS = "release_runtime_oci_owner_v1";
const RELEASE_RUNTIME_OWNERS = new WeakMap();
const OWNED_AIONIS_ENVIRONMENT = Object.freeze([
  "AIONIS_DATA_PATH",
  "AIONIS_HOST_API_KEY_FILE",
  "AIONIS_HOST_PRINCIPAL_ID",
  "AIONIS_HTTP_BODY_LIMIT_BYTES",
  "AIONIS_HTTP_HOST",
  "AIONIS_HTTP_PORT",
  "AIONIS_LOG_LEVEL",
  "AIONIS_OPERATOR_API_KEY_FILE",
  "AIONIS_OPERATOR_PRINCIPAL_ID",
  "AIONIS_SHUTDOWN_TIMEOUT_MS",
  "AIONIS_TENANT_ID",
  "AIONIS_TRUST_ROOT_PUBLIC_KEY_PATH",
  "AIONIS_TRUST_ROOT_SHA256",
]);
const ARTIFACT_KEYS = Object.freeze([
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
const ARTIFACT_ENVELOPE_KEYS = Object.freeze(
  ARTIFACT_KEYS.filter((key) => key !== "signature"),
);
const ARTIFACT_IDENTITY_KEYS = Object.freeze(
  ARTIFACT_ENVELOPE_KEYS.filter((key) => key !== "artifact_sha256"),
);

function fail(code) {
  throw new Error(`aionis_eval_release_runtime_oci_resource_${code}`);
}

function runtimeOwnerHandle(plan, owner) {
  const handle = Object.freeze(Object.assign(Object.create(null), {
    schema_version: "aionis_release_runtime_oci_owner_handle_v1",
    authority_class: RELEASE_RUNTIME_OWNER_CLASS,
    claim_eligible: true,
    plan_sha256: plan.plan_sha256,
    resource_count: plan.schedule.length,
    owner_id: owner.ownerId,
    owner_manifest_sha256: owner.ownerManifestSha256,
    container_authority_set_sha256: owner.containerAuthoritySetSha256,
    oci_runtime_authority_sha256: owner.ociRuntimeAuthority.authority_sha256,
  }));
  RELEASE_RUNTIME_OWNERS.set(handle, {
    disposePromise: null,
    owner,
    status: "ready",
  });
  return handle;
}

function runtimeOwnerState(value) {
  const state = value !== null && typeof value === "object"
    ? RELEASE_RUNTIME_OWNERS.get(value)
    : undefined;
  if (state === undefined) fail("owner_brand_invalid");
  return state;
}

export function claimReleaseRuntimeOciResourceOwnerV1(options) {
  const input = expectExactRecord(options, [
    "plan", "runtimeOwner",
  ], "release_runtime_owner_claim_input");
  const plan = verifyPilotPlanV1(input.plan);
  const state = runtimeOwnerState(input.runtimeOwner);
  if (state.status !== "ready") fail("owner_not_ready_or_already_claimed");
  if (input.runtimeOwner.schema_version !== "aionis_release_runtime_oci_owner_handle_v1"
    || input.runtimeOwner.authority_class !== RELEASE_RUNTIME_OWNER_CLASS
    || input.runtimeOwner.plan_sha256 !== plan.plan_sha256
    || input.runtimeOwner.resource_count !== plan.schedule.length
    || input.runtimeOwner.owner_id !== state.owner.ownerId
    || input.runtimeOwner.owner_manifest_sha256 !== state.owner.ownerManifestSha256
    || input.runtimeOwner.container_authority_set_sha256
      !== state.owner.containerAuthoritySetSha256
    || input.runtimeOwner.oci_runtime_authority_sha256
      !== state.owner.ociRuntimeAuthority.authority_sha256) {
    fail("owner_live_binding_invalid");
  }
  state.status = "claimed";
  return state.owner;
}

export async function disposeReleaseRuntimeOciResourceOwnerV1(value) {
  const state = runtimeOwnerState(value);
  if (state.status === "disposed") return;
  if (state.status === "disposing") return state.disposePromise;
  state.status = "disposing";
  const disposePromise = state.owner.closeAll();
  state.disposePromise = disposePromise;
  try {
    await disposePromise;
    state.status = "disposed";
  } catch (error) {
    state.status = "cleanup_failed";
    throw error;
  } finally {
    state.disposePromise = null;
  }
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

export function assertReleaseRuntimeDaemonEnvironmentFieldsV1(value) {
  if (!Array.isArray(value)) fail("daemon_token_file_contract_invalid");
  const fields = [...value];
  if (fields.some((field) => typeof field !== "string")
    || new Set(fields).size !== fields.length
    || canonicalJson([...fields].sort()) !== canonicalJson([...OWNED_AIONIS_ENVIRONMENT].sort())) {
    fail("daemon_token_file_contract_invalid");
  }
  return Object.freeze(fields);
}

function ownerId() {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
}

function verifyOwner(stats, code) {
  const expected = ownerId();
  if (expected !== null && stats.uid !== expected) fail(code);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function verifyCanonicalAbsolutePath(value, field) {
  const input = expectText(value, field, { maximumBytes: 16_384 });
  if (!path.isAbsolute(input) || path.normalize(input) !== input || input.includes(",")) {
    fail(`${field}_invalid`);
  }
  return input;
}

async function resolveCanonicalPath(value, field) {
  const input = verifyCanonicalAbsolutePath(value, field);
  let resolved;
  try { resolved = await realpath(input); } catch { fail(`${field}_missing`); }
  if (resolved !== input) fail(`${field}_alias_forbidden`);
  return resolved;
}

async function verifyPrivateRunRoot(value) {
  const resolved = await resolveCanonicalPath(value, "private_run_root");
  const stats = await lstat(resolved, { bigint: true });
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail("private_run_root_not_directory");
  verifyOwner(stats, "private_run_root_owner_mismatch");
  if (Number(stats.mode & 0o777n) !== 0o700) fail("private_run_root_mode_invalid");
  return resolved;
}

function collectChild(child, input, timeoutMs) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    timer.unref?.();
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_OUTPUT_BYTES) stdout.push(chunk);
      else {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAX_OUTPUT_BYTES) stderr.push(chunk);
      else {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        overflow,
        timedOut,
      });
    });
    if (input === undefined) child.stdin.end();
    else child.stdin.end(input);
  });
}

async function runOci(executablePath, argv, options = {}) {
  let child;
  try {
    child = spawn(executablePath, argv, {
      cwd: OCI_ENGINE_EXECUTION_CONTEXT_V1.working_directory,
      env: canonicalOciEngineEnvironmentV1(),
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch {
    fail(`${options.operation ?? "oci_command"}_spawn_failed`);
  }
  let result;
  try {
    result = await collectChild(
      child,
      options.input,
      options.timeoutMs ?? COMMAND_TIMEOUT_MS,
    );
  } catch {
    fail(`${options.operation ?? "oci_command"}_spawn_failed`);
  }
  if (result.timedOut) fail(`${options.operation ?? "oci_command"}_timeout`);
  if (result.overflow) fail(`${options.operation ?? "oci_command"}_output_limit`);
  if (options.allowFailure !== true
    && (result.exitCode !== 0 || result.signal !== null)) {
    const operation = options.operation ?? "oci_command";
    const diagnostic = result.stderr.toString("utf8").trim();
    let safeProvisioningCode = operation === "policy_provisioning"
      && /^continuation_runtime_v1_provisioning_failed:[a-z0-9_]+$/u.test(diagnostic)
      ? diagnostic.slice("continuation_runtime_v1_provisioning_failed:".length)
      : null;
    if (operation === "policy_provisioning" && safeProvisioningCode === null) {
      try {
        const event = JSON.parse(result.stdout.toString("utf8"));
        if (event?.event === "provisioning_failed"
          && typeof event.failure_code === "string"
          && /^[a-z0-9_]+$/u.test(event.failure_code)) {
          safeProvisioningCode = event.failure_code;
        }
      } catch { /* expose no untrusted process output */ }
    }
    fail(`${operation}_failed${safeProvisioningCode === null ? "" : `_${safeProvisioningCode}`}`);
  }
  return result;
}

function parseJsonOutput(bytes, operation) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { fail(`${operation}_json_invalid`); }
  return value;
}

function oneCanonicalJsonLine(bytes, operation) {
  const text = bytes.toString("utf8");
  const lines = text.split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length !== 1) fail(`${operation}_json_line_invalid`);
  let value;
  try { value = JSON.parse(lines[0]); } catch { fail(`${operation}_json_invalid`); }
  if (canonicalJson(value) !== lines[0]) fail(`${operation}_json_not_canonical`);
  return value;
}

async function inspectImage(executablePath, reference, expectedDigest) {
  const result = await runOci(executablePath, ["inspect", "--type=image", reference], {
    operation: "image_inspect",
  });
  const values = parseJsonOutput(result.stdout, "image_inspect");
  if (!Array.isArray(values) || values.length !== 1) fail("image_inspect_count_invalid");
  const value = values[0];
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || value.Id !== expectedDigest) fail("image_digest_mismatch");
  if (value.Os !== "linux" || typeof value.Architecture !== "string"
    || value.Architecture.length === 0 || value.Config?.User !== "node") {
    fail("image_platform_or_user_invalid");
  }
  return deepFreeze({
    digest: value.Id,
    os: value.Os,
    architecture: value.Architecture,
    configured_user: value.Config.User,
  });
}

const IMAGE_CLOSURE_PROBE_SOURCE = String.raw`
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
const root = "/app";
const manifestPath = path.join(root, "runtime-closure.manifest.json");
const raw = readFileSync(manifestPath);
const sha = (value) => createHash("sha256").update(value).digest("hex");
const manifest = JSON.parse(raw.toString("utf8"));
if (manifest.schema !== "aionis.continuation-runtime.oci-closure.v1"
  || manifest.hash_algorithm !== "sha256"
  || manifest.closure_encoding !== "sorted_path_nul_sha256_lf_v1"
  || !Array.isArray(manifest.files)
  || manifest.file_count !== manifest.files.length) throw new Error("manifest_invalid");
const paths = manifest.files.map((entry) => entry.path);
if (new Set(paths).size !== paths.length
  || JSON.stringify(paths) !== JSON.stringify([...paths].sort((a, b) => Buffer.from(a).compare(Buffer.from(b))))) {
  throw new Error("manifest_paths_invalid");
}
for (const entry of manifest.files) {
  if (typeof entry.path !== "string" || !/^[A-Za-z0-9._/-]+$/.test(entry.path)
    || path.posix.normalize(entry.path) !== entry.path
    || entry.path.startsWith("/") || entry.path.startsWith("../")
    || !/^[0-9a-f]{64}$/.test(entry.sha256)
    || sha(readFileSync(path.join(root, entry.path))) !== entry.sha256) {
    throw new Error("manifest_file_invalid");
  }
}
const closure = sha(manifest.files.map((entry) => entry.path + "\0" + entry.sha256 + "\n").join(""));
if (closure !== manifest.closure_sha256) throw new Error("closure_invalid");
const config = await import("file:///app/dist/runtime-v1/config.js");
console.log(JSON.stringify({
  schema_version: "aionis_release_runtime_image_probe_v1",
  manifest_sha256: sha(raw),
  closure_sha256: closure,
  file_count: manifest.file_count,
  entries: manifest.entries,
  daemon_environment_fields: config.CONTINUATION_RUNTIME_V1_DAEMON_ENV_FIELDS,
  runtime_uid: process.getuid(),
  runtime_gid: process.getgid(),
}));
`;

async function probeImageClosure(executablePath, digest, runtimeBinding) {
  const result = await runOci(executablePath, [
    "run",
    "--rm",
    "--pull=never",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pids-limit=64",
    "--ipc=none",
    "--entrypoint=node",
    digest,
    "--input-type=module",
    "--eval",
    IMAGE_CLOSURE_PROBE_SOURCE,
  ], { operation: "image_closure_probe" });
  const report = parseJsonOutput(result.stdout, "image_closure_probe");
  if (report?.schema_version !== "aionis_release_runtime_image_probe_v1"
    || report.manifest_sha256 !== runtimeBinding.oci_closure_manifest_sha256
    || report.closure_sha256 !== runtimeBinding.oci_closure_sha256
    || !Number.isSafeInteger(report.file_count) || report.file_count < 1
    || !Array.isArray(report.entries)
    || !report.entries.includes("dist/runtime-v1/daemon-entry.js")
    || !report.entries.includes("dist/runtime-v1/provisioning-entry.js")
    || report.runtime_uid !== 1_000
    || report.runtime_gid !== 1_000) {
    fail("image_closure_binding_invalid");
  }
  assertReleaseRuntimeDaemonEnvironmentFieldsV1(report.daemon_environment_fields);
  return deepFreeze(canonicalClone(report));
}

async function readPinnedTrustRoot(sourcePath, expectedPrincipalSha256, destination) {
  const resolved = await resolveCanonicalPath(sourcePath, "trust_root_public_key_path");
  const handle = await open(resolved, "r");
  let bytes;
  try {
    const before = await handle.stat({ bigint: true });
    const pathStats = await lstat(resolved, { bigint: true });
    if (!before.isFile() || pathStats.isSymbolicLink() || !sameIdentity(before, pathStats)
      || before.nlink !== 1n || before.size < 1n
      || before.size > BigInt(MAX_PUBLIC_KEY_BYTES)) fail("trust_root_file_posture_invalid");
    if (typeof process.getuid === "function"
      && before.uid !== 0n && before.uid !== BigInt(process.getuid())) {
      fail("trust_root_file_owner_mismatch");
    }
    if (Number(before.mode & 0o022n) !== 0) fail("trust_root_file_mode_invalid");
    bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (!sameIdentity(before, after) || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      fail("trust_root_file_changed_during_read");
    }
  } finally {
    await handle.close();
  }
  try {
    let publicKey;
    try { publicKey = createPublicKey(bytes); } catch { fail("trust_root_public_key_invalid"); }
    if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
      fail("trust_root_public_key_invalid");
    }
    const canonicalPublicPem = Buffer.from(publicKey.export({ format: "pem", type: "spki" }));
    if (!bytes.equals(canonicalPublicPem)) fail("trust_root_public_key_not_canonical_public_pem");
    const principal = sha256Bytes(publicKey.export({ format: "der", type: "spki" }));
    if (principal !== expectedPrincipalSha256) fail("trust_root_principal_mismatch");
    await writeFile(destination, bytes, { flag: "wx", mode: 0o400 });
    await chmod(destination, 0o400);
    return publicKey;
  } finally {
    bytes.fill(0);
  }
}

function verifyCases(plan, values) {
  const cases = expectArray(values, "release_runtime_cases", {
    minimum: 3,
    maximum: 3,
  }).map((value) => verifyPilotCaseV1(value));
  if (cases.some((pilotCase, index) => pilotCase.case_id !== plan.cases[index].case_id
    || pilotCase.case_sha256 !== plan.cases[index].case_sha256)) {
    fail("case_plan_binding_invalid");
  }
  return cases;
}

function authoritySubject(plan, cell) {
  return canonicalSha256({
    schema_version: "continuation_authority_subject_v1",
    tenant_id: plan.runtime_binding.tenant_id,
    scope: cell.isolation.runtime_scope,
    task_family: plan.runtime_binding.task_family,
  });
}

function verifySignedPolicyArtifact(value, expected, publicKey) {
  const record = expectExactRecord(value, ARTIFACT_KEYS, `${expected.field}_artifact`);
  if (record.tenant_id !== expected.tenantId
    || record.authority_subject_sha256 !== expected.subject
    || record.artifact_kind !== expected.kind
    || record.artifact_schema !== expected.schema
    || record.signature_algorithm !== "ed25519"
    || record.signer_principal_sha256 !== expected.trustRootSha256
    || record.trust_root_sha256 !== expected.trustRootSha256
    || record.payload === null || typeof record.payload !== "object"
    || Array.isArray(record.payload)
    || record.payload.tenant_id !== expected.tenantId
    || record.payload.authority_subject_sha256 !== expected.subject) {
    fail(`${expected.field}_artifact_binding_invalid`);
  }
  expectText(record.artifact_id, `${expected.field}_artifact_id`);
  expectPositiveInteger(record.artifact_revision, `${expected.field}_artifact_revision`);
  for (const field of [
    "artifact_sha256", "payload_sha256", "signer_principal_sha256", "trust_root_sha256",
  ]) expectSha256(record[field], `${expected.field}_${field}`);
  if (canonicalSha256(record.payload) !== record.payload_sha256) {
    fail(`${expected.field}_payload_digest_mismatch`);
  }
  const identity = Object.fromEntries(
    ARTIFACT_IDENTITY_KEYS.map((key) => [key, record[key]]),
  );
  if (canonicalSha256(identity) !== record.artifact_sha256) {
    fail(`${expected.field}_artifact_digest_mismatch`);
  }
  const envelope = Object.fromEntries(
    ARTIFACT_ENVELOPE_KEYS.map((key) => [key, record[key]]),
  );
  let signature;
  try { signature = Buffer.from(record.signature, "base64url"); } catch {
    fail(`${expected.field}_signature_invalid`);
  }
  if (signature.length !== 64 || signature.toString("base64url") !== record.signature
    || !verifySignature(
      null,
      Buffer.from(canonicalJson(envelope), "utf8"),
      publicKey,
      signature,
    )) fail(`${expected.field}_signature_invalid`);
  return deepFreeze({
    artifact_sha256: record.artifact_sha256,
    payload_sha256: record.payload_sha256,
  });
}

function verifyPolicyCommands(plan, values, publicKey) {
  const commands = expectArray(values, "cell_policy_commands", {
    minimum: 9,
    maximum: 9,
  });
  const bindings = commands.map((commandValue, index) => {
    const cell = plan.schedule[index];
    const command = expectExactRecord(commandValue, [
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
    ], `cell_policy_command_${index}`);
    const subject = authoritySubject(plan, cell);
    if (command.schema_version !== "offline_provisioning_command_v1"
      || command.kind !== "policy_bundle_install"
      || command.actor_kind !== "operator"
      || command.tenant_id !== plan.runtime_binding.tenant_id
      || command.scope !== cell.isolation.runtime_scope
      || command.task_family !== plan.runtime_binding.task_family
      || command.authority_subject_sha256 !== subject) {
      fail("cell_policy_command_binding_invalid");
    }
    expectText(command.operation_id, `cell_policy_command_${index}_operation_id`);
    expectSha256(
      command.actor_principal_sha256,
      `cell_policy_command_${index}_actor_principal_sha256`,
    );
    const bundle = expectExactRecord(command.policy_bundle, [
      "authority_subject_sha256",
      "compiler_policy",
      "evidence_policy",
      "schema_version",
      "tenant_id",
    ], `cell_policy_bundle_${index}`);
    if (bundle.schema_version !== "authority_policy_provisioning_bundle_v1"
      || bundle.tenant_id !== plan.runtime_binding.tenant_id
      || bundle.authority_subject_sha256 !== subject) {
      fail("cell_policy_bundle_binding_invalid");
    }
    const compilerPolicyRef = verifySignedPolicyArtifact(bundle.compiler_policy, {
      field: `cell_${index}_compiler_policy`,
      kind: "compiler_policy",
      schema: "continuation_compiler_policy_v1",
      subject,
      tenantId: plan.runtime_binding.tenant_id,
      trustRootSha256: plan.runtime_binding.trust_root_sha256,
    }, publicKey);
    const evidencePolicyRef = verifySignedPolicyArtifact(bundle.evidence_policy, {
      field: `cell_${index}_evidence_policy`,
      kind: "evidence_policy",
      schema: "effect_evidence_policy_v1",
      subject,
      tenantId: plan.runtime_binding.tenant_id,
      trustRootSha256: plan.runtime_binding.trust_root_sha256,
    }, publicKey);
    return deepFreeze({
      command: canonicalClone(command),
      binding: {
        ordinal: cell.ordinal,
        opaque_cell_id: cell.opaque_cell_id,
        runtime_scope: cell.isolation.runtime_scope,
        authority_subject_sha256: subject,
        provisioning_command_sha256: canonicalSha256(command),
        compiler_policy_ref: compilerPolicyRef,
        evidence_policy_ref: evidencePolicyRef,
      },
    });
  });
  const setSha256 = cellPolicyBundleSetSha256V1({
    pilotId: plan.pilot_id,
    tenantId: plan.runtime_binding.tenant_id,
    taskFamily: plan.runtime_binding.task_family,
    trustRootSha256: plan.runtime_binding.trust_root_sha256,
    bindings: bindings.map(({ binding }) => binding),
  });
  if (setSha256 !== plan.runtime_binding.cell_policy_bundle_set_sha256) {
    fail("cell_policy_command_set_binding_invalid");
  }
  return bindings;
}

function numericUser() {
  if (typeof process.getuid !== "function" || typeof process.getgid !== "function") {
    fail("numeric_user_unavailable");
  }
  const uid = process.getuid();
  const gid = process.getgid();
  if (!Number.isSafeInteger(uid) || uid < 1 || !Number.isSafeInteger(gid) || gid < 0) {
    fail("numeric_user_invalid");
  }
  return { uid, gid, value: `${uid}:${gid}` };
}

function safeComponent(value) {
  return value.toLowerCase().replace(/[^a-z0-9_.-]/gu, "-").slice(0, 80);
}

function sdkClientFacade(value) {
  const methods = [
    "createContinuation",
    "decideAuthority",
    "readDecision",
    "recordObservations",
    "recordOutcome",
  ];
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || methods.some((method) => typeof value[method] !== "function")) {
    fail("sdk_client_invalid");
  }
  return Object.freeze(Object.fromEntries(methods.map((method) => [
    method,
    (...args) => value[method](...args),
  ])));
}

function mount(source, target, readOnly = false) {
  return `type=bind,src=${source},dst=${target}${readOnly ? ",readonly" : ""}`;
}

function provisioningCreateArgv(config) {
  return [
    "create",
    "--interactive",
    "--name", config.name,
    "--pull=never",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pids-limit=128",
    "--ipc=none",
    `--user=${config.user.value}`,
    "--mount", mount(config.dataDirectory, "/data"),
    "--mount", mount(config.authorityDirectory, "/run/aionis", true),
    "--tmpfs", `/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=${config.user.uid},gid=${config.user.gid}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner}=${RELEASE_RUNTIME_OWNER_LABEL_V1}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner_id}=${config.ownerId}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.plan_sha256}=${config.plan.plan_sha256}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.cell_id}=${config.cell.opaque_cell_id}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.resource_kind}=provisioning`,
    `--env=AIONIS_DATA_PATH=${CONTAINER_DATA_PATH}`,
    `--env=AIONIS_TRUST_ROOT_PUBLIC_KEY_PATH=${CONTAINER_TRUST_ROOT_PATH}`,
    `--env=AIONIS_TRUST_ROOT_SHA256=${config.plan.runtime_binding.trust_root_sha256}`,
    "--entrypoint=node",
    config.imageDigest,
    "dist/runtime-v1/provisioning-entry.js",
  ];
}

function daemonCreateArgv(config) {
  return [
    "create",
    "--name", config.name,
    "--pull=never",
    "--init",
    "--network=bridge",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pids-limit=256",
    "--ipc=none",
    "--restart=no",
    "--stop-signal=SIGTERM",
    "--stop-timeout=15",
    "--no-healthcheck",
    `--user=${config.user.value}`,
    "--mount", mount(config.dataDirectory, "/data"),
    "--mount", mount(config.authorityDirectory, "/run/aionis", true),
    "--tmpfs", `/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=${config.user.uid},gid=${config.user.gid}`,
    `--publish=127.0.0.1::${CONTAINER_PORT}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner}=${RELEASE_RUNTIME_OWNER_LABEL_V1}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner_id}=${config.ownerId}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.plan_sha256}=${config.plan.plan_sha256}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.cell_id}=${config.cell.opaque_cell_id}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.resource_kind}=daemon`,
    `--env=AIONIS_DATA_PATH=${CONTAINER_DATA_PATH}`,
    `--env=AIONIS_HOST_API_KEY_FILE=${CONTAINER_HOST_TOKEN_PATH}`,
    `--env=AIONIS_HOST_PRINCIPAL_ID=${config.hostPrincipalId}`,
    "--env=AIONIS_HTTP_BODY_LIMIT_BYTES=1048576",
    "--env=AIONIS_HTTP_HOST=0.0.0.0",
    "--env=AIONIS_HTTP_PORT=3000",
    "--env=AIONIS_LOG_LEVEL=silent",
    `--env=AIONIS_OPERATOR_API_KEY_FILE=${CONTAINER_OPERATOR_TOKEN_PATH}`,
    `--env=AIONIS_OPERATOR_PRINCIPAL_ID=${config.operatorPrincipalId}`,
    "--env=AIONIS_SHUTDOWN_TIMEOUT_MS=10000",
    `--env=AIONIS_TENANT_ID=${config.plan.runtime_binding.tenant_id}`,
    `--env=AIONIS_TRUST_ROOT_PUBLIC_KEY_PATH=${CONTAINER_TRUST_ROOT_PATH}`,
    `--env=AIONIS_TRUST_ROOT_SHA256=${config.plan.runtime_binding.trust_root_sha256}`,
    "--entrypoint=node",
    config.imageDigest,
    "dist/runtime-v1/daemon-entry.js",
  ];
}

async function inspectContainer(executablePath, containerId) {
  const result = await runOci(executablePath, ["container", "inspect", containerId], {
    operation: "container_inspect",
  });
  const values = parseJsonOutput(result.stdout, "container_inspect");
  if (!Array.isArray(values) || values.length !== 1) fail("container_inspect_count_invalid");
  return values[0];
}

function environmentMap(values) {
  if (!Array.isArray(values)) fail("container_environment_invalid");
  const result = new Map();
  for (const value of values) {
    if (typeof value !== "string" || !value.includes("=")) fail("container_environment_invalid");
    const index = value.indexOf("=");
    const name = value.slice(0, index);
    if (result.has(name)) fail("container_environment_duplicate");
    result.set(name, value.slice(index + 1));
  }
  return result;
}

function findMount(inspect, destination) {
  const matches = Array.isArray(inspect.Mounts)
    ? inspect.Mounts.filter((value) => value?.Destination === destination)
    : [];
  if (matches.length !== 1) fail("container_mount_invalid");
  return matches[0];
}

function assertContainerConfiguration(inspect, expected, tokenValues) {
  const hostConfig = inspect?.HostConfig;
  const config = inspect?.Config;
  if (typeof inspect?.Id !== "string" || !/^[0-9a-f]{64}$/u.test(inspect.Id)
    || config?.Image !== expected.imageDigest
    || JSON.stringify(config.Entrypoint) !== JSON.stringify(["node"])
    || JSON.stringify(config.Cmd) !== JSON.stringify(["dist/runtime-v1/daemon-entry.js"])
    || config.User !== expected.user.value
    || hostConfig?.ReadonlyRootfs !== true
    || hostConfig?.NetworkMode !== "bridge"
    || hostConfig?.IpcMode !== "none"
    || hostConfig?.Init !== true
    || hostConfig?.PidsLimit !== 256
    || hostConfig?.RestartPolicy?.Name !== "no"
    || !Array.isArray(hostConfig.CapDrop) || !hostConfig.CapDrop.includes("ALL")
    || !Array.isArray(hostConfig.SecurityOpt)
    || !hostConfig.SecurityOpt.includes("no-new-privileges:true")) {
    fail("container_posture_invalid");
  }
  if (config.Labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner]
      !== RELEASE_RUNTIME_OWNER_LABEL_V1
    || config.Labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner_id]
      !== expected.ownerId
    || config.Labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.plan_sha256]
      !== expected.plan.plan_sha256
    || config.Labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.cell_id]
      !== expected.cell.opaque_cell_id
    || config.Labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.resource_kind]
      !== "daemon") {
    fail("container_label_binding_invalid");
  }
  const environment = environmentMap(config.Env);
  if (environment.has("AIONIS_HOST_API_KEY")
    || environment.has("AIONIS_OPERATOR_API_KEY")) fail("token_environment_forbidden");
  const expectedEnvironment = new Map([
    ["AIONIS_DATA_PATH", CONTAINER_DATA_PATH],
    ["AIONIS_HOST_API_KEY_FILE", CONTAINER_HOST_TOKEN_PATH],
    ["AIONIS_HOST_PRINCIPAL_ID", expected.hostPrincipalId],
    ["AIONIS_HTTP_BODY_LIMIT_BYTES", "1048576"],
    ["AIONIS_HTTP_HOST", "0.0.0.0"],
    ["AIONIS_HTTP_PORT", "3000"],
    ["AIONIS_LOG_LEVEL", "silent"],
    ["AIONIS_OPERATOR_API_KEY_FILE", CONTAINER_OPERATOR_TOKEN_PATH],
    ["AIONIS_OPERATOR_PRINCIPAL_ID", expected.operatorPrincipalId],
    ["AIONIS_SHUTDOWN_TIMEOUT_MS", "10000"],
    ["AIONIS_TENANT_ID", expected.plan.runtime_binding.tenant_id],
    ["AIONIS_TRUST_ROOT_PUBLIC_KEY_PATH", CONTAINER_TRUST_ROOT_PATH],
    ["AIONIS_TRUST_ROOT_SHA256", expected.plan.runtime_binding.trust_root_sha256],
  ]);
  for (const [name, value] of expectedEnvironment) {
    if (environment.get(name) !== value) fail("container_environment_binding_invalid");
  }
  const actualAionisFields = [...environment.keys()]
    .filter((name) => name.startsWith("AIONIS_"))
    .sort();
  if (JSON.stringify(actualAionisFields) !== JSON.stringify([...OWNED_AIONIS_ENVIRONMENT].sort())) {
    fail("container_environment_surface_invalid");
  }
  const serialized = JSON.stringify(inspect);
  if (tokenValues.some((token) => serialized.includes(token))) fail("token_exposed_in_inspect");
  for (const [destination, source, writable] of [
    ["/data", expected.dataDirectory, true],
    ["/run/aionis", expected.authorityDirectory, false],
  ]) {
    const entry = findMount(inspect, destination);
    if (entry.Type !== "bind" || entry.Source !== source || entry.RW !== writable) {
      fail("container_mount_binding_invalid");
    }
  }
  const mountDestinations = inspect.Mounts.map((entry) => entry.Destination).sort();
  if (JSON.stringify(mountDestinations) !== JSON.stringify(["/data", "/run/aionis"])) {
    fail("container_mount_surface_invalid");
  }
  const portBinding = hostConfig?.PortBindings?.[CONTAINER_PORT];
  if (!Array.isArray(portBinding) || portBinding.length !== 1
    || portBinding[0].HostIp !== "127.0.0.1") fail("container_port_binding_invalid");
  return deepFreeze({
    container_id: inspect.Id,
    configuration_sha256: canonicalSha256({
      image: config.Image,
      entrypoint: config.Entrypoint,
      command: config.Cmd,
      user: config.User,
      environment: [...expectedEnvironment.entries()].map(([name, value]) => ({ name, value })),
      labels: {
        owner: config.Labels[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner],
        owner_id: config.Labels[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner_id],
        plan_sha256:
          config.Labels[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.plan_sha256],
        cell_id: config.Labels[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.cell_id],
        resource_kind:
          config.Labels[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.resource_kind],
      },
      posture: {
        read_only: hostConfig.ReadonlyRootfs,
        network_mode: hostConfig.NetworkMode,
        ipc_mode: hostConfig.IpcMode,
        init: hostConfig.Init,
        pids_limit: hostConfig.PidsLimit,
        cap_drop: hostConfig.CapDrop,
        security_opt: hostConfig.SecurityOpt,
        restart_policy: hostConfig.RestartPolicy.Name,
      },
      mounts: [
        { destination: "/data", source_sha256: sha256Bytes(expected.dataDirectory), writable: true },
        {
          destination: "/run/aionis",
          source_sha256: sha256Bytes(expected.authorityDirectory),
          writable: false,
        },
      ],
      published_port: { container_port: CONTAINER_PORT, host_ip: "127.0.0.1" },
    }),
  });
}

function publishedPort(inspect) {
  const bindings = inspect?.NetworkSettings?.Ports?.[CONTAINER_PORT];
  if (!Array.isArray(bindings) || bindings.length !== 1
    || bindings[0].HostIp !== "127.0.0.1"
    || typeof bindings[0].HostPort !== "string"
    || !/^\d{1,5}$/u.test(bindings[0].HostPort)) fail("published_port_invalid");
  const port = Number(bindings[0].HostPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    fail("published_port_invalid");
  }
  return port;
}

async function waitReady(baseUrl, cancellationAuthority) {
  const deadline = Date.now() + READINESS_TIMEOUT_MS;
  while (Date.now() < deadline) {
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    try {
      const response = await fetch(`${baseUrl}/readyz`, {
        signal: AbortSignal.any([
          AbortSignal.timeout(1_500),
          releasePilotCancellationSignalV1(cancellationAuthority),
        ]),
      });
      if (response.status === 200) {
        const value = await response.json();
        if (value?.schema_version === "continuation_runtime_readiness_v1"
          && value.status === "ready"
          && Array.isArray(value.reason_codes)
          && value.reason_codes.length === 0) return;
      }
    } catch { /* retry until the bounded deadline */ }
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  fail("daemon_readiness_timeout");
}

function policyRefsFromProvisioningEvent(value, expected) {
  const result = value?.operation?.receipt?.result;
  if (value?.event !== "provisioning_complete"
    || value?.operation?.status !== "created"
    || result?.decision_kind !== "policy_bundle_install"
    || canonicalJson(result.compiler_policy_ref)
      !== canonicalJson(expected.compiler_policy_ref)
    || canonicalJson(result.evidence_policy_ref)
      !== canonicalJson(expected.evidence_policy_ref)) {
    fail("provisioning_result_binding_invalid");
  }
}

async function verifyDatabasePosture(dataPath) {
  const parent = path.dirname(dataPath);
  if (await realpath(parent) !== parent) fail("data_directory_alias_forbidden");
  const stats = await lstat(dataPath, { bigint: true });
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1n) {
    fail("database_file_posture_invalid");
  }
  verifyOwner(stats, "database_file_owner_mismatch");
  if (Number(stats.mode & 0o777n) !== 0o600) {
    await chmod(dataPath, 0o600);
    const after = await lstat(dataPath, { bigint: true });
    if (!sameIdentity(stats, after) || Number(after.mode & 0o777n) !== 0o600) {
      fail("database_file_mode_invalid");
    }
  }
}

async function stopAndRemoveContainer(runtimeAuthority, containerReference) {
  return recoverOciContainerAbsentV1({
    runtimeAuthority,
    containerReference,
    terminationMode: "graceful_then_force_remove",
  });
}

function containerDeletionExpectation(common, name, resourceKind) {
  return Object.freeze({
    authorityDirectory: common.authorityDirectory,
    cellId: common.cell.opaque_cell_id,
    dataDirectory: common.dataDirectory,
    imageDigest: common.imageDigest,
    name,
    ownerId: common.ownerId,
    planSha256: common.plan.plan_sha256,
    resourceKind,
  });
}

function assertContainerDeletionBinding(inspect, expected, expectedContainerId = null) {
  const labels = inspect?.Config?.Labels;
  const dataMount = findMount(inspect, "/data");
  const authorityMount = findMount(inspect, "/run/aionis");
  const mountDestinations = Array.isArray(inspect?.Mounts)
    ? inspect.Mounts.map((entry) => entry?.Destination).sort()
    : [];
  if (typeof inspect?.Id !== "string" || !/^[0-9a-f]{64}$/u.test(inspect.Id)
    || (expectedContainerId !== null && inspect.Id !== expectedContainerId)
    || inspect.Name !== `/${expected.name}`
    || inspect.Config?.Image !== expected.imageDigest
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner]
      !== RELEASE_RUNTIME_OWNER_LABEL_V1
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner_id]
      !== expected.ownerId
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.plan_sha256]
      !== expected.planSha256
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.cell_id]
      !== expected.cellId
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.resource_kind]
      !== expected.resourceKind
    || dataMount.Type !== "bind"
    || dataMount.Source !== expected.dataDirectory
    || dataMount.RW !== true
    || authorityMount.Type !== "bind"
    || authorityMount.Source !== expected.authorityDirectory
    || authorityMount.RW !== false
    || JSON.stringify(mountDestinations) !== JSON.stringify(["/data", "/run/aionis"])) {
    fail("container_cleanup_binding_invalid");
  }
  return inspect.Id;
}

async function assertContainerNameAbsent(runtimeAuthority, name) {
  const presence = await inspectOciContainerPresenceV1({
    containerReference: name,
    runtimeAuthority,
  });
  if (presence.presence !== "absent") fail("container_name_collision");
}

async function verifyCreatedContainerOwnership(
  runtimeAuthority,
  expected,
  expectedContainerId,
) {
  await verifyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  const presence = await inspectOciContainerPresenceV1({
    containerReference: expected.name,
    runtimeAuthority,
  });
  if (presence.presence !== "present"
    || presence.container_id !== expectedContainerId) {
    fail("created_container_identity_invalid");
  }
  const inspect = await inspectContainer(
    runtimeAuthority.executable_path,
    expectedContainerId,
  );
  const containerId = assertContainerDeletionBinding(
    inspect,
    expected,
    expectedContainerId,
  );
  await verifyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  return containerId;
}

async function removeExactlyOwnedContainer(
  runtimeAuthority,
  expected,
  expectedContainerId,
) {
  const presence = await inspectOciContainerPresenceV1({
    containerReference: expectedContainerId,
    runtimeAuthority,
  });
  if (presence.presence === "absent") {
    const namePresence = await inspectOciContainerPresenceV1({
      containerReference: expected.name,
      runtimeAuthority,
    });
    if (namePresence.presence !== "absent") fail("container_name_rebound");
    return false;
  }
  if (presence.container_id !== expectedContainerId) {
    fail("container_cleanup_identity_invalid");
  }
  await verifyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  const inspect = await inspectContainer(
    runtimeAuthority.executable_path,
    expectedContainerId,
  );
  assertContainerDeletionBinding(inspect, expected, expectedContainerId);
  await verifyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  const proof = await stopAndRemoveContainer(runtimeAuthority, expectedContainerId);
  if (proof.presence !== "absent"
    || proof.initial_container_id !== expectedContainerId) {
    fail("container_cleanup_proof_invalid");
  }
  const namePresence = await inspectOciContainerPresenceV1({
    containerReference: expected.name,
    runtimeAuthority,
  });
  if (namePresence.presence !== "absent") fail("container_name_rebound");
  return true;
}

async function removeOwnedRoot(resourceRoot, rootIdentity, children) {
  let current;
  try { current = await lstat(resourceRoot, { bigint: true }); } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (!current.isDirectory() || !sameIdentity(current, rootIdentity)) {
    fail("cleanup_root_identity_changed");
  }
  for (const child of [...children].reverse()) {
    await rm(child, { recursive: true, force: true });
  }
  await rm(resourceRoot, { recursive: true, force: true });
}

function orphanContainerName(ownerIdValue, resourceKind, ordinal) {
  return safeComponent(
    `aionis-${resourceKind === "daemon" ? "run" : "prov"}-${ownerIdValue}-${ordinal}`,
  );
}

async function runtimeOwnerEntryNames(privateRunRoot) {
  return (await readdir(privateRunRoot, { withFileTypes: true }))
    .filter((entry) => entry.name.startsWith(".aionis-release-runtime-"))
    .map((entry) => ({
      name: entry.name,
      type: entry.isDirectory() ? "directory" : entry.isFile() ? "file" : "other",
    }));
}

function assertRuntimeOwnerEntrySet(entries, manifest = null) {
  if (manifest === null) {
    if (entries.length !== 0) fail("unmanifested_runtime_owner_artifact_present");
    return;
  }
  const allowed = new Map([
    [RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1, "file"],
    [RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1, "file"],
    [RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1, "file"],
    [manifest.resource_root_name, "directory"],
  ]);
  for (const entry of entries) {
    const expectedType = allowed.get(entry.name);
    if (expectedType === undefined || expectedType !== entry.type) {
      fail("runtime_owner_artifact_set_invalid");
    }
  }
}

async function inspectOwnedOrphanContainer({
  expectedCell,
  expectedContainerId,
  manifest,
  resourceKind,
  resourceRoot,
  runtimeAuthority,
  reference,
}) {
  await verifyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  const inspect = await inspectContainer(runtimeAuthority.executable_path, reference);
  await verifyOciRuntimeAuthorityLiveV1(runtimeAuthority);
  const labels = inspect?.Config?.Labels;
  const expectedCellRoot = path.join(
    resourceRoot,
    `cell-${String(expectedCell.ordinal).padStart(2, "0")}`,
  );
  const dataMount = findMount(inspect, "/data");
  const authorityMount = findMount(inspect, "/run/aionis");
  if (inspect.Id !== expectedContainerId
    || inspect.Name !== `/${reference}`
    || inspect.Config?.Image !== manifest.runtime_image_digest
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner]
      !== RELEASE_RUNTIME_OWNER_LABEL_V1
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner_id]
      !== manifest.owner_id
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.plan_sha256]
      !== manifest.plan_sha256
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.cell_id]
      !== expectedCell.opaque_cell_id
    || labels?.[RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.resource_kind]
      !== resourceKind
    || dataMount.Type !== "bind"
    || dataMount.Source !== path.join(expectedCellRoot, "data")
    || authorityMount.Type !== "bind"
    || authorityMount.Source !== path.join(expectedCellRoot, "authority")) {
    fail("orphan_container_binding_invalid");
  }
  return inspect.Id;
}

function runtimeReconciliationReceipt(bodyValue) {
  const body = canonicalClone(bodyValue);
  return canonicalClone({ ...body, receipt_sha256: canonicalSha256(body) });
}

/**
 * Reconciles only the exact owner named by the durable manifest. A different
 * plan, authority, label, mount, name, or filesystem identity blocks startup.
 */
export async function reconcileReleaseRuntimeOciOwnerV1(options) {
  const input = expectExactRecord(options, [
    "ociExecutablePath", "privateRunRoot",
  ], "release_runtime_oci_reconciliation_input");
  const privateRunRoot = await verifyPrivateRunRoot(input.privateRunRoot);
  const recovery = await readActiveReleaseRuntimeOwnerManifestV1({ privateRunRoot });
  const entries = await runtimeOwnerEntryNames(privateRunRoot);
  if (recovery === null) {
    assertRuntimeOwnerEntrySet(entries, null);
    return runtimeReconciliationReceipt({
      schema_version: "aionis_release_runtime_reconciliation_receipt_v1",
      status: "no_orphan_owner_present",
      owner_id: null,
      plan_sha256: null,
      owner_manifest_sha256: null,
      discovered_container_count: 0,
      removed_container_count: 0,
      cleanup_confirmed: true,
      new_pilot_permitted: true,
    });
  }

  const manifest = recovery.manifest;
  let stage = "manifest_verification";
  let discoveredContainerCount = 0;
  let removedContainerCount = 0;
  try {
    assertRuntimeOwnerEntrySet(entries, manifest);
    const ociExecutablePath = await resolveCanonicalPath(
      input.ociExecutablePath,
      "oci_executable_path",
    );
    const runtimeAuthority = await buildOciRuntimeAuthorityV1({
      executablePath: ociExecutablePath,
    });
    await verifyOciRuntimeAuthorityLiveV1(runtimeAuthority);
    if (manifest.oci_runtime_authority_sha256 !== runtimeAuthority.authority_sha256
      || manifest.oci_engine_execution_context_sha256
        !== canonicalSha256(OCI_ENGINE_EXECUTION_CONTEXT_V1)) {
      fail("orphan_oci_authority_binding_mismatch");
    }
    const cells = [...manifest.scheduled_cells].sort((left, right) =>
      right.ordinal - left.ordinal);
    for (const resourceKind of ["daemon", "provisioning"]) {
      for (const cell of cells) {
        const reference = orphanContainerName(
          manifest.owner_id,
          resourceKind,
          cell.ordinal,
        );
        stage = "container_discovery";
        const presence = await inspectOciContainerPresenceV1({
          containerReference: reference,
          runtimeAuthority,
        });
        if (presence.presence === "absent") continue;
        discoveredContainerCount += 1;
        stage = "container_inspection";
        const containerId = await inspectOwnedOrphanContainer({
          expectedCell: cell,
          expectedContainerId: presence.container_id,
          manifest,
          resourceKind,
          resourceRoot: recovery.resourceRoot,
          runtimeAuthority,
          reference,
        });
        stage = "container_removal";
        const proof = await recoverOciContainerAbsentV1({
          containerReference: containerId,
          runtimeAuthority,
          terminationMode: "graceful_then_force_remove",
        });
        if (proof.presence !== "absent"
          || proof.initial_container_id !== containerId) {
          fail("orphan_container_removal_proof_invalid");
        }
        removedContainerCount += 1;
      }
    }
    stage = "resource_root_removal";
    await removeRecoveredReleaseRuntimeOwnerRootV1(recovery);
    const confirmation = await confirmRecoveredReleaseRuntimeOwnerCleanupV1(recovery);
    if (confirmation.cleanup_confirmed !== true) fail("orphan_cleanup_unconfirmed");
    return runtimeReconciliationReceipt({
      schema_version: "aionis_release_runtime_reconciliation_receipt_v1",
      status: "orphan_owner_reconciled",
      owner_id: manifest.owner_id,
      plan_sha256: manifest.plan_sha256,
      owner_manifest_sha256: manifest.manifest_sha256,
      discovered_container_count: discoveredContainerCount,
      removed_container_count: removedContainerCount,
      cleanup_confirmed: true,
      new_pilot_permitted: true,
    });
  } catch (error) {
    await persistRecoveredReleaseRuntimeCleanupIncompleteV1(recovery, {
      discoveredContainerCount,
      failureStage: stage,
      removedContainerCount,
    }).catch(() => {});
    throw error;
  }
}

export async function preflightReleaseRuntimeOciImageV1(options) {
  const input = expectExactRecord(options, [
    "ociExecutablePath", "plan", "runtimeImageReference",
  ], "release_runtime_oci_image_preflight_input");
  const plan = verifyPilotPlanV1(input.plan);
  const ociExecutablePath = await resolveCanonicalPath(
    input.ociExecutablePath,
    "oci_executable_path",
  );
  const runtimeImageReference = expectText(
    input.runtimeImageReference,
    "runtime_image_reference",
    { maximumBytes: 2_048 },
  );
  const ociRuntimeAuthority = await buildOciRuntimeAuthorityV1({
    executablePath: ociExecutablePath,
  });
  await verifyOciRuntimeAuthorityLiveV1(ociRuntimeAuthority);
  const initialImage = await inspectImage(
    ociExecutablePath,
    runtimeImageReference,
    plan.runtime_binding.oci_image_digest,
  );
  const imageProbe = await probeImageClosure(
    ociExecutablePath,
    initialImage.digest,
    plan.runtime_binding,
  );
  const finalImage = await inspectImage(
    ociExecutablePath,
    initialImage.digest,
    plan.runtime_binding.oci_image_digest,
  );
  if (canonicalJson(initialImage) !== canonicalJson(finalImage)) {
    fail("image_changed_during_probe");
  }
  return Object.freeze({
    ociExecutablePath,
    ociRuntimeAuthority: deepFreeze(canonicalClone(ociRuntimeAuthority)),
    image: initialImage,
    imageProbe,
  });
}

export async function prepareReleaseRuntimeOciResourcesV1(options) {
  const input = expectExactRecord(options, [
    "cancellationAuthority",
    "cases",
    "cellPolicyCommands",
    "ociExecutablePath",
    "orchestrationOwnerId",
    "plan",
    "privateRunRoot",
    "runtimeImageReference",
    "sdkClientAuthority",
    "trustRootPublicKeyPath",
  ], "release_runtime_oci_resource_input");
  const plan = verifyPilotPlanV1(input.plan);
  const cancellationAuthority = assertReleasePilotCancellationAuthorityV1(
    input.cancellationAuthority,
  );
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  verifyCases(plan, input.cases);
  const sdkClientAuthority = resolveReleaseSdkClientAuthorityV1(
    input.sdkClientAuthority,
    { plan },
  );
  const privateRunRoot = await verifyPrivateRunRoot(input.privateRunRoot);
  const imagePreflight = await preflightReleaseRuntimeOciImageV1({
    plan,
    ociExecutablePath: input.ociExecutablePath,
    runtimeImageReference: input.runtimeImageReference,
  });
  const {
    image: initialImage,
    imageProbe,
    ociExecutablePath,
    ociRuntimeAuthority,
  } = imagePreflight;
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  const ownerManifestHandle = await beginReleaseRuntimeOwnerManifestV1({
    ociEngineExecutionContextSha256: canonicalSha256(OCI_ENGINE_EXECUTION_CONTEXT_V1),
    ociRuntimeAuthoritySha256: ociRuntimeAuthority.authority_sha256,
    orchestrationOwnerId: input.orchestrationOwnerId,
    plan,
    privateRunRoot,
    runtimeImageDigest: initialImage.digest,
  });
  const resolvedOwnerManifest = resolveReleaseRuntimeOwnerManifestV1(
    ownerManifestHandle,
  );
  const resourceRoot = resolvedOwnerManifest.resourceRoot;
  const rootIdentity = resolvedOwnerManifest.resourceRootIdentity;

  const ownedChildren = [];
  const cellRecords = [];
  const pendingContainers = new Set();
  const ownedContainerReferences = new Set();
  const confirmedAbsentReferences = new Set();
  let closeAllCompleted = false;
  let closeAllPromise = null;
  const closeAll = () => {
    if (closeAllCompleted) return Promise.resolve();
    if (closeAllPromise === null) {
      const attempt = (async () => {
        const errors = [];
        for (const record of [...cellRecords].reverse()) {
          try { await record.close(); } catch (error) { errors.push(error); }
        }
        for (const pending of [...pendingContainers]) {
          if (pending.state !== "owned" || pending.containerId === null) {
            errors.push(new Error(
              "aionis_eval_release_runtime_oci_resource_container_ownership_ambiguous",
            ));
            continue;
          }
          try {
            await removeExactlyOwnedContainer(
              ociRuntimeAuthority,
              pending.expected,
              pending.containerId,
            );
            pendingContainers.delete(pending);
            confirmedAbsentReferences.add(pending.expected.name);
          } catch (error) {
            errors.push(error);
          }
        }
        if (errors.length > 0) {
          try {
            await persistReleaseRuntimeCleanupIncompleteV1(ownerManifestHandle, {
              discoveredContainerCount: ownedContainerReferences.size,
              failureStage: "container_removal",
              removedContainerCount: confirmedAbsentReferences.size,
            });
          } catch (receiptError) {
            errors.push(receiptError);
          }
          throw new AggregateError(
            errors,
            "aionis_eval_release_runtime_oci_resource_cleanup_failed",
          );
        }
        try {
          await removeOwnedRoot(resourceRoot, rootIdentity, ownedChildren);
          await confirmReleaseRuntimeOwnerCleanupV1(ownerManifestHandle);
        } catch (error) {
          const rootErrors = [error];
          try {
            await persistReleaseRuntimeCleanupIncompleteV1(ownerManifestHandle, {
              discoveredContainerCount: ownedContainerReferences.size,
              failureStage: "resource_root_removal",
              removedContainerCount: confirmedAbsentReferences.size,
            });
          } catch (receiptError) {
            rootErrors.push(receiptError);
          }
          throw new AggregateError(
            rootErrors,
            "aionis_eval_release_runtime_oci_resource_root_cleanup_failed",
          );
        }
        closeAllCompleted = true;
      })();
      closeAllPromise = attempt;
      void attempt.then(
        () => { closeAllPromise = null; },
        () => { closeAllPromise = null; },
      );
    }
    return closeAllPromise;
  };

  try {
    // The manifest/root already exist, so every cancellation checkpoint from
    // this point is covered by closeAll() in the catch below.
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    const sharedDirectory = path.join(resourceRoot, "shared");
    await mkdir(sharedDirectory, { mode: 0o700 });
    await chmod(sharedDirectory, 0o700);
    ownedChildren.push(sharedDirectory);
    const trustRootPath = path.join(sharedDirectory, "trust-root-public.pem");
    const publicKey = await readPinnedTrustRoot(
      input.trustRootPublicKeyPath,
      plan.runtime_binding.trust_root_sha256,
      trustRootPath,
    );
    const policies = verifyPolicyCommands(plan, input.cellPolicyCommands, publicKey);
    const user = numericUser();
    const runNonce = resolvedOwnerManifest.manifest.owner_id;
    const brokers = [];
    const authorities = [];

    const createOwnedContainer = async ({
      argv,
      common,
      name,
      operation,
      resourceKind,
    }) => {
      const expected = containerDeletionExpectation(
        common,
        name,
        resourceKind,
      );
      await assertContainerNameAbsent(ociRuntimeAuthority, name);
      const pending = {
        containerId: null,
        expected,
        state: "create_in_flight",
      };
      pendingContainers.add(pending);
      let created;
      try {
        created = await runOci(ociExecutablePath, argv, { operation });
      } catch (error) {
        try {
          const presence = await inspectOciContainerPresenceV1({
            containerReference: name,
            runtimeAuthority: ociRuntimeAuthority,
          });
          if (presence.presence === "absent") pendingContainers.delete(pending);
          else pending.state = "ambiguous";
        } catch {
          pending.state = "ambiguous";
        }
        throw error;
      }
      const containerId = created.stdout.toString("utf8").trim();
      if (!/^[0-9a-f]{64}$/u.test(containerId)) {
        pending.state = "ambiguous";
        fail("created_container_id_invalid");
      }
      pending.containerId = containerId;
      pending.state = "created_unverified";
      await verifyCreatedContainerOwnership(
        ociRuntimeAuthority,
        expected,
        containerId,
      );
      pending.state = "owned";
      ownedContainerReferences.add(name);
      return Object.freeze({ containerId, pending });
    };

    const closeOwnedContainer = async (pending) => {
      if (pending.state === "closed") return;
      if (pending.state !== "owned" || pending.containerId === null) {
        fail("container_ownership_ambiguous");
      }
      await removeExactlyOwnedContainer(
        ociRuntimeAuthority,
        pending.expected,
        pending.containerId,
      );
      pendingContainers.delete(pending);
      pending.state = "closed";
      confirmedAbsentReferences.add(pending.expected.name);
    };

    for (const [index, cell] of plan.schedule.entries()) {
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const cellRoot = path.join(resourceRoot, `cell-${String(cell.ordinal).padStart(2, "0")}`);
      const dataDirectory = path.join(cellRoot, "data");
      const authorityDirectory = path.join(cellRoot, "authority");
      await mkdir(cellRoot, { mode: 0o700 });
      await chmod(cellRoot, 0o700);
      ownedChildren.push(cellRoot);
      await mkdir(dataDirectory, { mode: 0o700 });
      await mkdir(authorityDirectory, { mode: 0o700 });
      await chmod(dataDirectory, 0o700);
      await chmod(authorityDirectory, 0o700);
      const dataPath = path.join(dataDirectory, "runtime.sqlite");
      const hostToken = randomBytes(48).toString("base64url");
      const operatorToken = randomBytes(48).toString("base64url");
      if (hostToken === operatorToken) fail("token_role_separation_failed");
      await copyFile(trustRootPath, path.join(authorityDirectory, "trust-root-public.pem"));
      await chmod(path.join(authorityDirectory, "trust-root-public.pem"), 0o400);
      await writeFile(path.join(authorityDirectory, "host-api-key"), hostToken, {
        flag: "wx", mode: 0o400,
      });
      await writeFile(path.join(authorityDirectory, "operator-api-key"), operatorToken, {
        flag: "wx", mode: 0o400,
      });
      const identity = cell.isolation.isolation_sha256.slice(0, 20);
      const hostPrincipalId = `host-eval-${identity}`;
      const operatorPrincipalId = `operator-eval-${identity}`;
      const provisionName = safeComponent(`aionis-prov-${runNonce}-${cell.ordinal}`);
      const daemonName = safeComponent(`aionis-run-${runNonce}-${cell.ordinal}`);
      const common = {
        cell,
        authorityDirectory,
        dataDirectory,
        hostPrincipalId,
        imageDigest: initialImage.digest,
        operatorPrincipalId,
        ownerId: runNonce,
        plan,
        user,
      };
      let provision;
      try {
        provision = await createOwnedContainer({
          argv: provisioningCreateArgv({ ...common, name: provisionName }),
          common,
          name: provisionName,
          operation: "policy_provisioning_create",
          resourceKind: "provisioning",
        });
        await runOci(
          ociExecutablePath,
          ["container", "start", "--attach", "--interactive", provision.containerId],
          {
            operation: "policy_provisioning",
            input: Buffer.from(`${canonicalJson(policies[index].command)}\n`, "utf8"),
          },
        ).then((result) => policyRefsFromProvisioningEvent(
          oneCanonicalJsonLine(result.stdout, "policy_provisioning"),
          policies[index].binding,
        ));
        checkpointReleasePilotCancellationV1(cancellationAuthority);
        await closeOwnedContainer(provision.pending);
      } catch (error) {
        if (provision !== undefined) {
          try {
            await closeOwnedContainer(provision.pending);
          } catch {
            /* closeAll retries only this ID-bound, exactly verified authority. */
          }
        }
        throw error;
      }
      await verifyDatabasePosture(dataPath);
      checkpointReleasePilotCancellationV1(cancellationAuthority);

      let daemon;
      try {
        daemon = await createOwnedContainer({
          argv: daemonCreateArgv({ ...common, name: daemonName }),
          common,
          name: daemonName,
          operation: "daemon_create",
          resourceKind: "daemon",
        });
        checkpointReleasePilotCancellationV1(cancellationAuthority);
      } catch (error) {
        throw error;
      }
      const containerId = daemon.containerId;
      let cellClosed = false;
      let cellClosePromise = null;
      const record = {
        ordinal: cell.ordinal,
        close() {
          if (cellClosed) return Promise.resolve();
          if (cellClosePromise === null) {
            const attempt = (async () => {
              await closeOwnedContainer(daemon.pending);
              await rm(cellRoot, { recursive: true, force: true });
              cellClosed = true;
            })();
            cellClosePromise = attempt;
            void attempt.then(
              () => { cellClosePromise = null; },
              () => { cellClosePromise = null; },
            );
          }
          return cellClosePromise;
        },
      };
      cellRecords.push(record);
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const prestartInspect = await inspectContainer(ociExecutablePath, containerId);
      const inspected = assertContainerConfiguration(
        prestartInspect,
        common,
        [hostToken, operatorToken],
      );
      await runOci(ociExecutablePath, ["container", "start", containerId], {
        operation: "daemon_start",
      });
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const runningInspect = await inspectContainer(ociExecutablePath, containerId);
      const port = publishedPort(runningInspect);
      assertContainerConfiguration(runningInspect, common, [hostToken, operatorToken]);
      const baseUrl = `http://127.0.0.1:${port}`;
      await waitReady(baseUrl, cancellationAuthority);
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      await verifyDatabasePosture(dataPath);
      let client;
      try {
        client = sdkClientFacade(
          await sdkClientAuthority.createClient({ baseUrl, apiKey: hostToken }),
        );
      } catch (error) {
        if (error instanceof Error
          && error.message.startsWith("aionis_eval_release_runtime_oci_resource_")) throw error;
        fail("sdk_client_authority_failed");
      }
      const binding = policies[index].binding;
      const authorityBody = canonicalClone({
        schema_version: "aionis_release_runtime_container_authority_v1",
        ordinal: cell.ordinal,
        opaque_cell_id: cell.opaque_cell_id,
        isolation_sha256: cell.isolation.isolation_sha256,
        runtime_scope: cell.isolation.runtime_scope,
        runtime_database_id: cell.isolation.runtime_database_id,
        runtime_database_path: dataPath,
        authority_subject_sha256: binding.authority_subject_sha256,
        provisioning_command_sha256: binding.provisioning_command_sha256,
        compiler_policy_ref: binding.compiler_policy_ref,
        evidence_policy_ref: binding.evidence_policy_ref,
        oci_runtime_authority_sha256: ociRuntimeAuthority.authority_sha256,
        runtime_image_digest: initialImage.digest,
        runtime_image_closure_sha256: imageProbe.closure_sha256,
        orchestration_owner_id: resolvedOwnerManifest.manifest.owner_id,
        owner_manifest_sha256: resolvedOwnerManifest.manifest.manifest_sha256,
        container_id: inspected.container_id,
        container_name: daemonName,
        container_configuration_sha256: inspected.configuration_sha256,
        loopback_host_port: port,
        token_transport: "read_only_file_mount_v1",
      });
      const containerAuthority = deepFreeze(canonicalClone({
        ...authorityBody,
        authority_sha256: canonicalSha256(authorityBody),
      }));
      authorities.push(containerAuthority);
      brokers.push(Object.freeze({
        client,
        dataPath,
        containerAuthority,
        close: record.close,
      }));
    }

    const authoritySetBody = canonicalClone({
      schema_version: "aionis_release_runtime_container_authority_set_v1",
      plan_sha256: plan.plan_sha256,
      oci_runtime_authority_sha256: ociRuntimeAuthority.authority_sha256,
      runtime_image_digest: initialImage.digest,
      runtime_image_closure_sha256: imageProbe.closure_sha256,
      orchestration_owner_id: resolvedOwnerManifest.manifest.owner_id,
      owner_manifest_sha256: resolvedOwnerManifest.manifest.manifest_sha256,
      container_authorities: authorities,
    });
    const owner = Object.freeze({
      schema_version: "aionis_release_runtime_oci_resources_v1",
      plan_sha256: plan.plan_sha256,
      owner_id: resolvedOwnerManifest.manifest.owner_id,
      owner_manifest_sha256: resolvedOwnerManifest.manifest.manifest_sha256,
      resource_root: resourceRoot,
      ociRuntimeAuthority: deepFreeze(canonicalClone(ociRuntimeAuthority)),
      imageAuthority: deepFreeze({
        schema_version: "aionis_release_runtime_image_authority_v1",
        image_digest: initialImage.digest,
        image_os: initialImage.os,
        image_architecture: initialImage.architecture,
        image_configured_user: initialImage.configured_user,
        image_runtime_uid: imageProbe.runtime_uid,
        image_runtime_gid: imageProbe.runtime_gid,
        closure_manifest_sha256: imageProbe.manifest_sha256,
        closure_sha256: imageProbe.closure_sha256,
      }),
      containerAuthoritySetSha256: canonicalSha256(authoritySetBody),
      ownerId: resolvedOwnerManifest.manifest.owner_id,
      ownerManifestSha256: resolvedOwnerManifest.manifest.manifest_sha256,
      brokers: Object.freeze(brokers),
      authorities: deepFreeze(authorities),
      closeAll,
    });
    return runtimeOwnerHandle(plan, owner);
  } catch (error) {
    try { await closeAll(); } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "aionis_eval_release_runtime_oci_resource_prepare_and_cleanup_failed",
      );
    }
    throw error;
  }
}
