import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  rmdir,
  unlink,
} from "node:fs/promises";
import path from "node:path";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
  expectNonNegativeInteger,
  expectSha256,
  expectText,
} from "./canonical.mjs";
import { verifyPilotPlanV1 } from "./pilot-contract.mjs";

export const RELEASE_RUNTIME_OWNER_LABEL_V1 =
  "aionis-release-runtime-oci-resource-v1";
export const RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1 =
  ".aionis-release-runtime-owner-v1.json";
export const RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1 =
  ".aionis-release-runtime-owner-incomplete-v1.json";
export const RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1 =
  ".aionis-release-runtime-owner-root-v1.json";
export const RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1 = Object.freeze({
  cell_id: "io.aionis.eval.cell-id",
  owner: "io.aionis.eval.owner",
  owner_id: "io.aionis.eval.owner-id",
  plan_sha256: "io.aionis.eval.plan-sha256",
  resource_kind: "io.aionis.eval.resource-kind",
});

const OWNER_STATES = new WeakMap();
const RECOVERY_STATES = new WeakMap();
const OWNER_ID_PATTERN = /^[0-9a-f]{32}$/u;
const RESOURCE_ROOT_PREFIX = ".aionis-release-runtime-owner-";

function fail(code) {
  throw new Error(`aionis_eval_release_runtime_owner_manifest_${code}`);
}

function publicHandle(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function currentOwnerId() {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
}

function verifyOwnedPrivateDirectory(stats, code) {
  const uid = currentOwnerId();
  if (!stats.isDirectory() || stats.isSymbolicLink()
    || (uid !== null && stats.uid !== uid)
    || stats.nlink < 1n
    || Number(stats.mode & 0o777n) !== 0o700) fail(code);
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

async function privateRunRoot(value) {
  const candidate = expectText(value, "release_runtime_owner_private_run_root", {
    maximumBytes: 16_384,
  });
  if (!path.isAbsolute(candidate) || path.normalize(candidate) !== candidate) {
    fail("private_run_root_invalid");
  }
  let resolved;
  let stats;
  try {
    resolved = await realpath(candidate);
    stats = await lstat(candidate, { bigint: true });
  } catch {
    fail("private_run_root_missing");
  }
  if (resolved !== candidate) fail("private_run_root_alias_forbidden");
  verifyOwnedPrivateDirectory(stats, "private_run_root_posture_invalid");
  return Object.freeze({ path: candidate, stats });
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, constants.O_RDONLY);
    await handle.sync();
  } catch {
    fail("directory_sync_failed");
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function writeExclusiveCanonical(file, value, parent) {
  let handle;
  try {
    handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    await handle.writeFile(`${canonicalJson(value)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await chmod(file, 0o600);
    await syncDirectory(parent);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error?.code === "EEXIST") fail("active_owner_exists");
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_release_runtime_owner_manifest_")) throw error;
    fail("manifest_write_failed");
  }
}

async function readCanonicalPrivateFile(file, field) {
  let pathStat;
  let handle;
  try {
    pathStat = await lstat(file, { bigint: true });
    const uid = currentOwnerId();
    if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.nlink !== 1n
      || (uid !== null && pathStat.uid !== uid)
      || Number(pathStat.mode & 0o777n) !== 0o600) fail(`${field}_posture_invalid`);
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!sameSnapshot(pathStat, before)) fail(`${field}_identity_changed`);
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(file, { bigint: true });
    if (!sameSnapshot(before, after) || !sameSnapshot(after, afterPath)) {
      fail(`${field}_changed_during_read`);
    }
    const text = bytes.toString("utf8");
    let value;
    try { value = JSON.parse(text); } catch { fail(`${field}_invalid`); }
    if (text !== `${canonicalJson(value)}\n`) fail(`${field}_not_canonical`);
    return value;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_release_runtime_owner_manifest_")) throw error;
    fail(`${field}_read_failed`);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function ownerManifestBody({
  ociEngineExecutionContextSha256,
  ociRuntimeAuthoritySha256,
  ownerId,
  plan,
  runtimeImageDigest,
}) {
  const resourceRootName = `${RESOURCE_ROOT_PREFIX}${ownerId}`;
  return canonicalClone({
    schema_version: "aionis_release_runtime_owner_manifest_v1",
    owner_id: ownerId,
    owner_label: RELEASE_RUNTIME_OWNER_LABEL_V1,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    oci_runtime_authority_sha256: ociRuntimeAuthoritySha256,
    oci_engine_execution_context_sha256: ociEngineExecutionContextSha256,
    runtime_image_digest: runtimeImageDigest,
    resource_root_name: resourceRootName,
    scheduled_cells: plan.schedule.map((cell) => ({
      ordinal: cell.ordinal,
      opaque_cell_id: cell.opaque_cell_id,
      cell_sha256: canonicalSha256(cell),
    })),
    container_label_contract: {
      keys: RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1,
      owner: RELEASE_RUNTIME_OWNER_LABEL_V1,
      owner_id: ownerId,
      plan_sha256: plan.plan_sha256,
      resource_kinds: ["daemon", "provisioning"],
    },
    recovery_policy: "same_hermetic_oci_authority_exact_owner_plan_cell_labels_v1",
    state: "active_cleanup_required_before_next_pilot",
  });
}

function rootIdentityReceipt(manifest, stats) {
  const body = canonicalClone({
    schema_version: "aionis_release_runtime_owner_root_identity_v1",
    owner_id: manifest.owner_id,
    owner_manifest_sha256: manifest.manifest_sha256,
    resource_root_name: manifest.resource_root_name,
    device_id: String(stats.dev),
    inode: String(stats.ino),
    state: "root_identity_sealed_before_runtime_resource_creation",
  });
  return canonicalClone({ ...body, receipt_sha256: canonicalSha256(body) });
}

function verifyRootIdentityReceipt(value, manifest) {
  const receipt = expectExactRecord(value, [
    "device_id",
    "inode",
    "owner_id",
    "owner_manifest_sha256",
    "receipt_sha256",
    "resource_root_name",
    "schema_version",
    "state",
  ], "release_runtime_owner_root_identity");
  if (receipt.schema_version !== "aionis_release_runtime_owner_root_identity_v1"
    || receipt.owner_id !== manifest.owner_id
    || receipt.owner_manifest_sha256 !== manifest.manifest_sha256
    || receipt.resource_root_name !== manifest.resource_root_name
    || !/^\d+$/u.test(receipt.device_id)
    || !/^\d+$/u.test(receipt.inode)
    || receipt.state !== "root_identity_sealed_before_runtime_resource_creation") {
    fail("root_identity_contract_invalid");
  }
  expectSha256(receipt.receipt_sha256, "release_runtime_owner_root_receipt_sha256");
  const body = Object.fromEntries(
    Object.entries(receipt).filter(([key]) => key !== "receipt_sha256"),
  );
  if (canonicalSha256(body) !== receipt.receipt_sha256) {
    fail("root_identity_integrity_invalid");
  }
  return canonicalClone(receipt);
}

function verifyOwnerManifest(value) {
  const manifest = expectExactRecord(value, [
    "container_label_contract",
    "manifest_sha256",
    "oci_engine_execution_context_sha256",
    "oci_runtime_authority_sha256",
    "owner_id",
    "owner_label",
    "pilot_id",
    "plan_sha256",
    "recovery_policy",
    "resource_root_name",
    "runtime_image_digest",
    "scheduled_cells",
    "schema_version",
    "state",
  ], "release_runtime_owner_manifest");
  if (manifest.schema_version !== "aionis_release_runtime_owner_manifest_v1"
    || !OWNER_ID_PATTERN.test(manifest.owner_id)
    || manifest.owner_label !== RELEASE_RUNTIME_OWNER_LABEL_V1
    || manifest.resource_root_name !== `${RESOURCE_ROOT_PREFIX}${manifest.owner_id}`
    || manifest.recovery_policy
      !== "same_hermetic_oci_authority_exact_owner_plan_cell_labels_v1"
    || manifest.state !== "active_cleanup_required_before_next_pilot") {
    fail("manifest_contract_invalid");
  }
  expectText(manifest.pilot_id, "release_runtime_owner_pilot_id");
  expectSha256(manifest.plan_sha256, "release_runtime_owner_plan_sha256");
  expectSha256(
    manifest.oci_runtime_authority_sha256,
    "release_runtime_owner_oci_authority_sha256",
  );
  expectSha256(
    manifest.oci_engine_execution_context_sha256,
    "release_runtime_owner_oci_context_sha256",
  );
  if (!/^sha256:[0-9a-f]{64}$/u.test(manifest.runtime_image_digest)) {
    fail("runtime_image_digest_invalid");
  }
  if (!Array.isArray(manifest.scheduled_cells) || manifest.scheduled_cells.length !== 9) {
    fail("scheduled_cells_invalid");
  }
  const ordinals = new Set();
  const cellIds = new Set();
  for (const cell of manifest.scheduled_cells) {
    const entry = expectExactRecord(cell, [
      "cell_sha256", "opaque_cell_id", "ordinal",
    ], "release_runtime_owner_scheduled_cell");
    if (!Number.isSafeInteger(entry.ordinal) || entry.ordinal < 1 || entry.ordinal > 9
      || ordinals.has(entry.ordinal) || cellIds.has(entry.opaque_cell_id)) {
      fail("scheduled_cells_invalid");
    }
    expectText(entry.opaque_cell_id, "release_runtime_owner_cell_id");
    expectSha256(entry.cell_sha256, "release_runtime_owner_cell_sha256");
    ordinals.add(entry.ordinal);
    cellIds.add(entry.opaque_cell_id);
  }
  const labels = expectExactRecord(manifest.container_label_contract, [
    "keys", "owner", "owner_id", "plan_sha256", "resource_kinds",
  ], "release_runtime_owner_label_contract");
  if (canonicalJson(labels.keys) !== canonicalJson(RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1)
    || labels.owner !== RELEASE_RUNTIME_OWNER_LABEL_V1
    || labels.owner_id !== manifest.owner_id
    || labels.plan_sha256 !== manifest.plan_sha256
    || canonicalJson(labels.resource_kinds) !== canonicalJson(["daemon", "provisioning"])) {
    fail("label_contract_invalid");
  }
  expectSha256(manifest.manifest_sha256, "release_runtime_owner_manifest_sha256");
  const body = Object.fromEntries(
    Object.entries(manifest).filter(([key]) => key !== "manifest_sha256"),
  );
  if (canonicalSha256(body) !== manifest.manifest_sha256) fail("manifest_integrity_invalid");
  return canonicalClone(manifest);
}

function ownerState(handle) {
  const state = handle !== null && typeof handle === "object"
    ? OWNER_STATES.get(handle)
    : undefined;
  if (state === undefined) fail("owner_handle_invalid");
  return state;
}

export async function beginReleaseRuntimeOwnerManifestV1(options) {
  const input = expectExactRecord(options, [
    "ociEngineExecutionContextSha256",
    "ociRuntimeAuthoritySha256",
    "orchestrationOwnerId",
    "plan",
    "privateRunRoot",
    "runtimeImageDigest",
  ], "release_runtime_owner_manifest_begin_input");
  const plan = verifyPilotPlanV1(input.plan);
  const root = await privateRunRoot(input.privateRunRoot);
  if (typeof input.orchestrationOwnerId !== "string"
    || !OWNER_ID_PATTERN.test(input.orchestrationOwnerId)) {
    fail("orchestration_owner_id_invalid");
  }
  const ociRuntimeAuthoritySha256 = expectSha256(
    input.ociRuntimeAuthoritySha256,
    "release_runtime_owner_oci_authority_sha256",
  );
  const ociEngineExecutionContextSha256 = expectSha256(
    input.ociEngineExecutionContextSha256,
    "release_runtime_owner_oci_context_sha256",
  );
  if (!/^sha256:[0-9a-f]{64}$/u.test(input.runtimeImageDigest)) {
    fail("runtime_image_digest_invalid");
  }
  const ownerId = input.orchestrationOwnerId;
  const body = ownerManifestBody({
    ociEngineExecutionContextSha256,
    ociRuntimeAuthoritySha256,
    ownerId,
    plan,
    runtimeImageDigest: input.runtimeImageDigest,
  });
  const manifest = verifyOwnerManifest({
    ...body,
    manifest_sha256: canonicalSha256(body),
  });
  const manifestPath = path.join(root.path, RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1);
  await writeExclusiveCanonical(manifestPath, manifest, root.path);
  const resourceRoot = path.join(root.path, manifest.resource_root_name);
  try {
    await mkdir(resourceRoot, { mode: 0o700 });
    await chmod(resourceRoot, 0o700);
    await syncDirectory(root.path);
  } catch {
    // The durable manifest deliberately remains as a recovery barrier.
    fail("resource_root_create_failed");
  }
  const rootIdentity = await lstat(resourceRoot, { bigint: true });
  verifyOwnedPrivateDirectory(rootIdentity, "resource_root_posture_invalid");
  const rootIdentityValue = rootIdentityReceipt(manifest, rootIdentity);
  const rootIdentityPath = path.join(
    root.path,
    RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1,
  );
  await writeExclusiveCanonical(rootIdentityPath, rootIdentityValue, root.path);
  const handle = publicHandle({
    schema_version: "aionis_release_runtime_owner_manifest_handle_v1",
    owner_id: ownerId,
    plan_sha256: plan.plan_sha256,
    manifest_sha256: manifest.manifest_sha256,
  });
  OWNER_STATES.set(handle, {
    manifest,
    manifestPath,
    privateRunRoot: root.path,
    privateRunRootIdentity: root.stats,
    resourceRoot,
    resourceRootIdentity: rootIdentity,
    rootIdentityPath,
    rootIdentityReceipt: rootIdentityValue,
  });
  return handle;
}

export function resolveReleaseRuntimeOwnerManifestV1(handle) {
  const state = ownerState(handle);
  return Object.freeze({
    manifest: canonicalClone(state.manifest),
    resourceRoot: state.resourceRoot,
    resourceRootIdentity: state.resourceRootIdentity,
  });
}

export async function readActiveReleaseRuntimeOwnerManifestV1(options) {
  const input = expectExactRecord(options, [
    "privateRunRoot",
  ], "release_runtime_owner_manifest_read_input");
  const root = await privateRunRoot(input.privateRunRoot);
  const manifestPath = path.join(root.path, RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1);
  const raw = await readCanonicalPrivateFile(manifestPath, "manifest");
  if (raw === null) {
    for (const file of [
      RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1,
      RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
    ]) {
      try {
        await lstat(path.join(root.path, file), { bigint: true });
        fail("orphan_metadata_without_manifest");
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
    return null;
  }
  const manifest = verifyOwnerManifest(raw);
  const rootIdentityPath = path.join(
    root.path,
    RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1,
  );
  const rawRootIdentity = await readCanonicalPrivateFile(
    rootIdentityPath,
    "root_identity",
  );
  const rootIdentityValue = rawRootIdentity === null
    ? null
    : verifyRootIdentityReceipt(rawRootIdentity, manifest);
  const recovery = Object.freeze({
    manifest,
    manifestPath,
    privateRunRoot: root.path,
    resourceRoot: path.join(root.path, manifest.resource_root_name),
    rootIdentityReceipt: rootIdentityValue,
  });
  RECOVERY_STATES.set(recovery, {
    manifest,
    manifestPath,
    privateRunRoot: root.path,
    resourceRoot: recovery.resourceRoot,
    rootIdentityPath,
    rootIdentityReceipt: rootIdentityValue,
  });
  return recovery;
}

async function writeIncompleteReceipt(state, options) {
  const input = expectExactRecord(options, [
    "discoveredContainerCount", "failureStage", "removedContainerCount",
  ], "release_runtime_owner_cleanup_incomplete_input");
  const discoveredContainerCount = expectNonNegativeInteger(
    input.discoveredContainerCount,
    "release_runtime_owner_discovered_container_count",
  );
  const removedContainerCount = expectNonNegativeInteger(
    input.removedContainerCount,
    "release_runtime_owner_removed_container_count",
  );
  if (removedContainerCount > discoveredContainerCount
    || !new Set([
      "container_discovery", "container_inspection", "container_removal",
      "manifest_verification", "resource_root_removal",
    ]).has(input.failureStage)) fail("cleanup_incomplete_input_invalid");
  const body = canonicalClone({
    schema_version: "aionis_release_runtime_cleanup_incomplete_receipt_v1",
    owner_id: state.manifest.owner_id,
    plan_sha256: state.manifest.plan_sha256,
    owner_manifest_sha256: state.manifest.manifest_sha256,
    oci_runtime_authority_sha256: state.manifest.oci_runtime_authority_sha256,
    failure_stage: input.failureStage,
    discovered_container_count: discoveredContainerCount,
    removed_container_count: removedContainerCount,
    cleanup_confirmed: false,
    state: "cleanup_incomplete_new_pilot_forbidden",
  });
  const receipt = canonicalClone({
    ...body,
    receipt_sha256: canonicalSha256(body),
  });
  const file = path.join(
    state.privateRunRoot,
    RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
  );
  try {
    await writeExclusiveCanonical(file, receipt, state.privateRunRoot);
  } catch (error) {
    if (!(error instanceof Error) || !error.message.endsWith("_active_owner_exists")) {
      throw error;
    }
    const existing = await readCanonicalPrivateFile(file, "incomplete_receipt");
    if (canonicalJson(existing) !== canonicalJson(receipt)) {
      fail("incomplete_receipt_already_exists");
    }
  }
  return receipt;
}

export async function persistReleaseRuntimeCleanupIncompleteV1(handle, options) {
  return writeIncompleteReceipt(ownerState(handle), options);
}

export async function persistRecoveredReleaseRuntimeCleanupIncompleteV1(
  recovery,
  options,
) {
  const state = recovery !== null && typeof recovery === "object"
    ? RECOVERY_STATES.get(recovery)
    : undefined;
  if (state === undefined) fail("recovery_handle_invalid");
  return writeIncompleteReceipt(state, options);
}

function recoveryState(recovery) {
  const state = recovery !== null && typeof recovery === "object"
    ? RECOVERY_STATES.get(recovery)
    : undefined;
  if (state === undefined) fail("recovery_handle_invalid");
  return state;
}

async function recoveredRootPosture(state) {
  let stats;
  try { stats = await lstat(state.resourceRoot, { bigint: true }); } catch (error) {
    if (error?.code === "ENOENT") return Object.freeze({ state: "absent" });
    fail("resource_root_verify_failed");
  }
  verifyOwnedPrivateDirectory(stats, "resource_root_posture_invalid");
  if (state.rootIdentityReceipt === null) {
    const entries = await readdir(state.resourceRoot);
    if (entries.length !== 0) fail("unsealed_resource_root_not_empty");
    return Object.freeze({ state: "unsealed_empty" });
  }
  if (String(stats.dev) !== state.rootIdentityReceipt.device_id
    || String(stats.ino) !== state.rootIdentityReceipt.inode) {
    fail("resource_root_identity_changed");
  }
  return Object.freeze({ state: "identity_bound" });
}

export async function removeRecoveredReleaseRuntimeOwnerRootV1(recovery) {
  const state = recoveryState(recovery);
  const posture = await recoveredRootPosture(state);
  if (posture.state === "identity_bound") {
    await rm(state.resourceRoot, { recursive: true, force: false });
  } else if (posture.state === "unsealed_empty") {
    await rmdir(state.resourceRoot);
  }
  await syncDirectory(state.privateRunRoot);
  return Object.freeze({
    schema_version: "aionis_release_runtime_recovered_root_removal_v1",
    owner_manifest_sha256: state.manifest.manifest_sha256,
    root_state_before_removal: posture.state,
    root_absent: true,
  });
}

export async function confirmRecoveredReleaseRuntimeOwnerCleanupV1(recovery) {
  const state = recoveryState(recovery);
  const posture = await recoveredRootPosture(state);
  if (posture.state !== "absent") fail("resource_root_still_exists");
  const liveManifest = await readCanonicalPrivateFile(state.manifestPath, "manifest");
  if (canonicalJson(liveManifest) !== canonicalJson(state.manifest)) {
    fail("manifest_changed_before_cleanup_confirmation");
  }
  if (state.rootIdentityReceipt !== null) {
    const liveRootIdentity = await readCanonicalPrivateFile(
      state.rootIdentityPath,
      "root_identity",
    );
    if (canonicalJson(liveRootIdentity) !== canonicalJson(state.rootIdentityReceipt)) {
      fail("root_identity_changed_before_cleanup_confirmation");
    }
  }
  await rm(state.rootIdentityPath, { force: true });
  await rm(path.join(
    state.privateRunRoot,
    RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
  ), { force: true });
  await syncDirectory(state.privateRunRoot);
  await unlink(state.manifestPath).catch(() => fail("manifest_remove_failed"));
  await syncDirectory(state.privateRunRoot);
  RECOVERY_STATES.delete(recovery);
  return Object.freeze({
    schema_version: "aionis_release_runtime_recovered_cleanup_confirmation_v1",
    owner_manifest_sha256: state.manifest.manifest_sha256,
    cleanup_confirmed: true,
  });
}

export async function confirmReleaseRuntimeOwnerCleanupV1(handle) {
  const state = ownerState(handle);
  let resourceRootExists = true;
  try {
    await lstat(state.resourceRoot, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") resourceRootExists = false;
    else fail("resource_root_verify_failed");
  }
  if (resourceRootExists) fail("resource_root_still_exists");
  const liveManifest = await readCanonicalPrivateFile(state.manifestPath, "manifest");
  if (canonicalJson(liveManifest) !== canonicalJson(state.manifest)) {
    fail("manifest_changed_before_cleanup_confirmation");
  }
  await rm(state.rootIdentityPath, { force: true });
  await rm(path.join(
    state.privateRunRoot,
    RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
  ), { force: true });
  await syncDirectory(state.privateRunRoot);
  await unlink(state.manifestPath).catch(() => fail("manifest_remove_failed"));
  await syncDirectory(state.privateRunRoot);
  OWNER_STATES.delete(handle);
  return Object.freeze({
    schema_version: "aionis_release_runtime_owner_cleanup_confirmation_v1",
    owner_manifest_sha256: state.manifest.manifest_sha256,
    cleanup_confirmed: true,
  });
}
