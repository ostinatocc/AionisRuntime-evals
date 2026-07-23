import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rm,
  unlink,
} from "node:fs/promises";
import path from "node:path";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { verifyPilotPlanV1 } from "./pilot-contract.mjs";

export const RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1 =
  ".aionis-release-workspace-owner-v1.json";
export const RELEASE_WORKSPACE_OWNER_ACTIVATION_FILE_V1 =
  ".aionis-release-workspace-owner-activation-v1.json";
export const RELEASE_WORKSPACE_OWNER_INCOMPLETE_FILE_V1 =
  ".aionis-release-workspace-owner-incomplete-v1.json";

const RESOURCE_ROOT_PREFIX = ".aionis-release-workspace-owner-";
const OWNER_ID_PATTERN = /^[0-9a-f]{32}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const MAX_MANIFEST_BYTES = 1_048_576;
const MAX_GIT_EXECUTABLE_BYTES = 128 * 1024 * 1024;
const OWNER_STATES = new WeakMap();

function fail(code) {
  throw new Error(`aionis_eval_release_workspace_owner_manifest_${code}`);
}

function publicHandle(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function currentOwnerId() {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSnapshot(left, right) {
  return sameIdentity(left, right)
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function verifyPrivateDirectory(stats, code) {
  const uid = currentOwnerId();
  if (!stats.isDirectory() || stats.isSymbolicLink()
    || (uid !== null && stats.uid !== uid)
    || Number(stats.mode & 0o777n) !== 0o700) fail(code);
}

async function resolvePrivateRunRoot(value) {
  const candidate = expectText(value, "workspace_owner_private_run_root", {
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
  verifyPrivateDirectory(stats, "private_run_root_posture_invalid");
  return Object.freeze({ path: candidate, stats });
}

function secureReadFlags(directory = false) {
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    fail("no_follow_unsupported");
  }
  return constants.O_RDONLY | constants.O_NOFOLLOW
    | (directory && Number.isInteger(constants.O_DIRECTORY) ? constants.O_DIRECTORY : 0);
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, secureReadFlags(true));
    await handle.sync();
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_release_workspace_owner_manifest_")) throw error;
    fail("directory_sync_failed");
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function writeExclusiveCanonical(file, value, parent) {
  let handle;
  try {
    handle = await open(
      file,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await handle.writeFile(`${canonicalJson(value)}\n`, "utf8");
    await handle.sync();
    await handle.chmod(0o600);
    await handle.close();
    handle = null;
    await syncDirectory(parent);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error?.code === "EEXIST") fail("active_owner_exists");
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_release_workspace_owner_manifest_")) throw error;
    fail("manifest_write_failed");
  }
}

async function readCanonicalPrivateFile(file, field) {
  let pathStats;
  let handle;
  try {
    pathStats = await lstat(file, { bigint: true });
    const uid = currentOwnerId();
    if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1n
      || (uid !== null && pathStats.uid !== uid)
      || Number(pathStats.mode & 0o777n) !== 0o600
      || pathStats.size < 2n || pathStats.size > BigInt(MAX_MANIFEST_BYTES)) {
      fail(`${field}_posture_invalid`);
    }
    handle = await open(file, secureReadFlags());
    const before = await handle.stat({ bigint: true });
    if (!sameSnapshot(pathStats, before)) fail(`${field}_identity_changed`);
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
      && error.message.startsWith("aionis_eval_release_workspace_owner_manifest_")) throw error;
    fail(`${field}_read_failed`);
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function gitExecutableAuthority(value) {
  const candidate = expectText(value, "workspace_owner_git_executable_path", {
    maximumBytes: 16_384,
  });
  if (!path.isAbsolute(candidate) || path.normalize(candidate) !== candidate) {
    fail("git_executable_path_invalid");
  }
  let resolved;
  let pathStats;
  let handle;
  try {
    resolved = await realpath(candidate);
    pathStats = await lstat(candidate, { bigint: true });
    if (resolved !== candidate || !pathStats.isFile() || pathStats.isSymbolicLink()
      || Number(pathStats.mode & 0o111n) === 0 || pathStats.size < 1n
      || pathStats.size > BigInt(MAX_GIT_EXECUTABLE_BYTES)) {
      fail("git_executable_posture_invalid");
    }
    handle = await open(candidate, secureReadFlags());
    const before = await handle.stat({ bigint: true });
    if (!sameSnapshot(pathStats, before)) fail("git_executable_identity_changed");
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(candidate, { bigint: true });
    if (!sameSnapshot(before, after) || !sameSnapshot(after, afterPath)) {
      fail("git_executable_changed_during_hash");
    }
    return canonicalClone({
      schema_version: "aionis_release_workspace_git_authority_v1",
      executable_path: candidate,
      executable_sha256: sha256Bytes(bytes),
      device_id: String(before.dev),
      inode: String(before.ino),
    });
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_release_workspace_owner_manifest_")) throw error;
    fail("git_executable_authority_failed");
  } finally {
    await handle?.close().catch(() => {});
  }
}

function verifyGitAuthority(value) {
  const authority = expectExactRecord(value, [
    "device_id", "executable_path", "executable_sha256", "inode", "schema_version",
  ], "workspace_owner_git_authority");
  if (authority.schema_version !== "aionis_release_workspace_git_authority_v1"
    || !path.isAbsolute(authority.executable_path)
    || path.normalize(authority.executable_path) !== authority.executable_path
    || !DECIMAL_PATTERN.test(authority.device_id) || !DECIMAL_PATTERN.test(authority.inode)) {
    fail("git_authority_invalid");
  }
  expectSha256(authority.executable_sha256, "workspace_owner_git_executable_sha256");
  return canonicalClone(authority);
}

function scheduledCells(plan) {
  return plan.schedule.map((cell) => canonicalClone({
    ordinal: cell.ordinal,
    opaque_cell_id: cell.opaque_cell_id,
    cell_sha256: canonicalSha256(cell),
  }));
}

function manifestBody({ gitAuthority, orchestrationOwnerId, plan, privateRunRoot }) {
  return canonicalClone({
    schema_version: "aionis_release_workspace_owner_manifest_v1",
    owner_id: orchestrationOwnerId,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    private_run_root_sha256: sha256Bytes(Buffer.from(privateRunRoot, "utf8")),
    resource_root_name: `${RESOURCE_ROOT_PREFIX}${orchestrationOwnerId}`,
    scheduled_cells: scheduledCells(plan),
    git_authority: gitAuthority,
    recovery_policy: "fixed_manifest_exact_identity_no_prefix_scan_v1",
    state: "prepared_root_not_yet_activated",
  });
}

function verifyManifest(value) {
  const manifest = expectExactRecord(value, [
    "git_authority", "manifest_sha256", "owner_id", "pilot_id", "plan_sha256",
    "private_run_root_sha256", "recovery_policy", "resource_root_name",
    "scheduled_cells", "schema_version", "state",
  ], "workspace_owner_manifest");
  if (manifest.schema_version !== "aionis_release_workspace_owner_manifest_v1"
    || !OWNER_ID_PATTERN.test(manifest.owner_id)
    || manifest.resource_root_name !== `${RESOURCE_ROOT_PREFIX}${manifest.owner_id}`
    || manifest.recovery_policy !== "fixed_manifest_exact_identity_no_prefix_scan_v1"
    || manifest.state !== "prepared_root_not_yet_activated") {
    fail("manifest_contract_invalid");
  }
  expectText(manifest.pilot_id, "workspace_owner_pilot_id");
  expectSha256(manifest.plan_sha256, "workspace_owner_plan_sha256");
  expectSha256(manifest.private_run_root_sha256, "workspace_owner_private_root_sha256");
  verifyGitAuthority(manifest.git_authority);
  if (!Array.isArray(manifest.scheduled_cells) || manifest.scheduled_cells.length !== 9) {
    fail("scheduled_cells_invalid");
  }
  const ordinals = new Set();
  const ids = new Set();
  for (const cell of manifest.scheduled_cells) {
    const entry = expectExactRecord(cell, [
      "cell_sha256", "opaque_cell_id", "ordinal",
    ], "workspace_owner_scheduled_cell");
    if (!Number.isSafeInteger(entry.ordinal) || entry.ordinal < 1 || entry.ordinal > 9
      || ordinals.has(entry.ordinal) || ids.has(entry.opaque_cell_id)) {
      fail("scheduled_cells_invalid");
    }
    expectText(entry.opaque_cell_id, "workspace_owner_cell_id");
    expectSha256(entry.cell_sha256, "workspace_owner_cell_sha256");
    ordinals.add(entry.ordinal);
    ids.add(entry.opaque_cell_id);
  }
  expectSha256(manifest.manifest_sha256, "workspace_owner_manifest_sha256");
  const body = Object.fromEntries(
    Object.entries(manifest).filter(([key]) => key !== "manifest_sha256"),
  );
  if (canonicalSha256(body) !== manifest.manifest_sha256) fail("manifest_integrity_invalid");
  return canonicalClone(manifest);
}

function rootIdentity(stats) {
  return canonicalClone({
    device_id: String(stats.dev),
    inode: String(stats.ino),
    uid: String(stats.uid),
    gid: String(stats.gid),
  });
}

function verifyRootIdentity(value) {
  const identity = expectExactRecord(value, [
    "device_id", "gid", "inode", "uid",
  ], "workspace_owner_root_identity");
  if (Object.values(identity).some((entry) => !DECIMAL_PATTERN.test(entry))) {
    fail("root_identity_invalid");
  }
  return canonicalClone(identity);
}

function activationBody(manifest, identity) {
  return canonicalClone({
    schema_version: "aionis_release_workspace_owner_activation_v1",
    owner_id: manifest.owner_id,
    plan_sha256: manifest.plan_sha256,
    owner_manifest_sha256: manifest.manifest_sha256,
    resource_root_name: manifest.resource_root_name,
    resource_root_identity: identity,
    state: "active_cleanup_required_before_next_pilot",
  });
}

function verifyActivation(value, manifest) {
  const activation = expectExactRecord(value, [
    "activation_sha256", "owner_id", "owner_manifest_sha256", "plan_sha256",
    "resource_root_identity", "resource_root_name", "schema_version", "state",
  ], "workspace_owner_activation");
  if (activation.schema_version !== "aionis_release_workspace_owner_activation_v1"
    || activation.owner_id !== manifest.owner_id
    || activation.plan_sha256 !== manifest.plan_sha256
    || activation.owner_manifest_sha256 !== manifest.manifest_sha256
    || activation.resource_root_name !== manifest.resource_root_name
    || activation.state !== "active_cleanup_required_before_next_pilot") {
    fail("activation_contract_invalid");
  }
  verifyRootIdentity(activation.resource_root_identity);
  expectSha256(activation.activation_sha256, "workspace_owner_activation_sha256");
  const body = Object.fromEntries(
    Object.entries(activation).filter(([key]) => key !== "activation_sha256"),
  );
  if (canonicalSha256(body) !== activation.activation_sha256) {
    fail("activation_integrity_invalid");
  }
  return canonicalClone(activation);
}

function incompleteReceipt(manifest, activation) {
  const body = canonicalClone({
    schema_version: "aionis_release_workspace_cleanup_incomplete_v1",
    owner_id: manifest.owner_id,
    plan_sha256: manifest.plan_sha256,
    owner_manifest_sha256: manifest.manifest_sha256,
    owner_activation_sha256: activation?.activation_sha256 ?? null,
    cleanup_confirmed: false,
    state: "cleanup_incomplete_new_pilot_forbidden",
  });
  return canonicalClone({ ...body, receipt_sha256: canonicalSha256(body) });
}

function pathsFor(root, manifest) {
  return Object.freeze({
    manifestPath: path.join(root.path, RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1),
    activationPath: path.join(root.path, RELEASE_WORKSPACE_OWNER_ACTIVATION_FILE_V1),
    incompletePath: path.join(root.path, RELEASE_WORKSPACE_OWNER_INCOMPLETE_FILE_V1),
    resourceRoot: path.join(root.path, manifest.resource_root_name),
  });
}

async function readOwnerFiles(root) {
  const manifestPath = path.join(root.path, RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1);
  const activationPath = path.join(root.path, RELEASE_WORKSPACE_OWNER_ACTIVATION_FILE_V1);
  const incompletePath = path.join(root.path, RELEASE_WORKSPACE_OWNER_INCOMPLETE_FILE_V1);
  const rawManifest = await readCanonicalPrivateFile(manifestPath, "manifest");
  if (rawManifest === null) {
    const [activation, incomplete] = await Promise.all([
      readCanonicalPrivateFile(activationPath, "activation"),
      readCanonicalPrivateFile(incompletePath, "incomplete_receipt"),
    ]);
    if (activation !== null || incomplete !== null) fail("receipt_without_active_manifest");
    return null;
  }
  const manifest = verifyManifest(rawManifest);
  const rawActivation = await readCanonicalPrivateFile(activationPath, "activation");
  const activation = rawActivation === null ? null : verifyActivation(rawActivation, manifest);
  return Object.freeze({
    manifest,
    activation,
    ...pathsFor(root, manifest),
  });
}

function ownerState(handle) {
  const state = handle !== null && typeof handle === "object"
    ? OWNER_STATES.get(handle)
    : undefined;
  if (state === undefined) fail("owner_handle_invalid");
  return state;
}

export async function beginReleaseWorkspaceOwnerManifestV1(options) {
  const input = expectExactRecord(options, [
    "gitExecutablePath", "orchestrationOwnerId", "plan", "privateRunRoot",
  ], "workspace_owner_begin_input");
  if (!OWNER_ID_PATTERN.test(input.orchestrationOwnerId)) fail("owner_id_invalid");
  const plan = verifyPilotPlanV1(input.plan);
  const root = await resolvePrivateRunRoot(input.privateRunRoot);
  if (await readOwnerFiles(root) !== null) fail("active_owner_exists");
  const gitAuthority = await gitExecutableAuthority(input.gitExecutablePath);
  const body = manifestBody({
    gitAuthority,
    orchestrationOwnerId: input.orchestrationOwnerId,
    plan,
    privateRunRoot: root.path,
  });
  const manifest = verifyManifest({ ...body, manifest_sha256: canonicalSha256(body) });
  const paths = pathsFor(root, manifest);
  await writeExclusiveCanonical(paths.manifestPath, manifest, root.path);
  const handle = publicHandle({
    schema_version: "aionis_release_workspace_owner_manifest_handle_v1",
    owner_id: manifest.owner_id,
    plan_sha256: manifest.plan_sha256,
    manifest_sha256: manifest.manifest_sha256,
  });
  OWNER_STATES.set(handle, {
    ...paths,
    activation: null,
    gitAuthority,
    manifest,
    privateRunRoot: root.path,
    privateRunRootIdentity: root.stats,
    resourceRootIdentity: null,
    cleanupComplete: false,
  });
  return handle;
}

export function resolveReleaseWorkspaceOwnerManifestV1(handle) {
  const state = ownerState(handle);
  return Object.freeze({
    manifest: canonicalClone(state.manifest),
    activation: state.activation === null ? null : canonicalClone(state.activation),
    resourceRoot: state.resourceRoot,
    resourceRootIdentity: state.resourceRootIdentity,
  });
}

export async function activateReleaseWorkspaceOwnerManifestV1(handle) {
  const state = ownerState(handle);
  if (state.activation !== null) return resolveReleaseWorkspaceOwnerManifestV1(handle);
  try {
    await mkdir(state.resourceRoot, { mode: 0o700 });
    await chmod(state.resourceRoot, 0o700);
    await syncDirectory(state.privateRunRoot);
  } catch {
    fail("resource_root_create_failed");
  }
  let canonicalRoot;
  let stats;
  try {
    canonicalRoot = await realpath(state.resourceRoot);
    stats = await lstat(state.resourceRoot, { bigint: true });
  } catch {
    fail("resource_root_activation_failed");
  }
  if (canonicalRoot !== state.resourceRoot) fail("resource_root_alias_forbidden");
  verifyPrivateDirectory(stats, "resource_root_posture_invalid");
  const identity = rootIdentity(stats);
  const body = activationBody(state.manifest, identity);
  const activation = verifyActivation({
    ...body,
    activation_sha256: canonicalSha256(body),
  }, state.manifest);
  await writeExclusiveCanonical(state.activationPath, activation, state.privateRunRoot);
  state.activation = activation;
  state.resourceRootIdentity = stats;
  return resolveReleaseWorkspaceOwnerManifestV1(handle);
}

async function persistIncomplete(owner) {
  const receipt = incompleteReceipt(owner.manifest, owner.activation);
  try {
    await writeExclusiveCanonical(owner.incompletePath, receipt, owner.privateRunRoot);
  } catch (error) {
    if (!(error instanceof Error) || !error.message.endsWith("_active_owner_exists")) {
      throw error;
    }
    const existing = await readCanonicalPrivateFile(
      owner.incompletePath,
      "incomplete_receipt",
    );
    if (canonicalJson(existing) !== canonicalJson(receipt)) {
      fail("incomplete_receipt_conflict");
    }
  }
  return receipt;
}

async function assertLiveRoot(owner) {
  let stats;
  let resolved;
  try {
    stats = await lstat(owner.resourceRoot, { bigint: true });
    resolved = await realpath(owner.resourceRoot);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    fail("resource_root_inspect_failed");
  }
  if (resolved !== owner.resourceRoot) fail("resource_root_alias_forbidden");
  verifyPrivateDirectory(stats, "resource_root_posture_invalid");
  if (owner.activation === null) {
    let entries;
    try { entries = await readdir(owner.resourceRoot); } catch {
      fail("prepared_root_read_failed");
    }
    if (entries.length !== 0) fail("prepared_root_not_empty");
    return stats;
  }
  const expected = owner.activation.resource_root_identity;
  if (canonicalJson(rootIdentity(stats)) !== canonicalJson(expected)) {
    fail("resource_root_identity_mismatch");
  }
  return stats;
}

async function removeBarrierFiles(owner) {
  const liveManifest = await readCanonicalPrivateFile(owner.manifestPath, "manifest");
  if (canonicalJson(verifyManifest(liveManifest)) !== canonicalJson(owner.manifest)) {
    fail("manifest_changed_before_cleanup_confirmation");
  }
  if (owner.activation !== null) {
    const liveActivation = await readCanonicalPrivateFile(owner.activationPath, "activation");
    if (canonicalJson(verifyActivation(liveActivation, owner.manifest))
      !== canonicalJson(owner.activation)) {
      fail("activation_changed_before_cleanup_confirmation");
    }
    await unlink(owner.activationPath).catch(() => fail("activation_remove_failed"));
    await syncDirectory(owner.privateRunRoot);
  }
  await unlink(owner.incompletePath).catch((error) => {
    if (error?.code !== "ENOENT") fail("incomplete_receipt_remove_failed");
  });
  await unlink(owner.manifestPath).catch(() => fail("manifest_remove_failed"));
  await syncDirectory(owner.privateRunRoot);
}

async function cleanupKnownOwner(owner) {
  const liveRoot = await resolvePrivateRunRoot(owner.privateRunRoot);
  if (!sameIdentity(liveRoot.stats, owner.privateRunRootIdentity)) {
    fail("private_run_root_identity_changed");
  }
  const liveFiles = await readOwnerFiles(liveRoot);
  if (liveFiles === null
    || canonicalJson(liveFiles.manifest) !== canonicalJson(owner.manifest)
    || canonicalJson(liveFiles.activation) !== canonicalJson(owner.activation)) {
    fail("owner_files_changed_before_cleanup");
  }
  const rootStats = await assertLiveRoot(owner);
  if (rootStats !== null) {
    await rm(owner.resourceRoot, { recursive: true, force: false });
    try {
      await lstat(owner.resourceRoot, { bigint: true });
      fail("resource_root_remove_not_confirmed");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await syncDirectory(owner.privateRunRoot);
  }
  await removeBarrierFiles(owner);
  return Object.freeze({
    schema_version: "aionis_release_workspace_owner_cleanup_confirmation_v1",
    owner_manifest_sha256: owner.manifest.manifest_sha256,
    cleanup_confirmed: true,
  });
}

export async function cleanupReleaseWorkspaceOwnerV1(handle) {
  const state = ownerState(handle);
  if (state.cleanupComplete) return state.cleanupConfirmation;
  try {
    const confirmation = await cleanupKnownOwner(state);
    state.cleanupComplete = true;
    state.cleanupConfirmation = confirmation;
    return confirmation;
  } catch (error) {
    try { await persistIncomplete(state); } catch (receiptError) {
      throw new AggregateError(
        [error, receiptError],
        "aionis_eval_release_workspace_owner_manifest_cleanup_and_receipt_failed",
      );
    }
    throw error;
  }
}

export async function readActiveReleaseWorkspaceOwnerManifestV1(options) {
  const input = expectExactRecord(options, [
    "privateRunRoot",
  ], "workspace_owner_read_input");
  const root = await resolvePrivateRunRoot(input.privateRunRoot);
  return readOwnerFiles(root);
}

function verifyManifestBindings(
  owner,
  expectedOwnerId,
  expectedPlanSha256,
  gitAuthority,
  privateRunRoot,
) {
  if (owner.manifest.owner_id !== expectedOwnerId
    || owner.manifest.plan_sha256 !== expectedPlanSha256
    || owner.manifest.private_run_root_sha256
      !== sha256Bytes(Buffer.from(privateRunRoot, "utf8"))
    || canonicalJson(owner.manifest.git_authority) !== canonicalJson(gitAuthority)) {
    fail("recovery_authority_mismatch");
  }
}

export async function reconcileReleaseWorkspaceOwnerV1(options) {
  const input = expectExactRecord(options, [
    "expectedOwnerId", "expectedPlanSha256", "gitExecutablePath", "privateRunRoot",
  ], "workspace_owner_reconcile_input");
  if (!OWNER_ID_PATTERN.test(input.expectedOwnerId)) fail("expected_owner_id_invalid");
  const expectedPlanSha256 = expectSha256(
    input.expectedPlanSha256,
    "workspace_owner_expected_plan_sha256",
  );
  const root = await resolvePrivateRunRoot(input.privateRunRoot);
  const owner = await readOwnerFiles(root);
  if (owner === null) {
    return Object.freeze({
      schema_version: "aionis_release_workspace_owner_reconciliation_v1",
      status: "no_active_owner",
      cleanup_confirmed: true,
    });
  }
  const liveGitAuthority = await gitExecutableAuthority(input.gitExecutablePath);
  verifyManifestBindings(
    owner,
    input.expectedOwnerId,
    expectedPlanSha256,
    liveGitAuthority,
    root.path,
  );
  const recoverableOwner = {
    ...owner,
    gitAuthority: liveGitAuthority,
    privateRunRoot: root.path,
    privateRunRootIdentity: root.stats,
    resourceRootIdentity: null,
  };
  try {
    const confirmation = await cleanupKnownOwner(recoverableOwner);
    return Object.freeze({
      schema_version: "aionis_release_workspace_owner_reconciliation_v1",
      status: owner.activation === null ? "prepared_owner_cleared" : "active_owner_recovered",
      cleanup_confirmed: confirmation.cleanup_confirmed,
      owner_manifest_sha256: owner.manifest.manifest_sha256,
    });
  } catch (error) {
    try { await persistIncomplete(recoverableOwner); } catch (receiptError) {
      throw new AggregateError(
        [error, receiptError],
        "aionis_eval_release_workspace_owner_manifest_reconcile_and_receipt_failed",
      );
    }
    throw error;
  }
}
