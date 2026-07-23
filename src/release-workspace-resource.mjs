import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import path from "node:path";

import {
  canonicalClone,
  canonicalSha256,
  expectArray,
  expectExactRecord,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { verifyPilotCaseV1, verifyPilotPlanV1 } from "./pilot-contract.mjs";
import {
  activateReleaseWorkspaceOwnerManifestV1,
  beginReleaseWorkspaceOwnerManifestV1,
  cleanupReleaseWorkspaceOwnerV1,
  resolveReleaseWorkspaceOwnerManifestV1,
} from "./release-workspace-owner-manifest.mjs";
import {
  captureWorkspaceEvidenceV1,
  captureWorkspaceInodeSetV1,
} from "./workspace-evidence.mjs";

const GIT_TIMEOUT_MS = 30_000;
const MAX_GIT_OUTPUT_BYTES = 1_048_576;
const COPY_CHUNK_BYTES = 1024 * 1024;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/u;
const RELEASE_WORKSPACE_OWNER_CLASS = "release_workspace_owner_v1";
const RELEASE_WORKSPACE_OWNERS = new WeakMap();

function fail(code) {
  throw new Error(`aionis_eval_release_workspace_resource_${code}`);
}

function workspaceOwnerHandle(plan, owner) {
  const handle = Object.freeze(Object.assign(Object.create(null), {
    schema_version: "aionis_release_workspace_owner_handle_v1",
    authority_class: RELEASE_WORKSPACE_OWNER_CLASS,
    claim_eligible: true,
    plan_sha256: plan.plan_sha256,
    resource_count: plan.schedule.length,
    owner_id: owner.owner_id,
    owner_manifest_sha256: owner.owner_manifest_sha256,
    workspace_authority_set_sha256: owner.workspace_authority_set_sha256,
  }));
  RELEASE_WORKSPACE_OWNERS.set(handle, {
    disposePromise: null,
    owner,
    status: "ready",
  });
  return handle;
}

function workspaceOwnerState(value) {
  const state = value !== null && typeof value === "object"
    ? RELEASE_WORKSPACE_OWNERS.get(value)
    : undefined;
  if (state === undefined) fail("owner_brand_invalid");
  return state;
}

export function claimReleaseWorkspaceResourceOwnerV1(options) {
  const input = expectExactRecord(options, [
    "plan", "workspaceOwner",
  ], "release_workspace_owner_claim_input");
  const plan = verifyPilotPlanV1(input.plan);
  const state = workspaceOwnerState(input.workspaceOwner);
  if (state.status !== "ready") fail("owner_not_ready_or_already_claimed");
  if (input.workspaceOwner.schema_version !== "aionis_release_workspace_owner_handle_v1"
    || input.workspaceOwner.authority_class !== RELEASE_WORKSPACE_OWNER_CLASS
    || input.workspaceOwner.plan_sha256 !== plan.plan_sha256
    || input.workspaceOwner.resource_count !== plan.schedule.length
    || input.workspaceOwner.owner_id !== state.owner.owner_id
    || input.workspaceOwner.owner_manifest_sha256 !== state.owner.owner_manifest_sha256
    || input.workspaceOwner.workspace_authority_set_sha256
      !== state.owner.workspace_authority_set_sha256) {
    fail("owner_live_binding_invalid");
  }
  state.status = "claimed";
  return state.owner;
}

export async function disposeReleaseWorkspaceResourceOwnerV1(value) {
  const state = workspaceOwnerState(value);
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

function compareUtf8(left, right) {
  return Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"));
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function ownerId() {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
}

function verifyOwner(stats, code = "owner_mismatch") {
  const expected = ownerId();
  if (expected !== null && stats.uid !== expected) fail(code);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSnapshot(left, right) {
  return sameIdentity(left, right)
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function verifyCanonicalAbsolutePath(value, field) {
  const input = expectText(value, field, { maximumBytes: 16_384 });
  if (!path.isAbsolute(input) || path.normalize(input) !== input) {
    fail(`${field}_not_canonical_absolute`);
  }
  return input;
}

async function resolveCanonicalPath(value, field) {
  const input = verifyCanonicalAbsolutePath(value, field);
  let resolved;
  try {
    resolved = await realpath(input);
  } catch {
    fail(`${field}_missing`);
  }
  if (resolved !== input) fail(`${field}_alias_forbidden`);
  return resolved;
}

async function verifyPrivateRunRoot(value) {
  const resolved = await resolveCanonicalPath(value, "private_run_root");
  const stats = await lstat(resolved, { bigint: true });
  if (!stats.isDirectory()) fail("private_run_root_not_directory");
  verifyOwner(stats, "private_run_root_owner_mismatch");
  if (Number(stats.mode & 0o777n) !== 0o700) {
    fail("private_run_root_mode_invalid");
  }
  return resolved;
}

async function verifyGitExecutable(value) {
  const resolved = await resolveCanonicalPath(value, "git_executable_path");
  const stats = await lstat(resolved, { bigint: true });
  if (!stats.isFile() || Number(stats.mode & 0o111n) === 0) {
    fail("git_executable_invalid");
  }
  return resolved;
}

function collectChild(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let overflow = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_GIT_OUTPUT_BYTES) stdout.push(chunk);
      else {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAX_GIT_OUTPUT_BYTES) stderr.push(chunk);
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
        timedOut,
        overflow,
      });
    });
  });
}

async function runGit(gitExecutablePath, repositoryPath, args, operation) {
  const child = spawn(gitExecutablePath, args, {
    cwd: repositoryPath,
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      HOME: "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
      TMPDIR: "/tmp",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const result = await collectChild(child, GIT_TIMEOUT_MS);
  if (result.timedOut) fail(`${operation}_timeout`);
  if (result.overflow) fail(`${operation}_output_limit`);
  if (result.exitCode !== 0 || result.signal !== null || result.stderr.length !== 0) {
    fail(`${operation}_failed`);
  }
  return result.stdout;
}

function singleLine(raw, operation) {
  if (raw.length < 2 || raw.at(-1) !== 0x0a) fail(`${operation}_output_invalid`);
  const body = raw.subarray(0, raw.length - 1);
  if (body.includes(0x00) || body.includes(0x0a) || body.includes(0x0d)) {
    fail(`${operation}_output_invalid`);
  }
  return body.toString("utf8");
}

async function verifyGitMetadataEntry(templatePath) {
  const metadataPath = path.join(templatePath, ".git");
  let stats;
  try {
    stats = await lstat(metadataPath, { bigint: true });
  } catch {
    fail("template_git_metadata_missing");
  }
  if (stats.isSymbolicLink() || (!stats.isDirectory() && !stats.isFile())) {
    fail("template_git_metadata_invalid");
  }
  verifyOwner(stats, "template_git_metadata_owner_mismatch");
  if (stats.isFile() && stats.nlink !== 1n) fail("template_git_metadata_hardlink_forbidden");
}

async function verifyTemplateGitAuthority(
  gitExecutablePath,
  templatePath,
  pilotCase,
) {
  const resolved = await resolveCanonicalPath(templatePath, "workspace_template_path");
  const rootStats = await lstat(resolved, { bigint: true });
  if (!rootStats.isDirectory()) fail("workspace_template_not_directory");
  verifyOwner(rootStats, "workspace_template_owner_mismatch");
  await verifyGitMetadataEntry(resolved);

  const topLevel = singleLine(
    await runGit(gitExecutablePath, resolved, ["rev-parse", "--show-toplevel"], "git_top_level"),
    "git_top_level",
  );
  let canonicalTopLevel;
  try {
    canonicalTopLevel = await realpath(topLevel);
  } catch {
    fail("git_top_level_missing");
  }
  if (topLevel !== resolved || canonicalTopLevel !== resolved) {
    fail("git_top_level_binding_mismatch");
  }

  const origin = singleLine(
    await runGit(
      gitExecutablePath,
      resolved,
      ["config", "--local", "--get-all", "remote.origin.url"],
      "git_origin",
    ),
    "git_origin",
  );
  if (origin !== pilotCase.workspace.repository_url) fail("git_origin_mismatch");

  const head = singleLine(
    await runGit(gitExecutablePath, resolved, ["rev-parse", "--verify", "HEAD"], "git_head"),
    "git_head",
  );
  if (head !== pilotCase.workspace.base_commit_sha) fail("git_head_mismatch");

  const cleanStatus = await runGit(
    gitExecutablePath,
    resolved,
    ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    "git_status",
  );
  const cleanStatusSha256 = sha256Bytes(cleanStatus);
  if (cleanStatusSha256 !== pilotCase.workspace.clean_status_sha256) {
    fail("git_status_sha256_mismatch");
  }
  return Object.freeze({
    templatePath: resolved,
    templateRealpathSha256: sha256Bytes(Buffer.from(resolved, "utf8")),
    head,
    cleanStatusSha256,
  });
}

function verifyTemplateMap(value, caseIds) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("workspace_templates_shape_invalid");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail("workspace_templates_shape_invalid");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    fail("workspace_templates_shape_invalid");
  }
  const expected = [...caseIds].sort(compareUtf8);
  const actual = [...keys].sort(compareUtf8);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail("workspace_templates_case_set_mismatch");
  }
  const entries = new Map();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      fail("workspace_templates_shape_invalid");
    }
    entries.set(key, descriptor.value);
  }
  return entries;
}

function verifyCases(plan, values) {
  const cases = expectArray(values, "release_workspace_cases", {
    minimum: 3,
    maximum: 3,
  }).map((value) => verifyPilotCaseV1(value));
  const caseById = new Map(cases.map((pilotCase) => [pilotCase.case_id, pilotCase]));
  if (caseById.size !== cases.length) fail("case_id_duplicate");
  if (plan.cases.length !== cases.length || plan.cases.some((ref, index) =>
    ref.case_id !== cases[index].case_id || ref.case_sha256 !== cases[index].case_sha256)) {
    fail("plan_case_binding_mismatch");
  }
  return { caseById, cases };
}

function secureOpenFlags(kind, write = false) {
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    fail("no_follow_unsupported");
  }
  if (kind === "directory") {
    if (!Number.isInteger(constants.O_DIRECTORY) || constants.O_DIRECTORY === 0) {
      fail("directory_open_unsupported");
    }
    return constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY;
  }
  if (write) {
    return constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
  }
  return constants.O_RDONLY | constants.O_NOFOLLOW
    | (Number.isInteger(constants.O_NONBLOCK) ? constants.O_NONBLOCK : 0);
}

async function verifyPathIdentity(absolute, expected, kind) {
  let stats;
  try {
    stats = await lstat(absolute, { bigint: true });
  } catch {
    fail("source_entry_identity_changed");
  }
  if (!sameIdentity(stats, expected)
    || (kind === "file" && !stats.isFile())
    || (kind === "directory" && !stats.isDirectory())) {
    fail("source_entry_identity_changed");
  }
}

async function openSourceEntry(absolute, kind) {
  let handle;
  try {
    handle = await open(absolute, secureOpenFlags(kind));
  } catch {
    fail("source_entry_open_failed");
  }
  try {
    const stats = await handle.stat({ bigint: true });
    if ((kind === "file" && !stats.isFile())
      || (kind === "directory" && !stats.isDirectory())) {
      fail("source_entry_type_changed");
    }
    verifyOwner(stats, "source_entry_owner_mismatch");
    if (kind === "file" && stats.nlink !== 1n) fail("source_hardlink_forbidden");
    await verifyPathIdentity(absolute, stats, kind);
    return { handle, stats };
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}

function verifyPathComponent(value) {
  if (value === "" || value === "." || value === ".."
    || value.includes("/") || value.includes("\\")
    || CONTROL_CHARACTER.test(value)) {
    fail("source_path_component_invalid");
  }
  if (value.toLowerCase() === ".git") fail("nested_git_metadata_forbidden");
  return value;
}

async function copyStableFile(source, destination) {
  const { handle: sourceHandle, stats: before } = await openSourceEntry(source, "file");
  let destinationHandle;
  try {
    const mode = Number(before.mode & 0o777n);
    destinationHandle = await open(destination, secureOpenFlags("file", true), mode);
    await destinationHandle.chmod(mode);
    if (before.size < 0n || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail("source_file_size_invalid");
    }
    const expectedSize = Number(before.size);
    let position = 0;
    while (position < expectedSize) {
      const chunk = Buffer.allocUnsafe(Math.min(COPY_CHUNK_BYTES, expectedSize - position));
      const { bytesRead } = await sourceHandle.read(chunk, 0, chunk.length, position);
      if (bytesRead === 0) fail("source_file_changed_during_copy");
      let written = 0;
      while (written < bytesRead) {
        const result = await destinationHandle.write(
          chunk,
          written,
          bytesRead - written,
          position + written,
        );
        if (result.bytesWritten === 0) fail("destination_write_failed");
        written += result.bytesWritten;
      }
      position += bytesRead;
    }
    const trailing = Buffer.allocUnsafe(1);
    if ((await sourceHandle.read(trailing, 0, 1, position)).bytesRead !== 0) {
      fail("source_file_changed_during_copy");
    }
    const after = await sourceHandle.stat({ bigint: true });
    if (!after.isFile() || after.nlink !== 1n || !sameSnapshot(before, after)) {
      fail("source_file_changed_during_copy");
    }
    verifyOwner(after, "source_entry_owner_mismatch");
    await verifyPathIdentity(source, after, "file");
  } finally {
    await destinationHandle?.close().catch(() => {});
    await sourceHandle.close();
  }
}

async function copyStableDirectory(sourceRoot, destinationRoot, relative = "") {
  const source = relative === "" ? sourceRoot : path.join(sourceRoot, relative);
  const destination = relative === "" ? destinationRoot : path.join(destinationRoot, relative);
  const { handle, stats: before } = await openSourceEntry(source, "directory");
  try {
    if (relative !== "") {
      const mode = Number(before.mode & 0o777n);
      await mkdir(destination, { mode });
      await chmod(destination, mode);
    }
    let names;
    try {
      names = await readdir(source, { encoding: "utf8" });
    } catch {
      fail("source_directory_read_failed");
    }
    names.sort(compareUtf8);
    for (const rawName of names) {
      if (relative === "" && rawName === ".git") continue;
      const name = verifyPathComponent(rawName);
      const childRelative = relative === "" ? name : path.join(relative, name);
      const childSource = path.join(sourceRoot, childRelative);
      const childDestination = path.join(destinationRoot, childRelative);
      let stats;
      try {
        stats = await lstat(childSource, { bigint: true });
      } catch {
        fail("source_entry_identity_changed");
      }
      if (stats.isSymbolicLink()) fail("source_symlink_forbidden");
      if (stats.isDirectory()) {
        await copyStableDirectory(sourceRoot, destinationRoot, childRelative);
      } else if (stats.isFile()) {
        await copyStableFile(childSource, childDestination);
      } else {
        fail("source_special_file_forbidden");
      }
    }
    const after = await handle.stat({ bigint: true });
    if (!after.isDirectory() || !sameSnapshot(before, after)) {
      fail("source_directory_changed_during_copy");
    }
    verifyOwner(after, "source_entry_owner_mismatch");
    await verifyPathIdentity(source, after, "directory");
  } finally {
    await handle.close();
  }
}

async function sha256StableOwnedFile(absolute) {
  const { handle, stats: before } = await openSourceEntry(absolute, "file");
  try {
    if (before.size < 0n || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail("fixture_file_size_invalid");
    }
    const digest = createHash("sha256");
    const expectedSize = Number(before.size);
    let position = 0;
    while (position < expectedSize) {
      const chunk = Buffer.allocUnsafe(Math.min(COPY_CHUNK_BYTES, expectedSize - position));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, position);
      if (bytesRead === 0) fail("fixture_file_changed_during_read");
      digest.update(chunk.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!after.isFile() || after.nlink !== 1n || !sameSnapshot(before, after)) {
      fail("fixture_file_changed_during_read");
    }
    await verifyPathIdentity(absolute, after, "file");
    return digest.digest("hex");
  } finally {
    await handle.close();
  }
}

function fixturePath(workspacePath, pilotCase) {
  const resolved = path.resolve(workspacePath, pilotCase.source_fixture.relative_path);
  if (resolved === workspacePath || !resolved.startsWith(`${workspacePath}${path.sep}`)) {
    fail("fixture_path_escape");
  }
  return resolved;
}

function verifyDisjointInodeSet(inodeSet, usedInodes) {
  for (const identifier of inodeSet.inode_identifiers) {
    if (usedInodes.has(identifier)) fail("workspace_inode_overlap");
  }
  for (const identifier of inodeSet.inode_identifiers) usedInodes.add(identifier);
}

function sameTemplateAuthority(left, right) {
  return left.templatePath === right.templatePath
    && left.templateRealpathSha256 === right.templateRealpathSha256
    && left.head === right.head
    && left.cleanStatusSha256 === right.cleanStatusSha256;
}

async function removeOwnedWorkspace(workspacePath, workspaceIdentity) {
  let current;
  try {
    current = await lstat(workspacePath, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (!current.isDirectory() || current.isSymbolicLink()
    || !sameIdentity(current, workspaceIdentity)) {
    fail("cleanup_workspace_identity_changed");
  }
  verifyOwner(current, "cleanup_workspace_owner_mismatch");
  await rm(workspacePath, { recursive: true, force: true });
}

export async function materializeReleasePilotWorkspacesV1(options) {
  const input = expectExactRecord(options, [
    "cases", "gitExecutablePath", "orchestrationOwnerId", "plan", "privateRunRoot",
    "workspaceTemplates",
  ], "release_workspace_materializer_input");
  const plan = verifyPilotPlanV1(input.plan);
  const { caseById, cases } = verifyCases(plan, input.cases);
  const privateRunRoot = await verifyPrivateRunRoot(input.privateRunRoot);
  const gitExecutablePath = await verifyGitExecutable(input.gitExecutablePath);
  const templateMap = verifyTemplateMap(
    input.workspaceTemplates,
    cases.map((pilotCase) => pilotCase.case_id),
  );

  const templateAuthorities = new Map();
  const templatePaths = new Set();
  for (const pilotCase of cases) {
    const authority = await verifyTemplateGitAuthority(
      gitExecutablePath,
      templateMap.get(pilotCase.case_id),
      pilotCase,
    );
    if (templatePaths.has(authority.templatePath)) fail("workspace_template_reused");
    templatePaths.add(authority.templatePath);
    templateAuthorities.set(pilotCase.case_id, authority);
  }

  const ownerManifest = await beginReleaseWorkspaceOwnerManifestV1({
    plan,
    privateRunRoot,
    gitExecutablePath,
    orchestrationOwnerId: input.orchestrationOwnerId,
  });
  await activateReleaseWorkspaceOwnerManifestV1(ownerManifest);
  const manifestAuthority = resolveReleaseWorkspaceOwnerManifestV1(ownerManifest);
  const resourceRoot = manifestAuthority.resourceRoot;
  let closeCompleted = false;
  let closePromise = null;
  const closeAll = () => {
    if (closeCompleted) return Promise.resolve();
    if (closePromise === null) {
      const attempt = (async () => {
        await cleanupReleaseWorkspaceOwnerV1(ownerManifest);
        closeCompleted = true;
      })();
      closePromise = attempt;
      void attempt.then(
        () => { closePromise = null; },
        () => { closePromise = null; },
      );
    }
    return closePromise;
  };

  try {
    const resources = [];
    const authorities = [];
    const usedInodes = new Set();
    for (const cell of plan.schedule) {
      const pilotCase = caseById.get(cell.case_id);
      if (pilotCase === undefined || pilotCase.case_sha256 !== cell.case_sha256) {
        fail("schedule_case_binding_mismatch");
      }
      const initialTemplateAuthority = templateAuthorities.get(cell.case_id);
      const beforeCopy = await verifyTemplateGitAuthority(
        gitExecutablePath,
        initialTemplateAuthority.templatePath,
        pilotCase,
      );
      if (!sameTemplateAuthority(initialTemplateAuthority, beforeCopy)) {
        fail("template_authority_changed");
      }

      const workspacePath = path.join(
        resourceRoot,
        `cell-${String(cell.ordinal).padStart(2, "0")}`,
      );
      await mkdir(workspacePath, { mode: 0o700 });
      await chmod(workspacePath, 0o700);
      const workspaceRootIdentity = await lstat(workspacePath, { bigint: true });
      await copyStableDirectory(initialTemplateAuthority.templatePath, workspacePath);

      const afterCopy = await verifyTemplateGitAuthority(
        gitExecutablePath,
        initialTemplateAuthority.templatePath,
        pilotCase,
      );
      if (!sameTemplateAuthority(initialTemplateAuthority, afterCopy)) {
        fail("template_authority_changed");
      }
      const canonicalWorkspacePath = await realpath(workspacePath);
      if (canonicalWorkspacePath !== workspacePath) fail("workspace_path_alias_forbidden");
      const workspaceEvidence = await captureWorkspaceEvidenceV1(workspacePath);
      const inodeSet = await captureWorkspaceInodeSetV1(workspacePath);
      if (workspaceEvidence.workspace_sha256 !== pilotCase.workspace.prepared_tree_sha256) {
        fail("workspace_prepared_tree_sha256_mismatch");
      }
      if (workspaceEvidence.inode_set_sha256 !== inodeSet.inode_set_sha256) {
        fail("workspace_inode_set_binding_mismatch");
      }
      verifyDisjointInodeSet(inodeSet, usedInodes);
      const sourceFixtureSha256 = await sha256StableOwnedFile(
        fixturePath(workspacePath, pilotCase),
      );
      if (sourceFixtureSha256 !== pilotCase.source_fixture.fixture_sha256) {
        fail("source_fixture_sha256_mismatch");
      }

      const authorityBody = canonicalClone({
        schema_version: "aionis_release_workspace_authority_v1",
        ordinal: cell.ordinal,
        opaque_cell_id: cell.opaque_cell_id,
        cell_sha256: canonicalSha256(cell),
        case_id: pilotCase.case_id,
        case_sha256: pilotCase.case_sha256,
        workspace_instance_id: cell.isolation.workspace_instance_id,
        workspace_path: workspacePath,
        workspace_prepared_sha256: workspaceEvidence.workspace_sha256,
        workspace_prepared_inode_set_sha256: workspaceEvidence.inode_set_sha256,
        workspace_identity: workspaceEvidence.workspace_identity,
        source_template_realpath_sha256: initialTemplateAuthority.templateRealpathSha256,
        source_template_head_sha: initialTemplateAuthority.head,
        source_template_clean_status_sha256: initialTemplateAuthority.cleanStatusSha256,
        source_fixture_sha256: sourceFixtureSha256,
      });
      const authority = deepFreeze(canonicalClone({
        ...authorityBody,
        authority_sha256: canonicalSha256(authorityBody),
      }));
      let cellClosed = false;
      let cellClosePromise = null;
      const close = () => {
        if (cellClosed) return Promise.resolve();
        if (cellClosePromise === null) {
          const attempt = (async () => {
            await removeOwnedWorkspace(workspacePath, workspaceRootIdentity);
            cellClosed = true;
          })();
          cellClosePromise = attempt;
          void attempt.then(
            () => { cellClosePromise = null; },
            () => { cellClosePromise = null; },
          );
        }
        return cellClosePromise;
      };
      authorities.push(authority);
      resources.push(deepFreeze({
        cell: canonicalClone(cell),
        pilotCase: canonicalClone(pilotCase),
        workspacePath,
        workspaceEvidence: canonicalClone(workspaceEvidence),
        inodeSet: canonicalClone(inodeSet),
        authority,
        close,
      }));
    }

    const frozenAuthorities = deepFreeze(authorities);
    const frozenResources = deepFreeze(resources);
    const authoritySetBody = canonicalClone({
      schema_version: "aionis_release_workspace_authority_set_v1",
      plan_sha256: plan.plan_sha256,
      workspace_authorities: frozenAuthorities,
    });
    const owner = Object.freeze({
      schema_version: "aionis_release_workspace_resources_v1",
      plan_sha256: plan.plan_sha256,
      owner_id: manifestAuthority.manifest.owner_id,
      owner_manifest_sha256: manifestAuthority.manifest.manifest_sha256,
      resource_root: resourceRoot,
      workspace_authority_set_sha256: canonicalSha256(authoritySetBody),
      resources: frozenResources,
      authorities: frozenAuthorities,
      closeAll,
    });
    return workspaceOwnerHandle(plan, owner);
  } catch (error) {
    try {
      await closeAll();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "aionis_eval_release_workspace_resource_materialization_and_cleanup_failed",
      );
    }
    throw error;
  }
}
