import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
  expectSha256,
  expectText,
} from "./canonical.mjs";

const MODULE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MAX_GIT_EXECUTABLE_BYTES = 134_217_728;
const MAX_GIT_OUTPUT_BYTES = 33_554_432;
const MAX_TRACKED_FILE_BYTES = 67_108_864;
const MAX_TRACKED_SOURCE_BYTES = 268_435_456;
const MAX_TRACKED_FILE_COUNT = 4_096;
const GIT_TIMEOUT_MS = 30_000;

export const EVAL_SOURCE_CLOSURE_ENCODING_V1 =
  "tracked_git_mode_nul_path_nul_content_sha256_lf_v1";

const RELEASE_PROVENANCE_AUTHORITIES = new WeakMap();

function fail(code) {
  throw new Error(`aionis_eval_release_repository_provenance_${code}`);
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function snapshotIdentity(stat) {
  return {
    device_id: stat.dev.toString(),
    inode: stat.ino.toString(),
    mode: stat.mode.toString(),
    owner_id: stat.uid.toString(),
    group_id: stat.gid.toString(),
    link_count: stat.nlink.toString(),
    size_bytes: stat.size.toString(),
    modified_time_ns: stat.mtimeNs.toString(),
    changed_time_ns: stat.ctimeNs.toString(),
  };
}

function absoluteCanonicalPath(value, field) {
  const text = expectText(value, field, { maximumBytes: 16_384 });
  if (!path.isAbsolute(text) || path.normalize(text) !== text) fail(`${field}_invalid`);
  return text;
}

function safeIntegerFromBigInt(value, field) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || BigInt(number) !== value) fail(`${field}_invalid`);
  return number;
}

export function gitExecutableIdentitySha256V1(value) {
  const input = expectExactRecord(value, [
    "executableSha256", "fileSizeBytes", "gitExecutablePath",
  ], "git_executable_identity_input");
  const gitExecutablePath = absoluteCanonicalPath(
    input.gitExecutablePath,
    "git_executable_identity_path",
  );
  const executableSha256 = expectSha256(
    input.executableSha256,
    "git_executable_identity_sha256",
  );
  if (!Number.isSafeInteger(input.fileSizeBytes) || input.fileSizeBytes < 1) {
    fail("git_executable_identity_size_invalid");
  }
  return canonicalSha256({
    schema_version: "aionis_release_git_executable_identity_v1",
    git_executable_path: gitExecutablePath,
    file_size_bytes: input.fileSizeBytes,
    executable_sha256: executableSha256,
  });
}

async function hashOpenFile(handle, size, maximumBytes, field) {
  if (size < 1n || size > BigInt(maximumBytes)) fail(`${field}_size_invalid`);
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(65_536);
  let position = 0;
  try {
    const total = safeIntegerFromBigInt(size, `${field}_size`);
    while (position < total) {
      const length = Math.min(buffer.length, total - position);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      if (bytesRead !== length) fail(`${field}_short_read`);
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const overflow = Buffer.allocUnsafe(1);
    try {
      if ((await handle.read(overflow, 0, 1, position)).bytesRead !== 0) {
        fail(`${field}_overflow`);
      }
    } finally {
      overflow.fill(0);
    }
    return hash.digest("hex");
  } finally {
    buffer.fill(0);
  }
}

async function openTrustedGitExecutable(gitExecutableValue) {
  const gitExecutablePath = absoluteCanonicalPath(
    gitExecutableValue,
    "git_executable_path",
  );
  let resolved;
  let pathStat;
  try {
    [resolved, pathStat] = await Promise.all([
      realpath(gitExecutablePath),
      lstat(gitExecutablePath, { bigint: true }),
    ]);
  } catch {
    fail("git_executable_missing");
  }
  if (resolved !== gitExecutablePath || path.basename(gitExecutablePath) !== "git"
    || !pathStat.isFile() || pathStat.isSymbolicLink()
    || pathStat.nlink < 1n || pathStat.uid !== 0n
    || (pathStat.mode & 0o111n) === 0n || (pathStat.mode & 0o022n) !== 0n
    || pathStat.size < 1n || pathStat.size > BigInt(MAX_GIT_EXECUTABLE_BYTES)) {
    fail("git_executable_posture_invalid");
  }
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    fail("no_follow_unsupported");
  }
  let handle;
  try {
    handle = await open(
      gitExecutablePath,
      constants.O_RDONLY | constants.O_NOFOLLOW
        | (Number.isInteger(constants.O_NONBLOCK) ? constants.O_NONBLOCK : 0),
    );
    const opened = await handle.stat({ bigint: true });
    if (!sameSnapshot(pathStat, opened)) fail("git_executable_identity_changed");
    const executableSha256 = await hashOpenFile(
      handle,
      opened.size,
      MAX_GIT_EXECUTABLE_BYTES,
      "git_executable",
    );
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(gitExecutablePath, { bigint: true });
    if (!sameSnapshot(opened, after) || !sameSnapshot(after, afterPath)) {
      fail("git_executable_changed_during_read");
    }
    return {
      executableSha256,
      gitExecutableIdentitySha256: gitExecutableIdentitySha256V1({
        gitExecutablePath,
        executableSha256,
        fileSizeBytes: safeIntegerFromBigInt(opened.size, "git_executable_size"),
      }),
      gitExecutablePath,
      handle,
      snapshot: opened,
    };
  } catch (error) {
    await handle?.close().catch(() => {});
    throw error;
  }
}

async function assertGitExecutableUnchanged(authority, { rehash = false } = {}) {
  let pathStat;
  try { pathStat = await lstat(authority.gitExecutablePath, { bigint: true }); } catch {
    fail("git_executable_disappeared");
  }
  const opened = await authority.handle.stat({ bigint: true });
  if (!sameSnapshot(authority.snapshot, opened)
    || !sameSnapshot(authority.snapshot, pathStat)) {
    fail("git_executable_changed_during_attestation");
  }
  if (rehash) {
    const digest = await hashOpenFile(
      authority.handle,
      opened.size,
      MAX_GIT_EXECUTABLE_BYTES,
      "git_executable_recheck",
    );
    if (digest !== authority.executableSha256) {
      fail("git_executable_digest_changed_during_attestation");
    }
  }
}

async function runTrustedGit(authority, repositoryRoot, args, operation) {
  await assertGitExecutableUnchanged(authority);
  const fullArgs = [
    "-c", "core.fsmonitor=false",
    "-c", "core.untrackedCache=false",
    "-c", "core.preloadindex=false",
    ...args,
  ];
  const child = spawn(authority.gitExecutablePath, fullArgs, {
    cwd: repositoryRoot,
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
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let overflow = false;
  const timer = setTimeout(() => child.kill("SIGKILL"), GIT_TIMEOUT_MS);
  const result = await new Promise((resolve, reject) => {
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_GIT_OUTPUT_BYTES) stdout.push(chunk);
      else { overflow = true; child.kill("SIGKILL"); }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= 1_048_576) stderr.push(chunk);
      else { overflow = true; child.kill("SIGKILL"); }
    });
    child.once("error", reject);
    child.once("close", (exitCode, signal) => resolve({ exitCode, signal }));
  }).finally(() => clearTimeout(timer));
  await assertGitExecutableUnchanged(authority);
  if (overflow || result.exitCode !== 0 || result.signal !== null) {
    Buffer.concat(stderr).fill(0);
    fail(`${operation}_failed`);
  }
  return Buffer.concat(stdout);
}

function exactGitLine(bytes, pattern, field) {
  const text = bytes.toString("utf8");
  if (!pattern.test(text) || Buffer.from(text, "utf8").compare(bytes) !== 0) {
    fail(`${field}_invalid`);
  }
  return text.slice(0, -1);
}

function parseTreeEntries(bytes) {
  if (bytes.length < 1 || bytes.at(-1) !== 0) fail("git_tree_listing_invalid");
  const records = [];
  let start = 0;
  let previousPathBytes = null;
  while (start < bytes.length) {
    const end = bytes.indexOf(0, start);
    if (end < 0 || end === start) fail("git_tree_listing_invalid");
    const record = bytes.subarray(start, end);
    const tab = record.indexOf(9);
    if (tab < 0) fail("git_tree_listing_invalid");
    const header = record.subarray(0, tab).toString("ascii");
    const match = /^(100644|100755) blob ([0-9a-f]{40})$/u.exec(header);
    if (match === null) fail("git_tree_entry_type_forbidden");
    const relativePathBytes = Buffer.from(record.subarray(tab + 1));
    const relativePath = relativePathBytes.toString("utf8");
    if (!Buffer.from(relativePath, "utf8").equals(relativePathBytes)
      || relativePath.length === 0 || path.posix.isAbsolute(relativePath)
      || relativePath.split("/").some((component) =>
        component.length === 0 || component === "." || component === "..")) {
      fail("git_tree_entry_path_invalid");
    }
    if (previousPathBytes !== null && Buffer.compare(previousPathBytes, relativePathBytes) >= 0) {
      fail("git_tree_entry_order_invalid");
    }
    previousPathBytes = relativePathBytes;
    records.push({
      gitMode: match[1],
      gitObjectSha1: match[2],
      relativePath,
      relativePathBytes,
    });
    if (records.length > MAX_TRACKED_FILE_COUNT) fail("tracked_file_count_limit");
    start = end + 1;
  }
  return records;
}

function trackedDirectories(repositoryRoot, entries) {
  const directories = new Set([repositoryRoot]);
  for (const entry of entries) {
    let relative = path.posix.dirname(entry.relativePath);
    while (relative !== ".") {
      directories.add(path.join(repositoryRoot, ...relative.split("/")));
      relative = path.posix.dirname(relative);
    }
  }
  return [...directories].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}

async function captureDirectorySnapshots(directories) {
  const snapshots = [];
  for (const directory of directories) {
    let stat;
    let resolved;
    try {
      [stat, resolved] = await Promise.all([
        lstat(directory, { bigint: true }),
        realpath(directory),
      ]);
    } catch {
      fail("tracked_directory_missing");
    }
    if (!stat.isDirectory() || stat.isSymbolicLink() || resolved !== directory) {
      fail("tracked_directory_posture_invalid");
    }
    snapshots.push({ directory, stat });
  }
  return snapshots;
}

async function assertDirectorySnapshotsUnchanged(snapshots) {
  for (const snapshot of snapshots) {
    let after;
    try { after = await lstat(snapshot.directory, { bigint: true }); } catch {
      fail("tracked_directory_disappeared");
    }
    if (!sameSnapshot(snapshot.stat, after)) fail("repository_changed_during_attestation");
  }
}

async function hashTrackedFile(repositoryRoot, entry) {
  const absolute = path.join(repositoryRoot, ...entry.relativePath.split("/"));
  let pathStat;
  try { pathStat = await lstat(absolute, { bigint: true }); } catch {
    fail("tracked_file_missing");
  }
  const executable = (pathStat.mode & 0o111n) !== 0n;
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.nlink !== 1n
    || pathStat.size < 0n || pathStat.size > BigInt(MAX_TRACKED_FILE_BYTES)
    || executable !== (entry.gitMode === "100755")) {
    fail("tracked_file_posture_invalid");
  }
  let handle;
  const buffer = Buffer.allocUnsafe(65_536);
  try {
    handle = await open(
      absolute,
      constants.O_RDONLY | constants.O_NOFOLLOW
        | (Number.isInteger(constants.O_NONBLOCK) ? constants.O_NONBLOCK : 0),
    );
    const opened = await handle.stat({ bigint: true });
    if (!sameSnapshot(pathStat, opened)) fail("tracked_file_identity_changed");
    const size = safeIntegerFromBigInt(opened.size, "tracked_file_size");
    const sha256 = createHash("sha256");
    const gitBlob = createHash("sha1");
    gitBlob.update(`blob ${size}\0`, "utf8");
    let position = 0;
    while (position < size) {
      const length = Math.min(buffer.length, size - position);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      if (bytesRead !== length) fail("tracked_file_short_read");
      const chunk = buffer.subarray(0, bytesRead);
      sha256.update(chunk);
      gitBlob.update(chunk);
      position += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(absolute, { bigint: true });
    if (!sameSnapshot(opened, after) || !sameSnapshot(after, afterPath)) {
      fail("tracked_file_changed_during_read");
    }
    if (gitBlob.digest("hex") !== entry.gitObjectSha1) {
      fail("tracked_file_git_blob_mismatch");
    }
    return {
      contentSha256: sha256.digest("hex"),
      size,
      snapshot: snapshotIdentity(opened),
    };
  } finally {
    buffer.fill(0);
    await handle?.close().catch(() => {});
  }
}

async function captureSourceClosure(repositoryRoot, treeBytes) {
  const entries = parseTreeEntries(treeBytes);
  const directorySnapshots = await captureDirectorySnapshots(
    trackedDirectories(repositoryRoot, entries),
  );
  const closure = createHash("sha256");
  closure.update("aionis_eval_source_closure_v1\0", "utf8");
  let sourceBytes = 0;
  const fileIdentities = [];
  for (const entry of entries) {
    const file = await hashTrackedFile(repositoryRoot, entry);
    sourceBytes += file.size;
    if (sourceBytes > MAX_TRACKED_SOURCE_BYTES) fail("tracked_source_size_limit");
    closure.update(entry.gitMode, "ascii");
    closure.update("\0", "ascii");
    closure.update(entry.relativePathBytes);
    closure.update("\0", "ascii");
    closure.update(file.contentSha256, "ascii");
    closure.update("\n", "ascii");
    fileIdentities.push({
      git_mode: entry.gitMode,
      relative_path: entry.relativePath,
      snapshot: file.snapshot,
    });
  }
  await assertDirectorySnapshotsUnchanged(directorySnapshots);
  return {
    closureSha256: closure.digest("hex"),
    sourceIdentityEpochSha256: canonicalSha256({
      schema_version: "aionis_eval_source_filesystem_identity_epoch_v1",
      directories: directorySnapshots.map(({ directory, stat }) => ({
        relative_path: path.relative(repositoryRoot, directory) || ".",
        snapshot: snapshotIdentity(stat),
      })),
      files: fileIdentities,
    }),
    trackedFileCount: entries.length,
  };
}

async function captureRepositoryPass(authority, repositoryRoot) {
  const topLevel = exactGitLine(
    await runTrustedGit(authority, repositoryRoot, ["rev-parse", "--show-toplevel"], "top_level"),
    /^\/[^\0\r\n]+\n$/u,
    "top_level",
  );
  let canonicalTopLevel;
  try { canonicalTopLevel = await realpath(topLevel); } catch { fail("top_level_missing"); }
  if (canonicalTopLevel !== repositoryRoot || topLevel !== repositoryRoot) {
    fail("top_level_binding_mismatch");
  }
  const gitCommitSha = exactGitLine(
    await runTrustedGit(authority, repositoryRoot, ["rev-parse", "--verify", "HEAD"], "head"),
    /^[0-9a-f]{40}\n$/u,
    "head",
  );
  const gitTreeSha = exactGitLine(
    await runTrustedGit(
      authority,
      repositoryRoot,
      ["rev-parse", "--verify", "HEAD^{tree}"],
      "head_tree",
    ),
    /^[0-9a-f]{40}\n$/u,
    "head_tree",
  );
  const treeBytes = await runTrustedGit(
    authority,
    repositoryRoot,
    ["ls-tree", "-r", "--full-tree", "-z", "HEAD"],
    "tree_listing",
  );
  const statusBefore = await runTrustedGit(
    authority,
    repositoryRoot,
    ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    "status_before",
  );
  if (statusBefore.length !== 0) fail("worktree_dirty");
  const closure = await captureSourceClosure(repositoryRoot, treeBytes);
  const statusAfter = await runTrustedGit(
    authority,
    repositoryRoot,
    ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    "status_after",
  );
  if (statusAfter.length !== 0) fail("worktree_dirty");
  const commitAfter = exactGitLine(
    await runTrustedGit(authority, repositoryRoot, ["rev-parse", "--verify", "HEAD"], "head_after"),
    /^[0-9a-f]{40}\n$/u,
    "head_after",
  );
  const treeAfter = exactGitLine(
    await runTrustedGit(
      authority,
      repositoryRoot,
      ["rev-parse", "--verify", "HEAD^{tree}"],
      "head_tree_after",
    ),
    /^[0-9a-f]{40}\n$/u,
    "head_tree_after",
  );
  const treeBytesAfter = await runTrustedGit(
    authority,
    repositoryRoot,
    ["ls-tree", "-r", "--full-tree", "-z", "HEAD"],
    "tree_listing_after",
  );
  if (commitAfter !== gitCommitSha || treeAfter !== gitTreeSha
    || !treeBytesAfter.equals(treeBytes)) fail("repository_changed_during_attestation");
  return canonicalClone({
    git_commit_sha: gitCommitSha,
    git_tree_sha: gitTreeSha,
    worktree_clean: true,
    closure_encoding: EVAL_SOURCE_CLOSURE_ENCODING_V1,
    closure_sha256: closure.closureSha256,
    source_identity_epoch_sha256: closure.sourceIdentityEpochSha256,
    tracked_file_count: closure.trackedFileCount,
  });
}

async function canonicalRepositoryRoot(repositoryRootValue) {
  const repositoryRoot = absoluteCanonicalPath(repositoryRootValue, "repository_root");
  let resolved;
  let stat;
  try {
    [resolved, stat] = await Promise.all([
      realpath(repositoryRoot),
      lstat(repositoryRoot, { bigint: true }),
    ]);
  } catch {
    fail("repository_root_missing");
  }
  if (resolved !== repositoryRoot || !stat.isDirectory() || stat.isSymbolicLink()) {
    fail("repository_root_posture_invalid");
  }
  return repositoryRoot;
}

/**
 * Captures a clean Git repository with the same real Git/file-system path used
 * by the release gate. This is also the only supported way to derive a future
 * frozen plan's eval binding fields.
 */
export async function captureReleaseEvalRepositoryProvenanceV1(options) {
  const input = expectExactRecord(options, [
    "gitExecutablePath", "repositoryRoot",
  ], "capture_input");
  const repositoryRoot = await canonicalRepositoryRoot(input.repositoryRoot);
  const gitAuthority = await openTrustedGitExecutable(input.gitExecutablePath);
  try {
    const first = await captureRepositoryPass(gitAuthority, repositoryRoot);
    const second = await captureRepositoryPass(gitAuthority, repositoryRoot);
    if (canonicalJson(first) !== canonicalJson(second)) {
      fail("repository_changed_between_passes");
    }
    await assertGitExecutableUnchanged(gitAuthority, { rehash: true });
    return canonicalClone({
      schema_version: "aionis_release_eval_repository_capture_v1",
      repository_root: repositoryRoot,
      ...first,
      git_executable_path: gitAuthority.gitExecutablePath,
      git_executable_sha256: gitAuthority.executableSha256,
      git_executable_identity_sha256: gitAuthority.gitExecutableIdentitySha256,
    });
  } finally {
    await gitAuthority.handle.close().catch(() => {});
  }
}

function verifyPlanBinding(planValue, capture, configuredGitExecutablePath) {
  if (planValue === null || typeof planValue !== "object" || Array.isArray(planValue)
    || planValue.eval_binding === null || typeof planValue.eval_binding !== "object"
    || Array.isArray(planValue.eval_binding)) fail("plan_invalid");
  const binding = planValue.eval_binding;
  if (configuredGitExecutablePath !== binding.git_executable_path
    || capture.git_commit_sha !== binding.git_commit_sha
    || capture.git_tree_sha !== binding.git_tree_sha
    || capture.worktree_clean !== binding.worktree_clean
    || capture.closure_sha256 !== binding.closure_sha256
    || capture.git_executable_path !== binding.git_executable_path
    || capture.git_executable_sha256 !== binding.git_executable_sha256
    || capture.git_executable_identity_sha256 !== binding.git_executable_identity_sha256) {
    fail("plan_binding_mismatch");
  }
  expectSha256(planValue.plan_sha256, "plan_sha256");
}

export function verifyReleaseEvalRepositoryCapturePlanBindingV1(options) {
  const input = expectExactRecord(options, [
    "capture", "configuredGitExecutablePath", "plan",
  ], "capture_plan_binding_input");
  verifyPlanBinding(input.plan, input.capture, input.configuredGitExecutablePath);
  return true;
}

/** Issues an opaque, reusable live lease for the module-fixed eval repo. */
export async function issueCurrentReleaseEvalRepositoryProvenanceV1(options) {
  const input = expectExactRecord(options, [
    "configuredGitExecutablePath", "plan",
  ], "release_authority_input");
  const capture = await captureReleaseEvalRepositoryProvenanceV1({
    gitExecutablePath: input.configuredGitExecutablePath,
    repositoryRoot: await realpath(MODULE_ROOT),
  });
  verifyPlanBinding(input.plan, capture, input.configuredGitExecutablePath);
  const body = canonicalClone({
    schema_version: "aionis_release_eval_repository_provenance_v1",
    authority_class: "live_current_eval_repository_release_authority_v1",
    claim_eligible: true,
    plan_sha256: input.plan.plan_sha256,
    repository_root: capture.repository_root,
    git_commit_sha: capture.git_commit_sha,
    git_tree_sha: capture.git_tree_sha,
    worktree_clean: capture.worktree_clean,
    closure_encoding: capture.closure_encoding,
    closure_sha256: capture.closure_sha256,
    source_identity_epoch_sha256: capture.source_identity_epoch_sha256,
    tracked_file_count: capture.tracked_file_count,
    git_executable_path: capture.git_executable_path,
    git_executable_sha256: capture.git_executable_sha256,
    git_executable_identity_sha256: capture.git_executable_identity_sha256,
  });
  const receipt = canonicalClone({ ...body, provenance_sha256: canonicalSha256(body) });
  const handle = Object.freeze({
    schema_version: "aionis_release_eval_repository_provenance_lease_v1",
    authority_class: receipt.authority_class,
    claim_eligible: true,
    plan_sha256: receipt.plan_sha256,
    git_executable_path: receipt.git_executable_path,
    provenance_sha256: receipt.provenance_sha256,
  });
  RELEASE_PROVENANCE_AUTHORITIES.set(handle, { receipt });
  return handle;
}

export async function verifyReleaseEvalRepositoryProvenanceReceiptLiveV1(options) {
  const input = expectExactRecord(options, [
    "plan", "provenanceReceipt",
  ], "live_receipt_verification_input");
  const receipt = expectExactRecord(input.provenanceReceipt, [
    "authority_class", "claim_eligible", "closure_encoding", "closure_sha256",
    "git_commit_sha", "git_executable_identity_sha256", "git_executable_path",
    "git_executable_sha256", "git_tree_sha", "plan_sha256", "provenance_sha256",
    "repository_root", "schema_version", "source_identity_epoch_sha256",
    "tracked_file_count", "worktree_clean",
  ], "live_provenance_receipt");
  const body = Object.fromEntries(
    Object.entries(receipt).filter(([key]) => key !== "provenance_sha256"),
  );
  let moduleRoot;
  try { moduleRoot = await realpath(MODULE_ROOT); } catch { fail("module_root_missing"); }
  if (receipt.schema_version !== "aionis_release_eval_repository_provenance_v1"
    || receipt.authority_class !== "live_current_eval_repository_release_authority_v1"
    || receipt.claim_eligible !== true || receipt.plan_sha256 !== input.plan?.plan_sha256
    || receipt.repository_root !== moduleRoot
    || canonicalSha256(body) !== receipt.provenance_sha256) {
    fail("live_provenance_receipt_invalid");
  }
  verifyPlanBinding(input.plan, receipt, receipt.git_executable_path);
  const live = await captureReleaseEvalRepositoryProvenanceV1({
    gitExecutablePath: receipt.git_executable_path,
    repositoryRoot: receipt.repository_root,
  });
  const expectedLive = {
    schema_version: "aionis_release_eval_repository_capture_v1",
    repository_root: receipt.repository_root,
    git_commit_sha: receipt.git_commit_sha,
    git_tree_sha: receipt.git_tree_sha,
    worktree_clean: receipt.worktree_clean,
    closure_encoding: receipt.closure_encoding,
    closure_sha256: receipt.closure_sha256,
    source_identity_epoch_sha256: receipt.source_identity_epoch_sha256,
    tracked_file_count: receipt.tracked_file_count,
    git_executable_path: receipt.git_executable_path,
    git_executable_sha256: receipt.git_executable_sha256,
    git_executable_identity_sha256: receipt.git_executable_identity_sha256,
  };
  if (canonicalJson(live) !== canonicalJson(expectedLive)) {
    fail("live_provenance_changed");
  }
  return canonicalClone(receipt);
}

/** Re-validates a genuine opaque lease; it is deliberately reusable through signing. */
export async function verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1(options) {
  const input = expectExactRecord(options, [
    "provenanceAuthority", "plan",
  ], "release_authority_claim_input");
  const state = input.provenanceAuthority !== null
    && typeof input.provenanceAuthority === "object"
    ? RELEASE_PROVENANCE_AUTHORITIES.get(input.provenanceAuthority)
    : undefined;
  if (state === undefined) fail("release_authority_brand_invalid");
  if (state.receipt.plan_sha256 !== input.plan?.plan_sha256
    || input.provenanceAuthority.plan_sha256 !== input.plan?.plan_sha256
    || input.provenanceAuthority.provenance_sha256 !== state.receipt.provenance_sha256
    || input.provenanceAuthority.git_executable_path !== state.receipt.git_executable_path) {
    fail("release_authority_live_binding_invalid");
  }
  return verifyReleaseEvalRepositoryProvenanceReceiptLiveV1({
    plan: input.plan,
    provenanceReceipt: state.receipt,
  });
}
