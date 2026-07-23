import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";

import {
  canonicalClone,
  canonicalSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";

const READ_CHUNK_BYTES = 1024 * 1024;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/u;

function fail(code) {
  throw new Error(`aionis_eval_workspace_${code}`);
}

function portablePath(value) {
  return value.split(path.sep).join("/");
}

function verifyPathComponent(value) {
  if (value === "" || value === "." || value === ".."
    || value.includes("/") || value.includes("\\")) {
    fail("path_component_invalid");
  }
  if (CONTROL_CHARACTER.test(value)) fail("path_component_control_forbidden");
  if (value.toLowerCase() === ".git") fail("git_metadata_forbidden");
  return value;
}

function verifyCanonicalPathComponents(value) {
  const parsed = path.parse(value);
  const remainder = value.slice(parsed.root.length);
  for (const component of remainder.split(path.sep).filter(Boolean)) {
    if (CONTROL_CHARACTER.test(component)) fail("path_component_control_forbidden");
  }
}

function expectedOwnerId() {
  return typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
}

function verifyOwner(stats) {
  const ownerId = expectedOwnerId();
  if (ownerId !== null && stats.uid !== ownerId) fail("owner_mismatch");
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

function inodeRecord(stats, kind, relativePath) {
  return {
    kind,
    path: relativePath === "" ? "." : portablePath(relativePath),
    device_id: String(stats.dev),
    inode: String(stats.ino),
    owner_id: String(stats.uid),
    link_count: String(stats.nlink),
    mode: Number(stats.mode & 0o777n),
  };
}

function buildInodeSet(inodes) {
  const inodeIdentifiers = inodes
    .map((entry) => `${entry.device_id}:${entry.inode}`)
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  for (let index = 1; index < inodeIdentifiers.length; index += 1) {
    if (inodeIdentifiers[index] === inodeIdentifiers[index - 1]) {
      fail("duplicate_inode_forbidden");
    }
  }
  const body = {
    schema_version: "aionis_pilot_workspace_inode_set_v1",
    inode_identifiers: inodeIdentifiers,
  };
  return canonicalClone({
    ...body,
    inode_set_sha256: canonicalSha256(body),
  });
}

async function verifyPathStillNamesHandle(absolute, handleStats, kind) {
  let pathStats;
  try {
    pathStats = await lstat(absolute, { bigint: true });
  } catch {
    fail("entry_identity_changed");
  }
  if (!sameIdentity(handleStats, pathStats)
    || (kind === "file" && !pathStats.isFile())
    || (kind === "directory" && !pathStats.isDirectory())) {
    fail("entry_identity_changed");
  }
}

function secureOpenFlags(kind) {
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    fail("no_follow_unsupported");
  }
  let flags = constants.O_RDONLY | constants.O_NOFOLLOW;
  if (kind === "directory") {
    if (!Number.isInteger(constants.O_DIRECTORY) || constants.O_DIRECTORY === 0) {
      fail("directory_open_unsupported");
    }
    flags |= constants.O_DIRECTORY;
  } else if (Number.isInteger(constants.O_NONBLOCK)) {
    flags |= constants.O_NONBLOCK;
  }
  return flags;
}

async function openExpectedEntry(absolute, kind) {
  let handle;
  try {
    handle = await open(absolute, secureOpenFlags(kind));
  } catch {
    fail("entry_open_failed");
  }
  try {
    const stats = await handle.stat({ bigint: true });
    if ((kind === "file" && !stats.isFile())
      || (kind === "directory" && !stats.isDirectory())) {
      fail("entry_type_changed");
    }
    verifyOwner(stats);
    if (kind === "file" && stats.nlink !== 1n) fail("hardlink_forbidden");
    await verifyPathStillNamesHandle(absolute, stats, kind);
    return { handle, stats };
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}

async function readStableFile(absolute, relativePath) {
  const { handle, stats: before } = await openExpectedEntry(absolute, "file");
  try {
    if (before.size < 0n || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail("file_size_invalid");
    }
    const expectedSize = Number(before.size);
    const digest = createHash("sha256");
    let position = 0;
    while (position < expectedSize) {
      const chunk = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, expectedSize - position));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, position);
      if (bytesRead === 0) fail("file_changed_during_read");
      digest.update(chunk.subarray(0, bytesRead));
      position += bytesRead;
    }
    const trailing = Buffer.allocUnsafe(1);
    const { bytesRead: trailingBytes } = await handle.read(trailing, 0, 1, position);
    if (trailingBytes !== 0) fail("file_changed_during_read");

    const after = await handle.stat({ bigint: true });
    if (!after.isFile() || after.nlink !== 1n || !sameSnapshot(before, after)) {
      fail("file_changed_during_read");
    }
    verifyOwner(after);
    await verifyPathStillNamesHandle(absolute, after, "file");
    return {
      entry: {
        kind: "file",
        mode: Number(before.mode & 0o777n),
        path: portablePath(relativePath),
        size_bytes: expectedSize,
        content_sha256: digest.digest("hex"),
      },
      inode: inodeRecord(before, "file", relativePath),
    };
  } finally {
    await handle.close();
  }
}

async function collectDirectory(root, relative, entries, inodes) {
  const absolute = relative === "" ? root : path.join(root, relative);
  const { handle, stats: before } = await openExpectedEntry(absolute, "directory");
  try {
    inodes.push(inodeRecord(before, "directory", relative));
    let names;
    try {
      names = await readdir(absolute, { encoding: "utf8" });
    } catch {
      fail("directory_read_failed");
    }
    names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    for (const rawName of names) {
      const name = verifyPathComponent(rawName);
      const childRelative = relative === "" ? name : path.join(relative, name);
      const childAbsolute = path.join(root, childRelative);
      let pathStats;
      try {
        pathStats = await lstat(childAbsolute, { bigint: true });
      } catch {
        fail("entry_identity_changed");
      }
      if (pathStats.isSymbolicLink()) fail("symlink_forbidden");
      if (pathStats.isDirectory()) {
        await collectDirectory(root, childRelative, entries, inodes);
      } else if (pathStats.isFile()) {
        const captured = await readStableFile(childAbsolute, childRelative);
        entries.push(captured.entry);
        inodes.push(captured.inode);
      } else {
        fail("special_file_forbidden");
      }
    }

    const after = await handle.stat({ bigint: true });
    if (!after.isDirectory() || !sameSnapshot(before, after)) {
      fail("directory_changed_during_capture");
    }
    verifyOwner(after);
    await verifyPathStillNamesHandle(absolute, after, "directory");
  } finally {
    await handle.close();
  }
}

async function captureWorkspaceSnapshotV1(workspacePathValue) {
  const workspacePath = expectText(workspacePathValue, "workspace_path", {
    maximumBytes: 16_384,
  });
  const absoluteInput = path.resolve(workspacePath);
  let resolved;
  try {
    resolved = await realpath(workspacePath);
  } catch {
    fail("root_missing");
  }
  if (resolved !== absoluteInput) fail("root_alias_forbidden");
  verifyCanonicalPathComponents(resolved);

  const entries = [];
  const inodes = [];
  await collectDirectory(resolved, "", entries, inodes);
  entries.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  inodes.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));

  const inodeSet = buildInodeSet(inodes);
  return { entries, inodeSet, inodes, resolved };
}

export async function captureWorkspaceInodeSetV1(workspacePathValue) {
  const snapshot = await captureWorkspaceSnapshotV1(workspacePathValue);
  return canonicalClone(snapshot.inodeSet);
}

export async function captureWorkspaceEvidenceV1(workspacePathValue) {
  const { entries, inodeSet, inodes, resolved } = await captureWorkspaceSnapshotV1(
    workspacePathValue,
  );
  const entrySetSha256 = canonicalSha256(entries);
  const projection = {
    schema_version: "aionis_pilot_workspace_projection_v1",
    file_count: entries.length,
    entry_set_sha256: entrySetSha256,
  };
  const root = inodes.find((entry) => entry.path === "." && entry.kind === "directory");
  if (root === undefined) fail("root_identity_missing");
  return canonicalClone({
    ...projection,
    inode_set_sha256: inodeSet.inode_set_sha256,
    workspace_identity: {
      realpath_sha256: sha256Bytes(Buffer.from(resolved, "utf8")),
      device_id: root.device_id,
      inode: root.inode,
    },
    workspace_sha256: canonicalSha256(projection),
  });
}
