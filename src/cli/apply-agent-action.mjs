#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, rename, rm } from "node:fs/promises";
import path from "node:path";

import { decodeAgentActionV2, agentActionSha256V2 } from "../agent-action.mjs";
import { canonicalJson, expectExactRecord } from "../canonical.mjs";

const REPLACE_TARGET_MAX_BYTES = 1_048_576;
const REPLACE_READ_CHUNK_BYTES = 64 * 1024;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/u;

function finish(value, status = 0) {
  process.stdout.write(`${canonicalJson(value)}\n`);
  process.exit(status);
}

function fail(code) {
  throw new Error(`aionis_eval_agent_executor_${code}`);
}

function failCommitted(code) {
  const error = new Error(`aionis_eval_agent_executor_${code}`);
  error.workspaceCommitted = true;
  throw error;
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 1_048_576) throw new Error("aionis_eval_agent_executor_input_too_large");
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error("aionis_eval_agent_executor_input_utf8_invalid");
  }
  if (!Buffer.from(decoded, "utf8").equals(bytes)) {
    throw new Error("aionis_eval_agent_executor_input_utf8_invalid");
  }
  return decoded;
}

function safeRelativeTarget(value) {
  if (typeof value !== "string" || value === "" || value.startsWith("/")
    || value.includes("\\") || CONTROL_CHARACTER.test(value)
    || !/^[A-Za-z0-9._/-]+$/u.test(value)) {
    fail("replace_text_path_invalid");
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "."
    || segment === ".." || segment.toLowerCase() === ".git")
    || path.posix.normalize(value) !== value) {
    fail("replace_text_path_invalid");
  }
  return segments;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameStableSnapshot(left, right) {
  return sameIdentity(left, right)
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function verifyWritableRegularFile(stats) {
  if (!stats.isFile() || stats.nlink !== 1n || stats.size < 0n
    || stats.size > BigInt(REPLACE_TARGET_MAX_BYTES)) {
    fail("replace_text_target_invalid");
  }
}

function verifyPrivateParent(stats) {
  const expectedUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
  if (!stats.isDirectory() || (stats.mode & 0o777n) !== 0o700n
    || (expectedUid !== null && stats.uid !== expectedUid)) {
    fail("replace_text_parent_invalid");
  }
}

async function verifyPathStillNamesHandle(target, handleStats) {
  let pathStats;
  try {
    pathStats = await lstat(target, { bigint: true });
  } catch {
    fail("replace_text_target_changed");
  }
  verifyWritableRegularFile(pathStats);
  if (!sameIdentity(handleStats, pathStats)) fail("replace_text_target_changed");
}

async function readBounded(handle) {
  const chunks = [];
  let position = 0;
  while (position <= REPLACE_TARGET_MAX_BYTES) {
    const chunk = Buffer.allocUnsafe(Math.min(
      REPLACE_READ_CHUNK_BYTES,
      REPLACE_TARGET_MAX_BYTES + 1 - position,
    ));
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, position);
    if (bytesRead === 0) break;
    chunks.push(chunk.subarray(0, bytesRead));
    position += bytesRead;
    if (position > REPLACE_TARGET_MAX_BYTES) fail("replace_text_target_too_large");
  }
  return Buffer.concat(chunks, position);
}

async function writeAll(handle, bytes) {
  let position = 0;
  while (position < bytes.length) {
    const { bytesWritten } = await handle.write(
      bytes,
      position,
      bytes.length - position,
      position,
    );
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten < 1) {
      fail("replace_text_write_failed");
    }
    position += bytesWritten;
  }
}

async function verifyCommittedReplacement(target, temporaryStats, expectedBytes, expectedMode) {
  let handle;
  try {
    handle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    verifyWritableRegularFile(before);
    if (!sameIdentity(temporaryStats, before)
      || before.size !== BigInt(expectedBytes.length)
      || Number(before.mode & 0o777n) !== expectedMode) {
      failCommitted("replace_text_committed_verification_failed");
    }
    await verifyPathStillNamesHandle(target, before);
    if (await realpath(target) !== target) {
      failCommitted("replace_text_committed_verification_failed");
    }
    const actualBytes = await readBounded(handle);
    const after = await handle.stat({ bigint: true });
    if (!sameStableSnapshot(before, after)
      || createHash("sha256").update(actualBytes).digest("hex")
        !== createHash("sha256").update(expectedBytes).digest("hex")) {
      failCommitted("replace_text_committed_verification_failed");
    }
  } catch (error) {
    if (error?.workspaceCommitted === true) throw error;
    failCommitted("replace_text_committed_verification_failed");
  } finally {
    if (handle !== undefined) await handle.close().catch(() => {});
  }
}

function uniqueOccurrenceIndex(content, oldText) {
  const first = content.indexOf(oldText);
  if (first < 0 || content.indexOf(oldText, first + 1) >= 0) {
    fail("replace_text_match_not_unique");
  }
  return first;
}

async function applyReplaceText(action, allowedTargetPath) {
  const workspaceInput = process.cwd();
  const workspace = await realpath(workspaceInput).catch(() => {
    fail("replace_text_workspace_invalid");
  });
  if (workspace !== path.resolve(workspaceInput)) fail("replace_text_workspace_invalid");
  if (action.path !== allowedTargetPath) fail("replace_text_path_invalid");

  const segments = safeRelativeTarget(action.path);
  const target = path.join(workspace, ...segments);
  const relative = path.relative(workspace, target);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail("replace_text_path_invalid");
  }

  const parent = path.dirname(target);
  const canonicalParent = await realpath(parent).catch(() => {
    fail("replace_text_parent_invalid");
  });
  if (canonicalParent !== parent) fail("replace_text_parent_invalid");
  const parentStats = await lstat(parent, { bigint: true }).catch(() => {
    fail("replace_text_parent_invalid");
  });
  verifyPrivateParent(parentStats);

  let pathStats;
  let canonicalTarget;
  try {
    pathStats = await lstat(target, { bigint: true });
    canonicalTarget = await realpath(target);
  } catch {
    fail("replace_text_target_invalid");
  }
  verifyWritableRegularFile(pathStats);
  if (canonicalTarget !== target) fail("replace_text_target_invalid");
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    fail("replace_text_no_follow_unsupported");
  }

  let sourceHandle;
  try {
    sourceHandle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    fail("replace_text_target_open_failed");
  }

  try {
    const openedStats = await sourceHandle.stat({ bigint: true });
    verifyWritableRegularFile(openedStats);
    if (!sameIdentity(pathStats, openedStats)) fail("replace_text_target_changed");
    await verifyPathStillNamesHandle(target, openedStats);
    if (await realpath(target) !== target) fail("replace_text_target_changed");

    const originalBytes = await readBounded(sourceHandle);
    const afterRead = await sourceHandle.stat({ bigint: true });
    if (!sameStableSnapshot(openedStats, afterRead)) {
      fail("replace_text_target_changed");
    }
    await verifyPathStillNamesHandle(target, afterRead);

    let content;
    try {
      content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
        .decode(originalBytes);
    } catch {
      fail("replace_text_target_utf8_invalid");
    }
    if (!Buffer.from(content, "utf8").equals(originalBytes)) {
      fail("replace_text_target_utf8_invalid");
    }

    const matchIndex = uniqueOccurrenceIndex(content, action.old_text);
    const replacement = `${content.slice(0, matchIndex)}${action.new_text}`
      + content.slice(matchIndex + action.old_text.length);
    const replacementBytes = Buffer.from(replacement, "utf8");
    if (replacementBytes.length > REPLACE_TARGET_MAX_BYTES) {
      fail("replace_text_result_too_large");
    }

    const targetMode = Number(afterRead.mode & 0o777n);
    const temporary = path.join(
      parent,
      `.aionis-replace-${process.pid}-${randomBytes(16).toString("hex")}.tmp`,
    );
    let temporaryHandle = null;
    let temporaryCreated = false;
    let renamed = false;
    let writtenStats;
    try {
      temporaryHandle = await open(
        temporary,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        targetMode,
      );
      temporaryCreated = true;
      const emptyStats = await temporaryHandle.stat({ bigint: true });
      verifyWritableRegularFile(emptyStats);
      if (emptyStats.size !== 0n || emptyStats.dev !== parentStats.dev) {
        fail("replace_text_temporary_invalid");
      }
      await writeAll(temporaryHandle, replacementBytes);
      await temporaryHandle.chmod(targetMode);
      await temporaryHandle.sync();
      writtenStats = await temporaryHandle.stat({ bigint: true });
      verifyWritableRegularFile(writtenStats);
      if (writtenStats.size !== BigInt(replacementBytes.length)
        || Number(writtenStats.mode & 0o777n) !== targetMode) {
        fail("replace_text_temporary_invalid");
      }
      await temporaryHandle.close();
      temporaryHandle = null;

      const beforeRename = await sourceHandle.stat({ bigint: true });
      if (!sameStableSnapshot(afterRead, beforeRename)) {
        fail("replace_text_target_changed");
      }
      await verifyPathStillNamesHandle(target, beforeRename);
      if (await realpath(target) !== target) fail("replace_text_target_changed");
      await sourceHandle.close();
      sourceHandle = null;
      await rename(temporary, target);
      renamed = true;
      await verifyCommittedReplacement(
        target,
        writtenStats,
        replacementBytes,
        targetMode,
      );
    } finally {
      if (temporaryHandle !== null) await temporaryHandle.close().catch(() => {});
      if (temporaryCreated && !renamed) await rm(temporary, { force: true }).catch(() => {});
    }
  } finally {
    if (sourceHandle !== null) {
      try {
        await sourceHandle.close();
      } catch {}
    }
  }
}

try {
  const gitExecutable = process.argv[2];
  if (process.argv.length !== 4 || typeof gitExecutable !== "string"
    || !gitExecutable.startsWith("/") || typeof process.argv[3] !== "string") {
    throw new Error("aionis_eval_agent_executor_target_authority_invalid");
  }
  const allowedTargetPath = safeRelativeTarget(process.argv[3]).join("/");
  const envelope = expectExactRecord(
    JSON.parse(await readStdin()),
    ["assistant_content"],
    "agent_executor_input",
  );
  const action = decodeAgentActionV2(envelope.assistant_content);
  const actionSha256 = agentActionSha256V2(action);
  if (action.action.kind === "no_safe_change") {
    finish({
      schema_version: "aionis_pilot_agent_executor_result_v1",
      status: "no_safe_change",
      action_sha256: actionSha256,
    });
  }
  if (action.action.kind === "replace_text") {
    try {
      await applyReplaceText(action.action, allowedTargetPath);
    } catch (error) {
      if (error?.workspaceCommitted === true) {
        process.stderr.write(`${error.message}\n`);
        process.exit(70);
      }
      process.stderr.write(
        typeof error?.message === "string"
          ? `${error.message}\n`
          : "replace_text failed\n",
      );
      finish({
        schema_version: "aionis_pilot_agent_executor_result_v1",
        status: "patch_rejected",
        action_sha256: actionSha256,
      }, 65);
    }
    finish({
      schema_version: "aionis_pilot_agent_executor_result_v1",
      status: "applied",
      action_sha256: actionSha256,
    });
  }
  throw new Error("aionis_eval_agent_executor_action_kind_invalid");
} catch (error) {
  const code = typeof error?.message === "string" && error.message.startsWith("aionis_eval_")
    ? error.message
    : "aionis_eval_agent_executor_invalid_response";
  finish({
    schema_version: "aionis_pilot_agent_executor_result_v1",
    status: "response_rejected",
    error_code: code,
  }, 64);
}
