import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  ExclusiveLockError,
  acquireExclusiveLock,
  releaseExclusiveLock,
} from "../src/exclusive-lock.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MODULE_URL = pathToFileURL(path.join(ROOT, "src/exclusive-lock.mjs")).href;

function fixturePath(name = "campaign.lock") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aionis-exclusive-lock-"));
  return { root, lockPath: path.join(root, name) };
}

function waitForOutput(child, expected, timeoutMs = 10_000) {
  let output = "";
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`timed out waiting for child output ${JSON.stringify(expected)}; got ${JSON.stringify(output)}`));
    }, timeoutMs);
    const onData = (chunk) => {
      output += chunk.toString("utf8");
      if (output.includes(expected)) {
        clearTimeout(timeout);
        child.stdout.off("data", onData);
        resolve(output);
      }
    };
    child.stdout.on("data", onData);
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      if (!output.includes(expected)) {
        clearTimeout(timeout);
        reject(new Error(`child exited before ${JSON.stringify(expected)}: code=${code} signal=${signal} output=${JSON.stringify(output)}`));
      }
    });
  });
}

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

function spawnLockHolder(lockPath) {
  const source = `
    import { acquireExclusiveLock } from ${JSON.stringify(MODULE_URL)};
    const lock = acquireExclusiveLock(${JSON.stringify(lockPath)});
    process.stdout.write(\`READY \${JSON.stringify(lock.metadata)}\\n\`);
    setInterval(() => {}, 1000);
  `;
  return spawn(process.execPath, ["--input-type=module", "--eval", source], {
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function attemptLockInChild(lockPath) {
  const source = `
    import { acquireExclusiveLock } from ${JSON.stringify(MODULE_URL)};
    try {
      const lock = acquireExclusiveLock(${JSON.stringify(lockPath)});
      lock.release();
      process.stdout.write("ACQUIRED");
    } catch (error) {
      process.stderr.write(String(error.code ?? error.message));
      process.exitCode = 1;
    }
  `;
  return spawnSync(process.execPath, ["--input-type=module", "--eval", source], {
    encoding: "utf8",
  });
}

function holderMetadata(output) {
  const line = output.trim();
  assert.equal(line.startsWith("READY "), true);
  return JSON.parse(line.slice("READY ".length));
}

function persistedMetadata(lockPath) {
  const database = new DatabaseSync(lockPath, { readOnly: true });
  try {
    return { ...database.prepare(`SELECT schema_version, owner_token, pid, hostname, created_at
      FROM aionis_exclusive_lock_owner WHERE singleton = 1`).get() };
  } finally {
    database.close();
  }
}

function errorCode(code) {
  return (error) => error instanceof ExclusiveLockError && error.code === code;
}

test("kernel transaction lock is private, auditable, and released durably", () => {
  const { root, lockPath } = fixturePath();
  const handle = acquireExclusiveLock(lockPath);
  const stat = fs.lstatSync(lockPath);
  const header = fs.readFileSync(lockPath).subarray(0, 16).toString("ascii");
  const metadata = handle.metadata;

  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(header, "SQLite format 3\0");
  assert.deepEqual(Object.keys(metadata), ["schema_version", "owner_token", "pid", "hostname", "created_at"]);
  assert.equal(metadata.schema_version, "aionis_exclusive_lock_v2");
  assert.equal(metadata.owner_token, handle.ownerToken);
  assert.equal(metadata.pid, process.pid);
  assert.equal(metadata.hostname, os.hostname());

  const originalFsync = fs.fsyncSync;
  let directoryFsyncs = 0;
  fs.fsyncSync = function observedFsync(descriptor) {
    if (fs.fstatSync(descriptor).isDirectory()) directoryFsyncs += 1;
    return originalFsync.call(fs, descriptor);
  };
  try {
    assert.equal(releaseExclusiveLock(handle), true);
  } finally {
    fs.fsyncSync = originalFsync;
  }
  assert.equal(directoryFsyncs, 1);
  assert.equal(fs.existsSync(lockPath), true);
  assert.deepEqual(persistedMetadata(lockPath), metadata);
  assert.deepEqual(fs.readdirSync(root), [path.basename(lockPath)]);
  assert.equal(handle.release(), false);
});

test("one cross-process owner excludes every live contender", async (context) => {
  const { lockPath } = fixturePath();
  const child = spawnLockHolder(lockPath);
  context.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  await waitForOutput(child, "READY ");

  const rawBefore = fs.readFileSync(lockPath);
  for (let index = 0; index < 5; index += 1) {
    assert.throws(() => acquireExclusiveLock(lockPath), errorCode("LOCK_HELD"));
    assert.deepEqual(fs.readFileSync(lockPath), rawBefore);
  }
});

test("same-process reads and reentrant attempts cannot release the kernel lock", () => {
  const { lockPath } = fixturePath();
  const owner = acquireExclusiveLock(lockPath);
  const raw = fs.readFileSync(lockPath);
  assert.equal(raw.subarray(0, 16).toString("ascii"), "SQLite format 3\0");
  assert.throws(() => acquireExclusiveLock(lockPath), errorCode("LOCK_HELD"));
  if (process.platform === "linux") {
    const reader = new DatabaseSync(lockPath, { readOnly: true });
    try {
      reader.prepare("SELECT name FROM sqlite_schema ORDER BY name").all();
    } finally {
      reader.close();
    }
  }

  const blocked = attemptLockInChild(lockPath);
  assert.equal(blocked.status, 1, blocked.stdout);
  assert.match(blocked.stderr, /LOCK_HELD/);
  assert.equal(owner.release(), true);

  const acquired = attemptLockInChild(lockPath);
  assert.equal(acquired.status, 0, acquired.stderr);
  assert.equal(acquired.stdout, "ACQUIRED");
});

test("a SIGKILL releases the kernel lock without PID or reclaim-marker recovery", {
  skip: process.platform === "win32" ? "SIGKILL semantics are POSIX-only" : false,
}, async (context) => {
  const { root, lockPath } = fixturePath();
  const child = spawnLockHolder(lockPath);
  context.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  const output = await waitForOutput(child, "\n");
  const stale = holderMetadata(output);
  assert.equal(stale.pid, child.pid);
  assert.throws(() => acquireExclusiveLock(lockPath), errorCode("LOCK_HELD"));

  const exited = waitForExit(child);
  child.kill("SIGKILL");
  const result = await exited;
  assert.equal(result.signal, "SIGKILL");

  const replacement = acquireExclusiveLock(lockPath);
  assert.notEqual(replacement.ownerToken, stale.owner_token);
  assert.equal(replacement.metadata.pid, process.pid);
  assert.equal(fs.lstatSync(lockPath).mode & 0o777, 0o600);
  replacement.release();
  assert.deepEqual(fs.readdirSync(root), [path.basename(lockPath)]);
});

test("corrupt, insecure, and symlink lock databases fail closed", () => {
  const malformed = fixturePath("malformed.lock");
  fs.writeFileSync(malformed.lockPath, "{\"truncated\":", { mode: 0o600 });
  assert.throws(() => acquireExclusiveLock(malformed.lockPath), errorCode("LOCK_MALFORMED"));
  assert.equal(fs.readFileSync(malformed.lockPath, "utf8"), "{\"truncated\":");

  const insecure = fixturePath("insecure.lock");
  fs.writeFileSync(insecure.lockPath, Buffer.alloc(0), { mode: 0o644 });
  fs.chmodSync(insecure.lockPath, 0o644);
  assert.throws(() => acquireExclusiveLock(insecure.lockPath), errorCode("LOCK_MALFORMED"));
  assert.equal(fs.lstatSync(insecure.lockPath).mode & 0o777, 0o644);

  const symlink = fixturePath("symlink.lock");
  const target = path.join(symlink.root, "target");
  fs.writeFileSync(target, Buffer.alloc(0), { mode: 0o600 });
  fs.symlinkSync(target, symlink.lockPath);
  assert.throws(() => acquireExclusiveLock(symlink.lockPath), errorCode("LOCK_MALFORMED"));
  assert.equal(fs.lstatSync(symlink.lockPath).isSymbolicLink(), true);
});

test("release refuses a replacement lock database without deleting it", () => {
  const { root, lockPath } = fixturePath();
  const original = acquireExclusiveLock(lockPath);
  const replacementPath = path.join(root, "replacement.lock");
  const prepared = acquireExclusiveLock(replacementPath);
  prepared.release();
  fs.unlinkSync(lockPath);
  fs.renameSync(replacementPath, lockPath);
  const replacementRaw = fs.readFileSync(lockPath);

  assert.throws(() => original.release(), errorCode("LOCK_OWNERSHIP_LOST"));
  assert.deepEqual(fs.readFileSync(lockPath), replacementRaw);
  assert.deepEqual(persistedMetadata(lockPath), prepared.metadata);
});

test("release refuses a same-inode permission mutation", () => {
  const { lockPath } = fixturePath();
  const handle = acquireExclusiveLock(lockPath);
  const inode = fs.lstatSync(lockPath).ino;
  fs.chmodSync(lockPath, 0o644);

  assert.equal(fs.lstatSync(lockPath).ino, inode);
  assert.throws(() => handle.release(), errorCode("LOCK_MALFORMED"));
  assert.equal(fs.lstatSync(lockPath).mode & 0o777, 0o644);
});
