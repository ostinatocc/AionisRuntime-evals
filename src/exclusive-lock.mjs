import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";

const LOCK_SCHEMA = "aionis_exclusive_lock_v2";
const OWNER_TOKEN_RE = /^[a-f0-9]{64}$/u;
const FILE_MODE = 0o600;
const LINUX_FLOCK_CANDIDATES = Object.freeze(["/usr/bin/flock", "/bin/flock"]);
const LINUX_FLOCK_CONFLICT_EXIT = 73;
const LINUX_FLOCK_TIMEOUT_MS = 5000;
const HANDLE_STATE = new WeakMap();
const PROCESS_LOCK_REGISTRY_KEY = Symbol.for("aionis.exclusive-lock.active-paths.v2");
const PROCESS_LOCK_PATHS = globalThis[PROCESS_LOCK_REGISTRY_KEY] instanceof Set
  ? globalThis[PROCESS_LOCK_REGISTRY_KEY]
  : new Set();
if (globalThis[PROCESS_LOCK_REGISTRY_KEY] !== PROCESS_LOCK_PATHS) {
  Object.defineProperty(globalThis, PROCESS_LOCK_REGISTRY_KEY, {
    value: PROCESS_LOCK_PATHS,
    enumerable: false,
    configurable: false,
    writable: false,
  });
}
const TABLE = "aionis_exclusive_lock_owner";
const TABLE_SQL = `CREATE TABLE IF NOT EXISTS ${TABLE} (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version TEXT NOT NULL,
  owner_token TEXT NOT NULL,
  pid INTEGER NOT NULL,
  hostname TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT`;
const TABLE_COLUMNS = Object.freeze([
  ["singleton", "INTEGER", 0, 1],
  ["schema_version", "TEXT", 1, 0],
  ["owner_token", "TEXT", 1, 0],
  ["pid", "INTEGER", 1, 0],
  ["hostname", "TEXT", 1, 0],
  ["created_at", "TEXT", 1, 0],
]);

export class ExclusiveLockError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = "ExclusiveLockError";
    this.code = code;
  }
}

function lockError(code, message, cause = undefined) {
  return new ExclusiveLockError(code, message, cause === undefined ? undefined : { cause });
}

function sqliteBusy(error) {
  return error?.code === "ERR_SQLITE_ERROR"
    && (error?.errcode === 5 || /\bdatabase is locked\b/iu.test(error?.message ?? ""));
}

function exactMode(stat, mode, field) {
  if ((stat.mode & 0o777) !== mode) {
    throw lockError("LOCK_MALFORMED", `${field} permissions must be exactly ${mode.toString(8)}`);
  }
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
    fs.fsyncSync(descriptor);
  } catch (error) {
    throw lockError("LOCK_IO", `cannot fsync lock parent directory: ${directory}`, error);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function lockPath(value) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || value.includes("\0")) {
    throw new TypeError("lockPath must be a non-empty trimmed string without NUL");
  }
  const absolute = path.resolve(value);
  const parent = path.dirname(absolute);
  let parentStat;
  try {
    parentStat = fs.lstatSync(parent);
  } catch (error) {
    throw lockError("LOCK_IO", `lock parent directory is unavailable: ${parent}`, error);
  }
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
    throw lockError("LOCK_IO", `lock parent must be a real directory: ${parent}`);
  }
  return { absolute, parent };
}

function lstatIfPresent(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function trustedLinuxFlockPath() {
  for (const candidate of LINUX_FLOCK_CANDIDATES) {
    try {
      const resolved = fs.realpathSync(candidate);
      const stat = fs.statSync(resolved);
      if (stat.isFile() && (stat.mode & 0o111) !== 0 && (stat.mode & 0o022) === 0) return resolved;
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw lockError("LOCK_UNSUPPORTED", `cannot validate Linux flock helper: ${candidate}`, error);
      }
    }
  }
  throw lockError(
    "LOCK_UNSUPPORTED",
    "Linux lock authority requires a non-group/world-writable util-linux flock at /usr/bin/flock or /bin/flock",
  );
}

function runLinuxFlock(flock, descriptor) {
  const result = spawnSync(
    flock,
    ["-x", "-n", "-E", String(LINUX_FLOCK_CONFLICT_EXIT), "3"],
    {
      env: { PATH: "/usr/bin:/bin", LC_ALL: "C" },
      stdio: ["ignore", "ignore", "pipe", descriptor],
      encoding: "utf8",
      timeout: LINUX_FLOCK_TIMEOUT_MS,
      killSignal: "SIGKILL",
      maxBuffer: 4096,
    },
  );
  if (result.error) {
    throw lockError("LOCK_UNSUPPORTED", "Linux flock helper could not execute", result.error);
  }
  if (!Number.isInteger(result.status)) {
    throw lockError("LOCK_IO", `Linux flock helper terminated without an exit status: ${result.signal ?? "unknown"}`);
  }
  return { status: result.status, stderr: (result.stderr ?? "").slice(0, 1024) };
}

function openLinuxLockDescriptor(absolute, expectedStat) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      absolute,
      fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || !sameFile(opened, expectedStat)) {
      throw lockError("LOCK_OWNERSHIP_LOST", `Linux flock descriptor changed inode: ${absolute}`);
    }
    exactMode(opened, FILE_MODE, "Linux flock descriptor");
    return descriptor;
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (error instanceof ExclusiveLockError) throw error;
    throw lockError("LOCK_IO", `cannot open Linux flock descriptor: ${absolute}`, error);
  }
}

function acquireLinuxKernelLock(absolute, expectedStat) {
  const flock = trustedLinuxFlockPath();
  const descriptor = openLinuxLockDescriptor(absolute, expectedStat);
  try {
    const acquired = runLinuxFlock(flock, descriptor);
    if (acquired.status === LINUX_FLOCK_CONFLICT_EXIT) {
      throw lockError("LOCK_HELD", `lock is held by another live process: ${absolute}`);
    }
    if (acquired.status !== 0) {
      throw lockError(
        "LOCK_UNSUPPORTED",
        `Linux flock helper failed with exit ${acquired.status}: ${JSON.stringify(acquired.stderr)}`,
      );
    }

    // flock(2) locks are attached to the inherited open-file-description. The
    // short-lived helper sets the lock on fd 3; after it exits, this parent fd
    // must still exclude a separately opened description. Verify that property
    // for every acquisition instead of trusting platform or filesystem labels.
    const contender = openLinuxLockDescriptor(absolute, expectedStat);
    let verification;
    try {
      verification = runLinuxFlock(flock, contender);
    } finally {
      fs.closeSync(contender);
    }
    if (verification.status !== LINUX_FLOCK_CONFLICT_EXIT) {
      throw lockError(
        "LOCK_UNSUPPORTED",
        `Linux flock retention self-check failed with exit ${verification.status}: ${JSON.stringify(verification.stderr)}`,
      );
    }
    return { descriptor, expectedStat, released: false };
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function releaseLinuxKernelLock(authority) {
  if (authority === null || authority.released) return false;
  let failure = null;
  try {
    const opened = fs.fstatSync(authority.descriptor);
    if (!opened.isFile() || !sameFile(opened, authority.expectedStat)) {
      failure = lockError("LOCK_OWNERSHIP_LOST", "Linux flock descriptor changed before release");
    }
  } catch (error) {
    failure = error instanceof ExclusiveLockError
      ? error
      : lockError("LOCK_IO", "cannot verify Linux flock descriptor before release", error);
  } finally {
    fs.closeSync(authority.descriptor);
    authority.released = true;
  }
  if (failure) throw failure;
  return true;
}

function acquirePlatformKernelLock(absolute, expectedStat) {
  if (process.platform === "linux") return acquireLinuxKernelLock(absolute, expectedStat);
  if (process.platform === "darwin") return null;
  throw lockError("LOCK_UNSUPPORTED", `exclusive lock authority is not implemented on ${process.platform}`);
}

function preparePrivateDatabase(absolute, parent) {
  const before = lstatIfPresent(absolute);
  if (before && (before.isSymbolicLink() || !before.isFile())) {
    throw lockError("LOCK_MALFORMED", `lock database must be a regular non-symlink file: ${absolute}`);
  }
  if (before) exactMode(before, FILE_MODE, "lock database");

  if (!before) {
    let descriptor;
    try {
      descriptor = fs.openSync(
        absolute,
        fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_RDWR
          | (fs.constants.O_NOFOLLOW ?? 0),
        FILE_MODE,
      );
      fs.fchmodSync(descriptor, FILE_MODE);
      fs.fsyncSync(descriptor);
    } catch (error) {
      if (error?.code !== "EEXIST") {
        if (error?.code === "ELOOP") {
          throw lockError("LOCK_MALFORMED", `lock database must not be a symlink: ${absolute}`, error);
        }
        throw lockError("LOCK_IO", `cannot create lock database: ${absolute}`, error);
      }
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    fsyncDirectory(parent);
  }
  const prepared = fs.lstatSync(absolute);
  if (prepared.isSymbolicLink() || !prepared.isFile()) {
    throw lockError("LOCK_MALFORMED", `lock database must be a regular non-symlink file: ${absolute}`);
  }
  exactMode(prepared, FILE_MODE, "lock database");
  return prepared;
}

function assertPathOwnership(absolute, expected) {
  let current;
  try {
    current = fs.lstatSync(absolute);
  } catch (error) {
    throw lockError("LOCK_OWNERSHIP_LOST", `lock database pathname is unavailable: ${absolute}`, error);
  }
  if (current.isSymbolicLink() || !current.isFile() || !sameFile(current, expected)) {
    throw lockError("LOCK_OWNERSHIP_LOST", `lock database inode changed: ${absolute}`);
  }
  exactMode(current, FILE_MODE, "lock database");
}

function createMetadata() {
  return {
    schema_version: LOCK_SCHEMA,
    owner_token: randomBytes(32).toString("hex"),
    pid: process.pid,
    hostname: os.hostname(),
    created_at: new Date().toISOString(),
  };
}

function assertMetadata(metadata, field = "lock metadata") {
  const expectedKeys = ["schema_version", "owner_token", "pid", "hostname", "created_at"];
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
    || !isDeepStrictEqual(Object.keys(metadata), expectedKeys)) {
    throw lockError("LOCK_MALFORMED", `${field} keys are invalid`);
  }
  if (metadata.schema_version !== LOCK_SCHEMA
    || typeof metadata.owner_token !== "string"
    || !OWNER_TOKEN_RE.test(metadata.owner_token)
    || !Number.isSafeInteger(metadata.pid)
    || metadata.pid < 1
    || typeof metadata.hostname !== "string"
    || metadata.hostname.length === 0
    || metadata.hostname.trim() !== metadata.hostname
    || typeof metadata.created_at !== "string"
    || !Number.isFinite(Date.parse(metadata.created_at))
    || new Date(metadata.created_at).toISOString() !== metadata.created_at) {
    throw lockError("LOCK_MALFORMED", `${field} values are invalid`);
  }
  return metadata;
}

function assertSchema(database, absolute) {
  const tables = database.prepare(
    "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
  ).all().map((row) => row.name);
  if (!isDeepStrictEqual(tables, [TABLE])) {
    throw lockError("LOCK_MALFORMED", `lock database schema is invalid: ${absolute}`);
  }
  const columns = database.prepare(`PRAGMA table_info(${TABLE})`).all().map((row) => [
    row.name,
    row.type,
    row.notnull,
    row.pk,
  ]);
  if (!isDeepStrictEqual(columns, TABLE_COLUMNS)) {
    throw lockError("LOCK_MALFORMED", `lock database columns are invalid: ${absolute}`);
  }
}

function closeQuietly(database, transactionStarted) {
  if (!database) return;
  if (transactionStarted) {
    try {
      database.exec("ROLLBACK");
    } catch {
      // Closing the connection still releases the kernel lock.
    }
  }
  try {
    database.close();
  } catch {
    // Preserve the acquisition error.
  }
}

function acquireDatabaseLock(absolute, expectedStat, metadata) {
  let database;
  let transactionStarted = false;
  try {
    const location = pathToFileURL(absolute);
    location.searchParams.set("mode", "rwc");
    if (process.platform === "darwin") location.searchParams.set("vfs", "unix-flock");
    database = new DatabaseSync(location, { timeout: 0 });
    assertPathOwnership(absolute, expectedStat);
    database.exec("PRAGMA busy_timeout = 0; PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA trusted_schema = OFF");
    database.exec(TABLE_SQL);
    assertSchema(database, absolute);
    database.exec("BEGIN IMMEDIATE");
    transactionStarted = true;
    assertPathOwnership(absolute, expectedStat);
    database.prepare(`INSERT INTO ${TABLE}
      (singleton, schema_version, owner_token, pid, hostname, created_at)
      VALUES (1, ?, ?, ?, ?, ?)
      ON CONFLICT(singleton) DO UPDATE SET
        schema_version = excluded.schema_version,
        owner_token = excluded.owner_token,
        pid = excluded.pid,
        hostname = excluded.hostname,
        created_at = excluded.created_at`).run(
      metadata.schema_version,
      metadata.owner_token,
      metadata.pid,
      metadata.hostname,
      metadata.created_at,
    );
    const recorded = { ...database.prepare(`SELECT schema_version, owner_token, pid, hostname, created_at
      FROM ${TABLE} WHERE singleton = 1`).get() };
    assertMetadata(recorded, "transactional lock metadata");
    if (!isDeepStrictEqual(recorded, metadata)) {
      throw lockError("LOCK_OWNERSHIP_LOST", `transactional lock metadata changed: ${absolute}`);
    }
    return { database, transactionStarted };
  } catch (error) {
    closeQuietly(database, transactionStarted);
    if (error instanceof ExclusiveLockError) throw error;
    if (sqliteBusy(error)) throw lockError("LOCK_HELD", `lock is held by another live process: ${absolute}`, error);
    if (/\bno such vfs\b/iu.test(error?.message ?? "")) {
      throw lockError("LOCK_UNSUPPORTED", `required SQLite kernel-lock VFS is unavailable: ${absolute}`, error);
    }
    throw lockError("LOCK_MALFORMED", `lock database could not establish its transaction authority: ${absolute}`, error);
  }
}

function makeHandle(absolute, parent, expectedStat, database, metadata, kernelAuthority) {
  const state = {
    absolute,
    parent,
    expectedStat,
    database,
    metadata,
    kernelAuthority,
    released: false,
  };
  const publicMetadata = Object.freeze({ ...metadata });
  const handle = Object.freeze({
    lockPath: absolute,
    ownerToken: publicMetadata.owner_token,
    metadata: publicMetadata,
    release: () => releaseState(state),
  });
  HANDLE_STATE.set(handle, state);
  return handle;
}

function releaseState(state) {
  if (state.released) return false;
  let failure = null;
  try {
    assertPathOwnership(state.absolute, state.expectedStat);
    const recorded = { ...state.database.prepare(`SELECT schema_version, owner_token, pid, hostname, created_at
      FROM ${TABLE} WHERE singleton = 1`).get() };
    assertMetadata(recorded, "transactional lock metadata");
    if (!isDeepStrictEqual(recorded, state.metadata)) {
      throw lockError("LOCK_OWNERSHIP_LOST", `transactional lock metadata changed: ${state.absolute}`);
    }
    state.database.exec("COMMIT");
  } catch (error) {
    failure = error instanceof ExclusiveLockError
      ? error
      : lockError("LOCK_IO", `lock transaction could not be released: ${state.absolute}`, error);
    try {
      state.database.exec("ROLLBACK");
    } catch {
      // Closing below is the final kernel-lock release path.
    }
  } finally {
    try {
      state.database.close();
    } catch (error) {
      failure ??= lockError("LOCK_IO", `lock database could not be closed: ${state.absolute}`, error);
    }
    try {
      releaseLinuxKernelLock(state.kernelAuthority);
    } catch (error) {
      failure ??= error;
    }
    state.released = true;
    PROCESS_LOCK_PATHS.delete(state.absolute);
    try {
      fsyncDirectory(state.parent);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure) throw failure;
  return true;
}

export function acquireExclusiveLock(value) {
  const resolved = lockPath(value);
  if (PROCESS_LOCK_PATHS.has(resolved.absolute)) {
    throw lockError("LOCK_HELD", `lock is already held by this process: ${resolved.absolute}`);
  }
  PROCESS_LOCK_PATHS.add(resolved.absolute);
  const metadata = createMetadata();
  let kernelAuthority = null;
  try {
    const expectedStat = preparePrivateDatabase(resolved.absolute, resolved.parent);
    kernelAuthority = acquirePlatformKernelLock(resolved.absolute, expectedStat);
    const authority = acquireDatabaseLock(resolved.absolute, expectedStat, metadata);
    return makeHandle(
      resolved.absolute,
      resolved.parent,
      expectedStat,
      authority.database,
      metadata,
      kernelAuthority,
    );
  } catch (error) {
    let failure = error;
    if (kernelAuthority !== null) {
      try {
        releaseLinuxKernelLock(kernelAuthority);
      } catch (releaseError) {
        failure = lockError(
          "LOCK_IO",
          `Linux kernel-lock helper could not be released after acquisition failure: ${resolved.absolute}`,
          new AggregateError([error, releaseError]),
        );
      }
    }
    PROCESS_LOCK_PATHS.delete(resolved.absolute);
    throw failure;
  }
}

export function releaseExclusiveLock(handle) {
  const state = HANDLE_STATE.get(handle);
  if (state === undefined) throw new TypeError("handle was not returned by acquireExclusiveLock");
  return releaseState(state);
}
