import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { DatabaseSync } from "node:sqlite";
import { acquireExclusiveLock } from "./exclusive-lock.mjs";

const AUTHORITY_SCHEMA = "aionis_campaign_head_authority_v1";
const ADMISSION_MODE = "blocked_groundwork";
const RUN_CLAIM_SCHEMA = "aionis_campaign_run_claim_v1";
const CAMPAIGN_CLAIM_SCHEMA = "aionis_campaign_identity_claim_v1";
const HEAD_RECORD_SCHEMA = "aionis_campaign_monotonic_head_v1";
const HEAD_BINDING_SCHEMA = "aionis_campaign_head_binding_v1";
const PROJECTION_ACK_SCHEMA = "aionis_campaign_projection_ack_v1";
const RUN_SCOPE_SCHEMA = "aionis_campaign_run_scope_v1";
const DATABASE_NAME = "campaign-authority.sqlite";
const LOCK_NAME = ".campaign-authority.lock";
const JOURNAL_DIRECTORY = "journal";
const RUN_CLAIMS_DIRECTORY = "run-claims";
const CAMPAIGN_CLAIMS_DIRECTORY = "campaign-claims";
const HEADS_DIRECTORY = "heads";
const PROJECTION_ACKS_DIRECTORY = "projection-acks";
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const IMMUTABLE_FILE_MODE = 0o400;
const MAX_RECORD_BYTES = 9 * 1024 * 1024;
const PENDING_JSON_RE = /^\.aionis-json-[0-9]+-[a-f0-9]{32}\.pending$/u;
const DIGEST_RE = /^[a-f0-9]{64}$/u;
const CAMPAIGN_ID_RE = /^campaign-[a-f0-9]{40}$/u;
const AUTHORITY_ID_RE = /^authority-[a-f0-9]{64}$/u;
const RUN_SCOPE_ID_RE = /^run-[a-f0-9]{64}$/u;
const GENERATION_RE = /^generation-[a-f0-9]{64}$/u;
const COMMIT_RE = /^[a-f0-9]{40}$/u;
const HANDLE_STATE = new WeakMap();
const SESSION_STATE = new WeakMap();

const SCHEMA_SQL = `
CREATE TABLE aionis_campaign_authority_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  admission_mode TEXT NOT NULL CHECK (admission_mode = 'blocked_groundwork'),
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE aionis_campaign_instances (
  campaign_id TEXT PRIMARY KEY,
  run_scope_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  ledger_root TEXT NOT NULL,
  ledger_root_dev TEXT NOT NULL,
  ledger_root_ino TEXT NOT NULL,
  ledger_instance_id TEXT NOT NULL,
  run_scope_json TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX aionis_campaign_instances_run_scope_uq
  ON aionis_campaign_instances(run_scope_id);
CREATE UNIQUE INDEX aionis_campaign_instances_generation_uq
  ON aionis_campaign_instances(generation);
CREATE UNIQUE INDEX aionis_campaign_instances_ledger_root_uq
  ON aionis_campaign_instances(ledger_root);
CREATE UNIQUE INDEX aionis_campaign_instances_ledger_instance_uq
  ON aionis_campaign_instances(ledger_instance_id);
CREATE TABLE aionis_campaign_run_claims (
  run_scope_id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  ledger_root TEXT NOT NULL,
  ledger_root_dev TEXT NOT NULL,
  ledger_root_ino TEXT NOT NULL,
  ledger_instance_id TEXT NOT NULL,
  run_scope_json TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX aionis_campaign_run_claims_campaign_idx
  ON aionis_campaign_run_claims(campaign_id, generation);
CREATE TABLE aionis_campaign_head_index (
  campaign_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 0),
  previous_head_sha256 TEXT,
  previous_payload_sha256 TEXT,
  payload_sha256 TEXT NOT NULL,
  head_sha256 TEXT NOT NULL,
  journal_relative_path TEXT NOT NULL,
  journal_bytes INTEGER NOT NULL CHECK (journal_bytes > 0),
  projected_at TEXT,
  PRIMARY KEY (campaign_id, generation, revision),
  FOREIGN KEY (campaign_id) REFERENCES aionis_campaign_instances(campaign_id),
  CHECK (
    (revision = 0 AND previous_head_sha256 IS NULL AND previous_payload_sha256 IS NULL)
    OR
    (revision > 0 AND previous_head_sha256 IS NOT NULL AND previous_payload_sha256 IS NOT NULL)
  )
) STRICT;
CREATE UNIQUE INDEX aionis_campaign_head_index_head_uq
  ON aionis_campaign_head_index(head_sha256);
CREATE UNIQUE INDEX aionis_campaign_head_index_journal_uq
  ON aionis_campaign_head_index(journal_relative_path);
`;

function schemaObjects(database) {
  return database.prepare(`SELECT type, name, tbl_name, sql FROM sqlite_schema
    WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`).all().map((entry) => ({ ...entry }));
}

const EXPECTED_SCHEMA_OBJECTS = (() => {
  const database = new DatabaseSync(":memory:");
  try {
    database.exec(SCHEMA_SQL);
    return Object.freeze(schemaObjects(database).map((entry) => Object.freeze(entry)));
  } finally {
    database.close();
  }
})();

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, keys, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${field} must be an object`);
  if (!isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort())) {
    fail(`${field} keys are invalid`);
  }
}

function nonEmptyString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || value.includes("\0")) {
    fail(`${field} must be a non-empty trimmed string without NUL`);
  }
  return value;
}

function safeInteger(value, field, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${field} must be a safe integer >= ${minimum}`);
  return value;
}

function isoTimestamp(value, field) {
  nonEmptyString(value, field);
  if (!Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail(`${field} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("canonical authority JSON cannot contain non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonical(entry)).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("canonical authority JSON contains a non-JSON value");
  }
  const keys = Object.keys(value).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function clone(value) {
  return structuredClone(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exactMode(stat, mode, field) {
  const actual = typeof stat.mode === "bigint"
    ? Number(stat.mode & 0o777n)
    : stat.mode & 0o777;
  if (actual !== mode) fail(`${field} permissions must be exactly ${mode.toString(8)}`);
}

function assertTrustedOwner(stat, field) {
  if (typeof process.getuid === "function" && Number(stat.uid) !== process.getuid()) {
    fail(`${field} must be owned by the authority process user`);
  }
}

function lstatIfPresent(target) {
  try {
    return fs.lstatSync(target, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function syncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function ensurePrivateDirectory(directory, field, { create = false, parent = null } = {}) {
  let stat = lstatIfPresent(directory);
  if (!stat && create) {
    try {
      fs.mkdirSync(directory, { mode: DIRECTORY_MODE });
      fs.chmodSync(directory, DIRECTORY_MODE);
      if (parent) syncDirectory(parent);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
    stat = lstatIfPresent(directory);
  }
  if (!stat || stat.isSymbolicLink() || !stat.isDirectory()) {
    fail(`${field} must be a real non-symlink directory`);
  }
  exactMode(stat, DIRECTORY_MODE, field);
  assertTrustedOwner(stat, field);
  return stat;
}

function assertPrivateFileStat(stat, field, mode = FILE_MODE) {
  if (stat.isSymbolicLink() || !stat.isFile()) fail(`${field} must be a regular non-symlink file`);
  exactMode(stat, mode, field);
  assertTrustedOwner(stat, field);
  if (Number(stat.nlink) !== 1) fail(`${field} must have exactly one hard link`);
  return stat;
}

function assertPrivateFile(target, field, mode = FILE_MODE) {
  const stat = fs.lstatSync(target, { bigint: true });
  assertPrivateFileStat(stat, field, mode);
  return stat;
}

function identity(stat) {
  return { dev: String(stat.dev), ino: String(stat.ino), uid: String(stat.uid) };
}

function sameIdentity(stat, expected) {
  return String(stat.dev) === expected.dev
    && String(stat.ino) === expected.ino
    && (expected.uid === undefined || String(stat.uid) === expected.uid);
}

function authorityPaths(directory) {
  const requested = path.resolve(nonEmptyString(directory, "campaign head authority directory"));
  const existing = lstatIfPresent(requested);
  const root = existing && !existing.isSymbolicLink() && existing.isDirectory()
    ? fs.realpathSync(requested)
    : requested;
  const journal = path.join(root, JOURNAL_DIRECTORY);
  return {
    root,
    database: path.join(root, DATABASE_NAME),
    lock: path.join(root, LOCK_NAME),
    journal,
    runClaims: path.join(journal, RUN_CLAIMS_DIRECTORY),
    campaignClaims: path.join(journal, CAMPAIGN_CLAIMS_DIRECTORY),
    heads: path.join(journal, HEADS_DIRECTORY),
    projectionAcks: path.join(journal, PROJECTION_ACKS_DIRECTORY),
  };
}

function createPrivateFile(target) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      target,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW ?? 0),
      FILE_MODE,
    );
    fs.fchmodSync(descriptor, FILE_MODE);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  syncDirectory(path.dirname(target));
}

function databaseConnection(databasePath) {
  const database = new DatabaseSync(databasePath, { timeout: 0 });
  database.exec(`PRAGMA busy_timeout = 0;
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = DELETE;
    PRAGMA synchronous = FULL;
    PRAGMA fullfsync = ON;
    PRAGMA trusted_schema = OFF`);
  return database;
}

function transaction(database, operation) {
  database.exec("BEGIN IMMEDIATE");
  try {
    const result = operation();
    database.exec("COMMIT");
    return result;
  } catch (error) {
    try {
      database.exec("ROLLBACK");
    } catch {
      // Preserve the authority error.
    }
    throw error;
  }
}

function validateDatabaseSchema(database) {
  const integrity = database.prepare("PRAGMA integrity_check").get();
  if (!integrity || Object.values(integrity)[0] !== "ok") fail("campaign head authority SQLite integrity check failed");
  if (database.prepare("PRAGMA foreign_key_check").all().length !== 0) {
    fail("campaign head authority SQLite foreign-key check failed");
  }
  if (!isDeepStrictEqual(schemaObjects(database), EXPECTED_SCHEMA_OBJECTS)) {
    fail("campaign head authority SQLite schema definition is invalid");
  }
}

function authorityMeta(database) {
  const rows = database.prepare(`SELECT schema_version, authority_id, admission_mode, created_at
    FROM aionis_campaign_authority_meta ORDER BY singleton`).all();
  if (rows.length !== 1) fail("campaign head authority metadata singleton is invalid");
  const value = { ...rows[0] };
  if (value.schema_version !== AUTHORITY_SCHEMA
    || !AUTHORITY_ID_RE.test(value.authority_id ?? "")
    || value.admission_mode !== ADMISSION_MODE) {
    fail("campaign head authority metadata is invalid");
  }
  isoTimestamp(value.created_at, "campaign head authority created_at");
  return value;
}

function initializeDatabase(database) {
  const tables = database.prepare(`SELECT name FROM sqlite_schema
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`).all();
  if (tables.length !== 0) fail("campaign head authority database was partially initialized");
  const metadata = {
    schema_version: AUTHORITY_SCHEMA,
    authority_id: `authority-${randomBytes(32).toString("hex")}`,
    admission_mode: ADMISSION_MODE,
    created_at: new Date().toISOString(),
  };
  transaction(database, () => {
    database.exec(SCHEMA_SQL);
    database.prepare(`INSERT INTO aionis_campaign_authority_meta
      (singleton, schema_version, authority_id, admission_mode, created_at) VALUES (1, ?, ?, ?, ?)`).run(
      metadata.schema_version,
      metadata.authority_id,
      metadata.admission_mode,
      metadata.created_at,
    );
  });
  return metadata;
}

function verifyAuthorityLayout(paths) {
  const rootStat = ensurePrivateDirectory(paths.root, "campaign head authority directory");
  const journalStat = ensurePrivateDirectory(paths.journal, "campaign head journal directory");
  const runClaimsStat = ensurePrivateDirectory(paths.runClaims, "campaign run-claims directory");
  const campaignClaimsStat = ensurePrivateDirectory(paths.campaignClaims, "campaign identity-claims directory");
  const headsStat = ensurePrivateDirectory(paths.heads, "campaign heads directory");
  const projectionAcksStat = ensurePrivateDirectory(paths.projectionAcks, "campaign projection-acks directory");
  const databaseStat = assertPrivateFile(paths.database, "campaign head authority database");
  const lockStat = assertPrivateFile(paths.lock, "campaign head authority lock");
  return {
    root: identity(rootStat),
    journal: identity(journalStat),
    runClaims: identity(runClaimsStat),
    campaignClaims: identity(campaignClaimsStat),
    heads: identity(headsStat),
    projectionAcks: identity(projectionAcksStat),
    database: identity(databaseStat),
    lock: identity(lockStat),
  };
}

function assertAuthorityIdentity(state) {
  const current = verifyAuthorityLayout(state.paths);
  for (const key of Object.keys(state.identities)) {
    if (!isDeepStrictEqual(current[key], state.identities[key])) {
      fail(`campaign head authority ${key} identity changed`);
    }
  }
}

function makeHandle(paths, identities, metadata) {
  const handle = Object.freeze({
    schemaVersion: AUTHORITY_SCHEMA,
    authorityId: metadata.authority_id,
  });
  HANDLE_STATE.set(handle, { paths, identities, metadata: clone(metadata) });
  return handle;
}

export function provisionCampaignHeadAuthority({ directory }) {
  let paths = authorityPaths(directory);
  ensurePrivateDirectory(paths.root, "campaign head authority directory", { create: true, parent: path.dirname(paths.root) });
  paths = authorityPaths(paths.root);
  ensurePrivateDirectory(paths.journal, "campaign head journal directory", { create: true, parent: paths.root });
  ensurePrivateDirectory(paths.runClaims, "campaign run-claims directory", { create: true, parent: paths.journal });
  ensurePrivateDirectory(paths.campaignClaims, "campaign identity-claims directory", { create: true, parent: paths.journal });
  ensurePrivateDirectory(paths.heads, "campaign heads directory", { create: true, parent: paths.journal });
  ensurePrivateDirectory(paths.projectionAcks, "campaign projection-acks directory", { create: true, parent: paths.journal });
  const lock = acquireExclusiveLock(paths.lock);
  let database;
  try {
    if (!lstatIfPresent(paths.database)) createPrivateFile(paths.database);
    assertPrivateFile(paths.database, "campaign head authority database");
    database = databaseConnection(paths.database);
    const existing = database.prepare(`SELECT name FROM sqlite_schema
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`).all();
    if (existing.length === 0) initializeDatabase(database);
    validateDatabaseSchema(database);
    authorityMeta(database);
  } finally {
    if (database) database.close();
    lock.release();
  }
  return openCampaignHeadAuthority({ directory: paths.root });
}

export function openCampaignHeadAuthority({ directory }) {
  const paths = authorityPaths(directory);
  const before = verifyAuthorityLayout(paths);
  const lock = acquireExclusiveLock(paths.lock);
  let database;
  let metadata;
  try {
    database = databaseConnection(paths.database);
    validateDatabaseSchema(database);
    metadata = authorityMeta(database);
  } finally {
    if (database) database.close();
    lock.release();
  }
  const identities = verifyAuthorityLayout(paths);
  if (!isDeepStrictEqual(before, identities)) fail("campaign head authority identity changed while opening");
  return makeHandle(paths, identities, metadata);
}

export function campaignHeadAuthorityInfo(authority) {
  const state = HANDLE_STATE.get(authority);
  if (!state) throw new TypeError("authority was not returned by provisionCampaignHeadAuthority/openCampaignHeadAuthority");
  return Object.freeze({
    schema_version: AUTHORITY_SCHEMA,
    authority_id: state.metadata.authority_id,
    admission_mode: state.metadata.admission_mode,
    directory: state.paths.root,
  });
}

function pathContains(parent, child) {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function campaignRootIdentity(authorityState, campaignRoot) {
  const requested = path.resolve(nonEmptyString(campaignRoot, "campaign root"));
  const rootStat = ensurePrivateDirectory(requested, "campaign root");
  const real = fs.realpathSync(requested);
  const realStat = fs.statSync(real, { bigint: true });
  if (!realStat.isDirectory()) fail("campaign root realpath must resolve to a directory");
  assertTrustedOwner(realStat, "campaign root");
  if (pathContains(authorityState.paths.root, real) || pathContains(real, authorityState.paths.root)) {
    fail("campaign root and protected authority root must be disjoint directory trees");
  }
  const value = {
    root: real,
    dev: String(realStat.dev),
    ino: String(realStat.ino),
  };
  value.ledger_instance_id = sha256(Buffer.from(canonical({
    schema_version: "aionis_campaign_ledger_instance_v1",
    ledger_root: value.root,
    ledger_root_dev: value.dev,
    ledger_root_ino: value.ino,
  })));
  if (!sameIdentity(rootStat, { dev: value.dev, ino: value.ino })) {
    fail("campaign root pathname and realpath identity differ");
  }
  return value;
}

function sessionState(session) {
  const state = SESSION_STATE.get(session);
  if (!state || !state.active) throw new TypeError("campaign head authority session is not active");
  return state;
}

export function assertCampaignHeadSessionIdentity(session) {
  const state = sessionState(session);
  assertAuthorityIdentity(state.authority);
  const current = campaignRootIdentity(state.authority, state.campaign.root);
  if (!isDeepStrictEqual(current, state.campaign)) fail("campaign root identity changed while authority session was active");
  return true;
}

export function withCampaignHeadAuthority(authority, { campaignRoot }, operation) {
  const authorityState = HANDLE_STATE.get(authority);
  if (!authorityState) throw new TypeError("authority was not returned by provisionCampaignHeadAuthority/openCampaignHeadAuthority");
  if (typeof operation !== "function") throw new TypeError("campaign head authority operation must be a function");
  if (operation.constructor?.name === "AsyncFunction") {
    throw new TypeError("campaign head authority operation must be synchronous");
  }
  assertAuthorityIdentity(authorityState);
  const authorityLock = acquireExclusiveLock(authorityState.paths.lock);
  let database;
  const session = Object.freeze({ authorityId: authorityState.metadata.authority_id });
  try {
    assertAuthorityIdentity(authorityState);
    database = databaseConnection(authorityState.paths.database);
    validateDatabaseSchema(database);
    const metadata = authorityMeta(database);
    if (!isDeepStrictEqual(metadata, authorityState.metadata)) fail("campaign head authority metadata changed");
    reconcilePendingJson(authorityState.paths.runClaims);
    reconcilePendingJson(authorityState.paths.campaignClaims);
    const campaign = campaignRootIdentity(authorityState, campaignRoot);
    SESSION_STATE.set(session, {
      active: true,
      authority: authorityState,
      database,
      campaign,
      cachedCampaign: null,
      pendingIndex: null,
    });
    reconcileClaimIndexes(SESSION_STATE.get(session));
    const result = operation(session);
    if (result && (typeof result === "object" || typeof result === "function")
      && typeof result.then === "function") {
      throw new TypeError("campaign head authority operation must not return a promise or thenable");
    }
    assertCampaignHeadSessionIdentity(session);
    return result;
  } finally {
    const state = SESSION_STATE.get(session);
    if (state) state.active = false;
    if (database) database.close();
    authorityLock.release();
  }
}

function normalizeRunScope(value) {
  exactKeys(value, ["repository", "run_id", "run_attempt", "head_sha", "phase", "job", "environment"], "campaign run scope");
  if (!/^[-0-9A-Za-z_.]+\/[-0-9A-Za-z_.]+$/u.test(value.repository ?? "")) fail("campaign run scope repository is invalid");
  safeInteger(value.run_id, "campaign run scope run_id", 1);
  safeInteger(value.run_attempt, "campaign run scope run_attempt", 1);
  if (!COMMIT_RE.test(value.head_sha ?? "")) fail("campaign run scope head_sha is invalid");
  for (const key of ["phase", "job", "environment"]) nonEmptyString(value[key], `campaign run scope ${key}`);
  return clone(value);
}

function runScopeBinding(runScope) {
  const source = normalizeRunScope(runScope);
  const json = canonical(source);
  const series = {
    repository: source.repository,
    run_id: source.run_id,
  };
  return {
    source,
    json,
    id: `run-${sha256(Buffer.from(canonical({ schema_version: RUN_SCOPE_SCHEMA, series })))}`,
  };
}

function claimCommon(state, campaignId, runScope, generation, createdAt) {
  return {
    authority_id: state.authority.metadata.authority_id,
    campaign_id: campaignId,
    run_scope_id: runScope.id,
    generation,
    ledger_root: state.campaign.root,
    ledger_root_dev: state.campaign.dev,
    ledger_root_ino: state.campaign.ino,
    ledger_instance_id: state.campaign.ledger_instance_id,
    run_scope: clone(runScope.source),
    created_at: createdAt,
  };
}

function claimPath(paths, kind, id) {
  if (kind === "run") return path.join(paths.runClaims, `${id}.json`);
  return path.join(paths.campaignClaims, `${id}.json`);
}

function reconcilePendingJson(directory) {
  let changed = false;
  for (const name of fs.readdirSync(directory)) {
    if (!name.startsWith(".aionis-json-")) continue;
    if (!PENDING_JSON_RE.test(name)) fail(`campaign authority pending JSON name is invalid: ${name}`);
    const target = path.join(directory, name);
    const stat = fs.lstatSync(target, { bigint: true });
    if (stat.isSymbolicLink() || !stat.isFile() || Number(stat.nlink) < 1 || Number(stat.nlink) > 2) {
      fail(`campaign authority pending JSON is not a recoverable staging file: ${name}`);
    }
    assertTrustedOwner(stat, "campaign authority pending JSON");
    const mode = Number(stat.mode & 0o777n);
    if (mode !== FILE_MODE && mode !== IMMUTABLE_FILE_MODE) {
      fail(`campaign authority pending JSON permissions are invalid: ${name}`);
    }
    fs.unlinkSync(target);
    changed = true;
  }
  if (changed) syncDirectory(directory);
}

function writeExclusiveJson(target, value, field) {
  const source = `${JSON.stringify(value, null, 2)}\n`;
  const bytes = Buffer.from(source);
  if (bytes.length < 1 || bytes.length > MAX_RECORD_BYTES) fail(`${field} size is invalid`);
  const directory = path.dirname(target);
  reconcilePendingJson(directory);
  const temporary = path.join(
    directory,
    `.aionis-json-${process.pid}-${randomBytes(16).toString("hex")}.pending`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW ?? 0),
      FILE_MODE,
    );
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, IMMUTABLE_FILE_MODE);
    fs.fsyncSync(descriptor);
    exactMode(fs.fstatSync(descriptor), IMMUTABLE_FILE_MODE, field);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.linkSync(temporary, target);
    syncDirectory(directory);
    fs.unlinkSync(temporary);
    syncDirectory(directory);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (lstatIfPresent(temporary)) {
      fs.unlinkSync(temporary);
      syncDirectory(directory);
    }
  }
  return bytes.length;
}

function readStrictJsonFile(target, field) {
  let descriptor;
  let source;
  let openedStat;
  try {
    descriptor = fs.openSync(
      target,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    openedStat = fs.fstatSync(descriptor, { bigint: true });
    assertPrivateFileStat(openedStat, field, IMMUTABLE_FILE_MODE);
    if (openedStat.size < 1n || openedStat.size > BigInt(MAX_RECORD_BYTES)) fail(`${field} size is invalid`);
    source = fs.readFileSync(descriptor, "utf8");
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    assertPrivateFileStat(afterRead, field, IMMUTABLE_FILE_MODE);
    if (!isDeepStrictEqual(identity(afterRead), identity(openedStat)) || afterRead.size !== openedStat.size) {
      fail(`${field} identity or size changed while it was read`);
    }
    const pathnameStat = fs.lstatSync(target, { bigint: true });
    assertPrivateFileStat(pathnameStat, field, IMMUTABLE_FILE_MODE);
    if (!isDeepStrictEqual(identity(pathnameStat), identity(openedStat))) {
      fail(`${field} pathname changed while it was read`);
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    fail(`${field} is not valid JSON: ${error.message}`);
  }
  if (source !== `${JSON.stringify(value, null, 2)}\n`) fail(`${field} is not canonical JSON`);
  return { value, bytes: Number(openedStat.size) };
}

function validateClaim(value, schema, field) {
  exactKeys(value, [
    "schema_version",
    "authority_id",
    "campaign_id",
    "run_scope_id",
    "generation",
    "ledger_root",
    "ledger_root_dev",
    "ledger_root_ino",
    "ledger_instance_id",
    "run_scope",
    "created_at",
  ], field);
  if (value.schema_version !== schema || !AUTHORITY_ID_RE.test(value.authority_id ?? "")) fail(`${field} schema/authority is invalid`);
  if (!CAMPAIGN_ID_RE.test(value.campaign_id ?? "") || !RUN_SCOPE_ID_RE.test(value.run_scope_id ?? "")) fail(`${field} identity is invalid`);
  if (!GENERATION_RE.test(value.generation ?? "") || !DIGEST_RE.test(value.ledger_instance_id ?? "")) fail(`${field} generation/ledger identity is invalid`);
  for (const key of ["ledger_root", "ledger_root_dev", "ledger_root_ino"]) nonEmptyString(value[key], `${field}.${key}`);
  const runScope = runScopeBinding(value.run_scope);
  if (runScope.id !== value.run_scope_id) fail(`${field} run scope digest is invalid`);
  isoTimestamp(value.created_at, `${field}.created_at`);
  return value;
}

function claimValue(schema, common) {
  return { schema_version: schema, ...clone(common) };
}

function claimCommonValue(claim) {
  const { schema_version: ignored, ...common } = claim;
  void ignored;
  return common;
}

function readClaimIfPresent(target, schema, field) {
  if (!lstatIfPresent(target)) return null;
  return validateClaim(readStrictJsonFile(target, field).value, schema, field);
}

function instanceRow(database, campaignId) {
  const row = database.prepare(`SELECT campaign_id, run_scope_id, generation, ledger_root,
    ledger_root_dev, ledger_root_ino, ledger_instance_id, run_scope_json, created_at
    FROM aionis_campaign_instances WHERE campaign_id = ?`).get(campaignId);
  return row ? { ...row } : null;
}

function instanceByRoot(database, ledgerRoot) {
  const row = database.prepare(`SELECT campaign_id, run_scope_id, generation, ledger_root,
    ledger_root_dev, ledger_root_ino, ledger_instance_id, run_scope_json, created_at
    FROM aionis_campaign_instances WHERE ledger_root = ?`).get(ledgerRoot);
  return row ? { ...row } : null;
}

function commonFromInstance(row) {
  let runScope;
  try {
    runScope = JSON.parse(row.run_scope_json);
  } catch (error) {
    fail(`campaign authority run scope is invalid JSON: ${error.message}`);
  }
  return {
    authority_id: null,
    campaign_id: row.campaign_id,
    run_scope_id: row.run_scope_id,
    generation: row.generation,
    ledger_root: row.ledger_root,
    ledger_root_dev: row.ledger_root_dev,
    ledger_root_ino: row.ledger_root_ino,
    ledger_instance_id: row.ledger_instance_id,
    run_scope: runScope,
    created_at: row.created_at,
  };
}

function insertInstance(database, common) {
  database.prepare(`INSERT INTO aionis_campaign_instances
    (campaign_id, run_scope_id, generation, ledger_root, ledger_root_dev, ledger_root_ino,
      ledger_instance_id, run_scope_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    common.campaign_id,
    common.run_scope_id,
    common.generation,
    common.ledger_root,
    common.ledger_root_dev,
    common.ledger_root_ino,
    common.ledger_instance_id,
    canonical(common.run_scope),
    common.created_at,
  );
}

function runClaimRow(database, runScopeId) {
  const row = database.prepare(`SELECT run_scope_id, campaign_id, generation, ledger_root,
    ledger_root_dev, ledger_root_ino, ledger_instance_id, run_scope_json, created_at
    FROM aionis_campaign_run_claims WHERE run_scope_id = ?`).get(runScopeId);
  return row ? { ...row } : null;
}

function insertRunClaim(database, common) {
  database.prepare(`INSERT INTO aionis_campaign_run_claims
    (run_scope_id, campaign_id, generation, ledger_root, ledger_root_dev, ledger_root_ino,
      ledger_instance_id, run_scope_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    common.run_scope_id,
    common.campaign_id,
    common.generation,
    common.ledger_root,
    common.ledger_root_dev,
    common.ledger_root_ino,
    common.ledger_instance_id,
    canonical(common.run_scope),
    common.created_at,
  );
}

function commonFromRunClaimRow(state, row) {
  if (!row) fail("campaign run claim is missing from the SQLite authority index");
  let runScope;
  try {
    runScope = JSON.parse(row.run_scope_json);
  } catch (error) {
    fail(`campaign run claim scope is invalid JSON: ${error.message}`);
  }
  const scope = runScopeBinding(runScope);
  const common = {
    authority_id: state.authority.metadata.authority_id,
    campaign_id: row.campaign_id,
    run_scope_id: row.run_scope_id,
    generation: row.generation,
    ledger_root: row.ledger_root,
    ledger_root_dev: row.ledger_root_dev,
    ledger_root_ino: row.ledger_root_ino,
    ledger_instance_id: row.ledger_instance_id,
    run_scope: scope.source,
    created_at: row.created_at,
  };
  if (scope.id !== row.run_scope_id) fail("campaign SQLite run claim digest is invalid");
  isoTimestamp(row.created_at, "campaign SQLite run claim created_at");
  return common;
}

function readClaimDirectory(state, kind) {
  const isRun = kind === "run";
  const directory = isRun ? state.authority.paths.runClaims : state.authority.paths.campaignClaims;
  const schema = isRun ? RUN_CLAIM_SCHEMA : CAMPAIGN_CLAIM_SCHEMA;
  const idPattern = isRun ? RUN_SCOPE_ID_RE : CAMPAIGN_ID_RE;
  const claims = [];
  reconcilePendingJson(directory);
  for (const name of fs.readdirSync(directory).sort()) {
    if (!name.endsWith(".json")) fail(`campaign ${kind} claim file name is invalid: ${name}`);
    const id = name.slice(0, -5);
    if (!idPattern.test(id)) fail(`campaign ${kind} claim file name is invalid: ${name}`);
    const claim = validateClaim(
      readStrictJsonFile(path.join(directory, name), `campaign ${kind} claim`).value,
      schema,
      `campaign ${kind} claim`,
    );
    const claimId = isRun ? claim.run_scope_id : claim.campaign_id;
    if (claimId !== id || claim.authority_id !== state.authority.metadata.authority_id) {
      fail(`campaign ${kind} claim pathname or authority binding is invalid`);
    }
    claims.push(claim);
  }
  return claims;
}

function sameCampaignBinding(left, right) {
  return [
    "authority_id",
    "campaign_id",
    "generation",
    "ledger_root",
    "ledger_root_dev",
    "ledger_root_ino",
    "ledger_instance_id",
  ].every((key) => left[key] === right[key]);
}

function reconcileClaimIndexes(state) {
  const runClaims = readClaimDirectory(state, "run");
  let campaignClaims = readClaimDirectory(state, "campaign");
  let campaigns = new Map(campaignClaims.map((claim) => [claim.campaign_id, claim]));
  const runs = new Map(runClaims.map((claim) => [claim.run_scope_id, claim]));

  for (const [campaignId, claims] of Map.groupBy(runClaims, (claim) => claim.campaign_id)) {
    if (campaigns.has(campaignId)) continue;
    if (instanceRow(state.database, campaignId) || claims.length !== 1 || claims[0].run_scope.phase !== "pilot") {
      fail("campaign run claim lacks a recoverable immutable identity claim");
    }
    writeExclusiveJson(
      claimPath(state.authority.paths, "campaign", campaignId),
      claimValue(CAMPAIGN_CLAIM_SCHEMA, claimCommonValue(claims[0])),
      "recovered campaign identity claim",
    );
  }
  campaignClaims = readClaimDirectory(state, "campaign");
  campaigns = new Map(campaignClaims.map((claim) => [claim.campaign_id, claim]));

  for (const campaign of campaignClaims) {
    const pilot = runs.get(campaign.run_scope_id);
    if (!pilot || !isDeepStrictEqual(claimCommonValue(pilot), claimCommonValue(campaign))) {
      fail("campaign identity claim is missing its exact pilot run claim");
    }
  }
  for (const claim of runClaims) {
    const campaign = campaigns.get(claim.campaign_id);
    if (!campaign || !sameCampaignBinding(claim, campaign)) {
      fail("campaign actor run claim crosses or lacks its campaign identity claim");
    }
  }

  const indexedCampaigns = state.database.prepare(`SELECT campaign_id, run_scope_id, generation, ledger_root,
    ledger_root_dev, ledger_root_ino, ledger_instance_id, run_scope_json, created_at
    FROM aionis_campaign_instances ORDER BY campaign_id`).all().map((row) => ({ ...row }));
  const indexedRuns = state.database.prepare(`SELECT run_scope_id, campaign_id, generation, ledger_root,
    ledger_root_dev, ledger_root_ino, ledger_instance_id, run_scope_json, created_at
    FROM aionis_campaign_run_claims ORDER BY run_scope_id`).all().map((row) => ({ ...row }));
  if (indexedCampaigns.some((row) => !campaigns.has(row.campaign_id))) {
    fail("campaign SQLite instance exists without an immutable identity claim");
  }
  if (indexedRuns.some((row) => !runs.has(row.run_scope_id))) {
    fail("campaign SQLite run singleton exists without an immutable run claim");
  }

  const missingCampaigns = campaignClaims.filter((claim) => !instanceRow(state.database, claim.campaign_id));
  const missingRuns = runClaims.filter((claim) => !runClaimRow(state.database, claim.run_scope_id));
  for (const claim of campaignClaims) {
    const row = instanceRow(state.database, claim.campaign_id);
    if (row && !isDeepStrictEqual(
      { ...commonFromInstance(row), authority_id: state.authority.metadata.authority_id },
      claimCommonValue(claim),
    )) {
      fail("campaign SQLite instance conflicts with its immutable identity claim");
    }
  }
  for (const claim of runClaims) {
    const row = runClaimRow(state.database, claim.run_scope_id);
    if (row && !isDeepStrictEqual(commonFromRunClaimRow(state, row), claimCommonValue(claim))) {
      fail("campaign SQLite run singleton conflicts with its immutable run claim");
    }
  }
  if (missingCampaigns.length === 0 && missingRuns.length === 0) return;
  transaction(state.database, () => {
    for (const claim of missingCampaigns) insertInstance(state.database, claimCommonValue(claim));
    for (const claim of missingRuns) insertRunClaim(state.database, claimCommonValue(claim));
  });
}

function assertAuthorityNamespaceBijection(state) {
  const campaignClaims = readClaimDirectory(state, "campaign");
  const expectedCampaigns = campaignClaims.map((claim) => claim.campaign_id).sort();
  for (const [root, field] of [
    [state.authority.paths.heads, "campaign head namespace"],
    [state.authority.paths.projectionAcks, "campaign projection-ack namespace"],
  ]) {
    const actualCampaigns = fs.readdirSync(root).sort();
    if (!isDeepStrictEqual(actualCampaigns, expectedCampaigns)) {
      fail(`${field} is not a bijection with immutable campaign claims`);
    }
    for (const claim of campaignClaims) {
      const campaignDirectory = path.join(root, claim.campaign_id);
      ensurePrivateDirectory(campaignDirectory, field);
      const generations = fs.readdirSync(campaignDirectory).sort();
      if (!isDeepStrictEqual(generations, [claim.generation])) {
        fail(`${field} generation is not a bijection with its immutable campaign claim`);
      }
      ensurePrivateDirectory(path.join(campaignDirectory, claim.generation), `${field} generation`);
    }
  }
}

function validateInstance(state, row) {
  if (!row) fail("campaign is not registered in the protected head authority");
  if (!CAMPAIGN_ID_RE.test(row.campaign_id ?? "") || !RUN_SCOPE_ID_RE.test(row.run_scope_id ?? "")
    || !GENERATION_RE.test(row.generation ?? "") || !DIGEST_RE.test(row.ledger_instance_id ?? "")) {
    fail("campaign head authority instance row is malformed");
  }
  const runScope = runScopeBinding(JSON.parse(row.run_scope_json));
  if (runScope.id !== row.run_scope_id) fail("campaign head authority instance run scope is malformed");
  isoTimestamp(row.created_at, "campaign head authority instance created_at");
  const expected = {
    ledger_root: state.campaign.root,
    ledger_root_dev: state.campaign.dev,
    ledger_root_ino: state.campaign.ino,
    ledger_instance_id: state.campaign.ledger_instance_id,
  };
  const actual = {
    ledger_root: row.ledger_root,
    ledger_root_dev: row.ledger_root_dev,
    ledger_root_ino: row.ledger_root_ino,
    ledger_instance_id: row.ledger_instance_id,
  };
  if (!isDeepStrictEqual(actual, expected)) fail("campaign ledger directory replay or identity replacement detected");
  const runClaim = readClaimIfPresent(
    claimPath(state.authority.paths, "run", row.run_scope_id),
    RUN_CLAIM_SCHEMA,
    "campaign run claim",
  );
  const campaignClaim = readClaimIfPresent(
    claimPath(state.authority.paths, "campaign", row.campaign_id),
    CAMPAIGN_CLAIM_SCHEMA,
    "campaign identity claim",
  );
  if (!runClaim || !campaignClaim) fail("campaign protected singleton claim is missing");
  const expectedCommon = {
    ...commonFromInstance(row),
    authority_id: state.authority.metadata.authority_id,
  };
  if (!isDeepStrictEqual(claimCommonValue(runClaim), expectedCommon)
    || !isDeepStrictEqual(claimCommonValue(campaignClaim), expectedCommon)) {
    fail("campaign protected singleton claims do not match the SQLite authority index");
  }
  const indexedRunClaim = commonFromRunClaimRow(state, runClaimRow(state.database, row.run_scope_id));
  if (!isDeepStrictEqual(indexedRunClaim, expectedCommon)) {
    fail("campaign pilot run claim does not match the SQLite authority index");
  }
  return { row, runScope, common: expectedCommon };
}

function validateActorRunClaim(state, runScopeId, campaignCommon) {
  const indexed = commonFromRunClaimRow(state, runClaimRow(state.database, runScopeId));
  for (const key of [
    "authority_id",
    "campaign_id",
    "generation",
    "ledger_root",
    "ledger_root_dev",
    "ledger_root_ino",
    "ledger_instance_id",
  ]) {
    if (indexed[key] !== campaignCommon[key]) fail("campaign head actor run claim crosses campaign authority");
  }
  const file = readClaimIfPresent(
    claimPath(state.authority.paths, "run", runScopeId),
    RUN_CLAIM_SCHEMA,
    "campaign actor run claim",
  );
  if (!file || !isDeepStrictEqual(claimCommonValue(file), indexed)) {
    fail("campaign head actor run claim file/index binding is invalid");
  }
  return indexed;
}

function headBinding(record) {
  return {
    schema_version: HEAD_BINDING_SCHEMA,
    authority_id: record.authority_id,
    campaign_id: record.campaign_id,
    run_scope_id: record.run_scope_id,
    generation: record.generation,
    ledger_instance_id: record.ledger_instance_id,
    revision: record.revision,
    payload_sha256: record.payload_sha256,
    previous_head_sha256: record.previous_head_sha256,
    head_sha256: record.head_sha256,
  };
}

function buildHeadRecord(common, revision, previous, payload, mutation, actorRunScopeId = common.run_scope_id) {
  if (!RUN_SCOPE_ID_RE.test(actorRunScopeId ?? "")) fail("campaign head actor run scope is invalid");
  const payloadSha256 = sha256(Buffer.from(canonical(payload)));
  const base = {
    schema_version: HEAD_RECORD_SCHEMA,
    authority_id: common.authority_id,
    campaign_id: common.campaign_id,
    run_scope_id: common.run_scope_id,
    generation: common.generation,
    ledger_instance_id: common.ledger_instance_id,
    actor_run_scope_id: actorRunScopeId,
    revision,
    previous_head_sha256: previous?.head_sha256 ?? null,
    previous_payload_sha256: previous?.payload_sha256 ?? null,
    payload_sha256: payloadSha256,
    mutation,
  };
  return { ...base, head_sha256: sha256(Buffer.from(canonical(base))) };
}

function headDirectory(paths, campaignId, generation, create = false) {
  const campaignDirectory = path.join(paths.heads, campaignId);
  ensurePrivateDirectory(campaignDirectory, "campaign head namespace", { create, parent: paths.heads });
  const generationDirectory = path.join(campaignDirectory, generation);
  ensurePrivateDirectory(generationDirectory, "campaign generation namespace", { create, parent: campaignDirectory });
  reconcilePendingJson(generationDirectory);
  return generationDirectory;
}

function headFileName(revision, headSha256) {
  return `${String(revision).padStart(16, "0")}-${headSha256}.json`;
}

function projectionAckDirectory(paths, campaignId, generation, create = false) {
  const campaignDirectory = path.join(paths.projectionAcks, campaignId);
  ensurePrivateDirectory(campaignDirectory, "campaign projection-ack namespace", {
    create,
    parent: paths.projectionAcks,
  });
  const generationDirectory = path.join(campaignDirectory, generation);
  ensurePrivateDirectory(generationDirectory, "campaign projection-ack generation namespace", {
    create,
    parent: campaignDirectory,
  });
  reconcilePendingJson(generationDirectory);
  return generationDirectory;
}

function buildProjectionAck(common, head, projectedAt) {
  const base = {
    schema_version: PROJECTION_ACK_SCHEMA,
    authority_id: common.authority_id,
    campaign_id: common.campaign_id,
    generation: common.generation,
    ledger_instance_id: common.ledger_instance_id,
    revision: head.revision,
    payload_sha256: head.payload_sha256,
    head_sha256: head.head_sha256,
    projected_at: projectedAt,
  };
  return { ...base, ack_sha256: sha256(Buffer.from(canonical(base))) };
}

function validateProjectionAck(value, common, head, field) {
  exactKeys(value, [
    "schema_version",
    "authority_id",
    "campaign_id",
    "generation",
    "ledger_instance_id",
    "revision",
    "payload_sha256",
    "head_sha256",
    "projected_at",
    "ack_sha256",
  ], field);
  if (value.schema_version !== PROJECTION_ACK_SCHEMA) fail(`${field} schema is invalid`);
  for (const key of ["authority_id", "campaign_id", "generation", "ledger_instance_id"]) {
    if (value[key] !== common[key]) fail(`${field} ${key} binding is invalid`);
  }
  for (const key of ["revision", "payload_sha256", "head_sha256"]) {
    if (value[key] !== head[key]) fail(`${field} protected-head binding is invalid`);
  }
  isoTimestamp(value.projected_at, `${field}.projected_at`);
  if (!DIGEST_RE.test(value.ack_sha256 ?? "")) fail(`${field} acknowledgement SHA-256 is invalid`);
  const { ack_sha256: ignored, ...base } = value;
  void ignored;
  if (sha256(Buffer.from(canonical(base))) !== value.ack_sha256) {
    fail(`${field} acknowledgement SHA-256 mismatch`);
  }
  return value;
}

function writeProjectionAck(state, common, head, projectedAt) {
  const directory = projectionAckDirectory(
    state.authority.paths,
    common.campaign_id,
    common.generation,
    true,
  );
  const target = path.join(directory, headFileName(head.revision, head.head_sha256));
  const expected = buildProjectionAck(common, head, projectedAt);
  if (lstatIfPresent(target)) {
    const existing = readStrictJsonFile(target, "campaign projection acknowledgement").value;
    validateProjectionAck(existing, common, head, "campaign projection acknowledgement");
    return existing;
  }
  writeExclusiveJson(target, expected, "campaign projection acknowledgement");
  return expected;
}

function validateHeadRecord(value, common, previous, field) {
  exactKeys(value, [
    "schema_version",
    "authority_id",
    "campaign_id",
    "run_scope_id",
    "generation",
    "ledger_instance_id",
    "actor_run_scope_id",
    "revision",
    "previous_head_sha256",
    "previous_payload_sha256",
    "payload_sha256",
    "mutation",
    "head_sha256",
  ], field);
  if (value.schema_version !== HEAD_RECORD_SCHEMA) fail(`${field} schema is invalid`);
  for (const key of ["authority_id", "campaign_id", "run_scope_id", "generation", "ledger_instance_id"]) {
    if (value[key] !== common[key]) fail(`${field} ${key} binding is invalid`);
  }
  if (!RUN_SCOPE_ID_RE.test(value.actor_run_scope_id ?? "")) fail(`${field} actor run scope is invalid`);
  safeInteger(value.revision, `${field}.revision`);
  if (!DIGEST_RE.test(value.payload_sha256 ?? "") || !DIGEST_RE.test(value.head_sha256 ?? "")) {
    fail(`${field} digest is invalid`);
  }
  if (value.revision === 0) {
    if (previous !== null || value.previous_head_sha256 !== null || value.previous_payload_sha256 !== null) {
      fail(`${field} initial predecessor is invalid`);
    }
    exactKeys(value.mutation, ["type", "payload"], `${field}.mutation`);
    if (value.mutation.type !== "initialize") fail(`${field} initial mutation is invalid`);
  } else {
    if (!previous || value.previous_head_sha256 !== previous.record.head_sha256
      || value.previous_payload_sha256 !== previous.record.payload_sha256) {
      fail(`${field} predecessor chain is invalid`);
    }
    exactKeys(value.mutation, ["type", "event"], `${field}.mutation`);
    if (value.mutation.type !== "append_event") fail(`${field} append mutation is invalid`);
  }
  const { head_sha256: ignored, ...base } = value;
  void ignored;
  if (sha256(Buffer.from(canonical(base))) !== value.head_sha256) fail(`${field} head SHA-256 mismatch`);
}

function applyHeadRecord(record, previous, field) {
  let payload;
  if (record.revision === 0) {
    payload = clone(record.mutation.payload);
  } else {
    payload = clone(previous.payload);
    if (!Number.isSafeInteger(payload.revision) || !Array.isArray(payload.events)) {
      fail(`${field} predecessor payload is not appendable`);
    }
    if (record.mutation.event?.revision !== record.revision) fail(`${field} event revision is invalid`);
    payload.revision += 1;
    payload.events.push(clone(record.mutation.event));
  }
  if (payload.revision !== record.revision) fail(`${field} payload revision is invalid`);
  if (sha256(Buffer.from(canonical(payload))) !== record.payload_sha256) fail(`${field} payload SHA-256 mismatch`);
  return payload;
}

function headIndexRow(record, relativePath, bytes, projectedAt = null) {
  return {
    campaign_id: record.campaign_id,
    generation: record.generation,
    revision: record.revision,
    previous_head_sha256: record.previous_head_sha256,
    previous_payload_sha256: record.previous_payload_sha256,
    payload_sha256: record.payload_sha256,
    head_sha256: record.head_sha256,
    journal_relative_path: relativePath,
    journal_bytes: bytes,
    projected_at: projectedAt,
  };
}

function insertHeadIndex(database, row) {
  database.prepare(`INSERT INTO aionis_campaign_head_index
    (campaign_id, generation, revision, previous_head_sha256, previous_payload_sha256,
      payload_sha256, head_sha256, journal_relative_path, journal_bytes, projected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    row.campaign_id,
    row.generation,
    row.revision,
    row.previous_head_sha256,
    row.previous_payload_sha256,
    row.payload_sha256,
    row.head_sha256,
    row.journal_relative_path,
    row.journal_bytes,
    row.projected_at,
  );
}

function headBindingFromIndex(common, row) {
  return {
    schema_version: HEAD_BINDING_SCHEMA,
    authority_id: common.authority_id,
    campaign_id: common.campaign_id,
    run_scope_id: common.run_scope_id,
    generation: common.generation,
    ledger_instance_id: common.ledger_instance_id,
    revision: row.revision,
    payload_sha256: row.payload_sha256,
    previous_head_sha256: row.previous_head_sha256,
    head_sha256: row.head_sha256,
  };
}

function indexedHeadRows(state, common) {
  return state.database.prepare(`SELECT campaign_id, generation, revision,
    previous_head_sha256, previous_payload_sha256, payload_sha256, head_sha256,
    journal_relative_path, journal_bytes, projected_at
    FROM aionis_campaign_head_index WHERE campaign_id = ? AND generation = ? ORDER BY revision`).all(
    common.campaign_id,
    common.generation,
  ).map((row) => ({ ...row }));
}

function validateIndexedSequence(state, common, indexed, headNames, acknowledgementNames, directory) {
  if (indexed.length === 0 || headNames.length !== indexed.length) return false;
  let unprojected = 0;
  for (const [index, row] of indexed.entries()) {
    if (row.campaign_id !== common.campaign_id || row.generation !== common.generation
      || row.revision !== index || !DIGEST_RE.test(row.payload_sha256 ?? "")
      || !DIGEST_RE.test(row.head_sha256 ?? "") || !Number.isSafeInteger(row.journal_bytes)
      || row.journal_bytes < 1) {
      fail(`campaign SQLite head index is malformed at revision ${index}`);
    }
    if (index === 0) {
      if (row.previous_head_sha256 !== null || row.previous_payload_sha256 !== null) {
        fail("campaign SQLite initial head predecessor is invalid");
      }
    } else if (row.previous_head_sha256 !== indexed[index - 1].head_sha256
      || row.previous_payload_sha256 !== indexed[index - 1].payload_sha256) {
      fail(`campaign SQLite head chain is invalid at revision ${index}`);
    }
    const expectedName = headFileName(index, row.head_sha256);
    const expectedRelativePath = path.relative(
      state.authority.paths.root,
      path.join(directory, expectedName),
    ).split(path.sep).join("/");
    if (headNames[index] !== expectedName || row.journal_relative_path !== expectedRelativePath) {
      fail(`campaign SQLite head pathname is invalid at revision ${index}`);
    }
    if (row.projected_at === null) unprojected += 1;
    else isoTimestamp(row.projected_at, `campaign SQLite projected_at revision ${index}`);
  }
  if (unprojected > 1 || (unprojected === 1 && indexed.at(-1).projected_at !== null)) {
    fail("campaign SQLite head index has an unprojected nonterminal revision");
  }
  const projectedCount = indexed.length - unprojected;
  if (acknowledgementNames.length !== projectedCount) {
    return false;
  }
  for (let index = 0; index < acknowledgementNames.length; index += 1) {
    if (acknowledgementNames[index] !== headFileName(index, indexed[index].head_sha256)) {
      return false;
    }
  }
  return true;
}

function fastProtectedCampaignState(state, validatedInstance, projection) {
  if (!projection || typeof projection !== "object") return null;
  const { common } = validatedInstance;
  const directory = headDirectory(state.authority.paths, common.campaign_id, common.generation);
  const acknowledgementDirectory = projectionAckDirectory(
    state.authority.paths,
    common.campaign_id,
    common.generation,
  );
  const headNames = fs.readdirSync(directory).sort();
  const acknowledgementNames = fs.readdirSync(acknowledgementDirectory).sort();
  const indexed = indexedHeadRows(state, common);
  if (indexed.length > headNames.length) fail("campaign SQLite head index is ahead of its immutable journal");
  if (!validateIndexedSequence(state, common, indexed, headNames, acknowledgementNames, directory)) return null;

  const currentRow = indexed.at(-1);
  const currentTarget = path.join(directory, headNames.at(-1));
  const loaded = readStrictJsonFile(currentTarget, `campaign head journal revision ${currentRow.revision}`);
  const previousRecord = currentRow.revision === 0 ? null : {
    record: {
      head_sha256: indexed.at(-2).head_sha256,
      payload_sha256: indexed.at(-2).payload_sha256,
    },
  };
  validateHeadRecord(
    loaded.value,
    common,
    previousRecord,
    `campaign head journal revision ${currentRow.revision}`,
  );
  validateActorRunClaim(state, loaded.value.actor_run_scope_id, common);
  const expectedCurrentRow = headIndexRow(
    loaded.value,
    currentRow.journal_relative_path,
    loaded.bytes,
    currentRow.projected_at,
  );
  if (!isDeepStrictEqual(currentRow, expectedCurrentRow)) {
    fail("campaign SQLite current head does not match its immutable journal record");
  }

  const acknowledgementIndex = acknowledgementNames.length - 1;
  if (acknowledgementIndex >= 0) {
    const acknowledgementRow = indexed[acknowledgementIndex];
    const acknowledgement = readStrictJsonFile(
      path.join(acknowledgementDirectory, acknowledgementNames[acknowledgementIndex]),
      `campaign projection acknowledgement ${acknowledgementIndex}`,
    ).value;
    validateProjectionAck(
      acknowledgement,
      common,
      headBindingFromIndex(common, acknowledgementRow),
      `campaign projection acknowledgement ${acknowledgementIndex}`,
    );
    if (acknowledgement.projected_at !== acknowledgementRow.projected_at) {
      fail("campaign current projection acknowledgement timestamp does not match SQLite");
    }
  }

  const currentHead = headBindingFromIndex(common, currentRow);
  let payload;
  let previousPayload = null;
  const projectionPayloadSha256 = projection.payload && typeof projection.payload === "object"
    ? sha256(Buffer.from(canonical(projection.payload)))
    : null;
  if (isDeepStrictEqual(projection.head, currentHead)
    && projectionPayloadSha256 === currentRow.payload_sha256) {
    payload = clone(projection.payload);
  } else if (currentRow.projected_at === null && currentRow.revision === 0 && projection.head === null) {
    payload = applyHeadRecord(loaded.value, null, "initial campaign head journal");
  } else if (currentRow.projected_at === null && currentRow.revision > 0) {
    const previousRow = indexed.at(-2);
    const previousHead = headBindingFromIndex(common, previousRow);
    if (!isDeepStrictEqual(projection.head, previousHead)
      || projectionPayloadSha256 !== previousRow.payload_sha256) {
      return null;
    }
    previousPayload = clone(projection.payload);
    payload = applyHeadRecord(
      loaded.value,
      { record: { head_sha256: previousRow.head_sha256, payload_sha256: previousRow.payload_sha256 }, payload: previousPayload },
      `campaign head journal revision ${currentRow.revision}`,
    );
  } else {
    return null;
  }
  if (payload.revision !== currentRow.revision || !Array.isArray(payload.events)) {
    fail("campaign protected projection payload is malformed");
  }
  const previousRow = currentRow.revision > 0 ? indexed.at(-2) : null;
  return {
    campaign_id: common.campaign_id,
    run_scope: clone(validatedInstance.runScope.source),
    payload,
    head: currentHead,
    projected_at: currentRow.projected_at,
    previous: previousRow === null ? null : {
      payload: previousPayload,
      head: headBindingFromIndex(common, previousRow),
      projected_at: previousRow.projected_at,
    },
  };
}

function scanHeads(state, validatedInstance) {
  const { common } = validatedInstance;
  const directory = headDirectory(state.authority.paths, common.campaign_id, common.generation);
  const names = fs.readdirSync(directory).sort();
  if (names.length === 0) fail("campaign protected head journal is empty");
  let previous = null;
  const entries = [];
  const validatedActorRuns = new Set();
  for (const [index, name] of names.entries()) {
    if (!/^\d{16}-[a-f0-9]{64}\.json$/u.test(name)) fail(`campaign head journal file name is invalid: ${name}`);
    const target = path.join(directory, name);
    const loaded = readStrictJsonFile(target, `campaign head journal revision ${index}`);
    validateHeadRecord(loaded.value, common, previous, `campaign head journal revision ${index}`);
    if (!validatedActorRuns.has(loaded.value.actor_run_scope_id)) {
      validateActorRunClaim(state, loaded.value.actor_run_scope_id, common);
      validatedActorRuns.add(loaded.value.actor_run_scope_id);
    }
    if (loaded.value.revision !== index || name !== headFileName(index, loaded.value.head_sha256)) {
      fail(`campaign head journal revision ${index} path is invalid`);
    }
    const payload = applyHeadRecord(loaded.value, previous, `campaign head journal revision ${index}`);
    const relativePath = path.relative(state.authority.paths.root, target).split(path.sep).join("/");
    const entry = {
      record: loaded.value,
      payload,
      row: headIndexRow(loaded.value, relativePath, loaded.bytes),
    };
    entries.push(entry);
    previous = entry;
  }

  const acknowledgementDirectory = projectionAckDirectory(
    state.authority.paths,
    common.campaign_id,
    common.generation,
  );
  const acknowledgementNames = fs.readdirSync(acknowledgementDirectory).sort();
  if (acknowledgementNames.length > entries.length) {
    fail("campaign projection acknowledgements are ahead of the immutable head journal");
  }
  for (const [index, name] of acknowledgementNames.entries()) {
    const entry = entries[index];
    if (name !== headFileName(index, entry.record.head_sha256)) {
      fail(`campaign projection acknowledgement path is invalid at revision ${index}`);
    }
    const acknowledgement = readStrictJsonFile(
      path.join(acknowledgementDirectory, name),
      `campaign projection acknowledgement ${index}`,
    ).value;
    validateProjectionAck(
      acknowledgement,
      common,
      headBinding(entry.record),
      `campaign projection acknowledgement ${index}`,
    );
    entry.row.projected_at = acknowledgement.projected_at;
  }
  const unprojected = entries.filter((entry) => entry.row.projected_at === null);
  if (unprojected.length > 1 || (unprojected.length === 1 && unprojected[0] !== entries.at(-1))) {
    fail("campaign protected head journal contains more than one unprojected revision");
  }
  if (entries.slice(0, -1).some((entry) => entry.row.projected_at === null)) {
    fail("campaign protected head journal has an unprojected nonterminal revision");
  }
  const indexed = state.database.prepare(`SELECT campaign_id, generation, revision,
    previous_head_sha256, previous_payload_sha256, payload_sha256, head_sha256,
    journal_relative_path, journal_bytes, projected_at
    FROM aionis_campaign_head_index WHERE campaign_id = ? AND generation = ? ORDER BY revision`).all(
    common.campaign_id,
    common.generation,
  ).map((row) => ({ ...row }));
  if (indexed.length > entries.length) fail("campaign SQLite head index is ahead of its immutable journal");
  const projectionRepairs = [];
  for (let index = 0; index < indexed.length; index += 1) {
    const actual = indexed[index];
    const expected = entries[index].row;
    const { projected_at: actualProjectedAt, ...actualHead } = actual;
    const { projected_at: expectedProjectedAt, ...expectedHead } = expected;
    if (!isDeepStrictEqual(actualHead, expectedHead)) {
      fail(`campaign SQLite head index mismatch at revision ${index}`);
    }
    if (actualProjectedAt === null && expectedProjectedAt !== null) {
      projectionRepairs.push({ revision: index, projectedAt: expectedProjectedAt });
    } else if (actualProjectedAt !== expectedProjectedAt) {
      fail(`campaign SQLite projection acknowledgement mismatch at revision ${index}`);
    }
  }
  if (projectionRepairs.length > 0 || indexed.length < entries.length) {
    transaction(state.database, () => {
      for (const repair of projectionRepairs) {
        const result = state.database.prepare(`UPDATE aionis_campaign_head_index SET projected_at = ?
          WHERE campaign_id = ? AND generation = ? AND revision = ? AND projected_at IS NULL`).run(
          repair.projectedAt,
          common.campaign_id,
          common.generation,
          repair.revision,
        );
        if (result.changes !== 1) fail("campaign projection acknowledgement repair lost authority");
      }
      for (let index = indexed.length; index < entries.length; index += 1) insertHeadIndex(state.database, entries[index].row);
    });
  }
  return entries;
}

function protectedCampaignState(session, projection = null) {
  const state = sessionState(session);
  const row = instanceByRoot(state.database, state.campaign.root);
  const validated = validateInstance(state, row);
  const fast = fastProtectedCampaignState(state, validated, projection);
  if (fast !== null) {
    state.cachedCampaign = clone(fast);
    state.pendingIndex = null;
    return fast;
  }
  const entries = scanHeads(state, validated);
  const current = entries.at(-1);
  const previous = entries.length > 1 ? entries.at(-2) : null;
  const result = {
    campaign_id: row.campaign_id,
    run_scope: clone(validated.runScope.source),
    payload: clone(current.payload),
    head: headBinding(current.record),
    projected_at: current.row.projected_at,
    previous: previous === null ? null : {
      payload: clone(previous.payload),
      head: headBinding(previous.record),
      projected_at: previous.row.projected_at,
    },
  };
  state.cachedCampaign = clone(result);
  state.pendingIndex = null;
  return result;
}

export function registerCampaignHead(session, { campaignId, runScope, initialPayload }) {
  const state = sessionState(session);
  assertCampaignHeadSessionIdentity(session);
  if (!CAMPAIGN_ID_RE.test(campaignId ?? "")) fail("campaign ID is invalid for protected registration");
  const scope = runScopeBinding(runScope);
  if (initialPayload?.campaign_id !== campaignId || initialPayload?.revision !== 0
    || !Array.isArray(initialPayload?.events) || initialPayload.events.length !== 0) {
    fail("protected campaign registration requires the exact revision-zero payload");
  }
  const runTarget = claimPath(state.authority.paths, "run", scope.id);
  const campaignTarget = claimPath(state.authority.paths, "campaign", campaignId);
  const existingRun = readClaimIfPresent(runTarget, RUN_CLAIM_SCHEMA, "campaign run claim");
  const existingCampaign = readClaimIfPresent(campaignTarget, CAMPAIGN_CLAIM_SCHEMA, "campaign identity claim");
  const existingRow = instanceRow(state.database, campaignId);
  if (existingRow && (!existingRun || !existingCampaign)) {
    fail("campaign SQLite singleton exists without both immutable claim files");
  }
  let common;
  let created = false;
  if (existingRun || existingCampaign) {
    const seed = claimCommonValue(existingRun ?? existingCampaign);
    if (existingRun && existingCampaign
      && !isDeepStrictEqual(claimCommonValue(existingRun), claimCommonValue(existingCampaign))) {
      fail("campaign run and campaign singleton claims disagree");
    }
    const expected = claimCommon(
      state,
      campaignId,
      scope,
      seed.generation,
      seed.created_at,
    );
    if (!isDeepStrictEqual(seed, expected)) {
      if (existingRun?.run_scope_id === scope.id) fail("protected run is already bound to another campaign directory or identity");
      fail("deterministic campaign ID is already bound to another protected run or directory");
    }
    common = expected;
  } else {
    common = claimCommon(
      state,
      campaignId,
      scope,
      `generation-${randomBytes(32).toString("hex")}`,
      new Date().toISOString(),
    );
    created = true;
  }
  if (!existingRun) writeExclusiveJson(runTarget, claimValue(RUN_CLAIM_SCHEMA, common), "campaign run claim");
  if (!existingCampaign) {
    writeExclusiveJson(campaignTarget, claimValue(CAMPAIGN_CLAIM_SCHEMA, common), "campaign identity claim");
  }
  const generationDirectory = headDirectory(state.authority.paths, campaignId, common.generation, true);
  projectionAckDirectory(state.authority.paths, campaignId, common.generation, true);
  const initialRecord = buildHeadRecord(
    common,
    0,
    null,
    initialPayload,
    { type: "initialize", payload: clone(initialPayload) },
  );
  const initialTarget = path.join(generationDirectory, headFileName(0, initialRecord.head_sha256));
  let initialBytes;
  if (lstatIfPresent(initialTarget)) {
    const loaded = readStrictJsonFile(initialTarget, "initial campaign head journal");
    if (!isDeepStrictEqual(loaded.value, initialRecord)) fail("initial protected campaign head conflicts with prior creation");
    initialBytes = loaded.bytes;
  } else {
    const other = fs.readdirSync(generationDirectory);
    if (other.length !== 0) fail("campaign generation already contains a conflicting initial head");
    initialBytes = writeExclusiveJson(initialTarget, initialRecord, "initial campaign head journal");
  }
  const relativePath = path.relative(state.authority.paths.root, initialTarget).split(path.sep).join("/");
  transaction(state.database, () => {
    const row = instanceRow(state.database, campaignId);
    if (!row) insertInstance(state.database, common);
    else {
      const indexedCommon = { ...commonFromInstance(row), authority_id: common.authority_id };
      if (!isDeepStrictEqual(indexedCommon, common)) fail("campaign SQLite singleton conflicts with immutable claims");
    }
    const indexedRun = runClaimRow(state.database, common.run_scope_id);
    if (!indexedRun) insertRunClaim(state.database, common);
    else if (!isDeepStrictEqual(commonFromRunClaimRow(state, indexedRun), common)) {
      fail("campaign SQLite run singleton conflicts with immutable claim");
    }
    const head = state.database.prepare(`SELECT campaign_id, generation, revision,
      previous_head_sha256, previous_payload_sha256, payload_sha256, head_sha256,
      journal_relative_path, journal_bytes, projected_at
      FROM aionis_campaign_head_index WHERE campaign_id = ? AND generation = ? AND revision = 0`).get(
      campaignId,
      common.generation,
    );
    const expected = headIndexRow(initialRecord, relativePath, initialBytes);
    if (!head) insertHeadIndex(state.database, expected);
    else if (!isDeepStrictEqual({ ...head }, { ...expected, projected_at: head.projected_at })) {
      fail("campaign SQLite initial head conflicts with immutable journal");
    }
  });
  const current = protectedCampaignState(session);
  if (current.head.revision !== 0 || current.head.payload_sha256 !== initialRecord.payload_sha256) {
    fail("protected campaign registration resolved to a non-initial head");
  }
  return { created, ...current };
}

export function readCampaignHead(session, { projection = null } = {}) {
  assertCampaignHeadSessionIdentity(session);
  const state = sessionState(session);
  return clone(state.cachedCampaign ?? protectedCampaignState(session, projection));
}

export function auditCampaignHeadJournal(session) {
  assertCampaignHeadSessionIdentity(session);
  assertAuthorityNamespaceBijection(sessionState(session));
  return clone(protectedCampaignState(session));
}

export function claimCampaignRun(session, { campaignId, runScope }) {
  const state = sessionState(session);
  assertCampaignHeadSessionIdentity(session);
  const instance = validateInstance(state, instanceRow(state.database, campaignId));
  const scope = runScopeBinding(runScope);
  const target = claimPath(state.authority.paths, "run", scope.id);
  const existingFile = readClaimIfPresent(target, RUN_CLAIM_SCHEMA, "campaign actor run claim");
  const existingRow = runClaimRow(state.database, scope.id);
  if (existingRow && !existingFile) fail("campaign SQLite run claim exists without its immutable claim file");
  const createdAt = existingFile?.created_at ?? new Date().toISOString();
  const common = claimCommon(
    state,
    campaignId,
    scope,
    instance.common.generation,
    createdAt,
  );
  if (existingFile && !isDeepStrictEqual(claimCommonValue(existingFile), common)) {
    fail("protected run series is already bound to another attempt, campaign, or generation");
  }
  if (!existingFile) writeExclusiveJson(target, claimValue(RUN_CLAIM_SCHEMA, common), "campaign actor run claim");
  if (!existingRow) {
    transaction(state.database, () => insertRunClaim(state.database, common));
  } else if (!isDeepStrictEqual(commonFromRunClaimRow(state, existingRow), common)) {
    fail("campaign SQLite run claim conflicts with immutable singleton");
  }
  return Object.freeze({ run_scope_id: scope.id, run_scope: clone(scope.source) });
}

export function appendCampaignHead(session, { expectedHead, actorRunScopeId, event, nextPayload }) {
  const state = sessionState(session);
  assertCampaignHeadSessionIdentity(session);
  const current = clone(state.cachedCampaign ?? protectedCampaignState(session));
  if (current.projected_at === null) fail("campaign cannot append while the current protected head is not projected");
  if (!isDeepStrictEqual(current.head, expectedHead)) fail("campaign protected head CAS mismatch");
  const nextRevision = current.head.revision + 1;
  if (event?.revision !== nextRevision || nextPayload?.revision !== nextRevision) {
    fail("campaign protected append revision is invalid");
  }
  const derived = clone(current.payload);
  derived.revision += 1;
  derived.events.push(clone(event));
  if (!isDeepStrictEqual(derived, nextPayload)) fail("campaign protected append payload is not the exact prior payload plus one event");
  const row = instanceRow(state.database, current.campaign_id);
  const validated = validateInstance(state, row);
  validateActorRunClaim(state, actorRunScopeId, validated.common);
  const record = buildHeadRecord(
    validated.common,
    nextRevision,
    {
      head_sha256: current.head.head_sha256,
      payload_sha256: current.head.payload_sha256,
    },
    nextPayload,
    { type: "append_event", event: clone(event) },
    actorRunScopeId,
  );
  const directory = headDirectory(state.authority.paths, row.campaign_id, row.generation);
  const target = path.join(directory, headFileName(nextRevision, record.head_sha256));
  if (fs.readdirSync(directory).some((name) => name.startsWith(`${String(nextRevision).padStart(16, "0")}-`))) {
    fail("campaign protected revision already exists");
  }
  const bytes = writeExclusiveJson(target, record, `campaign head journal revision ${nextRevision}`);
  const relativePath = path.relative(state.authority.paths.root, target).split(path.sep).join("/");
  const next = {
    campaign_id: current.campaign_id,
    run_scope: clone(current.run_scope),
    payload: clone(nextPayload),
    head: headBinding(record),
    projected_at: null,
    previous: {
      payload: clone(current.payload),
      head: clone(current.head),
      projected_at: current.projected_at,
    },
  };
  state.cachedCampaign = clone(next);
  state.pendingIndex = headIndexRow(record, relativePath, bytes);
  return next;
}

export function markCampaignHeadProjected(session, { head, projectedAt = new Date().toISOString() }) {
  const state = sessionState(session);
  assertCampaignHeadSessionIdentity(session);
  isoTimestamp(projectedAt, "campaign projection timestamp");
  if (state.pendingIndex !== null) {
    if (!isDeepStrictEqual(state.cachedCampaign?.head, head)
      || state.pendingIndex.head_sha256 !== head.head_sha256
      || state.pendingIndex.revision !== head.revision) {
      fail("campaign pending journal index does not match the projected head");
    }
    const validated = validateInstance(state, instanceRow(state.database, head.campaign_id));
    const acknowledgement = writeProjectionAck(state, validated.common, head, projectedAt);
    const row = { ...state.pendingIndex, projected_at: acknowledgement.projected_at };
    transaction(state.database, () => insertHeadIndex(state.database, row));
    state.cachedCampaign.projected_at = acknowledgement.projected_at;
    state.pendingIndex = null;
    return clone(state.cachedCampaign);
  }
  const current = protectedCampaignState(session);
  if (!isDeepStrictEqual(current.head, head)) fail("campaign projection head is not the current protected head");
  if (current.projected_at !== null) return current;
  const validated = validateInstance(state, instanceRow(state.database, head.campaign_id));
  const acknowledgement = writeProjectionAck(state, validated.common, head, projectedAt);
  transaction(state.database, () => {
    const result = state.database.prepare(`UPDATE aionis_campaign_head_index SET projected_at = ?
      WHERE campaign_id = ? AND generation = ? AND revision = ? AND head_sha256 = ? AND projected_at IS NULL`).run(
      acknowledgement.projected_at,
      head.campaign_id,
      head.generation,
      head.revision,
      head.head_sha256,
    );
    if (result.changes !== 1) fail("campaign projection head update lost authority");
  });
  return protectedCampaignState(session);
}
