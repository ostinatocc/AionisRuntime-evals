import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";

import {
  readEvidenceJsonBody,
  validateEvidenceCasRef,
} from "./evidence-cas.mjs";

export const RAW_WORKER_STATE_SCHEMA = "aionis_worker_state_artifact_v1";
export const RECOVERY_EVIDENCE_BOUNDARY_SCHEMA = "aionis_recovery_evidence_boundary_v1";
export const OFFLINE_SQLITE_BOUNDARY_SCHEMA = "aionis_offline_sqlite_boundary_v1";
export const OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER =
  "product_invariant_query_contract_unfrozen";

const DERIVED_WORKER_STATE_SCHEMA = "aionis_worker_state_v2";
const OFFLINE_SQLITE_FACT_SCHEMA = "aionis_offline_sqlite_verify_v2";
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_SQLITE_BYTES = 64 * 1024 * 1024 * 1024;
const SHA256_RE = /^[a-f0-9]{64}$/u;
const IMAGE_DIGEST_RE = /^sha256:[a-f0-9]{64}$/u;
const UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const POSITIVE_DECIMAL_RE = /^[1-9][0-9]*$/u;
const WORKER_CHECKPOINTS = new Set(["pilot", "after_wave_1", "after_wave_2", "after_wave_3"]);
const RECOVERY_KINDS = new Set([
  "none",
  "graceful_replacement",
  "sigkill_replacement",
  "offline_sqlite_verify",
]);
const QUEUE_STATUSES = new Set([
  "completed",
  "dead_letter",
  "provider_mismatch",
  "exhausted",
]);
const PRODUCT_INVARIANTS = Object.freeze([
  "golden_product_loop",
  "product_loop",
  "ordinary_memory_loop",
  "single_agent_loop",
  "multi_agent_loop",
]);
const OPERATION_KINDS = Object.freeze({
  guide: "product_guide_v1",
  outcome: "product_observe_v1",
  feedback: "product_feedback_v1",
  measure: "product_measure_v1",
});
const OPERATION_QUERY = `SELECT tenant_id, scope, operation_kind, operation_id,
       request_sha256, receipt_json, commit_id
FROM lite_runtime_write_operations
WHERE tenant_id = ? AND scope = ? AND operation_kind = ? AND operation_id = ?`;

const recoveryEvidenceValues = new WeakSet();
const offlineInspectionValues = new WeakSet();
const trialResponseEvidence = new WeakMap();

function fail(message) {
  throw new Error(message);
}

function plainObject(value, field) {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) fail(`${field} must be a plain object`);
  return value;
}

function exactKeys(value, keys, field) {
  plainObject(value, field);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (!isDeepStrictEqual(actual, expected)) {
    fail(`${field} keys must be exactly ${expected.join(", ")}; got ${actual.join(", ")}`);
  }
}

function nonEmptyString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || value.includes("\0")) {
    fail(`${field} must be a non-empty trimmed string without NUL`);
  }
  return value;
}

function nullableString(value, field) {
  if (value === null) return null;
  return nonEmptyString(value, field);
}

function safeInteger(value, field, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${field} must be a safe integer greater than or equal to ${minimum}`);
  }
  return value;
}

function sha256Hex(value, field) {
  if (!SHA256_RE.test(value ?? "")) fail(`${field} must be a lowercase SHA-256`);
  return value;
}

function isoTimestamp(value, field) {
  nonEmptyString(value, field);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    fail(`${field} must be a canonical ISO-8601 timestamp`);
  }
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonical(value, field = "canonical JSON") {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail(`${field} contains a non-finite number`);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonical(entry, field)).join(",")}]`;
  plainObject(value, field);
  const keys = Object.keys(value).sort((left, right) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
  );
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key], field)}`).join(",")}}`;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function pointerSegment(value) {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

// JSON.parse silently discards all but the final duplicate object key. Raw
// authority evidence must instead have exactly one interpretation.
class StrictJsonParser {
  constructor(source, field) {
    this.source = source;
    this.field = field;
    this.index = 0;
  }

  parse() {
    this.whitespace();
    const value = this.value("", 0);
    this.whitespace();
    if (this.index !== this.source.length) this.error("contains trailing data");
    return value;
  }

  error(message) {
    fail(`${this.field} ${message} at character ${this.index}`);
  }

  whitespace() {
    while (/^[\u0009\u000a\u000d\u0020]$/u.test(this.source[this.index] ?? "")) this.index += 1;
  }

  value(pointer, depth) {
    if (depth > 128) this.error("exceeds the maximum JSON nesting depth");
    const token = this.source[this.index];
    if (token === "{") return this.object(pointer, depth + 1);
    if (token === "[") return this.array(pointer, depth + 1);
    if (token === '"') return this.string();
    if (token === "t" && this.literal("true")) return true;
    if (token === "f" && this.literal("false")) return false;
    if (token === "n" && this.literal("null")) return null;
    if (token === "-" || (token >= "0" && token <= "9")) return this.number();
    this.error("is not valid JSON");
  }

  literal(expected) {
    if (this.source.slice(this.index, this.index + expected.length) !== expected) return false;
    this.index += expected.length;
    return true;
  }

  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (code < 0x20) this.error("contains an unescaped control character");
      const token = this.source[this.index];
      if (token === '"') {
        this.index += 1;
        try {
          return JSON.parse(this.source.slice(start, this.index));
        } catch (error) {
          this.error(`contains an invalid JSON string (${error.message})`);
        }
      }
      if (token === "\\") {
        this.index += 1;
        const escape = this.source[this.index];
        if (escape === "u") {
          const digits = this.source.slice(this.index + 1, this.index + 5);
          if (!/^[a-fA-F0-9]{4}$/u.test(digits)) this.error("contains an invalid Unicode escape");
          this.index += 5;
          continue;
        }
        if (!/^["\\/bfnrt]$/u.test(escape ?? "")) this.error("contains an invalid escape");
        this.index += 1;
        continue;
      }
      this.index += 1;
    }
    this.error("contains an unterminated string");
  }

  number() {
    const remainder = this.source.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(remainder);
    if (!match) this.error("contains an invalid number");
    this.index += match[0].length;
    const next = this.source[this.index];
    if (next !== undefined && !/^[\u0009\u000a\u000d\u0020,}\]]$/u.test(next)) {
      this.error("contains an invalid number terminator");
    }
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.error("contains a non-finite number");
    return value;
  }

  object(pointer, depth) {
    const value = {};
    const keys = new Set();
    this.index += 1;
    this.whitespace();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return value;
    }
    while (true) {
      if (this.source[this.index] !== '"') this.error("contains a non-string object key");
      const key = this.string();
      if (keys.has(key)) this.error(`contains duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.whitespace();
      if (this.source[this.index] !== ":") this.error("is missing an object colon");
      this.index += 1;
      this.whitespace();
      const child = this.value(`${pointer}/${pointerSegment(key)}`, depth);
      Object.defineProperty(value, key, {
        value: child,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.whitespace();
      const separator = this.source[this.index];
      if (separator === "}") {
        this.index += 1;
        return value;
      }
      if (separator !== ",") this.error("is missing an object separator");
      this.index += 1;
      this.whitespace();
    }
  }

  array(pointer, depth) {
    const value = [];
    this.index += 1;
    this.whitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return value;
    }
    let item = 0;
    while (true) {
      value.push(this.value(`${pointer}/${item}`, depth));
      item += 1;
      this.whitespace();
      const separator = this.source[this.index];
      if (separator === "]") {
        this.index += 1;
        return value;
      }
      if (separator !== ",") this.error("is missing an array separator");
      this.index += 1;
      this.whitespace();
    }
  }
}

function strictJsonBytes(value, field) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail(`${field} must be exact bytes`);
  const bytes = Buffer.from(value);
  if (bytes.length < 1 || bytes.length > MAX_JSON_BYTES) {
    fail(`${field} size must be between 1 byte and 8 MiB`);
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail(`${field} must not contain a UTF-8 BOM`);
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch (error) {
    fail(`${field} must be valid UTF-8: ${error.message}`);
  }
  return {
    bytes,
    sha256: sha256(bytes),
    value: new StrictJsonParser(source, field).parse(),
  };
}

function readStrictCasJson(campaignRoot, ref, field) {
  const normalizedRef = validateEvidenceCasRef(ref);
  const bytes = readEvidenceJsonBody({ campaignRoot, ref: normalizedRef });
  const parsed = strictJsonBytes(bytes, field);
  if (parsed.sha256 !== normalizedRef.sha256 || parsed.bytes.length !== normalizedRef.bytes) {
    fail(`${field} no longer matches its CAS reference`);
  }
  return { ...parsed, ref: normalizedRef };
}

function validateProcess(value, field) {
  exactKeys(value, [
    "boot_id",
    "pid_namespace_inode",
    "pid",
    "process_start_ticks",
    "container_id",
    "runtime_image_digest",
  ], field);
  if (!UUID_RE.test(value.boot_id ?? "")) fail(`${field}.boot_id must be a lowercase UUID`);
  if (!POSITIVE_DECIMAL_RE.test(value.pid_namespace_inode ?? "")) {
    fail(`${field}.pid_namespace_inode must be a positive decimal string`);
  }
  safeInteger(value.pid, `${field}.pid`, 1);
  if (!POSITIVE_DECIMAL_RE.test(value.process_start_ticks ?? "")) {
    fail(`${field}.process_start_ticks must be a positive decimal string`);
  }
  if (value.container_id !== null) sha256Hex(value.container_id, `${field}.container_id`);
  if (!IMAGE_DIGEST_RE.test(value.runtime_image_digest ?? "")) {
    fail(`${field}.runtime_image_digest must be an immutable SHA-256 image digest`);
  }
  return structuredClone(value);
}

function requiredRecord(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${field} must be an object`);
  return value;
}

function nonNegativeHealthInteger(value, field) {
  return safeInteger(value, field, 0);
}

function validateRuntimeHealth(value, field) {
  exactKeys(value, ["http_status", "body"], field);
  safeInteger(value.http_status, `${field}.http_status`, 100);
  const body = requiredRecord(value.body, `${field}.body`);
  const stores = requiredRecord(requiredRecord(body.lite, `${field}.body.lite`).stores, `${field}.body.lite.stores`);
  const write = requiredRecord(stores.write, `${field}.body.lite.stores.write`);
  const projections = requiredRecord(write.projections, `${field}.body.lite.stores.write.projections`);
  const worker = requiredRecord(stores.learning_control_worker, `${field}.body.lite.stores.learning_control_worker`);
  const backlog = requiredRecord(worker.backlog, `${field}.body.lite.stores.learning_control_worker.backlog`);
  const projectionFacts = {
    pending: nonNegativeHealthInteger(projections.pending, `${field}.projections.pending`),
    running: nonNegativeHealthInteger(projections.running, `${field}.projections.running`),
    retry: nonNegativeHealthInteger(projections.retry, `${field}.projections.retry`),
    dead_letter: nonNegativeHealthInteger(projections.dead_letter, `${field}.projections.dead_letter`),
    provider_mismatch: nonNegativeHealthInteger(projections.provider_mismatch, `${field}.projections.provider_mismatch`),
    legacy_pending_unrecoverable: nonNegativeHealthInteger(
      projections.legacy_pending_unrecoverable,
      `${field}.projections.legacy_pending_unrecoverable`,
    ),
  };
  const learningFacts = {
    pending: nonNegativeHealthInteger(backlog.pending, `${field}.backlog.pending`),
    leased: nonNegativeHealthInteger(backlog.leased, `${field}.backlog.leased`),
    expired_leases: nonNegativeHealthInteger(backlog.expired_leases, `${field}.backlog.expired_leases`),
    dead_letter: nonNegativeHealthInteger(backlog.dead_letter, `${field}.backlog.dead_letter`),
    exhausted: nonNegativeHealthInteger(backlog.exhausted, `${field}.backlog.exhausted`),
  };
  const healthy = value.http_status === 200
    && body.ok === true
    && worker.running === true
    && worker.closed === false
    && worker.last_error_code === null;
  return {
    healthy,
    worker_error: worker.last_error_code === null ? 0 : 1,
    terminal_backlog: {
      dead_letter: projectionFacts.dead_letter + learningFacts.dead_letter,
      provider_mismatch: projectionFacts.provider_mismatch,
      exhausted: learningFacts.exhausted,
    },
    undrained: projectionFacts.pending
      + projectionFacts.running
      + projectionFacts.retry
      + projectionFacts.legacy_pending_unrecoverable
      + learningFacts.pending
      + learningFacts.leased
      + learningFacts.expired_leases,
  };
}

function validateQueue(value, expectedTrialIds, field) {
  exactKeys(value, ["entries", "errors"], field);
  if (!Array.isArray(value.entries)) fail(`${field}.entries must be an array`);
  if (!Array.isArray(value.errors)) fail(`${field}.errors must be an array`);
  const entries = value.entries.map((entry, index) => {
    const itemField = `${field}.entries[${index}]`;
    exactKeys(entry, ["trial_id", "status"], itemField);
    nonEmptyString(entry.trial_id, `${itemField}.trial_id`);
    if (!QUEUE_STATUSES.has(entry.status)) fail(`${itemField}.status is not recognized`);
    return structuredClone(entry);
  });
  const sortedEntries = [...entries].sort((left, right) =>
    Buffer.compare(Buffer.from(left.trial_id), Buffer.from(right.trial_id))
  );
  if (!isDeepStrictEqual(entries, sortedEntries)) fail(`${field}.entries must be sorted by trial_id`);
  if (new Set(entries.map((entry) => entry.trial_id)).size !== entries.length) {
    fail(`${field}.entries contains duplicate trial_id values`);
  }
  if (!isDeepStrictEqual(entries.map((entry) => entry.trial_id), expectedTrialIds)) {
    fail(`${field}.entries do not match the ledger-owned terminal trial universe`);
  }
  const errors = value.errors.map((entry, index) => {
    const itemField = `${field}.errors[${index}]`;
    exactKeys(entry, ["error_id", "code", "stage", "occurred_at"], itemField);
    nonEmptyString(entry.error_id, `${itemField}.error_id`);
    nonEmptyString(entry.code, `${itemField}.code`);
    nonEmptyString(entry.stage, `${itemField}.stage`);
    isoTimestamp(entry.occurred_at, `${itemField}.occurred_at`);
    return structuredClone(entry);
  });
  const sortedErrors = [...errors].sort((left, right) =>
    Buffer.compare(Buffer.from(left.error_id), Buffer.from(right.error_id))
  );
  if (!isDeepStrictEqual(errors, sortedErrors)) fail(`${field}.errors must be sorted by error_id`);
  if (new Set(errors.map((entry) => entry.error_id)).size !== errors.length) {
    fail(`${field}.errors contains duplicate error_id values`);
  }
  return {
    terminal_backlog: {
      dead_letter: entries.filter((entry) => entry.status === "dead_letter").length,
      provider_mismatch: entries.filter((entry) => entry.status === "provider_mismatch").length,
      exhausted: entries.filter((entry) => entry.status === "exhausted").length,
    },
    undrained: entries.filter((entry) => entry.status !== "completed").length,
    worker_errors: errors.length,
  };
}

function operationIdentity(value) {
  return [value.tenant_id, value.scope, value.operation_kind, value.operation_id].join("\0");
}

function validateLogicalState(value, expectedOperationIdentities, field) {
  exactKeys(value, ["database_instance_id", "operations"], field);
  sha256Hex(value.database_instance_id, `${field}.database_instance_id`);
  if (!Array.isArray(value.operations)) fail(`${field}.operations must be an array`);
  const operations = value.operations.map((operation, index) => {
    const operationField = `${field}.operations[${index}]`;
    exactKeys(operation, [
      "tenant_id",
      "scope",
      "operation_kind",
      "operation_id",
      "request_sha256",
      "receipt_json",
      "commit_id",
    ], operationField);
    for (const key of ["tenant_id", "scope", "operation_kind", "operation_id"]) {
      nonEmptyString(operation[key], `${operationField}.${key}`);
    }
    sha256Hex(operation.request_sha256, `${operationField}.request_sha256`);
    nullableString(operation.commit_id, `${operationField}.commit_id`);
    if (typeof operation.receipt_json !== "string" || Buffer.byteLength(operation.receipt_json, "utf8") < 1) {
      fail(`${operationField}.receipt_json must contain exact persisted JSON text`);
    }
    strictJsonBytes(Buffer.from(operation.receipt_json, "utf8"), `${operationField}.receipt_json`);
    return structuredClone(operation);
  });
  const sorted = [...operations].sort((left, right) =>
    Buffer.compare(Buffer.from(operationIdentity(left)), Buffer.from(operationIdentity(right)))
  );
  if (!isDeepStrictEqual(operations, sorted)) fail(`${field}.operations must be sorted by persisted identity`);
  if (new Set(operations.map(operationIdentity)).size !== operations.length) {
    fail(`${field}.operations contains a duplicate persisted identity`);
  }
  const identities = operations.map((operation) => ({
    tenant_id: operation.tenant_id,
    scope: operation.scope,
    operation_kind: operation.operation_kind,
    operation_id: operation.operation_id,
  }));
  if (!isDeepStrictEqual(identities, expectedOperationIdentities)) {
    fail(`${field}.operations do not match the ledger-owned persisted operation universe`);
  }
  const normalized = {
    database_instance_id: value.database_instance_id,
    operations,
  };
  return { value: normalized, sha256: sha256(Buffer.from(canonical(normalized), "utf8")) };
}

function addBacklogs(left, right) {
  return {
    dead_letter: left.dead_letter + right.dead_letter,
    provider_mismatch: left.provider_mismatch + right.provider_mismatch,
    exhausted: left.exhausted + right.exhausted,
  };
}

function validateObservation(value, expectedPhase, expected, field) {
  exactKeys(value, [
    "phase",
    "captured_at",
    "process",
    "runtime_health",
    "executor_queue",
    "logical_state",
  ], field);
  if (value.phase !== expectedPhase) fail(`${field}.phase must be ${expectedPhase}`);
  isoTimestamp(value.captured_at, `${field}.captured_at`);
  const processValue = validateProcess(value.process, `${field}.process`);
  if (processValue.runtime_image_digest !== expected.runtime_image_digest) {
    fail(`${field}.process.runtime_image_digest does not match the ledger-owned candidate digest`);
  }
  const health = validateRuntimeHealth(value.runtime_health, `${field}.runtime_health`);
  const queue = validateQueue(
    value.executor_queue,
    expected.terminal_trial_ids,
    `${field}.executor_queue`,
  );
  const state = validateLogicalState(
    value.logical_state,
    expected.persisted_operation_identities,
    `${field}.logical_state`,
  );
  return {
    captured_at: value.captured_at,
    process_sha256: sha256(Buffer.from(canonical(processValue), "utf8")),
    state_sha256: state.sha256,
    terminal_backlog: addBacklogs(health.terminal_backlog, queue.terminal_backlog),
    worker_errors: health.worker_error + queue.worker_errors,
    runtime_healthy: health.healthy,
    queue_undrained: health.undrained + queue.undrained,
  };
}

function validateTransition(value, recovery) {
  exactKeys(value, ["kind", "observed_exit"], "worker state transition");
  if (value.kind !== recovery) fail("worker state transition kind does not match recovery");
  if (recovery === "none" || recovery === "offline_sqlite_verify") {
    if (value.observed_exit !== null) fail(`${recovery} transition must not claim a process exit`);
    return true;
  }
  exactKeys(value.observed_exit, ["exit_code", "signal", "oom_killed", "shutdown_log"], "observed process exit");
  safeInteger(value.observed_exit.exit_code, "observed process exit.exit_code", 0);
  if (value.observed_exit.signal !== null) nonEmptyString(value.observed_exit.signal, "observed process exit.signal");
  if (typeof value.observed_exit.oom_killed !== "boolean") {
    fail("observed process exit.oom_killed must be a boolean from the raw process supervisor record");
  }
  if (typeof value.observed_exit.shutdown_log !== "string") {
    fail("observed process exit.shutdown_log must be exact captured text");
  }
  if (recovery === "graceful_replacement") {
    return value.observed_exit.exit_code === 0
      && value.observed_exit.signal === null
      && value.observed_exit.oom_killed === false
      && value.observed_exit.shutdown_log.includes("draining Runtime before shutdown")
      && !/forcing Runtime shutdown|Runtime graceful shutdown failed/u.test(value.observed_exit.shutdown_log);
  }
  return value.observed_exit.exit_code === 137
    && value.observed_exit.signal === "SIGKILL"
    && value.observed_exit.oom_killed === false;
}

function validateExpectedRecovery(value) {
  exactKeys(value, [
    "checkpoint",
    "source_run_id",
    "source_run_attempt",
    "recovery",
    "runtime_image_digest",
    "terminal_trial_ids",
    "persisted_operation_identities",
  ], "expected recovery binding");
  if (!WORKER_CHECKPOINTS.has(value.checkpoint)) fail("expected recovery checkpoint is not frozen");
  safeInteger(value.source_run_id, "expected recovery source_run_id", 1);
  safeInteger(value.source_run_attempt, "expected recovery source_run_attempt", 1);
  if (!RECOVERY_KINDS.has(value.recovery)) fail("expected recovery kind is not frozen");
  if (!IMAGE_DIGEST_RE.test(value.runtime_image_digest ?? "")) {
    fail("expected recovery runtime_image_digest must be an immutable SHA-256 image digest");
  }
  if (!Array.isArray(value.terminal_trial_ids) || value.terminal_trial_ids.length < 1) {
    fail("expected recovery terminal_trial_ids must be a non-empty array");
  }
  const terminalTrialIds = value.terminal_trial_ids.map((trialId, index) =>
    nonEmptyString(trialId, `expected recovery terminal_trial_ids[${index}]`)
  );
  const sortedTrialIds = [...terminalTrialIds].sort((left, right) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right))
  );
  if (!isDeepStrictEqual(terminalTrialIds, sortedTrialIds)
    || new Set(terminalTrialIds).size !== terminalTrialIds.length) {
    fail("expected recovery terminal_trial_ids must be sorted and unique");
  }
  if (!Array.isArray(value.persisted_operation_identities)
    || value.persisted_operation_identities.length < 1) {
    fail("expected recovery persisted_operation_identities must be a non-empty array");
  }
  const persistedOperationIdentities = value.persisted_operation_identities.map((identity, index) => {
    const field = `expected recovery persisted_operation_identities[${index}]`;
    exactKeys(identity, ["tenant_id", "scope", "operation_kind", "operation_id"], field);
    for (const key of ["tenant_id", "scope", "operation_kind", "operation_id"]) {
      nonEmptyString(identity[key], `${field}.${key}`);
    }
    return structuredClone(identity);
  });
  const sortedOperationIdentities = [...persistedOperationIdentities].sort((left, right) =>
    Buffer.compare(Buffer.from(operationIdentity(left)), Buffer.from(operationIdentity(right)))
  );
  if (!isDeepStrictEqual(persistedOperationIdentities, sortedOperationIdentities)
    || new Set(persistedOperationIdentities.map(operationIdentity)).size !== persistedOperationIdentities.length) {
    fail("expected recovery persisted_operation_identities must be sorted and unique");
  }
  return {
    checkpoint: value.checkpoint,
    source_run_id: value.source_run_id,
    source_run_attempt: value.source_run_attempt,
    recovery: value.recovery,
    runtime_image_digest: value.runtime_image_digest,
    terminal_trial_ids: terminalTrialIds,
    persisted_operation_identities: persistedOperationIdentities,
  };
}

function validatePriorCheckpoint(value) {
  if (value === null) return null;
  exactKeys(value, [
    "schema_version",
    "checkpoint",
    "source_run_id",
    "source_run_attempt",
    "recovery",
    "before_process_id",
    "after_process_id",
    "before_state_sha256",
    "after_state_sha256",
    "terminal_backlog",
    "worker_errors",
    "recorded_at",
  ], "prior recovery checkpoint");
  if (value.schema_version !== DERIVED_WORKER_STATE_SCHEMA) fail("prior recovery checkpoint schema is invalid");
  nonEmptyString(value.after_process_id, "prior recovery checkpoint.after_process_id");
  sha256Hex(value.after_state_sha256, "prior recovery checkpoint.after_state_sha256");
  isoTimestamp(value.recorded_at, "prior recovery checkpoint.recorded_at");
  return structuredClone(value);
}

export function deriveRecoveryCheckpointEvidence(options) {
  exactKeys(options, ["campaignRoot", "workerStateRef", "expected", "priorCheckpoint"], "recovery evidence options");
  const expected = validateExpectedRecovery(options.expected);
  const prior = validatePriorCheckpoint(options.priorCheckpoint);
  const source = readStrictCasJson(options.campaignRoot, options.workerStateRef, "raw worker-state artifact");
  const artifact = source.value;
  exactKeys(artifact, [
    "schema_version",
    "checkpoint",
    "source",
    "recovery",
    "before",
    "transition",
    "after",
  ], "raw worker-state artifact");
  if (artifact.schema_version !== RAW_WORKER_STATE_SCHEMA) fail("raw worker-state artifact schema is invalid");
  exactKeys(artifact.source, ["run_id", "run_attempt"], "raw worker-state source");
  if (!isDeepStrictEqual(
    [artifact.checkpoint, artifact.source.run_id, artifact.source.run_attempt, artifact.recovery],
    [expected.checkpoint, expected.source_run_id, expected.source_run_attempt, expected.recovery],
  )) fail("raw worker-state artifact does not match the ledger-owned recovery binding");

  const before = validateObservation(
    artifact.before,
    "before_recovery",
    expected,
    "raw worker-state before observation",
  );
  const after = validateObservation(
    artifact.after,
    "after_recovery",
    expected,
    "raw worker-state after observation",
  );
  if (Date.parse(after.captured_at) < Date.parse(before.captured_at)) {
    fail("raw worker-state after observation predates its before observation");
  }
  const transitionValid = validateTransition(artifact.transition, expected.recovery);
  const replacementExpected = expected.recovery === "graceful_replacement"
    || expected.recovery === "sigkill_replacement";
  const processTransitionValid = replacementExpected
    ? before.process_sha256 !== after.process_sha256
    : before.process_sha256 === after.process_sha256;
  const statePreserved = before.state_sha256 === after.state_sha256;
  const chainValid = prior === null || (
    before.process_sha256 === prior.after_process_id
    && Date.parse(before.captured_at) >= Date.parse(prior.recorded_at)
  );
  // The checkpoint publishes the terminal (after) snapshot exactly. The before
  // snapshot remains an independent prerequisite so a replacement cannot hide
  // an already-unsafe queue merely by returning an empty new-process view.
  const terminalBacklog = after.terminal_backlog;
  const workerErrors = after.worker_errors;
  const beforeSafe = before.worker_errors === 0
    && Object.values(before.terminal_backlog).every((value) => value === 0);
  const queueDrained = before.queue_undrained === 0 && after.queue_undrained === 0;
  const workerHealthy = before.runtime_healthy && after.runtime_healthy;
  const checkpointPassed = transitionValid
    && processTransitionValid
    && statePreserved
    && chainValid
    && beforeSafe
    && queueDrained
    && workerHealthy
    && workerErrors === 0
    && Object.values(terminalBacklog).every((value) => value === 0);
  const recoveryCheckpoint = {
    schema_version: DERIVED_WORKER_STATE_SCHEMA,
    checkpoint: expected.checkpoint,
    source_run_id: expected.source_run_id,
    source_run_attempt: expected.source_run_attempt,
    recovery: expected.recovery,
    before_process_id: before.process_sha256,
    after_process_id: after.process_sha256,
    before_state_sha256: before.state_sha256,
    after_state_sha256: after.state_sha256,
    terminal_backlog: terminalBacklog,
    worker_errors: workerErrors,
    recorded_at: after.captured_at,
  };
  const derivation = {
    terminal_trial_count: expected.terminal_trial_ids.length,
    persisted_operation_count: expected.persisted_operation_identities.length,
    universe_sha256: sha256(Buffer.from(canonical({
      terminal_trial_ids: expected.terminal_trial_ids,
      persisted_operation_identities: expected.persisted_operation_identities,
    }), "utf8")),
    transition_valid: transitionValid,
    process_transition_valid: processTransitionValid,
    state_preserved: statePreserved,
    prior_chain_valid: chainValid,
    pre_recovery_state_safe: beforeSafe,
    queue_drained: queueDrained,
    runtime_worker_healthy: workerHealthy,
    checkpoint_passed: checkpointPassed,
  };
  const unsigned = {
    schema_version: RECOVERY_EVIDENCE_BOUNDARY_SCHEMA,
    worker_state_ref: source.ref,
    recovery_checkpoint: recoveryCheckpoint,
    derivation,
  };
  const result = deepFreeze({
    ...unsigned,
    facts_sha256: sha256(Buffer.from(canonical(unsigned), "utf8")),
  });
  recoveryEvidenceValues.add(result);
  return result;
}

function mode(stat) {
  return Number(stat.mode & 0o777n);
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sqliteDescriptorPath(descriptor) {
  if (process.platform === "linux") return `/proc/self/fd/${descriptor}`;
  if (process.platform === "darwin" || process.platform === "freebsd") return `/dev/fd/${descriptor}`;
  fail("offline SQLite authority requires a descriptor namespace on Linux, macOS, or FreeBSD");
}

function hashDescriptor(descriptor, byteLength) {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let position = 0;
  while (position < byteLength) {
    const requested = Math.min(buffer.length, byteLength - position);
    const read = fs.readSync(descriptor, buffer, 0, requested, position);
    if (read < 1) fail("SQLite descriptor ended before its frozen byte length");
    hash.update(buffer.subarray(0, read));
    position += read;
  }
  return hash.digest("hex");
}

function assertDatabaseFile(databasePath) {
  nonEmptyString(databasePath, "databasePath");
  const absolute = path.resolve(databasePath);
  const parent = fs.lstatSync(path.dirname(absolute), { bigint: true });
  if (parent.isSymbolicLink() || !parent.isDirectory()) {
    fail("offline SQLite parent must be a real non-symlink directory");
  }
  const pathnameStat = fs.lstatSync(absolute, { bigint: true });
  if (pathnameStat.isSymbolicLink() || !pathnameStat.isFile()) {
    fail("offline SQLite main must be a regular non-symlink file");
  }
  if (mode(pathnameStat) !== 0o600) fail("offline SQLite main permissions must be 600");
  if (typeof process.getuid === "function" && pathnameStat.uid !== BigInt(process.getuid())) {
    fail("offline SQLite main must be owned by the evaluator process UID");
  }
  const size = Number(pathnameStat.size);
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_SQLITE_BYTES) {
    fail("offline SQLite main size must be between 1 byte and 64 GiB");
  }
  for (const suffix of ["-wal", "-shm", "-journal"]) {
    try {
      fs.lstatSync(`${absolute}${suffix}`);
      fail(`offline SQLite main is not quiescent: ${suffix} exists`);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  return { absolute, pathnameStat, size };
}

function pragmaValues(db, pragma, field) {
  const rows = db.prepare(pragma).all();
  const values = rows.flatMap((row) => {
    if (!row || typeof row !== "object" || Array.isArray(row)) return [];
    return Object.values(row);
  });
  if (values.length !== rows.length || values.some((value) => typeof value !== "string")) {
    fail(`${field} returned an invalid SQLite result`);
  }
  return values;
}

function databaseHasTable(db, table) {
  return db.prepare(
    "SELECT 1 AS present FROM sqlite_schema WHERE type = 'table' AND name = ?",
  ).get(table) !== undefined;
}

function validateTrialBindings(campaignRoot, values) {
  if (!Array.isArray(values) || values.length < 1) fail("offline SQLite trialBindings must be a non-empty array");
  const bindings = values.map((value, index) => {
    const field = `offline SQLite trialBindings[${index}]`;
    exactKeys(value, [
      "trial_id",
      "tenant_id",
      "scope",
      "guide_operation_id",
      "outcome_operation_id",
      "feedback_operation_id",
      "measure_operation_id",
      "guide_response_ref",
      "outcome_response_ref",
      "feedback_response_ref",
      "measure_response_ref",
      "measure_replay_response_ref",
    ], field);
    for (const key of [
      "trial_id",
      "tenant_id",
      "scope",
      "guide_operation_id",
      "outcome_operation_id",
      "feedback_operation_id",
      "measure_operation_id",
    ]) nonEmptyString(value[key], `${field}.${key}`);
    const refs = {};
    const responses = {};
    for (const [role, key] of [
      ["guide", "guide_response_ref"],
      ["outcome", "outcome_response_ref"],
      ["feedback", "feedback_response_ref"],
      ["measure", "measure_response_ref"],
      ["measure_replay", "measure_replay_response_ref"],
    ]) {
      const response = readStrictCasJson(campaignRoot, value[key], `${field}.${key}`);
      refs[key] = response.ref;
      responses[role] = response;
    }
    const binding = { ...structuredClone(value), ...refs };
    trialResponseEvidence.set(binding, responses);
    return binding;
  });
  const sorted = [...bindings].sort((left, right) =>
    Buffer.compare(Buffer.from(left.trial_id), Buffer.from(right.trial_id))
  );
  if (!isDeepStrictEqual(bindings, sorted)) fail("offline SQLite trialBindings must be sorted by trial_id");
  if (new Set(bindings.map((binding) => binding.trial_id)).size !== bindings.length) {
    fail("offline SQLite trialBindings contains duplicate trial_id values");
  }
  const operationIds = bindings.flatMap((binding) => [
    binding.guide_operation_id,
    binding.outcome_operation_id,
    binding.feedback_operation_id,
    binding.measure_operation_id,
  ]);
  if (new Set(operationIds).size !== operationIds.length) {
    fail("offline SQLite trialBindings reuses an operation ID");
  }
  return bindings;
}

function validateOfflineExpected(value) {
  exactKeys(value, [
    "source_run_id",
    "source_run_attempt",
    "verified_after_wave",
    "product_invariants",
  ], "offline SQLite expected binding");
  safeInteger(value.source_run_id, "offline SQLite expected source_run_id", 1);
  safeInteger(value.source_run_attempt, "offline SQLite expected source_run_attempt", 1);
  safeInteger(value.verified_after_wave, "offline SQLite expected verified_after_wave", 1);
  if (!isDeepStrictEqual(value.product_invariants, PRODUCT_INVARIANTS)) {
    fail("offline SQLite expected product invariants do not match the frozen workload names");
  }
  return structuredClone(value);
}

function persistedOperation(db, binding, role, responseEvidence) {
  const row = db.prepare(OPERATION_QUERY).get(
    binding.tenant_id,
    binding.scope,
    OPERATION_KINDS[role],
    binding[`${role}_operation_id`],
  );
  if (!row || typeof row !== "object" || Array.isArray(row)) return null;
  const normalized = {
    tenant_id: row.tenant_id,
    scope: row.scope,
    operation_kind: row.operation_kind,
    operation_id: row.operation_id,
    request_sha256: row.request_sha256,
    receipt_json: row.receipt_json,
    commit_id: row.commit_id,
  };
  if (typeof normalized.receipt_json !== "string") fail("persisted Runtime operation receipt_json is invalid");
  const receipt = strictJsonBytes(
    Buffer.from(normalized.receipt_json, "utf8"),
    "persisted Runtime operation receipt_json",
  ).value;
  exactKeys(receipt, ["ok", "statusCode", "body"], "persisted Runtime operation receipt");
  if (receipt.ok !== true || receipt.statusCode !== 200) {
    fail("persisted Runtime operation receipt must be a successful HTTP 200 ProductServiceResult");
  }
  plainObject(receipt.body, "persisted Runtime operation receipt.body");
  if (!SHA256_RE.test(normalized.request_sha256 ?? "")) {
    fail("persisted Runtime operation request_sha256 is invalid");
  }
  return {
    ...normalized,
    receipt_sha256: sha256(Buffer.from(normalized.receipt_json, "utf8")),
    // Runtime persists the complete ProductServiceResult while the HTTP route
    // sends only result.body. Compare their strict JSON values; raw-byte
    // equality is impossible even for a correct real Runtime response.
    response_matches_cas: isDeepStrictEqual(receipt.body, responseEvidence.value),
  };
}

function inspectCampaignPersistence(db, bindings) {
  if (!databaseHasTable(db, "lite_runtime_write_operations")) {
    return {
      aionis_trials_verified: 0,
      exact_replay_rows: 0,
      results: bindings.map((binding) => ({ trial_id: binding.trial_id, operations: null, exact_replay: false })),
    };
  }
  const results = bindings.map((binding) => {
    const responses = trialResponseEvidence.get(binding);
    if (!responses) fail("offline SQLite trial response evidence lost its authority binding");
    const operations = {
      guide: persistedOperation(db, binding, "guide", responses.guide),
      outcome: persistedOperation(db, binding, "outcome", responses.outcome),
      feedback: persistedOperation(db, binding, "feedback", responses.feedback),
      measure: persistedOperation(db, binding, "measure", responses.measure),
    };
    const exactReplay = binding.measure_response_ref.sha256 === binding.measure_replay_response_ref.sha256
      && binding.measure_response_ref.bytes === binding.measure_replay_response_ref.bytes
      && operations.measure?.response_matches_cas === true;
    return {
      trial_id: binding.trial_id,
      operations: Object.fromEntries(Object.entries(operations).map(([role, operation]) => [role, operation === null
        ? null
        : {
            operation_kind: operation.operation_kind,
            operation_id: operation.operation_id,
            request_sha256: operation.request_sha256,
            receipt_sha256: operation.receipt_sha256,
            response_matches_cas: operation.response_matches_cas,
            commit_id: operation.commit_id,
          }])),
      exact_replay: exactReplay,
    };
  });
  return {
    aionis_trials_verified: results.filter((result) =>
      result.operations !== null
      && Object.values(result.operations).every((operation) => operation?.response_matches_cas === true)
    ).length,
    exact_replay_rows: results.filter((result) => result.exact_replay).length,
    results,
  };
}

function assertMainBinding(db, descriptorPath, descriptorStat) {
  const rows = db.prepare("PRAGMA database_list").all();
  const main = rows.filter((row) => row?.name === "main");
  const auxiliariesValid = rows.every((row) => row?.name === "main" || (row?.name === "temp" && row?.file === ""));
  if (!auxiliariesValid || main.length !== 1 || typeof main[0].file !== "string") {
    fail("offline SQLite connection is not bound only to the frozen main descriptor");
  }
  if (main[0].file !== descriptorPath) {
    const reported = fs.statSync(main[0].file, { bigint: true });
    if (reported.dev !== descriptorStat.dev || reported.ino !== descriptorStat.ino) {
      fail("offline SQLite connection main does not match the frozen descriptor");
    }
  }
}

export function inspectOfflineSqliteEvidence(options) {
  exactKeys(options, ["campaignRoot", "databasePath", "expected", "trialBindings"], "offline SQLite options");
  const expected = validateOfflineExpected(options.expected);
  const bindings = validateTrialBindings(options.campaignRoot, options.trialBindings);
  const database = assertDatabaseFile(options.databasePath);
  let descriptor;
  let sqlite;
  try {
    descriptor = fs.openSync(
      database.absolute,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameFile(opened, database.pathnameStat)) {
      fail("offline SQLite main changed while its descriptor was opened");
    }
    if (mode(opened) !== 0o600) fail("offline SQLite descriptor permissions must be 600");
    const firstSha256 = hashDescriptor(descriptor, database.size);
    const descriptorPath = sqliteDescriptorPath(descriptor);
    const location = pathToFileURL(descriptorPath);
    location.searchParams.set("mode", "ro");
    location.searchParams.set("immutable", "1");
    sqlite = new DatabaseSync(location, { readOnly: true });
    sqlite.exec("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF; PRAGMA foreign_keys = ON;");
    assertMainBinding(sqlite, descriptorPath, opened);
    const integrity = pragmaValues(sqlite, "PRAGMA integrity_check", "SQLite integrity_check");
    const quick = pragmaValues(sqlite, "PRAGMA quick_check", "SQLite quick_check");
    const foreignKeyViolations = sqlite.prepare("PRAGMA foreign_key_check").all().length;
    const persistence = inspectCampaignPersistence(sqlite, bindings);
    assertMainBinding(sqlite, descriptorPath, opened);
    sqlite.close();
    sqlite = undefined;

    const afterDescriptor = fs.fstatSync(descriptor, { bigint: true });
    const afterPathname = fs.lstatSync(database.absolute, { bigint: true });
    const secondSha256 = hashDescriptor(descriptor, database.size);
    if (!sameFile(opened, afterDescriptor)
      || !sameFile(opened, afterPathname)
      || firstSha256 !== secondSha256) {
      fail("offline SQLite main changed during authoritative verification");
    }
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      try {
        fs.lstatSync(`${database.absolute}${suffix}`);
        fail(`offline SQLite main became non-quiescent during verification: ${suffix} exists`);
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }

    const persistenceResult = {
      rows: persistence.results,
      aionis_trials_verified: persistence.aionis_trials_verified,
      exact_replay_rows: persistence.exact_replay_rows,
    };
    const operationQueryResultSha256 = sha256(Buffer.from(canonical(persistenceResult), "utf8"));
    const exactReplayResult = persistence.results.map((entry) => ({
      trial_id: entry.trial_id,
      exact_replay: entry.exact_replay,
    }));
    const coreFacts = {
      schema_version: OFFLINE_SQLITE_FACT_SCHEMA,
      source_run_id: expected.source_run_id,
      source_run_attempt: expected.source_run_attempt,
      verified_after_wave: expected.verified_after_wave,
      database_sha256: firstSha256,
      integrity_result: isDeepStrictEqual(integrity, ["ok"]) ? "ok" : canonical(integrity),
      quick_check_result: isDeepStrictEqual(quick, ["ok"]) ? "ok" : canonical(quick),
      aionis_trials_verified: persistence.aionis_trials_verified,
      exact_replay_rows: persistence.exact_replay_rows,
    };
    const inspectionPassed = coreFacts.integrity_result === "ok"
      && coreFacts.quick_check_result === "ok"
      && foreignKeyViolations === 0
      && persistence.aionis_trials_verified === bindings.length
      && persistence.exact_replay_rows === bindings.length;
    const unsigned = {
      schema_version: OFFLINE_SQLITE_BOUNDARY_SCHEMA,
      database: {
        path: database.absolute,
        sha256: firstSha256,
        bytes: database.size,
        mode: "0600",
        device: opened.dev.toString(),
        inode: opened.ino.toString(),
      },
      sqlite_checks: {
        integrity_check: integrity,
        quick_check: quick,
        foreign_key_violation_count: foreignKeyViolations,
      },
      authoritative_queries: [
        {
          name: "campaign_operation_receipts",
          query_sha256: sha256(Buffer.from(OPERATION_QUERY, "utf8")),
          result_sha256: operationQueryResultSha256,
        },
        {
          name: "measure_exact_replay",
          query_sha256: sha256(Buffer.from("measure_response_ref == measure_replay_response_ref == persisted product_measure_v1 receipt", "utf8")),
          result_sha256: sha256(Buffer.from(canonical(exactReplayResult), "utf8")),
        },
      ],
      core_facts: coreFacts,
      product_invariant_authority: {
        status: "unfrozen",
        expected_names: PRODUCT_INVARIANTS,
        blocker: OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER,
      },
      inspection_passed: inspectionPassed,
      admission_ready: false,
      ledger_facts: null,
    };
    const result = deepFreeze({
      ...unsigned,
      facts_sha256: sha256(Buffer.from(canonical(unsigned), "utf8")),
    });
    offlineInspectionValues.add(result);
    return result;
  } finally {
    if (sqlite) sqlite.close();
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

export function assertOfflineSqliteLedgerFacts(value) {
  if (!offlineInspectionValues.has(value)) fail("offline SQLite inspection was not created by this authority boundary");
  if (value.ledger_facts === null || value.admission_ready !== true) {
    fail(`offline SQLite admission is blocked: ${OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER}`);
  }
  return value.ledger_facts;
}

export function assertRecoveryEvidenceBoundary(value) {
  if (!recoveryEvidenceValues.has(value)) fail("recovery evidence was not created by this authority boundary");
  return value;
}
