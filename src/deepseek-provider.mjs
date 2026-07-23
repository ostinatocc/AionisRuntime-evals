import { spawn } from "node:child_process";
import { closeSync, fstatSync, readSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectNonNegativeInteger,
  expectPositiveInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { buildPilotCellV1, verifyPilotCellV1 } from "./pilot-contract.mjs";
import {
  DEEPSEEK_ENDPOINT_V1,
  DEEPSEEK_MODEL_V1,
  DEEPSEEK_REASONING_EFFORT_V1,
  DEEPSEEK_RESPONSE_FORMAT_V1,
  DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1,
  DEEPSEEK_THINKING_MODE_V1,
  deepSeekModelProtocolSha256V1,
  verifyDeepSeekModelProtocolV1,
} from "./deepseek-model-protocol.mjs";
import {
  createNonReleaseProviderContractAuthorityV1,
  reserveProviderAttemptV1,
  snapshotProviderAttemptAuthorityV1,
} from "./pilot-run-ledger.mjs";
import {
  assertReleasePilotCancellationAuthorityV1,
  checkpointReleasePilotCancellationV1,
  releasePilotCancellationSignalV1,
} from "./release-pilot-cancellation.mjs";

export {
  DEEPSEEK_ENDPOINT_V1,
  DEEPSEEK_MODEL_V1,
  DEEPSEEK_REASONING_EFFORT_V1,
  DEEPSEEK_RESPONSE_FORMAT_V1,
  DEEPSEEK_THINKING_MODE_V1,
};
export const DEEPSEEK_REQUEST_TIMEOUT_MS_V1 = 300_000;
export const DEEPSEEK_RESPONSE_BODY_LIMIT_BYTES_V1 = 2_097_152;
export const DEEPSEEK_API_KEY_FD_MIN_BYTES_V1 = 8;
export const DEEPSEEK_API_KEY_FD_MAX_BYTES_V1 = 512;

const modulePath = fileURLToPath(import.meta.url);
const PLATFORM_FETCH_V1 = typeof globalThis.fetch === "function"
  ? globalThis.fetch.bind(globalThis)
  : null;
const PLATFORM_DATE_V1 = Date;
const API_KEY_ATTESTATION_CHILD_MODE = "--deepseek-api-key-attestation-child";
const API_KEY_ATTESTATION_TIMEOUT_MS = 30_000;
const API_KEY_ATTESTATION_OUTPUT_LIMIT_BYTES = 65_536;
const API_KEY_ATTESTATION_SCHEMA_VERSION =
  "aionis_deepseek_api_key_attestation_receipt_v1";
const PROVIDER_CONTRACT_SMOKE_SCHEMA_VERSION =
  "aionis_deepseek_provider_contract_smoke_receipt_v1";
const PROVIDER_CONTRACT_SMOKE_MAX_TOKENS = 8_192;
const PROVIDER_CONTRACT_SMOKE_MARKER = "ok";
const PROVIDER_CONTRACT_SMOKE_MESSAGES = Object.freeze([
  Object.freeze({
    role: "system",
    content: "Return only the requested JSON object, with no markdown or additional keys.",
  }),
  Object.freeze({
    role: "user",
    content:
      'Aionis provider contract smoke. Return exactly {"aionis_provider_contract":"ok"}.',
  }),
]);
const PROVIDER_CONTRACT_SMOKE_TRANSPORT_EVIDENCE_KEYS = Object.freeze([
  "assistant_content_sha256",
  "canonical_request_sha256",
  "failure_class",
  "http_status",
  "outcome",
  "provider_contract_marker_verified",
  "request_receipt_sha256",
  "response_body_sha256",
  "response_receipt_sha256",
]);

const REQUEST_RECEIPT_KEYS = Object.freeze([
  "attempt_ordinal",
  "canonical_request_sha256",
  "cell_ref",
  "endpoint",
  "execution_authorization_sha256",
  "immutable_snapshot",
  "max_tokens",
  "model_protocol_sha256",
  "provider_attempt_reservation_sha256",
  "provider_may_update_weights",
  "provider_request_started_event_sha256",
  "request_receipt_sha256",
  "request_started_at",
  "request_timeout_ms",
  "requested_model",
  "reasoning_effort",
  "response_format",
  "retries",
  "schema_version",
  "thinking_mode",
]);

const RESPONSE_RECEIPT_KEYS = Object.freeze([
  "assistant_content_sha256",
  "attempt_ordinal",
  "canonical_request_sha256",
  "cell_ref",
  "completion_id",
  "failure_class",
  "finish_reason",
  "http_status",
  "outcome",
  "provider_created_unix_seconds",
  "request_receipt_sha256",
  "resolved_model",
  "response_body_sha256",
  "response_object",
  "response_received_at",
  "response_receipt_sha256",
  "schema_version",
  "system_fingerprint",
  "transport_request_id",
  "usage",
]);

const CELL_REF_KEYS = Object.freeze([
  "arm",
  "case_id",
  "case_sha256",
  "cell_sha256",
  "isolation_sha256",
  "opaque_cell_id",
  "ordinal",
  "pilot_id",
]);

const FAILURE_CLASSES = new Set([
  "none",
  "provider_http_status",
  "provider_incomplete_completion",
  "provider_response_limit",
  "provider_response_protocol",
  "provider_transport",
]);

const FINISH_REASONS = new Set([
  "stop",
  "length",
  "content_filter",
  "tool_calls",
  "insufficient_system_resource",
]);

function fail(code) {
  throw new Error(`aionis_eval_deepseek_${code}`);
}

export function assertDeepSeekApiKeyV1(value) {
  return expectText(value, "deepseek_api_key", { maximumBytes: 4_096 });
}

function formalApiKeyFdStat(value) {
  if (!Number.isInteger(value) || value < 3) fail("api_key_fd_invalid");
  let stat;
  try {
    stat = fstatSync(value, { bigint: true });
  } catch {
    fail("api_key_fd_invalid");
  }
  if (!stat.isFile()) fail("api_key_fd_not_regular_file");
  if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) {
    fail("api_key_fd_owner_invalid");
  }
  if (stat.nlink !== 1n) fail("api_key_fd_link_count_invalid");
  const permissionMode = stat.mode & 0o7777n;
  if (permissionMode !== 0o400n && permissionMode !== 0o600n) {
    fail("api_key_fd_mode_invalid");
  }
  if (stat.size < BigInt(DEEPSEEK_API_KEY_FD_MIN_BYTES_V1)
    || stat.size > BigInt(DEEPSEEK_API_KEY_FD_MAX_BYTES_V1)) {
    fail("api_key_fd_size_invalid");
  }
  return stat;
}

function sameApiKeyFdSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

export function assertExistingDeepSeekApiKeyFdV1(value) {
  formalApiKeyFdStat(value);
  return value;
}

/**
 * Reads a formal-run credential from a caller-owned descriptor without moving
 * its file offset or taking ownership of it. The caller must open the source
 * with O_NOFOLLOW: pathname provenance cannot be reconstructed from an FD.
 */
export function readDeepSeekApiKeyFdV1(value) {
  let bytes;
  let overflowProbe;
  try {
    const before = formalApiKeyFdStat(value);
    const length = Number(before.size);
    bytes = Buffer.alloc(length);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(value, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail("api_key_fd_read_incomplete");
      offset += count;
    }
    overflowProbe = Buffer.alloc(1);
    if (readSync(value, overflowProbe, 0, 1, length) !== 0) {
      fail("api_key_fd_size_changed_during_read");
    }
    const after = formalApiKeyFdStat(value);
    if (!sameApiKeyFdSnapshot(before, after)) {
      fail("api_key_fd_changed_during_read");
    }
    let apiKey;
    try {
      apiKey = assertDeepSeekApiKeyV1(bytes.toString("utf8"));
    } catch {
      fail("api_key_fd_content_invalid");
    }
    return apiKey;
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_deepseek_")) throw error;
    fail("api_key_fd_read_invalid");
  } finally {
    overflowProbe?.fill(0);
    bytes?.fill(0);
  }
}

function sparseAttestationEnvironment() {
  return {
    LANG: "C",
    LC_ALL: "C",
    TZ: "UTC",
  };
}

function collectApiKeyAttestationChild(child) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    let settled = false;
    const finish = (error, result = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error === null) resolve(result);
      else reject(error);
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= API_KEY_ATTESTATION_OUTPUT_LIMIT_BYTES) stdout.push(chunk);
      else if (!overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > API_KEY_ATTESTATION_OUTPUT_LIMIT_BYTES && !overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.once("error", () => finish(new Error("api_key_attestation_child_failed")));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, API_KEY_ATTESTATION_TIMEOUT_MS);
    timer.unref?.();
    child.once("close", (exitCode, signal) => finish(null, {
      exitCode,
      overflow,
      signal,
      stdout: Buffer.concat(stdout),
      timedOut,
    }));
  });
}

/**
 * Validates a formal provider credential in a fresh child. The parent never
 * materializes the API key, receives no digest of it, and the positional read
 * leaves the caller-owned descriptor reusable by the real runner.
 */
export async function attestDeepSeekApiKeyFdV1(options) {
  const input = expectExactRecord(options, ["apiKeyFd"], "api_key_attestation_options");
  const apiKeyFd = assertExistingDeepSeekApiKeyFdV1(input.apiKeyFd);
  let child;
  try {
    child = spawn(process.execPath, [modulePath, API_KEY_ATTESTATION_CHILD_MODE], {
      cwd: "/",
      env: sparseAttestationEnvironment(),
      shell: false,
      stdio: ["ignore", "pipe", "pipe", apiKeyFd],
      windowsHide: true,
    });
  } catch {
    fail("api_key_attestation_child_failed");
  }
  let result;
  try { result = await collectApiKeyAttestationChild(child); } catch {
    fail("api_key_attestation_child_failed");
  }
  if (result.exitCode !== 0 || result.signal !== null
    || result.overflow || result.timedOut) fail("api_key_attestation_child_failed");
  let receipt;
  try {
    const text = result.stdout.toString("utf8");
    receipt = JSON.parse(text);
    if (text !== `${canonicalJson(receipt)}\n`) fail("api_key_attestation_output_invalid");
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_deepseek_")) throw error;
    fail("api_key_attestation_output_invalid");
  }
  const verified = expectExactRecord(receipt, [
    "attester_process_id",
    "credential_validated",
    "private_key_transport",
    "schema_version",
  ], "api_key_attestation_receipt");
  if (verified.schema_version !== API_KEY_ATTESTATION_SCHEMA_VERSION
    || verified.attester_process_id !== child.pid
    || verified.credential_validated !== true
    || verified.private_key_transport !== "inherited_fd_3_positional_read_only") {
    fail("api_key_attestation_receipt_invalid");
  }
  return canonicalClone(verified);
}

async function apiKeyAttestationChildMain() {
  if (path.resolve(process.argv[1] ?? "") !== modulePath
    || process.argv[2] !== API_KEY_ATTESTATION_CHILD_MODE) {
    fail("api_key_attestation_child_entrypoint_invalid");
  }
  const apiKey = readDeepSeekApiKeyFdV1(3);
  try { closeSync(3); } catch { /* child exits immediately */ }
  if ([...process.argv, ...Object.entries(process.env).flat()].some((surface) =>
    typeof surface === "string" && surface.includes(apiKey))) {
    fail("api_key_public_surface_exposure");
  }
  process.stdout.write(`${canonicalJson({
    schema_version: API_KEY_ATTESTATION_SCHEMA_VERSION,
    attester_process_id: process.pid,
    credential_validated: true,
    private_key_transport: "inherited_fd_3_positional_read_only",
  })}\n`);
}

function verifySelfHash(value, hashField, field) {
  const expected = expectSha256(value[hashField], `${field}_${hashField}`);
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== hashField),
  );
  if (canonicalSha256(body) !== expected) fail(`${field}_${hashField}_mismatch`);
}

function nullableSha256(value, field) {
  if (value === null) return null;
  return expectSha256(value, field);
}

function nullableText(value, field) {
  if (value === null) return null;
  return expectText(value, field, { maximumBytes: 4_096 });
}

function verifyAttemptOrdinal(value, field) {
  expectPositiveInteger(value, field);
  if (value > DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1) fail(`${field}_invalid`);
  return value;
}

function verifyUsage(value, field) {
  const usage = expectExactRecord(value, [
    "completion_tokens",
    "prompt_cache_hit_tokens",
    "prompt_cache_miss_tokens",
    "prompt_tokens",
    "reasoning_tokens",
    "total_tokens",
  ], field);
  for (const name of Object.keys(usage)) {
    expectNonNegativeInteger(usage[name], `${field}_${name}`);
  }
  if (usage.prompt_tokens
      !== usage.prompt_cache_hit_tokens + usage.prompt_cache_miss_tokens) {
    fail(`${field}_prompt_cache_total_invalid`);
  }
  if (usage.total_tokens !== usage.prompt_tokens + usage.completion_tokens
    || usage.reasoning_tokens > usage.completion_tokens) {
    fail(`${field}_total_invalid`);
  }
  return usage;
}

export function deepSeekPilotCellRefV1(cellValue) {
  const cell = verifyPilotCellV1(cellValue);
  if (cell.ordinal > DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1) {
    fail("cell_ordinal_invalid");
  }
  return canonicalClone({
    pilot_id: cell.pilot_id,
    opaque_cell_id: cell.opaque_cell_id,
    ordinal: cell.ordinal,
    case_id: cell.case_id,
    case_sha256: cell.case_sha256,
    arm: cell.arm,
    isolation_sha256: cell.isolation.isolation_sha256,
    cell_sha256: canonicalSha256(cell),
  });
}

function verifyCellRef(value, cellValue, field) {
  const ref = expectExactRecord(value, CELL_REF_KEYS, field);
  const expected = deepSeekPilotCellRefV1(cellValue);
  if (canonicalJson(ref) !== canonicalJson(expected)) fail(`${field}_binding_mismatch`);
  return ref;
}

export function verifyDeepSeekRequestReceiptV1(value, options) {
  const expected = expectExactRecord(options, [
    "cell", "messages", "modelProtocol",
  ], "request_receipt_verification_options");
  const protocol = verifyDeepSeekModelProtocolV1(expected.modelProtocol);
  const receipt = expectExactRecord(
    value,
    REQUEST_RECEIPT_KEYS,
    "deepseek_request_receipt",
  );
  verifySelfHash(receipt, "request_receipt_sha256", "request_receipt");
  if (receipt.schema_version !== "aionis_deepseek_request_receipt_v1"
    || receipt.endpoint !== DEEPSEEK_ENDPOINT_V1
    || receipt.requested_model !== DEEPSEEK_MODEL_V1
    || receipt.model_protocol_sha256 !== deepSeekModelProtocolSha256V1(protocol)
    || receipt.thinking_mode !== DEEPSEEK_THINKING_MODE_V1
    || receipt.reasoning_effort !== DEEPSEEK_REASONING_EFFORT_V1
    || receipt.response_format !== DEEPSEEK_RESPONSE_FORMAT_V1
    || receipt.max_tokens !== protocol.max_tokens
    || receipt.request_timeout_ms !== DEEPSEEK_REQUEST_TIMEOUT_MS_V1
    || receipt.retries !== 0
    || receipt.immutable_snapshot !== false
    || receipt.provider_may_update_weights !== true) {
    fail("request_receipt_protocol_binding_invalid");
  }
  verifyCellRef(receipt.cell_ref, expected.cell, "request_receipt_cell_ref");
  verifyAttemptOrdinal(receipt.attempt_ordinal, "request_receipt_attempt_ordinal");
  expectSha256(
    receipt.canonical_request_sha256,
    "request_receipt_canonical_request_sha256",
  );
  for (const field of [
    "execution_authorization_sha256",
    "provider_attempt_reservation_sha256",
    "provider_request_started_event_sha256",
  ]) expectSha256(receipt[field], `request_receipt_${field}`);
  if (receipt.canonical_request_sha256
      !== deepSeekCanonicalRequestSha256V1(expected.messages, protocol)) {
    fail("request_receipt_canonical_request_sha256_mismatch");
  }
  expectCanonicalTimestamp(receipt.request_started_at, "request_receipt_started_at");
  return canonicalClone(receipt);
}

export function verifyDeepSeekResponseReceiptV1(value, options) {
  const expected = expectExactRecord(options, [
    "assistantMessage", "cell", "messages", "modelProtocol", "requestReceipt",
  ], "response_receipt_verification_options");
  const requestReceipt = verifyDeepSeekRequestReceiptV1(expected.requestReceipt, {
    cell: expected.cell,
    messages: expected.messages,
    modelProtocol: expected.modelProtocol,
  });
  const receipt = expectExactRecord(
    value,
    RESPONSE_RECEIPT_KEYS,
    "deepseek_response_receipt",
  );
  verifySelfHash(receipt, "response_receipt_sha256", "response_receipt");
  if (receipt.schema_version !== "aionis_deepseek_response_receipt_v1"
    || !new Set(["completed", "inconclusive"]).has(receipt.outcome)
    || !FAILURE_CLASSES.has(receipt.failure_class)
    || receipt.attempt_ordinal !== requestReceipt.attempt_ordinal
    || receipt.canonical_request_sha256 !== requestReceipt.canonical_request_sha256
    || receipt.request_receipt_sha256 !== requestReceipt.request_receipt_sha256) {
    fail("response_receipt_request_binding_invalid");
  }
  verifyCellRef(receipt.cell_ref, expected.cell, "response_receipt_cell_ref");
  verifyAttemptOrdinal(receipt.attempt_ordinal, "response_receipt_attempt_ordinal");
  if (receipt.http_status !== null
    && (!Number.isSafeInteger(receipt.http_status)
      || receipt.http_status < 100 || receipt.http_status > 599)) {
    fail("response_receipt_http_status_invalid");
  }
  nullableSha256(receipt.response_body_sha256, "response_receipt_body_sha256");
  nullableText(receipt.completion_id, "response_receipt_completion_id");
  nullableText(receipt.transport_request_id, "response_receipt_transport_request_id");
  nullableText(receipt.resolved_model, "response_receipt_resolved_model");
  nullableText(receipt.finish_reason, "response_receipt_finish_reason");
  nullableText(receipt.response_object, "response_receipt_object");
  nullableText(receipt.system_fingerprint, "response_receipt_system_fingerprint");
  if (receipt.finish_reason !== null && !FINISH_REASONS.has(receipt.finish_reason)) {
    fail("response_receipt_finish_reason_invalid");
  }
  if (receipt.provider_created_unix_seconds !== null) {
    expectPositiveInteger(
      receipt.provider_created_unix_seconds,
      "response_receipt_provider_created_unix_seconds",
    );
  }
  nullableSha256(receipt.assistant_content_sha256, "response_receipt_content_sha256");
  expectCanonicalTimestamp(receipt.response_received_at, "response_receipt_received_at");
  if (receipt.response_received_at < requestReceipt.request_started_at) {
    fail("response_receipt_temporal_order_invalid");
  }

  if (receipt.outcome === "completed") {
    if (receipt.failure_class !== "none"
      || receipt.http_status === null
      || receipt.http_status < 200 || receipt.http_status >= 300
      || receipt.response_body_sha256 === null
      || receipt.completion_id === null
      || receipt.resolved_model !== DEEPSEEK_MODEL_V1
      || receipt.finish_reason !== "stop"
      || receipt.provider_created_unix_seconds === null
      || receipt.response_object !== "chat.completion"
      || receipt.system_fingerprint === null
      || receipt.assistant_content_sha256 === null
      || receipt.usage === null) {
      fail("response_receipt_completed_evidence_incomplete");
    }
    verifyUsage(receipt.usage, "response_receipt_usage");
    const assistantMessage = verifyAssistantMessage(expected.assistantMessage);
    if (sha256Bytes(Buffer.from(assistantMessage.content, "utf8"))
        !== receipt.assistant_content_sha256) {
      fail("response_receipt_content_binding_mismatch");
    }
  } else {
    if (receipt.failure_class === "none"
      || receipt.assistant_content_sha256 !== null
      || receipt.usage !== null) {
      fail("response_receipt_inconclusive_evidence_invalid");
    }
    if (expected.assistantMessage !== null) {
      fail("response_receipt_inconclusive_content_invalid");
    }
    const incomplete = receipt.failure_class === "provider_incomplete_completion";
    if (incomplete) {
      if (receipt.http_status === null
        || receipt.http_status < 200 || receipt.http_status >= 300
        || receipt.response_body_sha256 === null
        || receipt.completion_id === null
        || receipt.resolved_model !== DEEPSEEK_MODEL_V1
        || receipt.finish_reason === null || receipt.finish_reason === "stop"
        || receipt.provider_created_unix_seconds === null
        || receipt.response_object !== "chat.completion"
        || receipt.system_fingerprint === null) {
        fail("response_receipt_incomplete_completion_invalid");
      }
    } else if (receipt.completion_id !== null
      || receipt.resolved_model !== null
      || receipt.finish_reason !== null
      || receipt.provider_created_unix_seconds !== null
      || receipt.response_object !== null
      || receipt.system_fingerprint !== null) {
      fail("response_receipt_inconclusive_identity_invalid");
    }
    if (receipt.failure_class === "provider_http_status"
      && (receipt.http_status === null
        || (receipt.http_status >= 200 && receipt.http_status < 300)
        || receipt.response_body_sha256 === null)) {
      fail("response_receipt_http_failure_invalid");
    }
    if (receipt.failure_class === "provider_response_protocol"
      && (receipt.http_status === null
        || receipt.http_status < 200 || receipt.http_status >= 300
        || receipt.response_body_sha256 === null)) {
      fail("response_receipt_protocol_failure_invalid");
    }
    if (receipt.failure_class === "provider_response_limit"
      && (receipt.http_status === null || receipt.response_body_sha256 !== null)) {
      fail("response_receipt_limit_failure_invalid");
    }
    if (receipt.failure_class === "provider_transport"
      && receipt.response_body_sha256 !== null) {
      fail("response_receipt_transport_failure_invalid");
    }
  }
  return canonicalClone(receipt);
}

function sampleTimestamp(clock) {
  let value;
  try {
    value = clock();
    if (value instanceof Date) value = value.toISOString();
    return expectCanonicalTimestamp(value, "deepseek_clock_timestamp");
  } catch {
    fail("clock_invalid");
  }
}

function verifyMessages(value) {
  const messages = expectArray(value, "deepseek_messages", { minimum: 1, maximum: 64 });
  for (const [index, messageValue] of messages.entries()) {
    const message = expectExactRecord(messageValue, ["content", "role"],
      `deepseek_message_${index}`);
    if (!new Set(["assistant", "system", "user"]).has(message.role)) {
      fail("message_role_invalid");
    }
    expectText(message.content, `deepseek_message_${index}_content`, {
      controls: true,
      maximumBytes: 262_144,
      trimmed: false,
    });
  }
  const cloned = canonicalClone(messages);
  if (Buffer.byteLength(canonicalJson(cloned), "utf8") > 1_048_576) {
    fail("request_body_too_large");
  }
  return cloned;
}

function verifyAssistantMessage(value) {
  const message = expectExactRecord(value, ["content", "role"],
    "deepseek_assistant_message");
  if (message.role !== "assistant") fail("assistant_message_role_invalid");
  expectText(message.content, "deepseek_assistant_message_content", {
    controls: true,
    maximumBytes: 1_048_576,
    trimmed: false,
  });
  return message;
}

function canonicalRequestV1(messagesValue, protocolValue) {
  const protocol = verifyDeepSeekModelProtocolV1(protocolValue);
  const messages = verifyMessages(messagesValue);
  const body = {
    model: DEEPSEEK_MODEL_V1,
    messages,
    thinking: { type: DEEPSEEK_THINKING_MODE_V1 },
    reasoning_effort: DEEPSEEK_REASONING_EFFORT_V1,
    response_format: { type: DEEPSEEK_RESPONSE_FORMAT_V1 },
    max_tokens: protocol.max_tokens,
    stream: false,
  };
  const text = canonicalJson(body);
  return Object.freeze({
    text,
    sha256: sha256Bytes(Buffer.from(text, "utf8")),
  });
}

export function deepSeekCanonicalRequestSha256V1(messages, modelProtocol) {
  return canonicalRequestV1(messages, modelProtocol).sha256;
}

function safeProviderText(value, field, apiKey) {
  try {
    const text = expectText(value, field, { maximumBytes: 4_096 });
    if (text.includes(apiKey) || /authorization\s*:/iu.test(text)) return null;
    return text;
  } catch {
    return null;
  }
}

function responseHeaderRequestId(response, apiKey) {
  try {
    if (response?.headers === null || response?.headers === undefined
      || typeof response.headers.get !== "function") return null;
    for (const name of ["x-request-id"]) {
      const candidate = safeProviderText(
        response.headers.get(name),
        "provider_header_request_id",
        apiKey,
      );
      if (candidate !== null) return candidate;
    }
  } catch {
    return null;
  }
  return null;
}

async function readResponseText(response) {
  const contentLengthText = response?.headers?.get?.("content-length");
  if (typeof contentLengthText === "string" && /^\d+$/u.test(contentLengthText)
    && Number(contentLengthText) > DEEPSEEK_RESPONSE_BODY_LIMIT_BYTES_V1) {
    throw new Error("aionis_eval_deepseek_response_body_limit");
  }
  if (response?.body !== null && response?.body !== undefined
    && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        const chunk = Buffer.from(item.value);
        size += chunk.length;
        if (size > DEEPSEEK_RESPONSE_BODY_LIMIT_BYTES_V1) {
          await reader.cancel();
          throw new Error("aionis_eval_deepseek_response_body_limit");
        }
        chunks.push(chunk);
      }
    } finally {
      reader.releaseLock?.();
    }
    return Buffer.concat(chunks).toString("utf8");
  }
  if (typeof response?.text !== "function") throw new Error("invalid_response_body");
  const text = await response.text();
  if (typeof text !== "string") throw new Error("invalid_response_body");
  if (Buffer.byteLength(text, "utf8") > DEEPSEEK_RESPONSE_BODY_LIMIT_BYTES_V1) {
    throw new Error("aionis_eval_deepseek_response_body_limit");
  }
  return text;
}

function parseDeepSeekResponse(bodyText, apiKey) {
  const parsed = JSON.parse(bodyText);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("provider_response_shape_invalid");
  }
  const completionId = safeProviderText(
    parsed.id,
    "provider_completion_id",
    apiKey,
  );
  const resolvedModel = safeProviderText(
    parsed.model,
    "provider_response_model",
    apiKey,
  );
  const systemFingerprint = safeProviderText(
    parsed.system_fingerprint,
    "provider_system_fingerprint",
    apiKey,
  );
  if (completionId === null
    || resolvedModel !== DEEPSEEK_MODEL_V1
    || systemFingerprint === null
    || parsed.object !== "chat.completion"
    || !Number.isSafeInteger(parsed.created)
    || parsed.created < 1) {
    fail("provider_response_identity_invalid");
  }
  if (!Array.isArray(parsed.choices) || parsed.choices.length !== 1) {
    fail("provider_response_choices_invalid");
  }
  const choice = parsed.choices[0];
  if (choice === null || typeof choice !== "object" || Array.isArray(choice)
    || choice.index !== 0
    || !FINISH_REASONS.has(choice.finish_reason)
    || choice.message === null || typeof choice.message !== "object"
    || Array.isArray(choice.message) || choice.message.role !== "assistant") {
    fail("provider_response_message_invalid");
  }
  const identity = {
    completion_id: completionId,
    finish_reason: choice.finish_reason,
    provider_created_unix_seconds: parsed.created,
    resolved_model: resolvedModel,
    response_object: parsed.object,
    system_fingerprint: systemFingerprint,
  };
  if (choice.finish_reason !== "stop") {
    return canonicalClone({
      outcome: "inconclusive",
      assistant_message: null,
      usage: null,
      ...identity,
    });
  }
  const content = expectText(choice.message.content, "provider_response_content", {
    controls: true,
    maximumBytes: 1_048_576,
    trimmed: false,
  });
  if (content.includes(apiKey)) fail("provider_response_secret_invalid");
  if (parsed.usage === null || typeof parsed.usage !== "object"
    || Array.isArray(parsed.usage)) fail("provider_response_usage_invalid");
  if (parsed.usage.completion_tokens_details === null
    || typeof parsed.usage.completion_tokens_details !== "object"
    || Array.isArray(parsed.usage.completion_tokens_details)) {
    fail("provider_response_usage_invalid");
  }
  const usage = verifyUsage({
    prompt_tokens: parsed.usage.prompt_tokens,
    completion_tokens: parsed.usage.completion_tokens,
    total_tokens: parsed.usage.total_tokens,
    prompt_cache_hit_tokens: parsed.usage.prompt_cache_hit_tokens,
    prompt_cache_miss_tokens: parsed.usage.prompt_cache_miss_tokens,
    reasoning_tokens: parsed.usage.completion_tokens_details.reasoning_tokens,
  }, "provider_response_usage");
  return canonicalClone({
    outcome: "completed",
    assistant_message: { role: "assistant", content },
    usage,
    ...identity,
  });
}

function buildRequestReceipt(cellRef, protocol, requestSha256, reservation, startedAt) {
  const body = {
    schema_version: "aionis_deepseek_request_receipt_v1",
    cell_ref: cellRef,
    attempt_ordinal: reservation.attempt_ordinal,
    endpoint: DEEPSEEK_ENDPOINT_V1,
    requested_model: DEEPSEEK_MODEL_V1,
    model_protocol_sha256: deepSeekModelProtocolSha256V1(protocol),
    thinking_mode: DEEPSEEK_THINKING_MODE_V1,
    reasoning_effort: DEEPSEEK_REASONING_EFFORT_V1,
    response_format: DEEPSEEK_RESPONSE_FORMAT_V1,
    max_tokens: protocol.max_tokens,
    retries: 0,
    immutable_snapshot: false,
    provider_may_update_weights: true,
    canonical_request_sha256: requestSha256,
    execution_authorization_sha256: reservation.execution_authorization_sha256,
    provider_attempt_reservation_sha256: reservation.reservation_sha256,
    provider_request_started_event_sha256: reservation.request_started_event_sha256,
    request_started_at: startedAt,
    request_timeout_ms: DEEPSEEK_REQUEST_TIMEOUT_MS_V1,
  };
  return canonicalClone({ ...body, request_receipt_sha256: canonicalSha256(body) });
}

function buildResponseReceipt({
  assistantContentSha256 = null,
  attemptOrdinal,
  bodySha256,
  cellRef,
  completionId = null,
  failureClass,
  finishReason = null,
  httpStatus,
  outcome,
  providerCreatedUnixSeconds = null,
  receivedAt,
  requestReceipt,
  resolvedModel = null,
  responseObject = null,
  systemFingerprint = null,
  transportRequestId = null,
  usage = null,
}) {
  const body = {
    schema_version: "aionis_deepseek_response_receipt_v1",
    cell_ref: cellRef,
    attempt_ordinal: attemptOrdinal,
    canonical_request_sha256: requestReceipt.canonical_request_sha256,
    request_receipt_sha256: requestReceipt.request_receipt_sha256,
    http_status: httpStatus,
    response_body_sha256: bodySha256,
    completion_id: completionId,
    transport_request_id: transportRequestId,
    resolved_model: resolvedModel,
    finish_reason: finishReason,
    provider_created_unix_seconds: providerCreatedUnixSeconds,
    response_object: responseObject,
    system_fingerprint: systemFingerprint,
    usage,
    assistant_content_sha256: assistantContentSha256,
    response_received_at: receivedAt,
    outcome,
    failure_class: failureClass,
  };
  return canonicalClone({ ...body, response_receipt_sha256: canonicalSha256(body) });
}

export function createDeepSeekProviderV1(options, cancellationAuthorityValue = null) {
  const config = expectExactRecord(options, [
    "apiKey", "attemptAuthority", "clock", "fetchImpl", "modelProtocol", "pilotId",
  ], "deepseek_provider_options");
  const apiKey = assertDeepSeekApiKeyV1(config.apiKey);
  if (typeof config.fetchImpl !== "function") fail("fetch_impl_invalid");
  if (typeof config.clock !== "function") fail("clock_invalid");
  const pilotId = expectText(config.pilotId, "deepseek_pilot_id");
  const protocol = verifyDeepSeekModelProtocolV1(config.modelProtocol);
  const fetchImpl = config.fetchImpl;
  const clock = config.clock;
  const attemptAuthority = config.attemptAuthority;
  const cancellationAuthority = cancellationAuthorityValue === null
    ? null
    : assertReleasePilotCancellationAuthorityV1(cancellationAuthorityValue);
  snapshotProviderAttemptAuthorityV1(attemptAuthority);
  const attemptedCellIds = new Set();

  return Object.freeze({
    async executeScoredRequest(inputValue) {
      const input = expectExactRecord(inputValue, [
        "cell", "messages",
      ], "deepseek_scored_request");
      const cell = verifyPilotCellV1(input.cell);
      if (cell.pilot_id !== pilotId) fail("pilot_binding_invalid");
      const cellRef = deepSeekPilotCellRefV1(cell);
      const messages = verifyMessages(input.messages);
      if (canonicalJson(messages).includes(apiKey)) fail("request_secret_present");
      if (attemptedCellIds.has(cell.opaque_cell_id)) fail("retry_forbidden");
      if (cancellationAuthority !== null) {
        checkpointReleasePilotCancellationV1(cancellationAuthority);
      }
      const canonicalRequest = canonicalRequestV1(messages, protocol);
      const requestText = canonicalRequest.text;
      const canonicalRequestSha256 = canonicalRequest.sha256;
      const reservation = await reserveProviderAttemptV1(attemptAuthority, {
        cell,
        modelInputSha256: canonicalSha256(messages),
        canonicalRequestSha256,
      });
      const attemptOrdinal = reservation.attempt_ordinal;
      attemptedCellIds.add(cell.opaque_cell_id);
      const requestStartedAt = sampleTimestamp(clock);
      const requestReceipt = buildRequestReceipt(
        cellRef,
        protocol,
        canonicalRequestSha256,
        reservation,
        requestStartedAt,
      );
      // Reservation durably burns the attempt before this checkpoint. If a
      // signal arrived while the ledger fsynced, no HTTP request is started and
      // the runner seals the burned run as claim-ineligible.
      if (cancellationAuthority !== null) {
        checkpointReleasePilotCancellationV1(cancellationAuthority);
      }

      let response;
      try {
        const timeoutSignal = AbortSignal.timeout(DEEPSEEK_REQUEST_TIMEOUT_MS_V1);
        const requestSignal = cancellationAuthority === null
          ? timeoutSignal
          : AbortSignal.any([
            timeoutSignal,
            releasePilotCancellationSignalV1(cancellationAuthority),
          ]);
        response = await fetchImpl(DEEPSEEK_ENDPOINT_V1, {
          method: "POST",
          headers: {
            Accept: "application/json",
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
          body: requestText,
          redirect: "error",
          signal: requestSignal,
        });
      } catch {
        const responseReceipt = buildResponseReceipt({
          assistantContentSha256: null,
          attemptOrdinal,
          bodySha256: null,
          cellRef,
          failureClass: "provider_transport",
          httpStatus: null,
          outcome: "inconclusive",
          receivedAt: sampleTimestamp(clock),
          requestReceipt,
        });
        return canonicalClone({
          outcome: "inconclusive",
          assistant_message: null,
          request_receipt: requestReceipt,
          response_receipt: responseReceipt,
        });
      }

      let httpStatus = null;
      let responseText;
      try {
        if (Number.isSafeInteger(response?.status)
          && response.status >= 100 && response.status <= 599) {
          httpStatus = response.status;
        }
        if (httpStatus === null) {
          throw new Error("invalid_response");
        }
        responseText = await readResponseText(response);
      } catch (error) {
        const responseLimit = error?.message === "aionis_eval_deepseek_response_body_limit";
        const responseReceipt = buildResponseReceipt({
          assistantContentSha256: null,
          attemptOrdinal,
          bodySha256: null,
          cellRef,
          failureClass: responseLimit ? "provider_response_limit" : "provider_transport",
          httpStatus,
          outcome: "inconclusive",
          receivedAt: sampleTimestamp(clock),
          requestReceipt,
        });
        return canonicalClone({
          outcome: "inconclusive",
          assistant_message: null,
          request_receipt: requestReceipt,
          response_receipt: responseReceipt,
        });
      }

      const responseBodySha256 = sha256Bytes(Buffer.from(responseText, "utf8"));
      const headerRequestId = responseHeaderRequestId(response, apiKey);
      const receivedAt = sampleTimestamp(clock);
      if (httpStatus < 200 || httpStatus >= 300) {
        const responseReceipt = buildResponseReceipt({
          assistantContentSha256: null,
          attemptOrdinal,
          bodySha256: responseBodySha256,
          cellRef,
          failureClass: "provider_http_status",
          httpStatus,
          outcome: "inconclusive",
          transportRequestId: headerRequestId,
          receivedAt,
          requestReceipt,
        });
        return canonicalClone({
          outcome: "inconclusive",
          assistant_message: null,
          request_receipt: requestReceipt,
          response_receipt: responseReceipt,
        });
      }

      let parsedResponse;
      try {
        parsedResponse = parseDeepSeekResponse(responseText, apiKey);
      } catch {
        const responseReceipt = buildResponseReceipt({
          assistantContentSha256: null,
          attemptOrdinal,
          bodySha256: responseBodySha256,
          cellRef,
          failureClass: "provider_response_protocol",
          httpStatus,
          outcome: "inconclusive",
          transportRequestId: headerRequestId,
          receivedAt,
          requestReceipt,
        });
        return canonicalClone({
          outcome: "inconclusive",
          assistant_message: null,
          request_receipt: requestReceipt,
          response_receipt: responseReceipt,
        });
      }

      if (parsedResponse.outcome === "inconclusive") {
        const responseReceipt = buildResponseReceipt({
          attemptOrdinal,
          bodySha256: responseBodySha256,
          cellRef,
          completionId: parsedResponse.completion_id,
          failureClass: "provider_incomplete_completion",
          finishReason: parsedResponse.finish_reason,
          httpStatus,
          outcome: "inconclusive",
          providerCreatedUnixSeconds:
            parsedResponse.provider_created_unix_seconds,
          receivedAt,
          requestReceipt,
          resolvedModel: parsedResponse.resolved_model,
          responseObject: parsedResponse.response_object,
          systemFingerprint: parsedResponse.system_fingerprint,
          transportRequestId: headerRequestId,
        });
        return canonicalClone({
          outcome: "inconclusive",
          assistant_message: null,
          request_receipt: requestReceipt,
          response_receipt: responseReceipt,
        });
      }

      const responseReceipt = buildResponseReceipt({
        assistantContentSha256: sha256Bytes(Buffer.from(
          parsedResponse.assistant_message.content,
          "utf8",
        )),
        attemptOrdinal,
        bodySha256: responseBodySha256,
        cellRef,
        completionId: parsedResponse.completion_id,
        failureClass: "none",
        finishReason: parsedResponse.finish_reason,
        httpStatus,
        outcome: "completed",
        providerCreatedUnixSeconds: parsedResponse.provider_created_unix_seconds,
        receivedAt,
        requestReceipt,
        resolvedModel: parsedResponse.resolved_model,
        responseObject: parsedResponse.response_object,
        systemFingerprint: parsedResponse.system_fingerprint,
        transportRequestId: headerRequestId,
        usage: parsedResponse.usage,
      });
      return canonicalClone({
        outcome: "completed",
        assistant_message: parsedResponse.assistant_message,
        request_receipt: requestReceipt,
        response_receipt: responseReceipt,
      });
    },

    budgetSnapshot() {
      const authoritySnapshot = snapshotProviderAttemptAuthorityV1(attemptAuthority);
      return canonicalClone({
        schema_version: "aionis_deepseek_attempt_budget_v1",
        pilot_id: pilotId,
        maximum_attempt_count: DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1,
        durable_completed_cell_count: authoritySnapshot.completed_cell_count,
        durable_next_attempt_ordinal: authoritySnapshot.next_attempt_ordinal,
        durable_active_attempt_ordinal: authoritySnapshot.active_attempt_ordinal,
        process_attempt_count: attemptedCellIds.size,
        attempted_opaque_cell_ids: [...attemptedCellIds],
      });
    },
  });
}

function deepSeekProviderContractSmokeModelProtocolV1() {
  return verifyDeepSeekModelProtocolV1({
    provider: "deepseek",
    endpoint: DEEPSEEK_ENDPOINT_V1,
    requested_model: DEEPSEEK_MODEL_V1,
    thinking_mode: DEEPSEEK_THINKING_MODE_V1,
    reasoning_effort: DEEPSEEK_REASONING_EFFORT_V1,
    response_format: DEEPSEEK_RESPONSE_FORMAT_V1,
    max_tokens: PROVIDER_CONTRACT_SMOKE_MAX_TOKENS,
    retries: 0,
    scored_agent_execution_count: DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1,
    maximum_provider_request_attempt_count: DEEPSEEK_SCORED_ATTEMPT_LIMIT_V1,
    immutable_snapshot: false,
    provider_may_update_weights: true,
  });
}

function providerContractMarkerVerified(content) {
  try {
    const value = expectExactRecord(
      JSON.parse(content),
      ["aionis_provider_contract"],
      "provider_contract_smoke_marker",
    );
    return value.aionis_provider_contract === PROVIDER_CONTRACT_SMOKE_MARKER;
  } catch {
    return false;
  }
}

/**
 * Internal transport seam for deterministic contract tests. Formal callers
 * must use runDeepSeekProviderContractSmokeV1, which does not accept a fetch
 * implementation or plaintext credential.
 */
export async function executeDeepSeekProviderContractSmokeTransportV1(options) {
  const input = expectExactRecord(options, [
    "apiKey", "clock", "fetchImpl",
  ], "provider_contract_smoke_transport_options");
  if (typeof input.fetchImpl !== "function") fail("contract_smoke_fetch_impl_invalid");
  if (typeof input.clock !== "function") fail("contract_smoke_clock_invalid");
  const protocol = deepSeekProviderContractSmokeModelProtocolV1();
  const pilotId = "deepseek-provider-contract-smoke";
  const cell = buildPilotCellV1({
    pilot_id: pilotId,
    ordinal: 1,
    opaque_cell_id: "provider-contract-smoke-cell",
    case_id: "provider-contract-smoke",
    case_sha256: canonicalSha256({
      schema_version: "aionis_deepseek_provider_contract_smoke_case_v1",
    }),
    arm: "baseline",
  });
  // The ephemeral non-release authority reuses the production transport and
  // receipt verifier without reserving any formal pilot or scored ledger cell.
  const provider = createDeepSeekProviderV1({
    apiKey: input.apiKey,
    attemptAuthority: createNonReleaseProviderContractAuthorityV1([cell]),
    clock: input.clock,
    fetchImpl: input.fetchImpl,
    modelProtocol: protocol,
    pilotId,
  });
  const result = await provider.executeScoredRequest({
    cell,
    messages: PROVIDER_CONTRACT_SMOKE_MESSAGES,
  });
  const response = result.response_receipt;
  const markerVerified = result.outcome === "completed"
    && providerContractMarkerVerified(result.assistant_message.content);
  return canonicalClone({
    canonical_request_sha256: response.canonical_request_sha256,
    request_receipt_sha256: result.request_receipt.request_receipt_sha256,
    response_receipt_sha256: response.response_receipt_sha256,
    http_status: response.http_status,
    response_body_sha256: response.response_body_sha256,
    assistant_content_sha256: response.assistant_content_sha256,
    provider_contract_marker_verified: markerVerified,
    outcome: markerVerified ? "provider_contract_verified" : "inconclusive",
    failure_class: markerVerified
      ? "none"
      : result.outcome === "completed"
        ? "provider_contract_marker"
        : response.failure_class,
  });
}

export function buildDeepSeekProviderContractSmokeReceiptV1(transportEvidence) {
  const evidence = expectExactRecord(
    transportEvidence,
    PROVIDER_CONTRACT_SMOKE_TRANSPORT_EVIDENCE_KEYS,
    "provider_contract_smoke_transport_evidence",
  );
  const protocol = deepSeekProviderContractSmokeModelProtocolV1();
  const body = {
    schema_version: PROVIDER_CONTRACT_SMOKE_SCHEMA_VERSION,
    claim_eligible: false,
    claim_ineligibility_reason: "single_unscored_provider_contract_smoke",
    scored_request: false,
    provider_request_attempt_count: 1,
    credential_transport: "caller_opened_private_regular_file_fd",
    credential_recorded: false,
    raw_content_recorded: false,
    endpoint: DEEPSEEK_ENDPOINT_V1,
    requested_model: DEEPSEEK_MODEL_V1,
    model_protocol_sha256: deepSeekModelProtocolSha256V1(protocol),
    request_timeout_ms: DEEPSEEK_REQUEST_TIMEOUT_MS_V1,
    retries: 0,
    ...evidence,
  };
  return canonicalClone({ ...body, receipt_sha256: canonicalSha256(body) });
}

export function parseDeepSeekProviderContractSmokeCliArgumentsV1(
  argvValue,
  environment = process.env,
) {
  const argv = expectArray(argvValue, "provider_contract_smoke_cli_argv", {
    minimum: 2,
    maximum: 2,
  });
  if (environment === null || typeof environment !== "object"
    || Array.isArray(environment)) fail("contract_smoke_environment_invalid");
  const forbiddenEnvironment = new Set([
    "AIONIS_DEEPSEEK_API_KEY",
    "DEEPSEEK_API_KEY",
  ]);
  if (Object.keys(environment).some((name) =>
    forbiddenEnvironment.has(name.toUpperCase()))) {
    fail("contract_smoke_secret_environment_forbidden");
  }
  if (argv[0] !== "--deepseek-key-fd"
    || typeof argv[1] !== "string"
    || !/^[3-9][0-9]*$/u.test(argv[1])) {
    fail("contract_smoke_arguments_invalid");
  }
  const apiKeyFd = Number(argv[1]);
  if (!Number.isSafeInteger(apiKeyFd)) fail("contract_smoke_arguments_invalid");
  return Object.freeze({ apiKeyFd });
}

export async function runDeepSeekProviderContractSmokeV1(options) {
  const input = expectExactRecord(
    options,
    ["apiKeyFd"],
    "provider_contract_smoke_options",
  );
  if (PLATFORM_FETCH_V1 === null) fail("contract_smoke_platform_fetch_unavailable");
  const apiKey = readDeepSeekApiKeyFdV1(input.apiKeyFd);
  const transportEvidence = await executeDeepSeekProviderContractSmokeTransportV1({
    apiKey,
    clock: () => new PLATFORM_DATE_V1().toISOString(),
    fetchImpl: PLATFORM_FETCH_V1,
  });
  return buildDeepSeekProviderContractSmokeReceiptV1(transportEvidence);
}

if (path.resolve(process.argv[1] ?? "") === modulePath
  && process.argv[2] === API_KEY_ATTESTATION_CHILD_MODE) {
  apiKeyAttestationChildMain().catch(() => {
    process.stderr.write("aionis_eval_deepseek_api_key_attestation_failed\n");
    process.exitCode = 1;
  });
}
