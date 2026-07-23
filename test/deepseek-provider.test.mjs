import assert from "node:assert/strict";
import { constants, readSync } from "node:fs";
import {
  chmod,
  link,
  mkdtemp,
  open,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalClone,
  canonicalJson,
  sha256Bytes,
} from "../src/canonical.mjs";
import {
  DEEPSEEK_ENDPOINT_V1,
  DEEPSEEK_MODEL_V1,
  DEEPSEEK_REASONING_EFFORT_V1,
  DEEPSEEK_REQUEST_TIMEOUT_MS_V1,
  DEEPSEEK_RESPONSE_FORMAT_V1,
  DEEPSEEK_RESPONSE_BODY_LIMIT_BYTES_V1,
  DEEPSEEK_THINKING_MODE_V1,
  assertExistingDeepSeekApiKeyFdV1,
  createDeepSeekProviderV1,
  readDeepSeekApiKeyFdV1,
  verifyDeepSeekRequestReceiptV1,
  verifyDeepSeekResponseReceiptV1,
} from "../src/deepseek-provider.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import { createNonReleaseProviderContractAuthorityV1 } from "../src/pilot-run-ledger.mjs";
import {
  createReleasePilotCancellationAuthorityV1,
  requestReleasePilotCancellationV1,
} from "../src/release-pilot-cancellation.mjs";

const SHA = "a".repeat(64);
const API_KEY = "test-deepseek-key-that-must-never-enter-evidence";
const PILOT_ID = "provider-transport-pilot";

function modelProtocol(overrides = {}) {
  return {
    provider: "deepseek",
    endpoint: DEEPSEEK_ENDPOINT_V1,
    requested_model: DEEPSEEK_MODEL_V1,
    thinking_mode: DEEPSEEK_THINKING_MODE_V1,
    reasoning_effort: DEEPSEEK_REASONING_EFFORT_V1,
    response_format: DEEPSEEK_RESPONSE_FORMAT_V1,
    max_tokens: 8_192,
    retries: 0,
    scored_agent_execution_count: 9,
    maximum_provider_request_attempt_count: 9,
    immutable_snapshot: false,
    provider_may_update_weights: true,
    ...overrides,
  };
}

function pilotCell(ordinal, opaqueCellId = `cell-${String(ordinal).padStart(2, "0")}`) {
  return buildPilotCellV1({
    pilot_id: PILOT_ID,
    ordinal,
    opaque_cell_id: opaqueCellId,
    case_id: `case-${String(ordinal).padStart(2, "0")}`,
    case_sha256: SHA,
    arm: ["baseline", "observe_only", "treatment"][(ordinal - 1) % 3],
  });
}

function clock() {
  let tick = 0;
  return () => {
    const value = new Date(Date.UTC(2026, 6, 22, 0, 0, 0, tick));
    tick += 1;
    return value.toISOString();
  };
}

function response(status, body, headers = {}) {
  const normalized = new Map(Object.entries(headers).map(([key, value]) => [
    key.toLowerCase(), value,
  ]));
  return {
    status,
    headers: { get: (name) => normalized.get(name.toLowerCase()) ?? null },
    async text() { return body; },
  };
}

function completionBody(
  index,
  resolvedModel = DEEPSEEK_MODEL_V1,
  finishReason = "stop",
) {
  return JSON.stringify({
    id: `provider-request-${index}`,
    object: "chat.completion",
    created: 1_784_678_400 + index,
    model: resolvedModel,
    system_fingerprint: `fp-deepseek-v4-flash-${index}`,
    choices: [{
      index: 0,
      finish_reason: finishReason,
      message: {
        role: "assistant",
        content: `verified assistant output ${index}`,
        reasoning_content: `bounded reasoning ${index}`,
      },
    }],
    usage: {
      prompt_tokens: 11,
      prompt_cache_hit_tokens: 3,
      prompt_cache_miss_tokens: 8,
      completion_tokens: 7,
      total_tokens: 18,
      completion_tokens_details: { reasoning_tokens: 5 },
      cost: 0.01,
    },
  });
}

function providerOptions(protocol, fetchImpl = async () => {
  throw new Error("fetch must not be reached");
}) {
  return {
    apiKey: API_KEY,
    attemptAuthority: createNonReleaseProviderContractAuthorityV1(
      Array.from({ length: 9 }, (_, index) => pilotCell(index + 1)),
    ),
    clock: clock(),
    fetchImpl,
    modelProtocol: protocol,
    pilotId: PILOT_ID,
  };
}

test("formal DeepSeek credential FD is private, stable, positional, and caller-owned", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aionis-deepseek-key-fd-"));
  const keyPath = path.join(root, "deepseek-key");
  const linkedPath = path.join(root, "deepseek-key-hard-link");
  const symlinkPath = path.join(root, "deepseek-key-symlink");
  const invalidPath = path.join(root, "deepseek-key-invalid");
  let keyFile;
  let invalidFile;
  try {
    await writeFile(keyPath, API_KEY, { mode: 0o600 });
    await chmod(keyPath, 0o600);
    keyFile = await open(keyPath, "r");
    assert.equal(assertExistingDeepSeekApiKeyFdV1(keyFile.fd), keyFile.fd);

    const firstByte = Buffer.alloc(1);
    assert.equal(readSync(keyFile.fd, firstByte, 0, 1, null), 1);
    assert.equal(firstByte.toString("utf8"), API_KEY.slice(0, 1));
    assert.equal(readDeepSeekApiKeyFdV1(keyFile.fd), API_KEY);
    const byteAfterRead = Buffer.alloc(1);
    assert.equal(readSync(keyFile.fd, byteAfterRead, 0, 1, null), 1);
    assert.equal(byteAfterRead.toString("utf8"), API_KEY.slice(1, 2));
    firstByte.fill(0);
    byteAfterRead.fill(0);

    await chmod(keyPath, 0o644);
    assert.throws(
      () => readDeepSeekApiKeyFdV1(keyFile.fd),
      /aionis_eval_deepseek_api_key_fd_mode_invalid/u,
    );
    await chmod(keyPath, 0o600);

    await link(keyPath, linkedPath);
    assert.throws(
      () => readDeepSeekApiKeyFdV1(keyFile.fd),
      /aionis_eval_deepseek_api_key_fd_link_count_invalid/u,
    );
    await rm(linkedPath);

    await symlink(keyPath, symlinkPath);
    await assert.rejects(
      open(symlinkPath, constants.O_RDONLY | constants.O_NOFOLLOW),
    );

    await writeFile(invalidPath, "not\na\ncredential", { mode: 0o600 });
    await chmod(invalidPath, 0o600);
    invalidFile = await open(invalidPath, "r");
    assert.throws(
      () => readDeepSeekApiKeyFdV1(invalidFile.fd),
      /aionis_eval_deepseek_api_key_fd_content_invalid/u,
    );
    assert.throws(
      () => readDeepSeekApiKeyFdV1(-1),
      /aionis_eval_deepseek_api_key_fd_invalid/u,
    );
  } finally {
    await invalidFile?.close();
    await keyFile?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("provider construction locks endpoint, model, reasoning, output, retries, and budget", () => {
  for (const override of [
    { endpoint: "https://example.invalid/chat" },
    { requested_model: "another/model" },
    { thinking_mode: "disabled" },
    { reasoning_effort: "high" },
    { response_format: "text" },
    { retries: 1 },
    { scored_agent_execution_count: 10 },
    { maximum_provider_request_attempt_count: 10 },
    { immutable_snapshot: true },
    { provider_may_update_weights: false },
  ]) {
    assert.throws(
      () => createDeepSeekProviderV1(providerOptions(modelProtocol(override))),
      /aionis_eval_deepseek_model_protocol_invalid/u,
    );
  }
  assert.throws(
    () => createDeepSeekProviderV1(providerOptions(modelProtocol({
      max_tokens: 384_001,
    }))),
    /aionis_eval_deepseek_model_protocol_max_tokens_invalid/u,
  );
  assert.throws(
    () => createDeepSeekProviderV1(providerOptions(modelProtocol({
      model_profile_sha256: SHA,
    }))),
    /aionis_eval_deepseek_model_protocol_shape_invalid/u,
  );
});

test("provider rejects an API key echoed into model messages before consuming budget", async () => {
  let fetchCount = 0;
  const provider = createDeepSeekProviderV1(providerOptions(modelProtocol(), async () => {
    fetchCount += 1;
    return response(200, completionBody(1));
  }));
  await assert.rejects(
    () => provider.executeScoredRequest({
      cell: pilotCell(1),
      messages: [{ role: "user", content: `Never transmit ${API_KEY}` }],
    }),
    /request_secret_present/u,
  );
  assert.equal(fetchCount, 0);
  assert.equal(provider.budgetSnapshot().process_attempt_count, 0);
});

test("cancellation after durable reservation prevents the provider HTTP request", async () => {
  const cancellationAuthority = createReleasePilotCancellationAuthorityV1();
  let fetchCount = 0;
  const options = providerOptions(modelProtocol(), async () => {
    fetchCount += 1;
    return response(200, completionBody(1));
  });
  options.clock = () => {
    requestReleasePilotCancellationV1(cancellationAuthority, { signal: "SIGTERM" });
    return "2026-07-23T00:00:00.000Z";
  };
  const provider = createDeepSeekProviderV1(options, cancellationAuthority);
  await assert.rejects(
    () => provider.executeScoredRequest({
      cell: pilotCell(1),
      messages: [{ role: "user", content: "Perform the frozen pilot task.\n" }],
    }),
    /aionis_eval_release_pilot_cancellation_requested/u,
  );
  assert.equal(fetchCount, 0);
  assert.equal(provider.budgetSnapshot().process_attempt_count, 1);
});

test("non-stop DeepSeek completions are provider-inconclusive and never reach the agent", async () => {
  const messages = [{ role: "user", content: "Perform the frozen pilot task.\n" }];
  for (const finishReason of [
    "length",
    "content_filter",
    "tool_calls",
    "insufficient_system_resource",
  ]) {
    const provider = createDeepSeekProviderV1(providerOptions(
      modelProtocol(),
      async () => response(
        200,
        completionBody(1, DEEPSEEK_MODEL_V1, finishReason),
        { "x-request-id": `transport-${finishReason}` },
      ),
    ));
    const cell = pilotCell(1);
    const result = await provider.executeScoredRequest({ cell, messages });
    assert.equal(result.outcome, "inconclusive");
    assert.equal(result.assistant_message, null);
    assert.equal(
      result.response_receipt.failure_class,
      "provider_incomplete_completion",
    );
    assert.equal(result.response_receipt.finish_reason, finishReason);
    assert.equal(result.response_receipt.completion_id, "provider-request-1");
    assert.equal(
      result.response_receipt.transport_request_id,
      `transport-${finishReason}`,
    );
    assert.doesNotThrow(() => verifyDeepSeekResponseReceiptV1(
      result.response_receipt,
      {
        assistantMessage: null,
        cell,
        messages,
        modelProtocol: modelProtocol(),
        requestReceipt: result.request_receipt,
      },
    ));
  }
});

test("transport emits secret-free canonical receipts and consumes failures in the hard budget", async () => {
  const protocol = modelProtocol();
  const httpFailureBody = JSON.stringify({
    error: { message: `provider echoed ${API_KEY}` },
  });
  const malformedSuccessBody = "{not-json";
  const scripted = [
    () => response(429, httpFailureBody, { "x-request-id": "provider-http-failure" }),
    () => { throw new Error(`network failed with ${API_KEY}`); },
    () => response(200, completionBody(3)),
    () => response(200, malformedSuccessBody, { "x-request-id": "provider-malformed" }),
    () => response(200, completionBody(5, "another/provider-model")),
    () => response(200, "x".repeat(DEEPSEEK_RESPONSE_BODY_LIMIT_BYTES_V1 + 1)),
    ...Array.from({ length: 3 }, (_, index) =>
      () => response(200, completionBody(index + 7))),
  ];
  const fetchCalls = [];
  const fetchImpl = async (url, init) => {
    fetchCalls.push({ url, init });
    return scripted[fetchCalls.length - 1]();
  };
  const provider = createDeepSeekProviderV1(providerOptions(protocol, fetchImpl));
  const messages = [{ role: "user", content: "Perform the frozen pilot task.\n" }];
  const cells = Array.from({ length: 9 }, (_, index) => pilotCell(index + 1));

  const first = await provider.executeScoredRequest({ cell: cells[0], messages });
  assert.equal(first.outcome, "inconclusive");
  assert.equal(first.response_receipt.failure_class, "provider_http_status");
  assert.equal(first.response_receipt.http_status, 429);
  assert.equal(first.response_receipt.transport_request_id, "provider-http-failure");
  assert.equal(
    first.response_receipt.response_body_sha256,
    sha256Bytes(Buffer.from(httpFailureBody, "utf8")),
  );
  assert.equal(first.assistant_message, null);
  assert.doesNotMatch(JSON.stringify(first), new RegExp(API_KEY, "u"));
  assert.doesNotMatch(JSON.stringify(first), /provider echoed/u);
  assert.doesNotThrow(() => verifyDeepSeekRequestReceiptV1(first.request_receipt, {
    cell: cells[0],
    messages,
    modelProtocol: protocol,
  }));
  assert.doesNotThrow(() => verifyDeepSeekResponseReceiptV1(first.response_receipt, {
    assistantMessage: first.assistant_message,
    cell: cells[0],
    messages,
    modelProtocol: protocol,
    requestReceipt: first.request_receipt,
  }));

  let retryError;
  try {
    await provider.executeScoredRequest({ cell: cells[0], messages });
  } catch (error) {
    retryError = error;
  }
  assert.match(String(retryError), /aionis_eval_deepseek_retry_forbidden/u);
  assert.doesNotMatch(String(retryError), new RegExp(API_KEY, "u"));
  assert.equal(provider.budgetSnapshot().process_attempt_count, 1);
  assert.equal(fetchCalls.length, 1);

  const results = [first];
  for (const cell of cells.slice(1)) {
    results.push(await provider.executeScoredRequest({ cell, messages }));
  }
  assert.equal(results[1].outcome, "inconclusive");
  assert.equal(results[1].response_receipt.failure_class, "provider_transport");
  assert.equal(results[1].response_receipt.http_status, null);
  assert.equal(results[1].response_receipt.response_body_sha256, null);
  assert.doesNotMatch(JSON.stringify(results[1]), new RegExp(API_KEY, "u"));

  assert.equal(results[2].outcome, "completed");
  assert.equal(results[2].response_receipt.resolved_model, DEEPSEEK_MODEL_V1);
  assert.equal(results[2].response_receipt.completion_id, "provider-request-3");
  assert.deepEqual(results[2].response_receipt.usage, {
    completion_tokens: 7,
    prompt_cache_hit_tokens: 3,
    prompt_cache_miss_tokens: 8,
    prompt_tokens: 11,
    reasoning_tokens: 5,
    total_tokens: 18,
  });
  assert.equal(
    results[2].response_receipt.assistant_content_sha256,
    sha256Bytes(Buffer.from(results[2].assistant_message.content, "utf8")),
  );

  assert.equal(results[3].outcome, "inconclusive");
  assert.equal(results[3].response_receipt.failure_class, "provider_response_protocol");
  assert.equal(
    results[3].response_receipt.response_body_sha256,
    sha256Bytes(Buffer.from(malformedSuccessBody, "utf8")),
  );
  assert.equal(results[4].outcome, "inconclusive");
  assert.equal(results[4].response_receipt.failure_class, "provider_response_protocol");
  assert.equal(results[4].response_receipt.resolved_model, null);
  assert.equal(results[5].outcome, "inconclusive");
  assert.equal(results[5].response_receipt.failure_class, "provider_response_limit");
  assert.equal(results[5].response_receipt.response_body_sha256, null);

  for (const [index, result] of results.entries()) {
    const requestReceipt = verifyDeepSeekRequestReceiptV1(result.request_receipt, {
      cell: cells[index],
      messages,
      modelProtocol: protocol,
    });
    verifyDeepSeekResponseReceiptV1(result.response_receipt, {
      assistantMessage: result.assistant_message,
      cell: cells[index],
      messages,
      modelProtocol: protocol,
      requestReceipt,
    });
    assert.equal(requestReceipt.attempt_ordinal, index + 1);
    assert.equal(requestReceipt.request_timeout_ms, DEEPSEEK_REQUEST_TIMEOUT_MS_V1);
    assert.equal(Object.hasOwn(requestReceipt, "messages"), false);
    assert.equal(Object.hasOwn(requestReceipt, "authorization"), false);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(API_KEY, "u"));
  }

  assert.equal(fetchCalls.length, 9);
  for (const [index, call] of fetchCalls.entries()) {
    assert.equal(call.url, DEEPSEEK_ENDPOINT_V1);
    assert.equal(call.init.method, "POST");
    assert.equal(call.init.redirect, "error");
    assert.equal(call.init.headers.Authorization, `Bearer ${API_KEY}`);
    assert.equal(call.init.signal instanceof AbortSignal, true);
    assert.equal(call.init.signal.aborted, false);
    assert.equal(
      results[index].request_receipt.canonical_request_sha256,
      sha256Bytes(Buffer.from(call.init.body, "utf8")),
    );
    assert.equal(call.init.body, canonicalJson(JSON.parse(call.init.body)));
    assert.deepEqual(JSON.parse(call.init.body).thinking, { type: "enabled" });
    assert.equal(JSON.parse(call.init.body).reasoning_effort, "max");
    assert.deepEqual(JSON.parse(call.init.body).response_format, {
      type: "json_object",
    });
    assert.equal(Object.hasOwn(JSON.parse(call.init.body), "temperature"), false);
    assert.equal(Object.hasOwn(JSON.parse(call.init.body), "n"), false);
  }

  assert.deepEqual(provider.budgetSnapshot(), {
    schema_version: "aionis_deepseek_attempt_budget_v1",
    pilot_id: PILOT_ID,
    maximum_attempt_count: 9,
    durable_completed_cell_count: 9,
    durable_next_attempt_ordinal: 10,
    durable_active_attempt_ordinal: 9,
    process_attempt_count: 9,
    attempted_opaque_cell_ids: cells.map((cell) => cell.opaque_cell_id),
  });

  let budgetError;
  try {
    await provider.executeScoredRequest({
      cell: pilotCell(1, "cell-10-budget-probe"),
      messages,
    });
  } catch (error) {
    budgetError = error;
  }
  assert.match(String(budgetError), /aionis_eval_run_ledger_attempt_order_invalid/u);
  assert.doesNotMatch(String(budgetError), new RegExp(API_KEY, "u"));
  assert.equal(fetchCalls.length, 9);

  const requestTampered = canonicalClone(results[2].request_receipt);
  requestTampered.cell_ref.opaque_cell_id = "cell-tampered";
  assert.throws(
    () => verifyDeepSeekRequestReceiptV1(requestTampered, {
      cell: cells[2],
      messages,
      modelProtocol: protocol,
    }),
    /request_receipt_sha256_mismatch/u,
  );
  const responseTampered = canonicalClone(results[2].response_receipt);
  responseTampered.resolved_model = "tampered/resolved-model";
  assert.throws(
    () => verifyDeepSeekResponseReceiptV1(responseTampered, {
      assistantMessage: results[2].assistant_message,
      cell: cells[2],
      messages,
      modelProtocol: protocol,
      requestReceipt: results[2].request_receipt,
    }),
    /response_receipt_sha256_mismatch/u,
  );
});
