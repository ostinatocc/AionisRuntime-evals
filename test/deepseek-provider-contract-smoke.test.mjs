import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJson,
  canonicalSha256,
  sha256Bytes,
} from "../src/canonical.mjs";
import {
  DEEPSEEK_ENDPOINT_V1,
  DEEPSEEK_MODEL_V1,
  DEEPSEEK_REASONING_EFFORT_V1,
  DEEPSEEK_RESPONSE_FORMAT_V1,
  DEEPSEEK_THINKING_MODE_V1,
  buildDeepSeekProviderContractSmokeReceiptV1,
  executeDeepSeekProviderContractSmokeTransportV1,
  parseDeepSeekProviderContractSmokeCliArgumentsV1,
  runDeepSeekProviderContractSmokeV1,
} from "../src/deepseek-provider.mjs";

const API_KEY = "test-only-provider-contract-smoke-secret";

function clock() {
  let tick = 0;
  return () => {
    const timestamp = new Date(Date.UTC(2026, 6, 23, 1, 2, 3, tick));
    tick += 1;
    return timestamp.toISOString();
  };
}

function response(status, body, headers = {}) {
  const normalized = new Map(Object.entries(headers).map(([name, value]) => [
    name.toLowerCase(), value,
  ]));
  return {
    status,
    headers: { get: (name) => normalized.get(name.toLowerCase()) ?? null },
    async text() { return body; },
  };
}

function completionBody(content = '{"aionis_provider_contract":"ok"}') {
  return JSON.stringify({
    id: "provider-contract-smoke-completion",
    object: "chat.completion",
    created: 1_784_769_600,
    model: DEEPSEEK_MODEL_V1,
    system_fingerprint: "fp-deepseek-v4-flash-contract-smoke",
    choices: [{
      index: 0,
      finish_reason: "stop",
      message: {
        role: "assistant",
        content,
        reasoning_content: "provider contract reasoning",
      },
    }],
    usage: {
      prompt_tokens: 22,
      prompt_cache_hit_tokens: 2,
      prompt_cache_miss_tokens: 20,
      completion_tokens: 10,
      total_tokens: 32,
      completion_tokens_details: { reasoning_tokens: 6 },
    },
  });
}

test("single unscored DeepSeek contract smoke reuses the frozen protocol and redacts content", async () => {
  const calls = [];
  const body = completionBody();
  const transport = await executeDeepSeekProviderContractSmokeTransportV1({
    apiKey: API_KEY,
    clock: clock(),
    fetchImpl: async (url, init) => {
      calls.push({ init, url });
      return response(200, body, { "x-request-id": "transport-contract-smoke" });
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, DEEPSEEK_ENDPOINT_V1);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.headers.Authorization, `Bearer ${API_KEY}`);
  assert.equal(calls[0].init.signal instanceof AbortSignal, true);
  const request = JSON.parse(calls[0].init.body);
  assert.equal(calls[0].init.body, canonicalJson(request));
  assert.equal(request.model, DEEPSEEK_MODEL_V1);
  assert.deepEqual(request.thinking, { type: DEEPSEEK_THINKING_MODE_V1 });
  assert.equal(request.reasoning_effort, DEEPSEEK_REASONING_EFFORT_V1);
  assert.deepEqual(request.response_format, { type: DEEPSEEK_RESPONSE_FORMAT_V1 });
  assert.equal(request.max_tokens, 8_192);
  assert.equal(request.stream, false);

  const receipt = buildDeepSeekProviderContractSmokeReceiptV1(transport);
  assert.equal(receipt.outcome, "provider_contract_verified");
  assert.equal(receipt.claim_eligible, false);
  assert.equal(receipt.scored_request, false);
  assert.equal(receipt.provider_request_attempt_count, 1);
  assert.equal(receipt.provider_contract_marker_verified, true);
  assert.equal(receipt.credential_transport, "caller_opened_private_regular_file_fd");
  assert.equal(receipt.credential_recorded, false);
  assert.equal(receipt.raw_content_recorded, false);
  assert.equal(receipt.response_body_sha256, sha256Bytes(Buffer.from(body, "utf8")));
  assert.equal(
    receipt.assistant_content_sha256,
    sha256Bytes(Buffer.from('{"aionis_provider_contract":"ok"}', "utf8")),
  );
  const bodyWithoutHash = Object.fromEntries(
    Object.entries(receipt).filter(([key]) => key !== "receipt_sha256"),
  );
  assert.equal(receipt.receipt_sha256, canonicalSha256(bodyWithoutHash));
  const encoded = canonicalJson(receipt);
  assert.equal(canonicalJson(JSON.parse(encoded)), encoded);
  assert.equal(encoded.includes(API_KEY), false);
  assert.equal(encoded.includes("provider contract reasoning"), false);
  for (const forbidden of [
    "authorization", "messages", "raw_request", "raw_response", "response_text",
  ]) assert.equal(Object.hasOwn(receipt, forbidden), false);
});

test("contract smoke turns provider and marker failures into secret-free claim-ineligible receipts", async () => {
  const providerErrorBody = JSON.stringify({
    error: { message: `credential rejected: ${API_KEY}` },
  });
  const httpTransport = await executeDeepSeekProviderContractSmokeTransportV1({
    apiKey: API_KEY,
    clock: clock(),
    fetchImpl: async () => response(
      401,
      providerErrorBody,
      { "x-request-id": "transport-http-failure" },
    ),
  });
  const httpReceipt = buildDeepSeekProviderContractSmokeReceiptV1(httpTransport);
  assert.equal(httpReceipt.outcome, "inconclusive");
  assert.equal(httpReceipt.failure_class, "provider_http_status");
  assert.equal(httpReceipt.http_status, 401);
  assert.equal(httpReceipt.response_body_sha256, sha256Bytes(
    Buffer.from(providerErrorBody, "utf8"),
  ));
  assert.equal(canonicalJson(httpReceipt).includes(API_KEY), false);
  assert.equal(canonicalJson(httpReceipt).includes("credential rejected"), false);

  const markerContent = '{"aionis_provider_contract":"wrong"}';
  const markerTransport = await executeDeepSeekProviderContractSmokeTransportV1({
    apiKey: API_KEY,
    clock: clock(),
    fetchImpl: async () => response(200, completionBody(markerContent)),
  });
  const markerReceipt = buildDeepSeekProviderContractSmokeReceiptV1(markerTransport);
  assert.equal(markerReceipt.outcome, "inconclusive");
  assert.equal(markerReceipt.failure_class, "provider_contract_marker");
  assert.equal(markerReceipt.provider_contract_marker_verified, false);
  assert.equal(
    markerReceipt.assistant_content_sha256,
    sha256Bytes(Buffer.from(markerContent, "utf8")),
  );
  assert.equal(canonicalJson(markerReceipt).includes(markerContent), false);
});

test("formal smoke surface accepts only a numeric private-file FD and has no fetch injection", async () => {
  assert.deepEqual(
    parseDeepSeekProviderContractSmokeCliArgumentsV1(
      ["--deepseek-key-fd", "3"],
      {},
    ),
    { apiKeyFd: 3 },
  );
  assert.throws(
    () => parseDeepSeekProviderContractSmokeCliArgumentsV1(
      ["--deepseek-api-key", API_KEY],
      {},
    ),
    /contract_smoke_arguments_invalid/u,
  );
  assert.throws(
    () => parseDeepSeekProviderContractSmokeCliArgumentsV1(
      ["--deepseek-key-fd", "3"],
      { DEEPSEEK_API_KEY: API_KEY },
    ),
    /contract_smoke_secret_environment_forbidden/u,
  );
  let injectedFetchCalled = false;
  await assert.rejects(
    runDeepSeekProviderContractSmokeV1({
      apiKeyFd: 3,
      fetchImpl: async () => {
        injectedFetchCalled = true;
      },
    }),
    /provider_contract_smoke_options_shape_invalid/u,
  );
  assert.equal(injectedFetchCalled, false);
});
