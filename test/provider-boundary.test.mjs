import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  OPENROUTER_CHAT_COMPLETIONS_ROUTE,
  OPENROUTER_COST_MICROUSD_RULE,
  assertCanonicalProviderRequest,
  createCanonicalProviderRequest,
  createProviderExecutionContract,
  hydrateProviderExecutionContract,
  openRouterCostToMicrousd,
  parseOpenRouterChatCompletion,
} from "../src/provider-boundary.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RELEASE_LOCK_SOURCE = fs.readFileSync(path.join(ROOT, "config/v0.3.12-release-lock.json"));
const WORKLOAD_SOURCE = fs.readFileSync(path.join(ROOT, "fixtures/v0.3.12/workload-manifest.json"));
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function contract(overrides = {}) {
  return createProviderExecutionContract({
    releaseLockSource: RELEASE_LOCK_SOURCE,
    workloadSource: WORKLOAD_SOURCE,
    frozenBindings: {
      release_lock_sha256: sha256(RELEASE_LOCK_SOURCE),
      workload_manifest_sha256: sha256(WORKLOAD_SOURCE),
      ...overrides,
    },
  });
}

function context(group, scenario, prompt = "Use only the prior verified execution branch.") {
  const guideOperationId = `guide-${group}-${scenario}`;
  return {
    trial: {
      trial_id: `pilot:w1:${group}:${scenario}:r1`,
      phase: "pilot",
      wave: 1,
      group,
      scenario,
      repetition: 1,
      preclaim: { guide_operation_id: guideOperationId },
      status: "claimed",
    },
    guide_response: group === "aionis"
      ? {
          operation_id: guideOperationId,
          guide_trace_id: `trace-${scenario}`,
          agent_context: { prompt_text: prompt },
        }
      : null,
  };
}

function responseBytes(executionContract, {
  scenario = "branch_recovery",
  choice = "formula_b",
  id = "gen-provider-boundary-1",
  model = executionContract.release_lock.providers.agent.requested_model,
  content = null,
  argumentsSource = JSON.stringify({ scenario_id: scenario, choice }),
  toolCalls = null,
  choices = null,
  usage = null,
} = {}) {
  const nativeCalls = toolCalls ?? [{
    id: "call-provider-boundary-1",
    type: "function",
    function: {
      name: executionContract.workload.tool_protocol.function.name,
      arguments: argumentsSource,
    },
  }];
  const value = {
    id,
    model,
    choices: choices ?? [{
      index: 0,
      message: { role: "assistant", content, tool_calls: nativeCalls },
      finish_reason: "tool_calls",
    }],
    usage: usage ?? {
      prompt_tokens: 120,
      completion_tokens: 8,
      total_tokens: 128,
      cost: 0.0012345,
    },
  };
  return Buffer.from(JSON.stringify(value), "utf8");
}

function parse(executionContract, ledgerContext, responseSource) {
  const request = createCanonicalProviderRequest({ contract: executionContract, ledgerContext });
  return parseOpenRouterChatCompletion({
    contract: executionContract,
    ledgerContext,
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: responseSource,
  });
}

test("execution contract binds exact ledger hashes and the release-lock workload bytes", () => {
  const value = contract();
  assert.equal(value.release_lock_sha256, sha256(RELEASE_LOCK_SOURCE));
  assert.equal(value.workload_manifest_sha256, sha256(WORKLOAD_SOURCE));
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.workload.execution_templates.provider_request), true);

  const reloaded = hydrateProviderExecutionContract(
    JSON.parse(JSON.stringify(value)),
    {
      release_lock_sha256: sha256(RELEASE_LOCK_SOURCE),
      workload_manifest_sha256: sha256(WORKLOAD_SOURCE),
    },
  );
  assert.deepEqual(reloaded, value);
  assert.equal(Object.isFrozen(reloaded), true);
  const drifted = JSON.parse(JSON.stringify(value));
  drifted.workload.scenario_definitions[0].task += " drift";
  assert.throws(() => hydrateProviderExecutionContract(drifted, {
    release_lock_sha256: sha256(RELEASE_LOCK_SOURCE),
    workload_manifest_sha256: sha256(WORKLOAD_SOURCE),
  }), /workload object drifted from its exact source bytes/);

  assert.throws(() => contract({ release_lock_sha256: "0".repeat(64) }), /ledger-owned frozen binding/);
  assert.throws(() => contract({ workload_manifest_sha256: "0".repeat(64) }), /ledger-owned frozen binding/);
  const reformatted = Buffer.from(JSON.stringify(JSON.parse(WORKLOAD_SOURCE)), "utf8");
  assert.throws(() => createProviderExecutionContract({
    releaseLockSource: RELEASE_LOCK_SOURCE,
    workloadSource: reformatted,
    frozenBindings: {
      release_lock_sha256: sha256(RELEASE_LOCK_SOURCE),
      workload_manifest_sha256: sha256(reformatted),
    },
  }), /release-lock binding/);
});

test("finite renderer emits one canonical compact request for baseline, long_context, and aionis", () => {
  const executionContract = contract();
  const cases = [
    ["baseline", "branch_recovery", /Scenario ID: branch_recovery/, /Prior context:/, false],
    ["long_context", "negative_transfer", /Prior context:/, /safe_patch passed/, true],
    ["aionis", "summary_only_inspect", /Aionis execution context:/, /runtime says inspect first/, true],
  ];
  for (const [group, scenario, expected, secondary, secondaryExpected] of cases) {
    const ledgerContext = context(group, scenario, "runtime says inspect first");
    const request = createCanonicalProviderRequest({ contract: executionContract, ledgerContext });
    assert.equal(request.method, "POST");
    assert.equal(request.route, OPENROUTER_CHAT_COMPLETIONS_ROUTE);
    assert.equal(request.content_type, "application/json");
    assert.equal(request.bytes.includes(0x0a), false, "compact JSON must contain no formatting newline bytes");
    assert.equal(request.sha256, sha256(request.bytes));
    assert.deepEqual(JSON.parse(request.bytes), request.body);
    assert.deepEqual(request.body.provider, { allow_fallbacks: false, require_parameters: true });
    assert.equal(Object.hasOwn(request.body.provider, "order"), false);
    assert.equal(Object.hasOwn(request.body.provider, "only"), false);
    assert.match(request.body.messages[1].content, expected);
    if (secondaryExpected) assert.match(request.body.messages[1].content, secondary);
    else assert.doesNotMatch(request.body.messages[1].content, secondary);
    assertCanonicalProviderRequest({ contract: executionContract, ledgerContext, requestBytes: request.bytes });
  }
});

test("provider request boundary rejects routing additions, value drift, and non-canonical reserialization", () => {
  const executionContract = contract();
  const ledgerContext = context("baseline", "branch_recovery");
  const expected = createCanonicalProviderRequest({ contract: executionContract, ledgerContext });

  const ordered = structuredClone(expected.body);
  ordered.provider.order = ["SomeProvider"];
  assert.throws(() => assertCanonicalProviderRequest({
    contract: executionContract,
    ledgerContext,
    requestBytes: Buffer.from(JSON.stringify(ordered)),
  }), /provider\.order and provider\.only/);

  const only = structuredClone(expected.body);
  only.provider.only = ["SomeProvider"];
  assert.throws(() => assertCanonicalProviderRequest({
    contract: executionContract,
    ledgerContext,
    requestBytes: Buffer.from(JSON.stringify(only)),
  }), /provider\.order and provider\.only/);

  const drifted = structuredClone(expected.body);
  drifted.max_tokens += 1;
  assert.throws(() => assertCanonicalProviderRequest({
    contract: executionContract,
    ledgerContext,
    requestBytes: Buffer.from(JSON.stringify(drifted)),
  }), /body drifted/);

  assert.throws(() => assertCanonicalProviderRequest({
    contract: executionContract,
    ledgerContext,
    requestBytes: Buffer.from(`${JSON.stringify(expected.body, null, 2)}\n`),
  }), /not the exact canonical compact UTF-8 body/);
  assert.throws(() => assertCanonicalProviderRequest({
    contract: executionContract,
    ledgerContext,
    requestBytes: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), expected.bytes]),
  }), /must not contain a UTF-8 BOM/);
});

test("exact OpenRouter parsing derives deterministic results for all three groups", () => {
  const executionContract = contract();
  const cases = [
    ["baseline", "branch_recovery", "formula_b", true, false],
    ["long_context", "negative_transfer", "fast_patch", false, true],
    ["aionis", "summary_only_inspect", "inspect_evidence", true, false],
  ];
  for (const [group, scenario, choice, passed, unsafe] of cases) {
    const ledgerContext = context(group, scenario);
    const raw = responseBytes(executionContract, { scenario, choice, id: `gen-${group}` });
    const result = parse(executionContract, ledgerContext, raw);
    assert.equal(result.schema_version, "aionis_openrouter_provider_boundary_v1");
    assert.equal(result.response_contract, "openrouter_nonstreaming_chat_completion_native_tool_v1");
    assert.equal(result.route, OPENROUTER_CHAT_COMPLETIONS_ROUTE);
    assert.equal(result.http_status, 200);
    assert.equal(result.provider_request_id, `gen-${group}`);
    assert.equal(result.returned_model, executionContract.release_lock.providers.agent.requested_model);
    assert.equal(result.fallback_used, false);
    assert.equal(result.response_sha256, sha256(raw));
    assert.deepEqual(result.tool_result, {
      schema_version: "aionis_bounded_soak_tool_result_v1",
      scenario_id: scenario,
      choice,
      expected_choice: executionContract.workload.scenario_definitions
        .find((entry) => entry.id === scenario).expected_choice,
      passed,
      unsafe_direct_use: unsafe,
    });
    assert.deepEqual(result.provider_usage, {
      input_tokens: 120,
      output_tokens: 8,
      total_tokens: 128,
      cost_microusd: 1_235,
    });
    assert.equal(result.cost_microusd_rule, OPENROUTER_COST_MICROUSD_RULE);
  }
});

test("response boundary rejects HTTP, returned-model, choice-count, multi-tool, and prose drift", () => {
  const executionContract = contract();
  const ledgerContext = context("baseline", "branch_recovery");
  const request = createCanonicalProviderRequest({ contract: executionContract, ledgerContext });
  assert.throws(() => parseOpenRouterChatCompletion({
    contract: executionContract,
    ledgerContext,
    requestBytes: request.bytes,
    httpStatus: 502,
    responseBytes: responseBytes(executionContract),
  }), /HTTP status must be exactly 200/);

  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    model: "deepseek/not-the-frozen-model",
  })), /returned-model allowlist/);
  const twoChoices = JSON.parse(responseBytes(executionContract));
  twoChoices.choices.push(structuredClone(twoChoices.choices[0]));
  assert.throws(() => parse(executionContract, ledgerContext, Buffer.from(JSON.stringify(twoChoices))), /exactly one choice/);

  const nativeCall = JSON.parse(responseBytes(executionContract)).choices[0].message.tool_calls[0];
  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    toolCalls: [nativeCall, { ...structuredClone(nativeCall), id: "call-2" }],
  })), /exactly one native function tool call/);
  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    content: "I choose formula_b.",
  })), /prose is forbidden/);
  assert.throws(() => parse(
    executionContract,
    ledgerContext,
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), responseBytes(executionContract)]),
  ), /must not contain a UTF-8 BOM/);
});

test("native arguments must be strict schema JSON for the ledger-owned scenario", () => {
  const executionContract = contract();
  const ledgerContext = context("baseline", "branch_recovery");
  for (const [argumentsSource, message] of [
    ['{"scenario_id":', /valid JSON/],
    [JSON.stringify({ scenario_id: "branch_recovery", choice: "formula_b", explanation: "extra" }), /keys must be exactly/],
    [JSON.stringify({ scenario_id: "negative_transfer", choice: "safe_patch" }), /does not match the ledger trial/],
    [JSON.stringify({ scenario_id: "branch_recovery", choice: "safe_patch" }), /not allowed for the ledger scenario/],
    ['{"scenario_id":"branch_recovery","choice":"formula_b","choice":"formula_a"}', /duplicate object key/],
  ]) {
    assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
      argumentsSource,
    })), message);
  }
});

test("usage fields and exact decimal cost conversion fail closed without floating ambiguity", () => {
  const executionContract = contract();
  const ledgerContext = context("baseline", "branch_recovery");
  assert.equal(openRouterCostToMicrousd("0"), 0);
  assert.equal(openRouterCostToMicrousd("0.000000000001"), 1);
  assert.equal(openRouterCostToMicrousd(`0.${"0".repeat(1_100)}1`), 1);
  assert.equal(openRouterCostToMicrousd("0.000000499999"), 1);
  assert.equal(openRouterCostToMicrousd("0.0000005"), 1);
  assert.equal(openRouterCostToMicrousd("0.001234"), 1_234);
  assert.equal(openRouterCostToMicrousd("1.2345675e-3"), 1_235);
  assert.equal(openRouterCostToMicrousd("1.2345674e-3"), 1_235);
  assert.throws(() => openRouterCostToMicrousd("-0"), /non-negative/);
  assert.throws(() => openRouterCostToMicrousd("00.1"), /JSON decimal number/);

  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    usage: { prompt_tokens: 120, completion_tokens: 8, total_tokens: 129, cost: 0.001 },
  })), /must equal prompt_tokens \+ completion_tokens/);
  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    usage: { prompt_tokens: 120.5, completion_tokens: 8, total_tokens: 128.5, cost: 0.001 },
  })), /positive JSON integer/);
  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    usage: { prompt_tokens: 120, completion_tokens: 8, total_tokens: 128, cost: "0.001" },
  })), /finite JSON number/);
  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    usage: { prompt_tokens: 120, completion_tokens: 8, total_tokens: 128, cost: -0.001 },
  })), /non-negative/);
  assert.throws(() => parse(executionContract, ledgerContext, responseBytes(executionContract, {
    usage: { prompt_tokens: 120, completion_tokens: 8, total_tokens: 128, cost: 50.000001 },
  })), /whole-campaign ceiling/);
});

test("Aionis rendering binds the Runtime guide echo and forbids cross-group context injection", () => {
  const executionContract = contract();
  const aionis = context("aionis", "branch_recovery");
  aionis.guide_response.operation_id = "guide-from-another-trial";
  assert.throws(() => createCanonicalProviderRequest({
    contract: executionContract,
    ledgerContext: aionis,
  }), /ledger-owned guide operation ID/);

  const baseline = context("baseline", "branch_recovery");
  baseline.guide_response = { operation_id: "unexpected", agent_context: { prompt_text: "inject" } };
  assert.throws(() => createCanonicalProviderRequest({
    contract: executionContract,
    ledgerContext: baseline,
  }), /must not accept an Aionis guide response/);
});
