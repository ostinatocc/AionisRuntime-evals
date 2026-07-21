import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  STABLE_GOVERNANCE_PATHS,
  assertNoSecretMaterial,
  captureWorkloadRawResponseIdentity,
  expandWorkloadScope,
  readJsonFile,
  renderWorkloadTemplate,
  selectWorkloadServedMemory,
  sha256,
  validateAuthorityManifest,
  validateFrozenContracts,
  validateReleaseLock,
  validateReturnedModel,
  validateWorkloadManifest,
} from "../src/contracts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOCK_PATH = path.join(ROOT, "config/v0.3.12-release-lock.json");
const AUTHORITY_PATH = path.join(ROOT, "fixtures/v0.3.12/authority-manifest.json");
const WORKLOAD_PATH = path.join(ROOT, "fixtures/v0.3.12/workload-manifest.json");

function documents() {
  return {
    lock: readJsonFile(LOCK_PATH).value,
    authority: readJsonFile(AUTHORITY_PATH).value,
    workload: readJsonFile(WORKLOAD_PATH).value,
  };
}

function copy(value) {
  return structuredClone(value);
}

test("frozen v0.3.12 authority and workload fixtures satisfy their cross-contract", () => {
  const values = documents();
  assert.doesNotThrow(() => validateFrozenContracts(values));
  assert.equal(sha256(fs.readFileSync(AUTHORITY_PATH)), values.lock.protocol_artifacts.authority_manifest.sha256);
  assert.equal(sha256(fs.readFileSync(WORKLOAD_PATH)), values.lock.protocol_artifacts.workload_manifest.sha256);
});

test("authority rejects candidate, digest, provider, model, fallback, retry, and budget drift", () => {
  const { lock, authority } = documents();
  const mutations = [
    (value) => { value.candidate.commit = "a".repeat(40); },
    (value) => { value.candidate.digest = `sha256:${"b".repeat(64)}`; },
    (value) => { value.providers.embedding.model = "different-embedding"; },
    (value) => { value.providers.agent.requested_model = "different-agent"; },
    (value) => { value.providers.agent.allowed_returned_models.push("fallback-model"); },
    (value) => { value.providers.agent.fallback_allowed = true; },
    (value) => { value.retry_policy.semantic_retries = 1; },
    (value) => { value.execution_limits.maximum_chat_calls = 91; },
    (value) => { value.execution_limits.maximum_cost_usd = 51; },
  ];
  for (const mutate of mutations) {
    const value = copy(authority);
    mutate(value);
    assert.throws(() => validateAuthorityManifest(value, lock));
  }
});

test("workload rejects matrix inflation, denominator drift, self-report, and missing recovery", () => {
  const { lock, workload } = documents();
  const mutations = [
    (value) => { value.groups.push("duplicate"); },
    (value) => { value.pilot.semantic_chat_calls = 10; },
    (value) => { value.soak.semantic_chat_calls = 82; },
    (value) => { value.soak.aionis_trials_per_wave = 10; },
    (value) => { value.soak.negative_transfer_trials = 10; },
    (value) => { value.product_invariants.pop(); },
    (value) => { value.verifier.model_self_report_accepted = true; },
    (value) => { value.recovery.after_wave_2 = "graceful_replacement"; },
  ];
  for (const mutate of mutations) {
    const value = copy(workload);
    mutate(value);
    assert.throws(() => validateWorkloadManifest(value, lock));
  }
});

test("workload v2 rejects executable protocol, provenance, schedule, and template drift", () => {
  const { lock, workload } = documents();
  const mutations = [
    (value) => { value.context_sources.aionis.runtime_routes.pop(); },
    (value) => { value.scenario_definitions[0].expected_choice = "formula_a"; },
    (value) => { value.scenario_definitions[1].runtime_fixture.extra = true; },
    (value) => { value.scenario_definitions[0].runtime_fixture.seed_observations[0].raw_ref = "fixture://wrong"; },
    (value) => { value.tool_protocol.invocation = "text_json"; },
    (value) => { value.tool_protocol.textual_fallback_accepted = true; },
    (value) => { value.tool_protocol.function.arguments_schema.properties.scenario_id.enum.reverse(); },
    (value) => { value.outcome_contract.tool_name = "different_tool"; },
    (value) => { value.outcome_contract.model_text_accepted = true; },
    (value) => { value.schedule.scope.shared_across_phases = false; },
    (value) => { value.schedule.soak_waves[1].not_before_elapsed_seconds = 1; },
    (value) => { value.id_provenance.request_id.authority = "runtime"; },
    (value) => { value.id_provenance.snapshot_id.derivation = "snapshot-{trial_id}"; },
    (value) => { delete value.execution_templates.seed_observe; },
    (value) => { delete value.execution_templates.post_trial_runtime_contract.feedback; },
    (value) => { value.execution_templates.trial_guide.response_assertions[2].path = "agent_context.agent_prompt"; },
    (value) => { value.execution_templates.renderer.missing_path_policy = "empty_string"; },
    (value) => { value.execution_templates.provider_request.request_template.messages[1].content.$concat.push({ $path: "scenario.expected_choice" }); },
    (value) => { value.execution_templates.provider_request.request_template.provider.allow_fallbacks = true; },
    (value) => { delete value.execution_templates.provider_request.request_template.provider.allow_fallbacks; },
    (value) => { value.execution_templates.provider_request.request_template.provider.require_parameters = false; },
    (value) => { delete value.execution_templates.provider_request.request_template.provider.require_parameters; },
    (value) => { value.execution_templates.provider_request.request_template.stream = true; },
    (value) => { delete value.execution_templates.provider_request.request_template.stream; },
    (value) => { value.execution_templates.provider_request.request_template.provider.order = ["unfrozen-provider"]; },
    (value) => { value.execution_templates.post_trial_runtime_contract.feedback.response_assertions[0].expected = "wrong"; },
    (value) => { value.execution_templates.post_trial_runtime_contract.measure.response_assertions[0].expected = "wrong"; },
    (value) => { value.execution_templates.post_trial_runtime_contract.operator_snapshot.route = "/wrong"; },
    (value) => { value.execution_templates.post_trial_runtime_contract.operator_snapshot.raw_response_capture.bytes_source = "parsed_json"; },
    (value) => { value.execution_templates.post_trial_runtime_contract.flight_recorder.request_template.product_trace.$path = "guide_response"; },
    (value) => { value.execution_templates.post_trial_runtime_contract.flight_recorder.raw_response_capture.capture_assertions[1].expected.$concat[0] = "wrong-"; },
  ];
  for (const mutate of mutations) {
    const value = copy(workload);
    mutate(value);
    assert.throws(() => validateWorkloadManifest(value, lock));
  }
});

test("finite workload renderer expands every executable request without hidden semantics", () => {
  const { lock, workload } = documents();
  const templates = workload.execution_templates;
  const scenario = workload.scenario_definitions[0];
  const campaignId = "campaign-renderer-v1";
  const harnessCommit = "a".repeat(40);
  const campaignScope = expandWorkloadScope(workload.schedule.scope.template, {
    harness_commit: harnessCommit,
    campaign_id: campaignId,
    scenario: scenario.id,
  });
  assert.equal(campaignScope, `bounded-soak:${harnessCommit}:${campaignId}:${scenario.id}`);

  const preclaim = {
    scope: campaignScope,
    guide_operation_id: "guide-operation-1",
    outcome_operation_id: "outcome-operation-1",
    feedback_operation_id: "feedback-operation-1",
    measure_operation_id: "measure-operation-1",
  };
  const guideResponse = {
    operation_id: preclaim.guide_operation_id,
    guide_trace_id: "guide-trace-1",
    agent_context: {
      prompt_text: "Use formula_b; formula_a is a failed branch.",
      use_now_memory_ids: ["memory-passed"],
      inspect_before_use_memory_ids: ["memory-summary"],
      do_not_use_memory_ids: ["memory-failed"],
    },
    guide_packet: { contract_version: "aionis_guide_packet_v1" },
  };
  const servedMemorySelection = selectWorkloadServedMemory(
    guideResponse,
    templates.post_trial_runtime_contract.feedback.served_memory_selection,
  );
  assert.deepEqual(servedMemorySelection, { surface: "use_now", ids: ["memory-passed"] });

  const baseContext = {
    campaign_id: campaignId,
    campaign_scope: campaignScope,
    group: "aionis",
    guide_response: guideResponse,
    preclaim,
    provider_response: { id: "provider-response-1" },
    release_lock: lock,
    scenario,
    schedule: workload.schedule,
    seed_observation: scenario.runtime_fixture.seed_observations[0],
    served_memory_selection: servedMemorySelection,
    tool_protocol: workload.tool_protocol,
    tool_result: {
      schema_version: "aionis_bounded_soak_tool_result_v1",
      scenario_id: scenario.id,
      choice: scenario.expected_choice,
      expected_choice: scenario.expected_choice,
      passed: true,
      unsafe_direct_use: false,
    },
    trial_id: "pilot-wave1-aionis-branch-recovery-r1",
  };

  const seedRequest = renderWorkloadTemplate(
    templates.seed_observe.request_variants.execution_tree.request_template,
    baseContext,
  );
  assert.equal(
    seedRequest.operation_id,
    `seed-${sha256(Buffer.from(`${campaignId}\0${scenario.id}\0passed_solution`))}`,
  );
  assert.equal(seedRequest.execution.raw_ref, scenario.runtime_fixture.seed_observations[0].raw_ref);
  assert.equal(seedRequest.execution.slots.execution_outcome_role, "passed_solution");
  assert.equal(seedRequest.execution.verification.status, "passed");

  const summaryScenario = workload.scenario_definitions[2];
  const summaryRequest = renderWorkloadTemplate(
    templates.seed_observe.request_variants.summary_only_memory.request_template,
    {
      ...baseContext,
      campaign_scope: expandWorkloadScope(workload.schedule.scope.template, {
        harness_commit: harnessCommit,
        campaign_id: campaignId,
        scenario: summaryScenario.id,
      }),
      scenario: summaryScenario,
      seed_observation: summaryScenario.runtime_fixture.seed_observations[0],
    },
  );
  assert.deepEqual(Object.keys(summaryRequest), templates.seed_observe.request_variants.summary_only_memory.request_exact_keys);
  assert.equal(Object.hasOwn(summaryRequest, "execution"), false);
  assert.match(summaryRequest.scope, /:summary_only_inspect$/);

  const guideRequest = renderWorkloadTemplate(templates.trial_guide.request_template, baseContext);
  assert.equal(guideRequest.operation_id, preclaim.guide_operation_id);
  const baselineProviderRequest = renderWorkloadTemplate(
    templates.provider_request.request_template,
    { ...baseContext, group: "baseline", guide_response: undefined },
  );
  assert.match(baselineProviderRequest.messages[1].content, /Allowed choices: formula_a, formula_b, unknown/);
  assert.doesNotMatch(baselineProviderRequest.messages[1].content, /Aionis execution context/);
  const longProviderRequest = renderWorkloadTemplate(
    templates.provider_request.request_template,
    { ...baseContext, group: "long_context", guide_response: undefined },
  );
  assert.match(longProviderRequest.messages[1].content, /Prior context:/);
  const aionisProviderRequest = renderWorkloadTemplate(templates.provider_request.request_template, baseContext);
  assert.match(aionisProviderRequest.messages[1].content, /Use formula_b/);
  assert.notStrictEqual(aionisProviderRequest.tools[0].function.parameters, workload.tool_protocol.function.arguments_schema);

  const outcomeRequest = renderWorkloadTemplate(
    templates.post_trial_runtime_contract.outcome_observe.request_template,
    baseContext,
  );
  assert.equal(outcomeRequest.execution.outcome, "succeeded");
  assert.equal(outcomeRequest.execution.slots.execution_outcome_role, "passed_solution");
  const feedbackRequest = renderWorkloadTemplate(
    templates.post_trial_runtime_contract.feedback.request_template,
    baseContext,
  );
  const feedbackResponse = {
    operation_id: preclaim.feedback_operation_id,
    learning_feedback_event_id: "feedback-event-1",
  };
  const measureRequest = renderWorkloadTemplate(
    templates.post_trial_runtime_contract.measure.request_template,
    { ...baseContext, feedback_response: feedbackResponse },
  );
  assert.equal(feedbackRequest.outcome, "positive");
  assert.equal(measureRequest.product_trace.baseline.continuity.continuityGuidanceCorrect, true);
  const snapshotRequest = renderWorkloadTemplate(
    templates.post_trial_runtime_contract.operator_snapshot.request_template,
    baseContext,
  );
  assert.deepEqual(Object.keys(snapshotRequest), templates.post_trial_runtime_contract.operator_snapshot.request_exact_keys);
  const flightRequest = renderWorkloadTemplate(
    templates.post_trial_runtime_contract.flight_recorder.request_template,
    {
      ...baseContext,
      feedback_response: feedbackResponse,
      measure_request: measureRequest,
      operator_snapshot_response: { operator_snapshot: { run_id: baseContext.trial_id } },
    },
  );
  assert.equal(flightRequest.operator_snapshot.run_id, baseContext.trial_id);

  const snapshotBytes = Buffer.from("{\"operator_snapshot\":true}\n", "utf8");
  const snapshotIdentity = captureWorkloadRawResponseIdentity("snapshot", baseContext.trial_id, snapshotBytes);
  assert.equal(snapshotIdentity.snapshot_response_sha256, sha256(snapshotBytes));
  const renderedSnapshotId = renderWorkloadTemplate(
    templates.post_trial_runtime_contract.operator_snapshot.raw_response_capture.capture_assertions[1].expected,
    { trial_id: baseContext.trial_id, snapshot_response_sha256: snapshotIdentity.snapshot_response_sha256 },
  );
  assert.equal(renderedSnapshotId, snapshotIdentity.snapshot_id);
  const recorderIdentity = captureWorkloadRawResponseIdentity("recorder", baseContext.trial_id, Buffer.from("recorder"));
  assert.match(recorderIdentity.recorder_response_sha256, /^[a-f0-9]{64}$/);
  assert.match(recorderIdentity.recorder_id, /^recorder-[a-f0-9]{64}$/);
});

test("finite workload renderer fails closed on missing paths, unknown operators, and invalid selection", () => {
  assert.throws(() => renderWorkloadTemplate({ $path: "missing.value" }, {}), /path is missing/);
  assert.throws(() => renderWorkloadTemplate({ $eval: "process.exit()" }, {}), /exactly one frozen operator/);
  assert.throws(() => renderWorkloadTemplate({ $concat: ["x", { $path: "object" }] }, { object: {} }), /accepts only/);
  assert.equal(
    renderWorkloadTemplate(
      { $if: { condition: true, then: "selected", else: { $path: "missing.value" } } },
      {},
    ),
    "selected",
  );
  assert.throws(() => expandWorkloadScope("scope:{campaign_id}", { wrong: "value" }), /keys must be exactly/);
  assert.throws(() => selectWorkloadServedMemory(
    { agent_context: { use_now_memory_ids: [], inspect_before_use_memory_ids: [], do_not_use_memory_ids: [] } },
    {
      ordered_surfaces: ["use_now", "inspect_before_use", "do_not_use"],
      id_fields: {
        use_now: "guide_response.agent_context.use_now_memory_ids",
        inspect_before_use: "guide_response.agent_context.inspect_before_use_memory_ids",
        do_not_use: "guide_response.agent_context.do_not_use_memory_ids",
      },
    },
  ), /no served memory IDs/);
});

test("release lock rejects extra fields and non-singleton returned-model allowlists", () => {
  const { lock } = documents();
  const extra = copy(lock);
  extra.unfrozen = true;
  assert.throws(() => validateReleaseLock(extra), /keys must be exactly/);
  const returned = copy(lock);
  returned.providers.agent.allowed_returned_models.push("another-model");
  assert.throws(() => validateReleaseLock(returned), /only the requested model/);
});

test("release lock binds the exact stable gate governance dependency set", () => {
  const { lock } = documents();
  assert.deepEqual(
    lock.stable_governance_artifacts.map((binding) => binding.path).sort(),
    [...STABLE_GOVERNANCE_PATHS].sort(),
  );
  const missing = copy(lock);
  missing.stable_governance_artifacts.pop();
  assert.throws(() => validateReleaseLock(missing), /exact stable gate dependency set/);
  const extra = copy(lock);
  extra.stable_governance_artifacts.push({ path: "scripts/ci/untrusted-extra.mjs", sha256: "f".repeat(64) });
  assert.throws(() => validateReleaseLock(extra), /exact stable gate dependency set/);
});

test("returned provider model must exactly match the frozen singleton", () => {
  const { authority } = documents();
  assert.equal(validateReturnedModel("deepseek/deepseek-v4-pro", authority), "deepseek/deepseek-v4-pro");
  assert.throws(() => validateReturnedModel("fallback-model", authority), /outside the frozen allowlist/);
});

test("secret-like provider material fails closed even without a familiar provider prefix", () => {
  const samples = [
    "sk-" + "x".repeat(24),
    "Authorization: Bearer " + "x".repeat(24),
    JSON.stringify({ api_key: "generic-value-that-is-long" }),
    JSON.stringify({ access_token: "generic-value-that-is-long" }),
    JSON.stringify({ authorization: "generic-value-that-is-long" }),
    JSON.stringify({ secret: "generic-value-that-is-long" }),
    JSON.stringify({ password: "correct-horse-battery-staple" }),
    JSON.stringify({ credential: "generic-value-that-is-long" }),
    JSON.stringify({ client_secret: "generic-value-that-is-long" }),
    JSON.stringify({ refresh_token: "generic-value-that-is-long" }),
    JSON.stringify({ private_key: "generic-value-that-is-long" }),
    JSON.stringify({ cookie: "generic-value-that-is-long" }),
    JSON.stringify({ session: "generic-value-that-is-long" }),
    "Set-Cookie: " + "x".repeat(24),
    "-----BEGIN PRIVATE KEY-----",
  ];
  for (const sample of samples) assert.throws(() => assertNoSecretMaterial(sample), /secret-like material/);
});

test("JSON schemas are strict Draft 2020-12 documents", () => {
  for (const file of [
    "schemas/authority-manifest.schema.json",
    "schemas/workload-manifest.schema.json",
    "schemas/artifact-bundle-manifest.schema.json",
    "schemas/workflow-run-evidence.schema.json",
  ]) {
    const schema = JSON.parse(fs.readFileSync(path.join(ROOT, file), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    assert.equal(schema.additionalProperties, false);
    assert.ok(Array.isArray(schema.required) && schema.required.length > 0);
    if (file === "schemas/workload-manifest.schema.json") {
      assert.equal(schema.$defs.execution_templates.additionalProperties, false);
      assert.equal(schema.$defs.execution_seed_observation.additionalProperties, false);
      assert.equal(schema.$defs.summary_seed_observation.additionalProperties, false);
      assert.equal(schema.$defs.raw_response_capture.additionalProperties, false);
    }
  }
});
