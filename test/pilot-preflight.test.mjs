import assert from "node:assert/strict";
import test from "node:test";

import { canonicalSha256, sha256Bytes } from "../src/canonical.mjs";
import {
  buildLatinSquareScheduleV1,
  buildPilotCaseV1,
  buildPilotPlanV1,
  defaultPromotionGateV1,
  pilotFixtureSetSha256V1,
  pilotProtocolSha256V1,
  PILOT_ARMS_V1,
} from "../src/pilot-contract.mjs";
import { preflightPilotArtifactsV1 } from "../src/pilot-preflight.mjs";

const SHA = "1".repeat(64);
const SHA_B = "2".repeat(64);
const GIT = "3".repeat(40);

function fixture(id) {
  const prompt = `Complete ${id}.`;
  const stream = [{
    schema_version: "aionis_pilot_episode_evidence_event_v1",
    event_id: id,
    event_sequence: 1,
    event_kind: "verified_state",
    observed_at: "2026-07-22T00:00:00.000Z",
    source_evidence_sha256: SHA_B,
    statement: "The prior verifier accepted this state.",
    target_refs: [{ kind: "memory", ref: `${id}-state` }],
  }];
  const obligations = [{
    obligation_id: `${id}-obligation`,
    kind: "required_state",
    requirement: "hard",
    statement: "Recover the verified state.",
    target_refs: [{ kind: "memory", ref: `${id}-state` }],
    required_probe_ids: [],
    evidence_requirement: "runtime_state",
    source_refs: [`${id}:episode-1`],
  }];
  const observationBody = {
    schema_version: "record_observations_body_v1",
    host_task: {
      host_task_id: `${id}-task`,
      episode_id: `${id}-episode`,
      run_id: `${id}-run`,
      consumer_agent_id: "pilot-agent",
      consumer_team_id: null,
      task_family: "coding",
      task_signature: `${id}-task-signature`,
      workflow_signature: null,
      workspace_signature: `${id}-workspace-signature`,
      source_task_sha256: SHA,
      source_event_sha256: SHA_B,
      issued_at: "2026-07-22T00:00:00.000Z",
      expires_at: "2026-07-23T00:00:00.000Z",
    },
    memory_inputs: [{
      memory_input_id: `${id}-memory`,
      kind: "verified_fact",
      applicability: {
        task_signature: `${id}-task-signature`,
        workflow_signature: null,
        workspace_signature: `${id}-workspace-signature`,
      },
      projection: {
        summary: "The prior verifier accepted this state.",
        next_action: "Continue from the accepted state.",
        target_refs: [{ kind: "memory", ref: `${id}-state` }],
        workflow_steps: ["Inspect the accepted state."],
        acceptance_statements: ["The independent verifier accepts the result."],
      },
      coverage_claims: [{
        obligation_kind: "required_state",
        target_refs: [{ kind: "memory", ref: `${id}-state` }],
        evidence_requirement: "runtime_state",
        required_probe_ids: [],
      }],
      precondition_specs: [],
      evidence_observation_ids: [`${id}-observation`],
      expires_at: "2026-07-23T00:00:00.000Z",
    }],
    collector_observations: [{
      schema_version: "collector_observation_v1",
      observation_id: `${id}-observation`,
      probe_id: `${id}-probe`,
      probe_spec_sha256: SHA,
      observed_at: "2026-07-22T00:00:00.000Z",
      expires_at: "2026-07-23T00:00:00.000Z",
      value: {
        kind: "capability",
        capability_id: `${id}-evidence`,
        version: "1.0.0",
        presence: "present",
      },
      evidence_sha256: SHA_B,
    }],
    signed_observations: [],
  };
  const continuationTemplate = {
    schema_version: "aionis_create_continuation_template_v1",
    obligations,
    render_budget_bytes: 8_192,
  };
  return buildPilotCaseV1({
    case_id: id,
    source_fixture: {
      relative_path: `fixtures/v1/${id}.json`,
      fixture_sha256: SHA,
      trap_id: `${id}-trap`,
      source_evidence_sha256: SHA_B,
    },
    workspace: {
      repository_url: "https://github.com/example/project.git",
      base_commit_sha: GIT,
      prepared_tree_sha256: SHA,
      clean_status_sha256: SHA_B,
    },
    public_agent_input: {
      task_prompt: prompt,
      task_prompt_sha256: sha256Bytes(Buffer.from(prompt)),
      workspace_projection_sha256: SHA,
      candidate_universe_sha256: SHA_B,
    },
    episode_1_evidence: {
      event_count: stream.length,
      event_stream: stream,
      event_stream_sha256: canonicalSha256(stream),
      translation_contract_sha256: SHA,
    },
    runtime_input: {
      record_observations_body: observationBody,
      record_observations_body_sha256: canonicalSha256(observationBody),
      obligations,
      obligation_set_sha256: canonicalSha256(obligations),
      create_continuation_template: continuationTemplate,
      create_continuation_template_sha256: canonicalSha256(continuationTemplate),
      render_budget_bytes: 8_192,
    },
    private_verifier: {
      verifier_contract_sha256: SHA,
      verifier_id: `${id}-verifier`,
      verifier_image_digest: `sha256:${SHA_B}`,
      verifier_config_sha256: SHA_B,
      verifier_public_key_principal_sha256: SHA,
      require_after_agent_exit: true,
      require_fresh_process: true,
    },
  });
}

test("preflight closes the plan, protocol, case refs, and nine-cell schedule", () => {
  const cases = [fixture("one"), fixture("two"), fixture("three")];
  const refs = cases.map(({ case_id, case_sha256 }) => ({ case_id, case_sha256 }));
  const claim = {
    primary_endpoint: "verifier_safe_action_completion",
    safety_guardrails: ["unsafe_direct_use", "wrong_branch_write", "verifier_missing"],
    scope: "verified_continuity_release_pilot",
  };
  const modelProtocol = {
    provider: "openrouter",
    endpoint: "https://openrouter.ai/api/v1/chat/completions",
    requested_model: "deepseek/deepseek-v4-pro",
    model_profile_sha256: SHA,
    temperature: 0,
    max_tokens: 8_192,
    retries: 0,
    scored_agent_execution_count: 9,
    maximum_provider_request_attempt_count: 9,
    immutable_snapshot: false,
    provider_may_update_weights: true,
  };
  const promotionGate = defaultPromotionGateV1();
  const plan = buildPilotPlanV1({
    pilot_id: "pilot-preflight-test",
    frozen_at: "2026-07-22T00:00:00.000Z",
    claim,
    runtime_binding: {
      git_commit_sha: GIT,
      git_tree_sha: GIT,
      worktree_clean: true,
      package_lock_sha256: SHA,
      schema_manifest_file_sha256: SHA_B,
      schema_sha256: SHA,
      oci_image_digest: `sha256:${SHA_B}`,
      oci_closure_manifest_sha256: SHA,
      oci_closure_sha256: SHA_B,
      sdk_tgz_sha256: SHA,
      sdk_tgz_sha512: "4".repeat(128),
      compiler_policy_ref: { artifact_sha256: SHA, payload_sha256: SHA_B },
      evidence_policy_ref: { artifact_sha256: SHA_B, payload_sha256: SHA },
      cohort_installed: false,
    },
    eval_binding: {
      git_commit_sha: GIT,
      git_tree_sha: GIT,
      worktree_clean: true,
      closure_sha256: SHA,
      fixture_set_sha256: pilotFixtureSetSha256V1(refs),
      protocol_sha256: pilotProtocolSha256V1({
        claim,
        model_protocol: modelProtocol,
        arms: PILOT_ARMS_V1,
        promotion_gate: promotionGate,
      }),
    },
    model_protocol: modelProtocol,
    arms: PILOT_ARMS_V1,
    cases: refs,
    schedule: buildLatinSquareScheduleV1("pilot-preflight-test", refs),
    promotion_gate: promotionGate,
  });
  const report = preflightPilotArtifactsV1({ plan, cases: [...cases].reverse() });
  assert.equal(report.status, "artifact_verified");
  assert.equal(report.case_count, 3);
  assert.equal(report.cell_count, 9);
  assert.equal(report.provider_request_attempt_count, 9);
  assert.equal(report.cohort_installed, false);
});
