import { createPrivateKey, createPublicKey } from "node:crypto";

import {
  canonicalClone,
  canonicalSha256,
  sha256Bytes,
} from "../../src/canonical.mjs";
import { buildPilotCaseV1 } from "../../src/pilot-contract.mjs";
import {
  buildPriorEpisodeVerifiedStateEnvelopeV1,
  buildSignedPriorEpisodeVerifiedStateV1,
} from "../../src/prior-episode-evidence.mjs";
import { verifierPublicKeyPrincipalSha256V1 } from "../../src/verifier-evidence.mjs";

const TEST_PRIOR_EPISODE_PRIVATE_KEY = createPrivateKey({
  key: Buffer.from(
    "MC4CAQAwBQYDK2VwBCIEID7HJCGxZKQ8gCzx1hMt0BYYExsjYRTx6yaq+Okmpn4t",
    "base64",
  ),
  format: "der",
  type: "pkcs8",
});

function digest(label) {
  return canonicalSha256({ schema_version: "aionis_test_fixture_digest_v1", label });
}

export function buildTestObligationV1(caseId) {
  return {
    obligation_id: `${caseId}-required-state`,
    kind: "required_state",
    requirement: "hard",
    statement: "Recover the verifier-accepted state before acting.",
    target_refs: [{ kind: "memory", ref: `${caseId}-active-state` }],
    required_probe_ids: [],
    evidence_requirement: "runtime_state",
    source_refs: [`${caseId}:episode-1`],
  };
}

export function buildTestObservationBodyV1(caseId) {
  return {
    schema_version: "record_observations_body_v1",
    host_task: {
      host_task_id: `${caseId}-task`,
      episode_id: `${caseId}-episode`,
      run_id: `${caseId}-run`,
      consumer_agent_id: "pilot-test-agent",
      consumer_team_id: null,
      task_family: "coding",
      task_signature: `${caseId}-task-signature`,
      workflow_signature: null,
      workspace_signature: `${caseId}-workspace-signature`,
      source_task_sha256: digest(`${caseId}:source-task`),
      source_event_sha256: digest(`${caseId}:source-event`),
      issued_at: "2026-07-22T00:00:00.000Z",
      expires_at: "2026-07-23T00:00:00.000Z",
    },
    memory_inputs: [{
      memory_input_id: `${caseId}-verified-state`,
      kind: "verified_fact",
      applicability: {
        task_signature: `${caseId}-task-signature`,
        workflow_signature: null,
        workspace_signature: `${caseId}-workspace-signature`,
      },
      projection: {
        summary: "The prior verifier accepted the active state.",
        next_action: "Continue from the accepted state.",
        target_refs: [{ kind: "memory", ref: `${caseId}-active-state` }],
        workflow_steps: ["Inspect the accepted state."],
        acceptance_statements: ["The independent verifier accepts the result."],
      },
      coverage_claims: [{
        obligation_kind: "required_state",
        target_refs: [{ kind: "memory", ref: `${caseId}-active-state` }],
        evidence_requirement: "runtime_state",
        required_probe_ids: [],
      }],
      precondition_specs: [],
      evidence_observation_ids: [`${caseId}-observation`],
      expires_at: "2026-07-23T00:00:00.000Z",
    }],
    collector_observations: [{
      schema_version: "collector_observation_v1",
      observation_id: `${caseId}-observation`,
      probe_id: `${caseId}-probe`,
      probe_spec_sha256: digest(`${caseId}:probe-spec`),
      observed_at: "2026-07-22T00:00:00.000Z",
      expires_at: "2026-07-23T00:00:00.000Z",
      value: {
        kind: "capability",
        capability_id: `${caseId}-fixture-evidence`,
        version: "1.0.0",
        presence: "present",
      },
      evidence_sha256: digest(`${caseId}:observation-evidence`),
    }],
    signed_observations: [],
  };
}

export function buildTestPriorVerifiedStateV1(options) {
  const privateKey =
    options.verifierPrivateKey ?? TEST_PRIOR_EPISODE_PRIVATE_KEY;
  const priorEvidence = buildSignedPriorEpisodeVerifiedStateV1({
    case_id: options.caseId,
    episode_id: `${options.caseId}-episode-1`,
    observed_at: options.observedAt,
    source_kind: "preseeded_verified_state",
    source_fixture_sha256: options.fixtureSha256,
    source_task_sha256: options.sourceTaskSha256,
    seed_workspace_sha256: options.workspaceSha256,
    verified_workspace_sha256: digest(`${options.caseId}:verified-workspace`),
    verified_source_relative_path:
      options.verifiedSourceRelativePath ?? "src/continuation.mjs",
    verified_source_sha256: digest(`${options.caseId}:verified-source`),
    semantic_claim: {
      accepted_symbol: "acceptedState",
      rejected_symbol: "rejectedState",
    },
    verifier_process: {
      check_process_count: 1,
      execution_mode: "host_node_static_reader_subprocess_v1",
      fresh_process_per_check: true,
      target_source_imported: false,
      source_access: "static_read_only",
      node_executable_sha256: digest("test-prior-verifier-node"),
      verifier_check_set_sha256: digest(`${options.caseId}:prior-check-set`),
    },
    checks: [{
      check_id: "test-prior-state-static-check",
      configured_argv_sha256: digest(`${options.caseId}:prior-check-argv`),
      executed_argv_sha256: digest(`${options.caseId}:prior-check-executed-argv`),
      exit_code: 0,
      status: "passed",
      stdout_sha256: digest(`${options.caseId}:prior-check-stdout`),
      stderr_sha256: digest(`${options.caseId}:prior-check-stderr`),
    }],
    metrics: {
      accepted_direction: true,
      action_completion: true,
      rediscovery_steps: 0,
      unsafe_direct_use: false,
      wrong_branch_attention: false,
      wrong_branch_write: false,
    },
    verdict: "passed",
    failure_class: "none",
  }, privateKey);
  return buildPriorEpisodeVerifiedStateEnvelopeV1(
    priorEvidence,
    createPublicKey(privateKey),
  );
}

export function buildTestPilotCaseV1(options) {
  const caseId = options.caseId;
  const observationBody = canonicalClone(
    options.observationBody ?? buildTestObservationBodyV1(caseId),
  );
  const obligations = options.obligations ?? [buildTestObligationV1(caseId)];
  const fixtureSha256 = options.fixtureSha256 ?? digest(`${caseId}:fixture`);
  const workspaceSha256 = options.workspaceSha256 ?? digest(`${caseId}:workspace`);
  const priorVerifiedState = buildTestPriorVerifiedStateV1({
    caseId,
    observedAt: observationBody.host_task.issued_at,
    fixtureSha256,
    sourceTaskSha256: observationBody.host_task.source_task_sha256,
    verifierPrivateKey: options.verifierPrivateKey,
    verifiedSourceRelativePath: options.verifiedSourceRelativePath,
    workspaceSha256,
  });
  const sourceEvidenceSha256 = priorVerifiedState.signed_evidence_sha256;
  observationBody.host_task.source_event_sha256 = sourceEvidenceSha256;
  for (const observation of observationBody.collector_observations) {
    observation.evidence_sha256 = sourceEvidenceSha256;
  }
  const prompt = `Complete the frozen pilot task ${caseId}.`;
  const episodeEvents = [{
    schema_version: "aionis_pilot_episode_evidence_event_v1",
    event_id: `${caseId}-episode-event-1`,
    event_sequence: 1,
    event_kind: "verified_state",
    observed_at: observationBody.host_task.issued_at,
    source_evidence_sha256: sourceEvidenceSha256,
    statement: "The prior verifier accepted the active state.",
    target_refs: obligations[0].target_refs,
  }];
  const continuationTemplate = {
    schema_version: "aionis_create_continuation_template_v1",
    obligations,
    render_budget_bytes: 16_384,
  };
  return buildPilotCaseV1({
    case_id: caseId,
    source_fixture: {
      digest_encoding: "raw_bytes_sha256_v1",
      relative_path: `fixtures/v1/${caseId}.json`,
      fixture_sha256: fixtureSha256,
      trap_id: `${caseId}-trap`,
      source_evidence_sha256: sourceEvidenceSha256,
    },
    workspace: {
      repository_url: "https://github.com/example/project.git",
      base_commit_sha: "a".repeat(40),
      prepared_tree_encoding: "aionis_pilot_workspace_projection_v1",
      prepared_tree_sha256: workspaceSha256,
      clean_status_encoding: "git_status_porcelain_v1_z_sha256_v1",
      clean_status_sha256: digest(`${caseId}:clean-status`),
    },
    public_agent_input: {
      task_prompt: prompt,
      task_prompt_sha256: sha256Bytes(Buffer.from(prompt, "utf8")),
      workspace_projection_sha256: workspaceSha256,
      candidate_universe_sha256: digest(`${caseId}:candidate-universe`),
    },
    episode_1_evidence: {
      event_count: episodeEvents.length,
      event_stream: episodeEvents,
      event_stream_sha256: canonicalSha256(episodeEvents),
      prior_verified_state: priorVerifiedState,
      translation_contract_sha256: digest(`${caseId}:translation-contract`),
    },
    runtime_input: {
      record_observations_body: observationBody,
      record_observations_body_sha256: canonicalSha256(observationBody),
      obligations,
      obligation_set_sha256: canonicalSha256(obligations),
      create_continuation_template: continuationTemplate,
      create_continuation_template_sha256: canonicalSha256(continuationTemplate),
      render_budget_bytes: continuationTemplate.render_budget_bytes,
    },
    private_verifier: {
      verifier_id: `${caseId}-verifier`,
      verifier_contract_sha256:
        options.verifierContractSha256 ?? digest(`${caseId}:verifier-contract`),
      verifier_config_sha256:
        options.verifierConfigSha256 ?? digest(`${caseId}:verifier-config`),
      verifier_image_digest:
        options.verifierImageDigest ?? `sha256:${digest(`${caseId}:verifier-image`)}`,
      verifier_public_key_principal_sha256:
        verifierPublicKeyPrincipalSha256V1(options.verifierPublicKey),
      require_fresh_process: true,
      require_after_agent_exit: true,
    },
  });
}
