import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { sha256 } from "../src/contracts.mjs";
import {
  verifyStablePromotion,
  workflowRunFetcherFromEvidenceFile,
} from "../src/stable-promotion.mjs";

const AUTHORITY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AUTHORITY_COMMIT = "a".repeat(40);

function writeJson(root, relativePath, value) {
  const absolute = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const source = `${JSON.stringify(value, null, 2)}\n`;
  fs.writeFileSync(absolute, source);
  return { path: relativePath, sha256: sha256(Buffer.from(source)), source };
}

function write(root, relativePath, source) {
  const absolute = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, source);
}

function git(root, ...args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function initRepository(prefix, origin) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.name", "Aionis Contract Test");
  git(root, "config", "user.email", "contract-test@example.invalid");
  git(root, "remote", "add", "origin", origin);
  return root;
}

function packageLock(version) {
  return {
    name: "@aionis/runtime-focused",
    version,
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { name: "@aionis/runtime-focused", version },
    },
  };
}

function runtimeManifest(version, status, defaultRef) {
  return {
    schema_version: "aionis_runtime_manifest_v1",
    behavior_contract: { routes: 21, schema: 6 },
    release: {
      version,
      status,
      source_tag: `v${version}`,
      github_repo: "ostinatocc/Aionis",
      docker_image: "ghcr.io/ostinatocc/aionis",
      docker_tag: `v${version}`,
      docker_platforms: ["linux/amd64"],
      default_installer_ref: defaultRef,
    },
  };
}

function workflowSource(runId, phase) {
  const publisher = phase === "publisher";
  return {
    repository: "ostinatocc/AionisRuntime-evals",
    run_id: runId,
    run_attempt: 1,
    head_sha: AUTHORITY_COMMIT,
    phase,
    job: publisher ? "evidence-publisher" : "paid-preflight",
    environment: publisher ? "bounded-soak-publisher" : "bounded-soak",
  };
}

function complexityBudget(threshold = 100) {
  return {
    schema_version: "aionis_runtime_complexity_budget_v4",
    baseline_commit: "b".repeat(40),
    intent: "Synthetic downward-ratchet contract fixture.",
    thresholds: {
      source_files: threshold,
      source_lines: threshold * 100,
      route_matrix_entries: 21,
      import_cycles: 0,
    },
  };
}

function artifactTrials(workload) {
  const trials = [];
  for (const phase of ["pilot", "soak"]) {
    const waves = phase === "pilot" ? 1 : workload.soak.waves;
    const repetitions = phase === "pilot"
      ? workload.pilot.repetitions_per_cell
      : workload.soak.repetitions_per_cell_per_wave;
    for (let wave = 1; wave <= waves; wave += 1) {
      for (const group of workload.groups) {
        for (const scenario of workload.scenarios) {
          for (let repetition = 1; repetition <= repetitions; repetition += 1) {
            trials.push({
              phase,
              wave,
              group,
              scenario,
              repetition,
              trial_id: `${phase}:w${wave}:${group}:${scenario}:r${repetition}`,
            });
          }
        }
      }
    }
  }
  return trials;
}

function artifactDocuments({ lock, workload, options }) {
  const trials = artifactTrials(workload);
  const sources = { pilot: workflowSource(1, "pilot"), soak: workflowSource(2, "soak") };
  const header = (kind) => ({
    schema_version: "aionis_soak_artifact_header_v1",
    kind,
    candidate: { commit: lock.candidate.commit, digest: lock.candidate.digest },
    harness_commit: AUTHORITY_COMMIT,
    source_workflows: options.artifactHeaderRunDrift
      ? { pilot: workflowSource(99, "pilot"), soak: sources.soak }
      : sources,
    providers: structuredClone(lock.providers),
    generation: structuredClone(lock.generation),
    retry_policy: structuredClone(lock.retry_policy),
    execution_limits: structuredClone(lock.execution_limits),
  });
  const source = (trial) => trial.phase === "pilot" ? sources.pilot : sources.soak;
  const failedTrialId = "soak:w2:aionis:branch_recovery:r3";
  const facts = new Map(trials.map((trial, index) => [trial.trial_id, {
    request_id: `request-${index + 1}-${trial.trial_id}`,
    operation_id: `operation-${index + 1}-${trial.trial_id}`,
    provider_request_id: `provider-request-${index + 1}-${trial.trial_id}`,
    request_sha256: sha256(Buffer.from(`request:${trial.trial_id}`)),
    response_sha256: sha256(Buffer.from(`response:${trial.trial_id}`)),
  }]));
  const api = trials.map((trial) => ({
    schema_version: "aionis_api_receipt_v2",
    trial_id: trial.trial_id,
    phase: trial.phase,
    wave: trial.wave,
    group: trial.group,
    scenario: trial.scenario,
    repetition: trial.repetition,
    source_run_id: source(trial).run_id,
    source_run_attempt: source(trial).run_attempt,
    ...facts.get(trial.trial_id),
    runtime_digest: lock.candidate.digest,
    http_status: 200,
    request_completed: true,
  }));
  if (options.artifactMissingTrial) api.pop();
  let unsafeInjected = false;
  const raw = trials.map((trial) => {
    const injectUnsafe = options.artifactUnsafeDirectUse
      && !unsafeInjected
      && trial.phase === "soak"
      && trial.group === "aionis"
      && trial.scenario === "negative_transfer";
    if (injectUnsafe) unsafeInjected = true;
    return {
      schema_version: "aionis_raw_agent_stream_v2",
      trial_id: trial.trial_id,
      phase: trial.phase,
      source_run_id: source(trial).run_id,
      source_run_attempt: source(trial).run_attempt,
      ...facts.get(trial.trial_id),
      requested_model: lock.providers.agent.requested_model,
      returned_model: lock.providers.agent.allowed_returned_models[0],
      fallback_used: false,
      generation: structuredClone(lock.generation),
      transport_attempts: 1,
      semantic_attempts: 1,
      provider_usage: {
        input_tokens: trial.group === "aionis" ? 10 : trial.group === "long_context" ? 20 : 15,
        output_tokens: 5,
        total_tokens: (trial.group === "aionis" ? 10 : trial.group === "long_context" ? 20 : 15) + 5,
        cost_microusd: 10_000,
      },
      memory_use_events: trial.group === "aionis"
        ? [{
            memory_id: `memory-${trial.trial_id}`,
            mode: injectUnsafe ? "direct" : "guided",
            adjudication: injectUnsafe ? "unsafe" : "safe",
          }]
        : [],
    };
  });
  const aionis = trials.filter((trial) => trial.group === "aionis");
  const operator = aionis.map((trial) => {
    const actionCompleted = options.artifactAllActionsPass || trial.trial_id !== failedTrialId;
    return {
      schema_version: "aionis_operator_snapshot_v2",
      trial_id: trial.trial_id,
      phase: trial.phase,
      source_run_id: source(trial).run_id,
      source_run_attempt: source(trial).run_attempt,
      snapshot_id: `snapshot-${trial.trial_id}`,
      operation_id: facts.get(trial.trial_id).operation_id,
      response_sha256: facts.get(trial.trial_id).response_sha256,
      terminal_state: actionCompleted ? "completed" : "failed",
      action_completed: actionCompleted,
      inspect_verified: true,
    };
  });
  const flight = aionis.map((trial) => ({
    schema_version: "aionis_flight_recorder_v2",
    trial_id: trial.trial_id,
    phase: trial.phase,
    source_run_id: source(trial).run_id,
    source_run_attempt: source(trial).run_attempt,
    recorder_id: `recorder-${trial.trial_id}`,
    operation_id: facts.get(trial.trial_id).operation_id,
    response_sha256: facts.get(trial.trial_id).response_sha256,
    outcome_id: `outcome-${trial.trial_id}`,
    feedback_id: `feedback-${trial.trial_id}`,
    measure_id: `measure-${trial.trial_id}`,
    replay_sha256: sha256(Buffer.from(`replay:${trial.trial_id}`)),
    outcome_verified: true,
    feedback_attributed: true,
    measure_recorded: true,
    exact_replay: true,
  }));
  const emptyBacklog = () => ({ dead_letter: 0, provider_mismatch: 0, exhausted: 0 });
  const durableState = sha256(Buffer.from("canonical durable worker state"));
  const worker = [
    ["pilot", sources.pilot, "none", "instance-0", "instance-0"],
    ["after_wave_1", sources.soak, workload.recovery.after_wave_1, "instance-0", "instance-1"],
    ["after_wave_2", sources.soak, workload.recovery.after_wave_2, "instance-1", "instance-2"],
    ["after_wave_3", sources.soak, workload.recovery.after_wave_3, "instance-2", "instance-2"],
  ].map(([checkpoint, workflow, recovery, beforeProcess, afterProcess]) => ({
    schema_version: "aionis_worker_state_v2",
    checkpoint,
    source_run_id: workflow.run_id,
    source_run_attempt: workflow.run_attempt,
    recovery,
    before_process_id: beforeProcess,
    after_process_id: afterProcess,
    before_state_sha256: durableState,
    after_state_sha256: durableState,
    checkpoint_passed: true,
    terminal_backlog: emptyBacklog(),
    worker_errors: 0,
  }));
  const sqlite = [{
    schema_version: "aionis_offline_sqlite_verify_v2",
    source_run_id: sources.soak.run_id,
    source_run_attempt: sources.soak.run_attempt,
    verified_after_wave: workload.soak.waves,
    database_sha256: sha256(Buffer.from("offline checkpointed sqlite bytes")),
    integrity_result: "ok",
    quick_check_result: "ok",
    aionis_trials_verified: workload.soak.total_aionis_trials,
    exact_replay_rows: workload.soak.total_aionis_trials,
    product_invariants: workload.product_invariants.map((name) => ({
      name,
      passed: true,
      query_sha256: sha256(Buffer.from(`query:${name}`)),
      result_sha256: sha256(Buffer.from(`result:${name}`)),
    })),
  }];
  if (options.rawRequestJoinDrift) raw[0].request_id = "drifted-request-id";
  if (options.duplicateProviderRequest) raw[1].provider_request_id = raw[0].provider_request_id;
  if (options.providerUsageDrift) raw[0].provider_usage.total_tokens += 1;
  if (options.runtimeDigestDrift) api[0].runtime_digest = `sha256:${"0".repeat(64)}`;
  if (options.operatorOperationDrift) operator[0].operation_id = "drifted-operation-id";
  if (options.recoveryProcessDrift) worker[1].after_process_id = worker[1].before_process_id;
  if (options.recoveryStateDrift) worker[2].after_state_sha256 = "f".repeat(64);
  if (options.sqliteResultDrift) sqlite[0].quick_check_result = "corrupt";
  const records = {
    api_receipts: api,
    flight_recorder: flight,
    offline_sqlite_verify: sqlite,
    operator_snapshots: operator,
    raw_agent_streams: raw,
    worker_state: worker,
  };
  const documents = new Map();
  for (const kind of lock.artifact_contract.required_kinds) {
    const lines = options.meaninglessArtifact && kind === "api_receipts"
      ? [header(kind), { sanitized: true }]
      : [header(kind), ...records[kind]];
    documents.set(kind, Buffer.from(`${lines.map((line) => JSON.stringify(line)).join("\n")}\n`));
  }
  return documents;
}

function createFixture(options = {}) {
  const createRoot = initRepository("aionis-create-fixture-", "https://github.com/ostinatocc/aionis-create.git");
  writeJson(createRoot, "package.json", { name: "@aionis/create", version: "0.3.9" });
  const createDefault = options.wrongCreateDefault || options.commentFakeDefault ? "v0.3.12" : "v0.3.13";
  const commentFake = options.commentFakeDefault ? "/* export const DEFAULT_RUNTIME_REF = \"v0.3.13\"; */\n" : "";
  write(createRoot, "src/index.ts", `${commentFake}export const DEFAULT_RUNTIME_REF = "${createDefault}";\n`);
  git(createRoot, "add", ".");
  git(createRoot, "commit", "-q", "-m", "fixture create");
  const createCommit = git(createRoot, "rev-parse", "HEAD");
  git(createRoot, "tag", "-a", "v0.3.9", "-m", "fixture create v0.3.9");

  const runtimeRoot = initRepository("aionis-runtime-fixture-", "https://github.com/ostinatocc/Aionis.git");
  const lock = structuredClone(JSON.parse(fs.readFileSync(path.join(AUTHORITY_ROOT, "config/v0.3.12-release-lock.json"), "utf8")));
  const candidateCreate = {
    name: "@aionis/create",
    version: "0.3.8",
    source_ref: "v0.3.8",
    source_commit: "c".repeat(40),
    repository: "https://github.com/ostinatocc/aionis-create.git",
    package_path: ".",
  };
  const candidateTrain = {
    schema_version: "aionis_release_train_v1",
    status: "candidate",
    runtime: {
      version: "0.3.12",
      source_tag: "v0.3.12",
      docker_image: "ghcr.io/ostinatocc/aionis",
      docker_tag: "v0.3.12",
      docker_platforms: ["linux/amd64"],
      default_installer_ref: "v0.3.6",
    },
    packages: { create: candidateCreate },
  };
  writeJson(runtimeRoot, "package.json", { name: "@aionis/runtime-focused", version: "0.3.12", private: true });
  writeJson(runtimeRoot, "package-lock.json", packageLock("0.3.12"));
  writeJson(runtimeRoot, "runtime-manifest.json", runtimeManifest("0.3.12", "candidate", "v0.3.6"));
  writeJson(runtimeRoot, "release-train.json", candidateTrain);
  writeJson(runtimeRoot, "docs/architecture/runtime-complexity-budget.json", complexityBudget());
  for (const [index, binding] of lock.stable_governance_artifacts.entries()) {
    const source = `frozen synthetic governance artifact ${index}: ${binding.path}\n`;
    write(runtimeRoot, binding.path, source);
    binding.sha256 = sha256(Buffer.from(source));
  }
  write(runtimeRoot, "src/runtime.ts", "export const runtimeBehavior = 'frozen';\n");
  git(runtimeRoot, "add", ".");
  git(runtimeRoot, "commit", "-q", "-m", "candidate");
  const candidateCommit = git(runtimeRoot, "rev-parse", "HEAD");
  git(runtimeRoot, "tag", "-a", "v0.3.12", "-m", "candidate v0.3.12");
  const candidateTagObject = git(runtimeRoot, "rev-parse", "refs/tags/v0.3.12^{tag}");

  Object.assign(lock.candidate, {
    commit: candidateCommit,
    oci_revision: candidateCommit,
  });
  const publication = {
    schema_version: "aionis_release_publication_evidence_v1",
    release_status: "candidate",
    runtime: { version: "0.3.12", tag: "v0.3.12", tag_object_oid: candidateTagObject, commit: candidateCommit },
    main_ci: { conclusion: "success", head_sha: candidateCommit },
    provider_evidence: {
      conclusion: "success",
      head_sha: candidateCommit,
      provider: lock.providers.embedding.provider,
      model: lock.providers.embedding.model,
      persisted_model: lock.providers.embedding.persisted_model,
      dimensions: lock.providers.embedding.dimensions,
      embedding_status: "ready",
    },
    docker: {
      image: lock.candidate.image,
      release_tag: lock.candidate.tag,
      digest: lock.candidate.digest,
      platforms: [lock.candidate.platform],
      latest_promoted: false,
      latest_at_verification: {
        tag: "latest",
        digest: `sha256:${"d".repeat(64)}`,
        version: "v0.3.6",
        commit: "e".repeat(40),
        platform: "linux/amd64",
      },
      source_workflow: {
        conclusion: "success",
        head_branch: "v0.3.12",
        head_sha: candidateCommit,
        completed_exact_digest_gates: {
          build: true,
          immutable_subject_verification: true,
          release_smoke: true,
          process_death_recovery: true,
          cross_version_upgrade: true,
          release_tag_promotion: true,
        },
      },
    },
    github_release: {
      target_commitish: candidateCommit,
      prerelease: true,
      latest: false,
      draft: false,
      published_at: "2026-07-20T13:00:00.000Z",
    },
  };
  const publicationDocument = writeJson(runtimeRoot, "docs/releases/v0.3.12-publication-evidence.json", publication);
  lock.candidate_publication_receipt = { path: publicationDocument.path, sha256: publicationDocument.sha256 };

  const authority = structuredClone(JSON.parse(fs.readFileSync(path.join(AUTHORITY_ROOT, "fixtures/v0.3.12/authority-manifest.json"), "utf8")));
  authority.candidate = structuredClone(lock.candidate);
  authority.candidate_publication_receipt = structuredClone(lock.candidate_publication_receipt);
  const authorityDocument = writeJson(runtimeRoot, "docs/releases/v0.3.12-soak-authority-manifest.json", authority);
  const workload = JSON.parse(fs.readFileSync(path.join(AUTHORITY_ROOT, "fixtures/v0.3.12/workload-manifest.json"), "utf8"));
  const workloadDocument = writeJson(runtimeRoot, "docs/releases/v0.3.12-soak-workload-manifest.json", workload);
  lock.protocol_artifacts.authority_manifest.sha256 = authorityDocument.sha256;
  lock.protocol_artifacts.workload_manifest.sha256 = workloadDocument.sha256;

  const artifactGeneratedAt = "2026-07-21T15:05:00.000Z";
  const releaseTag = `soak-v0.3.12-${AUTHORITY_COMMIT}`;
  const artifactDocumentsByKind = artifactDocuments({ lock, workload, options });
  const artifactPayloads = new Map();
  const entries = lock.artifact_contract.required_kinds.map((kind) => {
    const payload = artifactDocumentsByKind.get(kind);
    const hash = sha256(payload);
    const entry = {
      kind,
      uri: `${lock.artifact_contract.release_repository}/releases/download/${releaseTag}/${kind}-${hash}.jsonl`,
      sha256: hash,
      bytes: payload.byteLength,
    };
    artifactPayloads.set(entry.uri, payload);
    return entry;
  });
  const artifact = {
    schema_version: "aionis_soak_artifact_bundle_manifest_v1",
    generated_at: artifactGeneratedAt,
    candidate: { commit: candidateCommit, digest: lock.candidate.digest },
    harness_commit: AUTHORITY_COMMIT,
    source_workflow: workflowSource(2, "soak"),
    publisher_workflow: workflowSource(2, "publisher"),
    entries,
  };
  const artifactDocument = writeJson(runtimeRoot, "docs/releases/v0.3.12-soak-artifact-bundle-manifest.json", artifact);

  const wavePasses = options.wavePasses ?? [9, 8, 9];
  const waves = wavePasses.map((passed, index) => ({
    index: index + 1,
    semantic_chat_calls: 27,
    aionis_action_completion: { passed, total: 9 },
    wrong_direct_use: 0,
    ...(!options.missingNegativeDirectUse || index !== 0 ? {
      negative_direct_use: {
        unsafe_direct_uses: options.negativeDirectUseUnsafe?.[index] ?? 0,
        total: options.negativeDirectUseWaveTotals?.[index] ?? 3,
      },
    } : {}),
  }));
  const soak = {
    schema_version: "aionis_release_bounded_soak_evidence_v1",
    generated_at: "2026-07-21T15:10:00.000Z",
    authority: { decision: "pass", publication_authority: false },
    candidate_publication_receipt: structuredClone(lock.candidate_publication_receipt),
    candidate: {
      version: lock.candidate.version,
      tag: lock.candidate.tag,
      commit: candidateCommit,
      image: lock.candidate.image,
      digest: lock.candidate.digest,
      platform: lock.candidate.platform,
      oci_revision: candidateCommit,
      oci_version: lock.candidate.tag,
    },
    harness: { repository: "https://github.com/ostinatocc/AionisRuntime-evals", commit: AUTHORITY_COMMIT, real_tools: true, deterministic_outcome_verifier: true },
    providers: {
      embedding: structuredClone(lock.providers.embedding),
      agent: { provider: "openrouter", requested_model: "deepseek/deepseek-v4-pro", returned_models: ["deepseek/deepseek-v4-pro"], fallback_used: options.modelFallback === true },
    },
    protocol: {
      authority_manifest: { path: authorityDocument.path, sha256: authorityDocument.sha256 },
      authority_manifest_sha256: authorityDocument.sha256,
      workload_manifest: { path: workloadDocument.path, sha256: workloadDocument.sha256 },
      workload_manifest_sha256: workloadDocument.sha256,
      artifact_bundle_manifest: { path: artifactDocument.path, sha256: artifactDocument.sha256 },
      artifact_bundle_sha256: artifactDocument.sha256,
      groups: structuredClone(lock.protocol.groups),
      scenarios: structuredClone(lock.protocol.scenarios),
      product_invariants: structuredClone(lock.protocol.product_invariants),
      pilot_chat_calls: 9,
      soak_chat_calls: 81,
      soak_waves: 3,
    },
    pilot: {
      passed: true,
      aionis_action_completion: { passed: 3, total: 3 },
      wrong_direct_use: 0,
      failed_direct_use: 0,
      semantic_chat_calls: 9,
      negative_direct_use: { unsafe_direct_uses: 0, total: 1 },
      inspect_coverage: { passed: 3, total: 3 },
      outcome_coverage: { passed: 3, total: 3 },
      feedback_coverage: { passed: 3, total: 3 },
      measure_coverage: { passed: 3, total: 3 },
      durable_exact_replay: { passed: 3, total: 3 },
      terminal_backlog: { dead_letter: 0, provider_mismatch: 0, exhausted: 0 },
      semantic_retries: 0,
      worker_errors: 0,
      cost_usd: 0.09,
      started_at: "2026-07-20T14:35:00.000Z",
      completed_at: "2026-07-20T14:45:00.000Z",
      source_workflow: workflowSource(1, "pilot"),
    },
    waves,
    results: {
      aionis_action_completion: { passed: options.aggregatePassed ?? 26, total: 27 },
      inspect_coverage: { passed: 27, total: 27 },
      product_invariants: options.productInvariantMetric ?? { passed: 5, total: 5 },
      restart_recovery: options.restartRecoveryMetric ?? { passed: 3, total: 3 },
      outcome_coverage: { passed: 27, total: 27 },
      feedback_coverage: { passed: 27, total: 27 },
      measure_coverage: { passed: 27, total: 27 },
      durable_exact_replay: { passed: 27, total: 27 },
      negative_direct_use: {
        unsafe_direct_uses: options.aggregateNegativeDirectUseUnsafe ?? 0,
        total: options.aggregateNegativeDirectUseTotal ?? 9,
      },
      wrong_direct_use: 0,
      terminal_backlog: { dead_letter: options.deadLetter ?? 0, provider_mismatch: 0, exhausted: 0 },
      graceful_replacement_recovery: true,
      sigkill_replacement_recovery: true,
      offline_sqlite_verify: true,
      semantic_retries: 0,
      worker_errors: 0,
      context_tokens: options.negativeContext
        ? { aionis: -2, full_history: -1 }
        : { aionis: 270, full_history: 540 },
    },
    execution: {
      started_at: "2026-07-20T15:00:00.000Z",
      completed_at: "2026-07-21T15:00:00.000Z",
      limits: structuredClone(lock.execution_limits),
      observed: {
        duration_seconds: 86400,
        chat_calls: 81,
        campaign_chat_calls: 90,
        planned_waves: 3,
        completed_waves: 3,
        cost_usd: 0.81,
        campaign_cost_usd: 0.9,
      },
      persistent_volume: true,
      source_workflow: workflowSource(2, "soak"),
    },
    critical_incidents: [],
  };
  const soakDocument = writeJson(runtimeRoot, "docs/releases/v0.3.12-bounded-soak-evidence.json", soak);

  const stableTrain = structuredClone(candidateTrain);
  stableTrain.schema_version = "aionis_release_train_v2";
  stableTrain.status = "stable";
  Object.assign(stableTrain.runtime, { version: "0.3.13", source_tag: "v0.3.13", docker_tag: "v0.3.13", default_installer_ref: "v0.3.13" });
  stableTrain.packages.create = {
    ...candidateCreate,
    version: "0.3.9",
    source_ref: "v0.3.9",
    source_commit: createCommit,
  };
  stableTrain.stable_promotion = {
    schema_version: "aionis_stable_promotion_authority_v1",
    verifier: {
      repository: "https://github.com/ostinatocc/AionisRuntime-evals.git",
      source_ref: AUTHORITY_COMMIT,
      source_commit: AUTHORITY_COMMIT,
      verifier_path: "scripts/verify-stable-promotion.mjs",
    },
    candidate_publication: structuredClone(lock.candidate_publication_receipt),
    bounded_soak: { path: soakDocument.path, sha256: options.wrongSoakHash ? "f".repeat(64) : soakDocument.sha256 },
  };
  writeJson(runtimeRoot, "package.json", { name: "@aionis/runtime-focused", version: "0.3.13", private: true });
  writeJson(runtimeRoot, "package-lock.json", packageLock("0.3.13"));
  writeJson(runtimeRoot, "runtime-manifest.json", runtimeManifest("0.3.13", "stable", "v0.3.13"));
  writeJson(runtimeRoot, "release-train.json", stableTrain);
  if (options.complexityIncrease) writeJson(runtimeRoot, "docs/architecture/runtime-complexity-budget.json", complexityBudget(101));
  if (options.governanceDrift) write(runtimeRoot, lock.stable_governance_artifacts[0].path, "changed governance artifact\n");
  if (options.unboundReleaseDocument) writeJson(runtimeRoot, "docs/releases/unbound.json", { unbound: true });
  if (options.runtimeDrift) write(runtimeRoot, "src/runtime.ts", "export const runtimeBehavior = 'changed';\n");
  git(runtimeRoot, "add", ".");
  git(runtimeRoot, "commit", "-q", "-m", "stable promotion");
  const stableCommit = git(runtimeRoot, "rev-parse", "HEAD");
  git(runtimeRoot, "tag", "-a", "v0.3.13", "-m", "stable v0.3.13");
  git(runtimeRoot, "update-ref", "refs/remotes/origin/main", stableCommit);

  const lockPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aionis-lock-fixture-")), "release-lock.json");
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  if (options.corruptArtifact) {
    const first = entries[0];
    artifactPayloads.set(first.uri, Buffer.from("corrupt-but-same-contract\n"));
  }
  const workflowRuns = new Map([
    ["pilot", {
      run: {
        id: 1,
        run_attempt: 1,
        event: "workflow_dispatch",
        status: "completed",
        conclusion: "success",
        head_sha: AUTHORITY_COMMIT,
        repository: { full_name: "ostinatocc/AionisRuntime-evals" },
        path: options.workflowPathRef ? ".github/workflows/bounded-soak.yml@refs/heads/main" : ".github/workflows/bounded-soak.yml",
        created_at: "2026-07-20T14:15:00.000Z",
        updated_at: "2026-07-20T14:55:00.000Z",
      },
      jobs: [{
        id: 101,
        run_id: 1,
        run_attempt: 1,
        head_sha: AUTHORITY_COMMIT,
        name: "Protected pilot preflight",
        status: "completed",
        conclusion: "success",
        labels: ["self-hosted", "linux", "x64", "aionis-soak-persistent"],
        runner_id: 501,
        runner_group_name: "aionis-soak",
        started_at: "2026-07-20T14:30:00.000Z",
        completed_at: "2026-07-20T14:50:00.000Z",
      }],
    }],
    ["soak", {
      run: {
        id: 2,
        run_attempt: 1,
        event: "workflow_dispatch",
        status: "completed",
        conclusion: options.workflowFailure ? "failure" : "success",
        head_sha: AUTHORITY_COMMIT,
        repository: { full_name: "ostinatocc/AionisRuntime-evals" },
        path: options.workflowPathRef ? ".github/workflows/bounded-soak.yml@refs/heads/main" : ".github/workflows/bounded-soak.yml",
        created_at: "2026-07-20T14:55:00.000Z",
        updated_at: "2026-07-21T15:20:00.000Z",
      },
      jobs: [{
        id: 201,
        run_id: 2,
        run_attempt: 1,
        head_sha: AUTHORITY_COMMIT,
        name: "Protected soak preflight",
        status: "completed",
        conclusion: "success",
        labels: ["self-hosted", "linux", "x64", "aionis-soak-persistent"],
        runner_id: 501,
        runner_group_name: "aionis-soak",
        started_at: options.soakWindowDrift ? "2026-07-20T15:05:00.000Z" : "2026-07-20T14:58:00.000Z",
        completed_at: "2026-07-21T15:15:00.000Z",
      }],
    }],
    ["publisher", {
      run: {
        id: 2,
        run_attempt: 1,
        event: "workflow_dispatch",
        status: "completed",
        conclusion: options.workflowFailure ? "failure" : "success",
        head_sha: AUTHORITY_COMMIT,
        repository: { full_name: "ostinatocc/AionisRuntime-evals" },
        path: options.workflowPathRef ? ".github/workflows/bounded-soak.yml@refs/heads/main" : ".github/workflows/bounded-soak.yml",
        created_at: "2026-07-20T14:55:00.000Z",
        updated_at: "2026-07-21T15:20:00.000Z",
      },
      jobs: [{
        id: 202,
        run_id: 2,
        run_attempt: 1,
        head_sha: AUTHORITY_COMMIT,
        name: "Protected evidence publisher",
        status: "completed",
        conclusion: "success",
        labels: ["ubuntu-24.04"],
        runner_id: 502,
        runner_group_name: "GitHub Actions",
        started_at: "2026-07-21T15:16:00.000Z",
        completed_at: "2026-07-21T15:19:00.000Z",
      }],
    }],
  ]);
  const assets = entries.map((entry, index) => ({
    id: 1_000 + index,
    name: path.posix.basename(new URL(entry.uri).pathname),
    size: entry.bytes,
    digest: options.assetDigestDrift && index === 0 ? `sha256:${"0".repeat(64)}` : `sha256:${entry.sha256}`,
    state: "uploaded",
    created_at: options.assetWindowDrift && index === 0 ? "2026-07-21T15:15:30.000Z" : "2026-07-21T15:16:30.000Z",
    updated_at: "2026-07-21T15:18:00.000Z",
    uploader: "github-actions[bot]",
    download_url: entry.uri,
  }));
  const release = {
    id: 900,
    tag_name: releaseTag,
    target_commitish: options.releaseTargetDrift ? "b".repeat(40) : AUTHORITY_COMMIT,
    draft: false,
    prerelease: true,
    immutable: options.mutableRelease !== true,
    created_at: "2026-07-21T15:16:10.000Z",
    published_at: "2026-07-21T15:18:30.000Z",
    author: "github-actions[bot]",
  };
  const artifacts = entries.map((entry, index) => ({
    id: 2_000 + index,
    name: options.artifactNameDrift && index === 0
      ? `soak-${entry.kind}-wrong-name`
      : `soak-${entry.kind}-${AUTHORITY_COMMIT}-2-1-${entry.sha256}`,
    size_in_bytes: entry.bytes + 512,
    digest: `sha256:${(index + 1).toString(16).padStart(64, "0")}`,
    expired: options.artifactExpired === true && index === 0,
    created_at: "2026-07-21T15:06:00.000Z",
    updated_at: "2026-07-21T15:10:00.000Z",
    expires_at: options.artifactExpired && index === 0
      ? "2026-07-21T15:11:00.000Z"
      : "2026-10-19T15:10:00.000Z",
    workflow_run_id: options.artifactWrongRun && index === 0 ? 3 : 2,
    workflow_run_head_sha: AUTHORITY_COMMIT,
  }));
  return {
    runtimeRoot,
    createRoot,
    candidateCommit,
    stableCommit,
    lockPath,
    artifactPayloads,
    workflowRuns,
    release,
    artifacts,
    assets,
  };
}

function verify(fixture) {
  return verifyStablePromotion({
    runtimeRoot: fixture.runtimeRoot,
    createRoot: fixture.createRoot,
    expectedRuntimeCommit: fixture.stableCommit,
    authorityRoot: AUTHORITY_ROOT,
    authorityCommit: AUTHORITY_COMMIT,
    releaseLockPath: fixture.lockPath,
    workflowRunFetcher: async (source) => fixture.workflowRuns.get(source.phase),
    artifactProvenanceFetcher: async () => ({
      fetched_at: "2026-07-21T15:21:00.000Z",
      release: structuredClone(fixture.release),
      artifacts: structuredClone(fixture.artifacts),
      assets: structuredClone(fixture.assets),
    }),
    artifactFetcher: async (entry) => fixture.artifactPayloads.get(entry.uri),
  });
}

function workflowEvidence(fixture) {
  return {
    schema_version: "aionis_workflow_run_evidence_v1",
    repository: "ostinatocc/AionisRuntime-evals",
    fetched_at: "2026-07-21T15:21:00.000Z",
    records: [
      [workflowSource(1, "pilot"), fixture.workflowRuns.get("pilot")],
      [workflowSource(2, "soak"), fixture.workflowRuns.get("soak")],
      [workflowSource(2, "publisher"), fixture.workflowRuns.get("publisher")],
    ].map(([source, result]) => ({
      source,
      run: { ...result.run, repository: result.run.repository.full_name },
      job: result.jobs[0],
    })),
    release: structuredClone(fixture.release),
    artifacts: structuredClone(fixture.artifacts),
    assets: structuredClone(fixture.assets),
  };
}

test("stable verifier accepts a real annotated-tag, first-parent, no-drift fixture", async () => {
  const fixture = createFixture();
  const result = await verify(fixture);
  assert.deepEqual(result, {
    schema_version: "aionis_stable_promotion_verification_v1",
    ok: true,
    status: "stable",
    stable_commit: fixture.stableCommit,
    authority_commit: AUTHORITY_COMMIT,
    candidate_tag: "v0.3.12",
    candidate_commit: fixture.candidateCommit,
    candidate_digest: "sha256:f40c5a1f14af23674fab5e59414bbe4187a0d56dcf8a2798afd02c1563c4a5d6",
    expected_previous_latest: {
      tag: "latest",
      digest: `sha256:${"d".repeat(64)}`,
      version: "v0.3.6",
      commit: "e".repeat(40),
      platform: "linux/amd64",
    },
  });
});

test("sanitized workflow evidence supplies exact run/job facts without exposing a token", async () => {
  const fixture = createFixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aionis-workflow-evidence-"));
  const evidencePath = path.join(root, "workflow-evidence.json");
  fs.writeFileSync(evidencePath, `${JSON.stringify(workflowEvidence(fixture), null, 2)}\n`, { mode: 0o600 });
  const fetcher = workflowRunFetcherFromEvidenceFile(evidencePath);
  const result = await fetcher(workflowSource(1, "pilot"));
  assert.equal(result.run.id, 1);
  assert.equal(result.jobs[0].name, "Protected pilot preflight");
  const provenance = await fetcher.artifactProvenanceFetcher();
  assert.equal(provenance.release.immutable, true);
  assert.equal(provenance.artifacts.length, 6);
  assert.equal(provenance.assets.length, 6);

  const invalid = workflowEvidence(fixture);
  invalid.records[0].source.run_id = 2;
  const invalidPath = path.join(root, "invalid.json");
  fs.writeFileSync(invalidPath, `${JSON.stringify(invalid, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => workflowRunFetcherFromEvidenceFile(invalidPath), /run identity|duplicate/);
  const permissivePath = path.join(root, "permissive.json");
  fs.writeFileSync(permissivePath, `${JSON.stringify(workflowEvidence(fixture), null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(permissivePath, 0o644);
  assert.throws(() => workflowRunFetcherFromEvidenceFile(permissivePath), /permissions must be 0600/);

  const cli = spawnSync(process.execPath, [
    path.join(AUTHORITY_ROOT, "scripts/verify-stable-promotion.mjs"),
    "--runtime-root", fixture.runtimeRoot,
    "--create-root", fixture.createRoot,
    "--expected-runtime-commit", fixture.stableCommit,
  ], { cwd: AUTHORITY_ROOT, encoding: "utf8" });
  assert.notEqual(cli.status, 0);
  assert.match(cli.stderr, /--workflow-evidence is required/);
});

test("stable verifier rejects lightweight candidate tags", async () => {
  const fixture = createFixture();
  git(fixture.runtimeRoot, "tag", "-d", "v0.3.12");
  git(fixture.runtimeRoot, "tag", "v0.3.12", fixture.candidateCommit);
  await assert.rejects(() => verify(fixture), /candidate tag type/);
});

test("stable verifier rejects Runtime behavior drift outside the allowlist", async () => {
  await assert.rejects(() => verify(createFixture({ runtimeDrift: true })), /Runtime behavior changed after soak/);
  await assert.rejects(() => verify(createFixture({ unboundReleaseDocument: true })), /Runtime behavior changed after soak/);
});

test("stable verifier freezes governance callers and ratchets complexity downward", async () => {
  await assert.rejects(() => verify(createFixture({ governanceDrift: true })), /stable governance artifact .* raw hash mismatch/);
  await assert.rejects(() => verify(createFixture({ complexityIncrease: true })), /complexity budget threshold .* moved upward/);
});

test("stable verifier rejects Create default drift", async () => {
  await assert.rejects(() => verify(createFixture({ wrongCreateDefault: true })), /Create default Runtime ref/);
  await assert.rejects(() => verify(createFixture({ commentFakeDefault: true })), /Create default Runtime ref/);
});

test("stable verifier rejects model fallback and non-zero terminal backlog", async () => {
  await assert.rejects(() => verify(createFixture({ modelFallback: true })), /Agent provider/);
  await assert.rejects(() => verify(createFixture({ deadLetter: 1 })), /recovery, backlog, and incident/);
});

test("stable verifier rejects raw bounded receipt hash drift", async () => {
  await assert.rejects(() => verify(createFixture({ wrongSoakHash: true })), /raw hash mismatch/);
});

test("stable verifier verifies the real workflow run and downloaded artifact bytes", async () => {
  await assert.rejects(() => verify(createFixture({ workflowFailure: true })), /source workflow run/);
  await assert.rejects(() => verify(createFixture({ soakWindowDrift: true })), /soak execution was not contained/);
  await assert.rejects(() => verify(createFixture({ corruptArtifact: true })), /byte length mismatch|SHA-256 mismatch|exceeds its declared/);
});

test("stable verifier binds producer artifacts and publisher assets to the exact run", async () => {
  await assert.doesNotReject(() => verify(createFixture({ workflowPathRef: true })));
  await assert.rejects(() => verify(createFixture({ artifactWrongRun: true })), /workflow ownership/);
  await assert.rejects(() => verify(createFixture({ artifactExpired: true })), /is expired/);
  await assert.rejects(() => verify(createFixture({ artifactNameDrift: true })), /content-addressed .* upload/);
  await assert.rejects(() => verify(createFixture({ assetDigestDrift: true })), /release asset .* server metadata/);
  await assert.rejects(() => verify(createFixture({ assetWindowDrift: true })), /protected publisher job/);
  await assert.rejects(() => verify(createFixture({ mutableRelease: true })), /immutable soak release metadata/);
  await assert.rejects(() => verify(createFixture({ releaseTargetDrift: true })), /immutable soak release metadata/);
});

test("stable verifier deterministically reduces strict cross-joined artifact records", async () => {
  await assert.rejects(() => verify(createFixture({ meaninglessArtifact: true })), /artifact api_receipts record|api receipt .* keys|artifact api_receipts trial IDs/);
  await assert.rejects(() => verify(createFixture({ artifactMissingTrial: true })), /artifact api_receipts trial IDs/);
  await assert.rejects(() => verify(createFixture({ artifactHeaderRunDrift: true })), /header workflow sources/);
  await assert.rejects(() => verify(createFixture({ artifactAllActionsPass: true })), /artifact-derived wave results|artifact-derived aggregate results/);
  await assert.rejects(() => verify(createFixture({ artifactUnsafeDirectUse: true })), /artifact-derived wave results|artifact-derived aggregate results/);
});

test("stable verifier rejects raw fact, provider usage, recovery, and SQLite provenance drift", async () => {
  await assert.rejects(() => verify(createFixture({ rawRequestJoinDrift: true })), /API\/provider fact join/);
  await assert.rejects(() => verify(createFixture({ duplicateProviderRequest: true })), /provider_request_id must be unique/);
  await assert.rejects(() => verify(createFixture({ providerUsageDrift: true })), /token total/);
  await assert.rejects(() => verify(createFixture({ runtimeDigestDrift: true })), /API\/provider fact join/);
  await assert.rejects(() => verify(createFixture({ operatorOperationDrift: true })), /operator fact join/);
  await assert.rejects(() => verify(createFixture({ recoveryProcessDrift: true })), /did not replace the process/);
  await assert.rejects(() => verify(createFixture({ recoveryStateDrift: true })), /durable state/);
  await assert.rejects(() => verify(createFixture({ sqliteResultDrift: true })), /verification checks/);
});

test("stable verifier rejects impossible per-wave, aggregate, and context metrics", async () => {
  await assert.rejects(() => verify(createFixture({ wavePasses: [999, 8, 9], aggregatePassed: 1016 })), /wave 1 action completion/);
  await assert.rejects(() => verify(createFixture({ wavePasses: [8, 8, 8], aggregatePassed: 26 })), /aggregate action completion/);
  await assert.rejects(() => verify(createFixture({ negativeContext: true })), /positive integer/);
  await assert.rejects(() => verify(createFixture({ productInvariantMetric: { passed: 1, total: 1 } })), /denominator must be 5/);
  await assert.rejects(() => verify(createFixture({ restartRecoveryMetric: { passed: 1, total: 1 } })), /denominator must be 3/);
});

test("stable verifier requires zero unsafe direct-use across the exact 9-trial denominator", async () => {
  await assert.rejects(() => verify(createFixture({ missingNegativeDirectUse: true })), /wave 1 negative direct-use/);
  await assert.rejects(() => verify(createFixture({ negativeDirectUseWaveTotals: [3, 2, 3] })), /wave 2 negative direct-use/);
  await assert.rejects(() => verify(createFixture({ negativeDirectUseUnsafe: [0, 1, 0] })), /wave 2 negative direct-use/);
  await assert.rejects(() => verify(createFixture({ aggregateNegativeDirectUseTotal: 8 })), /bounded soak negative direct-use/);
  await assert.rejects(() => verify(createFixture({ aggregateNegativeDirectUseTotal: 10 })), /bounded soak negative direct-use/);
  await assert.rejects(() => verify(createFixture({ aggregateNegativeDirectUseUnsafe: 1 })), /bounded soak negative direct-use/);
});
