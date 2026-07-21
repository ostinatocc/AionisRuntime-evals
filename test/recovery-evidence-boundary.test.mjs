import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";

import {
  OFFLINE_SQLITE_BOUNDARY_SCHEMA,
  OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER,
  RAW_WORKER_STATE_SCHEMA,
  RECOVERY_EVIDENCE_BOUNDARY_SCHEMA,
  assertOfflineSqliteLedgerFacts,
  assertRecoveryEvidenceBoundary,
  deriveRecoveryCheckpointEvidence,
  inspectOfflineSqliteEvidence,
} from "../src/recovery-evidence-boundary.mjs";
import { putEvidenceJsonBody } from "../src/evidence-cas.mjs";

const PRODUCT_INVARIANTS = [
  "golden_product_loop",
  "product_loop",
  "ordinary_memory_loop",
  "single_agent_loop",
  "multi_agent_loop",
];
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const CANDIDATE_RUNTIME_IMAGE_DIGEST = `sha256:${"a".repeat(64)}`;
const OTHER_RUNTIME_IMAGE_DIGEST = `sha256:${"b".repeat(64)}`;
const TERMINAL_TRIAL_IDS = ["soak:w1:aionis:branch_recovery:r1"];
const PERSISTED_OPERATION_IDENTITIES = [{
  tenant_id: "default",
  scope: "bounded-soak:campaign:branch_recovery",
  operation_kind: "product_guide_v1",
  operation_id: "guide-operation-1",
}];

function fixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aionis-recovery-boundary-"));
  const campaignRoot = path.join(parent, "campaign");
  fs.mkdirSync(campaignRoot, { mode: 0o700 });
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return { parent, campaignRoot };
}

function processFact(seed, runtimeImageDigest = CANDIDATE_RUNTIME_IMAGE_DIGEST) {
  return {
    boot_id: "1d48a92a-f523-4d08-9c12-40c36ec09e52",
    pid_namespace_inode: "4026532456",
    pid: seed,
    process_start_ticks: String(10_000 + seed),
    container_id: sha256(`container:${seed}`),
    runtime_image_digest: runtimeImageDigest,
  };
}

function health(overrides = {}) {
  return {
    http_status: 200,
    body: {
      ok: true,
      lite: {
        stores: {
          write: {
            projections: {
              pending: 0,
              running: 0,
              retry: 0,
              dead_letter: 0,
              provider_mismatch: 0,
              legacy_pending_unrecoverable: 0,
              ...(overrides.projections ?? {}),
            },
          },
          learning_control_worker: {
            running: true,
            closed: false,
            last_error_code: null,
            backlog: {
              pending: 0,
              leased: 0,
              expired_leases: 0,
              completed: 12,
              dead_letter: 0,
              exhausted: 0,
              oldest_available_at: null,
              oldest_lease_expiry: null,
              ...(overrides.backlog ?? {}),
            },
            ...(overrides.worker ?? {}),
          },
        },
      },
    },
    ...(overrides.root ?? {}),
  };
}

function logicalState(suffix = "") {
  return {
    database_instance_id: sha256("runtime-database-instance"),
    operations: [{
      tenant_id: "default",
      scope: "bounded-soak:campaign:branch_recovery",
      operation_kind: "product_guide_v1",
      operation_id: "guide-operation-1",
      request_sha256: sha256("guide-request"),
      receipt_json: JSON.stringify({ contract_version: "aionis_guide_result_v1", suffix }),
      commit_id: "commit-1",
    }],
  };
}

function queue({ status = "completed", errors = [] } = {}) {
  return {
    entries: [{ trial_id: "soak:w1:aionis:branch_recovery:r1", status }],
    errors,
  };
}

function observation(phase, capturedAt, process, options = {}) {
  return {
    phase,
    captured_at: capturedAt,
    process,
    runtime_health: options.health ?? health(),
    executor_queue: options.queue ?? queue(),
    logical_state: options.logicalState ?? logicalState(),
  };
}

function workerArtifact(options = {}) {
  const recovery = options.recovery ?? "graceful_replacement";
  const beforeProcess = options.beforeProcess ?? processFact(41);
  const afterProcess = options.afterProcess ?? processFact(recovery.includes("replacement") ? 42 : 41);
  const observedExit = recovery === "graceful_replacement"
    ? {
        exit_code: 0,
        signal: null,
        oom_killed: false,
        shutdown_log: "draining Runtime before shutdown\nRuntime stopped",
      }
    : recovery === "sigkill_replacement"
      ? { exit_code: 137, signal: "SIGKILL", oom_killed: false, shutdown_log: "" }
      : null;
  return {
    schema_version: RAW_WORKER_STATE_SCHEMA,
    checkpoint: options.checkpoint ?? "after_wave_1",
    source: { run_id: options.runId ?? 202, run_attempt: options.runAttempt ?? 1 },
    recovery,
    before: observation(
      options.beforePhase ?? "before_recovery",
      options.beforeAt ?? "2026-07-21T01:00:00.000Z",
      beforeProcess,
      options.before ?? {},
    ),
    transition: { kind: recovery, observed_exit: options.observedExit ?? observedExit },
    after: observation(
      options.afterPhase ?? "after_recovery",
      options.afterAt ?? "2026-07-21T01:01:00.000Z",
      afterProcess,
      options.after ?? {},
    ),
  };
}

function putWorker(campaignRoot, artifact) {
  return putEvidenceJsonBody({
    campaignRoot,
    body: Buffer.from(JSON.stringify(artifact), "utf8"),
  });
}

function derive(campaignRoot, ref, overrides = {}) {
  return deriveRecoveryCheckpointEvidence({
    campaignRoot,
    workerStateRef: ref,
    expected: {
      checkpoint: overrides.checkpoint ?? "after_wave_1",
      source_run_id: overrides.runId ?? 202,
      source_run_attempt: overrides.runAttempt ?? 1,
      recovery: overrides.recovery ?? "graceful_replacement",
      runtime_image_digest: overrides.runtimeImageDigest ?? CANDIDATE_RUNTIME_IMAGE_DIGEST,
      terminal_trial_ids: overrides.terminalTrialIds ?? TERMINAL_TRIAL_IDS,
      persisted_operation_identities: overrides.persistedOperationIdentities
        ?? PERSISTED_OPERATION_IDENTITIES,
    },
    priorCheckpoint: overrides.priorCheckpoint ?? null,
  });
}

test("raw worker-state CAS bytes derive a private, immutable recovery checkpoint", (t) => {
  const { campaignRoot } = fixture(t);
  const ref = putWorker(campaignRoot, workerArtifact());
  const result = derive(campaignRoot, ref);

  assert.equal(result.schema_version, RECOVERY_EVIDENCE_BOUNDARY_SCHEMA);
  assert.deepEqual(result.worker_state_ref, ref);
  assert.equal(result.recovery_checkpoint.schema_version, "aionis_worker_state_v2");
  assert.equal(result.recovery_checkpoint.recovery, "graceful_replacement");
  assert.notEqual(
    result.recovery_checkpoint.before_process_id,
    result.recovery_checkpoint.after_process_id,
    "replacement identity must be derived from boot/namespace/start/container facts, not a PID",
  );
  assert.equal(
    result.recovery_checkpoint.before_state_sha256,
    result.recovery_checkpoint.after_state_sha256,
  );
  assert.deepEqual(result.recovery_checkpoint.terminal_backlog, {
    dead_letter: 0,
    provider_mismatch: 0,
    exhausted: 0,
  });
  assert.equal(result.recovery_checkpoint.worker_errors, 0);
  assert.equal(result.derivation.terminal_trial_count, 1);
  assert.equal(result.derivation.persisted_operation_count, 1);
  assert.match(result.derivation.universe_sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.derivation.checkpoint_passed, true);
  assert.match(result.facts_sha256, /^[a-f0-9]{64}$/);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.recovery_checkpoint.terminal_backlog), true);
  assert.equal(assertRecoveryEvidenceBoundary(result), result);
  assert.throws(
    () => assertRecoveryEvidenceBoundary(structuredClone(result)),
    /not created by this authority boundary/,
  );
});

test("phase, replacement, state, chain, queue, health, and exit semantics fail closed", (t) => {
  const { campaignRoot } = fixture(t);

  const sameProcess = workerArtifact({ afterProcess: processFact(41) });
  assert.equal(derive(campaignRoot, putWorker(campaignRoot, sameProcess)).derivation.checkpoint_passed, false);

  const changedState = workerArtifact({ after: { logicalState: logicalState("drift") } });
  assert.equal(derive(campaignRoot, putWorker(campaignRoot, changedState)).derivation.state_preserved, false);

  const unsafeQueue = workerArtifact({
    after: {
      queue: queue({
        status: "provider_mismatch",
        errors: [{
          error_id: "error-1",
          code: "PROVIDER_MISMATCH",
          stage: "provider_response",
          occurred_at: "2026-07-21T01:00:30.000Z",
        }],
      }),
    },
  });
  const unsafe = derive(campaignRoot, putWorker(campaignRoot, unsafeQueue));
  assert.equal(unsafe.derivation.checkpoint_passed, false);
  assert.equal(unsafe.recovery_checkpoint.terminal_backlog.provider_mismatch, 1);
  assert.equal(unsafe.recovery_checkpoint.worker_errors, 1);

  const nonterminalHealthCases = [
    ["projection pending", { projections: { pending: 1 } }],
    ["projection running", { projections: { running: 1 } }],
    ["projection retry", { projections: { retry: 1 } }],
    ["legacy projection pending", { projections: { legacy_pending_unrecoverable: 1 } }],
    ["learning pending", { backlog: { pending: 1 } }],
    ["learning leased", { backlog: { leased: 1 } }],
    ["learning expired lease", { backlog: { expired_leases: 1 } }],
  ];
  for (const [name, healthOverride] of nonterminalHealthCases) {
    for (const phase of ["before", "after"]) {
      const candidate = workerArtifact({
        [phase]: { health: health(healthOverride) },
      });
      const result = derive(campaignRoot, putWorker(campaignRoot, candidate));
      assert.equal(result.derivation.queue_drained, false, `${phase} ${name} must remain undrained`);
      assert.equal(result.derivation.checkpoint_passed, false, `${phase} ${name} must block recovery`);
    }
  }

  const unhealthy = workerArtifact({ after: { health: health({ worker: { last_error_code: "drain_failed" } }) } });
  assert.equal(derive(campaignRoot, putWorker(campaignRoot, unhealthy)).derivation.runtime_worker_healthy, false);

  const badExit = workerArtifact({
    observedExit: { exit_code: 1, signal: null, oom_killed: false, shutdown_log: "failed" },
  });
  assert.equal(derive(campaignRoot, putWorker(campaignRoot, badExit)).derivation.transition_valid, false);

  const wrongPhase = workerArtifact({ afterPhase: "before_recovery" });
  assert.throws(
    () => derive(campaignRoot, putWorker(campaignRoot, wrongPhase)),
    /phase must be after_recovery/,
  );

  const first = derive(campaignRoot, putWorker(campaignRoot, workerArtifact()));
  const evolvedState = logicalState("wave-2-authorized-trials");
  const continuedArtifact = workerArtifact({
    checkpoint: "after_wave_2",
    recovery: "sigkill_replacement",
    beforeProcess: processFact(42),
    afterProcess: processFact(43),
    beforeAt: "2026-07-21T02:00:00.000Z",
    afterAt: "2026-07-21T02:01:00.000Z",
    before: { logicalState: evolvedState },
    after: { logicalState: evolvedState },
  });
  const continued = deriveRecoveryCheckpointEvidence({
    campaignRoot,
    workerStateRef: putWorker(campaignRoot, continuedArtifact),
    expected: {
      checkpoint: "after_wave_2",
      source_run_id: 202,
      source_run_attempt: 1,
      recovery: "sigkill_replacement",
      runtime_image_digest: CANDIDATE_RUNTIME_IMAGE_DIGEST,
      terminal_trial_ids: TERMINAL_TRIAL_IDS,
      persisted_operation_identities: PERSISTED_OPERATION_IDENTITIES,
    },
    priorCheckpoint: first.recovery_checkpoint,
  });
  assert.equal(continued.derivation.prior_chain_valid, true);
  assert.equal(continued.derivation.state_preserved, true);
  assert.equal(continued.derivation.checkpoint_passed, true);
  assert.notEqual(
    continued.recovery_checkpoint.before_state_sha256,
    first.recovery_checkpoint.after_state_sha256,
    "authorized wave writes may evolve logical state between recovery checkpoints",
  );

  const secondArtifact = workerArtifact({
    checkpoint: "after_wave_2",
    recovery: "sigkill_replacement",
    beforeProcess: processFact(99),
    afterProcess: processFact(100),
    beforeAt: "2026-07-21T02:00:00.000Z",
    afterAt: "2026-07-21T02:01:00.000Z",
  });
  const second = deriveRecoveryCheckpointEvidence({
    campaignRoot,
    workerStateRef: putWorker(campaignRoot, secondArtifact),
    expected: {
      checkpoint: "after_wave_2",
      source_run_id: 202,
      source_run_attempt: 1,
      recovery: "sigkill_replacement",
      runtime_image_digest: CANDIDATE_RUNTIME_IMAGE_DIGEST,
      terminal_trial_ids: TERMINAL_TRIAL_IDS,
      persisted_operation_identities: PERSISTED_OPERATION_IDENTITIES,
    },
    priorCheckpoint: first.recovery_checkpoint,
  });
  assert.equal(second.derivation.prior_chain_valid, false);
  assert.equal(second.derivation.checkpoint_passed, false);
});

test("worker-state parsing rejects duplicate keys, CAS tamper, permissive mode, and binding drift", (t) => {
  const { campaignRoot } = fixture(t);
  const artifact = workerArtifact();
  const source = JSON.stringify(artifact).replace(
    '"checkpoint":"after_wave_1"',
    '"checkpoint":"after_wave_1","checkpoint":"after_wave_1"',
  );
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot, body: Buffer.from(source) }),
    /duplicate object key "checkpoint"/,
  );

  const bindingRef = putWorker(campaignRoot, artifact);
  assert.throws(
    () => derive(campaignRoot, bindingRef, { recovery: "sigkill_replacement" }),
    /does not match the ledger-owned recovery binding/,
  );
  for (const [phase, seed] of [["beforeProcess", 41], ["afterProcess", 42]]) {
    const digestDrift = workerArtifact({
      [phase]: processFact(seed, OTHER_RUNTIME_IMAGE_DIGEST),
    });
    assert.throws(
      () => derive(campaignRoot, putWorker(campaignRoot, digestDrift)),
      /runtime_image_digest does not match the ledger-owned candidate digest/,
      `${phase} must bind to the frozen candidate image digest`,
    );
  }
  assert.throws(
    () => deriveRecoveryCheckpointEvidence({
      campaignRoot,
      workerStateRef: bindingRef,
      expected: {
        checkpoint: "after_wave_1",
        source_run_id: 202,
        source_run_attempt: 1,
        recovery: "graceful_replacement",
        runtime_image_digest: CANDIDATE_RUNTIME_IMAGE_DIGEST,
        terminal_trial_ids: TERMINAL_TRIAL_IDS,
        persisted_operation_identities: PERSISTED_OPERATION_IDENTITIES,
        checkpoint_passed: true,
      },
      priorCheckpoint: null,
    }),
    /keys must be exactly/,
  );

  const target = path.join(campaignRoot, ...bindingRef.cas_path.split("/"));
  fs.chmodSync(target, 0o644);
  assert.throws(() => derive(campaignRoot, bindingRef), /permissions must be 600/);
  fs.chmodSync(target, 0o600);
  const original = fs.readFileSync(target);
  const tampered = Buffer.from(original);
  tampered[tampered.length - 2] = tampered[tampered.length - 2] === 0x7d ? 0x20 : 0x7d;
  fs.writeFileSync(target, tampered, { mode: 0o600 });
  assert.throws(() => derive(campaignRoot, bindingRef), /SHA-256 mismatch/);
});

test("recovery requires the exact ledger-owned terminal trial and persisted operation universe", (t) => {
  const { campaignRoot } = fixture(t);
  const missingTrial = workerArtifact({
    before: { queue: { entries: [], errors: [] } },
    after: { queue: { entries: [], errors: [] } },
  });
  assert.throws(
    () => derive(campaignRoot, putWorker(campaignRoot, missingTrial)),
    /terminal trial universe/,
  );

  const missingOperationState = {
    database_instance_id: sha256("runtime-database-instance"),
    operations: [],
  };
  const missingOperation = workerArtifact({
    before: { logicalState: missingOperationState },
    after: { logicalState: missingOperationState },
  });
  assert.throws(
    () => derive(campaignRoot, putWorker(campaignRoot, missingOperation)),
    /persisted operation universe/,
  );

  assert.throws(
    () => derive(campaignRoot, putWorker(campaignRoot, workerArtifact()), {
      terminalTrialIds: [...TERMINAL_TRIAL_IDS, TERMINAL_TRIAL_IDS[0]],
    }),
    /terminal_trial_ids must be sorted and unique/,
  );
  assert.throws(
    () => derive(campaignRoot, putWorker(campaignRoot, workerArtifact()), {
      persistedOperationIdentities: [...PERSISTED_OPERATION_IDENTITIES, PERSISTED_OPERATION_IDENTITIES[0]],
    }),
    /persisted_operation_identities must be sorted and unique/,
  );
});

function response(campaignRoot, role, operationId) {
  const bytes = Buffer.from(JSON.stringify({
    contract_version: `aionis_${role}_result_v1`,
    operation_id: operationId,
    ok: true,
  }), "utf8");
  return { bytes, ref: putEvidenceJsonBody({ campaignRoot, body: bytes }) };
}

function sqliteFixture(t, campaignRoot) {
  const { parent } = fixture(t);
  const databasePath = path.join(parent, "aionis-lite-write.sqlite");
  const ids = {
    guide: "guide-operation-1",
    outcome: "outcome-operation-1",
    feedback: "feedback-operation-1",
    measure: "measure-operation-1",
  };
  const responses = Object.fromEntries(Object.entries(ids).map(([role, id]) => [role, response(campaignRoot, role, id)]));
  const db = new DatabaseSync(databasePath);
  db.exec(`
    PRAGMA journal_mode = DELETE;
    PRAGMA foreign_keys = ON;
    CREATE TABLE lite_runtime_write_operations (
      tenant_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      operation_kind TEXT NOT NULL,
      operation_id TEXT NOT NULL,
      request_sha256 TEXT NOT NULL,
      receipt_json TEXT NOT NULL,
      commit_id TEXT,
      created_at TEXT NOT NULL,
      PRIMARY KEY (tenant_id, scope, operation_kind, operation_id)
    );
  `);
  const insert = db.prepare(`INSERT INTO lite_runtime_write_operations
    (tenant_id, scope, operation_kind, operation_id, request_sha256, receipt_json, commit_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  const kinds = {
    guide: "product_guide_v1",
    outcome: "product_observe_v1",
    feedback: "product_feedback_v1",
    measure: "product_measure_v1",
  };
  for (const role of Object.keys(ids)) {
    insert.run(
      "default",
      "bounded-soak:campaign:branch_recovery",
      kinds[role],
      ids[role],
      sha256(`${role}-request`),
      JSON.stringify({
        ok: true,
        statusCode: 200,
        body: JSON.parse(responses[role].bytes.toString("utf8")),
      }),
      role === "measure" ? null : `${role}-commit`,
      "2026-07-21T03:00:00.000Z",
    );
  }
  db.close();
  fs.chmodSync(databasePath, 0o600);
  const trialBindings = [{
    trial_id: "soak:w3:aionis:branch_recovery:r1",
    tenant_id: "default",
    scope: "bounded-soak:campaign:branch_recovery",
    guide_operation_id: ids.guide,
    outcome_operation_id: ids.outcome,
    feedback_operation_id: ids.feedback,
    measure_operation_id: ids.measure,
    guide_response_ref: responses.guide.ref,
    outcome_response_ref: responses.outcome.ref,
    feedback_response_ref: responses.feedback.ref,
    measure_response_ref: responses.measure.ref,
    measure_replay_response_ref: responses.measure.ref,
  }];
  return { databasePath, ids, responses, trialBindings };
}

function offlineExpected() {
  return {
    source_run_id: 202,
    source_run_attempt: 1,
    verified_after_wave: 3,
    product_invariants: PRODUCT_INVARIANTS,
  };
}

test("real quiescent SQLite bytes and persisted Runtime receipts derive core offline facts", (t) => {
  const root = fixture(t);
  const sqlite = sqliteFixture(t, root.campaignRoot);
  const result = inspectOfflineSqliteEvidence({
    campaignRoot: root.campaignRoot,
    databasePath: sqlite.databasePath,
    expected: offlineExpected(),
    trialBindings: sqlite.trialBindings,
  });

  assert.equal(result.schema_version, OFFLINE_SQLITE_BOUNDARY_SCHEMA);
  assert.equal(result.database.sha256, sha256(fs.readFileSync(sqlite.databasePath)));
  assert.equal(result.database.bytes, fs.statSync(sqlite.databasePath).size);
  assert.equal(result.database.mode, "0600");
  assert.deepEqual(result.sqlite_checks.integrity_check, ["ok"]);
  assert.deepEqual(result.sqlite_checks.quick_check, ["ok"]);
  assert.equal(result.sqlite_checks.foreign_key_violation_count, 0);
  assert.equal(result.core_facts.integrity_result, "ok");
  assert.equal(result.core_facts.quick_check_result, "ok");
  assert.equal(result.core_facts.aionis_trials_verified, 1);
  assert.equal(result.core_facts.exact_replay_rows, 1);
  assert.equal(result.inspection_passed, true);
  assert.equal(result.product_invariant_authority.status, "unfrozen");
  assert.equal(result.product_invariant_authority.blocker, OFFLINE_SQLITE_PRODUCT_INVARIANT_BLOCKER);
  assert.deepEqual(result.product_invariant_authority.expected_names, PRODUCT_INVARIANTS);
  assert.equal(result.admission_ready, false);
  assert.equal(result.ledger_facts, null);
  assert.throws(
    () => assertOfflineSqliteLedgerFacts(result),
    /product_invariant_query_contract_unfrozen/,
  );
  assert.throws(
    () => assertOfflineSqliteLedgerFacts(structuredClone(result)),
    /not created by this authority boundary/,
  );
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.core_facts), true);
});

test("offline receipt mismatches are counted internally and cannot be self-reported away", (t) => {
  const root = fixture(t);
  const sqlite = sqliteFixture(t, root.campaignRoot);
  const wrong = response(root.campaignRoot, "measure", "different-operation");
  const drifted = structuredClone(sqlite.trialBindings);
  drifted[0].measure_response_ref = wrong.ref;
  drifted[0].measure_replay_response_ref = wrong.ref;
  const result = inspectOfflineSqliteEvidence({
    campaignRoot: root.campaignRoot,
    databasePath: sqlite.databasePath,
    expected: offlineExpected(),
    trialBindings: drifted,
  });
  assert.equal(result.core_facts.aionis_trials_verified, 0);
  assert.equal(result.core_facts.exact_replay_rows, 0);
  assert.equal(result.inspection_passed, false);

  assert.throws(() => inspectOfflineSqliteEvidence({
    campaignRoot: root.campaignRoot,
    databasePath: sqlite.databasePath,
    expected: offlineExpected(),
    trialBindings: sqlite.trialBindings,
    aionis_trials_verified: 1,
  }), /keys must be exactly/);
});

test("SQLite authority rejects symlink, permissions, live sidecars, empty/corrupt files, and CAS tamper", (t) => {
  const root = fixture(t);
  const sqlite = sqliteFixture(t, root.campaignRoot);
  const inspect = (databasePath = sqlite.databasePath, trialBindings = sqlite.trialBindings) =>
    inspectOfflineSqliteEvidence({
      campaignRoot: root.campaignRoot,
      databasePath,
      expected: offlineExpected(),
      trialBindings,
    });

  fs.chmodSync(sqlite.databasePath, 0o644);
  assert.throws(() => inspect(), /permissions must be 600/);
  fs.chmodSync(sqlite.databasePath, 0o600);

  const symlink = path.join(path.dirname(sqlite.databasePath), "linked.sqlite");
  fs.symlinkSync(sqlite.databasePath, symlink);
  assert.throws(() => inspect(symlink), /regular non-symlink file/);

  fs.writeFileSync(`${sqlite.databasePath}-wal`, Buffer.from("not-quiescent"), { mode: 0o600 });
  assert.throws(() => inspect(), /not quiescent: -wal exists/);
  fs.unlinkSync(`${sqlite.databasePath}-wal`);

  const empty = path.join(path.dirname(sqlite.databasePath), "empty.sqlite");
  fs.writeFileSync(empty, Buffer.alloc(0), { mode: 0o600 });
  assert.throws(() => inspect(empty), /size must be between 1 byte and 64 GiB/);

  const corrupt = path.join(path.dirname(sqlite.databasePath), "corrupt.sqlite");
  fs.writeFileSync(corrupt, Buffer.from("not a sqlite database"), { mode: 0o600 });
  assert.throws(() => inspect(corrupt));

  const tamperedBindings = structuredClone(sqlite.trialBindings);
  const responseRef = tamperedBindings[0].guide_response_ref;
  const responsePath = path.join(root.campaignRoot, ...responseRef.cas_path.split("/"));
  fs.writeFileSync(responsePath, Buffer.from("{}"), { mode: 0o600 });
  assert.throws(() => inspect(sqlite.databasePath, tamperedBindings), /size mismatch|SHA-256 mismatch/);
});
