import { readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
  expectSha256,
} from "./canonical.mjs";
import { verifyPilotCaseV1, verifyPilotPlanV1 } from "./pilot-contract.mjs";
import {
  verifyCellArmPreparedPayloadV1,
  verifyCellResultRecordedPayloadV1,
  verifyModelInputFrozenPayloadV1,
  verifyPilotRunEventEnvelopeV1,
  verifyProviderAttemptCompletedPayloadV1,
  verifyProviderAttemptReservationPayloadV1,
  verifyProviderRequestStartedPayloadV1,
  verifyResourceCleanupConfirmedPayloadV1,
  verifyRunAbortedPayloadV1,
} from "./pilot-run-event-contract.mjs";
import { scorePilotV1 } from "./pilot-scorer.mjs";
import {
  verifySignedRunnerExecutionAuthorizationV1,
  verifySignedRunnerAbortManifestV1,
  verifySignedRunnerFinalManifestV1,
} from "./runner-signature.mjs";

function fail(code) {
  throw new Error(`aionis_eval_sealed_pilot_run_${code}`);
}

function pilotIndexName(pilotId) {
  return `${canonicalSha256({
    schema_version: "aionis_pilot_global_index_identity_v1",
    pilot_id: pilotId,
  })}.json`;
}

function pilotDirectoryName(pilotId, planSha256) {
  return canonicalSha256({
    schema_version: "aionis_pilot_run_directory_identity_v1",
    pilot_id: pilotId,
    plan_sha256: planSha256,
  });
}

async function readCanonicalFile(filePath, field) {
  let text;
  let value;
  try {
    text = await readFile(filePath, "utf8");
    value = JSON.parse(text);
  } catch {
    fail(`${field}_missing_or_invalid`);
  }
  if (text !== `${canonicalJson(value)}\n`) fail(`${field}_noncanonical`);
  return value;
}

function verifySelfHash(value, hashField, field) {
  expectSha256(value[hashField], `${field}_${hashField}`);
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== hashField),
  );
  if (canonicalSha256(body) !== value[hashField]) fail(`${field}_integrity_invalid`);
}

function casesForPlan(plan, casesValue, verifierPublicKeys) {
  if (!Array.isArray(casesValue) || casesValue.length !== 3
    || !Array.isArray(verifierPublicKeys) || verifierPublicKeys.length !== 3) {
    fail("case_authority_count_invalid");
  }
  const byId = new Map();
  for (const [index, caseValue] of casesValue.entries()) {
    const pilotCase = verifyPilotCaseV1(caseValue);
    if (byId.has(pilotCase.case_id)) fail("case_authority_duplicate");
    byId.set(pilotCase.case_id, {
      pilotCase,
      verifierPublicKey: verifierPublicKeys[index],
    });
  }
  const ordered = plan.cases.map((ref) => byId.get(ref.case_id));
  if (ordered.some((entry, index) => entry === undefined
    || entry.pilotCase.case_sha256 !== plan.cases[index].case_sha256)) {
    fail("case_authority_binding_invalid");
  }
  return { byId, ordered };
}

async function replayPilotRunLedgerV1(options) {
  const input = expectExactRecord(options, [
    "authorityRoot",
    "cases",
    "executionManifest",
    "plan",
    "runnerPublicKey",
    "verifierPublicKeys",
  ], "sealed_pilot_run_options");
  const plan = verifyPilotPlanV1(input.plan);
  const authorityRoot = input.authorityRoot;
  if (typeof authorityRoot !== "string" || !path.isAbsolute(authorityRoot)
    || path.normalize(authorityRoot) !== authorityRoot
    || await realpath(authorityRoot) !== authorityRoot) fail("authority_root_invalid");
  const caseAuthorities = casesForPlan(plan, input.cases, input.verifierPublicKeys);
  const runDirectoryIdentity = pilotDirectoryName(plan.pilot_id, plan.plan_sha256);
  const runDirectory = path.join(authorityRoot, "pilots", runDirectoryIdentity);
  const index = await readCanonicalFile(
    path.join(authorityRoot, "pilot-index", pilotIndexName(plan.pilot_id)),
    "pilot_index",
  );
  const indexRecord = expectExactRecord(index, [
    "execution_authorization_sha256",
    "pilot_id",
    "pilot_index_sha256",
    "plan_sha256",
    "restart_policy",
    "run_directory_identity",
    "schema_version",
  ], "sealed_pilot_index");
  verifySelfHash(indexRecord, "pilot_index_sha256", "pilot_index");
  if (indexRecord.schema_version !== "aionis_pilot_global_index_v1"
    || indexRecord.pilot_id !== plan.pilot_id
    || indexRecord.plan_sha256 !== plan.plan_sha256
    || indexRecord.run_directory_identity !== runDirectoryIdentity
    || indexRecord.restart_policy !== "forbid_same_pilot_id_within_signed_authority_root"
    || await realpath(runDirectory) !== runDirectory) fail("pilot_index_binding_invalid");

  const eventNames = await readdir(path.join(runDirectory, "events"));
  eventNames.sort();
  if (eventNames.length < 2 || eventNames.length > 59
    || eventNames.some((name, index) => name !== `${String(index + 1).padStart(6, "0")}.json`)) {
    fail("event_set_invalid");
  }
  const rawEvents = [];
  for (const name of eventNames) {
    rawEvents.push(await readCanonicalFile(
      path.join(runDirectory, "events", name),
      "run_event",
    ));
  }
  const authorizationSha256 = indexRecord.execution_authorization_sha256;
  let cursor = 0;
  let previousSha256 = null;
  const events = [];
  const consume = (eventKind, cell) => {
    const value = rawEvents[cursor];
    if (value === undefined) fail("event_sequence_truncated");
    const event = verifyPilotRunEventEnvelopeV1(value, {
      authorizationSha256,
      cell,
      eventKind,
      plan,
      previousEventSha256: previousSha256,
      sequence: cursor + 1,
    });
    previousSha256 = event.event_sha256;
    events.push(event);
    cursor += 1;
    return event;
  };
  const payload = async (event, field) => {
    const value = await readCanonicalFile(
      path.join(runDirectory, "artifacts", `${event.payload_sha256}.json`),
      field,
    );
    if (canonicalSha256(value) !== event.payload_sha256) fail(`${field}_hash_invalid`);
    return value;
  };

  const startedEvent = consume("run_started", null);
  const started = expectExactRecord(await payload(startedEvent, "run_started_payload"), [
    "authority_root_sha256",
    "execution_authorization",
    "execution_manifest",
    "provider_attempt_policy",
    "recovery_policy",
    "run_directory_identity",
    "schema_version",
  ], "sealed_run_started_payload");
  if (started.schema_version !== "aionis_pilot_run_started_payload_v1"
    || started.run_directory_identity !== runDirectoryIdentity
    || canonicalJson(started.execution_manifest) !== canonicalJson(input.executionManifest)) {
    fail("run_started_binding_invalid");
  }
  const executionAuthorization = verifySignedRunnerExecutionAuthorizationV1(
    started.execution_authorization,
    {
      plan,
      executionManifest: input.executionManifest,
      fixedLedgerAuthorityRoot: authorityRoot,
      publicKey: input.runnerPublicKey,
    },
  );
  if (executionAuthorization.execution_authorization_sha256 !== authorizationSha256) {
    fail("authorization_index_binding_invalid");
  }
  const cleanupOwnerKinds = executionAuthorization.claim_eligible === true
    ? ["runtime_owner", "workspace_owner"]
    : [];

  function cellFromEventRef(eventValue) {
    if (eventValue?.cell_ref === null) return null;
    const ordinal = eventValue?.cell_ref?.ordinal;
    if (!Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > plan.schedule.length) {
      fail("abort_event_cell_ref_invalid");
    }
    return plan.schedule[ordinal - 1];
  }

  async function consumeAbort(expectedCell) {
    const next = rawEvents[cursor];
    if (next === undefined || next.event_kind !== "run_aborted") {
      fail("abort_event_missing");
    }
    const eventCell = cellFromEventRef(next);
    if (expectedCell !== undefined && canonicalJson(eventCell) !== canonicalJson(expectedCell)) {
      fail("abort_event_cell_binding_invalid");
    }
    const event = consume("run_aborted", eventCell);
    const abort = verifyRunAbortedPayloadV1(
      await payload(event, "run_aborted_payload"),
      { authorizationSha256, cell: eventCell, ownerKinds: cleanupOwnerKinds, plan },
    );
    return canonicalClone({ ...abort, run_aborted_event_sha256: event.event_sha256 });
  }

  const results = [];
  let previousCellResultEventSha256 = null;
  let runAbort = null;
  for (const [cellIndex, cell] of plan.schedule.entries()) {
    if (rawEvents[cursor]?.event_kind === "run_aborted") {
      runAbort = await consumeAbort(null);
      break;
    }
    const preparedEvent = consume("cell_arm_prepared", cell);
    const modelInputEvent = consume("model_input_frozen", cell);
    const authority = caseAuthorities.byId.get(cell.case_id);
    const preparedArm = await verifyCellArmPreparedPayloadV1(
      await payload(preparedEvent, "prepared_arm_payload"),
      {
        cell,
        pilotCase: authority.pilotCase,
        plan,
      },
    );
    const modelInputPayload = await verifyModelInputFrozenPayloadV1(
      await payload(modelInputEvent, "model_input_payload"),
      {
        cell,
        pilotCase: authority.pilotCase,
        plan,
        preparedArm,
        preparedArmEventSha256: preparedEvent.event_sha256,
      },
    );
    const modelInput = modelInputPayload.agent_model_input;
    if (rawEvents[cursor]?.event_kind === "run_aborted") {
      runAbort = await consumeAbort(cell);
      break;
    }
    const reservationEvent = consume("provider_attempt_reserved", cell);
    const requestStartedEvent = consume("provider_request_started", cell);
    const reservation = await verifyProviderAttemptReservationPayloadV1(
      await payload(reservationEvent, "reservation_payload"),
      {
        authorizationSha256,
        cell,
        modelInput,
        plan,
        previousCellResultEventSha256,
      },
    );
    await verifyProviderRequestStartedPayloadV1(
      await payload(requestStartedEvent, "request_started_payload"),
      {
        authorizationSha256,
        cell,
        plan,
        reservation,
        reservationEventSha256: reservationEvent.event_sha256,
      },
    );
    if (rawEvents[cursor]?.event_kind === "run_aborted") {
      runAbort = await consumeAbort(cell);
      break;
    }
    const completionEvent = consume("provider_attempt_completed", cell);
    const completion = await verifyProviderAttemptCompletedPayloadV1(
      await payload(completionEvent, "completion_payload"),
      {
        authorizationSha256,
        cell,
        modelInput,
        plan,
        requestStartedEventSha256: requestStartedEvent.event_sha256,
        reservation,
      },
    );
    if (rawEvents[cursor]?.event_kind === "run_aborted") {
      runAbort = await consumeAbort(cell);
      break;
    }
    const resultEvent = consume("cell_result_recorded", cell);
    const recorded = await verifyCellResultRecordedPayloadV1(
      await payload(resultEvent, "cell_result_payload"),
      {
        cell,
        completion,
        completionEventSha256: completionEvent.event_sha256,
        modelInput,
        pilotCase: authority.pilotCase,
        plan,
        verifierPublicKey: authority.verifierPublicKey,
      },
    );
    const result = recorded.cell_result;
    results.push(result);
    previousCellResultEventSha256 = resultEvent.event_sha256;
  }
  let verdict = null;
  let runClosure = null;
  let cleanupReceipt = null;
  if (runAbort === null && rawEvents[cursor]?.event_kind === "run_aborted") {
    runAbort = await consumeAbort(null);
  }
  if (runAbort === null) {
    if (results.length !== plan.schedule.length) fail("normal_run_result_count_invalid");
    const cleanupEvent = consume("resource_cleanup_confirmed", null);
    const cleanupPayload = verifyResourceCleanupConfirmedPayloadV1(
      await payload(cleanupEvent, "resource_cleanup_confirmed_payload"),
      { authorizationSha256, ownerKinds: cleanupOwnerKinds, plan },
    );
    cleanupReceipt = cleanupPayload.cleanup_receipt;
    if (rawEvents[cursor]?.event_kind === "run_aborted") {
      runAbort = await consumeAbort(null);
    }
  }
  if (runAbort === null) {
    const verdictEvent = consume("verdict_recorded", null);
    verdict = await payload(verdictEvent, "verdict_payload");
    const recomputedVerdict = scorePilotV1({ plan, cellResults: results }, {
      pilotCases: caseAuthorities.ordered.map((entry) => entry.pilotCase),
      verifierPublicKeys: caseAuthorities.ordered.map((entry) => entry.verifierPublicKey),
    });
    if (canonicalJson(verdict) !== canonicalJson(recomputedVerdict)) {
      fail("verdict_replay_mismatch");
    }
    if (rawEvents[cursor]?.event_kind === "run_aborted") {
      runAbort = await consumeAbort(null);
    }
  }
  if (runAbort === null) {
    const closeEvent = consume("run_closed", null);
    const closePayload = expectExactRecord(await payload(closeEvent, "run_closed_payload"), [
      "cleanup_receipt_sha256",
      "counts",
      "execution_authorization_sha256",
      "pilot_id",
      "plan_sha256",
      "schema_version",
      "state",
      "verdict_sha256",
    ], "sealed_run_closed_payload");
    if (closePayload.schema_version !== "aionis_pilot_run_closed_v1"
      || closePayload.state !== "closed_pending_runner_seal"
      || closePayload.cleanup_receipt_sha256 !== cleanupReceipt.cleanup_receipt_sha256
      || closePayload.verdict_sha256 !== verdict.verdict_sha256
      || closePayload.execution_authorization_sha256 !== authorizationSha256) {
      fail("run_closed_binding_invalid");
    }
    runClosure = { ...closePayload, run_closed_event_sha256: closeEvent.event_sha256 };
    if (rawEvents[cursor]?.event_kind === "run_aborted") {
      runAbort = await consumeAbort(null);
    }
  }
  if (cursor !== rawEvents.length) fail("event_sequence_suffix_invalid");
  if (runAbort !== null && runAbort.completed_cell_count !== results.length) {
    fail("run_aborted_result_count_invalid");
  }
  const terminalEvent = events.at(-1);
  const ledgerSnapshot = {
    schema_version: "aionis_pilot_run_ledger_snapshot_v1",
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    execution_authorization_sha256: authorizationSha256,
    run_started_event_sha256: startedEvent.event_sha256,
    event_count: events.length,
    event_chain_head_sha256: terminalEvent.event_sha256,
    completed_cell_count: runAbort?.completed_cell_count ?? plan.schedule.length,
    next_attempt_ordinal: runAbort?.next_attempt_ordinal ?? plan.schedule.length + 1,
    active_attempt_ordinal: runAbort?.active_attempt_ordinal ?? null,
    verdict_sha256: verdict?.verdict_sha256 ?? null,
    closed: true,
    restart_policy: "forbid_same_pilot_id_within_signed_authority_root",
  };
  return {
    authorityRoot,
    executionAuthorization,
    ledgerSnapshot,
    plan,
    results,
    ...(runClosure === null ? {} : { runClosure }),
    ...(runAbort === null ? {} : { runAbort }),
    runDirectory,
    ...(verdict === null ? {} : { verdict }),
    terminalState: runAbort === null ? "completed" : "aborted",
  };
}

function presealReplayReport(replay) {
  const body = canonicalClone({
    schema_version: "aionis_pilot_preseal_replay_v1",
    status: replay.terminalState === "completed"
      ? "verified_before_final_signature"
      : "verified_before_abort_signature",
    terminal_state: replay.terminalState,
    pilot_id: replay.plan.pilot_id,
    plan_sha256: replay.plan.plan_sha256,
    execution_authorization: replay.executionAuthorization,
    ledger_snapshot: replay.ledgerSnapshot,
    run_closure: replay.runClosure ?? null,
    run_abort: replay.runAbort ?? null,
    verdict: replay.verdict ?? null,
    cell_result_sha256s: replay.results.map((result) => result.cell_result_sha256),
  });
  return canonicalClone({
    ...body,
    preseal_replay_sha256: canonicalSha256(body),
  });
}

export async function replayPilotRunBeforeFinalSignatureV1(options) {
  return presealReplayReport(await replayPilotRunLedgerV1(options));
}

export async function verifySealedPilotRunV1(options) {
  const replay = await replayPilotRunLedgerV1(options);
  const manifestName = replay.terminalState === "completed"
    ? "final-manifest.json"
    : "abort-manifest.json";
  const finalManifest = await readCanonicalFile(
    path.join(replay.runDirectory, manifestName),
    replay.terminalState === "completed" ? "final_manifest" : "abort_manifest",
  );
  if (replay.terminalState === "completed") {
    verifySignedRunnerFinalManifestV1(finalManifest, {
      plan: replay.plan,
      executionManifest: options.executionManifest,
      executionAuthorization: replay.executionAuthorization,
      fixedLedgerAuthorityRoot: replay.authorityRoot,
      ledgerSnapshot: replay.ledgerSnapshot,
      runClosure: replay.runClosure,
      verdict: replay.verdict,
      sealedAt: finalManifest.sealed_at,
      publicKey: options.runnerPublicKey,
    });
  } else {
    verifySignedRunnerAbortManifestV1(finalManifest, {
      plan: replay.plan,
      executionManifest: options.executionManifest,
      executionAuthorization: replay.executionAuthorization,
      fixedLedgerAuthorityRoot: replay.authorityRoot,
      ledgerSnapshot: replay.ledgerSnapshot,
      runAbort: replay.runAbort,
      sealedAt: finalManifest.sealed_at,
      publicKey: options.runnerPublicKey,
    });
  }
  const reportBody = canonicalClone({
    schema_version: "aionis_verified_sealed_pilot_run_v1",
    status: replay.terminalState === "completed" ? "verified" : "verified_aborted",
    terminal_state: replay.terminalState,
    pilot_id: replay.plan.pilot_id,
    plan_sha256: replay.plan.plan_sha256,
    execution_authorization_sha256:
      replay.executionAuthorization.execution_authorization_sha256,
    event_count: replay.ledgerSnapshot.event_count,
    event_chain_head_sha256: replay.ledgerSnapshot.event_chain_head_sha256,
    cell_result_count: replay.results.length,
    verdict_sha256: replay.verdict?.verdict_sha256 ?? null,
    final_manifest_sha256: replay.terminalState === "completed"
      ? finalManifest.final_manifest_sha256
      : null,
    abort_manifest_sha256: replay.terminalState === "aborted"
      ? finalManifest.abort_manifest_sha256
      : null,
    claim_eligible: replay.terminalState === "completed"
      ? finalManifest.claim_eligible
      : false,
  });
  return canonicalClone({
    ...reportBody,
    verification_report_sha256: canonicalSha256(reportBody),
  });
}
