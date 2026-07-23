import { lstat, mkdir, open, readFile, realpath, unlink } from "node:fs/promises";
import path from "node:path";

import { buildAgentModelInputV1 } from "./agent-action.mjs";
import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
  expectSha256,
  expectText,
} from "./canonical.mjs";
import { verifyPilotCellV1, verifyPilotPlanV1 } from "./pilot-contract.mjs";
import {
  verifyCellArmPreparedPayloadV1,
  verifyCellResultRecordedPayloadV1,
  verifyModelInputFrozenPayloadV1,
  verifyPilotRunEventEnvelopeV1,
  verifyProviderAttemptCompletedPayloadV1,
  verifyProviderAttemptReservationPayloadV1,
  verifyProviderRequestStartedPayloadV1,
  verifyResourceCleanupReceiptV1,
  verifyResourceCleanupConfirmedPayloadV1,
  verifyRunAbortedPayloadV1,
} from "./pilot-run-event-contract.mjs";
import { verifySignedRunnerExecutionAuthorizationV1 } from "./runner-signature.mjs";
import {
  assertReleasePilotCancellationAuthorityV1,
  commitReleasePilotFinalManifestV1,
} from "./release-pilot-cancellation.mjs";

const providerAttemptAuthorities = new WeakSet();
const nonReleaseContractAuthorities = new WeakSet();
const finalManifestPersistenceTestAuthorities = new WeakMap();
const FINAL_MANIFEST_PERSISTENCE_STAGES = new Set([
  "after_open",
  "after_write",
  "after_file_fsync",
  "after_directory_fsync",
]);

function fail(code) {
  throw new Error(`aionis_eval_run_ledger_${code}`);
}

async function syncDirectory(directory) {
  const handle = await open(directory, "r");
  try { await handle.sync(); } finally { await handle.close(); }
}

async function exclusiveCanonicalFile(filePath, value, existsCode = "artifact_exists") {
  let handle;
  try {
    handle = await open(filePath, "wx", 0o600);
    await handle.writeFile(`${canonicalJson(value)}\n`, "utf8");
    await handle.sync();
  } catch (error) {
    if (error?.code === "EEXIST") fail(existsCode);
    throw error;
  } finally {
    if (handle !== undefined) await handle.close();
  }
  await syncDirectory(path.dirname(filePath));
}

function persistenceTestObserver(authority) {
  if (authority === null) return null;
  const observer = authority !== null && typeof authority === "object"
    ? finalManifestPersistenceTestAuthorities.get(authority)
    : undefined;
  if (observer === undefined) fail("final_manifest_persistence_test_authority_invalid");
  return observer;
}

async function notifyFinalManifestPersistenceStage(observer, stage) {
  if (observer === null) return;
  if (!FINAL_MANIFEST_PERSISTENCE_STAGES.has(stage)) {
    fail("final_manifest_persistence_stage_invalid");
  }
  await observer(Object.freeze({
    schema_version: "aionis_non_release_final_manifest_persistence_stage_v1",
    stage,
  }));
}

async function removeUncommittedFinalManifest(filePath) {
  let removed = false;
  try {
    await unlink(filePath);
    removed = true;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (removed) await syncDirectory(path.dirname(filePath));
}

async function persistUncommittedFinalManifest(filePath, value, observer) {
  let handle;
  let created = false;
  try {
    try {
      handle = await open(filePath, "wx", 0o600);
      created = true;
      await notifyFinalManifestPersistenceStage(observer, "after_open");
      await handle.writeFile(`${canonicalJson(value)}\n`, "utf8");
      await notifyFinalManifestPersistenceStage(observer, "after_write");
      await handle.sync();
      await notifyFinalManifestPersistenceStage(observer, "after_file_fsync");
    } finally {
      if (handle !== undefined) await handle.close();
    }
    await syncDirectory(path.dirname(filePath));
    await notifyFinalManifestPersistenceStage(observer, "after_directory_fsync");
  } catch (error) {
    if (error?.code === "EEXIST" && !created) fail("final_manifest_exists");
    if (created) {
      try {
        await removeUncommittedFinalManifest(filePath);
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          "aionis_eval_run_ledger_uncommitted_final_manifest_cleanup_failed",
        );
      }
    }
    throw error;
  }
}

export function createNonReleaseContractTestFinalManifestPersistenceAuthorityV1(
  observer,
) {
  if (typeof observer !== "function") {
    fail("final_manifest_persistence_test_observer_invalid");
  }
  const handle = Object.freeze(Object.assign(Object.create(null), {
    schema_version:
      "aionis_non_release_final_manifest_persistence_test_authority_v1",
    authority_class: "non_release_contract_test_only_v1",
  }));
  finalManifestPersistenceTestAuthorities.set(handle, observer);
  return handle;
}

async function contentAddressedCanonicalFile(directory, value) {
  const payload = canonicalClone(value);
  const payloadSha256 = canonicalSha256(payload);
  const filePath = path.join(directory, `${payloadSha256}.json`);
  let handle;
  let created = false;
  try {
    handle = await open(filePath, "wx", 0o600);
    created = true;
    await handle.writeFile(`${canonicalJson(payload)}\n`, "utf8");
    await handle.sync();
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const existing = await readFile(filePath, "utf8");
    if (existing !== `${canonicalJson(payload)}\n`) fail("artifact_hash_collision");
  } finally {
    if (handle !== undefined) await handle.close();
  }
  if (created) await syncDirectory(directory);
  return payloadSha256;
}

async function ensurePrivateDirectory(directory) {
  let created = false;
  try {
    await mkdir(directory, { mode: 0o700, recursive: false });
    created = true;
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
  let canonicalDirectory;
  let metadata;
  try {
    canonicalDirectory = await realpath(directory);
    metadata = await lstat(directory);
  } catch {
    fail("authority_directory_missing");
  }
  if (canonicalDirectory !== directory || !metadata.isDirectory() || metadata.isSymbolicLink()
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    fail("authority_directory_unsafe");
  }
  if (created) await syncDirectory(path.dirname(directory));
}

async function verifyAuthorityRoot(value) {
  const root = expectText(value, "run_ledger_authority_root", { maximumBytes: 16_384 });
  if (!path.isAbsolute(root) || path.normalize(root) !== root) fail("authority_root_invalid");
  let canonicalRoot;
  let metadata;
  try {
    canonicalRoot = await realpath(root);
    metadata = await lstat(root);
  } catch {
    fail("authority_root_missing");
  }
  if (canonicalRoot !== root || !metadata.isDirectory() || metadata.isSymbolicLink()
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    fail("authority_root_unsafe");
  }
  return root;
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

function cellRef(cell) {
  return canonicalClone({
    ordinal: cell.ordinal,
    opaque_cell_id: cell.opaque_cell_id,
    cell_sha256: canonicalSha256(cell),
  });
}

function exactScheduledCell(cell, plan) {
  const expected = plan.schedule[cell.ordinal - 1];
  return expected !== undefined && canonicalJson(cell) === canonicalJson(expected);
}

export async function reserveProviderAttemptV1(authority, inputValue) {
  if ((typeof authority !== "object" && typeof authority !== "function")
    || authority === null
    || (!providerAttemptAuthorities.has(authority)
      && !nonReleaseContractAuthorities.has(authority))) {
    fail("provider_attempt_authority_invalid");
  }
  return authority.reserveProviderAttempt(inputValue);
}

export function snapshotProviderAttemptAuthorityV1(authority) {
  if ((typeof authority !== "object" && typeof authority !== "function")
    || authority === null
    || (!providerAttemptAuthorities.has(authority)
      && !nonReleaseContractAuthorities.has(authority))) {
    fail("provider_attempt_authority_invalid");
  }
  return authority.snapshot();
}

export function createNonReleaseProviderContractAuthorityV1(scheduleValue) {
  if (!Array.isArray(scheduleValue) || scheduleValue.length < 1 || scheduleValue.length > 9) {
    fail("non_release_schedule_invalid");
  }
  const schedule = scheduleValue.map((value) => verifyPilotCellV1(value));
  let nextOrdinal = 1;
  let activeAttemptOrdinal = null;
  const authority = Object.freeze({
    async reserveProviderAttempt(inputValue) {
      const input = expectExactRecord(inputValue, [
        "canonicalRequestSha256", "cell", "modelInputSha256",
      ], "non_release_attempt_reservation");
      const cell = verifyPilotCellV1(input.cell);
      const expected = schedule[nextOrdinal - 1];
      if (expected === undefined || canonicalJson(cell) !== canonicalJson(expected)) {
        fail("attempt_order_invalid");
      }
      const canonicalRequestSha256 = expectSha256(
        input.canonicalRequestSha256,
        "non_release_canonical_request_sha256",
      );
      const modelInputSha256 = expectSha256(
        input.modelInputSha256,
        "non_release_model_input_sha256",
      );
      const executionAuthorizationSha256 = canonicalSha256({
        schema_version: "aionis_non_release_provider_contract_authority_v1",
        pilot_id: cell.pilot_id,
      });
      const body = canonicalClone({
        schema_version: "aionis_non_release_provider_attempt_reservation_v1",
        execution_authorization_sha256: executionAuthorizationSha256,
        attempt_ordinal: cell.ordinal,
        opaque_cell_id: cell.opaque_cell_id,
        canonical_request_sha256: canonicalRequestSha256,
        model_input_sha256: modelInputSha256,
      });
      const reservationSha256 = canonicalSha256(body);
      const requestStartedEventSha256 = canonicalSha256({
        ...body,
        reservation_sha256: reservationSha256,
        state: "non_release_contract_test_only",
      });
      activeAttemptOrdinal = cell.ordinal;
      nextOrdinal += 1;
      return canonicalClone({
        ...body,
        reservation_sha256: reservationSha256,
        reservation_event_sha256: canonicalSha256({ body, kind: "reservation" }),
        request_started_sha256: canonicalSha256({ body, kind: "request_started" }),
        request_started_event_sha256: requestStartedEventSha256,
      });
    },
    snapshot() {
      return canonicalClone({
        schema_version: "aionis_non_release_provider_contract_snapshot_v1",
        completed_cell_count: nextOrdinal - 1,
        next_attempt_ordinal: nextOrdinal,
        active_attempt_ordinal: activeAttemptOrdinal,
      });
    },
  });
  nonReleaseContractAuthorities.add(authority);
  return authority;
}

export async function beginPilotRunLedgerV1(
  options,
  finalManifestPersistenceTestAuthority = null,
) {
  const config = expectExactRecord(options, [
    "authorityRoot", "executionAuthorization", "executionManifest", "plan",
    "runnerPublicKey",
  ], "run_ledger_options");
  const plan = verifyPilotPlanV1(config.plan);
  const finalManifestPersistenceObserver = persistenceTestObserver(
    finalManifestPersistenceTestAuthority,
  );
  const pilotId = plan.pilot_id;
  const planSha256 = plan.plan_sha256;
  const authorityRoot = await verifyAuthorityRoot(config.authorityRoot);
  const executionAuthorization = verifySignedRunnerExecutionAuthorizationV1(
    config.executionAuthorization,
    {
      plan,
      executionManifest: config.executionManifest,
      fixedLedgerAuthorityRoot: authorityRoot,
      publicKey: config.runnerPublicKey,
    },
  );
  if (finalManifestPersistenceObserver !== null
    && executionAuthorization.claim_eligible !== false) {
    fail("final_manifest_persistence_test_authority_release_forbidden");
  }
  const authorizationSha256 = executionAuthorization.execution_authorization_sha256;
  const cleanupOwnerKinds = executionAuthorization.claim_eligible === true
    ? ["runtime_owner", "workspace_owner"]
    : [];
  const indexDirectory = path.join(authorityRoot, "pilot-index");
  const pilotsDirectory = path.join(authorityRoot, "pilots");
  await ensurePrivateDirectory(indexDirectory);
  await ensurePrivateDirectory(pilotsDirectory);
  const runDirectoryIdentity = pilotDirectoryName(pilotId, planSha256);
  const directory = path.join(pilotsDirectory, runDirectoryIdentity);
  const indexBody = canonicalClone({
    schema_version: "aionis_pilot_global_index_v1",
    pilot_id: pilotId,
    plan_sha256: planSha256,
    execution_authorization_sha256: authorizationSha256,
    run_directory_identity: runDirectoryIdentity,
    restart_policy: "forbid_same_pilot_id_within_signed_authority_root",
  });
  await exclusiveCanonicalFile(
    path.join(indexDirectory, pilotIndexName(pilotId)),
    { ...indexBody, pilot_index_sha256: canonicalSha256(indexBody) },
    "pilot_already_started",
  );
  try {
    await mkdir(directory, { mode: 0o700, recursive: false });
  } catch (error) {
    if (error?.code === "EEXIST") fail("pilot_run_directory_exists");
    throw error;
  }
  await syncDirectory(pilotsDirectory);
  const artifactDirectory = path.join(directory, "artifacts");
  const eventDirectory = path.join(directory, "events");
  await ensurePrivateDirectory(artifactDirectory);
  await ensurePrivateDirectory(eventDirectory);

  let nextOrdinal = 1;
  let sequence = 0;
  let eventChainHeadSha256 = null;
  let previousCellResultEventSha256 = null;
  let active = null;
  let cleanupReceipt = null;
  let verdict = null;
  let abortClosure = null;
  let closed = false;
  let finalManifestPersisted = false;
  let abortManifestPersisted = false;
  let mutationQueue = Promise.resolve();
  const cellResults = new Map();

  function serialized(operation) {
    const next = mutationQueue.then(operation, operation);
    mutationQueue = next.catch(() => {});
    return next;
  }

  async function appendEvent(eventKind, cell, payload) {
    const payloadSha256 = await contentAddressedCanonicalFile(artifactDirectory, payload);
    const eventBody = canonicalClone({
      schema_version: "aionis_pilot_run_event_v1",
      sequence: sequence + 1,
      previous_event_sha256: eventChainHeadSha256,
      event_kind: eventKind,
      pilot_id: pilotId,
      plan_sha256: planSha256,
      execution_authorization_sha256: authorizationSha256,
      cell_ref: cell === null ? null : cellRef(cell),
      payload_sha256: payloadSha256,
      observed_at: new Date().toISOString(),
    });
    const event = verifyPilotRunEventEnvelopeV1(
      canonicalClone({ ...eventBody, event_sha256: canonicalSha256(eventBody) }),
      {
        authorizationSha256,
        cell,
        eventKind,
        plan,
        previousEventSha256: eventChainHeadSha256,
        sequence: sequence + 1,
      },
    );
    await exclusiveCanonicalFile(
      path.join(eventDirectory, `${String(event.sequence).padStart(6, "0")}.json`),
      event,
      "event_sequence_exists",
    );
    sequence = event.sequence;
    eventChainHeadSha256 = event.event_sha256;
    return event;
  }

  const startedEvent = await appendEvent("run_started", null, {
    schema_version: "aionis_pilot_run_started_payload_v1",
    execution_authorization: executionAuthorization,
    execution_manifest: config.executionManifest,
    authority_root_sha256: canonicalSha256({ authority_root: authorityRoot }),
    run_directory_identity: runDirectoryIdentity,
    provider_attempt_policy: "request_bound_reservation_fsync_before_http_v1",
    recovery_policy: "burn_and_seal_inconclusive_without_resume_v1",
  });

  const ledger = Object.freeze({
    async recordCellPreparation(inputValue) {
      return serialized(async () => {
        if (closed || verdict !== null || active !== null) fail("preparation_state_invalid");
        const input = expectExactRecord(inputValue, [
          "agentModelInput", "cell", "pilotCase", "preparedArm",
        ], "run_ledger_cell_preparation");
        const cell = verifyPilotCellV1(input.cell);
        if (cell.pilot_id !== pilotId || cell.ordinal !== nextOrdinal
          || !exactScheduledCell(cell, plan)) fail("preparation_order_invalid");
        const preparedArm = await verifyCellArmPreparedPayloadV1(input.preparedArm, {
          cell,
          pilotCase: input.pilotCase,
          plan,
        });
        const recomputedModelInput = buildAgentModelInputV1({
          pilotCase: input.pilotCase,
          preparedArm,
        });
        if (canonicalJson(recomputedModelInput) !== canonicalJson(input.agentModelInput)) {
          fail("model_input_binding_invalid");
        }
        const preparedEvent = await appendEvent(
          "cell_arm_prepared",
          cell,
          preparedArm,
        );
        const modelInputPayload = await verifyModelInputFrozenPayloadV1({
          schema_version: "aionis_pilot_model_input_frozen_v1",
          prepared_arm_event_sha256: preparedEvent.event_sha256,
          agent_model_input: recomputedModelInput,
        }, {
          cell,
          pilotCase: input.pilotCase,
          plan,
          preparedArm,
          preparedArmEventSha256: preparedEvent.event_sha256,
        });
        const modelInputEvent = await appendEvent(
          "model_input_frozen",
          cell,
          modelInputPayload,
        );
        active = {
          cell,
          preparedArm,
          preparedEvent,
          modelInput: recomputedModelInput,
          modelInputEvent,
          reservation: null,
          reservationEvent: null,
          requestStarted: null,
          requestStartedEvent: null,
          providerCompletion: null,
          providerCompletionEvent: null,
        };
        return canonicalClone({
          prepared_arm_event_sha256: preparedEvent.event_sha256,
          model_input_event_sha256: modelInputEvent.event_sha256,
          model_input_sha256: recomputedModelInput.model_input_sha256,
        });
      });
    },

    async reserveProviderAttempt(inputValue) {
      return serialized(async () => {
        if (closed || verdict !== null || active === null
          || active.reservation !== null) fail("attempt_state_invalid");
        const input = expectExactRecord(inputValue, [
          "canonicalRequestSha256", "cell", "modelInputSha256",
        ], "run_ledger_attempt_reservation");
        const cell = verifyPilotCellV1(input.cell);
        const canonicalRequestSha256 = expectSha256(
          input.canonicalRequestSha256,
          "run_ledger_canonical_request_sha256",
        );
        const modelInputSha256 = expectSha256(
          input.modelInputSha256,
          "run_ledger_model_input_sha256",
        );
        if (cell.pilot_id !== pilotId || cell.ordinal !== nextOrdinal
          || !exactScheduledCell(cell, plan)
          || canonicalJson(cell) !== canonicalJson(active.cell)
          || modelInputSha256 !== active.modelInput.model_input_sha256) {
          fail("attempt_order_invalid");
        }
        const reservationBody = canonicalClone({
          schema_version: "aionis_pilot_provider_attempt_reservation_v1",
          pilot_id: pilotId,
          plan_sha256: planSha256,
          execution_authorization_sha256: authorizationSha256,
          attempt_ordinal: cell.ordinal,
          opaque_cell_id: cell.opaque_cell_id,
          cell_sha256: canonicalSha256(cell),
          isolation_sha256: cell.isolation.isolation_sha256,
          model_input_sha256: modelInputSha256,
          canonical_request_sha256: canonicalRequestSha256,
          previous_cell_result_event_sha256: previousCellResultEventSha256,
          state: "reserved_fail_closed",
        });
        const reservation = await verifyProviderAttemptReservationPayloadV1({
          ...reservationBody,
          reservation_sha256: canonicalSha256(reservationBody),
        }, {
          authorizationSha256,
          cell,
          modelInput: active.modelInput,
          plan,
          previousCellResultEventSha256,
        });
        const reservationEvent = await appendEvent(
          "provider_attempt_reserved",
          cell,
          reservation,
        );
        const requestStartedBody = canonicalClone({
          schema_version: "aionis_pilot_provider_request_started_v1",
          pilot_id: pilotId,
          plan_sha256: planSha256,
          execution_authorization_sha256: authorizationSha256,
          attempt_ordinal: cell.ordinal,
          opaque_cell_id: cell.opaque_cell_id,
          reservation_sha256: reservation.reservation_sha256,
          reservation_event_sha256: reservationEvent.event_sha256,
          canonical_request_sha256: canonicalRequestSha256,
          state: "http_may_start_after_this_event",
        });
        const requestStarted = await verifyProviderRequestStartedPayloadV1({
          ...requestStartedBody,
          request_started_sha256: canonicalSha256(requestStartedBody),
        }, {
          authorizationSha256,
          cell,
          plan,
          reservation,
          reservationEventSha256: reservationEvent.event_sha256,
        });
        const requestStartedEvent = await appendEvent(
          "provider_request_started",
          cell,
          requestStarted,
        );
        active.reservation = reservation;
        active.reservationEvent = reservationEvent;
        active.requestStarted = requestStarted;
        active.requestStartedEvent = requestStartedEvent;
        return canonicalClone({
          ...reservation,
          reservation_event_sha256: reservationEvent.event_sha256,
          request_started_sha256: requestStarted.request_started_sha256,
          request_started_event_sha256: requestStartedEvent.event_sha256,
        });
      });
    },

    async completeProviderAttempt(inputValue) {
      return serialized(async () => {
        const input = expectExactRecord(inputValue, [
          "assistantMessage", "cell", "messages", "requestReceipt", "responseReceipt",
        ], "run_ledger_attempt_completion");
        const cell = verifyPilotCellV1(input.cell);
        if (active === null || active.reservation === null
          || active.requestStartedEvent === null
          || active.providerCompletionEvent !== null
          || canonicalJson(cell) !== canonicalJson(active.cell)) fail("attempt_not_reserved");
        const completionBody = canonicalClone({
          schema_version: "aionis_pilot_provider_attempt_completed_v1",
          pilot_id: pilotId,
          plan_sha256: planSha256,
          execution_authorization_sha256: authorizationSha256,
          attempt_ordinal: cell.ordinal,
          opaque_cell_id: cell.opaque_cell_id,
          reservation_sha256: active.reservation.reservation_sha256,
          request_started_event_sha256: active.requestStartedEvent.event_sha256,
          request_receipt: input.requestReceipt,
          response_receipt: input.responseReceipt,
          assistant_message: input.assistantMessage,
          messages: input.messages,
          state: "completed",
        });
        const completion = await verifyProviderAttemptCompletedPayloadV1({
          ...completionBody,
          attempt_completion_sha256: canonicalSha256(completionBody),
        }, {
          authorizationSha256,
          cell,
          modelInput: active.modelInput,
          plan,
          requestStartedEventSha256: active.requestStartedEvent.event_sha256,
          reservation: active.reservation,
        });
        active.providerCompletion = completion;
        active.providerCompletionEvent = await appendEvent(
          "provider_attempt_completed",
          cell,
          completion,
        );
        return canonicalClone({
          attempt_completion_sha256: completion.attempt_completion_sha256,
          attempt_completion_event_sha256: active.providerCompletionEvent.event_sha256,
        });
      });
    },

    async recordCellResult(inputValue) {
      return serialized(async () => {
        const input = expectExactRecord(inputValue, [
          "cellResult", "pilotCase", "verifierPublicKey",
        ], "run_ledger_cell_result_input");
        if (active === null || active.providerCompletionEvent === null) {
          fail("provider_attempt_incomplete");
        }
        const payload = await verifyCellResultRecordedPayloadV1({
          schema_version: "aionis_pilot_cell_result_recorded_v1",
          provider_attempt_completion_event_sha256:
            active.providerCompletionEvent.event_sha256,
          cell_result: input.cellResult,
        }, {
          cell: active.cell,
          completion: active.providerCompletion,
          completionEventSha256: active.providerCompletionEvent.event_sha256,
          modelInput: active.modelInput,
          pilotCase: input.pilotCase,
          plan,
          verifierPublicKey: input.verifierPublicKey,
        });
        const result = payload.cell_result;
        const event = await appendEvent("cell_result_recorded", active.cell, payload);
        cellResults.set(active.cell.ordinal, result);
        previousCellResultEventSha256 = event.event_sha256;
        nextOrdinal += 1;
        active = null;
        return canonicalClone({
          cell_result_sha256: result.cell_result_sha256,
          cell_result_event_sha256: event.event_sha256,
        });
      });
    },

    async recordResourceCleanup(inputValue) {
      return serialized(async () => {
        if (closed || verdict !== null || cleanupReceipt !== null || active !== null
          || cellResults.size !== plan.schedule.length
          || nextOrdinal !== plan.schedule.length + 1) fail("cleanup_state_invalid");
        const input = expectExactRecord(inputValue, [
          "cleanupReceipt",
        ], "run_ledger_resource_cleanup_input");
        const payload = verifyResourceCleanupConfirmedPayloadV1({
          schema_version: "aionis_pilot_resource_cleanup_confirmed_v1",
          pilot_id: pilotId,
          plan_sha256: planSha256,
          execution_authorization_sha256: authorizationSha256,
          cleanup_receipt: input.cleanupReceipt,
          cleanup_receipt_sha256: input.cleanupReceipt?.cleanup_receipt_sha256,
          state: "claim_required_cleanup_confirmed",
        }, {
          authorizationSha256,
          ownerKinds: cleanupOwnerKinds,
          plan,
        });
        const event = await appendEvent("resource_cleanup_confirmed", null, payload);
        cleanupReceipt = payload.cleanup_receipt;
        return canonicalClone({
          cleanup_receipt_sha256: cleanupReceipt.cleanup_receipt_sha256,
          resource_cleanup_event_sha256: event.event_sha256,
        });
      });
    },

    async recordVerdict(inputValue) {
      return serialized(async () => {
        if (closed || verdict !== null || cleanupReceipt === null || active !== null
          || cellResults.size !== plan.schedule.length
          || nextOrdinal !== plan.schedule.length + 1) fail("verdict_state_invalid");
        const input = expectExactRecord(inputValue, [
          "pilotCases", "verdict", "verifierPublicKeys",
        ], "run_ledger_verdict_input");
        const { scorePilotV1, verifyPilotVerdictV1 } = await import("./pilot-scorer.mjs");
        const verified = verifyPilotVerdictV1(input.verdict);
        const recomputed = scorePilotV1({
          plan,
          cellResults: [...cellResults.values()],
        }, {
          pilotCases: input.pilotCases,
          verifierPublicKeys: input.verifierPublicKeys,
        });
        if (canonicalJson(verified) !== canonicalJson(recomputed)) fail("verdict_binding_invalid");
        const event = await appendEvent("verdict_recorded", null, verified);
        verdict = verified;
        return canonicalClone({
          verdict_sha256: verified.verdict_sha256,
          verdict_event_sha256: event.event_sha256,
        });
      });
    },

    async closeRun() {
      return serialized(async () => {
        if (closed || verdict === null || active !== null) fail("close_state_invalid");
        const counts = {
          provider_attempt_count: plan.schedule.length,
          cell_result_count: cellResults.size,
          treatment_ledger_closed_count: [...cellResults.values()]
            .filter((result) => result.cell.arm === "treatment"
              && result.treatment_ledger?.state === "closed").length,
          runtime_observation_count: [...cellResults.values()]
            .filter((result) => result.runtime_observation !== null).length,
        };
        const payload = canonicalClone({
          schema_version: "aionis_pilot_run_closed_v1",
          pilot_id: pilotId,
          plan_sha256: planSha256,
          execution_authorization_sha256: authorizationSha256,
          cleanup_receipt_sha256: cleanupReceipt.cleanup_receipt_sha256,
          verdict_sha256: verdict.verdict_sha256,
          counts,
          state: "closed_pending_runner_seal",
        });
        const event = await appendEvent("run_closed", null, payload);
        closed = true;
        return canonicalClone({
          ...payload,
          run_closed_event_sha256: event.event_sha256,
        });
      });
    },

    async abortRun(inputValue) {
      return serialized(async () => {
        if (abortClosure !== null || finalManifestPersisted || abortManifestPersisted) {
          fail("abort_state_invalid");
        }
        const input = expectExactRecord(inputValue, [
          "cleanupReceipt",
          "failingCell",
          "failureClass",
          "failureEvidenceRefSha256",
          "failureStage",
        ], "run_ledger_abort_input");
        const failingCell = input.failingCell === null
          ? null
          : verifyPilotCellV1(input.failingCell);
        if (failingCell !== null && (failingCell.pilot_id !== pilotId
          || !exactScheduledCell(failingCell, plan)
          || (active !== null && canonicalJson(failingCell) !== canonicalJson(active.cell))
          || (active === null && failingCell.ordinal !== nextOrdinal))) {
          fail("abort_cell_invalid");
        }
        if (active !== null && failingCell === null) fail("abort_active_cell_missing");
        const abortCleanupReceipt = verifyResourceCleanupReceiptV1(input.cleanupReceipt, {
          ownerKinds: cleanupOwnerKinds,
          resourceCount: plan.schedule.length,
        });
        if (cleanupReceipt !== null
          && canonicalJson(cleanupReceipt) !== canonicalJson(abortCleanupReceipt)) {
          fail("abort_cleanup_receipt_binding_invalid");
        }
        const failureEvidenceRefSha256 = expectSha256(
          input.failureEvidenceRefSha256,
          "run_ledger_abort_failure_evidence_ref_sha256",
        );
        const activeProviderAttemptState = active === null
          ? "no_active_attempt"
          : active.reservation === null
            ? "prepared_not_reserved"
            : active.providerCompletion === null
              ? "request_may_have_started_burned"
              : "provider_completed_pending_cell_result";
        const providerAttemptReservationCount = cellResults.size
          + (active?.reservation === null || active?.reservation === undefined ? 0 : 1);
        const providerAttemptCompletionCount = cellResults.size
          + (active?.providerCompletion === null || active?.providerCompletion === undefined
            ? 0
            : 1);
        const payload = verifyRunAbortedPayloadV1(canonicalClone({
          schema_version: "aionis_pilot_run_aborted_v1",
          pilot_id: pilotId,
          plan_sha256: planSha256,
          execution_authorization_sha256: authorizationSha256,
          failure_stage: input.failureStage,
          failure_class: input.failureClass,
          failure_evidence_ref_sha256: failureEvidenceRefSha256,
          failing_cell_ref: failingCell === null ? null : cellRef(failingCell),
          completed_cell_count: cellResults.size,
          next_attempt_ordinal: nextOrdinal,
          active_attempt_ordinal: active?.cell.ordinal ?? null,
          provider_attempt_reservation_count: providerAttemptReservationCount,
          provider_attempt_completion_count: providerAttemptCompletionCount,
          active_provider_attempt_state: activeProviderAttemptState,
          cleanup_receipt: abortCleanupReceipt,
          cleanup_receipt_sha256: abortCleanupReceipt.cleanup_receipt_sha256,
          cleanup_confirmed: abortCleanupReceipt.cleanup_confirmed,
          state: "aborted_claim_ineligible_no_resume",
        }), {
          authorizationSha256,
          cell: failingCell,
          ownerKinds: cleanupOwnerKinds,
          plan,
        });
        const event = await appendEvent("run_aborted", failingCell, payload);
        abortClosure = canonicalClone({
          ...payload,
          run_aborted_event_sha256: event.event_sha256,
        });
        closed = true;
        return canonicalClone(abortClosure);
      });
    },

    async persistFinalManifest(manifestValue, cancellationAuthorityValue) {
      return serialized(async () => {
        const cancellationAuthority = assertReleasePilotCancellationAuthorityV1(
          cancellationAuthorityValue,
        );
        if (!closed || verdict === null || abortClosure !== null || finalManifestPersisted
          || manifestValue === null || typeof manifestValue !== "object"
          || Array.isArray(manifestValue)
          || manifestValue.schema_version !== "aionis_pilot_runner_final_manifest_v1"
          || manifestValue.pilot_id !== pilotId
          || manifestValue.plan_sha256 !== planSha256
          || manifestValue.execution_authorization_sha256 !== authorizationSha256
          || manifestValue.event_chain_head_sha256 !== eventChainHeadSha256
          || manifestValue.run_closed_event_sha256 !== eventChainHeadSha256
          || manifestValue.verdict_sha256 !== verdict.verdict_sha256) {
          fail("final_manifest_state_invalid");
        }
        expectSha256(manifestValue.final_manifest_sha256, "run_ledger_final_manifest_sha256");
        const finalManifestPath = path.join(directory, "final-manifest.json");
        await persistUncommittedFinalManifest(
          finalManifestPath,
          manifestValue,
          finalManifestPersistenceObserver,
        );
        try {
          // Synchronous with signal delivery: either a pre-existing signal
          // wins and the uncommitted file is removed, or this transition wins
          // and every later signal is post-commit/observational only.
          commitReleasePilotFinalManifestV1(cancellationAuthority);
          finalManifestPersisted = true;
        } catch (error) {
          try {
            await removeUncommittedFinalManifest(finalManifestPath);
          } catch (cleanupError) {
            throw new AggregateError(
              [error, cleanupError],
              "aionis_eval_run_ledger_uncommitted_final_manifest_cleanup_failed",
            );
          }
          throw error;
        }
        return canonicalClone({
          final_manifest_sha256: manifestValue.final_manifest_sha256,
          event_chain_head_sha256: eventChainHeadSha256,
        });
      });
    },

    async persistAbortManifest(manifestValue) {
      return serialized(async () => {
        if (!closed || abortClosure === null || finalManifestPersisted
          || abortManifestPersisted
          || manifestValue === null || typeof manifestValue !== "object"
          || Array.isArray(manifestValue)
          || manifestValue.schema_version !== "aionis_pilot_runner_abort_manifest_v1"
          || manifestValue.status !== "aborted"
          || manifestValue.outcome !== "aborted_inconclusive"
          || manifestValue.claim_eligible !== false
          || manifestValue.resumable !== false
          || manifestValue.pilot_id !== pilotId
          || manifestValue.plan_sha256 !== planSha256
          || manifestValue.execution_authorization_sha256 !== authorizationSha256
          || manifestValue.event_chain_head_sha256 !== eventChainHeadSha256
          || manifestValue.run_aborted_event_sha256 !== eventChainHeadSha256
          || manifestValue.abort_payload_sha256 !== canonicalSha256(
            Object.fromEntries(
              Object.entries(abortClosure)
                .filter(([key]) => key !== "run_aborted_event_sha256"),
            ),
          )) {
          fail("abort_manifest_state_invalid");
        }
        expectSha256(
          manifestValue.abort_manifest_sha256,
          "run_ledger_abort_manifest_sha256",
        );
        await exclusiveCanonicalFile(
          path.join(directory, "abort-manifest.json"),
          manifestValue,
          "abort_manifest_exists",
        );
        abortManifestPersisted = true;
        return canonicalClone({
          abort_manifest_sha256: manifestValue.abort_manifest_sha256,
          event_chain_head_sha256: eventChainHeadSha256,
        });
      });
    },

    snapshot() {
      return canonicalClone({
        schema_version: "aionis_pilot_run_ledger_snapshot_v1",
        pilot_id: pilotId,
        plan_sha256: planSha256,
        execution_authorization_sha256: authorizationSha256,
        run_started_event_sha256: startedEvent.event_sha256,
        event_count: sequence,
        event_chain_head_sha256: eventChainHeadSha256,
        completed_cell_count: cellResults.size,
        next_attempt_ordinal: nextOrdinal,
        active_attempt_ordinal: active?.cell.ordinal ?? null,
        verdict_sha256: verdict?.verdict_sha256 ?? null,
        closed,
        restart_policy: "forbid_same_pilot_id_within_signed_authority_root",
      });
    },
  });
  providerAttemptAuthorities.add(ledger);
  return ledger;
}
