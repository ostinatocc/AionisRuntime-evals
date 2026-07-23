import { expectExactRecord } from "./canonical.mjs";

const CANCELLATION_STATES = new WeakMap();
const SIGNAL_DRAIN_STATES = new WeakMap();
const RELEASE_PILOT_SIGNALS_V1 = Object.freeze(["SIGINT", "SIGTERM"]);
const RELEASE_PILOT_SIGNAL_SET_V1 = new Set(RELEASE_PILOT_SIGNALS_V1);

let activeSignalDrain = null;

function fail(code) {
  throw new Error(`aionis_eval_release_pilot_cancellation_${code}`);
}

function publicHandle(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function stateFor(authority) {
  const state = authority !== null && typeof authority === "object"
    ? CANCELLATION_STATES.get(authority)
    : undefined;
  if (state === undefined) fail("authority_invalid");
  return state;
}

/**
 * Opaque, downgrade-only authority. Holding the handle permits observing or
 * requesting cancellation, but can never make an incomplete run claimable.
 */
export function createReleasePilotCancellationAuthorityV1() {
  const controller = new AbortController();
  const handle = publicHandle({
    schema_version: "aionis_release_pilot_cancellation_authority_v1",
    authority_class: "release_pilot_downgrade_only_cancellation_v1",
  });
  CANCELLATION_STATES.set(handle, {
    controller,
    requested: false,
    signal: null,
    finalManifestCommitted: false,
    postCommitSignal: null,
  });
  return handle;
}

export function assertReleasePilotCancellationAuthorityV1(authority) {
  stateFor(authority);
  return authority;
}

export function requestReleasePilotCancellationV1(authority, options) {
  const input = expectExactRecord(options, ["signal"], "release_pilot_cancellation_request");
  if (!RELEASE_PILOT_SIGNAL_SET_V1.has(input.signal)) fail("signal_invalid");
  const state = stateFor(authority);
  if (state.finalManifestCommitted) {
    if (state.postCommitSignal === null) state.postCommitSignal = input.signal;
    return snapshotReleasePilotCancellationV1(authority);
  }
  if (!state.requested) {
    state.requested = true;
    state.signal = input.signal;
    state.controller.abort(new Error("aionis_eval_release_pilot_cancellation_requested"));
  }
  return snapshotReleasePilotCancellationV1(authority);
}

export function snapshotReleasePilotCancellationV1(authority) {
  const state = stateFor(authority);
  return Object.freeze({
    schema_version: "aionis_release_pilot_cancellation_snapshot_v1",
    cancellation_requested: state.requested,
    signal: state.signal,
    final_manifest_committed: state.finalManifestCommitted,
    post_commit_signal: state.postCommitSignal,
  });
}

/**
 * Linearizes a successfully persisted final manifest against SIGINT/SIGTERM.
 * The caller must invoke this synchronously, only after the claimable manifest
 * and its containing directory have both been fsynced. A signal requested
 * before this point wins and the caller must remove the uncommitted manifest;
 * a signal delivered after this point is observational only and cannot
 * downgrade an already durable release result.
 */
export function commitReleasePilotFinalManifestV1(authority) {
  const state = stateFor(authority);
  if (state.finalManifestCommitted) fail("final_manifest_already_committed");
  if (state.requested) fail("requested");
  state.finalManifestCommitted = true;
  return snapshotReleasePilotCancellationV1(authority);
}

export function releasePilotSignalExitCodeV1(authority) {
  const state = stateFor(authority);
  if (state.finalManifestCommitted) return null;
  if (state.signal === "SIGINT") return 130;
  if (state.signal === "SIGTERM") return 143;
  return null;
}

export function releasePilotCancellationSignalV1(authority) {
  return stateFor(authority).controller.signal;
}

export function checkpointReleasePilotCancellationV1(authority) {
  if (stateFor(authority).requested) fail("requested");
  return true;
}

/**
 * Installs a single process drain lease. Handlers only flip the cancellation
 * authority; they never call exit(), dispose resources, or perform async work.
 */
export function installReleasePilotSignalDrainV1() {
  if (activeSignalDrain !== null) fail("signal_drain_already_installed");
  const cancellationAuthority = createReleasePilotCancellationAuthorityV1();
  const handlers = new Map();
  for (const signal of RELEASE_PILOT_SIGNALS_V1) {
    const handler = () => {
      requestReleasePilotCancellationV1(cancellationAuthority, { signal });
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  const handle = publicHandle({
    schema_version: "aionis_release_pilot_signal_drain_v1",
    cancellationAuthority,
  });
  SIGNAL_DRAIN_STATES.set(handle, { disposed: false, handlers });
  activeSignalDrain = handle;
  return handle;
}

export function disposeReleasePilotSignalDrainV1(handle) {
  const state = handle !== null && typeof handle === "object"
    ? SIGNAL_DRAIN_STATES.get(handle)
    : undefined;
  if (state === undefined) fail("signal_drain_invalid");
  if (state.disposed) return snapshotReleasePilotCancellationV1(
    handle.cancellationAuthority,
  );
  for (const [signal, handler] of state.handlers) {
    process.removeListener(signal, handler);
  }
  state.disposed = true;
  if (activeSignalDrain === handle) activeSignalDrain = null;
  return snapshotReleasePilotCancellationV1(handle.cancellationAuthority);
}
