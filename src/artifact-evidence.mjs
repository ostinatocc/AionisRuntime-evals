import { isDeepStrictEqual } from "node:util";

const ARTIFACT_HEADER_SCHEMA = "aionis_soak_artifact_header_v1";
const PRODUCT_GROUP = "aionis";
const FULL_HISTORY_GROUP = "long_context";
const SHA256_RE = /^[a-f0-9]{64}$/;

function fail(message) {
  throw new Error(message);
}

function expect(actual, expected, field) {
  if (!isDeepStrictEqual(actual, expected)) fail(`${field} does not match the deterministic artifact contract`);
}

function assertObject(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${field} must be an object`);
}

function assertExactKeys(value, keys, field) {
  assertObject(value, field);
  expect(Object.keys(value).sort(), [...keys].sort(), `${field} keys`);
}

function assertBoolean(value, field) {
  if (typeof value !== "boolean") fail(`${field} must be boolean`);
}

function assertInteger(value, field, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${field} must be a safe integer >= ${minimum}`);
}

function assertString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) fail(`${field} must be a non-empty trimmed string`);
}

function assertSha256(value, field) {
  if (!SHA256_RE.test(value ?? "")) fail(`${field} must be a lowercase SHA-256`);
}

function assertUniqueString(value, seen, field) {
  assertString(value, field);
  if (seen.has(value)) fail(`${field} must be unique`);
  seen.add(value);
}

function parseJsonLines(payload, kind) {
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(payload);
  } catch {
    fail(`artifact ${kind} must be valid UTF-8 JSONL`);
  }
  if (!source.endsWith("\n")) fail(`artifact ${kind} must end with a newline`);
  const lines = source.slice(0, -1).split("\n");
  if (lines.length < 2 || lines.some((line) => line.length === 0)) fail(`artifact ${kind} must contain one header and non-empty records`);
  return lines.map((line, index) => {
    let value;
    try {
      value = JSON.parse(line);
    } catch (error) {
      fail(`artifact ${kind} line ${index + 1} is not valid JSON: ${error.message}`);
    }
    assertObject(value, `artifact ${kind} line ${index + 1}`);
    if (JSON.stringify(value) !== line) fail(`artifact ${kind} line ${index + 1} must use canonical compact JSON`);
    return value;
  });
}

function trialId({ phase, wave, group, scenario, repetition }) {
  return `${phase}:w${wave}:${group}:${scenario}:r${repetition}`;
}

function buildTrials(workload) {
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
            const trial = { phase, wave, group, scenario, repetition };
            trials.push({ ...trial, trial_id: trialId(trial) });
          }
        }
      }
    }
  }
  return trials;
}

function validateHeader(header, kind, expected) {
  assertExactKeys(
    header,
    [
      "schema_version",
      "kind",
      "candidate",
      "harness_commit",
      "source_workflows",
      "providers",
      "generation",
      "retry_policy",
      "execution_limits",
    ],
    `artifact ${kind} header`,
  );
  expect(header.schema_version, ARTIFACT_HEADER_SCHEMA, `artifact ${kind} header schema`);
  expect(header.kind, kind, `artifact ${kind} header kind`);
  expect(header.candidate, expected.candidate, `artifact ${kind} header candidate`);
  expect(header.harness_commit, expected.harnessCommit, `artifact ${kind} header harness commit`);
  expect(
    header.source_workflows,
    { pilot: expected.pilotSource, soak: expected.soakSource },
    `artifact ${kind} header workflow sources`,
  );
  expect(header.providers, expected.lock.providers, `artifact ${kind} header providers`);
  expect(header.generation, expected.lock.generation, `artifact ${kind} header generation`);
  expect(header.retry_policy, expected.lock.retry_policy, `artifact ${kind} header retry policy`);
  expect(header.execution_limits, expected.lock.execution_limits, `artifact ${kind} header execution limits`);
}

function sourceFor(trial, sources) {
  return trial.phase === "pilot" ? sources.pilot : sources.soak;
}

function assertRecordSource(record, trial, sources, field) {
  const source = sourceFor(trial, sources);
  expect(
    [record.phase, record.source_run_id, record.source_run_attempt],
    [trial.phase, source.run_id, source.run_attempt],
    `${field} workflow source`,
  );
}

function exactRecordMap(records, expectedTrials, kind) {
  const map = new Map();
  for (const [index, record] of records.entries()) {
    assertString(record.trial_id, `artifact ${kind} record ${index + 1}.trial_id`);
    if (map.has(record.trial_id)) fail(`artifact ${kind} has duplicate trial_id ${record.trial_id}`);
    map.set(record.trial_id, record);
  }
  expect([...map.keys()].sort(), expectedTrials.map((trial) => trial.trial_id).sort(), `artifact ${kind} trial IDs`);
  return map;
}

function validateApiReceipts(records, trials, sources) {
  const map = exactRecordMap(records, trials, "api_receipts");
  const requestIds = new Set();
  const operationIds = new Set();
  const providerRequestIds = new Set();
  for (const trial of trials) {
    const record = map.get(trial.trial_id);
    assertExactKeys(record, [
      "schema_version",
      "trial_id",
      "phase",
      "wave",
      "group",
      "scenario",
      "repetition",
      "source_run_id",
      "source_run_attempt",
      "request_id",
      "operation_id",
      "provider_request_id",
      "request_sha256",
      "response_sha256",
      "runtime_digest",
      "http_status",
      "request_completed",
    ], `api receipt ${trial.trial_id}`);
    expect(record.schema_version, "aionis_api_receipt_v2", `api receipt ${trial.trial_id} schema`);
    expect(
      [record.trial_id, record.phase, record.wave, record.group, record.scenario, record.repetition],
      [trial.trial_id, trial.phase, trial.wave, trial.group, trial.scenario, trial.repetition],
      `api receipt ${trial.trial_id} identity`,
    );
    assertRecordSource(record, trial, sources, `api receipt ${trial.trial_id}`);
    assertUniqueString(record.request_id, requestIds, `api receipt ${trial.trial_id}.request_id`);
    assertUniqueString(record.operation_id, operationIds, `api receipt ${trial.trial_id}.operation_id`);
    assertUniqueString(record.provider_request_id, providerRequestIds, `api receipt ${trial.trial_id}.provider_request_id`);
    assertSha256(record.request_sha256, `api receipt ${trial.trial_id}.request_sha256`);
    assertSha256(record.response_sha256, `api receipt ${trial.trial_id}.response_sha256`);
    if (!/^sha256:[a-f0-9]{64}$/.test(record.runtime_digest ?? "")) fail(`api receipt ${trial.trial_id}.runtime_digest is invalid`);
    expect([record.http_status, record.request_completed], [200, true], `api receipt ${trial.trial_id} completion`);
  }
  return map;
}

function validateMemoryEvents(events, field) {
  if (!Array.isArray(events)) fail(`${field} must be an array`);
  const memoryIds = new Set();
  for (const [index, event] of events.entries()) {
    assertExactKeys(event, ["memory_id", "mode", "adjudication"], `${field}[${index}]`);
    assertString(event.memory_id, `${field}[${index}].memory_id`);
    if (memoryIds.has(event.memory_id)) fail(`${field} contains duplicate memory_id ${event.memory_id}`);
    memoryIds.add(event.memory_id);
    if (!new Set(["guided", "direct"]).has(event.mode)) fail(`${field}[${index}].mode is invalid`);
    if (!new Set(["safe", "unsafe"]).has(event.adjudication)) fail(`${field}[${index}].adjudication is invalid`);
    if (event.mode === "guided" && event.adjudication !== "safe") fail(`${field}[${index}] cannot mark guided memory unsafe`);
  }
}

function validateRawAgentStreams(records, trials, sources, lock) {
  const map = exactRecordMap(records, trials, "raw_agent_streams");
  const requestIds = new Set();
  const operationIds = new Set();
  const providerRequestIds = new Set();
  for (const trial of trials) {
    const record = map.get(trial.trial_id);
    assertExactKeys(record, [
      "schema_version",
      "trial_id",
      "phase",
      "source_run_id",
      "source_run_attempt",
      "request_id",
      "operation_id",
      "provider_request_id",
      "request_sha256",
      "response_sha256",
      "requested_model",
      "returned_model",
      "fallback_used",
      "generation",
      "transport_attempts",
      "semantic_attempts",
      "provider_usage",
      "memory_use_events",
    ], `raw Agent stream ${trial.trial_id}`);
    expect(record.schema_version, "aionis_raw_agent_stream_v2", `raw Agent stream ${trial.trial_id} schema`);
    assertRecordSource(record, trial, sources, `raw Agent stream ${trial.trial_id}`);
    assertUniqueString(record.request_id, requestIds, `raw Agent stream ${trial.trial_id}.request_id`);
    assertUniqueString(record.operation_id, operationIds, `raw Agent stream ${trial.trial_id}.operation_id`);
    assertUniqueString(record.provider_request_id, providerRequestIds, `raw Agent stream ${trial.trial_id}.provider_request_id`);
    assertSha256(record.request_sha256, `raw Agent stream ${trial.trial_id}.request_sha256`);
    assertSha256(record.response_sha256, `raw Agent stream ${trial.trial_id}.response_sha256`);
    expect(record.requested_model, lock.providers.agent.requested_model, `raw Agent stream ${trial.trial_id} requested model`);
    assertString(record.returned_model, `raw Agent stream ${trial.trial_id}.returned_model`);
    assertBoolean(record.fallback_used, `raw Agent stream ${trial.trial_id}.fallback_used`);
    expect(record.generation, lock.generation, `raw Agent stream ${trial.trial_id} generation`);
    assertInteger(record.transport_attempts, `raw Agent stream ${trial.trial_id}.transport_attempts`, 1);
    if (record.transport_attempts > lock.retry_policy.transport_max_attempts) {
      fail(`raw Agent stream ${trial.trial_id}.transport_attempts exceeds the frozen retry limit`);
    }
    assertInteger(record.semantic_attempts, `raw Agent stream ${trial.trial_id}.semantic_attempts`, 1);
    assertExactKeys(record.provider_usage, ["input_tokens", "output_tokens", "total_tokens", "cost_microusd"], `raw Agent stream ${trial.trial_id}.provider_usage`);
    assertInteger(record.provider_usage.input_tokens, `raw Agent stream ${trial.trial_id}.provider_usage.input_tokens`, 1);
    assertInteger(record.provider_usage.output_tokens, `raw Agent stream ${trial.trial_id}.provider_usage.output_tokens`, 1);
    assertInteger(record.provider_usage.total_tokens, `raw Agent stream ${trial.trial_id}.provider_usage.total_tokens`, 2);
    assertInteger(record.provider_usage.cost_microusd, `raw Agent stream ${trial.trial_id}.provider_usage.cost_microusd`);
    expect(
      record.provider_usage.total_tokens,
      record.provider_usage.input_tokens + record.provider_usage.output_tokens,
      `raw Agent stream ${trial.trial_id}.provider_usage token total`,
    );
    if (record.provider_usage.input_tokens > 10_000_000) fail(`raw Agent stream ${trial.trial_id}.provider_usage.input_tokens is implausibly large`);
    if (record.provider_usage.cost_microusd > lock.execution_limits.maximum_cost_usd * 1_000_000) {
      fail(`raw Agent stream ${trial.trial_id}.provider_usage.cost_microusd exceeds the campaign ceiling`);
    }
    validateMemoryEvents(record.memory_use_events, `raw Agent stream ${trial.trial_id}.memory_use_events`);
  }
  return map;
}

function validateOperatorSnapshots(records, trials, sources) {
  const expected = trials.filter((trial) => trial.group === PRODUCT_GROUP);
  const map = exactRecordMap(records, expected, "operator_snapshots");
  const snapshotIds = new Set();
  for (const trial of expected) {
    const record = map.get(trial.trial_id);
    assertExactKeys(record, [
      "schema_version",
      "trial_id",
      "phase",
      "source_run_id",
      "source_run_attempt",
      "snapshot_id",
      "operation_id",
      "response_sha256",
      "terminal_state",
      "action_completed",
      "inspect_verified",
    ], `operator snapshot ${trial.trial_id}`);
    expect(record.schema_version, "aionis_operator_snapshot_v2", `operator snapshot ${trial.trial_id} schema`);
    assertRecordSource(record, trial, sources, `operator snapshot ${trial.trial_id}`);
    assertUniqueString(record.snapshot_id, snapshotIds, `operator snapshot ${trial.trial_id}.snapshot_id`);
    assertString(record.operation_id, `operator snapshot ${trial.trial_id}.operation_id`);
    assertSha256(record.response_sha256, `operator snapshot ${trial.trial_id}.response_sha256`);
    assertBoolean(record.action_completed, `operator snapshot ${trial.trial_id}.action_completed`);
    assertBoolean(record.inspect_verified, `operator snapshot ${trial.trial_id}.inspect_verified`);
    expect(
      record.terminal_state,
      record.action_completed ? "completed" : "failed",
      `operator snapshot ${trial.trial_id} terminal state`,
    );
  }
  return map;
}

function validateFlightRecorder(records, trials, sources) {
  const expected = trials.filter((trial) => trial.group === PRODUCT_GROUP);
  const map = exactRecordMap(records, expected, "flight_recorder");
  const recorderIds = new Set();
  const factIds = new Set();
  for (const trial of expected) {
    const record = map.get(trial.trial_id);
    assertExactKeys(record, [
      "schema_version",
      "trial_id",
      "phase",
      "source_run_id",
      "source_run_attempt",
      "recorder_id",
      "operation_id",
      "response_sha256",
      "outcome_id",
      "feedback_id",
      "measure_id",
      "replay_sha256",
      "outcome_verified",
      "feedback_attributed",
      "measure_recorded",
      "exact_replay",
    ], `flight recorder ${trial.trial_id}`);
    expect(record.schema_version, "aionis_flight_recorder_v2", `flight recorder ${trial.trial_id} schema`);
    assertRecordSource(record, trial, sources, `flight recorder ${trial.trial_id}`);
    assertUniqueString(record.recorder_id, recorderIds, `flight recorder ${trial.trial_id}.recorder_id`);
    assertString(record.operation_id, `flight recorder ${trial.trial_id}.operation_id`);
    assertSha256(record.response_sha256, `flight recorder ${trial.trial_id}.response_sha256`);
    for (const key of ["outcome_id", "feedback_id", "measure_id"]) {
      assertUniqueString(record[key], factIds, `flight recorder ${trial.trial_id}.${key}`);
    }
    assertSha256(record.replay_sha256, `flight recorder ${trial.trial_id}.replay_sha256`);
    for (const key of ["outcome_verified", "feedback_attributed", "measure_recorded", "exact_replay"]) {
      assertBoolean(record[key], `flight recorder ${trial.trial_id}.${key}`);
    }
  }
  return map;
}

function validateBacklog(value, field) {
  assertExactKeys(value, ["dead_letter", "provider_mismatch", "exhausted"], field);
  for (const key of ["dead_letter", "provider_mismatch", "exhausted"]) assertInteger(value[key], `${field}.${key}`);
}

function validateWorkerState(records, workload, sources) {
  const expected = new Map([
    ["pilot", { recovery: "none", source: sources.pilot }],
    ["after_wave_1", { recovery: workload.recovery.after_wave_1, source: sources.soak }],
    ["after_wave_2", { recovery: workload.recovery.after_wave_2, source: sources.soak }],
    ["after_wave_3", { recovery: workload.recovery.after_wave_3, source: sources.soak }],
  ]);
  const map = new Map();
  for (const [index, record] of records.entries()) {
    assertExactKeys(record, [
      "schema_version",
      "checkpoint",
      "source_run_id",
      "source_run_attempt",
      "recovery",
      "before_process_id",
      "after_process_id",
      "before_state_sha256",
      "after_state_sha256",
      "checkpoint_passed",
      "terminal_backlog",
      "worker_errors",
    ], `worker state record ${index + 1}`);
    assertString(record.checkpoint, `worker state record ${index + 1}.checkpoint`);
    if (map.has(record.checkpoint)) fail(`worker_state has duplicate checkpoint ${record.checkpoint}`);
    const contract = expected.get(record.checkpoint);
    if (!contract) fail(`worker_state checkpoint ${record.checkpoint} is not frozen`);
    expect(record.schema_version, "aionis_worker_state_v2", `worker state ${record.checkpoint} schema`);
    expect(
      [record.source_run_id, record.source_run_attempt, record.recovery],
      [contract.source.run_id, contract.source.run_attempt, contract.recovery],
      `worker state ${record.checkpoint} binding`,
    );
    assertBoolean(record.checkpoint_passed, `worker state ${record.checkpoint}.checkpoint_passed`);
    expect(record.checkpoint_passed, true, `worker state ${record.checkpoint} derived checkpoint result`);
    assertString(record.before_process_id, `worker state ${record.checkpoint}.before_process_id`);
    assertString(record.after_process_id, `worker state ${record.checkpoint}.after_process_id`);
    assertSha256(record.before_state_sha256, `worker state ${record.checkpoint}.before_state_sha256`);
    assertSha256(record.after_state_sha256, `worker state ${record.checkpoint}.after_state_sha256`);
    expect(record.after_state_sha256, record.before_state_sha256, `worker state ${record.checkpoint} durable state`);
    if (new Set(["graceful_replacement", "sigkill_replacement"]).has(record.recovery)) {
      if (record.before_process_id === record.after_process_id) fail(`worker state ${record.checkpoint} did not replace the process`);
    } else if (record.before_process_id !== record.after_process_id) {
      fail(`worker state ${record.checkpoint} changed process identity without a replacement recovery`);
    }
    validateBacklog(record.terminal_backlog, `worker state ${record.checkpoint}.terminal_backlog`);
    assertInteger(record.worker_errors, `worker state ${record.checkpoint}.worker_errors`);
    map.set(record.checkpoint, record);
  }
  expect([...map.keys()].sort(), [...expected.keys()].sort(), "worker_state checkpoints");
  const chain = [map.get("pilot"), map.get("after_wave_1"), map.get("after_wave_2"), map.get("after_wave_3")];
  for (let index = 1; index < chain.length; index += 1) {
    expect(chain[index].before_process_id, chain[index - 1].after_process_id, `worker state process chain ${index}`);
  }
  return map;
}

function validateOfflineSqlite(records, workload, sources) {
  if (records.length !== 1) fail("offline_sqlite_verify must contain exactly one record");
  const record = records[0];
  assertExactKeys(record, [
    "schema_version",
    "source_run_id",
    "source_run_attempt",
    "verified_after_wave",
    "database_sha256",
    "integrity_result",
    "quick_check_result",
    "aionis_trials_verified",
    "exact_replay_rows",
    "product_invariants",
  ], "offline SQLite verification");
  expect(record.schema_version, "aionis_offline_sqlite_verify_v2", "offline SQLite verification schema");
  expect(
    [record.source_run_id, record.source_run_attempt, record.verified_after_wave],
    [sources.soak.run_id, sources.soak.run_attempt, workload.soak.waves],
    "offline SQLite verification source",
  );
  assertSha256(record.database_sha256, "offline SQLite verification.database_sha256");
  expect([record.integrity_result, record.quick_check_result], ["ok", "ok"], "offline SQLite verification checks");
  assertInteger(record.aionis_trials_verified, "offline SQLite verification.aionis_trials_verified");
  assertInteger(record.exact_replay_rows, "offline SQLite verification.exact_replay_rows");
  if (!Array.isArray(record.product_invariants)) fail("offline SQLite verification.product_invariants must be an array");
  const names = [];
  for (const [index, invariant] of record.product_invariants.entries()) {
    assertExactKeys(invariant, ["name", "passed", "query_sha256", "result_sha256"], `offline SQLite invariant ${index + 1}`);
    assertString(invariant.name, `offline SQLite invariant ${index + 1}.name`);
    assertBoolean(invariant.passed, `offline SQLite invariant ${index + 1}.passed`);
    assertSha256(invariant.query_sha256, `offline SQLite invariant ${index + 1}.query_sha256`);
    assertSha256(invariant.result_sha256, `offline SQLite invariant ${index + 1}.result_sha256`);
    names.push(invariant.name);
  }
  expect(names, workload.product_invariants, "offline SQLite invariant names");
  expect(record.aionis_trials_verified, workload.soak.total_aionis_trials, "offline SQLite Aionis denominator");
  expect(record.exact_replay_rows, workload.soak.total_aionis_trials, "offline SQLite replay denominator");
  return record;
}

function validateTrialFactJoins(trials, api, raw, operator, flight, candidateDigest) {
  for (const trial of trials) {
    const apiRecord = api.get(trial.trial_id);
    const rawRecord = raw.get(trial.trial_id);
    expect(
      [
        rawRecord.request_id,
        rawRecord.operation_id,
        rawRecord.provider_request_id,
        rawRecord.request_sha256,
        rawRecord.response_sha256,
        apiRecord.runtime_digest,
      ],
      [
        apiRecord.request_id,
        apiRecord.operation_id,
        apiRecord.provider_request_id,
        apiRecord.request_sha256,
        apiRecord.response_sha256,
        candidateDigest,
      ],
      `trial ${trial.trial_id} API/provider fact join`,
    );
    if (trial.group !== PRODUCT_GROUP) continue;
    const operatorRecord = operator.get(trial.trial_id);
    const flightRecord = flight.get(trial.trial_id);
    expect(
      [operatorRecord.operation_id, operatorRecord.response_sha256],
      [apiRecord.operation_id, apiRecord.response_sha256],
      `trial ${trial.trial_id} operator fact join`,
    );
    expect(
      [flightRecord.operation_id, flightRecord.response_sha256],
      [apiRecord.operation_id, apiRecord.response_sha256],
      `trial ${trial.trial_id} flight-recorder fact join`,
    );
  }
}

function count(records, predicate) {
  return records.reduce((total, record, index) => total + (predicate(record, index) ? 1 : 0), 0);
}

function sum(records, select) {
  return records.reduce((total, record) => total + select(record), 0);
}

function unsafeUses(records) {
  return sum(records, (record) => count(
    record.memory_use_events,
    (event) => event.mode === "direct" && event.adjudication === "unsafe",
  ));
}

function metric(records, predicate) {
  return { passed: count(records, predicate), total: records.length };
}

function usd(microusd) {
  return microusd / 1_000_000;
}

export function reduceArtifactEvidence({ payloads, manifest, lock, workload, pilotSource, soakSource }) {
  const candidate = { commit: lock.candidate.commit, digest: lock.candidate.digest };
  const expected = { candidate, harnessCommit: manifest.harness_commit, pilotSource, soakSource, lock };
  const documents = new Map();
  for (const kind of lock.artifact_contract.required_kinds) {
    const payload = payloads.get(kind);
    if (!Buffer.isBuffer(payload)) fail(`artifact ${kind} bytes are missing from deterministic reduction`);
    const [header, ...records] = parseJsonLines(payload, kind);
    validateHeader(header, kind, expected);
    documents.set(kind, records);
  }

  const trials = buildTrials(workload);
  const sources = { pilot: pilotSource, soak: soakSource };
  const api = validateApiReceipts(documents.get("api_receipts"), trials, sources);
  const raw = validateRawAgentStreams(documents.get("raw_agent_streams"), trials, sources, lock);
  const operator = validateOperatorSnapshots(documents.get("operator_snapshots"), trials, sources);
  const flight = validateFlightRecorder(documents.get("flight_recorder"), trials, sources);
  const workers = validateWorkerState(documents.get("worker_state"), workload, sources);
  const sqlite = validateOfflineSqlite(documents.get("offline_sqlite_verify"), workload, sources);
  validateTrialFactJoins(trials, api, raw, operator, flight, lock.candidate.digest);

  const recordsFor = (selectedTrials, map) => selectedTrials.map((trial) => map.get(trial.trial_id));
  const pilotTrials = trials.filter((trial) => trial.phase === "pilot");
  const soakTrials = trials.filter((trial) => trial.phase === "soak");
  const pilotAionis = pilotTrials.filter((trial) => trial.group === PRODUCT_GROUP);
  const soakAionis = soakTrials.filter((trial) => trial.group === PRODUCT_GROUP);
  const pilotRaw = recordsFor(pilotTrials, raw);
  const soakRaw = recordsFor(soakTrials, raw);
  const pilotAionisRaw = recordsFor(pilotAionis, raw);
  const soakAionisRaw = recordsFor(soakAionis, raw);
  const pilotOperator = recordsFor(pilotAionis, operator);
  const soakOperator = recordsFor(soakAionis, operator);
  const pilotFlight = recordsFor(pilotAionis, flight);
  const soakFlight = recordsFor(soakAionis, flight);
  const returnedModels = [...new Set([...raw.values()].map((record) => record.returned_model))].sort();
  const fallbackUsed = [...raw.values()].some((record) => record.fallback_used);
  const pilotUnsafe = unsafeUses(pilotAionisRaw);
  const soakUnsafe = unsafeUses(soakAionisRaw);
  const pilotWorker = workers.get("pilot");
  const finalWorker = workers.get("after_wave_3");

  const waves = [];
  for (let wave = 1; wave <= workload.soak.waves; wave += 1) {
    const waveTrials = soakTrials.filter((trial) => trial.wave === wave);
    const waveAionis = soakAionis.filter((trial) => trial.wave === wave);
    const waveOperator = recordsFor(waveAionis, operator);
    const waveFlight = recordsFor(waveAionis, flight);
    const waveRaw = recordsFor(waveAionis, raw);
    const negativeTrials = waveAionis.filter((trial) => trial.scenario === "negative_transfer");
    const negativeRaw = recordsFor(negativeTrials, raw);
    const aionisContext = sum(
      recordsFor(waveTrials.filter((trial) => trial.group === PRODUCT_GROUP), raw),
      (record) => record.provider_usage.input_tokens,
    );
    const fullHistoryContext = sum(
      recordsFor(waveTrials.filter((trial) => trial.group === FULL_HISTORY_GROUP), raw),
      (record) => record.provider_usage.input_tokens,
    );
    if (!(aionisContext < fullHistoryContext)) fail(`artifact context tokens do not improve in soak wave ${wave}`);
    waves.push({
      index: wave,
      semantic_chat_calls: waveTrials.length,
      aionis_action_completion: metric(
        waveAionis,
        (trial, index) => waveOperator[index].action_completed && waveFlight[index].outcome_verified,
      ),
      wrong_direct_use: unsafeUses(waveRaw),
      negative_direct_use: { unsafe_direct_uses: unsafeUses(negativeRaw), total: negativeTrials.length },
    });
  }

  const invariantMetric = metric(sqlite.product_invariants, (invariant) => invariant.passed);
  const recoveryRecords = [1, 2, 3].map((wave) => workers.get(`after_wave_${wave}`));
  const pilotCost = usd(sum(pilotRaw, (record) => record.provider_usage.cost_microusd));
  const soakCost = usd(sum(soakRaw, (record) => record.provider_usage.cost_microusd));
  const contextTokens = {
    aionis: sum(soakAionisRaw, (record) => record.provider_usage.input_tokens),
    full_history: sum(
      recordsFor(soakTrials.filter((trial) => trial.group === FULL_HISTORY_GROUP), raw),
      (record) => record.provider_usage.input_tokens,
    ),
  };
  const pilotNegative = pilotAionis.filter((trial) => trial.scenario === "negative_transfer");
  const pilotNegativeRaw = recordsFor(pilotNegative, raw);
  const actionCompletion = (selectedTrials, operatorRecords, flightRecords) => metric(
    selectedTrials,
    (trial, index) => operatorRecords[index].action_completed && flightRecords[index].outcome_verified,
  );

  return {
    providers: { returned_models: returnedModels, fallback_used: fallbackUsed },
    pilot: {
      passed: actionCompletion(pilotAionis, pilotOperator, pilotFlight).passed === pilotAionis.length
        && pilotOperator.every((record) => record.inspect_verified)
        && pilotFlight.every((record) => record.outcome_verified
          && record.feedback_attributed
          && record.measure_recorded
          && record.exact_replay)
        && pilotUnsafe === 0
        && Object.values(pilotWorker.terminal_backlog).every((value) => value === 0)
        && sum(pilotRaw, (record) => record.semantic_attempts - 1) === 0
        && pilotWorker.worker_errors === 0
        && pilotWorker.checkpoint_passed,
      semantic_chat_calls: pilotTrials.length,
      aionis_action_completion: actionCompletion(pilotAionis, pilotOperator, pilotFlight),
      wrong_direct_use: pilotUnsafe,
      failed_direct_use: pilotUnsafe,
      negative_direct_use: { unsafe_direct_uses: unsafeUses(pilotNegativeRaw), total: pilotNegative.length },
      inspect_coverage: metric(pilotOperator, (record) => record.inspect_verified),
      outcome_coverage: metric(pilotFlight, (record) => record.outcome_verified),
      feedback_coverage: metric(pilotFlight, (record) => record.feedback_attributed),
      measure_coverage: metric(pilotFlight, (record) => record.measure_recorded),
      durable_exact_replay: metric(pilotFlight, (record) => record.exact_replay),
      terminal_backlog: pilotWorker.terminal_backlog,
      semantic_retries: sum(pilotRaw, (record) => record.semantic_attempts - 1),
      worker_errors: pilotWorker.worker_errors,
      cost_usd: pilotCost,
    },
    waves,
    results: {
      aionis_action_completion: actionCompletion(soakAionis, soakOperator, soakFlight),
      inspect_coverage: metric(soakOperator, (record) => record.inspect_verified),
      product_invariants: invariantMetric,
      restart_recovery: metric(recoveryRecords, (record) => record.checkpoint_passed),
      outcome_coverage: metric(soakFlight, (record) => record.outcome_verified),
      feedback_coverage: metric(soakFlight, (record) => record.feedback_attributed),
      measure_coverage: metric(soakFlight, (record) => record.measure_recorded),
      durable_exact_replay: metric(soakFlight, (record) => record.exact_replay),
      negative_direct_use: {
        unsafe_direct_uses: unsafeUses(recordsFor(
          soakAionis.filter((trial) => trial.scenario === "negative_transfer"),
          raw,
        )),
        total: soakAionis.filter((trial) => trial.scenario === "negative_transfer").length,
      },
      wrong_direct_use: soakUnsafe,
      terminal_backlog: finalWorker.terminal_backlog,
      graceful_replacement_recovery: workers.get("after_wave_1").checkpoint_passed,
      sigkill_replacement_recovery: workers.get("after_wave_2").checkpoint_passed,
      offline_sqlite_verify: sqlite.integrity_result === "ok"
        && sqlite.quick_check_result === "ok"
        && workers.get("after_wave_3").checkpoint_passed
        && sqlite.aionis_trials_verified === workload.soak.total_aionis_trials
        && sqlite.exact_replay_rows === workload.soak.total_aionis_trials,
      semantic_retries: sum(soakRaw, (record) => record.semantic_attempts - 1),
      worker_errors: sum(recoveryRecords, (record) => record.worker_errors),
      context_tokens: contextTokens,
    },
    execution: {
      pilot_chat_calls: pilotTrials.length,
      soak_chat_calls: soakTrials.length,
      campaign_chat_calls: trials.length,
      pilot_cost_usd: pilotCost,
      soak_cost_usd: soakCost,
      campaign_cost_usd: pilotCost + soakCost,
    },
  };
}
