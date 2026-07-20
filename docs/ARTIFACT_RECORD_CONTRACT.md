# Bounded-soak artifact record contract

The six release assets are canonical UTF-8 JSONL. Each line is one compact
`JSON.stringify` object, the file ends with one newline, and the first line is
the common header:

```json
{"schema_version":"aionis_soak_artifact_header_v1","kind":"api_receipts","candidate":{"commit":"<40 hex>","digest":"sha256:<64 hex>"},"harness_commit":"<40 hex>","source_workflows":{"pilot":"<exact source object>","soak":"<exact source object>"},"providers":"<frozen providers object>","generation":"<frozen generation object>","retry_policy":"<frozen retry object>","execution_limits":"<frozen limits object>"}
```

The verifier rejects unknown or missing keys. It also rejects invalid UTF-8,
blank lines, non-canonical JSON, duplicate IDs, missing joins, a missing final
newline, any asset over 8 MiB, or secret-like material.

Before publication, the six files must be uploaded as six GitHub Actions
artifacts on the exact soak run. Each artifact name includes its kind, harness
commit, run ID, run attempt and raw-file SHA-256. The Actions API digest covers
the upload archive; the protected publisher must download the archive and
revalidate the contained raw file before emitting an immutable prerelease whose
tag and target are bound to the authority commit. Stable verification requires
all six exact-run artifact records, all six release asset records, and the
immutable release record.

## Trial identity

Every semantic call has this deterministic ID:

```text
<pilot|soak>:w<wave>:<group>:<scenario>:r<repetition>
```

The frozen workload expands to exactly 9 pilot and 81 soak IDs. API receipts
and raw streams must contain all 90 IDs exactly once. Operator snapshots and
flight-recorder records contain the exact 30 Aionis IDs: 3 pilot plus 27 soak.
Every record carries the phase and exact source run ID/attempt from the header.

## Record keys

- `api_receipts` (`aionis_api_receipt_v2`): identity and source fields plus
  globally unique `request_id`, `operation_id`, `provider_request_id`, raw-byte
  `request_sha256`, raw-byte `response_sha256`, exact candidate
  `runtime_digest`, `http_status`, and `request_completed`.
- `raw_agent_streams` (`aionis_raw_agent_stream_v2`): identity/source fields,
  the same five request/operation/provider/hash join fields, `requested_model`,
  `returned_model`, `fallback_used`, exact `generation`, `transport_attempts`,
  `semantic_attempts`, exact provider `provider_usage` (`input_tokens`,
  `output_tokens`, `total_tokens`, `cost_microusd`), and
  `memory_use_events`. Each memory event has exactly `memory_id`, `mode`
  (`guided` or `direct`) and `adjudication` (`safe` or `unsafe`).
- `operator_snapshots` (`aionis_operator_snapshot_v2`): identity/source fields,
  unique `snapshot_id`, joined `operation_id` and `response_sha256`,
  `terminal_state`, `action_completed`, `inspect_verified`.
- `flight_recorder` (`aionis_flight_recorder_v2`): identity/source fields,
  unique `recorder_id`, joined `operation_id` and `response_sha256`, unique
  `outcome_id`, `feedback_id`, `measure_id`, raw `replay_sha256`, and the four
  outcome/feedback/measure/replay verification booleans.
- `worker_state` (`aionis_worker_state_v2`): `checkpoint`, source run
  ID/attempt, `recovery`, before/after process-instance fingerprints,
  before/after canonical logical-state SHA-256, `checkpoint_passed`, exact
  terminal backlog, and `worker_errors`.
  The exact checkpoints are `pilot`, `after_wave_1`, `after_wave_2`, and
  `after_wave_3`; the instance chain must be continuous and replacement
  checkpoints must change instance identity without changing logical state.
- `offline_sqlite_verify` (`aionis_offline_sqlite_verify_v2`): soak run
  ID/attempt, `verified_after_wave`, checkpointed `database_sha256`, exact
  `integrity_result: "ok"`, exact `quick_check_result: "ok"`, denominators, and
  five ordered named invariants with query/result SHA-256 values.

Request/response hashes cover bytes observed at the real provider boundary, not
a later reserialization. `provider_request_id` and `provider_usage` must come
from the provider response. Process IDs are non-reusable instance fingerprints,
not bare container PIDs. Logical-state digests use a canonical state export;
`database_sha256` covers the stopped, WAL-checkpointed SQLite main file.

The executable source of truth is
[`src/artifact-evidence.mjs`](../src/artifact-evidence.mjs). Contract changes
require a new authority commit and a newly frozen Runtime promotion binding.

## Deterministic reduction

The reducer derives pilot and per-wave action completion, outcome/feedback/
measure/replay coverage, negative direct-use, model/fallback facts, semantic
retries, context tokens, cost, recovery, worker backlog, SQLite integrity and
the five product invariants. It then exact-deep-equals the derived pilot,
three waves, aggregate results and execution totals against the bounded-soak
receipt. The receipt cannot supply its own denominator or override raw facts.
