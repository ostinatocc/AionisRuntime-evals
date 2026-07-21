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

## Current v2 authority limit

This v2 format is a structural, post-run record contract. It validates the
fields and cross-record joins described below and can recompute summary metrics
from those submitted fields. It does not bind a public record set to the exact
campaign-ledger ID and revision, the private evidence-CAS object universe,
per-exchange trusted transport collector records, trusted host task/use
receipts, or supervisor-issued recovery evidence. Passing the v2 parser is
therefore not proof that the recorded calls or effects happened at a trusted
boundary.

Stable promotion remains fail-closed independently with
`product_invariant_query_contract_unfrozen`. Before that blocker can be replaced
with executable evidence, artifact v3 must bind campaign/CAS/collector/host
authority, and the other
[pre-unblock requirements](../README.md#admission-pre-unblock-requirements) must
be implemented under newly frozen hashes. A syntactically and hash-valid v2
bundle cannot authorize stable promotion.

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

## Ledger-internal frozen ID provenance

ID authority is defined by workload v2 and is checked when the campaign ledger
accepts its internal checkpoints. The campaign ledger preclaims `request_id`,
`guide_operation_id`, `outcome_operation_id`, `feedback_operation_id`, and
`measure_operation_id`. The guide, outcome-observe, feedback, and measure
requests send their corresponding preclaim; each Runtime response must echo the
same `operation_id`. The guide's `guide_trace_id`, feedback's
`learning_feedback_event_id`, and measure's `measurement_id` come from their
actual Runtime response-body fields. `provider_request_id` is the provider
chat-completion response body's `id`.

Operator snapshot and flight-recorder responses currently expose no intrinsic
`snapshot_id` or `recorder_id`. The campaign ledger therefore content-addresses
the exact raw Runtime response bytes and records their `response_sha256`. The
only permitted derived identities are:

```text
snapshot-<sha256(UTF8(trial_id) || NUL || UTF8(response_sha256))>
recorder-<sha256(UTF8(trial_id) || NUL || UTF8(response_sha256))>
```

Both use the full 64-character lowercase digest. A transport request header,
including `x-request-id`, is not a substitute for a missing Runtime body ID.
The campaign ledger rejects absent, duplicate, non-echoed, or
provenance-mismatched identities and must not invent any other ID. Its current
request/response SHA-256 values cover the exact bytes supplied to its boundary;
trusted socket provenance remains blocked until the collector is implemented.
The public v2 artifact reducer only carries these identifiers and hashes and
checks uniqueness/cross-record equality; it does not re-establish their ledger
preclaim or CAS provenance. Artifact v3 must bind those authorities before a
public record can count as trusted execution evidence.

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
  Logical state may evolve between checkpoints because the intervening wave is
  authorized to write; only each individual recovery's before/after pair must
  be identical.
- `offline_sqlite_verify` (`aionis_offline_sqlite_verify_v2`): soak run
  ID/attempt, `verified_after_wave`, checkpointed `database_sha256`, exact
  `integrity_result: "ok"`, exact `quick_check_result: "ok"`, denominators, and
  five ordered named invariants with query/result SHA-256 values.

The current workload does not yet provide authoritative queries for those five
end-to-end product invariants. `src/recovery-evidence-boundary.mjs` therefore
performs real descriptor-bound SQLite integrity, persistence and exact-replay
checks but returns `admission_ready: false` and
`product_invariant_query_contract_unfrozen`. Wave-three and final admission
must remain blocked until a newly frozen workload executes the missing
second-guide, rehydrate, agent/team and handoff evidence. Hashes of invented
`query:<name>` strings are not valid invariant evidence.

Once the trusted collector is implemented, request/response hashes must cover
bytes it observes at the real provider boundary, not a later reserialization.
`provider_request_id` and `provider_usage` must come from that provider response.
Process IDs are non-reusable instance fingerprints, not bare container PIDs.
Logical-state digests use a canonical state export; `database_sha256` covers the
stopped, WAL-checkpointed SQLite main file.

Before sanitized artifact construction, the campaign ledger keeps exact JSON
bodies in its private content-addressed evidence store. Every CAS reference is
the sole path derived from the raw SHA-256, and the store rechecks file type,
`0600` mode, byte count, UTF-8/JSON validity and digest on restart. The provider
request must equal the finite-renderer output as canonical compact UTF-8; the
provider response is parsed internally to derive its IDs, model, native tool
arguments, usage and cost. Transport metadata never contains authorization or
cookie headers. Only internally persisted retryable HTTP responses may open
another dispatch attempt. Network failures are fail-closed until the in-process
executor can authoritatively distinguish a pre-send failure; a caller-supplied
`not_sent`, unknown or already-sent claim is not retry authority.

CAS and strict parsing alone do not prove transport provenance. The current
campaign APIs can be handed response bytes by their caller, so pilot admission
is pinned to `trusted_transport_collector_unavailable` and must fail even when
all synthetic facts look correct. A future in-process collector must own the
socket exchange, bind each attempt to the prepared request, and produce
ledger-consumable authority before these bytes can count as real-provider
evidence. Feedback coverage independently requires Runtime
`learning_attribution_status: "verified_host_receipt"`; `legacy_unverified` and
`not_attributed` are retained as evidence but never counted as attributed
learning.

## Executable workload rendering

Workload v2 uses the finite `aionis_finite_renderer_v1` grammar implemented by
`renderWorkloadTemplate`; double-curly interpolation and arbitrary expressions
are forbidden. Ordinary JSON is recursively deep-cloned. An operator object
has exactly one of these keys:

- `$path`: read an own-property-only dot path; a missing or undefined value
  fails the trial.
- `$concat`: render and concatenate string, finite-number, or boolean scalars.
- `$join`: join a rendered string array with the literal separator.
- `$if`: render a boolean condition and only the selected branch.
- `$equals`: deep-strict compare exactly two rendered values.
- `$not`: negate a rendered boolean.
- `$sha256_utf8_nul`: hash one or more rendered strings as UTF-8 parts separated
  by a single NUL byte, with no leading or trailing NUL.

`expandWorkloadScope` is the only scope-template expander, and every rendered
campaign scope must equal the campaign-ledger preclaim scope. The execution-tree
scenario facts are rendered through one shared `/v1/observe` template into
Runtime `execution` evidence containing `raw_ref`, `evidence`, `verification`,
and `slots.execution_outcome_role`; summary-only memory deliberately omits the
`execution` body.

The frozen `aionis_memory_role_surface_policy_v1` is evaluated per memory, not
per scenario. Seed observe responses must establish a unique
`client_id → memory_id` binding. On every guide response the campaign joins that
provenance to `memory_packet.relevant_memories[].execution_state`,
`feedback_attribution_v1.items[]`, and all three AgentContext memory-ID arrays.
The exact policy is `passed_solution → use_now`,
`failed_branch → do_not_use`, and `summary_only → inspect_before_use`.
Attribution must be available and projection-complete. This also permits a
later summary-only trial to contain both a previously verified outcome on
`use_now` and the original summary on `inspect_before_use` without collapsing
the entire scenario to one surface.

For each Aionis trial the frozen post-trial route order is observe, feedback,
measure, operator snapshot, then flight recorder. The same canonical measure
request is also replayed once and both its request and raw response must be
byte-identical before the snapshot stage. Snapshot and flight-recorder
response bytes are hashed before JSON parsing; their content IDs and both hash
values must pass the workload assertions before the campaign ledger can settle
the trial. OpenRouter `provider.order` and `provider.only` remain explicitly
unfrozen because the authority freezes the model but no underlying provider
identity; adding either field requires newly frozen authority.

Executable workload rendering and template validation are authoritative in
[`src/contracts.mjs`](../src/contracts.mjs). Artifact-record validation and the
deterministic promotion reducer are independently authoritative in
[`src/artifact-evidence.mjs`](../src/artifact-evidence.mjs). Contract changes
require a new authority commit and a newly frozen Runtime promotion binding.

[`schemas/workload-manifest.schema.json`](../schemas/workload-manifest.schema.json)
is deliberately structural and non-authoritative. It is useful for shape
linting, but it does not encode every semantic admission rule. JSON Schema
success alone grants no workload authority; `validateWorkloadManifest` in
`src/contracts.mjs` plus the release lock's raw manifest hash is the admission
authority.

## Deterministic reduction

Within the submitted v2 record set, the reducer derives pilot and per-wave
action completion, outcome/feedback/measure/replay coverage, negative
direct-use, model/fallback facts, semantic retries, context tokens, cost,
recovery, worker backlog and SQLite integrity. Those calculations detect
internal record inconsistencies but do not establish the missing trusted-source
bindings described above.
The v2 parser also structurally aggregates the five named product-invariant
records, but those hashes are not an executable semantic authority. Stable
promotion therefore fails with `product_invariant_query_contract_unfrozen`
instead of treating that aggregate as 5/5 evidence. Once a later frozen
workload defines and executes the invariant protocol, the reducer must derive
those results rather than trust a record's `passed` field. It then
exact-deep-equals the derived pilot, three waves, aggregate results and
execution totals against the bounded-soak receipt. The receipt cannot supply
its own denominator or override raw facts.
