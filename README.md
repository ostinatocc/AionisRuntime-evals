# Aionis Runtime external soak authority

This repository is the Git-authoritative home for the bounded release soak. It
is deliberately outside the focused Runtime daemon and carries no publication
authority. The Runtime stable gate checks out one exact commit and executes
`scripts/verify-stable-promotion.mjs`; it does not copy this implementation into
Runtime core.

## Current safety state

This is a fail-closed authority implementation, not an enabled paid runner. It
can validate the frozen v0.3.12 candidate, build the executable workload-v2
trial plan, persist a restart-safe pilot-to-soak campaign ledger, verify
stable-promotion evidence, and build content-addressed artifact manifests. The
provider executor, trusted transport collector, trusted host-use receipt
boundary, and trusted recovery supervisor are intentionally absent.
Even with an exact protected GitHub context, a paid phase stops with
`PAID_EXECUTOR_UNAVAILABLE` before any provider request. A synthetically
completed campaign can produce an auditable pilot receipt, but that receipt is
unconditionally `fail` with `trusted_transport_collector_unavailable`; soak
cannot start. Legacy feedback is retained as `legacy_unverified` and never
counts toward feedback coverage—admission requires `verified_host_receipt`.
Final-wave admission has an independent
`product_invariant_query_contract_unfrozen` blocker: the existing workload names
five end-to-end product invariants but does not yet execute the second-guide,
rehydrate, agent/team and handoff evidence needed to prove them. No caller-fed
HTTP bytes or SQLite-only substitute is treated as a pass.

The frozen release lock binds:

- Runtime `v0.3.12`, exact commit, image digest, OCI revision and platform;
- DashScope `qwen3.7-text-embedding`, 1536 dimensions;
- OpenRouter `deepseek/deepseek-v4-pro`, with one allowed returned model and no
  fallback;
- generation parameters, transport-only retries and zero semantic retries;
- 9 pilot calls, 81 soak calls, three waves, 90 calls total, a 24–36 hour bound,
  and a 50 USD hard ceiling;
- five named product invariants, three recovery checkpoints and the exact 0/9
  negative direct-use denominator;
- native function calling, deterministic verifier-only outcomes, exact Runtime
  request/response assertions and scenario-shared continuity scopes;
- the raw SHA-256 of the authority/workload manifests and stable-promotion
  governance callers.

## Campaign ledger

`src/campaign-ledger.mjs` is the restart-safe local sequencing ledger for a
future executor. Within a non-rollback campaign directory, it freezes all 90
trial identities and operation preclaims before a provider request, binds the
raw lock/authority/workload hashes, checkpoints the provider boundary before
and after dispatch, enforces a persisted pilot admission before soak, and
admits soak waves only in order. Its envelope and lock are `0600` inside a
`0700` directory; updates use a persistent private SQLite lock database,
monotonic revision/CAS, atomic rename and directory sync. On macOS the SQLite
transaction uses the `unix-flock` VFS. On Linux, where that optional VFS is not
normally compiled, a trusted non-group/world-writable util-linux `flock` places
the kernel lock on a parent-owned inherited file description; every acquisition
uses a second independently opened descriptor to prove the lock remains held
after the short-lived helper exits. Missing or incompatible lock support fails
closed—there is no fallback to POSIX `unix`, `unix-excl`, or stale dot-file
locking. Closing the authority descriptor or SIGKILL releases the kernel lock;
no PID-liveness guess or stale-marker deletion can grant ownership. A
crash after dispatch is explicitly ambiguous and never auto-resends the paid
request.
This is not yet complete paid-dispatch authority. The local envelope CAS does
not detect restoration of an older valid envelope (revision ABA), and the same
protected run can currently recreate its deterministic campaign in another
directory. Before any paid send, a protected non-rollback monotonic head and a
run-scoped campaign singleton must bind campaign ID, generation, revision,
previous payload hash and current payload hash outside the replaceable envelope.
Exact seed, guide and provider JSON bodies are content-addressed in a private
`0700`/`0600` sidecar CAS. Its API accepts only a JSON body and has no separate
header or metadata input, but it does not classify arbitrary JSON string values
as secrets; the provider and Runtime boundaries must never place authorization,
cookie or credential material in that body. CAS publication uses no-clobber
hard-link creation, verifies an already-existing digest object byte-for-byte,
and never replaces a racing writer's object. Provider request bytes are rendered
inside the ledger from the raw-hash-bound workload, durably prepared before
dispatch, and compared byte for byte at the final send boundary. OpenRouter
response ID, returned model, native
tool result, token usage and cost are derived from the strict raw response parser
rather than accepted as caller-supplied checkpoint facts. Retryable HTTP
responses are persisted one attempt at a time before another dispatch becomes
eligible, and the attempt ceiling is checked before the next send. Network
failures are not currently retryable because a caller-supplied `not_sent` claim
is not authority; unknown or sent network state remains terminally ambiguous.
The ledger stops when the observed 50 USD campaign-cost ceiling is crossed. The
protected OpenRouter key must also enforce a 50 USD provider-side hard budget
because a response's final charge is not knowable before that request completes.
The current response-recording APIs still receive bytes from their caller; CAS
immutability proves those bytes do not change, not that they came from a real
socket. The pilot reducer therefore cannot pass until an in-process trusted
collector owns the HTTP exchange and issues the corresponding authority record.

## Admission pre-unblock requirements

The static transport and product-invariant blockers are safety stops, not the
only missing work. Removing or changing either blocker by itself must not make a
pilot, wave, or stable release admissible. Before admission can be unlocked, a
new frozen authority revision must implement and test all of these boundaries:

- a trusted in-process collector must own every pilot and soak provider
  exchange, bind the byte-exact prepared request to the socket response, and
  issue authority for every attempt and every wave—not just one pilot summary;
- a protected monotonic campaign head and run-scoped singleton must reject
  valid-envelope rollback, revision ABA, whole-directory replay, and duplicate
  campaign creation before any paid dispatch;
- the workload must freeze a host task envelope and a host-use receipt, and
  feedback coverage must join `verified_host_receipt` to those exact trusted
  records rather than accept a caller-selected attribution status;
- a trusted recovery supervisor must issue worker-state evidence and bind the
  candidate image, process instance, request/response content, persisted
  operations, and every terminal and non-terminal queue counter. Its versioned
  contract must also freeze raw-versus-normalized process-exit semantics (for
  example, Node reports a SIGKILL child as `code: null, signal: SIGKILL`, while
  the current evidence shape records normalized exit code `137`). For terminal
  offline verification it must own and causally bind the same database instance
  across stop, WAL checkpoint, immutable-descriptor inspection, restart and
  post-restart health; the current live worker-state and quiescent SQLite
  inspections are separate evidence paths;
- ledger-owned offline SQLite inspection must join each persisted operation's
  request hash to the corresponding immutable campaign request in CAS. The
  current Runtime column is an operation-specific semantic digest after
  identity/default injection, not the wire-body digest, so this requires either
  a newly frozen versioned digest-and-effective-identity contract with golden
  vectors or a separately persisted versioned `wire_request_sha256`; raw CAS
  SHA equality is not a valid implementation;
- a successor artifact contract (v3) must bind the public records to the exact
  campaign ID and revision, required CAS objects, per-exchange collector
  authority, and trusted host-use receipts; and
- the workload must freeze and execute the second-guide, rehydrate, agent/team,
  handoff, and other query/behavior steps needed to derive the five product
  invariants independently.

The paid executor, protected credentials, upload path, and publisher also remain
unimplemented. Completing the checklist requires a newly reviewed authority
commit and newly frozen hashes; it is not a license to mutate the current
v0.3.12 lock in place.

Before the first pilot claim, the ledger must complete the workload-v2 seed
universe in its frozen order. Each `/v1/observe` seed stores the exact request
and response hashes, HTTP/contract identity, Runtime echoes, commit assertions,
and a unique `client_id → memory_id → expected role/surface` lineage. An
ambiguous seed dispatch may replay only the exact request bytes with the same
deterministic operation ID; seed calls are outside the paid provider budget.
Aionis trial claims then follow the frozen
order. Every served memory must resolve to a completed seed or earlier outcome,
and its frozen provenance must match all three Runtime projections:
`memory_packet.execution_outcome_role`, persisted
`feedback_attribution_v1.served_surface`, and the AgentContext surface. A failed
branch on `use_now`, a summary on direct use, incomplete attribution, duplicate
ID, or cross-projection mismatch fails before provider dispatch.
The guide plus outcome, feedback, measure, byte-exact measure replay, operator
snapshot and flight-recorder requests are rendered internally. Exact request
and raw response bodies are retained in CAS and reparsed on restart. Successful
trial receipts are constructed by the ledger from those checkpoints; callers
can submit only failure receipts. Pilot and wave recovery parsing requires
strict raw worker-state CAS artifacts, including process-instance, logical
state, queue and health projections, instead of accepting summary booleans.
Those raw artifacts are still supplied by the caller, however; CAS persistence
does not make them supervisor-issued evidence. Their terminal-trial and
persisted-operation universes are rebuilt from the ledger for every historical
checkpoint and must match the raw queue/operation state exactly, which detects
internal mismatch but does not close the trusted-supervisor gap. Offline SQLite
inspection is ledger-owned: its public wrapper derives all 27 soak Aionis
bindings and brands the result to the exact campaign revision, so callers cannot
submit a convenient subset. It does not yet join every database `request_sha256`
to the corresponding immutable request object in campaign CAS; the effective
semantic-digest identity context needed for that join is not frozen in v0.3.12.

## Local validation

Node.js 24 is required.

```bash
npm ci --ignore-scripts
npm test
npm run -s validate:fixture
```

`schemas/workload-manifest.schema.json` is intentionally a structural linting
schema. It is not an admission authority and does not encode every frozen
semantic rule. `validateWorkloadManifest` in `src/contracts.mjs`, together with
the raw manifest hash in the release lock, is the authoritative workload
admission check. Passing JSON Schema validation alone grants no execution or
promotion authority.

A dry plan never requests paid execution:

```bash
node src/run-bounded-soak.mjs pilot \
  --lock config/v0.3.12-release-lock.json \
  --authority fixtures/v0.3.12/authority-manifest.json \
  --workload fixtures/v0.3.12/workload-manifest.json
```

## Stable verifier interface

The Runtime adapter invokes:

```bash
node scripts/verify-stable-promotion.mjs \
  --runtime-root /exact/runtime/checkout \
  --create-root /exact/create/checkout \
  --workflow-evidence /trusted/sanitized-workflow-evidence.json \
  --expected-runtime-commit 0123456789abcdef0123456789abcdef01234567
```

The trusted Runtime adapter fetches GitHub run/job facts with its narrow
`actions:read` token, removes every unused field, and passes only the non-secret
JSON described by `schemas/workflow-run-evidence.schema.json`. The external
verifier never receives that token. The evidence path must be a regular
non-symlink file with mode `0600` or stricter. Production verification requires this
file; unauthenticated public-API lookup exists only behind the explicit
`--allow-anonymous-workflow-fetch` local diagnostic flag.

The verifier checks repository bytes, Git objects, sanitized workflow facts,
six exact-run Actions artifact records, and six public content-addressed release
assets. The artifact names bind kind, harness commit, workflow run, attempt and
raw SHA-256; release assets must be created by the later protected publisher in
that same run. The soak release itself must target the authority commit and be
reported immutable by GitHub. It validates annotated
candidate/stable tags, first-parent lineage, a narrow post-candidate allowlist,
dependency and behavior no-drift, the exact Create default, raw receipt and
manifest hashes, models, three-wave denominators, recovery, terminal backlog,
duration, cost and previous `latest` coordinates. Its success JSON has exactly
nine fields. A failure writes no success JSON and grants no publication
authority.

For the current v0.3.12 workload, the verifier intentionally fails after those
provenance and fact checks with
`product_invariant_query_contract_unfrozen`. The workload freezes five
invariant names, but not the executable query/behavior protocol required to
derive their results independently. Consequently the nine-field success JSON
contract is dormant until a new workload freezes that protocol; self-reported
`passed` values and syntactically valid query/result hashes cannot authorize a
stable release.

## Artifact manifest

Six non-empty, sanitized canonical JSONL artifacts are required: API receipts, flight
recorder, offline SQLite verification, operator snapshots, raw agent streams,
and worker state. The builder rejects missing/duplicate kinds, symlinks,
secret-like material, non-JSONL bundles, mutable filenames, wrong workflow
identity and an existing output path. Every release asset name contains its
SHA-256 and is limited to 8 MiB.

All workflows in the current repository, including the placeholder publisher
job, have only `contents: read`. When the executor is implemented, the protected
soak producer must retain read-only repository permission and upload the six
content-addressed files as Actions artifacts attached to its exact run. A later,
separately reviewed GitHub-hosted publisher job behind
`bounded-soak-publisher` may receive a job-scoped `contents: write` grant only
after it downloads and revalidates those same-run artifacts. The executable
producer/upload and publisher paths are currently unavailable and fail closed.

Stable admission does not trust the summary receipt by itself. The current v2
parser requires the exact 90-trial ID universe, rejects duplicate or missing
published-field joins, binds record headers to the candidate, harness,
pilot/soak run and frozen model/policy, and recomputes summary metrics from the
submitted records. It is still only a structural post-run evidence format: it
does not bind those records to the campaign-ledger revision and private CAS,
per-exchange trusted transport authority, trusted host task/use receipts, or a
trusted recovery supervisor. Its invariant rows are also only named booleans
and hashes, not executable semantic evidence. Consequently parser/reducer
acceptance cannot turn caller-produced or synthetic records into authoritative
evidence. Stable success remains impossible because the independent
`product_invariant_query_contract_unfrozen` blocker executes after the existing
checks. Artifact v3 and the other pre-unblock boundaries above are required
before that blocker may be replaced by an executable invariant protocol.
The exact per-kind record shapes are documented in
`docs/ARTIFACT_RECORD_CONTRACT.md` and enforced by the same reducer used by the
stable gate.

The evaluation repository and its soak release assets must be public for the
stable verifier's token-free asset downloads. Provider values never belong in
the repository, release assets, sanitized workflow evidence or Runtime adapter
environment passed to this verifier.

The repository scaffold, read-only branch-protection CI, protected workflow
contracts and verifier are ready. Both GitHub environments are configured with
the current reviewer and protected-branch controls documented in
`.github/ENVIRONMENT-PROTECTION.md`; the provider executor, trusted collectors,
paid execution, artifact v3, and release publication remain intentionally
unavailable.
