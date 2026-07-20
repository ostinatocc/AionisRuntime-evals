# Aionis Runtime external soak authority

This repository is the Git-authoritative home for the bounded release soak. It
is deliberately outside the focused Runtime daemon and carries no publication
authority. The Runtime stable gate checks out one exact commit and executes
`scripts/verify-stable-promotion.mjs`; it does not copy this implementation into
Runtime core.

## Current safety state

This is a scaffold, not an enabled paid runner. It can validate the frozen
v0.3.12 candidate, build deterministic trial plans, verify stable-promotion
evidence, and build content-addressed artifact manifests. The provider executor
is intentionally absent. Even with an exact protected GitHub context, a paid
phase stops with `PAID_EXECUTOR_UNAVAILABLE` before any provider request.

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
- the raw SHA-256 of the authority/workload manifests and stable-promotion
  governance callers.

## Local validation

Node.js 24 is required.

```bash
npm ci --ignore-scripts
npm test
npm run -s validate:fixture
```

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

## Artifact manifest

Six non-empty, sanitized canonical JSONL artifacts are required: API receipts, flight
recorder, offline SQLite verification, operator snapshots, raw agent streams,
and worker state. The builder rejects missing/duplicate kinds, symlinks,
secret-like material, non-JSONL bundles, mutable filenames, wrong workflow
identity and an existing output path. Every release asset name contains its
SHA-256 and is limited to 8 MiB.

The protected soak producer has read-only repository permissions. When the
executor is implemented, it must upload the six content-addressed files as
Actions artifacts attached to its exact run. A separate GitHub-hosted job behind
`bounded-soak-publisher` is the only job allowed `contents: write`; it must
download and revalidate those same-run artifacts before creating release assets.
Both jobs are currently unavailable and fail closed.

Stable admission does not trust the summary receipt by itself. A pinned
deterministic reducer requires the exact 90-trial ID universe, rejects duplicate
or missing cross-artifact joins, binds every record to the candidate, harness,
pilot/soak run and frozen model/policy, then recomputes action completion,
0/9 negative direct-use, all coverage, 5/5 invariants, 3/3 recovery, backlog,
context and cost. The v2 records cross-join unique request, operation and
provider-request IDs plus raw request/response hashes; provider usage is the
sole token/cost source, and recovery/SQLite conclusions bind instance and state
digests. The recomputed pilot, waves, aggregate and execution totals
must deep-equal the receipt.
The exact per-kind record shapes are documented in
`docs/ARTIFACT_RECORD_CONTRACT.md` and enforced by the same reducer used by the
stable gate.

The evaluation repository and its soak release assets must be public for the
stable verifier's token-free asset downloads. Provider values never belong in
the repository, release assets, sanitized workflow evidence or Runtime adapter
environment passed to this verifier.

The repository scaffold, read-only branch-protection CI, protected workflow
contracts and verifier are ready. Environment configuration, provider executor
implementation, paid execution and release publication remain intentionally
unavailable.
