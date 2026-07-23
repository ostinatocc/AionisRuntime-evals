# Aionis Continuation Runtime Evals

This repository is the independent external evidence authority for Aionis
Continuation Runtime V1. It does not ship Runtime code, compile policy, or
turn one task result into a product rule.

The release pilot has exactly three arms over three frozen cases:

- `baseline`: no Runtime traffic;
- `observe_only`: the same observation request as treatment, with no
  continuation request and no model-visible Runtime content;
- `treatment`: observation, a strictly decoded continuation projection, a
  blind post-exit verifier, and a closed Runtime outcome ledger.

The 3 x 3 pilot is a directional release gate for verified continuity. It is
not a statistical claim and it is not the governed-learning effect cohort.
The Runtime cohort remains an independent `control` versus `candidate`
evidence gate.

The frozen external model protocol uses DeepSeek directly through
`https://api.deepseek.com/chat/completions` with `deepseek-v4-flash`, thinking
enabled, `reasoning_effort=max`, JSON output, and no retries. All nine
cells share that exact protocol. Provider credentials are runtime secrets and
must never enter a plan, receipt, ledger event, report, workspace, or CI
configuration.

Before freezing the nine-call pilot, the live provider contract can be checked
with one unscored request:

```bash
chmod 0600 "/absolute/path/to/deepseek-api-key"
exec {DEEPSEEK_FD}<"/absolute/path/to/deepseek-api-key"
npm run -s provider:smoke -- --deepseek-key-fd "$DEEPSEEK_FD"
```

The CLI accepts no plaintext-key or key-path argument, uses the platform
`fetch`, performs no retry, and emits one canonical receipt without raw prompt,
response, or credential content. The receipt always has
`claim_eligible=false`; it proves only the provider/model contract, never
Aionis product effect.

## Development

```bash
npm install --ignore-scripts
npm run check
```

`npm run test:runtime-v1` additionally requires an exact local Runtime
checkout and its locally packed `@aionis/continuation-sdk`. The integration
gate uses real signed policy provisioning, a real SQLite authority, and real
HTTP SDK traffic. It does not call an external model.

Freeze the formal artifacts from a canonical non-secret blueprint only after
both repositories and the locked Runtime authority closure are clean:

```bash
cp config/release-pilot-blueprint.example.canonical.json \
  /absolute/path/to/release-pilot-blueprint.canonical.json
# Replace every /absolute placeholder and image digest, then rewrite the file
# as one canonical JSON line.
exec {ROOT_FD}<"/absolute/path/to/root-private.pem"
npm run -s pilot:freeze-release -- \
  --blueprint /absolute/path/to/release-pilot-blueprint.canonical.json \
  --output /absolute/path/to/fresh-0700-freeze-root \
  --root-signing-key-fd "$ROOT_FD"
```

The freezer emits three small audited Git templates, three case artifacts, the
Latin-square plan, three OCI verifier configurations, nine root-signed cell
policy commands, runner/verifier public artifacts, and the non-secret
orchestration config. It creates fresh Ed25519 runner, three verifier, and
future-effect private keys under the caller-selected `0700` root with mode
`0600`; none of their bytes or paths enters the public config. The three
single-action cases use neutral A/B display, environment, and credential
selectors; accepted directions are balanced as closely as three cases permit.
The public prompt contains the complete relevant source tree but not the prior
verifier verdict; only treatment receives that accepted-path evidence through
Aionis.

The prior evidence explicitly has
`source_kind=preseeded_verified_state`: it does not claim an episode-1 LLM
action. During freezing, a private preseeded workspace contains the accepted
state, each semantic check runs in a fresh host Node subprocess that reads the
target only as inert text, and the case verifier key signs the resulting
canonical receipt. The freezer then independently recomputes the workspace,
source, host executable, configured check-set, and actual execution-argv
digests before binding that full signed-receipt digest into the source fixture,
episode event, Runtime host task, and collector observation.

The frozen post-agent OCI verifier uses the same four static checks and never
imports or executes an agent-modified module. Those checks report completion,
accepted direction, prohibited-branch writes, and unsafe direct use. Their
line-break-sensitive lexical digests admit only the frozen source or one exact
candidate-call implementation, reject comments and hard-coded substitutes,
and cannot be short-circuited by an agent-written `process.exit(0)`. An
unchanged `no_safe_change` workspace or malformed source fails completion
without being mislabeled as unsafe direct use.

Freezing performs zero model requests and zero OCI executions. Its
`artifact_verified` report proves canonical bindings, not resource readiness
or product effect. The next command must therefore be the release runner's
`--preflight-only` resource gate. The example blueprint is deliberately
non-runnable until all placeholder paths and digests are replaced.

Because Runtime's `dist-authority` and SDK build outputs are intentionally
ignored by Git, the freezer does not trust their self-description alone. The
Runtime lock pins the authority manifest bytes, closure, entrypoint, file
count, authoring module, every manifest-listed file digest, and the exact
packed SDK SHA-256/SHA-512. All authority files are rechecked before dynamic
import and again immediately before and after signing. The root private
`KeyObject` is created only inside that synchronous signing scope; case,
verifier, SDK, and artifact construction code never receives it.

Frozen pilot artifacts are checked as canonical single-line JSON files:

```bash
npm run pilot:preflight -- \
  --plan /absolute/path/to/plan.json \
  --case /absolute/path/to/case-1.json \
  --case /absolute/path/to/case-2.json \
  --case /absolute/path/to/case-3.json
```

Artifact preflight validates the plan self-hash, all case self-hashes, the ordered
fixture-set digest, the protocol projection digest, the exact Latin-square
schedule, the nine-request ceiling, and the no-cohort boundary. It performs
no provider request and deliberately reports `artifact_verified`, not
`ready`. The executable runner must additionally prove the locked Git trees,
SDK/OCI/policy artifacts, per-cell workspace/Runtime/process isolation, and
verifier authority before any scored request is authorized.

## Executable authority status

The offline 3 x 3 executable test is intentionally marked
`non_release_contract_test`. Its injected provider transport, controlled OCI
executable, and injected Runtime adapters can exercise the complete 58-event
ledger, sealed replay, verifier process, and signer process, but can never
produce a claim-eligible manifest.

The release runner rejects injected transports, test OCI authorities, copied
resource handles, and raw caller-provided adapters before creating a ledger or
sending HTTP. The trusted release provisioner and FD-only production CLI are
implemented. They bind the packed SDK, nine private Git workspaces, nine live
Runtime containers, signed policy set, three fresh OCI verifiers, runner
authorization signer, and terminal signer without accepting a private-key
path or plaintext credential.

The CLI accepts one canonical non-secret orchestration config plus five
already-open numeric descriptors. Secret files must be caller-owned regular
files with one link and mode `0400` or `0600`. The example uses placeholders
only:

The config schema is `aionis_release_pilot_orchestration_config_v1` and is
self-hashed by `artifact_sha256`. It contains only absolute paths for the plan,
three ordered cases, nine-cell policy set, packed SDK and consumer root, three
ordered verifier-public artifacts, runner-public artifact, three Git template
roots, trust-root public key, private run root, ledger authority root, and
Git/OCI executables, plus the immutable Runtime image reference. Runner and
verifier public artifacts contain only Ed25519 SPKI DER (`base64url`), its
public principal, and—for verifiers—the canonical verifier config. No config
field exists for a secret value or private-key path.

The plan's `eval_binding` also freezes `git_executable_path`,
`git_executable_sha256`, and `git_executable_identity_sha256` alongside the
eval commit, tree, and source closure. Formal execution accepts only that
exact absolute Git realpath when it is a root-owned regular executable that
is not group- or world-writable. The source closure encoding is
`tracked_git_mode_nul_path_nul_content_sha256_lf_v1`: every tracked file is
read with `O_NOFOLLOW`, checked against its Git blob, and folded with its Git
mode and path. `git status --porcelain=v1 -z --untracked-files=all` must be
empty, so modified, staged, and non-ignored untracked files all fail closed.
The live receipt additionally seals a host-local file/directory identity epoch
(inode, mode, ownership, link count, size, mtime, and ctime), so changing a
tracked file and restoring identical bytes between gates is still detected.
The deliberately ignored historical corpus described below remains outside
the V1 authority tree.

This is a live gate, not a declaration copied from the plan. The CLI scans
the module-fixed current eval repository before creating SDK, workspace, or
Runtime resources; revalidates the same opaque provenance lease before
authorization and before any ledger/provider work; and revalidates again
before terminal signing. The authorization and final signer children perform
their own live scan. Source drift can therefore produce only a
claim-ineligible `eval_provenance` / `provenance_invalid` abort after a ledger
exists, never a release final manifest.

```bash
exec {DEEPSEEK_FD}<"/absolute/placeholder/deepseek-api-key"
exec {RUNNER_FD}<"/absolute/placeholder/runner-signing-key.pk8"
exec {VERIFIER_1_FD}<"/absolute/placeholder/verifier-1.pk8"
exec {VERIFIER_2_FD}<"/absolute/placeholder/verifier-2.pk8"
exec {VERIFIER_3_FD}<"/absolute/placeholder/verifier-3.pk8"

env -i HOME="$HOME" PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  LANG=C LC_ALL=C TZ=UTC \
  node src/cli/run-release-pilot.mjs \
    --config /absolute/path/to/release-orchestration.canonical.json \
    --deepseek-key-fd "$DEEPSEEK_FD" \
    --runner-signing-key-fd "$RUNNER_FD" \
    --verifier-private-key-fd "$VERIFIER_1_FD" \
    --verifier-private-key-fd "$VERIFIER_2_FD" \
    --verifier-private-key-fd "$VERIFIER_3_FD" \
    --preflight-only
```

`--preflight-only` is a real resource preflight: it validates the packed SDK,
creates and verifies all nine workspaces and Runtime resources, attests all
five secret FDs in fresh children, constructs the live execution manifest,
signs an execution authorization, and then confirms reverse cleanup. It
creates no ledger and sends zero provider requests. Its status is
`release_resources_verified_not_executed`, with `claim_eligible=false`; it is
not an effect result.

Omit `--preflight-only` only for the frozen nine-call run. The main CLI rejects
secret environment variables plus all `NODE_*`, TLS key-log/CA overrides,
OpenSSL config, proxy variables (including lowercase variants), and dynamic
loader overrides. Run it from a deliberately sparse supervisor environment.
Once a formal ledger reserves a provider attempt, the same `pilot_id` must not
be restarted or replayed; freeze a new pilot authority instead.

After an unclean exit, reconcile the durable Runtime and workspace owners
before attempting another pilot. Recovery uses the same canonical public
config and exact Git/OCI authorities, but accepts no secret descriptors,
creates no new owner or ledger, and sends no provider request:

```bash
env -i HOME="$HOME" PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  LANG=C LC_ALL=C TZ=UTC \
  npm run -s pilot:recover-release -- \
    --config /absolute/path/to/release-orchestration.canonical.json
```

A successful result has `status=orphan_reconciliation_complete` and
`claim_eligible=false`. Recovery removes only resources that match the sealed
owner, plan, cell, image, mount, and authority bindings. Ambiguous ownership,
authority failure, or incomplete cleanup fails closed, retains the resources
and private receipts for inspection, and blocks the next pilot.

This repository still does not contain a completed real nine-call release
pilot or release-effect claim. The CLI makes that run possible; it does not
substitute infrastructure readiness for product evidence.

Historical pre-V1 eval directories may still exist in an old local workspace,
but they are ignored and are not part of this repository's V1 authority tree.
