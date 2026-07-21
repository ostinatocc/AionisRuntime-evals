# Protected campaign-head authority

`src/campaign-head-authority.mjs` is the local monotonic sequencing authority for
the campaign ledger. It is groundwork for a future paid executor; its persisted
metadata fixes `admission_mode` to `blocked_groundwork`, and the module exposes
no transition that can enable admission.

## Authority and projection

The authority root and campaign root are separate directory trees. The
authority root contains the non-replaceable sequencing state; the campaign
root contains `campaign-ledger.json` and private evidence CAS objects. The JSON
ledger is a rebuildable projection, never the authority for a transition.

```text
$AIONIS_CAMPAIGN_AUTHORITY_ROOT/          0700
├── .campaign-authority.lock              0600
├── campaign-authority.sqlite             0600
└── journal/                               0700
    ├── run-claims/                        0700
    │   └── run-<sha256>.json              0400, O_EXCL
    ├── campaign-claims/                   0700
    │   └── campaign-<sha1>.json           0400, O_EXCL
    ├── heads/                             0700
    │   └── <campaign>/<generation>/       0700
    │       └── <revision>-<sha256>.json   0400, no-clobber
    └── projection-acks/                   0700
        └── <campaign>/<generation>/       0700
            └── <revision>-<sha256>.json   0400, no-clobber

$AIONIS_CAMPAIGN_ROOT/                    0700
├── campaign-ledger.json                  0600, replaceable projection
└── evidence/                             existing private CAS
```

Provisioning is an explicit administrative operation through
`provisionCampaignHeadAuthority`. Normal execution receives an opaque handle
from `openCampaignHeadAuthority`; it does not create a missing root, database,
claim, or schema. A future runner must take the authority-root path only from
protected runner configuration, never from workflow input or a campaign CLI
argument.

All state-changing and protected read paths take the one global authority
kernel lock. There is no campaign-local lock and therefore no global/local lock
order to invert. While holding the lock, the implementation rechecks the
canonical authority root, database and lock inode identities, validates the
SQLite schema and integrity, and binds the campaign root by canonical path,
device, inode, owner, and a derived ledger-instance digest. The journal and all
fixed claim/head/acknowledgement directory identities are frozen in the opaque
handle too. Immutable files are opened with `O_NOFOLLOW` and read from one file
descriptor whose identity, size, mode, owner, link count and final pathname are
rechecked. Authority callbacks are synchronous; promises and thenables are
rejected before the lock can escape its lexical critical section.

## Run singleton

The singleton key is the GitHub run series:

```json
{"repository":"owner/repository","run_id":12345}
```

Its ID is the SHA-256 of that canonical, versioned object. The immutable claim
also binds the first `run_attempt`, phase, exact `head_sha`, job, environment,
campaign, generation, and campaign-directory identity. An identical retry is
idempotent. A different attempt or any other changed field under the same run
series is a permanent conflict; a GitHub rerun cannot mint another paid
generation. `begin_soak` must separately claim its soak run series before its
event can enter the head journal.

## Monotonic head

Revision zero stores the complete genesis payload. Every later immutable record
stores exactly one accepted event and binds:

- authority, campaign, pilot run, actor run, generation, and ledger instance;
- revision and the predecessor head and payload SHA-256 values;
- the next canonical payload SHA-256; and
- a SHA-256 over the complete record body.

Revision filenames include both the zero-padded revision and record digest.
Each immutable record is fully written and fsynced in a private staging file,
changed to `0400`, fsynced again, then hard-linked without clobber to its final
name and directory-fsynced. A stale staging link is recoverable under the
authority lock; a final revision is never replaced or reused. Projection
acknowledgements use the same publication protocol after the envelope rename
and directory sync. The SQLite database is a transactional, exact-schema index;
it is not allowed to lead either immutable journal. If it is behind continuous
valid head and acknowledgement journals, every missing run/head/projection row
is repaired without changing the generation.

The campaign envelope is valid only when its complete `authority_head` and
payload match the protected current head. A known previous envelope is used for
recovery only when the current journal revision has not yet been acknowledged
as projected. Restoring a previously acknowledged envelope, copying a campaign
directory, changing its inode, introducing a journal gap, or presenting a
SQLite index ahead of the journal fails closed.

Normal reads validate the SQLite chain, immutable current tail, current
projection acknowledgement and exact bound envelope. This keeps campaign
execution linear rather than replaying an ever-growing payload on every event.
`auditCampaignLedger` re-reads and hashes every immutable revision and
acknowledgement, reconstructs every payload prefix, and must run in admission
preflight and after recovery before paid authority can ever be enabled. It also
requires the campaign and generation namespaces under both journals to be a
bijection with immutable campaign claims. SQLite uses `synchronous=FULL`,
`fullfsync=ON`, and the rollback-journal mode; the production mount must still
prove its own filesystem and power-loss semantics.

## Crash outcomes

| Last durable state | Recovery result |
| --- | --- |
| claim/head temporary file was never published | no accepted mutation |
| immutable claim exists but SQLite row is absent | repair the same singleton row |
| immutable head/acknowledgement exists but SQLite is behind | repair every missing revision and actor-run row |
| journal is current and the JSON projection is the acknowledged predecessor | rebuild the current projection once |
| JSON projection is current but projection acknowledgement is absent | acknowledge that exact protected head |
| SQLite is ahead, journal has a gap/fork, or projection is an unknown state | fail closed and preserve evidence |

A CAS object written before the authority lock can remain as an unreachable
orphan after a stale mutation loses CAS. It cannot become a ledger event without
the protected head transition. Provider dispatch remains independently
blocked; when implemented, `provider_dispatch_started` must be durable in this
authority before a socket send, and an ambiguous post-marker crash must never
auto-resend.

## Trust boundary and unresolved whole-root rollback

This design assumes the complete authority root is on a protected, persistent,
non-rollback filesystem outside the campaign directory and is writable only by
the trusted runner identity. It detects rollback or copying of the campaign
directory while that authority survives. It also repairs a rolled-back SQLite
index while the immutable journal survives.

No purely local file format can detect cloning or restoring the complete
authority root together with its journal, SQLite database, metadata, and lock.
Two such copies can carry the same authority ID and diverge. Before paid
admission, the real runner mount must be verified and the run claim/current
head must be anchored in a non-clonable protected service or remote append-only
log if host- or volume-level rollback is in scope. Hosted CI only proves the
module's local semantics; it cannot certify the production mount or supply that
external anchor.

Consequently, this module closes campaign-directory revision ABA and duplicate
creation within one surviving authority root. It does not, by itself, authorize
the 9-call pilot, soak, artifact publication, or stable promotion.
