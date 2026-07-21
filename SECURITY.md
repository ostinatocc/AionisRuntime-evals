# Security boundary

- Never commit provider values, authorization headers, environment dumps, raw
  request headers or unsanitized provider error bodies.
- Every current workflow and job, including the placeholder publisher, has only
  `contents: read`; checkout credentials are not persisted. A future protected
  publisher may receive a job-scoped `contents: write` grant only in the same
  reviewed change that implements exact-run download and byte revalidation.
- Paid phases require `workflow_dispatch`, an explicit acknowledgement, the
  protected `bounded-soak` environment and a dedicated persistent self-hosted
  runner.
- The local campaign revision CAS is crash/restart sequencing, not rollback
  resistance. Paid dispatch remains forbidden until a protected non-rollback
  monotonic head and run-scoped singleton reject revision ABA, directory replay,
  and duplicate campaign creation.
- Candidate commit, image digest, models and all budgets come from the committed
  release lock; workflow inputs cannot override them.
- Semantic retries and model/provider fallback are forbidden.
- Raw evidence must be sanitized before the content-addressed artifact manifest
  is generated. The manifest builder rejects common token/header forms and any
  symlink in an artifact path.
- Stable verification receives only a normalized three-job workflow evidence
  document plus six exact-run Actions artifact and six release asset metadata
  records. The trusted Runtime adapter keeps its short-lived `actions:read`
  token; the external verifier process receives neither that token nor the
  broader GitHub Actions environment.
- The self-hosted producer must remain `contents: read`. Only a later,
  independently reviewed GitHub-hosted `bounded-soak-publisher` job may request
  `contents: write`, after revalidating the exact-run uploads and before
  publishing an immutable release targeted at the exact authority commit. Both
  executable paths remain unavailable and fail closed in this scaffold.
- The current v2 deterministic reducer parses canonical JSONL, verifies its
  published trial-ID joins, and derives summary metrics independently of the
  receipt. It does not yet bind campaign/CAS state, trusted transport records,
  trusted host-use receipts, or supervisor-issued recovery evidence. Treat v2
  parser acceptance as structural validation only. Stable promotion remains
  fail-closed because the executable product-invariant protocol is unfrozen;
  artifact v3 and every pre-unblock authority listed in `README.md` are required
  before that terminal blocker can be replaced.
- The bounded soak has evidence authority only. It cannot publish Runtime tags,
  releases, packages or the Docker `latest` tag.

If sensitive material enters an artifact, do not upload it. Remove the affected
artifact, rotate the exposed provider value through its provider, regenerate the
sanitized evidence and start a new authority run.
