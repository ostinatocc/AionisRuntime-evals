# Security boundary

- Never commit provider values, authorization headers, environment dumps, raw
  request headers or unsanitized provider error bodies.
- CI and the self-hosted producer have read-only repository permissions and
  disable persisted checkout credentials; only the protected publisher job has
  a job-scoped `contents: write` grant.
- Paid phases require `workflow_dispatch`, an explicit acknowledgement, the
  protected `bounded-soak` environment and a dedicated persistent self-hosted
  runner.
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
- The self-hosted producer remains `contents: read`. Only the later GitHub-hosted
  `bounded-soak-publisher` job may request `contents: write`, after independently
  revalidating the exact-run uploads and publishing an immutable release targeted
  at the exact authority commit. Both executable paths remain unavailable and
  fail closed in this scaffold.
- The deterministic reducer parses canonical JSONL, verifies exact trial-ID
  joins across all six assets and derives admission metrics independently of
  the summary receipt. Hash-valid but meaningless artifacts fail closed.
- The bounded soak has evidence authority only. It cannot publish Runtime tags,
  releases, packages or the Docker `latest` tag.

If sensitive material enters an artifact, do not upload it. Remove the affected
artifact, rotate the exposed provider value through its provider, regenerate the
sanitized evidence and start a new authority run.
