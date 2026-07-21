# Current GitHub environment protection

The `bounded-soak` and `bounded-soak-publisher` environments already exist in
the repository. At this authority snapshot, both environments have the same
GitHub-side deployment protection:

- the configured reviewer pool is `Cognary` and `ostinatocc`;
- one eligible configured reviewer must approve a deployment;
- self-review is prevented, so the workflow initiator cannot approve their own
  deployment; and
- deployment branches are restricted to protected branches
  (`protected_branches: true`, custom branch policies disabled).

These are current external controls, not permissions granted by workflow YAML.
They do not make either executable path complete. The paid producer additionally
requires a dedicated self-hosted runner labelled `aionis-soak-persistent` with
a persistent Runtime volume and a separate protected, persistent, non-rollback
campaign-authority mount. The authority-root path must come only from protected
runner configuration, never workflow input. A Linux runner must also provide
the trusted util-linux `flock` capability required by the authority lock
boundary. Its preflight must exercise acquire/contend/SIGKILL recovery on the
actual authority mount, perform a complete campaign-journal audit, and verify
the filesystem, ownership and private-mode contract. Hosted CI cannot certify
that mount. A non-clonable service or remote append-only anchor remains required
if complete host or authority-volume rollback is in scope. Provider
values must remain absent from repository and organization scope and must not be
added to an environment until the paid executor and all admission pre-unblock
authorities are implemented and independently reviewed.

The current scaffold intentionally contains no provider executor and references
no provider values. Therefore protected pilot/soak preflight always terminates
with `PAID_EXECUTOR_UNAVAILABLE` after every frozen-coordinate check passes.

The `bounded-soak-publisher` environment is a second mandatory trust boundary,
but the current placeholder job still inherits the workflow's
`contents: read`; no current job has `contents: write`. A future publisher
implementation may add a narrow job-scoped `contents: write` permission only
after independent review. It must run after the protected soak producer,
download the six artifacts attached to that exact workflow run, revalidate
every raw byte and content hash, and only then publish content-addressed release
assets targeted at the exact authority commit.

The publisher is also intentionally unavailable in this scaffold. It always
terminates with `EVIDENCE_PUBLISHER_UNAVAILABLE`; no release asset can be emitted
until the producer upload and independent publisher implementation are reviewed.
