# Required GitHub environment protection

The `bounded-soak` environment is a mandatory external control, not an optional
workflow convention. Before enabling either paid phase, configure it with:

- at least one required reviewer who is not the workflow initiator;
- deployment restricted to the protected default branch and immutable soak tags;
- a dedicated self-hosted runner labelled `aionis-soak-persistent` with a
  persistent Runtime volume;
- no provider values at repository or organization scope;
- provider values only in this protected environment after the paid executor is
  implemented and independently reviewed.

The current scaffold intentionally contains no provider executor and references
no provider values. Therefore protected pilot/soak preflight always terminates
with `PAID_EXECUTOR_UNAVAILABLE` after every frozen-coordinate check passes.

The `bounded-soak-publisher` environment is a second mandatory trust boundary.
Configure it with an independent required reviewer and deployment restrictions
matching the exact authority commit. Its GitHub-hosted job is the only job with
`contents: write`; it must run after the protected soak producer, download the
six artifacts attached to that exact workflow run, revalidate every raw byte and
content hash, and only then publish the six content-addressed release assets.

The publisher is also intentionally unavailable in this scaffold. It always
terminates with `EVIDENCE_PUBLISHER_UNAVAILABLE`; no release asset can be emitted
until the producer upload and independent publisher implementation are reviewed.
