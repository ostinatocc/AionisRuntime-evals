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

## Development

```bash
npm install --ignore-scripts
npm run check
```

`npm run test:runtime-v1` additionally requires an exact local Runtime
checkout and its locally packed `@aionis/continuation-sdk`. The integration
gate uses real signed policy provisioning, a real SQLite authority, and real
HTTP SDK traffic. It does not call an external model.

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

Historical pre-V1 eval directories may still exist in an old local workspace,
but they are ignored and are not part of this repository's V1 authority tree.
