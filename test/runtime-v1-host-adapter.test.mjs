import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { canonicalSha256 } from "../src/canonical.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import { createRuntimeV1HostAdapter } from "../src/runtime-v1-host-adapter.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

test("baseline performs no Runtime traffic and exposes no Runtime context", async () => {
  let calls = 0;
  const forbidden = async () => { calls += 1; throw new Error("unexpected Runtime call"); };
  const client = Object.freeze({
    createContinuation: forbidden,
    decideAuthority: forbidden,
    readDecision: forbidden,
    recordObservations: forbidden,
    recordOutcome: forbidden,
  });
  const keys = generateKeyPairSync("ed25519");
  const pilotCase = buildTestPilotCaseV1({
    caseId: "baseline-case",
    verifierPublicKey: keys.publicKey,
  });
  const cell = buildPilotCellV1({
    pilot_id: "pilot-adapter-test",
    opaque_cell_id: "cell-01",
    ordinal: 1,
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    arm: "baseline",
  });
  const adapter = createRuntimeV1HostAdapter({
    cell,
    client,
    pilotCase,
    scope: cell.isolation.runtime_scope,
    verifierPublicKey: keys.publicKey,
  });
  const result = await adapter.prepareArm();
  assert.equal(calls, 0);
  assert.equal(result.runtime, null);
  assert.equal(result.model_context, null);
  assert.equal(
    result.observation_body_sha256,
    canonicalSha256(pilotCase.runtime_input.record_observations_body),
  );
});
