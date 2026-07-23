import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import * as authoritySurface from "../src/release-cell-resource-authority.mjs";
import * as provisionerSurface from "../src/release-cell-resource-provisioner.mjs";
import {
  claimReleaseCellResourceAuthorityV1,
  disposeReleaseCellResourceAuthorityV1,
} from "../src/release-cell-resource-provisioner.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

test("release resource minting is absent from the public authority surface", () => {
  assert.deepEqual(Object.keys(authoritySurface).sort(), [
    "claimReleaseCellResourceAuthorityV1",
    "disposeReleaseCellResourceAuthorityV1",
  ]);
  assert.deepEqual(Object.keys(provisionerSurface).sort(), [
    "claimReleaseCellResourceAuthorityV1",
    "disposeReleaseCellResourceAuthorityV1",
    "provisionReleaseCellResourcesV1",
  ]);
});

test("caller-shaped claim-eligible handles cannot mint or claim release resources", async () => {
  const cases = [1, 2, 3].map((index) => buildTestPilotCaseV1({
    caseId: `release-authority-private-${index}`,
    verifierPublicKey: generateKeyPairSync("ed25519").publicKey,
  }));
  const plan = buildTestPilotPlanV1(cases, {
    pilotId: "release-cell-resource-authority-private-issuer-test",
  });
  const forged = Object.freeze(Object.assign(Object.create(null), {
    schema_version: "aionis_release_cell_resource_authority_handle_v1",
    authority_class: "release_cell_resource_authority_v1",
    claim_eligible: true,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    execution_manifest_sha256: "a".repeat(64),
    resource_count: plan.schedule.length,
    resource_authority_closure_sha256: "b".repeat(64),
  }));
  assert.throws(
    () => claimReleaseCellResourceAuthorityV1({
      cellResourceAuthority: forged,
      plan,
    }),
    /brand_invalid/u,
  );
  await assert.rejects(
    () => disposeReleaseCellResourceAuthorityV1(forged),
    /brand_invalid/u,
  );
});
