import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  agentActionSha256V1,
  buildAgentModelInputV1,
  decodeAgentActionV1,
} from "../src/agent-action.mjs";
import { canonicalClone, sha256Bytes } from "../src/canonical.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

function prepared(pilotCase, arm, modelContext = null) {
  const cell = buildPilotCellV1({
    pilot_id: "pilot-agent-action-test",
    opaque_cell_id: `cell-${arm}`,
    ordinal: 1,
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    arm,
  });
  return {
    schema_version: "aionis_pilot_prepared_arm_v1",
    cell,
    arm,
    observation_body_sha256: pilotCase.runtime_input.record_observations_body_sha256,
    model_context: modelContext,
    runtime: arm === "baseline" ? null : {
      observation: {},
      continuation: arm === "treatment" ? {
        render_content_sha256: sha256Bytes(Buffer.from(modelContext, "utf8")),
      } : null,
      settlement: null,
    },
  };
}

test("baseline and observe-only model inputs are byte-identical while treatment adds only context", () => {
  const keys = generateKeyPairSync("ed25519");
  const pilotCase = buildTestPilotCaseV1({
    caseId: "agent-input-case",
    verifierPublicKey: keys.publicKey,
  });
  const baseline = buildAgentModelInputV1({
    pilotCase,
    preparedArm: prepared(pilotCase, "baseline"),
  });
  const observed = buildAgentModelInputV1({
    pilotCase,
    preparedArm: prepared(pilotCase, "observe_only"),
  });
  const treatment = buildAgentModelInputV1({
    pilotCase,
    preparedArm: prepared(pilotCase, "treatment", "Verified state: continue branch B."),
  });

  assert.deepEqual(baseline, observed);
  assert.equal(baseline.runtime_context_sha256, null);
  assert.equal(treatment.public_prompt_sha256, baseline.public_prompt_sha256);
  assert.notEqual(treatment.model_input_sha256, baseline.model_input_sha256);
  assert.match(treatment.runtime_context_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(treatment.messages.length, 3);

  const substituted = prepared(pilotCase, "treatment", "Verified state: branch A.");
  substituted.model_context = "Unverified replacement: branch B.";
  assert.throws(
    () => buildAgentModelInputV1({ pilotCase, preparedArm: substituted }),
    /prepared_arm_render_binding_invalid/u,
  );

  const skippedObservation = prepared(pilotCase, "observe_only");
  skippedObservation.runtime.observation = null;
  assert.throws(
    () => buildAgentModelInputV1({ pilotCase, preparedArm: skippedObservation }),
    /prepared_arm_observation_missing/u,
  );
});

test("agent action is a strict single bounded diff or explicit no-safe-change", () => {
  const action = {
    schema_version: "aionis_pilot_agent_action_v1",
    summary: "Update the accepted branch marker.",
    action: {
      kind: "apply_unified_diff",
      patch: [
        "diff --git a/state.txt b/state.txt",
        "--- a/state.txt",
        "+++ b/state.txt",
        "@@ -1 +1 @@",
        "-old",
        "+accepted",
        "",
      ].join("\n"),
    },
  };
  assert.deepEqual(decodeAgentActionV1(JSON.stringify(action)), action);
  assert.match(agentActionSha256V1(action), /^[0-9a-f]{64}$/u);

  for (const mutate of [
    (value) => { value.extra = true; },
    (value) => { value.action.patch = "```diff\n"; },
    (value) => {
      value.action.patch = "diff --git a/../escape b/../escape\n--- a/../escape\n+++ b/../escape\n";
    },
    (value) => {
      value.action.patch = "diff --git a/.git/config b/.git/config\n--- a/.git/config\n+++ b/.git/config\n";
    },
    (value) => {
      value.action.patch = [
        "diff --git a/link b/link", "new file mode 120000", "--- /dev/null",
        "+++ b/link", "@@ -0,0 +1 @@", "+../outside", "",
      ].join("\n");
    },
    (value) => {
      value.action.patch = [
        "diff --git a/old.txt b/new.txt", "similarity index 100%", "rename from old.txt",
        "rename to new.txt", "",
      ].join("\n");
    },
    (value) => {
      value.action.patch = [
        "diff --git a/state.txt b/state.txt", "--- a/other.txt", "+++ b/state.txt",
        "@@ -1 +1 @@", "-old", "+new", "",
      ].join("\n");
    },
  ]) {
    const invalid = canonicalClone(action);
    mutate(invalid);
    assert.throws(() => decodeAgentActionV1(invalid), /aionis_eval_/u);
  }

  assert.deepEqual(decodeAgentActionV1({
    schema_version: "aionis_pilot_agent_action_v1",
    summary: "The requested change conflicts with the verified state.",
    action: { kind: "no_safe_change", patch: null },
  }).action, { kind: "no_safe_change", patch: null });
});
