import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  agentActionSha256V2,
  buildAgentModelInputV1,
  decodeAgentActionV2,
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

test("controls are byte-identical and the signed case path enters the v2 instruction", () => {
  const keys = generateKeyPairSync("ed25519");
  const pilotCase = buildTestPilotCaseV1({
    caseId: "agent-input-case",
    verifierPrivateKey: keys.privateKey,
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
  assert.match(
    baseline.messages[0].content,
    /schema_version must be exactly aionis_pilot_agent_action_v2\./u,
  );
  assert.match(
    baseline.messages[0].content,
    /action must be exactly \{"kind":"replace_text","path":"src\/continuation\.mjs","old_text":"<exact-existing-text>","new_text":"<replacement-text>"\}/u,
  );
  assert.match(baseline.messages[0].content, /Do not return a diff\./u);
  assert.match(
    baseline.messages[0].content,
    /old_text must be non-empty, copied verbatim from the provided file, and uniquely identify the intended occurrence/u,
  );
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

test("v2 decodes only one canonical bounded replace_text action", () => {
  const replacement = {
    schema_version: "aionis_pilot_agent_action_v2",
    summary: "Continue through the verified branch.",
    action: {
      kind: "replace_text",
      path: "src/continuation.mjs",
      old_text: "  throw new Error(\"continuation path not selected\");",
      new_text: "  return credentialPathA(sessionId);",
    },
  };
  const decoded = decodeAgentActionV2(replacement);
  assert.deepEqual(decoded, replacement);
  assert.notStrictEqual(decoded, replacement);
  assert.deepEqual(decodeAgentActionV2(JSON.stringify(replacement)), replacement);
  assert.match(agentActionSha256V2(replacement), /^[0-9a-f]{64}$/u);

  const deletion = canonicalClone(replacement);
  deletion.summary = "Delete the obsolete branch marker.";
  deletion.action.old_text = "const obsolete = true;\n";
  deletion.action.new_text = "";
  assert.deepEqual(decodeAgentActionV2(deletion), deletion);

  for (const mutate of [
    (value) => { value.action.extra = true; },
    (value) => { delete value.action.new_text; },
    (value) => { value.action.path = "/src/continuation.mjs"; },
    (value) => { value.action.path = "./src/continuation.mjs"; },
    (value) => { value.action.path = "../src/continuation.mjs"; },
    (value) => { value.action.path = "src//continuation.mjs"; },
    (value) => { value.action.path = "src/.GIT/continuation.mjs"; },
    (value) => { value.action.old_text = ""; },
    (value) => { value.action.new_text = value.action.old_text; },
    (value) => { value.action.old_text = "old\u0000text"; },
    (value) => { value.action.new_text = "new\u0000text"; },
    (value) => { value.action.old_text = "\ud800"; },
    (value) => { value.action.new_text = "\udc00"; },
    (value) => {
      value.action.old_text = "o".repeat(131_073);
      value.action.new_text = "n".repeat(131_072);
    },
    (value) => { value.action.old_text = "o".repeat(262_145); },
  ]) {
    const invalid = canonicalClone(replacement);
    mutate(invalid);
    assert.throws(() => decodeAgentActionV2(invalid), /aionis_eval_/u);
  }
});

test("v2 rejects legacy diff and accepts only exact no_safe_change", () => {
  assert.throws(() => decodeAgentActionV2({
    schema_version: "aionis_pilot_agent_action_v2",
    summary: "Attempt a legacy diff.",
    action: {
      kind: "apply_unified_diff",
      patch: "--- a/state.txt\n+++ b/state.txt\n@@ -1 +1 @@\n-old\n+new\n",
    },
  }), /kind_invalid/u);
  assert.throws(() => decodeAgentActionV2({
    schema_version: "aionis_pilot_agent_action_v1",
    summary: "Attempt an old schema.",
    action: { kind: "no_safe_change", patch: null },
  }), /schema_invalid/u);
  assert.deepEqual(decodeAgentActionV2({
    schema_version: "aionis_pilot_agent_action_v2",
    summary: "The requested change conflicts with the verified state.",
    action: { kind: "no_safe_change", patch: null },
  }).action, { kind: "no_safe_change", patch: null });
});
