import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildAgentExecutionAuthorityV1,
  executeAgentActionV1,
  verifyAgentExecutionAuthorityV1,
  verifyAgentExitReceiptV1,
} from "../src/agent-execution.mjs";
import { canonicalClone, canonicalSha256 } from "../src/canonical.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

test("agent action executes one bounded diff in a fresh process and emits a bound receipt", async () => {
  const workspace = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-agent-execution-"),
  ));
  try {
    await writeFile(path.join(workspace, "state.txt"), "old\n", "utf8");
    const keys = generateKeyPairSync("ed25519");
    const pilotCase = buildTestPilotCaseV1({
      caseId: "agent-execution-case",
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
    });
    const cell = buildPilotCellV1({
      pilot_id: "pilot-agent-execution-test",
      opaque_cell_id: "cell-agent-execution",
      ordinal: 1,
      case_id: pilotCase.case_id,
      case_sha256: pilotCase.case_sha256,
      arm: "treatment",
    });
    const assistantContent = JSON.stringify({
      schema_version: "aionis_pilot_agent_action_v1",
      summary: "Apply the accepted state.",
      action: {
        kind: "apply_unified_diff",
        patch: [
          "diff --git a/state.txt b/state.txt",
          "index 3367afd..c0d0fb4 100644",
          "--- a/state.txt",
          "+++ b/state.txt",
          "@@ -1 +1 @@",
          "-old",
          "+accepted",
          "",
        ].join("\n"),
      },
    });
    let tick = 0;
    const clock = () => new Date(Date.UTC(2026, 6, 22, 0, 0, 0, tick++));
    const receipt = await executeAgentActionV1({
      cell,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        workspacePath: workspace,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent,
      providerResponseReceiptSha256: canonicalSha256({ receipt: "provider" }),
      clock,
    });

    assert.equal((await readFile(path.join(workspace, "state.txt"), "utf8")), "accepted\n");
    assert.equal(receipt.execution_status, "applied");
    assert.equal(receipt.exit_code, 0);
    assert.notEqual(receipt.workspace_before_sha256, receipt.workspace_after_sha256);
    assert.deepEqual(verifyAgentExitReceiptV1(receipt, cell), receipt);

    const tampered = canonicalClone(receipt);
    tampered.workspace_after_sha256 = "f".repeat(64);
    assert.throws(
      () => verifyAgentExitReceiptV1(tampered, cell),
      /receipt_integrity_invalid/u,
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("invalid model output is rejected by the executor without mutating the workspace", async () => {
  const workspace = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-agent-reject-"),
  ));
  try {
    await writeFile(path.join(workspace, "state.txt"), "old\n", "utf8");
    const keys = generateKeyPairSync("ed25519");
    const pilotCase = buildTestPilotCaseV1({
      caseId: "agent-reject-case",
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
    });
    const cell = buildPilotCellV1({
      pilot_id: "pilot-agent-reject-test",
      opaque_cell_id: "cell-agent-reject",
      ordinal: 1,
      case_id: pilotCase.case_id,
      case_sha256: pilotCase.case_sha256,
      arm: "baseline",
    });
    const receipt = await executeAgentActionV1({
      cell,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        workspacePath: workspace,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent: "not json and not a patch",
      providerResponseReceiptSha256: canonicalSha256({ receipt: "provider-invalid" }),
    });
    assert.equal(receipt.execution_status, "response_rejected");
    assert.equal(receipt.exit_code, 64);
    assert.equal(receipt.workspace_before_sha256, receipt.workspace_after_sha256);
    assert.equal((await readFile(path.join(workspace, "state.txt"), "utf8")), "old\n");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("execution authority rejects a same-content inode replacement", async () => {
  const workspace = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-agent-identity-"),
  ));
  try {
    const statePath = path.join(workspace, "state.txt");
    await writeFile(statePath, "stable\n", { mode: 0o600 });
    const keys = generateKeyPairSync("ed25519");
    const pilotCase = buildTestPilotCaseV1({
      caseId: "agent-identity-case",
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
    });
    const cell = buildPilotCellV1({
      pilot_id: "pilot-agent-identity-test",
      opaque_cell_id: "cell-agent-identity",
      ordinal: 1,
      case_id: pilotCase.case_id,
      case_sha256: pilotCase.case_sha256,
      arm: "baseline",
    });
    const authority = await buildAgentExecutionAuthorityV1({
      cell,
      workspacePath: workspace,
      gitExecutablePath: "/usr/bin/git",
    });
    assert.match(authority.workspace_prepared_inode_set_sha256, /^[0-9a-f]{64}$/u);

    const replacementPath = path.join(workspace, "replacement.txt");
    await writeFile(replacementPath, "stable\n", { mode: 0o600 });
    await rename(replacementPath, statePath);
    await assert.rejects(
      () => verifyAgentExecutionAuthorityV1(authority, cell),
      /aionis_eval_agent_execution_execution_authority_live_mismatch/u,
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
