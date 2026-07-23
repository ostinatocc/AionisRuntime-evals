import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildAgentExecutionAuthorityV1,
  executeAgentActionV1,
  verifyAgentExecutionAuthorityV1,
  verifyAgentExitReceiptV1,
} from "../src/agent-execution.mjs";
import { canonicalClone, canonicalSha256 } from "../src/canonical.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

const executorPath = fileURLToPath(new URL("../src/cli/apply-agent-action.mjs", import.meta.url));

function replaceTextAction(pathValue, oldText, newText) {
  return JSON.stringify({
    schema_version: "aionis_pilot_agent_action_v2",
    summary: "Replace one exact text occurrence.",
    action: {
      kind: "replace_text",
      path: pathValue,
      old_text: oldText,
      new_text: newText,
    },
  });
}

function runExecutorDirect(workspace, assistantContent) {
  const execution = spawnSync(process.execPath, [
    executorPath,
    "/usr/bin/git",
    "src/continuation.mjs",
  ], {
    cwd: workspace,
    input: `${JSON.stringify({ assistant_content: assistantContent })}\n`,
    encoding: "utf8",
    maxBuffer: 1_048_576,
    timeout: 30_000,
    killSignal: "SIGKILL",
  });
  assert.equal(execution.signal, null, execution.stderr);
  return {
    exitCode: execution.status,
    result: JSON.parse(execution.stdout),
    stderr: execution.stderr,
  };
}

test("agent action executes one bounded replacement in a fresh process and emits a receipt", async () => {
  const workspace = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-agent-execution-"),
  ));
  try {
    await mkdir(path.join(workspace, "src"), { mode: 0o700 });
    await writeFile(
      path.join(workspace, "src", "continuation.mjs"),
      "selected=old\n",
      { encoding: "utf8", mode: 0o600 },
    );
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
    const assistantContent = replaceTextAction(
      "src/continuation.mjs",
      "selected=old",
      "selected=accepted",
    );
    let tick = 0;
    const clock = () => new Date(Date.UTC(2026, 6, 22, 0, 0, 0, tick++));
    const receipt = await executeAgentActionV1({
      cell,
      pilotCase,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        pilotCase,
        workspacePath: workspace,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent,
      providerResponseReceiptSha256: canonicalSha256({ receipt: "provider" }),
      clock,
    });

    assert.equal(
      await readFile(path.join(workspace, "src", "continuation.mjs"), "utf8"),
      "selected=accepted\n",
    );
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

test("replace_text changes the unique match through the bound executor process", async () => {
  const workspace = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-agent-replace-text-"),
  ));
  try {
    await mkdir(path.join(workspace, "src"), { mode: 0o700 });
    await writeFile(
      path.join(workspace, "src", "continuation.mjs"),
      "before\nselected=old\ncontinuation\n",
      { encoding: "utf8", mode: 0o600 },
    );
    const keys = generateKeyPairSync("ed25519");
    const pilotCase = buildTestPilotCaseV1({
      caseId: "agent-replace-text-case",
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
    });
    const cell = buildPilotCellV1({
      pilot_id: "pilot-agent-replace-text-test",
      opaque_cell_id: "cell-agent-replace-text",
      ordinal: 1,
      case_id: pilotCase.case_id,
      case_sha256: pilotCase.case_sha256,
      arm: "treatment",
    });
    const receipt = await executeAgentActionV1({
      cell,
      pilotCase,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        pilotCase,
        workspacePath: workspace,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent: replaceTextAction(
        "src/continuation.mjs",
        "selected=old",
        "selected=accepted",
      ),
      providerResponseReceiptSha256: canonicalSha256({ receipt: "replace-text" }),
    });

    assert.equal(
      await readFile(path.join(workspace, "src", "continuation.mjs"), "utf8"),
      "before\nselected=accepted\ncontinuation\n",
    );
    assert.equal(receipt.execution_status, "applied");
    assert.equal(receipt.exit_code, 0);
    assert.notEqual(receipt.workspace_before_sha256, receipt.workspace_after_sha256);
    assert.equal(
      Number((await stat(path.join(workspace, "src", "continuation.mjs"))).mode & 0o777),
      0o600,
    );
    assert.deepEqual(verifyAgentExitReceiptV1(receipt, cell), receipt);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("replace_text rejects a repeated old_text without changing the workspace", async () => {
  const workspace = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-agent-replace-duplicate-"),
  ));
  try {
    await mkdir(path.join(workspace, "src"), { mode: 0o700 });
    const statePath = path.join(workspace, "src", "continuation.mjs");
    const original = "selected=old\nselected=old\n";
    await writeFile(statePath, original, "utf8");
    const keys = generateKeyPairSync("ed25519");
    const pilotCase = buildTestPilotCaseV1({
      caseId: "agent-replace-duplicate-case",
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
    });
    const cell = buildPilotCellV1({
      pilot_id: "pilot-agent-replace-duplicate-test",
      opaque_cell_id: "cell-agent-replace-duplicate",
      ordinal: 1,
      case_id: pilotCase.case_id,
      case_sha256: pilotCase.case_sha256,
      arm: "treatment",
    });
    const receipt = await executeAgentActionV1({
      cell,
      pilotCase,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        pilotCase,
        workspacePath: workspace,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent: replaceTextAction(
        "src/continuation.mjs",
        "selected=old",
        "selected=accepted",
      ),
      providerResponseReceiptSha256: canonicalSha256({ receipt: "replace-duplicate" }),
    });

    assert.equal(receipt.execution_status, "patch_rejected");
    assert.equal(receipt.exit_code, 65);
    assert.equal(receipt.workspace_before_sha256, receipt.workspace_after_sha256);
    assert.equal(await readFile(statePath, "utf8"), original);
    assert.deepEqual(verifyAgentExitReceiptV1(receipt, cell), receipt);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("replace_text rejects symlink, hardlink, non-regular, invalid UTF-8, and escaping paths", async () => {
  const root = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-agent-replace-security-"),
  ));
  const workspace = path.join(root, "workspace");
  const outside = path.join(root, "outside");
  try {
    await mkdir(workspace, { mode: 0o700 });
    await mkdir(outside, { mode: 0o700 });
    await mkdir(path.join(workspace, "src"), { mode: 0o700 });
    const outsideState = path.join(outside, "continuation.mjs");
    await writeFile(outsideState, "outside=old\n", "utf8");

    const target = path.join(workspace, "src", "continuation.mjs");
    await symlink(outsideState, target);
    let execution = runExecutorDirect(
      workspace,
      replaceTextAction("src/continuation.mjs", "outside=old", "outside=changed"),
    );
    assert.equal(execution.exitCode, 65);
    assert.equal(execution.result.status, "patch_rejected");
    assert.equal(await readFile(outsideState, "utf8"), "outside=old\n");

    await rm(target);
    await link(outsideState, target);
    execution = runExecutorDirect(
      workspace,
      replaceTextAction("src/continuation.mjs", "outside=old", "outside=changed"),
    );
    assert.equal(execution.exitCode, 65);
    assert.equal(execution.result.status, "patch_rejected");
    assert.equal(await readFile(outsideState, "utf8"), "outside=old\n");

    await rm(target);
    await mkdir(target);
    execution = runExecutorDirect(
      workspace,
      replaceTextAction("src/continuation.mjs", "outside=old", "outside=changed"),
    );
    assert.equal(execution.exitCode, 65);
    assert.equal(execution.result.status, "patch_rejected");
    await rm(target, { recursive: true });

    await writeFile(target, Buffer.from([0xff, 0xfe, 0xfd]));
    execution = runExecutorDirect(
      workspace,
      replaceTextAction("src/continuation.mjs", "old", "changed"),
    );
    assert.equal(execution.exitCode, 65);
    assert.equal(execution.result.status, "patch_rejected");
    assert.deepEqual(await readFile(target), Buffer.from([0xff, 0xfe, 0xfd]));
    await rm(target);

    await rm(path.join(workspace, "src"), { recursive: true });
    await symlink(outside, path.join(workspace, "src"));
    execution = runExecutorDirect(
      workspace,
      replaceTextAction("src/continuation.mjs", "outside=old", "outside=changed"),
    );
    assert.equal(execution.exitCode, 65);
    assert.equal(execution.result.status, "patch_rejected");
    assert.equal(await readFile(outsideState, "utf8"), "outside=old\n");

    execution = runExecutorDirect(
      workspace,
      replaceTextAction("../outside/state.txt", "outside=old", "outside=changed"),
    );
    assert.equal(execution.exitCode, 64);
    assert.equal(execution.result.status, "response_rejected");
    assert.equal(await readFile(outsideState, "utf8"), "outside=old\n");
  } finally {
    await rm(root, { recursive: true, force: true });
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
      pilotCase,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        pilotCase,
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
      pilotCase,
      workspacePath: workspace,
      gitExecutablePath: "/usr/bin/git",
    });
    assert.match(authority.workspace_prepared_inode_set_sha256, /^[0-9a-f]{64}$/u);

    const replacementPath = path.join(workspace, "replacement.txt");
    await writeFile(replacementPath, "stable\n", { mode: 0o600 });
    await rename(replacementPath, statePath);
    await assert.rejects(
      () => verifyAgentExecutionAuthorityV1(authority, cell, pilotCase),
      /aionis_eval_agent_execution_execution_authority_live_mismatch/u,
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
