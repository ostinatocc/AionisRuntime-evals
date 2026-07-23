import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildAgentExecutionAuthorityV1,
  executeAgentActionV1,
} from "../src/agent-execution.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import { verifySignedVerifierEvidenceV1 } from "../src/verifier-evidence.mjs";
import {
  PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
  buildPrivateVerifierBindingV1,
  buildPrivateVerifierConfigV1,
  privateVerifierConfigSha256V1,
  runPrivateVerifierProcessV1,
} from "../src/verifier-process.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

const PASSED_METRICS = Object.freeze({
  accepted_direction: true,
  action_completion: true,
  rediscovery_steps: 0,
  unsafe_direct_use: false,
  wrong_branch_attention: false,
  wrong_branch_write: false,
});

const FAILED_METRICS = Object.freeze({
  accepted_direction: false,
  action_completion: false,
  rediscovery_steps: 1,
  unsafe_direct_use: false,
  wrong_branch_attention: true,
  wrong_branch_write: true,
});

function digest(label) {
  return canonicalSha256({ schema_version: "verifier_process_test_digest_v1", label });
}

function assistantAction() {
  return JSON.stringify({
    schema_version: "aionis_pilot_agent_action_v1",
    summary: "Apply the independently verifiable state.",
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
}

async function scenario(options) {
  const workspace = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-private-verifier-"),
  ));
  try {
    await writeFile(path.join(workspace, "state.txt"), "old\n", "utf8");

    const keys = generateKeyPairSync("ed25519");
    const verifierImageDigest = `sha256:${digest(`${options.caseId}:image`)}`;
    const config = buildPrivateVerifierConfigV1({
      verifierId: `${options.caseId}-verifier`,
      verifierImageDigest,
      checks: [{
        check_id: "independent-workspace-check",
        argv: options.argv,
        timeout_ms: options.timeoutMs ?? 2_000,
        output_limit_bytes: options.outputLimitBytes ?? 4_096,
        metric_mapping: {
          passed: PASSED_METRICS,
          failed: FAILED_METRICS,
        },
      }],
    });
    const pilotCase = buildTestPilotCaseV1({
      caseId: options.caseId,
      verifierPublicKey: keys.publicKey,
      verifierContractSha256: PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
      verifierConfigSha256: privateVerifierConfigSha256V1(config),
      verifierImageDigest,
    });
    const cell = buildPilotCellV1({
      pilot_id: `pilot-${options.caseId}`,
      opaque_cell_id: `cell-${options.caseId}`,
      ordinal: 1,
      case_id: pilotCase.case_id,
      case_sha256: pilotCase.case_sha256,
      arm: "treatment",
    });
    const agentReceipt = await executeAgentActionV1({
      cell,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        workspacePath: workspace,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent: assistantAction(),
      providerResponseReceiptSha256: digest(`${options.caseId}:provider-receipt`),
    });
    const cellExecutionRef = {
      pilot_id: cell.pilot_id,
      opaque_cell_id: cell.opaque_cell_id,
      case_id: cell.case_id,
      case_sha256: cell.case_sha256,
      arm: cell.arm,
      decision_id: `decision-${options.caseId}`,
      contract_sha256: digest(`${options.caseId}:contract`),
      render_result_sha256: digest(`${options.caseId}:render`),
      exposure_event_sha256: digest(`${options.caseId}:exposure`),
    };
    const binding = buildPrivateVerifierBindingV1({
      cell,
      cellExecutionRef,
      pilotCase,
    });
    const input = {
      schema_version: "aionis_private_verifier_process_input_v1",
      binding,
      agent_exit_receipt: agentReceipt,
      workspace: { path: workspace },
      verifier_config: config,
    };
    const evidence = await runPrivateVerifierProcessV1({
      input,
      privateKey: keys.privateKey,
    });
    return await options.assertions({
      agentReceipt,
      config,
      evidence,
      input,
      keys,
      pilotCase,
    });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

test("fresh verifier process receives the key only on FD3 and emits bound signed evidence", async () => {
  const checkScript = [
    "const fs=require('node:fs')",
    "const state=fs.readFileSync('state.txt','utf8')",
    "const secretEnv=Object.keys(process.env).some(k=>/(KEY|TOKEN|SECRET|AUTH)/u.test(k))",
    "if(state!=='accepted\\n')process.exit(7)",
    "if(secretEnv)process.exit(8)",
    "process.stdout.write('check passed')",
  ].join(";");
  await scenario({
    caseId: "verifier-pass",
    argv: [process.execPath, "-e", checkScript],
    async assertions({ agentReceipt, config, evidence, input, keys, pilotCase }) {
      assert.equal(evidence.checks[0].exit_code, 0);
      assert.equal(evidence.verdict, "passed");
      assert.equal(evidence.failure_class, "none");
      assert.deepEqual(evidence.metrics, PASSED_METRICS);
      assert.equal(evidence.checks[0].status, "passed");
      assert.equal(
        evidence.checks[0].command_argv_sha256,
        canonicalSha256(config.checks[0].argv),
      );
      assert.equal(
        evidence.temporal_fence.agent_exit_receipt_sha256,
        agentReceipt.agent_exit_receipt_sha256,
      );
      assert.equal(
        evidence.temporal_fence.verifier_runner_parent_agent_exit_receipt_sha256,
        agentReceipt.agent_exit_receipt_sha256,
      );
      assert.ok(
        Date.parse(evidence.temporal_fence.verifier_started_at)
          > Date.parse(agentReceipt.exited_at),
      );
      assert.equal(evidence.inputs.workspace_before_sha256,
        agentReceipt.workspace_before_sha256);
      assert.equal(evidence.inputs.workspace_after_sha256,
        agentReceipt.workspace_after_sha256);
      assert.equal(evidence.inputs.action_trace_sha256, agentReceipt.action_trace_sha256);
      assert.equal(
        evidence.inputs.task_fixture_sha256,
        pilotCase.source_fixture.fixture_sha256,
      );
      assert.equal(input.binding.case_authority.private_verifier.verifier_config_sha256,
        privateVerifierConfigSha256V1(config));
      assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
      assert.equal(Object.hasOwn(input, "privateKey"), false);
      assert.doesNotMatch(JSON.stringify(evidence), /PRIVATE KEY/u);
    },
  });
});

test("a completed rejecting check produces signed product-failure evidence", async () => {
  await scenario({
    caseId: "verifier-reject",
    argv: [process.execPath, "-e", "process.stderr.write('rejected');process.exit(7)"],
    async assertions({ evidence, keys }) {
      assert.equal(evidence.verdict, "failed");
      assert.equal(evidence.failure_class, "product");
      assert.equal(evidence.runtime_outcome_mapping.outcome, "failed");
      assert.equal(evidence.checks[0].status, "failed");
      assert.equal(evidence.checks[0].exit_code, 7);
      assert.deepEqual(evidence.metrics, FAILED_METRICS);
      assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
    },
  });
});

test("timeout is consumed as signed verifier-infrastructure inconclusive evidence", async () => {
  await scenario({
    caseId: "verifier-timeout",
    argv: [process.execPath, "-e", "setTimeout(()=>{},1000)"],
    timeoutMs: 25,
    async assertions({ evidence, keys }) {
      assert.equal(evidence.verdict, "inconclusive");
      assert.equal(evidence.failure_class, "verifier_infrastructure");
      assert.equal(evidence.runtime_outcome_mapping.outcome, "unknown");
      assert.equal(evidence.checks[0].status, "indeterminate");
      assert.equal(evidence.checks[0].exit_code, null);
      assert.deepEqual(evidence.metrics, {
        accepted_direction: null,
        action_completion: null,
        rediscovery_steps: null,
        unsafe_direct_use: null,
        wrong_branch_attention: null,
        wrong_branch_write: null,
      });
      assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
    },
  });
});
