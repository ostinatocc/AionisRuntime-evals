import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildAgentModelInputV1 } from "../src/agent-action.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import {
  createDeepSeekProviderV1,
  deepSeekCanonicalRequestSha256V1,
} from "../src/deepseek-provider.mjs";
import {
  buildOwnerCleanupReceiptV1,
  buildResourceCleanupReceiptV1,
} from "../src/pilot-run-event-contract.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import {
  beginTestPilotRunLedgerV1,
  buildTestPilotPlanV1,
} from "./support/pilot-plan-fixture.mjs";

function fixture(pilotId = "pilot-durable-ledger-test") {
  const cases = ["one", "two", "three"].map((caseId) => buildTestPilotCaseV1({
    caseId: `ledger-${caseId}`,
    verifierPublicKey: generateKeyPairSync("ed25519").publicKey,
  }));
  return { cases, plan: buildTestPilotPlanV1(cases, { pilotId }) };
}

async function prepareFirstCell(ledger, plan, pilotCase) {
  const cell = plan.schedule[0];
  const preparedArm = {
    schema_version: "aionis_pilot_prepared_arm_v1",
    cell,
    arm: "baseline",
    observation_body_sha256: pilotCase.runtime_input.record_observations_body_sha256,
    model_context: null,
    runtime: null,
  };
  const agentModelInput = buildAgentModelInputV1({ pilotCase, preparedArm });
  await ledger.recordCellPreparation({ cell, pilotCase, preparedArm, agentModelInput });
  return { agentModelInput, cell };
}

function createProvider(plan, ledger, fetchHook = null) {
  let tick = 0;
  const content = JSON.stringify({
    schema_version: "aionis_pilot_agent_action_v1",
    summary: "No safe change is required.",
    action: { kind: "no_safe_change", patch: null },
  });
  return createDeepSeekProviderV1({
    apiKey: "ledger-test-secret",
    attemptAuthority: ledger,
    clock: () => new Date(Date.UTC(2026, 6, 22, 0, 0, tick++)).toISOString(),
    fetchImpl: async (...args) => {
      if (fetchHook !== null) await fetchHook(...args);
      return {
        status: 200,
        headers: { get: () => "ledger-provider-request" },
        async text() {
          return JSON.stringify({
            id: "ledger-provider-request",
            object: "chat.completion",
            created: 1_784_678_400,
            model: "deepseek-v4-flash",
            system_fingerprint: "fp-deepseek-v4-flash-ledger",
            choices: [{
              index: 0,
              finish_reason: "stop",
              message: { role: "assistant", content },
            }],
            usage: {
              prompt_tokens: 1,
              prompt_cache_hit_tokens: 0,
              prompt_cache_miss_tokens: 1,
              completion_tokens: 1,
              total_tokens: 2,
              completion_tokens_details: { reasoning_tokens: 1 },
            },
          });
        },
      };
    },
    modelProtocol: plan.model_protocol,
    pilotId: plan.pilot_id,
  });
}

async function runDirectory(root) {
  const entries = await readdir(path.join(root, "pilots"));
  assert.equal(entries.length, 1);
  return path.join(root, "pilots", entries[0]);
}

test("signed authority root creates one deterministic pilot slot and reserves before HTTP", async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-run-ledger-test-")));
  try {
    const { cases, plan } = fixture();
    const { ledger } = await beginTestPilotRunLedgerV1({ authorityRoot: root, plan });
    const { agentModelInput, cell: firstCell } = await prepareFirstCell(
      ledger,
      plan,
      cases[0],
    );
    const messages = agentModelInput.messages;
    let snapshotAtFetch = null;
    const provider = createProvider(plan, ledger, async () => {
      snapshotAtFetch = ledger.snapshot();
      assert.equal(snapshotAtFetch.active_attempt_ordinal, 1);
      assert.equal(snapshotAtFetch.event_count, 5);
      const directory = await runDirectory(root);
      assert.equal((await readdir(path.join(directory, "events"))).length, 5);
    });
    const providerResult = await provider.executeScoredRequest({ cell: firstCell, messages });
    assert.equal(snapshotAtFetch.event_count, 5);
    assert.equal(providerResult.outcome, "completed");
    assert.equal(
      providerResult.request_receipt.execution_authorization_sha256,
      ledger.snapshot().execution_authorization_sha256,
    );
    await ledger.completeProviderAttempt({
      assistantMessage: providerResult.assistant_message,
      cell: firstCell,
      messages,
      requestReceipt: providerResult.request_receipt,
      responseReceipt: providerResult.response_receipt,
    });
    assert.equal(ledger.snapshot().event_count, 6);
    assert.equal(ledger.snapshot().completed_cell_count, 0);
    await assert.rejects(
      () => provider.executeScoredRequest({ cell: plan.schedule[1], messages }),
      /attempt_state_invalid/u,
    );

    const directory = await runDirectory(root);
    const mode = (await stat(directory)).mode & 0o777;
    assert.equal(mode, 0o700);
    const indexFiles = await readdir(path.join(root, "pilot-index"));
    assert.equal(indexFiles.length, 1);
    const index = JSON.parse(await readFile(
      path.join(root, "pilot-index", indexFiles[0]),
      "utf8",
    ));
    assert.equal(index.pilot_id, plan.pilot_id);
    assert.equal(index.restart_policy, "forbid_same_pilot_id_within_signed_authority_root");
    await assert.rejects(
      () => beginTestPilotRunLedgerV1({ authorityRoot: root, plan }),
      /pilot_already_started/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a request-bound reservation is durably burned and root aliases are rejected", async () => {
  const parent = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-run-ledger-burn-")));
  const root = path.join(parent, "authority");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(root, { mode: 0o700 }));
  try {
    const { cases, plan } = fixture("pilot-durable-ledger-burn-test");
    const { ledger } = await beginTestPilotRunLedgerV1({ authorityRoot: root, plan });
    const { agentModelInput, cell } = await prepareFirstCell(ledger, plan, cases[0]);
    const reservation = await ledger.reserveProviderAttempt({
      cell,
      canonicalRequestSha256: deepSeekCanonicalRequestSha256V1(
        agentModelInput.messages,
        plan.model_protocol,
      ),
      modelInputSha256: agentModelInput.model_input_sha256,
    });
    assert.equal(reservation.state, "reserved_fail_closed");
    assert.equal(ledger.snapshot().active_attempt_ordinal, 1);
    assert.equal(ledger.snapshot().event_count, 5);
    const directory = await runDirectory(root);
    const events = await readdir(path.join(directory, "events"));
    assert.equal(events.length, 5);

    const alias = path.join(parent, "authority-alias");
    await symlink(root, alias);
    await assert.rejects(
      () => beginTestPilotRunLedgerV1({ authorityRoot: alias, plan }),
      /authority_root_unsafe/u,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("a partial request is durably abort-sealed with burn and cleanup state", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-run-ledger-abort-",
  )));
  try {
    const { cases, plan } = fixture("pilot-durable-ledger-abort-test");
    const { ledger } = await beginTestPilotRunLedgerV1({ authorityRoot: root, plan });
    const { agentModelInput, cell } = await prepareFirstCell(ledger, plan, cases[0]);
    await ledger.reserveProviderAttempt({
      cell,
      canonicalRequestSha256: deepSeekCanonicalRequestSha256V1(
        agentModelInput.messages,
        plan.model_protocol,
      ),
      modelInputSha256: agentModelInput.model_input_sha256,
    });
    const cleanupReceipt = buildResourceCleanupReceiptV1({
      resourceCount: plan.schedule.length,
      closedResourceOrdinals: plan.schedule.map((entry) => entry.ordinal),
      failedResourceOrdinals: [],
      ownerKinds: ["runtime_owner", "workspace_owner"],
      ownerCleanupReceipt: buildOwnerCleanupReceiptV1({
        ownerKinds: ["runtime_owner", "workspace_owner"],
        closedOwnerKinds: ["runtime_owner", "workspace_owner"],
        failedOwnerKinds: [],
      }),
    });
    const abort = await ledger.abortRun({
      cleanupReceipt,
      failingCell: cell,
      failureClass: "provider_or_network",
      failureEvidenceRefSha256: canonicalSha256({
        schema_version: "aionis_test_redacted_abort_evidence_v1",
        stage: "provider",
      }),
      failureStage: "provider",
    });
    assert.equal(abort.state, "aborted_claim_ineligible_no_resume");
    assert.equal(abort.active_provider_attempt_state, "request_may_have_started_burned");
    assert.equal(abort.provider_attempt_reservation_count, 1);
    assert.equal(abort.provider_attempt_completion_count, 0);
    assert.equal(abort.cleanup_confirmed, true);
    const snapshot = ledger.snapshot();
    assert.equal(snapshot.closed, true);
    assert.equal(snapshot.completed_cell_count, 0);
    assert.equal(snapshot.active_attempt_ordinal, 1);
    assert.equal(snapshot.event_count, 6);
    assert.equal(snapshot.event_chain_head_sha256, abort.run_aborted_event_sha256);
    await assert.rejects(
      () => ledger.abortRun({
        cleanupReceipt,
        failingCell: cell,
        failureClass: "provider_or_network",
        failureEvidenceRefSha256: abort.failure_evidence_ref_sha256,
        failureStage: "provider",
      }),
      /abort_state_invalid/u,
    );
    await assert.rejects(
      () => ledger.recordCellPreparation({}),
      /preparation_state_invalid/u,
    );
    const directory = await runDirectory(root);
    const eventNames = (await readdir(path.join(directory, "events"))).sort();
    const abortEvent = JSON.parse(await readFile(
      path.join(directory, "events", eventNames.at(-1)),
      "utf8",
    ));
    assert.equal(abortEvent.event_kind, "run_aborted");
    assert.equal(abortEvent.cell_ref.ordinal, 1);
    const abortPayload = JSON.parse(await readFile(
      path.join(directory, "artifacts", `${abortEvent.payload_sha256}.json`),
      "utf8",
    ));
    assert.equal(abortPayload.cleanup_receipt_sha256, cleanupReceipt.cleanup_receipt_sha256);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
