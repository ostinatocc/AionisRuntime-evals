import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { watch } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildAgentExecutionAuthorityV1 } from "../src/agent-execution.mjs";
import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  sha256Bytes,
} from "../src/canonical.mjs";
import {
  buildNonReleaseContractTestCellResourceAuthorityV1,
} from "../src/cell-resource-authority.mjs";
import {
  runExecutablePilotV1,
  runNonReleaseContractTestExecutablePilotV1,
} from "../src/executable-pilot-runner.mjs";
import {
  FINAL_SIGNER_PROCESS_CONTRACT_V1,
  runNonReleaseContractTestSealedPilotFinalSignerProcessV1,
} from "../src/final-signer-process.mjs";
import {
  DEEPSEEK_ENDPOINT_V1,
  DEEPSEEK_MODEL_V1,
} from "../src/deepseek-provider.mjs";
import {
  OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
  buildNonReleaseContractTestOciRuntimeAuthorityV1,
  buildOciPrivateVerifierConfigV1,
  ociPrivateVerifierConfigSha256V1,
} from "../src/oci-verifier-process.mjs";
import { verifyPilotCellResultV1 } from "../src/pilot-result.mjs";
import {
  createNonReleaseContractTestFinalManifestPersistenceAuthorityV1,
} from "../src/pilot-run-ledger.mjs";
import { verifyPilotVerdictV1 } from "../src/pilot-scorer.mjs";
import {
  preflightNonReleaseContractTestPilotExecutionManifestV1,
} from "../src/runner-authority.mjs";
import {
  NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1,
  buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1,
  verifySignedRunnerExecutionAuthorizationV1,
  verifySignedRunnerFinalManifestV1,
} from "../src/runner-signature.mjs";
import {
  createReleasePilotCancellationAuthorityV1,
  requestReleasePilotCancellationV1,
  snapshotReleasePilotCancellationV1,
} from "../src/release-pilot-cancellation.mjs";
import { pilotCellOperationIdsV1 } from "../src/runtime-v1-host-adapter.mjs";
import { verifySealedPilotRunV1 } from "../src/sealed-pilot-run.mjs";
import { verifySignedVerifierEvidenceV1 } from "../src/verifier-evidence.mjs";
import { captureWorkspaceEvidenceV1 } from "../src/workspace-evidence.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import {
  buildTestEvalRepositoryProvenanceV1,
  TEST_RUNNER_KEYS_V1,
  buildTestCellPolicyBindingsV1,
  buildTestPilotPlanV1,
} from "./support/pilot-plan-fixture.mjs";

const OFFLINE_API_KEY = "offline-deepseek-contract-key";

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
  wrong_branch_attention: false,
  wrong_branch_write: false,
});

function digest(label) {
  return canonicalSha256({
    schema_version: "aionis_executable_pilot_runner_test_digest_v1",
    label,
  });
}

function providerClock() {
  let tick = 0;
  return () => new Date(Date.UTC(2020, 0, 1, 0, 0, tick++)).toISOString();
}

function assistantContent() {
  return JSON.stringify({
    schema_version: "aionis_pilot_agent_action_v2",
    summary: "No safe workspace change is justified by the frozen public task.",
    action: { kind: "no_safe_change", patch: null },
  });
}

function providerResponse(requestId) {
  return {
    status: 200,
    headers: {
      get(name) {
        return name.toLowerCase() === "x-request-id" ? requestId : null;
      },
    },
    async text() {
      return JSON.stringify({
        id: requestId,
        object: "chat.completion",
        created: 1_784_678_400,
        model: DEEPSEEK_MODEL_V1,
        system_fingerprint: "fp-deepseek-v4-flash-runner",
        choices: [{
          index: 0,
          finish_reason: "stop",
          message: { role: "assistant", content: assistantContent() },
        }],
        usage: {
          prompt_tokens: 32,
          prompt_cache_hit_tokens: 8,
          prompt_cache_miss_tokens: 24,
          completion_tokens: 16,
          total_tokens: 48,
          completion_tokens_details: { reasoning_tokens: 8 },
        },
      });
    },
  };
}

function fakeOciRuntimeSource(logPath) {
  return `#!${process.execPath}
const fs = require("node:fs");
const argv = process.argv.slice(2);
let fd3Bytes = null;
try { fd3Bytes = fs.readFileSync(3).length; } catch { fd3Bytes = -1; }
const secretEnvironmentKeys = Object.keys(process.env).filter((key) =>
  /(?:API|AUTH|CREDENTIAL|KEY|PASSWORD|SECRET|TOKEN)/u.test(key));
fs.appendFileSync(${JSON.stringify(logPath)}, JSON.stringify({
  argv,
  fd3_bytes: fd3Bytes,
  secret_environment_keys: secretEnvironmentKeys,
}) + "\\n", { encoding: "utf8", mode: 0o600 });
if (argv[0] !== "run") process.exit(0);
process.stderr.write("controlled verifier rejection\\n");
process.exit(7);
`;
}

function runtimeObservation(pilotCase, cell) {
  if (cell.arm === "baseline") return null;
  const operationId = pilotCellOperationIdsV1(cell).observation;
  const operationRequestSha256 = digest(`${cell.opaque_cell_id}:observation-request`);
  const snapshot = {
    world_snapshot_id: operationId,
    world_snapshot_sha256: digest(`${cell.opaque_cell_id}:world-snapshot`),
    host_task_envelope_sha256: digest(`${cell.opaque_cell_id}:host-task-envelope`),
  };
  const result = {
    schema_version: "record_observations_result_v1",
    authority_branch_set: null,
    durable_job_set: null,
    memory_revision_ref: null,
    observation_snapshot_ref: snapshot,
  };
  const receipt = {
    schema_version: "continuation_runtime_operation_receipt_v1",
    tenant_id: "executable-pilot-contract-tenant",
    scope: cell.isolation.runtime_scope,
    operation_kind: "record_observations",
    operation_id: operationId,
    actor_kind: "trusted_host",
    actor_principal_sha256: digest(`${cell.opaque_cell_id}:host-principal`),
    request_sha256: operationRequestSha256,
    completed_at: "2026-07-22T00:00:00.000Z",
    result,
  };
  return canonicalClone({
    operation_id: operationId,
    scope: cell.isolation.runtime_scope,
    operation_receipt: receipt,
    operation_receipt_sha256: canonicalSha256(receipt),
    operation_request_sha256: operationRequestSha256,
    request_body_sha256: pilotCase.runtime_input.record_observations_body_sha256,
    ...snapshot,
  });
}

function createPreparedArmAdapter({ cell, pilotCase, tracker }) {
  const observation = runtimeObservation(pilotCase, cell);
  const runtimeContext = cell.arm === "treatment"
    ? `Verified continuation evidence for ${pilotCase.case_id}.`
    : null;
  const continuation = cell.arm === "treatment" ? canonicalClone({
    decision_id: `decision-${cell.opaque_cell_id}`,
    contract_sha256: digest(`${cell.opaque_cell_id}:contract`),
    render_result_sha256: digest(`${cell.opaque_cell_id}:render-result`),
    render_content_sha256: sha256Bytes(Buffer.from(runtimeContext, "utf8")),
    exposure_event_sha256: digest(`${cell.opaque_cell_id}:exposure-event`),
  }) : null;

  return Object.freeze({
    async prepareArm() {
      const prepared = canonicalClone({
        schema_version: "aionis_pilot_prepared_arm_v1",
        cell,
        arm: cell.arm,
        observation_body_sha256:
          pilotCase.runtime_input.record_observations_body_sha256,
        model_context: runtimeContext,
        runtime: cell.arm === "baseline" ? null : {
          observation,
          continuation,
          settlement: null,
        },
      });
      tracker.prepared.push(prepared);
      return prepared;
    },

    async settleTreatment(prepared, settlementInput) {
      const settlement = canonicalClone({
        record_outcome_operation_id: pilotCellOperationIdsV1(cell).outcome,
        request_body_sha256: digest(`${cell.opaque_cell_id}:outcome-body`),
        operation_request_sha256: digest(`${cell.opaque_cell_id}:outcome-request`),
        operation_receipt_sha256: digest(`${cell.opaque_cell_id}:outcome-receipt`),
        use_receipt_sha256: digest(`${cell.opaque_cell_id}:use-receipt`),
        outcome_evidence_sha256: settlementInput.verifierEvidence.evidence_sha256,
        ledger_head_event_sha256: digest(`${cell.opaque_cell_id}:ledger-head`),
        full_decision_response_sha256:
          digest(`${cell.opaque_cell_id}:full-decision-response`),
        effect_state: "not_applicable",
      });
      tracker.settled.push({
        cell,
        prepared,
        verifier_evidence_sha256: settlementInput.verifierEvidence.evidence_sha256,
        settlement,
      });
      return canonicalClone({
        ...prepared,
        runtime: { ...prepared.runtime, settlement },
      });
    },

    async close() {
      tracker.closed.push(cell.opaque_cell_id);
    },
  });
}

async function readEventBoundary(authorityRoot, expectedOrdinal) {
  const pilotNames = await readdir(path.join(authorityRoot, "pilots"));
  if (pilotNames.length !== 1) throw new Error("pilot directory was not durable");
  const runDirectory = path.join(authorityRoot, "pilots", pilotNames[0]);
  const eventDirectory = path.join(runDirectory, "events");
  const artifactDirectory = path.join(runDirectory, "artifacts");
  const names = (await readdir(eventDirectory)).sort();
  const events = await Promise.all(names.map(async (name) =>
    JSON.parse(await readFile(path.join(eventDirectory, name), "utf8"))));
  const reservation = events.at(-2);
  const requestStarted = events.at(-1);
  const reservationPayload = JSON.parse(await readFile(
    path.join(artifactDirectory, `${reservation.payload_sha256}.json`),
    "utf8",
  ));
  const requestStartedPayload = JSON.parse(await readFile(
    path.join(artifactDirectory, `${requestStarted.payload_sha256}.json`),
    "utf8",
  ));
  return {
    event_count: events.length,
    reservation_event_kind: reservation.event_kind,
    request_started_event_kind: requestStarted.event_kind,
    reservation_cell_ordinal: reservation.cell_ref?.ordinal ?? null,
    request_started_cell_ordinal: requestStarted.cell_ref?.ordinal ?? null,
    reservation_attempt_ordinal: reservationPayload.attempt_ordinal,
    request_started_attempt_ordinal: requestStartedPayload.attempt_ordinal,
    reservation_file_mode: (await lstat(
      path.join(eventDirectory, names.at(-2)),
    )).mode & 0o777,
    request_started_file_mode: (await lstat(
      path.join(eventDirectory, names.at(-1)),
    )).mode & 0o777,
    expected_ordinal: expectedOrdinal,
  };
}

async function readCanonicalEvents(authorityRoot) {
  const [runDirectoryName] = await readdir(path.join(authorityRoot, "pilots"));
  const runDirectory = path.join(authorityRoot, "pilots", runDirectoryName);
  const eventDirectory = path.join(runDirectory, "events");
  const names = (await readdir(eventDirectory)).sort();
  const events = [];
  for (const name of names) {
    const filePath = path.join(eventDirectory, name);
    const text = await readFile(filePath, "utf8");
    const value = JSON.parse(text);
    assert.equal(text, `${canonicalJson(value)}\n`);
    assert.equal((await lstat(filePath)).mode & 0o777, 0o600);
    const body = Object.fromEntries(
      Object.entries(value).filter(([key]) => key !== "event_sha256"),
    );
    assert.equal(value.event_sha256, canonicalSha256(body));
    events.push(value);
  }
  return { events, runDirectory };
}

async function installRechainedPayloadTamper(runDirectory, events, eventIndex, mutate) {
  const eventDirectory = path.join(runDirectory, "events");
  const artifactDirectory = path.join(runDirectory, "artifacts");
  const target = events[eventIndex];
  const originalPayload = JSON.parse(await readFile(
    path.join(artifactDirectory, `${target.payload_sha256}.json`),
    "utf8",
  ));
  const tamperedPayload = mutate(canonicalClone(originalPayload));
  const tamperedPayloadSha256 = canonicalSha256(tamperedPayload);
  const tamperedArtifactPath = path.join(
    artifactDirectory,
    `${tamperedPayloadSha256}.json`,
  );
  await writeFile(
    tamperedArtifactPath,
    `${canonicalJson(tamperedPayload)}\n`,
    { mode: 0o600 },
  );

  let previousEventSha256 = eventIndex === 0 ? null : events[eventIndex - 1].event_sha256;
  for (let index = eventIndex; index < events.length; index += 1) {
    const body = canonicalClone({
      ...Object.fromEntries(
        Object.entries(events[index]).filter(([key]) => key !== "event_sha256"),
      ),
      previous_event_sha256: previousEventSha256,
      payload_sha256: index === eventIndex
        ? tamperedPayloadSha256
        : events[index].payload_sha256,
    });
    const rechained = canonicalClone({ ...body, event_sha256: canonicalSha256(body) });
    await writeFile(
      path.join(eventDirectory, `${String(index + 1).padStart(6, "0")}.json`),
      `${canonicalJson(rechained)}\n`,
      { mode: 0o600 },
    );
    previousEventSha256 = rechained.event_sha256;
  }

  return async () => {
    for (let index = eventIndex; index < events.length; index += 1) {
      await writeFile(
        path.join(eventDirectory, `${String(index + 1).padStart(6, "0")}.json`),
        `${canonicalJson(events[index])}\n`,
        { mode: 0o600 },
      );
    }
    if (tamperedPayloadSha256 !== target.payload_sha256) {
      await rm(tamperedArtifactPath, { force: true });
    }
  };
}

async function readAuthorityArtifactBuffers(directory) {
  const buffers = [];
  for (const name of await readdir(directory)) {
    const entryPath = path.join(directory, name);
    const metadata = await lstat(entryPath);
    if (metadata.isDirectory()) buffers.push(...await readAuthorityArtifactBuffers(entryPath));
    else if (metadata.isFile()) buffers.push(await readFile(entryPath));
  }
  return buffers;
}

function closedLedgerSnapshot(result, executionAuthorization, plan) {
  return canonicalClone({
    schema_version: "aionis_pilot_run_ledger_snapshot_v1",
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    execution_authorization_sha256:
      executionAuthorization.execution_authorization_sha256,
    run_started_event_sha256: result.final_manifest.run_started_event_sha256,
    event_count: result.final_manifest.event_count,
    event_chain_head_sha256: result.final_manifest.event_chain_head_sha256,
    completed_cell_count: 9,
    next_attempt_ordinal: 10,
    active_attempt_ordinal: null,
    verdict_sha256: result.verdict.verdict_sha256,
    closed: true,
    restart_policy: "forbid_same_pilot_id_within_signed_authority_root",
  });
}

test("executable pilot runner seals one offline 3x3 run through real child boundaries", async () => {
  const root = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-executable-pilot-runner-"),
  ));
  const authorityRoot = path.join(root, "authority");
  const runtimePath = path.join(root, "fake-oci-runtime");
  const runtimeLogPath = path.join(root, "fake-oci-runtime.jsonl");
  const workspacePaths = Array.from(
    { length: 9 },
    (_, index) => path.join(root, `workspace-${String(index + 1).padStart(2, "0")}`),
  );
  const runtimeDirectories = Array.from(
    { length: 9 },
    (_, index) => path.join(root, `runtime-${String(index + 1).padStart(2, "0")}`),
  );
  let runnerSigningKeyFile = null;
  let formalApiKeyFile = null;
  try {
    await mkdir(authorityRoot, { mode: 0o700 });
    await Promise.all(workspacePaths.map((workspacePath) =>
      mkdir(workspacePath, { mode: 0o700 })));
    await Promise.all(runtimeDirectories.map((directory) =>
      mkdir(directory, { mode: 0o700 })));
    await writeFile(runtimePath, fakeOciRuntimeSource(runtimeLogPath), { mode: 0o700 });
    await chmod(runtimePath, 0o700);

    const workspaceEvidence = await captureWorkspaceEvidenceV1(workspacePaths[0]);
    for (const workspacePath of workspacePaths.slice(1)) {
      assert.equal(
        (await captureWorkspaceEvidenceV1(workspacePath)).workspace_sha256,
        workspaceEvidence.workspace_sha256,
      );
    }

    const verifierKeys = Array.from({ length: 3 }, () => generateKeyPairSync("ed25519"));
    const verifierConfigs = verifierKeys.map((_, index) => {
      const caseId = `executable-pilot-case-${index + 1}`;
      const imageDigest = `sha256:${digest(`${caseId}:verifier-image`)}`;
      return buildOciPrivateVerifierConfigV1({
        verifierId: `${caseId}-verifier`,
        verifierImageDigest: imageDigest,
        verifierImageReference:
          `registry.invalid/aionis/verifier@${imageDigest}`,
        checks: [{
          check_id: `${caseId}-private-check`,
          argv: ["/opt/aionis/bin/private-check", "reject"],
          timeout_ms: 5_000,
          output_limit_bytes: 16_384,
          metric_mapping: {
            passed: PASSED_METRICS,
            failed: FAILED_METRICS,
          },
        }],
      });
    });
    const cases = verifierKeys.map((keys, index) => buildTestPilotCaseV1({
      caseId: `executable-pilot-case-${index + 1}`,
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
      verifierContractSha256: OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
      verifierConfigSha256: ociPrivateVerifierConfigSha256V1(verifierConfigs[index]),
      verifierImageDigest: verifierConfigs[index].verifier_image_digest,
      workspaceSha256: workspaceEvidence.workspace_sha256,
    }));
    const plan = buildTestPilotPlanV1(cases, {
      pilotId: "executable-pilot-offline-contract",
    });
    const cellPolicyBindings = buildTestCellPolicyBindingsV1(cases, {
      pilotId: plan.pilot_id,
      tenantId: plan.runtime_binding.tenant_id,
      taskFamily: plan.runtime_binding.task_family,
    });
    const runtimeAuthority = await buildNonReleaseContractTestOciRuntimeAuthorityV1({
      runtimeKind: "docker",
      executablePath: runtimePath,
    });
    const gitExecutablePath = await realpath("/usr/bin/git");
    const tracker = { prepared: [], settled: [], closed: [] };
    const casesById = new Map(cases.map((pilotCase, index) => [
      pilotCase.case_id,
      { pilotCase, index },
    ]));
    const rawCellResources = [];
    const cellAuthorities = [];
    for (const [index, cell] of plan.schedule.entries()) {
      const caseContext = casesById.get(cell.case_id);
      const policyBinding = cellPolicyBindings[index];
      const executionAuthority = await buildAgentExecutionAuthorityV1({
        cell,
        pilotCase: caseContext.pilotCase,
        workspacePath: workspacePaths[index],
        gitExecutablePath,
      });
      rawCellResources.push({
        adapter: createPreparedArmAdapter({
          cell,
          pilotCase: caseContext.pilotCase,
          tracker,
        }),
        executionAuthority,
        ociRuntimeAuthority: runtimeAuthority,
        verifierConfig: verifierConfigs[caseContext.index],
        verifierPrivateKey: verifierKeys[caseContext.index].privateKey,
        verifierPublicKey: verifierKeys[caseContext.index].publicKey,
      });
      cellAuthorities.push({
        opaque_cell_id: cell.opaque_cell_id,
        runtime_scope: cell.isolation.runtime_scope,
        runtime_database_id: cell.isolation.runtime_database_id,
        runtime_database_path: path.join(runtimeDirectories[index], "runtime.sqlite"),
        workspace_instance_id: cell.isolation.workspace_instance_id,
        workspace_path: workspacePaths[index],
        agent_execution_authority: executionAuthority,
        agent_process_id: cell.isolation.agent_process_id,
        agent_exit_authority_principal_sha256:
          cell.isolation.agent_exit_authority_principal_sha256,
        isolation_sha256: cell.isolation.isolation_sha256,
        authority_subject_sha256: policyBinding.authority_subject_sha256,
        provisioning_command_sha256: policyBinding.provisioning_command_sha256,
        compiler_policy_ref: policyBinding.compiler_policy_ref,
        evidence_policy_ref: policyBinding.evidence_policy_ref,
      });
    }
    const runnerAuthority = canonicalClone({
      schema_version: "aionis_pilot_runner_authority_v1",
      eval_binding: plan.eval_binding,
      eval_repository_provenance: buildTestEvalRepositoryProvenanceV1(plan),
      runtime_binding: plan.runtime_binding,
      oci_runtime_authority: runtimeAuthority,
      provider: {
        endpoint: plan.model_protocol.endpoint,
        requested_model: plan.model_protocol.requested_model,
        maximum_provider_request_attempt_count:
          plan.model_protocol.maximum_provider_request_attempt_count,
      },
      case_authorities: cases.map((pilotCase) => ({
        case_id: pilotCase.case_id,
        case_sha256: pilotCase.case_sha256,
        source_fixture_sha256: pilotCase.source_fixture.fixture_sha256,
        workspace_repository_url: pilotCase.workspace.repository_url,
        workspace_base_commit_sha: pilotCase.workspace.base_commit_sha,
        workspace_prepared_tree_sha256: pilotCase.workspace.prepared_tree_sha256,
        workspace_clean_status_sha256: pilotCase.workspace.clean_status_sha256,
        verifier_image_digest: pilotCase.private_verifier.verifier_image_digest,
        verifier_contract_sha256: pilotCase.private_verifier.verifier_contract_sha256,
        verifier_config_sha256: pilotCase.private_verifier.verifier_config_sha256,
        verifier_public_key_principal_sha256:
          pilotCase.private_verifier.verifier_public_key_principal_sha256,
      })),
      cell_authorities: cellAuthorities,
    });
    const executionManifest =
      await preflightNonReleaseContractTestPilotExecutionManifestV1({
      authority: runnerAuthority,
      cases,
      plan,
    });
    assert.equal(
      executionManifest.oci_runtime_authority_sha256,
      runtimeAuthority.authority_sha256,
    );
    assert.deepEqual(executionManifest.runner_authority, runnerAuthority);
    assert.equal(
      executionManifest.evidence_authority_class,
      "non_release_contract_test_authority_v1",
    );
    const cellResources = buildNonReleaseContractTestCellResourceAuthorityV1({
      cellResources: rawCellResources,
      executionManifest,
      plan,
    });
    assert.equal(cellResources.claim_eligible, false);
    assert.equal(cellResources.resource_count, 9);
    const executionAuthorization =
      buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1({
      plan,
      executionManifest,
      fixedLedgerAuthorityRoot: authorityRoot,
      issuedAt: "2026-07-22T00:00:01.000Z",
    }, TEST_RUNNER_KEYS_V1.privateKey);
    assert.equal(executionAuthorization.claim_eligible, false);
    assert.deepEqual(
      executionAuthorization.runner_transport_authority,
      NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1,
    );
    assert.deepEqual(verifySignedRunnerExecutionAuthorizationV1(
      executionAuthorization,
      {
        plan,
        executionManifest,
        fixedLedgerAuthorityRoot: authorityRoot,
        publicKey: TEST_RUNNER_KEYS_V1.publicKey,
      },
    ), executionAuthorization);
    const runnerSigningKeyDer = Buffer.from(TEST_RUNNER_KEYS_V1.privateKey.export({
      format: "der",
      type: "pkcs8",
    }));
    const runnerSigningKeyPath = path.join(root, "runner-signing-key.pk8");
    await writeFile(runnerSigningKeyPath, runnerSigningKeyDer, { mode: 0o600 });
    runnerSigningKeyDer.fill(0);
    runnerSigningKeyFile = await open(runnerSigningKeyPath, "r");
    const formalApiKeyPath = path.join(root, "deepseek-api-key");
    await writeFile(formalApiKeyPath, OFFLINE_API_KEY, { mode: 0o600 });
    await chmod(formalApiKeyPath, 0o600);
    formalApiKeyFile = await open(formalApiKeyPath, "r");

    await assert.rejects(
      runNonReleaseContractTestSealedPilotFinalSignerProcessV1({
        authorityRoot,
        cases,
        executionManifest,
        nonReleaseContractTestRunnerPrivateKey: Buffer.alloc(1),
        plan,
        runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
        verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
      }),
      /aionis_eval_final_signer_process_non_release_private_key_object_required/u,
    );

    const transportCalls = [];
    const boundaryFailures = [];
    const fetchImpl = async (url, options) => {
      const ordinal = transportCalls.length + 1;
      let durableBoundary = null;
      try {
        durableBoundary = await readEventBoundary(authorityRoot, ordinal);
      } catch (error) {
        boundaryFailures.push(error);
      }
      transportCalls.push({
        ordinal,
        url,
        method: options.method,
        authorizationMatches: options.headers.Authorization === `Bearer ${OFFLINE_API_KEY}`,
        contentType: options.headers["Content-Type"],
        redirect: options.redirect,
        body: JSON.parse(options.body),
        durableBoundary,
      });
      return providerResponse(`offline-provider-request-${ordinal}`);
    };

    await assert.rejects(runExecutablePilotV1({
      apiKeyFd: -1,
      authorityRoot,
      cases,
      cellResourceAuthority: rawCellResources,
      executionAuthorization,
      executionManifest,
      evalProvenanceAuthority: {},
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      runnerSigningKeyFd: runnerSigningKeyFile.fd,
    }), /aionis_eval_deepseek_api_key_fd_invalid/u);
    assert.equal(transportCalls.length, 0);

    await assert.rejects(runExecutablePilotV1({
      apiKeyFd: formalApiKeyFile.fd,
      authorityRoot,
      cases,
      cellResourceAuthority: cellResources,
      executionAuthorization,
      executionManifest,
      evalProvenanceAuthority: {},
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      runnerSigningKeyFd: runnerSigningKeyFile.fd,
    }), /aionis_eval_release_repository_provenance_release_authority_brand_invalid/u);
    assert.equal(transportCalls.length, 0);

    await assert.rejects(runExecutablePilotV1({
      apiKeyFd: formalApiKeyFile.fd,
      authorityRoot,
      cases,
      cellResourceAuthority: rawCellResources,
      executionAuthorization,
      executionManifest,
      evalProvenanceAuthority: {},
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      runnerSigningKeyFd: runnerSigningKeyFile.fd,
    }), /aionis_eval_release_repository_provenance_release_authority_brand_invalid/u);
    assert.equal(transportCalls.length, 0);

    await assert.rejects(runNonReleaseContractTestExecutablePilotV1({
      apiKey: OFFLINE_API_KEY,
      authorityRoot,
      cases,
      cellResourceAuthority: rawCellResources,
      executionAuthorization,
      executionManifest,
      fetchImpl,
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      providerClock: providerClock(),
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }), /aionis_eval_cell_resource_authority_non_release_brand_invalid/u);
    assert.equal(transportCalls.length, 0);

    await assert.rejects(runNonReleaseContractTestExecutablePilotV1({
      apiKey: OFFLINE_API_KEY,
      authorityRoot,
      cases,
      cellResourceAuthority: { ...cellResources },
      executionAuthorization,
      executionManifest,
      fetchImpl,
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      providerClock: providerClock(),
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }), /aionis_eval_cell_resource_authority_non_release_brand_invalid/u);
    assert.equal(transportCalls.length, 0);

    await assert.rejects(runExecutablePilotV1({
      apiKeyFd: formalApiKeyFile.fd,
      authorityRoot,
      cases,
      cellResourceAuthority: cellResources,
      executionAuthorization,
      executionManifest,
      fetchImpl,
      plan,
      providerClock: providerClock(),
      runnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }), /aionis_eval_executable_pilot_runner_options_shape_invalid/u);

    await assert.rejects(runExecutablePilotV1({
      apiKeyFd: formalApiKeyFile.fd,
      authorityRoot,
      cases,
      cellResourceAuthority: cellResources,
      executionAuthorization,
      executionManifest,
      evalProvenanceAuthority: {},
      plan,
      runnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }), /aionis_eval_executable_pilot_runner_options_shape_invalid/u);

    await assert.rejects(runExecutablePilotV1({
      apiKeyFd: formalApiKeyFile.fd,
      authorityRoot,
      cases,
      cellResourceAuthority: cellResources,
      executionAuthorization,
      executionManifest,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }), /aionis_eval_executable_pilot_runner_options_shape_invalid/u);

    await assert.rejects(runExecutablePilotV1({
      apiKeyFd: formalApiKeyFile.fd,
      authorityRoot,
      cases,
      cellResourceAuthority: cellResources,
      executionAuthorization,
      executionManifest,
      evalProvenanceAuthority: {},
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      runnerSigningKeyFd: -1,
    }), /aionis_eval_final_signer_process_runner_signing_key_fd_invalid/u);

    const successfulRunCancellation = createReleasePilotCancellationAuthorityV1();
    const result = await runNonReleaseContractTestExecutablePilotV1({
      apiKey: OFFLINE_API_KEY,
      authorityRoot,
      cases,
      cellResourceAuthority: cellResources,
      executionAuthorization,
      executionManifest,
      fetchImpl,
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      providerClock: providerClock(),
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }, successfulRunCancellation);

    const committedCancellationSnapshot = snapshotReleasePilotCancellationV1(
      successfulRunCancellation,
    );
    assert.equal(committedCancellationSnapshot.final_manifest_committed, true);
    assert.equal(committedCancellationSnapshot.cancellation_requested, false);
    const postCommitSignalSnapshot = requestReleasePilotCancellationV1(
      successfulRunCancellation,
      { signal: "SIGTERM" },
    );
    assert.equal(postCommitSignalSnapshot.final_manifest_committed, true);
    assert.equal(postCommitSignalSnapshot.cancellation_requested, false);
    assert.equal(postCommitSignalSnapshot.post_commit_signal, "SIGTERM");

    assert.deepEqual(boundaryFailures, []);
    assert.equal(transportCalls.length, 9);
    for (const [index, call] of transportCalls.entries()) {
      const ordinal = index + 1;
      assert.equal(call.ordinal, ordinal);
      assert.equal(call.url, DEEPSEEK_ENDPOINT_V1);
      assert.equal(call.method, "POST");
      assert.equal(call.authorizationMatches, true);
      assert.equal(call.contentType, "application/json");
      assert.equal(call.redirect, "error");
      assert.equal(call.body.model, DEEPSEEK_MODEL_V1);
      assert.deepEqual(call.body.thinking, { type: "enabled" });
      assert.equal(call.body.reasoning_effort, "max");
      assert.deepEqual(call.body.response_format, { type: "json_object" });
      assert.equal(Object.hasOwn(call.body, "temperature"), false);
      assert.equal(Object.hasOwn(call.body, "n"), false);
      assert.equal(call.body.stream, false);
      assert.equal(call.durableBoundary.event_count, ordinal * 6 - 1);
      assert.equal(call.durableBoundary.reservation_event_kind, "provider_attempt_reserved");
      assert.equal(call.durableBoundary.request_started_event_kind, "provider_request_started");
      assert.equal(call.durableBoundary.reservation_cell_ordinal, ordinal);
      assert.equal(call.durableBoundary.request_started_cell_ordinal, ordinal);
      assert.equal(call.durableBoundary.reservation_attempt_ordinal, ordinal);
      assert.equal(call.durableBoundary.request_started_attempt_ordinal, ordinal);
      assert.equal(call.durableBoundary.reservation_file_mode, 0o600);
      assert.equal(call.durableBoundary.request_started_file_mode, 0o600);
    }

    assert.equal(result.schema_version, "aionis_executable_pilot_run_result_v1");
    assert.equal(result.cell_results.length, 9);
    assert.equal(new Set(result.cell_results.map((cellResult) =>
      cellResult.agent_exit_receipt.os_process_id)).size, 9);
    assert.equal(result.cell_results.every((cellResult) =>
      cellResult.agent_exit_receipt.fresh_process
      && cellResult.agent_exit_receipt.execution_status === "no_safe_change"
      && cellResult.agent_exit_receipt.os_process_id !== process.pid), true);
    for (const resultValue of result.cell_results) {
      const caseContext = casesById.get(resultValue.cell.case_id);
      assert.deepEqual(verifyPilotCellResultV1(resultValue, {
        plan,
        pilotCase: caseContext.pilotCase,
        verifierPublicKey: verifierKeys[caseContext.index].publicKey,
      }), resultValue);
      assert.deepEqual(
        verifySignedVerifierEvidenceV1(
          resultValue.verifier_evidence,
          verifierKeys[caseContext.index].publicKey,
        ),
        resultValue.verifier_evidence,
      );
      assert.equal(resultValue.verifier_evidence.temporal_fence.fresh_process, true);
      assert.equal(resultValue.verifier_evidence.temporal_fence.after_agent_exit, true);
      assert.equal(resultValue.verifier_evidence.checks[0].status, "failed");
      assert.equal(resultValue.evaluation.state, "scored");
      assert.equal(resultValue.evaluation.failure_class, "product");
      assert.equal(
        resultValue.runtime_observation === null,
        resultValue.cell.arm === "baseline",
      );
    }
    assert.equal(result.cell_results.filter((cellResult) =>
      cellResult.runtime_observation !== null).length, 6);
    assert.equal(result.cell_results.filter((cellResult) =>
      cellResult.cell.arm === "treatment"
      && cellResult.treatment_ledger?.state === "closed").length, 3);
    assert.equal(tracker.prepared.length, 9);
    assert.equal(tracker.prepared.filter((prepared) =>
      prepared.runtime?.continuation !== null
      && prepared.runtime?.continuation !== undefined).length, 3);
    assert.equal(tracker.settled.length, 3);
    assert.equal(tracker.closed.length, 9);
    assert.equal(tracker.settled.every((entry) =>
      entry.settlement.outcome_evidence_sha256 === entry.verifier_evidence_sha256), true);

    assert.deepEqual(verifyPilotVerdictV1(result.verdict), result.verdict);
    assert.equal(result.verdict.verdict, "reject");
    assert.equal(result.verdict.counts.cell_count, 9);
    assert.equal(result.verdict.counts.infrastructure_failure_count, 0);
    assert.equal(result.verdict.counts.runtime_observation_evidence_count, 6);
    assert.equal(result.verdict.counts.treatment_ledger_closed_count, 3);
    assert.equal(result.run_closure.counts.provider_attempt_count, 9);
    assert.equal(result.run_closure.counts.cell_result_count, 9);
    assert.equal(result.run_closure.counts.runtime_observation_count, 6);
    assert.equal(result.run_closure.counts.treatment_ledger_closed_count, 3);

    const { events, runDirectory } = await readCanonicalEvents(authorityRoot);
    assert.equal(events.length, 58);
    assert.deepEqual(events.map((event) => event.event_kind), [
      "run_started",
      ...plan.schedule.flatMap(() => [
        "cell_arm_prepared",
        "model_input_frozen",
        "provider_attempt_reserved",
        "provider_request_started",
        "provider_attempt_completed",
        "cell_result_recorded",
      ]),
      "resource_cleanup_confirmed",
      "verdict_recorded",
      "run_closed",
    ]);
    for (const [index, event] of events.entries()) {
      assert.equal(event.sequence, index + 1);
      assert.equal(event.previous_event_sha256, index === 0 ? null : events[index - 1].event_sha256);
      const artifactPath = path.join(
        runDirectory,
        "artifacts",
        `${event.payload_sha256}.json`,
      );
      const artifactText = await readFile(artifactPath, "utf8");
      const artifact = JSON.parse(artifactText);
      assert.equal(artifactText, `${canonicalJson(artifact)}\n`);
      assert.equal(canonicalSha256(artifact), event.payload_sha256);
      assert.equal((await lstat(artifactPath)).mode & 0o777, 0o600);
    }
    assert.equal(events.at(-1).event_sha256, result.run_closure.run_closed_event_sha256);
    assert.equal(events.at(-1).event_sha256, result.final_manifest.event_chain_head_sha256);

    const ledgerSnapshot = closedLedgerSnapshot(result, executionAuthorization, plan);
    assert.deepEqual(verifySignedRunnerFinalManifestV1(result.final_manifest, {
      plan,
      executionManifest,
      executionAuthorization,
      fixedLedgerAuthorityRoot: authorityRoot,
      ledgerSnapshot,
      runClosure: result.run_closure,
      verdict: result.verdict,
      sealedAt: result.final_manifest.sealed_at,
      publicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }), result.final_manifest);
    assert.equal(result.final_manifest.signature_algorithm, "ed25519");
    assert.equal(result.final_manifest.claim_eligible, false);
    assert.equal(
      result.final_manifest.evidence_authority_class,
      "non_release_contract_test_authority_v1",
    );
    assert.deepEqual(
      result.final_manifest.runner_transport_authority,
      NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1,
    );
    assert.equal(
      FINAL_SIGNER_PROCESS_CONTRACT_V1.pre_signature_authority,
      "full_sealed_ledger_replay_inside_signer_process",
    );
    assert.equal(
      FINAL_SIGNER_PROCESS_CONTRACT_V1.private_key_transport,
      "inherited_fd_3_only",
    );
    assert.equal(FINAL_SIGNER_PROCESS_CONTRACT_V1.caller_ledger_snapshot_policy, "forbidden");
    assert.equal(FINAL_SIGNER_PROCESS_CONTRACT_V1.caller_verdict_policy, "forbidden");

    const signerInput = {
      authorityRoot,
      cases,
      executionManifest,
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
    };
    await assert.rejects(
      runNonReleaseContractTestSealedPilotFinalSignerProcessV1({
        ...signerInput,
        ledgerSnapshot: {
          ...ledgerSnapshot,
          event_chain_head_sha256: "0".repeat(64),
        },
      }),
      /aionis_eval_non_release_contract_test_final_signer_process_options_shape_invalid/u,
    );
    await assert.rejects(
      runNonReleaseContractTestSealedPilotFinalSignerProcessV1({
        ...signerInput,
        verdict: {
          ...result.verdict,
          verdict: "promote",
        },
      }),
      /aionis_eval_non_release_contract_test_final_signer_process_options_shape_invalid/u,
    );

    const finalManifestPath = path.join(runDirectory, "final-manifest.json");
    const finalManifestText = await readFile(finalManifestPath, "utf8");
    assert.equal(finalManifestText, `${canonicalJson(result.final_manifest)}\n`);
    assert.deepEqual(JSON.parse(finalManifestText), result.final_manifest);
    assert.equal((await lstat(finalManifestPath)).mode & 0o777, 0o600);

    const privateKeyDer = Buffer.from(TEST_RUNNER_KEYS_V1.privateKey.export({
      format: "der",
      type: "pkcs8",
    }));
    const privateKeyEncodings = [
      privateKeyDer,
      Buffer.from(privateKeyDer.toString("base64"), "utf8"),
      Buffer.from(privateKeyDer.toString("base64url"), "utf8"),
      Buffer.from(privateKeyDer.toString("hex"), "utf8"),
    ];
    const providerKeyBytes = Buffer.from(OFFLINE_API_KEY, "utf8");
    const providerKeyEncodings = [
      providerKeyBytes,
      Buffer.from(providerKeyBytes.toString("base64"), "utf8"),
      Buffer.from(providerKeyBytes.toString("base64url"), "utf8"),
      Buffer.from(providerKeyBytes.toString("hex"), "utf8"),
    ];
    for (const artifact of await readAuthorityArtifactBuffers(authorityRoot)) {
      assert.equal(privateKeyEncodings.some((needle) => artifact.includes(needle)), false);
      assert.equal(providerKeyEncodings.some((needle) => artifact.includes(needle)), false);
    }
    privateKeyDer.fill(0);
    for (const encoded of privateKeyEncodings.slice(1)) encoded.fill(0);
    providerKeyBytes.fill(0);
    for (const encoded of providerKeyEncodings.slice(1)) encoded.fill(0);

    const sealedVerificationOptions = {
      authorityRoot,
      cases,
      executionManifest,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
    };
    const sealedReport = await verifySealedPilotRunV1(sealedVerificationOptions);
    assert.equal(sealedReport.status, "verified");
    assert.equal(sealedReport.cell_result_count, 9);
    assert.equal(sealedReport.event_count, 58);
    assert.equal(sealedReport.claim_eligible, false);
    assert.equal(sealedReport.final_manifest_sha256, result.final_manifest.final_manifest_sha256);

    const tamperedFinalManifest = {
      ...result.final_manifest,
      signature: `${result.final_manifest.signature[0] === "A" ? "B" : "A"}${
        result.final_manifest.signature.slice(1)
      }`,
    };
    await writeFile(
      finalManifestPath,
      `${canonicalJson(tamperedFinalManifest)}\n`,
      { mode: 0o600 },
    );
    await assert.rejects(
      verifySealedPilotRunV1(sealedVerificationOptions),
      /aionis_eval_runner_signature_final_manifest_signature_invalid/u,
    );
    await writeFile(finalManifestPath, finalManifestText, { mode: 0o600 });

    const runtimeCalls = (await readFile(runtimeLogPath, "utf8"))
      .trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    assert.equal(runtimeCalls.length, 9);
    assert.equal(runtimeCalls.every((call) => call.argv[0] === "run"), true);
    assert.equal(runtimeCalls.every((call) => call.argv.includes("--network=none")), true);
    assert.equal(runtimeCalls.every((call) => call.argv.includes("--read-only")), true);
    assert.equal(runtimeCalls.every((call) => call.argv.includes("--cap-drop=ALL")), true);
    assert.equal(runtimeCalls.every((call) =>
      call.argv.includes("--security-opt=no-new-privileges:true")), true);
    assert.equal(runtimeCalls.every((call) => call.argv.includes("--pull=never")), true);
    assert.equal(runtimeCalls.every((call) => call.argv.at(-1) === "reject"), true);
    assert.equal(runtimeCalls.every((call) => call.secret_environment_keys.length === 0), true);
    assert.equal(runtimeCalls.every((call) => new Set([-1, 0]).has(call.fd3_bytes)), true);
    assert.equal(new Set(runtimeCalls.map((call) =>
      call.argv[call.argv.indexOf("--name") + 1])).size, 9);

    const eventIndex = (kind, occurrence = 0) => {
      const indexes = events.flatMap((event, index) =>
        event.event_kind === kind ? [index] : []);
      assert.ok(indexes[occurrence] !== undefined);
      return indexes[occurrence];
    };
    const rechainedPayloadAttacks = [
      {
        name: "prepared payload exact keys",
        index: eventIndex("cell_arm_prepared"),
        pattern: /prepared_arm_shape_invalid/u,
        mutate: (payload) => ({ ...payload, unbound_field: "forbidden" }),
      },
      {
        name: "model input prepared-event reference",
        index: eventIndex("model_input_frozen"),
        pattern: /model_input_binding_invalid/u,
        mutate: (payload) => ({
          ...payload,
          prepared_arm_event_sha256: digest("tampered-prepared-event-ref"),
        }),
      },
      {
        name: "reservation authorization",
        index: eventIndex("provider_attempt_reserved"),
        pattern: /reservation_binding_invalid/u,
        mutate: (payload) => {
          const body = {
            ...payload,
            execution_authorization_sha256: digest("tampered-authorization"),
          };
          delete body.reservation_sha256;
          return { ...body, reservation_sha256: canonicalSha256(body) };
        },
      },
      {
        name: "reservation plan",
        index: eventIndex("provider_attempt_reserved"),
        pattern: /reservation_binding_invalid/u,
        mutate: (payload) => {
          const body = { ...payload, plan_sha256: digest("tampered-plan") };
          delete body.reservation_sha256;
          return { ...body, reservation_sha256: canonicalSha256(body) };
        },
      },
      {
        name: "reservation cell and ordinal",
        index: eventIndex("provider_attempt_reserved"),
        pattern: /reservation_binding_invalid/u,
        mutate: (payload) => {
          const body = {
            ...payload,
            attempt_ordinal: payload.attempt_ordinal + 1,
            cell_sha256: digest("tampered-cell"),
          };
          delete body.reservation_sha256;
          return { ...body, reservation_sha256: canonicalSha256(body) };
        },
      },
      {
        name: "reservation canonical request",
        index: eventIndex("provider_attempt_reserved"),
        pattern: /reservation_binding_invalid/u,
        mutate: (payload) => {
          const body = {
            ...payload,
            canonical_request_sha256: digest("tampered-canonical-request"),
          };
          delete body.reservation_sha256;
          return { ...body, reservation_sha256: canonicalSha256(body) };
        },
      },
      {
        name: "reservation previous result reference",
        index: eventIndex("provider_attempt_reserved", 1),
        pattern: /reservation_binding_invalid/u,
        mutate: (payload) => {
          const body = {
            ...payload,
            previous_cell_result_event_sha256: digest("tampered-previous-result"),
          };
          delete body.reservation_sha256;
          return { ...body, reservation_sha256: canonicalSha256(body) };
        },
      },
      {
        name: "request-start reservation event reference",
        index: eventIndex("provider_request_started"),
        pattern: /request_started_binding_invalid/u,
        mutate: (payload) => {
          const body = {
            ...payload,
            reservation_event_sha256: digest("tampered-reservation-event"),
          };
          delete body.request_started_sha256;
          return { ...body, request_started_sha256: canonicalSha256(body) };
        },
      },
      {
        name: "completion frozen messages",
        index: eventIndex("provider_attempt_completed"),
        pattern: /completion_binding_invalid/u,
        mutate: (payload) => {
          const body = canonicalClone({
            ...payload,
            messages: payload.messages.map((message, index) => index === 0
              ? { ...message, content: `${message.content}\ntampered` }
              : message),
          });
          delete body.attempt_completion_sha256;
          return { ...body, attempt_completion_sha256: canonicalSha256(body) };
        },
      },
      {
        name: "completion receipt request-start reference",
        index: eventIndex("provider_attempt_completed"),
        pattern: /completion_receipt_binding_invalid/u,
        mutate: (payload) => {
          const requestBody = {
            ...payload.request_receipt,
            provider_request_started_event_sha256:
              digest("tampered-receipt-request-start-event"),
          };
          delete requestBody.request_receipt_sha256;
          const requestReceipt = {
            ...requestBody,
            request_receipt_sha256: canonicalSha256(requestBody),
          };
          const responseBody = {
            ...payload.response_receipt,
            request_receipt_sha256: requestReceipt.request_receipt_sha256,
          };
          delete responseBody.response_receipt_sha256;
          const responseReceipt = {
            ...responseBody,
            response_receipt_sha256: canonicalSha256(responseBody),
          };
          const completionBody = {
            ...payload,
            request_receipt: requestReceipt,
            response_receipt: responseReceipt,
          };
          delete completionBody.attempt_completion_sha256;
          return {
            ...completionBody,
            attempt_completion_sha256: canonicalSha256(completionBody),
          };
        },
      },
      {
        name: "recorded result completion-event reference",
        index: eventIndex("cell_result_recorded"),
        pattern: /cell_result_event_binding_invalid/u,
        mutate: (payload) => ({
          ...payload,
          provider_attempt_completion_event_sha256:
            digest("tampered-completion-event-ref"),
        }),
      },
    ];
    for (const attack of rechainedPayloadAttacks) {
      const restore = await installRechainedPayloadTamper(
        runDirectory,
        events,
        attack.index,
        attack.mutate,
      );
      try {
        await assert.rejects(
          verifySealedPilotRunV1(sealedVerificationOptions),
          attack.pattern,
          attack.name,
        );
      } finally {
        await restore();
      }
    }

    const reservationEvent = events.find((event) =>
      event.event_kind === "provider_attempt_reserved");
    const tamperedArtifactPath = path.join(
      runDirectory,
      "artifacts",
      `${reservationEvent.payload_sha256}.json`,
    );
    const originalArtifact = JSON.parse(await readFile(tamperedArtifactPath, "utf8"));
    await writeFile(tamperedArtifactPath, `${canonicalJson({
      ...originalArtifact,
      state: "tampered_after_seal",
    })}\n`, { mode: 0o600 });
    await assert.rejects(
      verifySealedPilotRunV1(sealedVerificationOptions),
      /aionis_eval_sealed_pilot_run_reservation_payload_hash_invalid/u,
    );

    const cancellationAuthorityRoot = path.join(root, "cancellation-authority");
    await mkdir(cancellationAuthorityRoot, { mode: 0o700 });
    const cancellationAuthority = createReleasePilotCancellationAuthorityV1();
    const cancellationCloseCalls = Array.from({ length: plan.schedule.length }, () => 0);
    const cancellationTracker = { prepared: [], settled: [], closed: [] };
    const cancellationRawCellResources = rawCellResources.map((resource, index) => {
      const cell = plan.schedule[index];
      const caseContext = casesById.get(cell.case_id);
      const baseAdapter = createPreparedArmAdapter({
        cell,
        pilotCase: caseContext.pilotCase,
        tracker: cancellationTracker,
      });
      return {
        ...resource,
        adapter: Object.freeze({
          prepareArm: baseAdapter.prepareArm,
          ...(typeof baseAdapter.settleTreatment === "function" ? {
            settleTreatment: baseAdapter.settleTreatment,
          } : {}),
          async close() {
            cancellationCloseCalls[index] += 1;
            cancellationTracker.closed.push(cell.opaque_cell_id);
          },
        }),
      };
    });
    const cancellationCellResources = buildNonReleaseContractTestCellResourceAuthorityV1({
      cellResources: cancellationRawCellResources,
      executionManifest,
      plan,
    });
    const cancellationExecutionAuthorization =
      buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1({
        plan,
        executionManifest,
        fixedLedgerAuthorityRoot: cancellationAuthorityRoot,
        issuedAt: "2026-07-22T00:00:30.000Z",
      }, TEST_RUNNER_KEYS_V1.privateKey);
    let cancellationFetchCount = 0;
    const cancellationResult = await runNonReleaseContractTestExecutablePilotV1({
      apiKey: OFFLINE_API_KEY,
      authorityRoot: cancellationAuthorityRoot,
      cases,
      cellResourceAuthority: cancellationCellResources,
      executionAuthorization: cancellationExecutionAuthorization,
      executionManifest,
      fetchImpl: async (_url, init) => {
        cancellationFetchCount += 1;
        requestReleasePilotCancellationV1(cancellationAuthority, { signal: "SIGTERM" });
        assert.equal(init.signal.aborted, true);
        throw init.signal.reason;
      },
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      providerClock: providerClock(),
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }, cancellationAuthority);
    assert.equal(cancellationFetchCount, 1);
    assert.equal(
      cancellationResult.schema_version,
      "aionis_executable_pilot_aborted_result_v1",
    );
    assert.equal(cancellationResult.claim_eligible, false);
    assert.equal(cancellationResult.resumable, false);
    assert.equal(cancellationResult.failure_stage, "provider");
    assert.equal(cancellationResult.failure_class, "provider_or_network");
    assert.equal(cancellationResult.run_abort.cleanup_confirmed, true);
    assert.equal(cancellationResult.abort_manifest.status, "aborted");
    assert.equal(cancellationResult.abort_manifest.claim_eligible, false);
    assert.deepEqual(cancellationCloseCalls, Array.from({ length: 9 }, () => 1));
    const {
      events: cancellationEvents,
      runDirectory: cancellationRunDirectory,
    } = await readCanonicalEvents(cancellationAuthorityRoot);
    assert.deepEqual(cancellationEvents.map((event) => event.event_kind), [
      "run_started",
      "cell_arm_prepared",
      "model_input_frozen",
      "provider_attempt_reserved",
      "provider_request_started",
      "run_aborted",
    ]);
    assert.equal(
      cancellationEvents.some((event) => event.event_kind === "provider_attempt_completed"),
      false,
    );
    assert.equal(
      cancellationEvents.some((event) => event.event_kind === "cell_result_recorded"),
      false,
    );
    const cancellationAbortPayload = JSON.parse(await readFile(path.join(
      cancellationRunDirectory,
      "artifacts",
      `${cancellationEvents.at(-1).payload_sha256}.json`,
    ), "utf8"));
    assert.equal(
      cancellationAbortPayload.active_provider_attempt_state,
      "request_may_have_started_burned",
    );
    assert.ok(await readFile(
      path.join(cancellationRunDirectory, "abort-manifest.json"),
      "utf8",
    ));
    await assert.rejects(
      readFile(path.join(cancellationRunDirectory, "final-manifest.json"), "utf8"),
      /ENOENT/u,
    );
    const cancellationSealedReport = await verifySealedPilotRunV1({
      authorityRoot: cancellationAuthorityRoot,
      cases,
      executionManifest,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
    });
    assert.equal(cancellationSealedReport.status, "verified_aborted");
    assert.equal(cancellationSealedReport.claim_eligible, false);

    const finalizationAuthorityRoot = path.join(root, "finalization-authority");
    await mkdir(finalizationAuthorityRoot, { mode: 0o700 });
    const finalizationCancellation = createReleasePilotCancellationAuthorityV1();
    const finalizationTracker = { prepared: [], settled: [], closed: [] };
    const finalizationRawResources = rawCellResources.map((resource, index) => {
      const cell = plan.schedule[index];
      const caseContext = casesById.get(cell.case_id);
      return {
        ...resource,
        adapter: createPreparedArmAdapter({
          cell,
          pilotCase: caseContext.pilotCase,
          tracker: finalizationTracker,
        }),
      };
    });
    const finalizationCellResources = buildNonReleaseContractTestCellResourceAuthorityV1({
      cellResources: finalizationRawResources,
      executionManifest,
      plan,
    });
    const finalizationExecutionAuthorization =
      buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1({
        plan,
        executionManifest,
        fixedLedgerAuthorityRoot: finalizationAuthorityRoot,
        issuedAt: "2026-07-22T00:00:45.000Z",
      }, TEST_RUNNER_KEYS_V1.privateKey);
    let releaseFirstFetch;
    const firstFetchBarrier = new Promise((resolve) => { releaseFirstFetch = resolve; });
    let observeFirstFetch;
    const firstFetchObserved = new Promise((resolve) => { observeFirstFetch = resolve; });
    let finalizationFetchCount = 0;
    const finalizationRun = runNonReleaseContractTestExecutablePilotV1({
      apiKey: OFFLINE_API_KEY,
      authorityRoot: finalizationAuthorityRoot,
      cases,
      cellResourceAuthority: finalizationCellResources,
      executionAuthorization: finalizationExecutionAuthorization,
      executionManifest,
      fetchImpl: async () => {
        finalizationFetchCount += 1;
        if (finalizationFetchCount === 1) {
          observeFirstFetch();
          await firstFetchBarrier;
        }
        return {
          status: 503,
          headers: { get() { return null; } },
          async text() { return "{}"; },
        };
      },
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      providerClock: providerClock(),
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    }, finalizationCancellation);
    await firstFetchObserved;
    const [finalizationRunDirectoryName] = await readdir(path.join(
      finalizationAuthorityRoot,
      "pilots",
    ));
    const finalizationEventsDirectory = path.join(
      finalizationAuthorityRoot,
      "pilots",
      finalizationRunDirectoryName,
      "events",
    );
    let finalizationWatcher;
    const runClosedSignalObserved = new Promise((resolve) => {
      finalizationWatcher = watch(finalizationEventsDirectory, (_event, filename) => {
        if (filename?.toString() !== "000058.json") return;
        finalizationWatcher.close();
        requestReleasePilotCancellationV1(finalizationCancellation, {
          signal: "SIGTERM",
        });
        resolve();
      });
    });
    releaseFirstFetch();
    const finalizationResult = await finalizationRun;
    await runClosedSignalObserved;
    assert.equal(finalizationFetchCount, 9);
    assert.equal(finalizationResult.schema_version, "aionis_executable_pilot_aborted_result_v1");
    assert.equal(finalizationResult.claim_eligible, false);
    assert.ok(
      ["run_close", "final_signer"].includes(finalizationResult.failure_stage),
      `expected cancellation during finalization, received ${finalizationResult.failure_stage}`,
    );
    assert.equal(finalizationResult.abort_manifest.status, "aborted");
    const {
      events: finalizationEvents,
      runDirectory: finalizationRunDirectory,
    } = await readCanonicalEvents(finalizationAuthorityRoot);
    assert.deepEqual(finalizationEvents.slice(-2).map((event) => event.event_kind), [
      "run_closed",
      "run_aborted",
    ]);
    assert.ok(await readFile(
      path.join(finalizationRunDirectory, "abort-manifest.json"),
      "utf8",
    ));
    await assert.rejects(
      readFile(path.join(finalizationRunDirectory, "final-manifest.json"), "utf8"),
      /ENOENT/u,
    );
    const finalizationSealedReport = await verifySealedPilotRunV1({
      authorityRoot: finalizationAuthorityRoot,
      cases,
      executionManifest,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
    });
    assert.equal(finalizationSealedReport.status, "verified_aborted");
    assert.equal(finalizationSealedReport.claim_eligible, false);

    const preparationAbortAuthorityRoot = path.join(
      root,
      "preparation-abort-authority",
    );
    await mkdir(preparationAbortAuthorityRoot, { mode: 0o700 });
    const preparationAbortTracker = { prepared: [], settled: [], closed: [] };
    const preparationAbortRawResources = rawCellResources.map((resource, index) => {
      const cell = plan.schedule[index];
      const caseContext = casesById.get(cell.case_id);
      const baseAdapter = createPreparedArmAdapter({
        cell,
        pilotCase: caseContext.pilotCase,
        tracker: preparationAbortTracker,
      });
      return {
        ...resource,
        adapter: Object.freeze({
          async prepareArm() {
            if (cell.ordinal === 2) {
              throw new Error("controlled_cell_preparation_failure");
            }
            return baseAdapter.prepareArm();
          },
          ...(typeof baseAdapter.settleTreatment === "function" ? {
            settleTreatment: baseAdapter.settleTreatment,
          } : {}),
          close: baseAdapter.close,
        }),
      };
    });
    const preparationAbortResources =
      buildNonReleaseContractTestCellResourceAuthorityV1({
        cellResources: preparationAbortRawResources,
        executionManifest,
        plan,
      });
    const preparationAbortAuthorization =
      buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1({
        plan,
        executionManifest,
        fixedLedgerAuthorityRoot: preparationAbortAuthorityRoot,
        issuedAt: "2026-07-22T00:00:50.000Z",
      }, TEST_RUNNER_KEYS_V1.privateKey);
    let preparationAbortFetchCount = 0;
    const preparationAbortResult = await runNonReleaseContractTestExecutablePilotV1({
      apiKey: OFFLINE_API_KEY,
      authorityRoot: preparationAbortAuthorityRoot,
      cases,
      cellResourceAuthority: preparationAbortResources,
      executionAuthorization: preparationAbortAuthorization,
      executionManifest,
      fetchImpl: async () => {
        preparationAbortFetchCount += 1;
        return {
          status: 503,
          headers: { get() { return null; } },
          async text() { return "{}"; },
        };
      },
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      providerClock: providerClock(),
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    });
    assert.equal(preparationAbortFetchCount, 1);
    assert.equal(
      preparationAbortResult.schema_version,
      "aionis_executable_pilot_aborted_result_v1",
    );
    assert.equal(preparationAbortResult.failure_stage, "cell_preparation");
    assert.equal(preparationAbortResult.failure_class, "harness_infrastructure");
    assert.equal(preparationAbortResult.completed_cell_result_sha256s.length, 1);
    assert.equal(preparationAbortResult.run_abort.completed_cell_count, 1);
    assert.equal(preparationAbortResult.run_abort.next_attempt_ordinal, 2);
    assert.equal(preparationAbortResult.run_abort.active_attempt_ordinal, null);
    assert.equal(
      preparationAbortResult.run_abort.active_provider_attempt_state,
      "no_active_attempt",
    );
    assert.equal(
      preparationAbortResult.run_abort.failing_cell_ref.opaque_cell_id,
      "cell-02",
    );
    assert.equal(preparationAbortResult.abort_manifest.status, "aborted");
    assert.deepEqual(
      preparationAbortTracker.closed,
      [
        plan.schedule[0].opaque_cell_id,
        ...plan.schedule.slice(1).reverse().map((cell) => cell.opaque_cell_id),
      ],
    );
    const {
      events: preparationAbortEvents,
      runDirectory: preparationAbortRunDirectory,
    } = await readCanonicalEvents(preparationAbortAuthorityRoot);
    assert.deepEqual(preparationAbortEvents.map((event) => event.event_kind), [
      "run_started",
      "cell_arm_prepared",
      "model_input_frozen",
      "provider_attempt_reserved",
      "provider_request_started",
      "provider_attempt_completed",
      "cell_result_recorded",
      "run_aborted",
    ]);
    assert.equal(
      preparationAbortEvents.at(-1).cell_ref.opaque_cell_id,
      "cell-02",
    );
    assert.ok(await readFile(
      path.join(preparationAbortRunDirectory, "abort-manifest.json"),
      "utf8",
    ));
    await assert.rejects(
      readFile(path.join(preparationAbortRunDirectory, "final-manifest.json"), "utf8"),
      /ENOENT/u,
    );
    const preparationAbortSealedReport = await verifySealedPilotRunV1({
      authorityRoot: preparationAbortAuthorityRoot,
      cases,
      executionManifest,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
    });
    assert.equal(preparationAbortSealedReport.status, "verified_aborted");
    assert.equal(preparationAbortSealedReport.cell_result_count, 1);
    assert.equal(preparationAbortSealedReport.claim_eligible, false);

    const persistenceStages = [
      "after_open",
      "after_write",
      "after_file_fsync",
      "after_directory_fsync",
    ];
    for (const [stageIndex, cancellationStage] of persistenceStages.entries()) {
      const stageAuthorityRoot = path.join(
        root,
        `final-persist-${cancellationStage}-authority`,
      );
      await mkdir(stageAuthorityRoot, { mode: 0o700 });
      const stageCancellation = createReleasePilotCancellationAuthorityV1();
      const stageTracker = { prepared: [], settled: [], closed: [] };
      const stageResources = rawCellResources.map((resource, index) => {
        const cell = plan.schedule[index];
        const caseContext = casesById.get(cell.case_id);
        return {
          ...resource,
          adapter: createPreparedArmAdapter({
            cell,
            pilotCase: caseContext.pilotCase,
            tracker: stageTracker,
          }),
        };
      });
      const stageCellResources = buildNonReleaseContractTestCellResourceAuthorityV1({
        cellResources: stageResources,
        executionManifest,
        plan,
      });
      const stageExecutionAuthorization =
        buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1({
          plan,
          executionManifest,
          fixedLedgerAuthorityRoot: stageAuthorityRoot,
          issuedAt: `2026-07-22T00:01:0${stageIndex}.000Z`,
        }, TEST_RUNNER_KEYS_V1.privateKey);
      const observedPersistenceStages = [];
      const persistenceAuthority =
        createNonReleaseContractTestFinalManifestPersistenceAuthorityV1(
          ({ stage }) => {
            observedPersistenceStages.push(stage);
            if (stage === cancellationStage) {
              requestReleasePilotCancellationV1(stageCancellation, {
                signal: "SIGTERM",
              });
            }
          },
        );
      let stageFetchCount = 0;
      const stageResult = await runNonReleaseContractTestExecutablePilotV1({
        apiKey: OFFLINE_API_KEY,
        authorityRoot: stageAuthorityRoot,
        cases,
        cellResourceAuthority: stageCellResources,
        executionAuthorization: stageExecutionAuthorization,
        executionManifest,
        fetchImpl: async () => {
          stageFetchCount += 1;
          return providerResponse(
            `final-persist-${stageIndex}-request-${stageFetchCount}`,
          );
        },
        nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
        plan,
        providerClock: providerClock(),
        runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      }, stageCancellation, persistenceAuthority);
      assert.equal(stageFetchCount, 9, cancellationStage);
      assert.equal(
        stageResult.schema_version,
        "aionis_executable_pilot_aborted_result_v1",
        cancellationStage,
      );
      assert.equal(stageResult.failure_stage, "final_manifest_persist", cancellationStage);
      assert.equal(stageResult.failure_class, "filesystem_infrastructure", cancellationStage);
      assert.equal(stageResult.claim_eligible, false, cancellationStage);
      assert.equal(stageResult.abort_manifest.status, "aborted", cancellationStage);
      assert.deepEqual(observedPersistenceStages, persistenceStages, cancellationStage);
      const stageCancellationSnapshot = snapshotReleasePilotCancellationV1(
        stageCancellation,
      );
      assert.equal(stageCancellationSnapshot.cancellation_requested, true);
      assert.equal(stageCancellationSnapshot.final_manifest_committed, false);
      const {
        events: stageEvents,
        runDirectory: stageRunDirectory,
      } = await readCanonicalEvents(stageAuthorityRoot);
      assert.deepEqual(stageEvents.slice(-2).map((event) => event.event_kind), [
        "run_closed",
        "run_aborted",
      ], cancellationStage);
      await assert.rejects(
        readFile(path.join(stageRunDirectory, "final-manifest.json"), "utf8"),
        /ENOENT/u,
        cancellationStage,
      );
      assert.ok(await readFile(
        path.join(stageRunDirectory, "abort-manifest.json"),
        "utf8",
      ));
      const stageSealedReport = await verifySealedPilotRunV1({
        authorityRoot: stageAuthorityRoot,
        cases,
        executionManifest,
        plan,
        runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
        verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
      });
      assert.equal(stageSealedReport.status, "verified_aborted", cancellationStage);
      assert.equal(stageSealedReport.claim_eligible, false, cancellationStage);
    }

    const abortAuthorityRoot = path.join(root, "abort-authority");
    await mkdir(abortAuthorityRoot, { mode: 0o700 });
    const abortCloseCalls = Array.from({ length: plan.schedule.length }, () => 0);
    const abortTracker = { prepared: [], settled: [], closed: [] };
    const abortRawCellResources = rawCellResources.map((resource, index) => {
      const cell = plan.schedule[index];
      const caseContext = casesById.get(cell.case_id);
      const baseAdapter = createPreparedArmAdapter({
        cell,
        pilotCase: caseContext.pilotCase,
        tracker: abortTracker,
      });
      return {
        ...resource,
        adapter: Object.freeze({
          prepareArm: baseAdapter.prepareArm,
          ...(typeof baseAdapter.settleTreatment === "function" ? {
            settleTreatment: baseAdapter.settleTreatment,
          } : {}),
          async close() {
            abortCloseCalls[index] += 1;
            if (index === 0) throw new Error("deterministic-first-resource-close-failure");
            abortTracker.closed.push(cell.opaque_cell_id);
          },
        }),
      };
    });
    const abortCellResources = buildNonReleaseContractTestCellResourceAuthorityV1({
      cellResources: abortRawCellResources,
      executionManifest,
      plan,
    });
    const abortExecutionAuthorization =
      buildSignedNonReleaseContractTestRunnerExecutionAuthorizationV1({
        plan,
        executionManifest,
        fixedLedgerAuthorityRoot: abortAuthorityRoot,
        issuedAt: "2026-07-22T00:01:00.000Z",
      }, TEST_RUNNER_KEYS_V1.privateKey);
    let abortFetchCount = 0;
    const abortResult = await runNonReleaseContractTestExecutablePilotV1({
      apiKey: OFFLINE_API_KEY,
      authorityRoot: abortAuthorityRoot,
      cases,
      cellResourceAuthority: abortCellResources,
      executionAuthorization: abortExecutionAuthorization,
      executionManifest,
      fetchImpl: async () => providerResponse(`abort-provider-${++abortFetchCount}`),
      nonReleaseContractTestRunnerPrivateKey: TEST_RUNNER_KEYS_V1.privateKey,
      plan,
      providerClock: providerClock(),
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
    });
    assert.equal(abortFetchCount, 1);
    assert.equal(abortResult.schema_version, "aionis_executable_pilot_aborted_result_v1");
    assert.equal(abortResult.claim_eligible, false);
    assert.equal(abortResult.resumable, false);
    assert.equal(abortResult.run_abort.cleanup_confirmed, false);
    assert.equal(abortResult.run_abort.cleanup_receipt.state, "cleanup_incomplete");
    assert.equal(abortResult.abort_manifest.status, "aborted");
    assert.equal(abortResult.abort_manifest.claim_eligible, false);
    assert.equal(abortResult.abort_manifest.resumable, false);
    assert.deepEqual(abortCloseCalls, Array.from({ length: 9 }, () => 1));
    assert.equal(abortTracker.closed.length, 8);
    const { events: abortEvents, runDirectory: abortRunDirectory } =
      await readCanonicalEvents(abortAuthorityRoot);
    assert.equal(abortEvents.at(-1).event_kind, "run_aborted");
    assert.equal(abortEvents.length, 7);
    assert.equal(abortEvents.at(-1).cell_ref.ordinal, 1);
    assert.ok(await readFile(path.join(abortRunDirectory, "abort-manifest.json"), "utf8"));
    const abortSealedReport = await verifySealedPilotRunV1({
      authorityRoot: abortAuthorityRoot,
      cases,
      executionManifest,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
    });
    assert.equal(abortSealedReport.status, "verified_aborted");
    assert.equal(abortSealedReport.claim_eligible, false);
  } finally {
    await formalApiKeyFile?.close();
    await runnerSigningKeyFile?.close();
    await rm(root, { recursive: true, force: true });
  }
});
