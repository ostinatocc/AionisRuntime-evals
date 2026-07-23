import { buildAgentModelInputV1 } from "./agent-action.mjs";
import { executeAgentActionV1 } from "./agent-execution.mjs";
import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
} from "./canonical.mjs";
import {
  resolveNonReleaseContractTestCellResourcesV1,
} from "./cell-resource-authority.mjs";
import {
  buildOciPrivateVerifierBindingV1,
} from "./oci-verifier-process.mjs";
import {
  assertDeepSeekApiKeyV1,
  readDeepSeekApiKeyFdV1,
  createDeepSeekProviderV1,
} from "./deepseek-provider.mjs";
import { verifyPilotCaseV1, verifyPilotPlanV1 } from "./pilot-contract.mjs";
import {
  claimReleaseCellResourceAuthorityV1,
} from "./release-cell-resource-authority.mjs";
import {
  verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1,
} from "./release-eval-repository-provenance.mjs";
import {
  assertReleasePilotCancellationAuthorityV1,
  checkpointReleasePilotCancellationV1,
  createReleasePilotCancellationAuthorityV1,
} from "./release-pilot-cancellation.mjs";
import {
  buildOwnerCleanupReceiptV1,
  buildResourceCleanupReceiptV1,
  RELEASE_CLEANUP_OWNER_KINDS_V1,
  verifyOwnerCleanupReceiptV1,
} from "./pilot-run-event-contract.mjs";
import {
  buildPilotCellResultV1,
  buildPilotInfrastructureFailureV1,
} from "./pilot-result.mjs";
import {
  assertExistingRunnerSigningKeyFdV1,
  runNonReleaseContractTestSealedPilotAbortSignerProcessV1,
  runNonReleaseContractTestSealedPilotFinalSignerProcessV1,
  runSealedPilotAbortSignerProcessV1,
  runSealedPilotFinalSignerProcessV1,
} from "./final-signer-process.mjs";
import { beginPilotRunLedgerV1 } from "./pilot-run-ledger.mjs";
import { scorePilotV1 } from "./pilot-scorer.mjs";
import {
  preflightNonReleaseContractTestPilotExecutionManifestV1,
  preflightPilotExecutionManifestV1,
} from "./runner-authority.mjs";
import {
  NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1,
  RELEASE_RUNNER_TRANSPORT_AUTHORITY_V1,
  verifySignedRunnerExecutionAuthorizationV1,
} from "./runner-signature.mjs";

const PLATFORM_FETCH_V1 = typeof globalThis.fetch === "function"
  ? globalThis.fetch.bind(globalThis)
  : null;
const PLATFORM_DATE_V1 = Date;
const PLATFORM_DATE_NOW_V1 = Date.now.bind(Date);

const COMMON_RUNNER_OPTION_KEYS = Object.freeze([
  "authorityRoot",
  "cases",
  "cellResourceAuthority",
  "executionAuthorization",
  "executionManifest",
  "plan",
  "runnerPublicKey",
]);

const FORMAL_RUNNER_OPTION_KEYS = Object.freeze([
  ...COMMON_RUNNER_OPTION_KEYS,
  "apiKeyFd",
  "evalProvenanceAuthority",
  "runnerSigningKeyFd",
]);

const NON_RELEASE_CONTRACT_TEST_RUNNER_OPTION_KEYS = Object.freeze([
  ...COMMON_RUNNER_OPTION_KEYS,
  "apiKey",
  "fetchImpl",
  "nonReleaseContractTestRunnerPrivateKey",
  "providerClock",
]);

function fail(code) {
  throw new Error(`aionis_eval_executable_pilot_runner_${code}`);
}

function nowAfter(minimumTimestamp = null) {
  const sampled = new PLATFORM_DATE_V1(PLATFORM_DATE_NOW_V1());
  if (minimumTimestamp !== null
    && sampled.getTime() <= PLATFORM_DATE_V1.parse(minimumTimestamp)) {
    return new PLATFORM_DATE_V1(
      PLATFORM_DATE_V1.parse(minimumTimestamp) + 1,
    ).toISOString();
  }
  return sampled.toISOString();
}

function platformProviderClockV1() {
  return new PLATFORM_DATE_V1(PLATFORM_DATE_NOW_V1()).toISOString();
}

function yieldToPendingSignalHandlers() {
  return new Promise((resolve) => setImmediate(resolve));
}

function verifyResource(value, cell) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("cell_resource_invalid");
  }
  const expectedKeys = [
    "adapter",
    "executionAuthority",
    "ociRuntimeAuthority",
    "runVerifier",
    "verifierConfig",
    "verifierPublicKey",
  ];
  if (Object.keys(value).sort().join("\n") !== [...expectedKeys].sort().join("\n")) {
    fail("cell_resource_shape_invalid");
  }
  if (value.adapter === null || typeof value.adapter !== "object"
    || typeof value.adapter.prepareArm !== "function"
    || (cell.arm === "treatment" && typeof value.adapter.settleTreatment !== "function")
    || typeof value.runVerifier !== "function") {
    fail("cell_adapter_invalid");
  }
  return value;
}

function treatmentLedger(prepared, settlement, state, evidence) {
  if (prepared.arm !== "treatment") return null;
  const continuation = prepared.runtime.continuation;
  const common = {
    state,
    decision_id: continuation.decision_id,
    contract_sha256: continuation.contract_sha256,
    render_result_sha256: continuation.render_result_sha256,
    render_content_sha256: continuation.render_content_sha256,
    exposure_event_sha256: continuation.exposure_event_sha256,
  };
  if (state === "open") {
    return canonicalClone({
      ...common,
      record_outcome_operation_id: null,
      request_body_sha256: null,
      operation_request_sha256: null,
      operation_receipt_sha256: null,
      use_receipt_sha256: null,
      outcome_evidence_sha256: null,
      ledger_head_event_sha256: null,
      full_decision_response_sha256: null,
      effect_state: null,
    });
  }
  if (settlement === null || evidence === null) fail("closed_treatment_evidence_missing");
  return canonicalClone({ ...common, ...settlement });
}

function cellExecutionRef(cell, prepared) {
  const continuation = cell.arm === "treatment" ? prepared.runtime.continuation : null;
  return canonicalClone({
    pilot_id: cell.pilot_id,
    opaque_cell_id: cell.opaque_cell_id,
    arm: cell.arm,
    case_id: cell.case_id,
    case_sha256: cell.case_sha256,
    decision_id: continuation?.decision_id ?? null,
    contract_sha256: continuation?.contract_sha256 ?? null,
    render_result_sha256: continuation?.render_result_sha256 ?? null,
    exposure_event_sha256: continuation?.exposure_event_sha256 ?? null,
  });
}

function infrastructureFailure(cell, stage, failureClass, minimumTimestamp) {
  const observedAt = nowAfter(minimumTimestamp);
  return buildPilotInfrastructureFailureV1({
    failure_class: failureClass,
    stage,
    observed_at: observedAt,
    evidence_ref_sha256: canonicalSha256({
      schema_version: "aionis_executable_pilot_redacted_failure_ref_v1",
      pilot_id: cell.pilot_id,
      opaque_cell_id: cell.opaque_cell_id,
      stage,
      observed_at: observedAt,
    }),
  });
}

async function closeAdapter(resource) {
  if (typeof resource.adapter.close === "function") await resource.adapter.close();
}

function buildResourceCloser(resources, disposeOwners, ownerKinds) {
  const states = resources.map(() => "pending");
  let ownerCleanupPromise = null;
  let finalReceipt = null;
  function cellState() {
    const closedResourceOrdinals = [];
    const failedResourceOrdinals = [];
    for (const [index, state] of states.entries()) {
      if (state === "closed") closedResourceOrdinals.push(index + 1);
      if (state === "failed") failedResourceOrdinals.push(index + 1);
    }
    return { closedResourceOrdinals, failedResourceOrdinals };
  }
  async function closeOwners() {
    if (ownerCleanupPromise === null) {
      ownerCleanupPromise = (async () => {
        try {
          return verifyOwnerCleanupReceiptV1(await disposeOwners(), { ownerKinds });
        } catch {
          return buildOwnerCleanupReceiptV1({
            ownerKinds,
            closedOwnerKinds: [],
            failedOwnerKinds: ownerKinds,
          });
        }
      })();
    }
    return ownerCleanupPromise;
  }
  return Object.freeze({
    async close(index) {
      if (states[index] === "closed") return;
      if (states[index] === "failed") {
        throw new Error("aionis_eval_executable_pilot_runner_resource_already_failed");
      }
      if (states[index] !== "pending") fail("resource_cleanup_state_invalid");
      states[index] = "closing";
      try {
        await closeAdapter(resources[index]);
        states[index] = "closed";
      } catch (error) {
        states[index] = "failed";
        throw error;
      }
    },
    async complete() {
      if (finalReceipt !== null) return finalReceipt;
      for (let index = resources.length - 1; index >= 0; index -= 1) {
        if (states[index] !== "pending") continue;
        try {
          await this.close(index);
        } catch {
          // The sealed cleanup receipt carries the failed ordinal without error text.
        }
      }
      const ownerCleanupReceipt = await closeOwners();
      finalReceipt = buildResourceCleanupReceiptV1({
        resourceCount: resources.length,
        ...cellState(),
        ownerKinds,
        ownerCleanupReceipt,
      });
      return finalReceipt;
    },
    verifyComplete() {
      if (finalReceipt === null) fail("resource_cleanup_not_completed");
      return finalReceipt;
    },
  });
}

function caseMapForPlan(plan, casesValue) {
  if (!Array.isArray(casesValue) || casesValue.length !== 3) fail("case_count_invalid");
  const map = new Map();
  for (const value of casesValue) {
    const pilotCase = verifyPilotCaseV1(value);
    if (map.has(pilotCase.case_id)) fail("case_duplicate");
    map.set(pilotCase.case_id, pilotCase);
  }
  if (plan.cases.some((ref) => {
    const pilotCase = map.get(ref.case_id);
    return pilotCase === undefined || pilotCase.case_sha256 !== ref.case_sha256;
  })) fail("case_plan_binding_invalid");
  return map;
}

function abortFailureClass(stage) {
  if (stage === "provider") return "provider_or_network";
  if (stage === "verifier") return "verifier_infrastructure";
  if (stage === "runtime_settlement") return "runtime_infrastructure";
  if (stage === "final_signer") return "signature_infrastructure";
  if (stage === "resource_cleanup") return "resource_cleanup_infrastructure";
  if (stage === "eval_provenance") return "provenance_invalid";
  if (stage === "ledger" || stage === "final_manifest_persist") {
    return "filesystem_infrastructure";
  }
  return "harness_infrastructure";
}

function abortFailureEvidenceRef({
  cleanupReceipt,
  executionAuthorization,
  failureClass,
  failureStage,
  ledgerSnapshot,
  plan,
}) {
  return canonicalSha256({
    schema_version: "aionis_pilot_redacted_abort_failure_evidence_ref_v1",
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    execution_authorization_sha256:
      executionAuthorization.execution_authorization_sha256,
    failure_stage: failureStage,
    failure_class: failureClass,
    pre_abort_event_chain_head_sha256: ledgerSnapshot.event_chain_head_sha256,
    completed_cell_count: ledgerSnapshot.completed_cell_count,
    next_attempt_ordinal: ledgerSnapshot.next_attempt_ordinal,
    active_attempt_ordinal: ledgerSnapshot.active_attempt_ordinal,
    cleanup_receipt_sha256: cleanupReceipt.cleanup_receipt_sha256,
    redaction_policy: "error_text_argv_environment_and_credentials_excluded_v1",
  });
}

function abortedRunResult(plan, results, abortClosure, abortManifest) {
  const resultBody = canonicalClone({
    schema_version: "aionis_executable_pilot_aborted_result_v1",
    status: "aborted",
    outcome: "aborted_inconclusive",
    claim_eligible: false,
    resumable: false,
    plan_sha256: plan.plan_sha256,
    completed_cell_result_sha256s:
      results.map((result) => result.cell_result_sha256),
    failure_stage: abortClosure.failure_stage,
    failure_class: abortClosure.failure_class,
    run_abort: abortClosure,
    abort_manifest: abortManifest,
  });
  return canonicalClone({
    ...resultBody,
    result_sha256: canonicalSha256(resultBody),
  });
}

async function executePilot(input, transport, cancellationAuthorityValue) {
  const cancellationAuthority = assertReleasePilotCancellationAuthorityV1(
    cancellationAuthorityValue,
  );
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  const plan = verifyPilotPlanV1(input.plan);
  const apiKey = assertDeepSeekApiKeyV1(input.apiKey);
  if (typeof transport.fetchImpl !== "function"
    || typeof transport.providerClock !== "function"
    || typeof transport.disposeOwners !== "function"
    || typeof transport.verifyEvalProvenance !== "function"
    || typeof transport.runAbortSignerProcess !== "function"
    || typeof transport.runFinalSignerProcess !== "function") {
    fail("provider_transport_invalid");
  }
  const executionAuthorization = verifySignedRunnerExecutionAuthorizationV1(
    input.executionAuthorization,
    {
      plan,
      executionManifest: input.executionManifest,
      fixedLedgerAuthorityRoot: input.authorityRoot,
      publicKey: input.runnerPublicKey,
    },
  );
  if (canonicalJson(executionAuthorization.runner_transport_authority)
      !== canonicalJson(transport.authority)) {
    fail("runner_transport_authority_mismatch");
  }
  if (!Array.isArray(input.cellResources)
    || input.cellResources.length !== plan.schedule.length) fail("cell_resource_count_invalid");
  const casesById = caseMapForPlan(plan, input.cases);
  const liveExecutionManifest = await transport.preflightExecutionManifest({
    authority: input.executionManifest.runner_authority,
    cases: input.cases,
    plan,
  });
  if (canonicalJson(liveExecutionManifest) !== canonicalJson(input.executionManifest)) {
    fail("execution_manifest_live_mismatch");
  }
  const resources = plan.schedule.map((cell, index) => verifyResource(
    input.cellResources[index],
    cell,
  ));
  for (const [index, resource] of resources.entries()) {
    const authority = input.executionManifest.runner_authority.cell_authorities[index];
    if (canonicalJson(resource.executionAuthority)
        !== canonicalJson(authority.agent_execution_authority)
      || canonicalJson(resource.ociRuntimeAuthority)
        !== canonicalJson(input.executionManifest.runner_authority.oci_runtime_authority)) {
      fail("cell_resource_authority_mismatch");
    }
  }
  const orderedCases = plan.cases.map((ref) => casesById.get(ref.case_id));
  const verifierPublicKeys = orderedCases.map((pilotCase) => {
    const resource = resources.find((candidate, index) =>
      plan.schedule[index].case_id === pilotCase.case_id);
    return resource.verifierPublicKey;
  });
  const resourceCloser = buildResourceCloser(
    resources,
    transport.disposeOwners,
    transport.cleanupOwnerKinds,
  );
  let ledger = null;
  let currentCell = null;
  let currentStage = "ledger";
  const results = [];
  try {
    currentStage = "eval_provenance";
    await transport.verifyEvalProvenance();
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    currentStage = "ledger";
    ledger = await beginPilotRunLedgerV1({
      authorityRoot: input.authorityRoot,
      executionAuthorization: input.executionAuthorization,
      executionManifest: input.executionManifest,
      plan,
      runnerPublicKey: input.runnerPublicKey,
    }, transport.finalManifestPersistenceTestAuthority ?? null);
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    const provider = createDeepSeekProviderV1({
      apiKey,
      attemptAuthority: ledger,
      clock: transport.providerClock,
      fetchImpl: transport.fetchImpl,
      modelProtocol: plan.model_protocol,
      pilotId: plan.pilot_id,
    }, cancellationAuthority);

    for (const [index, cell] of plan.schedule.entries()) {
      currentCell = cell;
      currentStage = "cell_preparation";
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const resource = resources[index];
      const pilotCase = casesById.get(cell.case_id);
      const prepared = await resource.adapter.prepareArm();
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const modelInput = buildAgentModelInputV1({ pilotCase, preparedArm: prepared });
      await ledger.recordCellPreparation({
        cell,
        pilotCase,
        preparedArm: prepared,
        agentModelInput: modelInput,
      });
      currentStage = "provider";
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const providerResult = await provider.executeScoredRequest({
        cell,
        messages: modelInput.messages,
      });
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      currentStage = "provider_completion";
      await ledger.completeProviderAttempt({
        assistantMessage: providerResult.assistant_message,
        cell,
        messages: modelInput.messages,
        requestReceipt: providerResult.request_receipt,
        responseReceipt: providerResult.response_receipt,
      });
      checkpointReleasePilotCancellationV1(cancellationAuthority);

      let agentReceipt = null;
      let verifierEvidence = null;
      let failure = null;
      let ledgerProjection = treatmentLedger(prepared, null, "open", null);
      if (providerResult.outcome === "inconclusive") {
        failure = buildPilotInfrastructureFailureV1({
          failure_class: "provider_or_network",
          stage: "provider",
          observed_at: providerResult.response_receipt.response_received_at,
          evidence_ref_sha256: providerResult.response_receipt.response_receipt_sha256,
        });
      } else {
        currentStage = "agent_execution";
        try {
          agentReceipt = await executeAgentActionV1({
            cell,
            pilotCase,
            executionAuthority: resource.executionAuthority,
            assistantContent: providerResult.assistant_message.content,
            providerResponseReceiptSha256:
              providerResult.response_receipt.response_receipt_sha256,
          });
          checkpointReleasePilotCancellationV1(cancellationAuthority);
        } catch {
          checkpointReleasePilotCancellationV1(cancellationAuthority);
          failure = infrastructureFailure(
            cell,
            "agent_execution",
            "harness_infrastructure",
            providerResult.response_receipt.response_received_at,
          );
        }

        if (agentReceipt !== null) {
          currentStage = "verifier";
          try {
            const binding = buildOciPrivateVerifierBindingV1({
              cell,
              cellExecutionRef: cellExecutionRef(cell, prepared),
              pilotCase,
            });
            verifierEvidence = await resource.runVerifier({
              schema_version: "aionis_oci_private_verifier_process_input_v1",
              binding,
              agent_exit_receipt: agentReceipt,
              workspace: { path: resource.executionAuthority.workspace_path },
              verifier_config: resource.verifierConfig,
              runtime_authority: resource.ociRuntimeAuthority,
            });
            checkpointReleasePilotCancellationV1(cancellationAuthority);
          } catch {
            checkpointReleasePilotCancellationV1(cancellationAuthority);
            failure = infrastructureFailure(
              cell,
              "verifier",
              "verifier_infrastructure",
              agentReceipt.exited_at,
            );
          }
        }

        if (cell.arm === "treatment" && verifierEvidence !== null) {
          currentStage = "runtime_settlement";
          try {
            const settled = await resource.adapter.settleTreatment(prepared, {
              useObservedAt: agentReceipt.started_at,
              outcomeObservedAt: nowAfter(verifierEvidence.temporal_fence.verifier_started_at),
              verifierEvidence,
            });
            ledgerProjection = treatmentLedger(
              prepared,
              settled.runtime.settlement,
              "closed",
              verifierEvidence,
            );
            checkpointReleasePilotCancellationV1(cancellationAuthority);
          } catch {
            checkpointReleasePilotCancellationV1(cancellationAuthority);
            failure = infrastructureFailure(
              cell,
              "runtime_settlement",
              "harness_infrastructure",
              verifierEvidence.temporal_fence.verifier_started_at,
            );
          }
        }
      }

      currentStage = "cell_result";
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      const result = buildPilotCellResultV1({
        cell,
        observation_body_sha256: prepared.observation_body_sha256,
        runtime_context: prepared.model_context,
        runtime_observation: prepared.runtime?.observation ?? null,
        agent_model_input: modelInput,
        assistant_message: providerResult.assistant_message,
        provider_request_receipt: providerResult.request_receipt,
        provider_response_receipt: providerResult.response_receipt,
        agent_exit_receipt: agentReceipt,
        verifier_evidence: verifierEvidence,
        infrastructure_failure: failure,
        treatment_ledger: ledgerProjection,
      }, {
        plan,
        pilotCase,
        verifierPublicKey: resource.verifierPublicKey,
      });
      currentStage = "resource_cleanup";
      await resourceCloser.close(index);
      checkpointReleasePilotCancellationV1(cancellationAuthority);
      currentStage = "cell_result";
      await ledger.recordCellResult({
        cellResult: result,
        pilotCase,
        verifierPublicKey: resource.verifierPublicKey,
      });
      results.push(result);
      currentCell = null;
      checkpointReleasePilotCancellationV1(cancellationAuthority);
    }

    currentStage = "resource_cleanup";
    const cleanupReceipt = await resourceCloser.complete();
    if (!cleanupReceipt.cleanup_confirmed) fail("resource_cleanup_unconfirmed");
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    currentStage = "ledger";
    await ledger.recordResourceCleanup({ cleanupReceipt });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    currentStage = "scoring";
    const verdict = scorePilotV1({ plan, cellResults: results }, {
      pilotCases: orderedCases,
      verifierPublicKeys,
    });
    currentStage = "verdict";
    await ledger.recordVerdict({
      verdict,
      pilotCases: orderedCases,
      verifierPublicKeys,
    });
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    currentStage = "run_close";
    const runClosure = await ledger.closeRun();
    // Give a SIGINT/SIGTERM delivered during the close fsync a turn before a
    // claim-capable signer is started.
    await yieldToPendingSignalHandlers();
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    currentStage = "eval_provenance";
    await transport.verifyEvalProvenance();
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    currentStage = "final_signer";
    const finalManifest = await transport.runFinalSignerProcess({
      authorityRoot: input.authorityRoot,
      cases: orderedCases,
      executionManifest: input.executionManifest,
      plan,
      runnerPublicKey: input.runnerPublicKey,
      verifierPublicKeys,
    });
    // A signal delivered while the signer replayed must downgrade the run
    // before the final manifest can be persisted.
    await yieldToPendingSignalHandlers();
    checkpointReleasePilotCancellationV1(cancellationAuthority);
    currentStage = "final_manifest_persist";
    await ledger.persistFinalManifest(finalManifest, cancellationAuthority);
    return canonicalClone({
      schema_version: "aionis_executable_pilot_run_result_v1",
      plan_sha256: plan.plan_sha256,
      cell_results: results,
      verdict,
      run_closure: runClosure,
      final_manifest: finalManifest,
      result_sha256: canonicalSha256({
        plan_sha256: plan.plan_sha256,
        cell_result_sha256s: results.map((result) => result.cell_result_sha256),
        verdict_sha256: verdict.verdict_sha256,
        final_manifest_sha256: finalManifest.final_manifest_sha256,
      }),
    });
  } catch (runError) {
    const cleanupReceipt = await resourceCloser.complete();
    if (ledger === null) {
      fail("pilot_failed_before_ledger_authority");
    }
    const ledgerSnapshot = ledger.snapshot();
    const provenanceFailure = runError instanceof Error
      && runError.message.includes("release_repository_provenance");
    const failureStage = provenanceFailure ? "eval_provenance" : currentStage;
    const failureClass = abortFailureClass(failureStage);
    const failureEvidenceRefSha256 = abortFailureEvidenceRef({
      cleanupReceipt,
      executionAuthorization,
      failureClass,
      failureStage,
      ledgerSnapshot,
      plan,
    });
    let abortClosure;
    try {
      abortClosure = await ledger.abortRun({
        cleanupReceipt,
        failingCell: currentCell,
        failureClass,
        failureEvidenceRefSha256,
        failureStage,
      });
    } catch (abortEventError) {
      void runError;
      void abortEventError;
      fail("run_abort_event_persist_failed");
    }
    let abortManifest;
    try {
      abortManifest = await transport.runAbortSignerProcess({
        authorityRoot: input.authorityRoot,
        cases: orderedCases,
        executionManifest: input.executionManifest,
        plan,
        runnerPublicKey: input.runnerPublicKey,
        verifierPublicKeys,
      });
      await ledger.persistAbortManifest(abortManifest);
    } catch (abortSealError) {
      throw new AggregateError(
        [runError, abortSealError],
        "aionis_eval_executable_pilot_runner_run_abort_manifest_seal_failed",
      );
    }
    return abortedRunResult(plan, results, abortClosure, abortManifest);
  }
}

export async function runExecutablePilotWithCancellationV1(
  options,
  cancellationAuthority,
) {
  const input = expectExactRecord(
    options,
    FORMAL_RUNNER_OPTION_KEYS,
    "executable_pilot_runner_options",
  );
  assertReleasePilotCancellationAuthorityV1(cancellationAuthority);
  checkpointReleasePilotCancellationV1(cancellationAuthority);
  // This happens before release-resource claim so an unsafe credential can
  // neither start a Runtime nor consume a one-shot authority handle.
  const apiKey = readDeepSeekApiKeyFdV1(input.apiKeyFd);
  assertExistingRunnerSigningKeyFdV1(input.runnerSigningKeyFd);
  if (typeof PLATFORM_FETCH_V1 !== "function") fail("platform_fetch_unavailable");
  await verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1({
    plan: input.plan,
    provenanceAuthority: input.evalProvenanceAuthority,
  });
  const claimed = claimReleaseCellResourceAuthorityV1({
    cellResourceAuthority: input.cellResourceAuthority,
    plan: input.plan,
  });
  if (canonicalJson(claimed.executionManifest)
      !== canonicalJson(input.executionManifest)) {
    await claimed.disposeAll();
    fail("release_resource_manifest_mismatch");
  }
  try {
    return await executePilot({ ...input, apiKey, cellResources: claimed.resources }, {
      authority: RELEASE_RUNNER_TRANSPORT_AUTHORITY_V1,
      cleanupOwnerKinds: RELEASE_CLEANUP_OWNER_KINDS_V1,
      disposeOwners: claimed.disposeAll,
      fetchImpl: PLATFORM_FETCH_V1,
      preflightExecutionManifest: preflightPilotExecutionManifestV1,
      providerClock: platformProviderClockV1,
      verifyEvalProvenance: () =>
        verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1({
          plan: input.plan,
          provenanceAuthority: input.evalProvenanceAuthority,
        }),
      runAbortSignerProcess: (signerInput) => runSealedPilotAbortSignerProcessV1({
        ...signerInput,
        runnerSigningKeyFd: input.runnerSigningKeyFd,
      }),
      runFinalSignerProcess: (signerInput) => runSealedPilotFinalSignerProcessV1({
        ...signerInput,
        runnerSigningKeyFd: input.runnerSigningKeyFd,
      }),
      finalManifestPersistenceTestAuthority: null,
    }, cancellationAuthority);
  } catch (error) {
    await claimed.disposeAll();
    throw error;
  } finally {
    claimed.verifyDisposed();
  }
}

export async function runExecutablePilotV1(options) {
  return runExecutablePilotWithCancellationV1(
    options,
    createReleasePilotCancellationAuthorityV1(),
  );
}

export async function runNonReleaseContractTestExecutablePilotV1(
  options,
  cancellationAuthority = createReleasePilotCancellationAuthorityV1(),
  finalManifestPersistenceTestAuthority = null,
) {
  const input = expectExactRecord(
    options,
    NON_RELEASE_CONTRACT_TEST_RUNNER_OPTION_KEYS,
    "non_release_contract_test_executable_pilot_runner_options",
  );
  const cellResources = resolveNonReleaseContractTestCellResourcesV1(
    input.cellResourceAuthority,
    { executionManifest: input.executionManifest, plan: input.plan },
  );
  return executePilot({ ...input, cellResources }, {
    authority: NON_RELEASE_CONTRACT_TEST_RUNNER_TRANSPORT_AUTHORITY_V1,
    cleanupOwnerKinds: [],
    disposeOwners: async () => buildOwnerCleanupReceiptV1({
      ownerKinds: [],
      closedOwnerKinds: [],
      failedOwnerKinds: [],
    }),
    fetchImpl: input.fetchImpl,
    preflightExecutionManifest:
      preflightNonReleaseContractTestPilotExecutionManifestV1,
    providerClock: input.providerClock,
    verifyEvalProvenance: async () => true,
    runAbortSignerProcess: (signerInput) =>
      runNonReleaseContractTestSealedPilotAbortSignerProcessV1({
        ...signerInput,
        nonReleaseContractTestRunnerPrivateKey:
          input.nonReleaseContractTestRunnerPrivateKey,
      }),
    runFinalSignerProcess: (signerInput) =>
      runNonReleaseContractTestSealedPilotFinalSignerProcessV1({
        ...signerInput,
        nonReleaseContractTestRunnerPrivateKey:
          input.nonReleaseContractTestRunnerPrivateKey,
      }),
    finalManifestPersistenceTestAuthority,
  }, cancellationAuthority);
}
