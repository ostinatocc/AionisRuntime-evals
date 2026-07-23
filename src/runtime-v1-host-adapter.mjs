import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import {
  decodeCreateContinuationResponseV1,
  decodeFullDecisionResponseV1,
  decodeRecordObservationsResponseV1,
  decodeRecordOutcomeResponseV1,
} from "./runtime-v1-response.mjs";
import { verifyPilotCaseV1, verifyPilotCellV1 } from "./pilot-contract.mjs";
import {
  verifierPublicKeyPrincipalSha256V1,
  verifySignedVerifierEvidenceV1,
} from "./verifier-evidence.mjs";

const ARMS = new Set(["baseline", "observe_only", "treatment"]);
const CLIENT_METHODS = Object.freeze([
  "createContinuation",
  "decideAuthority",
  "readDecision",
  "recordObservations",
  "recordOutcome",
]);

function fail(code) {
  throw new Error(`aionis_eval_runtime_adapter_${code}`);
}

function verifyClient(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("client_invalid");
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...CLIENT_METHODS].sort())
    || CLIENT_METHODS.some((method) => typeof value[method] !== "function")) {
    fail("client_surface_invalid");
  }
  return value;
}

export function pilotCellOperationIdsV1(cellValue) {
  const cell = verifyPilotCellV1(cellValue);
  const suffix = cell.isolation.isolation_sha256;
  return canonicalClone({
    observation: `pilot-observe-${suffix}`,
    continuation: `pilot-continue-${suffix}`,
    outcome: `pilot-outcome-${suffix}`,
    use: `pilot-use-${suffix}`,
  });
}

function operationProjection(decoded) {
  const response = decoded.response;
  return canonicalClone({
    operation_id: response.operation_receipt.operation_id,
    scope: response.operation_receipt.scope,
    operation_receipt: response.operation_receipt,
    operation_receipt_sha256: response.operation_receipt_sha256,
    operation_request_sha256: response.operation_receipt.request_sha256,
  });
}

function treatmentProjection(decoded, continuationBodySha256) {
  return canonicalClone({
    ...operationProjection(decoded),
    request_body_sha256: continuationBodySha256,
    decision_id: decoded.identity.decision_id,
    episode_id: decoded.identity.episode_id,
    contract_sha256: decoded.contract.contract_sha256,
    coverage_certificate_sha256: decoded.coverage.certificate_sha256,
    exposure_event_sha256: decoded.exposureReceipt.event_sha256,
    render_result_sha256: decoded.render.render_result_sha256,
    render_content_sha256: sha256Bytes(Buffer.from(decoded.render.content, "utf8")),
    projection_sha256: decoded.render.projection_sha256,
    render_status: decoded.render.status,
    coverage_status: decoded.coverage.status,
    safe_fallback_mode: decoded.contract.safe_fallback.mode,
    selected_capsules: decoded.selectedCapsules,
    serving_mode: decoded.authority.serving_mode,
    experiment_cohort_ref: decoded.authority.experiment_cohort_ref,
    serving_assignment_receipt: decoded.authority.serving_assignment_receipt,
  });
}

export function createRuntimeV1HostAdapter(options) {
  const config = expectExactRecord(options, [
    "cell", "client", "pilotCase", "scope", "verifierPublicKey",
  ], "adapter_options");
  const client = verifyClient(config.client);
  const scope = expectText(config.scope, "adapter_scope");
  const cell = verifyPilotCellV1(config.cell);
  const pilotCase = verifyPilotCaseV1(config.pilotCase);
  if (cell.case_id !== pilotCase.case_id
    || cell.case_sha256 !== pilotCase.case_sha256
    || scope !== cell.isolation.runtime_scope
    || !ARMS.has(cell.arm)) fail("cell_case_or_scope_binding_invalid");
  const verifierPublicKey = config.verifierPublicKey;
  const verifierPrincipalSha256 = verifierPublicKeyPrincipalSha256V1(verifierPublicKey);
  if (verifierPrincipalSha256
      !== pilotCase.private_verifier.verifier_public_key_principal_sha256) {
    fail("verifier_public_key_binding_invalid");
  }
  const operationIds = pilotCellOperationIdsV1(cell);

  return Object.freeze({
    async prepareArm(inputValue) {
      if (inputValue !== undefined) fail("prepare_arm_arguments_forbidden");
      const runtimeInput = pilotCase.runtime_input;
      const observationBody = runtimeInput.record_observations_body;
      const observationBodySha256 = canonicalSha256(observationBody);
      if (observationBodySha256 !== runtimeInput.record_observations_body_sha256) {
        fail("case_observation_body_binding_invalid");
      }
      if (cell.arm === "baseline") {
        return canonicalClone({
          schema_version: "aionis_pilot_prepared_arm_v1",
          cell,
          arm: cell.arm,
          observation_body_sha256: observationBodySha256,
          model_context: null,
          runtime: null,
        });
      }

      const observationValue = await client.recordObservations({
        operationId: operationIds.observation,
        scope,
        body: observationBody,
      });
      const observation = decodeRecordObservationsResponseV1(observationValue, {
        operationId: operationIds.observation,
        scope,
      });
      const observationProjection = canonicalClone({
        ...operationProjection(observation),
        request_body_sha256: observationBodySha256,
        world_snapshot_id: observation.snapshotRef.world_snapshot_id,
        world_snapshot_sha256: observation.snapshotRef.world_snapshot_sha256,
        host_task_envelope_sha256: observation.snapshotRef.host_task_envelope_sha256,
      });

      if (cell.arm === "observe_only") {
        return canonicalClone({
          schema_version: "aionis_pilot_prepared_arm_v1",
          cell,
          arm: cell.arm,
          observation_body_sha256: observationBodySha256,
          model_context: null,
          runtime: {
            observation: observationProjection,
            continuation: null,
            settlement: null,
          },
        });
      }

      const continuationBody = canonicalClone({
        schema_version: "create_continuation_body_v1",
        world_snapshot_ref: {
          world_snapshot_id: observation.snapshotRef.world_snapshot_id,
          world_snapshot_sha256: observation.snapshotRef.world_snapshot_sha256,
        },
        obligations: runtimeInput.obligations,
        render_budget_bytes: runtimeInput.render_budget_bytes,
      });
      const continuationBodySha256 = canonicalSha256(continuationBody);
      const continuationValue = await client.createContinuation({
        operationId: operationIds.continuation,
        scope,
        body: continuationBody,
      });
      const continuation = decodeCreateContinuationResponseV1(continuationValue, {
        operationId: operationIds.continuation,
        scope,
      });
      return canonicalClone({
        schema_version: "aionis_pilot_prepared_arm_v1",
        cell,
        arm: cell.arm,
        observation_body_sha256: observationBodySha256,
        model_context: continuation.render.content,
        runtime: {
          observation: observationProjection,
          continuation: treatmentProjection(continuation, continuationBodySha256),
          settlement: null,
        },
      });
    },

    async settleTreatment(preparedValue, settlementValue) {
      const prepared = expectExactRecord(preparedValue, [
        "arm", "cell", "model_context", "observation_body_sha256", "runtime", "schema_version",
      ], "prepared_treatment");
      if (prepared.schema_version !== "aionis_pilot_prepared_arm_v1"
        || prepared.arm !== "treatment" || cell.arm !== "treatment"
        || canonicalJson(prepared.cell) !== canonicalJson(cell)
        || typeof prepared.model_context !== "string") {
        fail("prepared_treatment_invalid");
      }
      const runtime = expectExactRecord(prepared.runtime, [
        "continuation", "observation", "settlement",
      ], "prepared_runtime");
      if (runtime.settlement !== null) fail("treatment_already_settled");
      const continuation = expectExactRecord(runtime.continuation, [
        "contract_sha256",
        "coverage_certificate_sha256",
        "coverage_status",
        "decision_id",
        "episode_id",
        "experiment_cohort_ref",
        "exposure_event_sha256",
        "operation_receipt_sha256",
        "operation_id",
        "operation_receipt",
        "operation_request_sha256",
        "projection_sha256",
        "render_content_sha256",
        "render_result_sha256",
        "render_status",
        "request_body_sha256",
        "safe_fallback_mode",
        "selected_capsules",
        "serving_assignment_receipt",
        "serving_mode",
        "scope",
      ], "prepared_continuation");
      if (continuation.serving_mode !== "authoritative_unassigned"
        || continuation.experiment_cohort_ref !== null
        || continuation.serving_assignment_receipt !== null) {
        fail("pilot_cohort_boundary_violated");
      }

      const settlement = expectExactRecord(settlementValue, [
        "outcomeObservedAt", "useObservedAt", "verifierEvidence",
      ], "settlement_input");
      expectCanonicalTimestamp(settlement.useObservedAt, "settlement_use_observed_at");
      expectCanonicalTimestamp(settlement.outcomeObservedAt, "settlement_outcome_observed_at");
      const verifierEvidence = verifySignedVerifierEvidenceV1(
        settlement.verifierEvidence,
        verifierPublicKey,
      );
      const expectedCellExecutionRef = canonicalClone({
        pilot_id: cell.pilot_id,
        opaque_cell_id: cell.opaque_cell_id,
        arm: cell.arm,
        case_id: cell.case_id,
        case_sha256: cell.case_sha256,
        decision_id: continuation.decision_id,
        contract_sha256: continuation.contract_sha256,
        render_result_sha256: continuation.render_result_sha256,
        exposure_event_sha256: continuation.exposure_event_sha256,
      });
      const expectedVerifierAuthority = canonicalClone({
        verifier_id: pilotCase.private_verifier.verifier_id,
        verifier_image_digest: pilotCase.private_verifier.verifier_image_digest,
        verifier_contract_sha256:
          pilotCase.private_verifier.verifier_contract_sha256,
        verifier_config_sha256: pilotCase.private_verifier.verifier_config_sha256,
        public_key_principal_sha256: verifierPrincipalSha256,
      });
      if (canonicalJson(verifierEvidence.cell_execution_ref)
          !== canonicalJson(expectedCellExecutionRef)
        || canonicalJson(verifierEvidence.verifier_authority_ref)
          !== canonicalJson(expectedVerifierAuthority)
        || verifierEvidence.temporal_fence.agent_exit_authority_principal_sha256
          !== cell.isolation.agent_exit_authority_principal_sha256
        || verifierEvidence.inputs.task_fixture_sha256
          !== pilotCase.source_fixture.fixture_sha256
        || verifierEvidence.inputs.workspace_before_sha256
          !== pilotCase.workspace.prepared_tree_sha256
        || Date.parse(settlement.useObservedAt)
          > Date.parse(verifierEvidence.temporal_fence.agent_exited_at)
        || Date.parse(settlement.outcomeObservedAt)
          < Date.parse(verifierEvidence.temporal_fence.verifier_started_at)) {
        fail("settlement_evidence_binding_invalid");
      }

      const capsuleUses = continuation.selected_capsules.map((selected) => ({
        capsule_scope: scope,
        capsule_id: selected.capsule.capsule_id,
        capsule_revision: selected.capsule.capsule_revision,
        capsule_sha256: selected.capsule.capsule_sha256,
        surface: selected.surface,
        use_state: "unknown",
      }));
      const body = canonicalClone({
        schema_version: "record_outcome_body_v1",
        decision_ref: {
          decision_id: continuation.decision_id,
          contract_sha256: continuation.contract_sha256,
          exposure_receipt_sha256: continuation.exposure_event_sha256,
        },
        use_receipt: {
          schema_version: "host_capsule_use_receipt_v1",
          decision_id: continuation.decision_id,
          use_id: operationIds.use,
          observed_at: settlement.useObservedAt,
          render_result_sha256: continuation.render_result_sha256,
          capsule_uses: capsuleUses,
          evidence_sha256: verifierEvidence.inputs.action_trace_sha256,
        },
        outcome_receipt: {
          schema_version: "host_outcome_receipt_v1",
          decision_id: continuation.decision_id,
          observed_at: settlement.outcomeObservedAt,
          outcome: verifierEvidence.runtime_outcome_mapping.outcome,
          outcome_code: verifierEvidence.runtime_outcome_mapping.outcome_code,
          evidence_sha256: verifierEvidence.evidence_sha256,
          summary: null,
        },
      });
      const outcomeValue = await client.recordOutcome({
        operationId: operationIds.outcome,
        scope,
        body,
      });
      const outcome = decodeRecordOutcomeResponseV1(outcomeValue, {
        operationId: operationIds.outcome,
        scope,
        decisionId: continuation.decision_id,
        useReceipt: body.use_receipt,
        outcomeReceipt: body.outcome_receipt,
      });
      const decisionValue = await client.readDecision({
        decisionId: continuation.decision_id,
        scope,
        view: "full",
        excludeCapsule: null,
        substituteBranch: null,
      });
      const decision = decodeFullDecisionResponseV1(decisionValue, {
        decisionId: continuation.decision_id,
        outcomeOperationId: operationIds.outcome,
        outcome: verifierEvidence.runtime_outcome_mapping.outcome,
      });
      const settlementProjection = canonicalClone({
        record_outcome_operation_id: operationIds.outcome,
        request_body_sha256: canonicalSha256(body),
        operation_request_sha256: outcome.response.operation_receipt.request_sha256,
        operation_receipt_sha256: outcome.response.operation_receipt_sha256,
        use_receipt_sha256: canonicalSha256(body.use_receipt),
        outcome_evidence_sha256: verifierEvidence.evidence_sha256,
        ledger_head_event_sha256: outcome.ledgerHead.event_sha256,
        full_decision_response_sha256: decision.response.response_sha256,
        effect_state: decision.effect.state,
      });
      return canonicalClone({
        ...prepared,
        runtime: {
          ...runtime,
          settlement: settlementProjection,
        },
      });
    },
  });
}
