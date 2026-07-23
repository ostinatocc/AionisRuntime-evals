import {
  canonicalClone,
  canonicalSha256,
  expectArray,
  expectExactRecord,
} from "./canonical.mjs";
import {
  pilotFixtureSetSha256V1,
  pilotProtocolSha256V1,
  verifyPilotCaseV1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";

function fail(code) {
  throw new Error(`aionis_eval_pilot_preflight_${code}`);
}

export function preflightPilotArtifactsV1(value) {
  const input = expectExactRecord(value, ["cases", "plan"], "pilot_preflight_input");
  const plan = verifyPilotPlanV1(input.plan);
  const cases = expectArray(input.cases, "pilot_preflight_cases", {
    minimum: 3,
    maximum: 3,
  }).map(verifyPilotCaseV1);
  const byId = new Map(cases.map((pilotCase) => [pilotCase.case_id, pilotCase]));
  if (byId.size !== 3) fail("case_id_duplicate");
  const orderedCases = plan.cases.map((ref) => {
    const pilotCase = byId.get(ref.case_id);
    if (!pilotCase || pilotCase.case_sha256 !== ref.case_sha256) {
      fail("case_ref_mismatch");
    }
    return pilotCase;
  });
  if (orderedCases.some((pilotCase) =>
    pilotCase.runtime_input.record_observations_body.host_task.task_family
      !== plan.runtime_binding.task_family)) {
    fail("case_task_family_binding_mismatch");
  }
  if (pilotFixtureSetSha256V1(plan.cases) !== plan.eval_binding.fixture_set_sha256) {
    fail("fixture_set_binding_mismatch");
  }
  const protocolSha256 = pilotProtocolSha256V1({
    claim: plan.claim,
    model_protocol: plan.model_protocol,
    arms: plan.arms,
    promotion_gate: plan.promotion_gate,
  });
  if (protocolSha256 !== plan.eval_binding.protocol_sha256) {
    fail("protocol_binding_mismatch");
  }
  const caseArtifactSetSha256 = canonicalSha256({
    schema_version: "aionis_pilot_case_artifact_set_v1",
    cases: orderedCases,
  });
  return canonicalClone({
    schema_version: "aionis_pilot_preflight_report_v1",
    status: "artifact_verified",
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    protocol_sha256: protocolSha256,
    fixture_set_sha256: plan.eval_binding.fixture_set_sha256,
    case_artifact_set_sha256: caseArtifactSetSha256,
    case_count: orderedCases.length,
    cell_count: plan.schedule.length,
    provider_request_attempt_count: plan.model_protocol.maximum_provider_request_attempt_count,
    cohort_installed: plan.runtime_binding.cohort_installed,
  });
}
