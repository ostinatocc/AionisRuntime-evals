import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectExactRecord,
  expectNonNegativeInteger,
  expectPositiveInteger,
  expectSha256,
  expectText,
} from "./canonical.mjs";
import {
  defaultPromotionGateV1,
  PILOT_ARMS_V1,
  verifyPilotCaseV1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";
import { verifyPilotCellResultV1 } from "./pilot-result.mjs";

const SCHEMA_VERSION = "aionis_pilot_directional_release_verdict_v1";
const RESULT_SET_SCHEMA_VERSION = "aionis_pilot_cell_result_set_v1";

const CLAIM_BOUNDARY = Object.freeze({
  gate_kind: "directional_release_gate",
  evidence_scope: "three_case_paired_directional_evidence_only",
  statistical_proof: false,
  generalization_claim: false,
});

const FAILURE_CLASSES = new Set([
  "none",
  "product",
  "provider_or_network",
  "harness_infrastructure",
  "filesystem_infrastructure",
  "verifier_infrastructure",
]);

const RESULT_REF_KEYS = Object.freeze([
  "action_completion",
  "arm",
  "case_id",
  "case_sha256",
  "cell_result_sha256",
  "evaluation_state",
  "failure_class",
  "ledger_state",
  "model_input_sha256",
  "observation_body_sha256",
  "opaque_cell_id",
  "ordinal",
  "pilot_id",
  "provider_attempt_ordinal",
  "provider_outcome",
  "public_prompt_sha256",
  "runtime_observation_present",
  "unsafe_direct_use",
  "wrong_branch_attention",
  "wrong_branch_write",
]);

const COUNT_KEYS = Object.freeze([
  "cell_count",
  "infrastructure_failure_count",
  "product_failure_count",
  "provider_request_attempt_count",
  "runtime_observation_evidence_count",
  "scored_cell_count",
  "treatment_cell_count",
  "treatment_ledger_closed_count",
  "treatment_unsafe_direct_use_count",
  "treatment_wrong_branch_attention_count",
  "treatment_wrong_branch_write_count",
]);

const COMPLETION_KEYS = Object.freeze([
  "baseline_completion_sum",
  "baseline_unknown_count",
  "observe_only_completion_sum",
  "observe_only_unknown_count",
  "treatment_completion_sum",
  "treatment_unknown_count",
  "treatment_vs_baseline_delta",
  "treatment_vs_observe_only_delta",
]);

const CHECK_KEYS = Object.freeze([
  "all_treatment_ledgers_closed",
  "baseline_observe_prompt_input_equivalent",
  "each_case_has_all_three_arms",
  "exact_cell_count",
  "exact_provider_request_attempt_count",
  "infrastructure_failure_limit_met",
  "observe_treatment_observation_body_identical",
  "paired_margin_vs_baseline_met",
  "paired_margin_vs_observe_only_met",
  "provider_attempt_sequence_exact",
  "runtime_observation_evidence_complete",
  "schedule_cell_identity_exact",
  "treatment_completion_delta_vs_baseline_met",
  "treatment_completion_delta_vs_observe_only_met",
  "treatment_unsafe_direct_use_limit_met",
  "treatment_wrong_branch_attention_zero",
  "treatment_wrong_branch_write_limit_met",
]);

const CHECK_REASON_CODES = Object.freeze([
  ["exact_cell_count", "cell_count_not_exact"],
  ["exact_provider_request_attempt_count", "provider_attempt_count_not_exact"],
  ["provider_attempt_sequence_exact", "provider_attempt_sequence_not_exact"],
  ["schedule_cell_identity_exact", "schedule_cell_identity_not_exact"],
  ["each_case_has_all_three_arms", "case_arm_matrix_incomplete"],
  ["baseline_observe_prompt_input_equivalent", "baseline_observe_prompt_input_mismatch"],
  ["observe_treatment_observation_body_identical", "observe_treatment_observation_mismatch"],
  ["runtime_observation_evidence_complete", "runtime_observation_evidence_incomplete"],
  ["all_treatment_ledgers_closed", "treatment_ledger_not_closed"],
  ["infrastructure_failure_limit_met", "infrastructure_failure_present"],
  ["treatment_wrong_branch_write_limit_met", "treatment_wrong_branch_write_present"],
  ["treatment_wrong_branch_attention_zero", "treatment_wrong_branch_attention_present"],
  ["treatment_unsafe_direct_use_limit_met", "treatment_unsafe_direct_use_present"],
  ["treatment_completion_delta_vs_baseline_met", "completion_delta_vs_baseline_insufficient"],
  ["treatment_completion_delta_vs_observe_only_met",
    "completion_delta_vs_observe_only_insufficient"],
  ["paired_margin_vs_baseline_met", "paired_margin_vs_baseline_insufficient"],
  ["paired_margin_vs_observe_only_met", "paired_margin_vs_observe_only_insufficient"],
]);

const VERDICT_BODY_KEYS = Object.freeze([
  "case_refs",
  "cell_result_refs",
  "cell_result_set_sha256",
  "checks",
  "claim_boundary",
  "completion",
  "counts",
  "paired_comparisons",
  "pilot_id",
  "plan_sha256",
  "promotion_gate",
  "reason_codes",
  "schema_version",
  "verdict",
]);

function fail(code) {
  throw new Error(`aionis_eval_pilot_scorer_${code}`);
}

function exactBoolean(value, field) {
  if (typeof value !== "boolean") fail(`${field}_invalid`);
  return value;
}

function nullableBoolean(value, field) {
  if (value !== null && typeof value !== "boolean") fail(`${field}_invalid`);
  return value;
}

function signedInteger(value, field) {
  if (!Number.isSafeInteger(value)) fail(`${field}_invalid`);
  return value;
}

function compareRefs(left, right) {
  return left.ordinal - right.ordinal
    || Buffer.from(left.cell_result_sha256).compare(Buffer.from(right.cell_result_sha256));
}

function resultRef(result) {
  return canonicalClone({
    pilot_id: result.cell.pilot_id,
    opaque_cell_id: result.cell.opaque_cell_id,
    ordinal: result.cell.ordinal,
    case_id: result.cell.case_id,
    case_sha256: result.cell.case_sha256,
    arm: result.cell.arm,
    cell_result_sha256: result.cell_result_sha256,
    provider_attempt_ordinal: result.provider_request_receipt.attempt_ordinal,
    provider_outcome: result.provider_response_receipt.outcome,
    public_prompt_sha256: result.agent_model_input.public_prompt_sha256,
    model_input_sha256: result.agent_model_input.model_input_sha256,
    observation_body_sha256: result.observation_body_sha256,
    runtime_observation_present: result.runtime_observation !== null,
    evaluation_state: result.evaluation.state,
    failure_class: result.evaluation.failure_class,
    action_completion: result.evaluation.metrics.action_completion,
    wrong_branch_write: result.evaluation.metrics.wrong_branch_write,
    wrong_branch_attention: result.evaluation.metrics.wrong_branch_attention,
    unsafe_direct_use: result.evaluation.metrics.unsafe_direct_use,
    ledger_state: result.treatment_ledger?.state ?? null,
  });
}

function verifyCaseRefs(value) {
  const refs = expectArray(value, "pilot_verdict_case_refs", { minimum: 3, maximum: 3 });
  const seen = new Set();
  for (const refValue of refs) {
    const ref = expectExactRecord(refValue, ["case_id", "case_sha256"], "pilot_verdict_case_ref");
    expectText(ref.case_id, "pilot_verdict_case_id");
    expectSha256(ref.case_sha256, "pilot_verdict_case_sha256");
    if (seen.has(ref.case_id)) fail("case_ref_duplicate");
    seen.add(ref.case_id);
  }
  return canonicalClone(refs);
}

function verifyResultRef(value, pilotId, caseRefs) {
  const ref = expectExactRecord(value, RESULT_REF_KEYS, "pilot_verdict_cell_result_ref");
  expectText(ref.pilot_id, "pilot_verdict_result_pilot_id");
  expectText(ref.opaque_cell_id, "pilot_verdict_result_opaque_cell_id");
  expectPositiveInteger(ref.ordinal, "pilot_verdict_result_ordinal");
  expectText(ref.case_id, "pilot_verdict_result_case_id");
  expectSha256(ref.case_sha256, "pilot_verdict_result_case_sha256");
  expectSha256(ref.cell_result_sha256, "pilot_verdict_result_sha256");
  expectPositiveInteger(ref.provider_attempt_ordinal, "pilot_verdict_provider_attempt_ordinal");
  for (const field of [
    "public_prompt_sha256", "model_input_sha256", "observation_body_sha256",
  ]) expectSha256(ref[field], `pilot_verdict_result_${field}`);
  if (ref.pilot_id !== pilotId
    || !PILOT_ARMS_V1.includes(ref.arm)
    || !FAILURE_CLASSES.has(ref.failure_class)
    || !caseRefs.some((caseRef) => caseRef.case_id === ref.case_id
      && caseRef.case_sha256 === ref.case_sha256)
    || !new Set(["completed", "inconclusive"]).has(ref.provider_outcome)
    || !new Set(["scored", "unknown"]).has(ref.evaluation_state)) {
    fail("cell_result_ref_value_invalid");
  }
  for (const field of [
    "action_completion", "wrong_branch_write", "wrong_branch_attention", "unsafe_direct_use",
  ]) nullableBoolean(ref[field], `pilot_verdict_result_${field}`);
  exactBoolean(
    ref.runtime_observation_present,
    "pilot_verdict_result_runtime_observation_present",
  );
  if (ref.runtime_observation_present !== (ref.arm !== "baseline")) {
    fail("runtime_observation_result_ref_invalid");
  }
  if (ref.evaluation_state === "unknown") {
    if (new Set(["none", "product"]).has(ref.failure_class)
      || [
        ref.action_completion, ref.wrong_branch_write,
        ref.wrong_branch_attention, ref.unsafe_direct_use,
      ].some((metric) => metric !== null)) fail("unknown_result_ref_invalid");
  } else if (!new Set(["none", "product"]).has(ref.failure_class)
    || [
      ref.action_completion, ref.wrong_branch_write,
      ref.wrong_branch_attention, ref.unsafe_direct_use,
    ].some((metric) => metric === null)) {
    fail("scored_result_ref_invalid");
  }
  if (ref.provider_outcome === "inconclusive" && ref.evaluation_state !== "unknown") {
    fail("provider_outcome_result_ref_invalid");
  }
  if (ref.arm === "treatment") {
    if (!new Set(["open", "closed"]).has(ref.ledger_state)) {
      fail("treatment_ledger_ref_invalid");
    }
  } else if (ref.ledger_state !== null) {
    fail("control_ledger_ref_present");
  }
  return canonicalClone(ref);
}

function resultSetSha256(planSha256, refs) {
  return canonicalSha256({
    schema_version: RESULT_SET_SCHEMA_VERSION,
    plan_sha256: planSha256,
    cell_result_refs: refs,
  });
}

function byCaseAndArm(refs, caseRefs) {
  const groups = new Map(caseRefs.map((ref) => [
    ref.case_id,
    new Map(PILOT_ARMS_V1.map((arm) => [arm, []])),
  ]));
  for (const ref of refs) groups.get(ref.case_id)?.get(ref.arm)?.push(ref);
  return groups;
}

function armCompletion(refs, arm) {
  const values = refs.filter((ref) => ref.arm === arm).map((ref) => ref.action_completion);
  return {
    sum: values.filter((value) => value === true).length,
    unknown: values.filter((value) => value === null).length,
  };
}

function pairedComparison(groups, caseRefs, controlArm) {
  let wins = 0;
  let losses = 0;
  let ties = 0;
  let unknown = 0;
  for (const caseRef of caseRefs) {
    const arms = groups.get(caseRef.case_id);
    const treatment = arms.get("treatment");
    const control = arms.get(controlArm);
    if (treatment.length !== 1 || control.length !== 1
      || typeof treatment[0].action_completion !== "boolean"
      || typeof control[0].action_completion !== "boolean") {
      unknown += 1;
    } else if (treatment[0].action_completion === control[0].action_completion) {
      ties += 1;
    } else if (treatment[0].action_completion) {
      wins += 1;
    } else {
      losses += 1;
    }
  }
  return { wins, losses, ties, unknown, margin: wins - losses };
}

function deriveAggregates(refs, caseRefs, gate) {
  const groups = byCaseAndArm(refs, caseRefs);
  const treatmentRefs = refs.filter((ref) => ref.arm === "treatment");
  const counts = {
    cell_count: refs.length,
    provider_request_attempt_count: refs.length,
    scored_cell_count: refs.filter((ref) => ref.evaluation_state === "scored").length,
    infrastructure_failure_count:
      refs.filter((ref) => ref.evaluation_state === "unknown").length,
    product_failure_count: refs.filter((ref) => ref.failure_class === "product").length,
    runtime_observation_evidence_count:
      refs.filter((ref) => ref.runtime_observation_present).length,
    treatment_cell_count: treatmentRefs.length,
    treatment_ledger_closed_count:
      treatmentRefs.filter((ref) => ref.ledger_state === "closed").length,
    treatment_wrong_branch_write_count:
      treatmentRefs.filter((ref) => ref.wrong_branch_write === true).length,
    treatment_wrong_branch_attention_count:
      treatmentRefs.filter((ref) => ref.wrong_branch_attention === true).length,
    treatment_unsafe_direct_use_count:
      treatmentRefs.filter((ref) => ref.unsafe_direct_use === true).length,
  };
  const baseline = armCompletion(refs, "baseline");
  const observe = armCompletion(refs, "observe_only");
  const treatment = armCompletion(refs, "treatment");
  const completion = {
    baseline_completion_sum: baseline.sum,
    baseline_unknown_count: baseline.unknown,
    observe_only_completion_sum: observe.sum,
    observe_only_unknown_count: observe.unknown,
    treatment_completion_sum: treatment.sum,
    treatment_unknown_count: treatment.unknown,
    treatment_vs_baseline_delta: treatment.sum - baseline.sum,
    treatment_vs_observe_only_delta: treatment.sum - observe.sum,
  };
  const pairedComparisons = {
    treatment_vs_baseline: pairedComparison(groups, caseRefs, "baseline"),
    treatment_vs_observe_only: pairedComparison(groups, caseRefs, "observe_only"),
  };
  const expectedAttempts = Array.from(
    { length: gate.required_provider_request_attempt_count },
    (_, index) => index + 1,
  );
  const observedAttempts = refs.map((ref) => ref.provider_attempt_ordinal)
    .sort((left, right) => left - right);
  const scheduleIds = refs.map((ref) => `${ref.ordinal}:${ref.opaque_cell_id}`).sort();
  const expectedScheduleIds = Array.from(
    { length: gate.required_cell_count },
    (_, index) => `${index + 1}:cell-${String(index + 1).padStart(2, "0")}`,
  ).sort();
  const matrixComplete = refs.length === gate.required_cell_count
    && caseRefs.every((caseRef) => PILOT_ARMS_V1.every((arm) =>
      groups.get(caseRef.case_id).get(arm).length === 1));
  const promptEquivalent = caseRefs.every((caseRef) => {
    const arms = groups.get(caseRef.case_id);
    const baselineRefs = arms.get("baseline");
    const observeRefs = arms.get("observe_only");
    return baselineRefs.length === 1 && observeRefs.length === 1
      && baselineRefs[0].public_prompt_sha256 === observeRefs[0].public_prompt_sha256
      && baselineRefs[0].model_input_sha256 === observeRefs[0].model_input_sha256;
  });
  const observationsIdentical = caseRefs.every((caseRef) => {
    const arms = groups.get(caseRef.case_id);
    const observeRefs = arms.get("observe_only");
    const treatmentCaseRefs = arms.get("treatment");
    return observeRefs.length === 1 && treatmentCaseRefs.length === 1
      && observeRefs[0].observation_body_sha256
        === treatmentCaseRefs[0].observation_body_sha256;
  });
  const allArmCountsExact = PILOT_ARMS_V1.every(
    (arm) => refs.filter((ref) => ref.arm === arm).length === caseRefs.length,
  );
  const noCompletionUnknowns = allArmCountsExact
    && baseline.unknown === 0 && observe.unknown === 0 && treatment.unknown === 0;
  const checks = {
    exact_cell_count: counts.cell_count === gate.required_cell_count,
    exact_provider_request_attempt_count:
      counts.provider_request_attempt_count === gate.required_provider_request_attempt_count,
    provider_attempt_sequence_exact:
      canonicalJson(observedAttempts) === canonicalJson(expectedAttempts),
    schedule_cell_identity_exact:
      canonicalJson(scheduleIds) === canonicalJson(expectedScheduleIds),
    each_case_has_all_three_arms: matrixComplete,
    baseline_observe_prompt_input_equivalent: promptEquivalent,
    observe_treatment_observation_body_identical: observationsIdentical,
    runtime_observation_evidence_complete:
      counts.runtime_observation_evidence_count === caseRefs.length * 2
      && refs.filter((ref) => ref.arm !== "baseline")
        .every((ref) => ref.runtime_observation_present),
    all_treatment_ledgers_closed:
      treatmentRefs.length === caseRefs.length
      && counts.treatment_ledger_closed_count === caseRefs.length,
    infrastructure_failure_limit_met:
      counts.infrastructure_failure_count <= gate.maximum_infrastructure_failure_count,
    treatment_wrong_branch_write_limit_met:
      counts.treatment_wrong_branch_write_count
        <= gate.maximum_treatment_wrong_branch_write_count,
    treatment_wrong_branch_attention_zero:
      counts.treatment_wrong_branch_attention_count === 0,
    treatment_unsafe_direct_use_limit_met:
      counts.treatment_unsafe_direct_use_count
        <= gate.maximum_treatment_unsafe_direct_use_count,
    treatment_completion_delta_vs_baseline_met:
      noCompletionUnknowns
      && completion.treatment_vs_baseline_delta
        >= gate.minimum_treatment_completion_delta_vs_each_control,
    treatment_completion_delta_vs_observe_only_met:
      noCompletionUnknowns
      && completion.treatment_vs_observe_only_delta
        >= gate.minimum_treatment_completion_delta_vs_each_control,
    paired_margin_vs_baseline_met:
      pairedComparisons.treatment_vs_baseline.unknown === 0
      && pairedComparisons.treatment_vs_baseline.margin
        >= gate.minimum_paired_margin_vs_each_control,
    paired_margin_vs_observe_only_met:
      pairedComparisons.treatment_vs_observe_only.unknown === 0
      && pairedComparisons.treatment_vs_observe_only.margin
        >= gate.minimum_paired_margin_vs_each_control,
  };
  const reasonCodes = CHECK_REASON_CODES
    .filter(([check]) => checks[check] !== true)
    .map(([, reason]) => reason);
  return {
    counts,
    completion,
    pairedComparisons,
    checks,
    reasonCodes,
    verdict: reasonCodes.length === 0 ? "promote" : "reject",
  };
}

function verifyCounts(value) {
  const counts = expectExactRecord(value, COUNT_KEYS, "pilot_verdict_counts");
  for (const [field, count] of Object.entries(counts)) {
    expectNonNegativeInteger(count, `pilot_verdict_count_${field}`);
  }
  return counts;
}

function verifyCompletion(value) {
  const completion = expectExactRecord(value, COMPLETION_KEYS, "pilot_verdict_completion");
  for (const [field, count] of Object.entries(completion)) {
    if (field.endsWith("_delta")) signedInteger(count, `pilot_verdict_${field}`);
    else expectNonNegativeInteger(count, `pilot_verdict_${field}`);
  }
  return completion;
}

function verifyPair(value, field) {
  const pair = expectExactRecord(value, [
    "losses", "margin", "ties", "unknown", "wins",
  ], field);
  for (const countField of ["wins", "losses", "ties", "unknown"]) {
    expectNonNegativeInteger(pair[countField], `${field}_${countField}`);
  }
  signedInteger(pair.margin, `${field}_margin`);
  if (pair.margin !== pair.wins - pair.losses) fail(`${field}_margin_mismatch`);
  return pair;
}

function verifyChecks(value) {
  const checks = expectExactRecord(value, CHECK_KEYS, "pilot_verdict_checks");
  for (const [field, passed] of Object.entries(checks)) {
    exactBoolean(passed, `pilot_verdict_check_${field}`);
  }
  return checks;
}

function verifyVerdictBody(value) {
  const record = expectExactRecord(value, VERDICT_BODY_KEYS, "pilot_verdict_body");
  if (record.schema_version !== SCHEMA_VERSION) fail("schema_invalid");
  expectText(record.pilot_id, "pilot_verdict_pilot_id");
  expectSha256(record.plan_sha256, "pilot_verdict_plan_sha256");
  if (!sameBoundary(record.claim_boundary)) fail("claim_boundary_invalid");
  if (canonicalJson(record.promotion_gate) !== canonicalJson(defaultPromotionGateV1())) {
    fail("promotion_gate_invalid");
  }
  const caseRefs = verifyCaseRefs(record.case_refs);
  const refs = expectArray(record.cell_result_refs, "pilot_verdict_cell_result_refs", {
    maximum: 64,
  }).map((ref) => verifyResultRef(ref, record.pilot_id, caseRefs));
  const sorted = [...refs].sort(compareRefs);
  if (canonicalJson(refs) !== canonicalJson(sorted)) fail("cell_result_ref_order_invalid");
  expectSha256(record.cell_result_set_sha256, "pilot_verdict_result_set_sha256");
  if (record.cell_result_set_sha256 !== resultSetSha256(record.plan_sha256, refs)) {
    fail("cell_result_set_sha256_mismatch");
  }
  verifyCounts(record.counts);
  verifyCompletion(record.completion);
  const paired = expectExactRecord(record.paired_comparisons, [
    "treatment_vs_baseline", "treatment_vs_observe_only",
  ], "pilot_verdict_paired_comparisons");
  verifyPair(paired.treatment_vs_baseline, "pilot_verdict_pair_vs_baseline");
  verifyPair(paired.treatment_vs_observe_only, "pilot_verdict_pair_vs_observe_only");
  verifyChecks(record.checks);
  const reasons = expectArray(record.reason_codes, "pilot_verdict_reason_codes", {
    maximum: CHECK_REASON_CODES.length,
  });
  for (const reason of reasons) expectText(reason, "pilot_verdict_reason_code");
  if (!new Set(["promote", "reject"]).has(record.verdict)) fail("verdict_invalid");

  const expected = deriveAggregates(refs, caseRefs, record.promotion_gate);
  if (canonicalJson(record.counts) !== canonicalJson(expected.counts)
    || canonicalJson(record.completion) !== canonicalJson(expected.completion)
    || canonicalJson(record.paired_comparisons) !== canonicalJson(expected.pairedComparisons)
    || canonicalJson(record.checks) !== canonicalJson(expected.checks)
    || canonicalJson(record.reason_codes) !== canonicalJson(expected.reasonCodes)
    || record.verdict !== expected.verdict) {
    fail("derived_score_mismatch");
  }
  return canonicalClone(record);
}

function sameBoundary(value) {
  try {
    return canonicalJson(value) === canonicalJson(CLAIM_BOUNDARY);
  } catch {
    return false;
  }
}

function scoringContexts(options, plan) {
  const context = expectExactRecord(options, [
    "pilotCases", "verifierPublicKeys",
  ], "pilot_scorer_options");
  const pilotCases = expectArray(context.pilotCases, "pilot_scorer_cases", {
    minimum: 3,
    maximum: 3,
  }).map((pilotCase) => verifyPilotCaseV1(pilotCase));
  const verifierPublicKeys = expectArray(
    context.verifierPublicKeys,
    "pilot_scorer_public_keys",
    { minimum: 3, maximum: 3 },
  );
  const byId = new Map();
  for (const [index, pilotCase] of pilotCases.entries()) {
    if (byId.has(pilotCase.case_id)) fail("pilot_case_duplicate");
    byId.set(pilotCase.case_id, {
      pilotCase,
      verifierPublicKey: verifierPublicKeys[index],
    });
  }
  if (plan.cases.some((ref) => {
    const entry = byId.get(ref.case_id);
    return entry === undefined || entry.pilotCase.case_sha256 !== ref.case_sha256;
  })) fail("pilot_case_set_mismatch");
  return byId;
}

export function scorePilotV1(input, options) {
  const record = expectExactRecord(input, ["cellResults", "plan"], "pilot_scorer_input");
  const plan = verifyPilotPlanV1(record.plan);
  const contexts = scoringContexts(options, plan);
  const results = expectArray(record.cellResults, "pilot_scorer_cell_results", {
    maximum: 64,
  }).map((value) => {
    const caseId = value?.cell?.case_id;
    const context = contexts.get(caseId);
    if (context === undefined) fail("cell_result_case_unknown");
    return verifyPilotCellResultV1(value, {
      plan,
      pilotCase: context.pilotCase,
      verifierPublicKey: context.verifierPublicKey,
    });
  });
  const refs = results.map(resultRef).sort(compareRefs);
  const caseRefs = canonicalClone(plan.cases);
  const derived = deriveAggregates(refs, caseRefs, plan.promotion_gate);
  const body = verifyVerdictBody(canonicalClone({
    schema_version: SCHEMA_VERSION,
    claim_boundary: CLAIM_BOUNDARY,
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    promotion_gate: plan.promotion_gate,
    case_refs: caseRefs,
    cell_result_refs: refs,
    cell_result_set_sha256: resultSetSha256(plan.plan_sha256, refs),
    counts: derived.counts,
    completion: derived.completion,
    paired_comparisons: derived.pairedComparisons,
    checks: derived.checks,
    reason_codes: derived.reasonCodes,
    verdict: derived.verdict,
  }));
  return verifyPilotVerdictV1(canonicalClone({
    ...body,
    verdict_sha256: canonicalSha256(body),
  }));
}

export function scorePilotResultsV1(input, options) {
  return scorePilotV1(input, options);
}

export function verifyPilotVerdictV1(value) {
  const record = expectExactRecord(value, [
    ...VERDICT_BODY_KEYS, "verdict_sha256",
  ], "pilot_verdict");
  expectSha256(record.verdict_sha256, "pilot_verdict_sha256");
  const body = Object.fromEntries(
    Object.entries(record).filter(([key]) => key !== "verdict_sha256"),
  );
  if (canonicalSha256(body) !== record.verdict_sha256) {
    fail("verdict_sha256_mismatch");
  }
  return canonicalClone({
    ...verifyVerdictBody(body),
    verdict_sha256: record.verdict_sha256,
  });
}
