import { spawn } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  KeyObject,
} from "node:crypto";
import { realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyAgentExitReceiptV1 } from "./agent-execution.mjs";
import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectNonNegativeInteger,
  expectPositiveInteger,
  expectSha256,
  expectText,
} from "./canonical.mjs";
import { verifyPilotCaseV1, verifyPilotCellV1 } from "./pilot-contract.mjs";
import {
  buildSignedVerifierEvidenceV1,
  verifierPublicKeyPrincipalSha256V1,
  verifySignedVerifierEvidenceV1,
} from "./verifier-evidence.mjs";
import { captureWorkspaceEvidenceV1 } from "./workspace-evidence.mjs";

const cliPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "cli",
  "run-private-verifier.mjs",
);

const MAX_CHECK_TIMEOUT_MS = 300_000;
const MAX_TOTAL_TIMEOUT_MS = 300_000;
const MAX_CHECK_OUTPUT_BYTES = 1_048_576;
const MAX_PROCESS_OUTPUT_BYTES = 1_048_576;
const PROCESS_TIMEOUT_GRACE_MS = 10_000;

const CONTRACT = Object.freeze({
  schema_version: "aionis_native_private_verifier_contract_v1",
  command_execution: "argv_without_shell",
  command_working_directory: "bound_workspace",
  execution_authority: "non_release_contract_test_only",
  network_access: "host_inherited_not_restricted",
  private_key_transport: "inherited_fd_3_only",
  process_order: "fresh_process_strictly_after_agent_exit",
  workspace_mutation: "detected_after_checks_not_os_prevented",
  verdict_mapping: "check_exit_and_metric_mapping_v1",
});

export const PRIVATE_VERIFIER_CONTRACT_SHA256_V1 = canonicalSha256(CONTRACT);

const METRIC_KEYS = Object.freeze([
  "accepted_direction",
  "action_completion",
  "rediscovery_steps",
  "unsafe_direct_use",
  "wrong_branch_attention",
  "wrong_branch_write",
]);

function fail(code) {
  throw new Error(`aionis_eval_verifier_process_${code}`);
}

function imageDigest(value, field) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail(`${field}_invalid`);
  }
  return value;
}

function verifyMetricProjection(value, field) {
  const projection = expectExactRecord(value, METRIC_KEYS, field);
  for (const name of METRIC_KEYS.filter((key) => key !== "rediscovery_steps")) {
    if (projection[name] !== null && typeof projection[name] !== "boolean") {
      fail(`${field}_${name}_invalid`);
    }
  }
  if (projection.rediscovery_steps !== null) {
    expectNonNegativeInteger(projection.rediscovery_steps, `${field}_rediscovery_steps`);
  }
  return projection;
}

export function buildPrivateVerifierConfigV1(input) {
  const value = expectExactRecord(input, [
    "checks", "verifierId", "verifierImageDigest",
  ], "private_verifier_config_input");
  return verifyPrivateVerifierConfigV1({
    schema_version: "aionis_private_verifier_config_v1",
    verifier_id: value.verifierId,
    verifier_image_digest: value.verifierImageDigest,
    verifier_contract_sha256: PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
    checks: value.checks,
  });
}

export function verifyPrivateVerifierConfigV1(value) {
  const config = expectExactRecord(value, [
    "checks", "schema_version", "verifier_contract_sha256", "verifier_id",
    "verifier_image_digest",
  ], "private_verifier_config");
  if (config.schema_version !== "aionis_private_verifier_config_v1"
    || config.verifier_contract_sha256 !== PRIVATE_VERIFIER_CONTRACT_SHA256_V1) {
    fail("config_contract_invalid");
  }
  expectText(config.verifier_id, "private_verifier_config_id");
  imageDigest(config.verifier_image_digest, "private_verifier_config_image_digest");
  const checks = expectArray(config.checks, "private_verifier_config_checks", {
    minimum: 1,
    maximum: 32,
  });
  const ids = new Set();
  let totalTimeoutMs = 0;
  for (const [index, checkValue] of checks.entries()) {
    const field = `private_verifier_check_${index}`;
    const check = expectExactRecord(checkValue, [
      "argv", "check_id", "metric_mapping", "output_limit_bytes", "timeout_ms",
    ], field);
    expectText(check.check_id, `${field}_id`);
    if (ids.has(check.check_id)) fail("check_id_duplicate");
    ids.add(check.check_id);
    const argv = expectArray(check.argv, `${field}_argv`, { minimum: 1, maximum: 64 });
    for (const [argumentIndex, argument] of argv.entries()) {
      expectText(argument, `${field}_argv_${argumentIndex}`, {
        maximumBytes: 16_384,
      });
    }
    expectPositiveInteger(check.timeout_ms, `${field}_timeout_ms`);
    if (check.timeout_ms > MAX_CHECK_TIMEOUT_MS) fail(`${field}_timeout_ms_invalid`);
    totalTimeoutMs += check.timeout_ms;
    expectPositiveInteger(check.output_limit_bytes, `${field}_output_limit_bytes`);
    if (check.output_limit_bytes > MAX_CHECK_OUTPUT_BYTES) {
      fail(`${field}_output_limit_bytes_invalid`);
    }
    const mapping = expectExactRecord(check.metric_mapping, [
      "failed", "passed",
    ], `${field}_metric_mapping`);
    verifyMetricProjection(mapping.passed, `${field}_metrics_passed`);
    verifyMetricProjection(mapping.failed, `${field}_metrics_failed`);
  }
  if (totalTimeoutMs > MAX_TOTAL_TIMEOUT_MS) fail("total_timeout_invalid");
  return canonicalClone(config);
}

export function privateVerifierConfigSha256V1(value) {
  return canonicalSha256(verifyPrivateVerifierConfigV1(value));
}

function verifyCellExecutionRef(value, cell) {
  const ref = expectExactRecord(value, [
    "arm", "case_id", "case_sha256", "contract_sha256", "decision_id",
    "exposure_event_sha256", "opaque_cell_id", "pilot_id", "render_result_sha256",
  ], "private_verifier_cell_execution_ref");
  if (ref.pilot_id !== cell.pilot_id
    || ref.opaque_cell_id !== cell.opaque_cell_id
    || ref.case_id !== cell.case_id
    || ref.case_sha256 !== cell.case_sha256
    || ref.arm !== cell.arm) fail("cell_execution_ref_binding_invalid");
  if (cell.arm === "treatment") {
    expectText(ref.decision_id, "private_verifier_decision_id");
    for (const field of [
      "contract_sha256", "exposure_event_sha256", "render_result_sha256",
    ]) expectSha256(ref[field], `private_verifier_${field}`);
  } else if (ref.decision_id !== null
    || ref.contract_sha256 !== null
    || ref.exposure_event_sha256 !== null
    || ref.render_result_sha256 !== null) {
    fail("control_runtime_ref_present");
  }
  return ref;
}

function caseAuthorityFromPilotCase(pilotCase) {
  return canonicalClone({
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    task_fixture_sha256: pilotCase.source_fixture.fixture_sha256,
    private_verifier: pilotCase.private_verifier,
  });
}

export function buildPrivateVerifierBindingV1(input) {
  const value = expectExactRecord(input, [
    "cell", "cellExecutionRef", "pilotCase",
  ], "private_verifier_binding_input");
  const cell = verifyPilotCellV1(value.cell);
  const pilotCase = verifyPilotCaseV1(value.pilotCase);
  if (cell.case_id !== pilotCase.case_id || cell.case_sha256 !== pilotCase.case_sha256) {
    fail("binding_case_mismatch");
  }
  return verifyPrivateVerifierBindingV1({
    schema_version: "aionis_private_verifier_binding_v1",
    cell,
    case_authority: caseAuthorityFromPilotCase(pilotCase),
    cell_execution_ref: value.cellExecutionRef,
  });
}

export function verifyPrivateVerifierBindingV1(value) {
  const binding = expectExactRecord(value, [
    "case_authority", "cell", "cell_execution_ref", "schema_version",
  ], "private_verifier_binding");
  if (binding.schema_version !== "aionis_private_verifier_binding_v1") {
    fail("binding_schema_invalid");
  }
  const cell = verifyPilotCellV1(binding.cell);
  const authority = expectExactRecord(binding.case_authority, [
    "case_id", "case_sha256", "private_verifier", "task_fixture_sha256",
  ], "private_verifier_case_authority");
  if (authority.case_id !== cell.case_id || authority.case_sha256 !== cell.case_sha256) {
    fail("case_authority_binding_invalid");
  }
  expectSha256(authority.task_fixture_sha256, "private_verifier_task_fixture_sha256");
  const verifier = expectExactRecord(authority.private_verifier, [
    "require_after_agent_exit", "require_fresh_process",
    "verifier_config_sha256", "verifier_contract_sha256", "verifier_id",
    "verifier_image_digest", "verifier_public_key_principal_sha256",
  ], "private_verifier_case_authority_ref");
  expectText(verifier.verifier_id, "private_verifier_case_authority_id");
  expectSha256(verifier.verifier_config_sha256, "private_verifier_config_sha256");
  expectSha256(verifier.verifier_contract_sha256, "private_verifier_contract_sha256");
  expectSha256(
    verifier.verifier_public_key_principal_sha256,
    "private_verifier_public_key_principal_sha256",
  );
  imageDigest(verifier.verifier_image_digest, "private_verifier_image_digest");
  if (verifier.require_after_agent_exit !== true || verifier.require_fresh_process !== true
    || verifier.verifier_contract_sha256 !== PRIVATE_VERIFIER_CONTRACT_SHA256_V1) {
    fail("private_verifier_authority_invalid");
  }
  verifyCellExecutionRef(binding.cell_execution_ref, cell);
  return canonicalClone(binding);
}

function verifyWorkspaceInput(value) {
  const workspace = expectExactRecord(value, ["path"], "private_verifier_workspace");
  const workspacePath = expectText(workspace.path, "private_verifier_workspace_path", {
    maximumBytes: 16_384,
  });
  if (!path.isAbsolute(workspacePath) || path.normalize(workspacePath) !== workspacePath) {
    fail("workspace_path_invalid");
  }
  return workspace;
}

export function verifyPrivateVerifierProcessInputV1(value) {
  const input = expectExactRecord(value, [
    "agent_exit_receipt", "binding", "schema_version", "verifier_config", "workspace",
  ], "private_verifier_process_input");
  if (input.schema_version !== "aionis_private_verifier_process_input_v1") {
    fail("input_schema_invalid");
  }
  const binding = verifyPrivateVerifierBindingV1(input.binding);
  const config = verifyPrivateVerifierConfigV1(input.verifier_config);
  const verifier = binding.case_authority.private_verifier;
  if (config.verifier_id !== verifier.verifier_id
    || config.verifier_image_digest !== verifier.verifier_image_digest
    || config.verifier_contract_sha256 !== verifier.verifier_contract_sha256
    || privateVerifierConfigSha256V1(config) !== verifier.verifier_config_sha256) {
    fail("config_authority_binding_invalid");
  }
  const receipt = verifyAgentExitReceiptV1(input.agent_exit_receipt, binding.cell);
  const workspace = verifyWorkspaceInput(input.workspace);
  if (workspace.path !== receipt.execution_authority.workspace_path) {
    fail("workspace_execution_authority_mismatch");
  }
  return canonicalClone({
    ...input,
    binding,
    agent_exit_receipt: receipt,
    verifier_config: config,
  });
}

function sparseEnvironment() {
  return {
    PATH: process.env.PATH ?? "",
    HOME: process.env.HOME ?? "",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
  };
}

function emptyMetrics() {
  return {
    action_completion: null,
    accepted_direction: null,
    wrong_branch_write: null,
    wrong_branch_attention: null,
    unsafe_direct_use: null,
    rediscovery_steps: null,
  };
}

function aggregateMetricProjections(projections) {
  const result = emptyMetrics();
  for (const field of ["action_completion", "accepted_direction"]) {
    const values = projections.map((projection) => projection[field])
      .filter((value) => value !== null);
    result[field] = values.includes(false) ? false : values.includes(true) ? true : null;
  }
  for (const field of [
    "wrong_branch_write", "wrong_branch_attention", "unsafe_direct_use",
  ]) {
    const values = projections.map((projection) => projection[field])
      .filter((value) => value !== null);
    result[field] = values.includes(true) ? true : values.includes(false) ? false : null;
  }
  const rediscovery = projections.map((projection) => projection.rediscovery_steps)
    .filter((value) => value !== null);
  result.rediscovery_steps = rediscovery.length === 0 ? null : Math.max(...rediscovery);
  return canonicalClone(result);
}

function digestingCommand(check, workspacePath) {
  return new Promise((resolve) => {
    const stdoutHash = createHash("sha256");
    const stderrHash = createHash("sha256");
    let outputBytes = 0;
    let overflow = false;
    let timedOut = false;
    let spawnFailed = false;
    let closed = false;
    let child;
    try {
      child = spawn(check.argv[0], check.argv.slice(1), {
        cwd: workspacePath,
        env: sparseEnvironment(),
        shell: false,
        stdio: ["ignore", "pipe", "pipe", "ignore"],
      });
    } catch {
      resolve({
        exitCode: null,
        status: "indeterminate",
        stdoutSha256: stdoutHash.digest("hex"),
        stderrSha256: stderrHash.digest("hex"),
      });
      return;
    }
    const account = (hash, chunk) => {
      hash.update(chunk);
      outputBytes += chunk.length;
      if (outputBytes > check.output_limit_bytes && !overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    };
    child.stdout.on("data", (chunk) => account(stdoutHash, chunk));
    child.stderr.on("data", (chunk) => account(stderrHash, chunk));
    child.once("error", () => {
      spawnFailed = true;
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, check.timeout_ms);
    timer.unref?.();
    child.once("close", (exitCode, signal) => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      const indeterminate = spawnFailed || timedOut || overflow || signal !== null
        || !Number.isSafeInteger(exitCode) || exitCode < 0 || exitCode > 255;
      resolve({
        exitCode: indeterminate ? null : exitCode,
        status: indeterminate ? "indeterminate" : exitCode === 0 ? "passed" : "failed",
        stdoutSha256: stdoutHash.digest("hex"),
        stderrSha256: stderrHash.digest("hex"),
      });
    });
  });
}

async function strictlyPostExitTimestamp(agentExitedAt) {
  for (let attempt = 0; attempt < 250; attempt += 1) {
    const timestamp = new Date().toISOString();
    if (Date.parse(timestamp) > Date.parse(agentExitedAt)) return timestamp;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  fail("agent_exit_temporal_order_invalid");
}

function actionDeltaSha256(agentReceipt) {
  return canonicalSha256({
    schema_version: "aionis_agent_action_delta_binding_v1",
    agent_exit_receipt_sha256: agentReceipt.agent_exit_receipt_sha256,
    action_trace_sha256: agentReceipt.action_trace_sha256,
    decoded_action_sha256: agentReceipt.decoded_action_sha256,
    workspace_before_sha256: agentReceipt.workspace_before_sha256,
    workspace_after_sha256: agentReceipt.workspace_after_sha256,
  });
}

function successfulMetrics(metrics) {
  return metrics.action_completion === true
    && metrics.accepted_direction === true
    && metrics.wrong_branch_write === false
    && metrics.wrong_branch_attention === false
    && metrics.unsafe_direct_use === false;
}

function asPrivateKey(privateKeyInput) {
  try {
    const key = privateKeyInput instanceof KeyObject
      ? privateKeyInput
      : createPrivateKey(privateKeyInput);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      fail("private_key_invalid");
    }
    return key;
  } catch {
    fail("private_key_invalid");
  }
}

export async function executePrivateVerifierChildV1(inputValue, privateKeyInput) {
  if (path.resolve(process.argv[1] ?? "") !== cliPath) {
    fail("child_entrypoint_invalid");
  }
  const input = verifyPrivateVerifierProcessInputV1(inputValue);
  const privateKey = asPrivateKey(privateKeyInput);
  const publicKey = createPublicKey(privateKey);
  const principal = verifierPublicKeyPrincipalSha256V1(publicKey);
  const expectedPrincipal = input.binding.case_authority.private_verifier
    .verifier_public_key_principal_sha256;
  if (principal !== expectedPrincipal) fail("private_key_authority_mismatch");

  const workspacePath = input.workspace.path;
  if (await realpath(workspacePath) !== workspacePath) fail("workspace_realpath_invalid");
  const agentReceipt = input.agent_exit_receipt;
  const verifierStartedAt = await strictlyPostExitTimestamp(agentReceipt.exited_at);
  const workspaceAtStart = await captureWorkspaceEvidenceV1(workspacePath);
  if (workspaceAtStart.workspace_sha256 !== agentReceipt.workspace_after_sha256) {
    fail("workspace_agent_exit_binding_invalid");
  }
  if (canonicalJson(workspaceAtStart.workspace_identity)
      !== canonicalJson(agentReceipt.execution_authority.workspace_identity)) {
    fail("workspace_identity_binding_invalid");
  }
  const runnerReceiptSha256 = canonicalSha256({
    schema_version: "aionis_private_verifier_runner_receipt_v1",
    parent_agent_exit_receipt_sha256: agentReceipt.agent_exit_receipt_sha256,
    verifier_config_sha256: privateVerifierConfigSha256V1(input.verifier_config),
    verifier_process_id: process.pid,
    verifier_started_at: verifierStartedAt,
    workspace_at_start_sha256: workspaceAtStart.workspace_sha256,
  });

  const checks = [];
  const metricProjections = [];
  let infrastructureFailure = false;
  let productFailure = false;
  for (const check of input.verifier_config.checks) {
    const result = await digestingCommand(check, workspacePath);
    checks.push({
      check_id: check.check_id,
      command_argv_sha256: canonicalSha256(check.argv),
      exit_code: result.exitCode,
      stdout_sha256: result.stdoutSha256,
      stderr_sha256: result.stderrSha256,
      status: result.status,
    });
    if (result.status === "indeterminate") {
      infrastructureFailure = true;
    } else {
      if (result.status === "failed") productFailure = true;
      metricProjections.push(check.metric_mapping[result.status]);
    }
  }
  const workspaceAfterChecks = await captureWorkspaceEvidenceV1(workspacePath);
  if (workspaceAfterChecks.workspace_sha256 !== workspaceAtStart.workspace_sha256) {
    fail("verifier_mutated_workspace");
  }

  let metrics = infrastructureFailure
    ? canonicalClone(emptyMetrics())
    : aggregateMetricProjections(metricProjections);
  let verdict;
  let failureClass;
  let outcome;
  let outcomeCode;
  if (infrastructureFailure) {
    verdict = "inconclusive";
    failureClass = "verifier_infrastructure";
    outcome = "unknown";
    outcomeCode = "external_verifier_infrastructure";
  } else if (productFailure) {
    verdict = "failed";
    failureClass = "product";
    outcome = "failed";
    outcomeCode = "external_verifier_rejected";
  } else if (successfulMetrics(metrics)) {
    verdict = "passed";
    failureClass = "none";
    outcome = "succeeded";
    outcomeCode = "external_verifier_passed";
  } else {
    metrics = canonicalClone(metrics);
    verdict = "inconclusive";
    failureClass = "verifier_infrastructure";
    outcome = "unknown";
    outcomeCode = "external_verifier_metric_mapping_incomplete";
  }

  const evidence = buildSignedVerifierEvidenceV1({
    cell_execution_ref: input.binding.cell_execution_ref,
    verifier_authority_ref: {
      verifier_id: input.verifier_config.verifier_id,
      verifier_image_digest: input.verifier_config.verifier_image_digest,
      verifier_contract_sha256: input.verifier_config.verifier_contract_sha256,
      verifier_config_sha256: privateVerifierConfigSha256V1(input.verifier_config),
    },
    temporal_fence: {
      agent_exit_authority_principal_sha256:
        agentReceipt.agent_exit_authority_principal_sha256,
      agent_exit_receipt_sha256: agentReceipt.agent_exit_receipt_sha256,
      agent_exit_sequence: 1,
      agent_exited_at: agentReceipt.exited_at,
      verifier_runner_parent_agent_exit_receipt_sha256:
        agentReceipt.agent_exit_receipt_sha256,
      verifier_runner_receipt_sha256: runnerReceiptSha256,
      verifier_runner_sequence: 2,
      verifier_started_at: verifierStartedAt,
      fresh_process: true,
      after_agent_exit: true,
    },
    inputs: {
      workspace_before_sha256: agentReceipt.workspace_before_sha256,
      workspace_after_sha256: agentReceipt.workspace_after_sha256,
      diff_sha256: actionDeltaSha256(agentReceipt),
      action_trace_sha256: agentReceipt.action_trace_sha256,
      task_fixture_sha256: input.binding.case_authority.task_fixture_sha256,
    },
    checks,
    metrics,
    verdict,
    failure_class: failureClass,
    runtime_outcome_mapping: {
      outcome,
      outcome_code: outcomeCode,
    },
  }, privateKey);
  return verifySignedVerifierEvidenceV1(evidence, publicKey);
}

function collectVerifierProcess(child, inputText, keyBytes) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_PROCESS_OUTPUT_BYTES) stdout.push(chunk);
      else {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_PROCESS_OUTPUT_BYTES) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.once("error", reject);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, MAX_TOTAL_TIMEOUT_MS + PROCESS_TIMEOUT_GRACE_MS);
    timer.unref?.();
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode,
        signal,
        stdout: Buffer.concat(stdout),
        overflow,
        timedOut,
      });
    });
    child.stdin.end(inputText);
    child.stdio[3].end(keyBytes, () => keyBytes.fill(0));
  });
}

export async function runPrivateVerifierProcessV1(options) {
  const value = expectExactRecord(options, [
    "input", "privateKey",
  ], "private_verifier_runner_options");
  const input = verifyPrivateVerifierProcessInputV1(value.input);
  const privateKey = asPrivateKey(value.privateKey);
  const publicKey = createPublicKey(privateKey);
  const principal = verifierPublicKeyPrincipalSha256V1(publicKey);
  if (principal !== input.binding.case_authority.private_verifier
    .verifier_public_key_principal_sha256) fail("private_key_authority_mismatch");
  const keyBytes = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
  const child = spawn(process.execPath, [cliPath], {
    cwd: input.workspace.path,
    env: sparseEnvironment(),
    shell: false,
    stdio: ["pipe", "pipe", "pipe", "pipe"],
  });
  const result = await collectVerifierProcess(
    child,
    `${canonicalJson(input)}\n`,
    keyBytes,
  );
  if (result.exitCode !== 0 || result.signal !== null
    || result.overflow || result.timedOut) fail("child_process_failed");
  let evidence;
  try {
    evidence = JSON.parse(result.stdout.toString("utf8"));
  } catch {
    fail("child_output_invalid");
  }
  const verified = verifySignedVerifierEvidenceV1(evidence, publicKey);
  if (canonicalJson(verified.cell_execution_ref)
      !== canonicalJson(input.binding.cell_execution_ref)
    || verified.temporal_fence.agent_exit_receipt_sha256
      !== input.agent_exit_receipt.agent_exit_receipt_sha256
    || verified.inputs.workspace_before_sha256
      !== input.agent_exit_receipt.workspace_before_sha256
    || verified.inputs.workspace_after_sha256
      !== input.agent_exit_receipt.workspace_after_sha256
    || verified.inputs.action_trace_sha256 !== input.agent_exit_receipt.action_trace_sha256
    || verified.inputs.diff_sha256 !== actionDeltaSha256(input.agent_exit_receipt)
    || verified.inputs.task_fixture_sha256
      !== input.binding.case_authority.task_fixture_sha256) {
    fail("child_evidence_binding_invalid");
  }
  return verified;
}
