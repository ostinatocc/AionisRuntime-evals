import { spawn } from "node:child_process";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assistantContentSha256V1,
} from "./agent-action.mjs";
import {
  canonicalClone,
  canonicalSha256,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { verifyPilotCaseV1, verifyPilotCellV1 } from "./pilot-contract.mjs";
import { captureWorkspaceEvidenceV1 } from "./workspace-evidence.mjs";
import { gitExecutableIdentitySha256V1 } from
  "./release-eval-repository-provenance.mjs";

const executorPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "cli",
  "apply-agent-action.mjs",
);
const EXECUTOR_TIMEOUT_MS = 30_000;

function fail(code) {
  throw new Error(`aionis_eval_agent_execution_${code}`);
}

function now(clock) {
  const value = clock();
  const timestamp = value instanceof Date ? value.toISOString() : value;
  return expectCanonicalTimestamp(timestamp, "agent_execution_clock");
}

function collectChild(child, input) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= 1_048_576) stdout.push(chunk);
      else child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= 1_048_576) stderr.push(chunk);
      else child.kill("SIGKILL");
    });
    child.once("error", reject);
    child.once("close", (exitCode, signal) => resolve({
      exitCode,
      signal,
      stdout: Buffer.concat(stdout),
      stderr: Buffer.concat(stderr),
      outputOverflow: stdoutBytes > 1_048_576 || stderrBytes > 1_048_576,
    }));
    child.stdin.end(input);
  });
}

function verifyWorkspaceIdentity(value, field) {
  const identity = expectExactRecord(value, [
    "device_id", "inode", "realpath_sha256",
  ], field);
  for (const name of ["device_id", "inode"]) {
    if (typeof identity[name] !== "string" || !/^\d+$/u.test(identity[name])) {
      fail(`${field}_${name}_invalid`);
    }
  }
  expectSha256(identity.realpath_sha256, `${field}_realpath_sha256`);
  return identity;
}

function pilotCaseForCell(pilotCaseValue, cell) {
  const pilotCase = verifyPilotCaseV1(pilotCaseValue);
  if (pilotCase.case_id !== cell.case_id
    || pilotCase.case_sha256 !== cell.case_sha256) {
    fail("execution_authority_case_binding_invalid");
  }
  return pilotCase;
}

function allowedTargetPath(pilotCase) {
  const value = pilotCase.episode_1_evidence.prior_verified_state
    .signed_evidence.verified_source_relative_path;
  const segments = value.split("/");
  if (Buffer.byteLength(value, "utf8") < 1
    || Buffer.byteLength(value, "utf8") > 4_096
    || path.posix.isAbsolute(value)
    || path.posix.normalize(value) !== value
    || !/^[A-Za-z0-9._/-]+$/u.test(value)
    || segments.some((segment) => segment === "" || segment === "."
      || segment === ".." || segment.toLowerCase() === ".git")) {
    fail("execution_authority_allowed_target_path_invalid");
  }
  return value;
}

function verifyExecutionAuthorityRecord(value, cell, pilotCaseValue = null) {
  const authority = expectExactRecord(value, [
    "allowed_target_path", "authority_sha256", "case_sha256", "cell_sha256",
    "executor_entry_sha256", "git_executable_path",
    "git_executable_identity_sha256", "git_executable_sha256", "schema_version",
    "workspace_identity",
    "workspace_instance_id", "workspace_path", "workspace_prepared_inode_set_sha256",
    "workspace_prepared_sha256",
  ], "agent_execution_authority");
  if (authority.schema_version !== "aionis_pilot_agent_execution_authority_v2"
    || authority.workspace_instance_id !== cell.isolation.workspace_instance_id
    || authority.case_sha256 !== cell.case_sha256
    || authority.cell_sha256 !== canonicalSha256(cell)
    || !path.isAbsolute(authority.workspace_path)
    || path.normalize(authority.workspace_path) !== authority.workspace_path
    || !path.isAbsolute(authority.git_executable_path)
    || path.normalize(authority.git_executable_path) !== authority.git_executable_path) {
    fail("execution_authority_binding_invalid");
  }
  verifyWorkspaceIdentity(authority.workspace_identity, "agent_execution_workspace_identity");
  expectText(authority.allowed_target_path, "agent_execution_allowed_target_path");
  if (pilotCaseValue !== null) {
    const pilotCase = pilotCaseForCell(pilotCaseValue, cell);
    if (authority.case_sha256 !== pilotCase.case_sha256
      || authority.allowed_target_path !== allowedTargetPath(pilotCase)) {
      fail("execution_authority_case_binding_invalid");
    }
  }
  for (const field of [
    "authority_sha256", "case_sha256", "cell_sha256", "executor_entry_sha256",
    "git_executable_identity_sha256", "git_executable_sha256",
    "workspace_prepared_inode_set_sha256", "workspace_prepared_sha256",
  ]) expectSha256(authority[field], `agent_execution_${field}`);
  const body = Object.fromEntries(
    Object.entries(authority).filter(([key]) => key !== "authority_sha256"),
  );
  if (canonicalSha256(body) !== authority.authority_sha256) {
    fail("execution_authority_integrity_invalid");
  }
  return authority;
}

export async function buildAgentExecutionAuthorityV1(options) {
  const input = expectExactRecord(options, [
    "cell", "gitExecutablePath", "pilotCase", "workspacePath",
  ], "agent_execution_authority_input");
  const cell = verifyPilotCellV1(input.cell);
  const pilotCase = pilotCaseForCell(input.pilotCase, cell);
  const workspacePath = expectText(input.workspacePath, "workspace_path", {
    maximumBytes: 16_384,
  });
  const gitExecutablePath = expectText(
    input.gitExecutablePath,
    "git_executable_path",
    { maximumBytes: 16_384 },
  );
  let canonicalWorkspacePath;
  let canonicalGitPath;
  let canonicalExecutorPath;
  try {
    canonicalWorkspacePath = await realpath(workspacePath);
    canonicalGitPath = await realpath(gitExecutablePath);
    canonicalExecutorPath = await realpath(executorPath);
  } catch {
    fail("execution_authority_path_missing");
  }
  if (canonicalWorkspacePath !== workspacePath || canonicalGitPath !== gitExecutablePath
    || canonicalExecutorPath !== executorPath) fail("execution_authority_path_alias_forbidden");
  const workspace = await captureWorkspaceEvidenceV1(workspacePath);
  const gitExecutableBytes = await readFile(gitExecutablePath);
  const gitExecutableSha256 = sha256Bytes(gitExecutableBytes);
  const body = canonicalClone({
    schema_version: "aionis_pilot_agent_execution_authority_v2",
    case_sha256: pilotCase.case_sha256,
    cell_sha256: canonicalSha256(cell),
    allowed_target_path: allowedTargetPath(pilotCase),
    workspace_instance_id: cell.isolation.workspace_instance_id,
    workspace_path: workspacePath,
    workspace_identity: workspace.workspace_identity,
    workspace_prepared_inode_set_sha256: workspace.inode_set_sha256,
    workspace_prepared_sha256: workspace.workspace_sha256,
    executor_entry_sha256: sha256Bytes(await readFile(executorPath)),
    git_executable_path: gitExecutablePath,
    git_executable_sha256: gitExecutableSha256,
    git_executable_identity_sha256: gitExecutableIdentitySha256V1({
      gitExecutablePath,
      executableSha256: gitExecutableSha256,
      fileSizeBytes: gitExecutableBytes.length,
    }),
  });
  gitExecutableBytes.fill(0);
  return canonicalClone({ ...body, authority_sha256: canonicalSha256(body) });
}

export async function verifyAgentExecutionAuthorityV1(value, cellValue, pilotCaseValue) {
  const cell = verifyPilotCellV1(cellValue);
  const pilotCase = pilotCaseForCell(pilotCaseValue, cell);
  const authority = verifyExecutionAuthorityRecord(value, cell, pilotCase);
  const actual = await buildAgentExecutionAuthorityV1({
    cell,
    pilotCase,
    workspacePath: authority.workspace_path,
    gitExecutablePath: authority.git_executable_path,
  });
  if (canonicalSha256(actual) !== canonicalSha256(authority)) {
    fail("execution_authority_live_mismatch");
  }
  return canonicalClone(authority);
}

function decodeExecutorResult(stdout) {
  let parsed;
  try { parsed = JSON.parse(stdout.toString("utf8")); } catch { return null; }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || parsed.schema_version !== "aionis_pilot_agent_executor_result_v1"
    || !new Set([
      "applied", "no_safe_change", "patch_rejected", "response_rejected",
    ]).has(parsed.status)) return null;
  if (parsed.action_sha256 !== undefined) expectSha256(
    parsed.action_sha256,
    "agent_executor_action_sha256",
  );
  return parsed;
}

export async function executeAgentActionV1(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail("options_invalid");
  }
  const allowed = new Set([
    "assistantContent", "cell", "clock", "executionAuthority",
    "pilotCase", "providerResponseReceiptSha256",
  ]);
  if (Object.keys(options).some((key) => !allowed.has(key))) fail("options_invalid");
  const cell = verifyPilotCellV1(options.cell);
  const executionAuthority = await verifyAgentExecutionAuthorityV1(
    options.executionAuthority,
    cell,
    options.pilotCase,
  );
  const workspacePath = executionAuthority.workspace_path;
  const assistantContent = expectText(options.assistantContent, "assistant_content", {
    controls: true,
    maximumBytes: 1_048_576,
    trimmed: false,
  });
  const providerResponseReceiptSha256 = expectSha256(
    options.providerResponseReceiptSha256,
    "provider_response_receipt_sha256",
  );
  const clock = options.clock ?? (() => new Date());
  if (typeof clock !== "function") fail("clock_invalid");
  const before = await captureWorkspaceEvidenceV1(workspacePath);
  if (before.inode_set_sha256 !== executionAuthority.workspace_prepared_inode_set_sha256) {
    fail("execution_workspace_identity_changed");
  }
  const startedAt = now(clock);
  const child = spawn(process.execPath, [
    executorPath,
    executionAuthority.git_executable_path,
    executionAuthority.allowed_target_path,
  ], {
    cwd: workspacePath,
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      PATH: process.env.PATH ?? "",
      HOME: workspacePath,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_OPTIONAL_LOCKS: "0",
    },
    timeout: EXECUTOR_TIMEOUT_MS,
    killSignal: "SIGKILL",
  });
  const osProcessId = child.pid;
  const execution = await collectChild(
    child,
    `${JSON.stringify({ assistant_content: assistantContent })}\n`,
  );
  const exitedAt = now(clock);
  const after = await captureWorkspaceEvidenceV1(workspacePath);
  const executorResult = execution.outputOverflow ? null : decodeExecutorResult(execution.stdout);
  const executionStatus = executorResult?.status ?? "executor_crashed";
  const decodedActionSha256 = executorResult?.action_sha256 ?? null;
  const trace = {
    schema_version: "aionis_pilot_agent_action_trace_v1",
    provider_response_receipt_sha256: providerResponseReceiptSha256,
    assistant_content_sha256: assistantContentSha256V1(assistantContent),
    decoded_action_sha256: decodedActionSha256,
    executor_status: executionStatus,
    executor_exit_code: execution.exitCode,
    executor_signal: execution.signal,
    workspace_before_sha256: before.workspace_sha256,
    workspace_after_sha256: after.workspace_sha256,
  };
  const body = canonicalClone({
    schema_version: "aionis_pilot_agent_exit_receipt_v1",
    cell_ref: {
      pilot_id: cell.pilot_id,
      opaque_cell_id: cell.opaque_cell_id,
      case_id: cell.case_id,
      case_sha256: cell.case_sha256,
      arm: cell.arm,
      isolation_sha256: cell.isolation.isolation_sha256,
    },
    agent_process_id: cell.isolation.agent_process_id,
    agent_exit_authority_principal_sha256:
      cell.isolation.agent_exit_authority_principal_sha256,
    execution_authority: executionAuthority,
    os_process_id: osProcessId,
    fresh_process: true,
    started_at: startedAt,
    exited_at: exitedAt,
    exit_code: execution.exitCode,
    signal: execution.signal,
    execution_status: executionStatus,
    provider_response_receipt_sha256: providerResponseReceiptSha256,
    assistant_content_sha256: trace.assistant_content_sha256,
    decoded_action_sha256: decodedActionSha256,
    workspace_before_sha256: before.workspace_sha256,
    workspace_after_sha256: after.workspace_sha256,
    stdout_sha256: sha256Bytes(execution.stdout),
    stderr_sha256: sha256Bytes(execution.stderr),
    action_trace_sha256: canonicalSha256(trace),
  });
  return canonicalClone({
    ...body,
    agent_exit_receipt_sha256: canonicalSha256(body),
  });
}

export function verifyAgentExitReceiptV1(value, cellValue) {
  const cell = verifyPilotCellV1(cellValue);
  const receipt = expectExactRecord(value, [
    "action_trace_sha256", "agent_exit_authority_principal_sha256",
    "agent_exit_receipt_sha256", "agent_process_id", "assistant_content_sha256",
    "cell_ref", "decoded_action_sha256", "execution_authority", "execution_status",
    "exit_code", "exited_at",
    "fresh_process", "os_process_id", "provider_response_receipt_sha256", "schema_version",
    "signal", "started_at", "stderr_sha256", "stdout_sha256", "workspace_after_sha256",
    "workspace_before_sha256",
  ], "agent_exit_receipt");
  const cellRef = expectExactRecord(receipt.cell_ref, [
    "arm", "case_id", "case_sha256", "isolation_sha256", "opaque_cell_id", "pilot_id",
  ], "agent_exit_cell_ref");
  verifyExecutionAuthorityRecord(receipt.execution_authority, cell);
  if (receipt.schema_version !== "aionis_pilot_agent_exit_receipt_v1"
    || receipt.fresh_process !== true
    || receipt.agent_process_id !== cell.isolation.agent_process_id
    || receipt.agent_exit_authority_principal_sha256
      !== cell.isolation.agent_exit_authority_principal_sha256
    || cellRef.pilot_id !== cell.pilot_id
    || cellRef.opaque_cell_id !== cell.opaque_cell_id
    || cellRef.case_id !== cell.case_id
    || cellRef.case_sha256 !== cell.case_sha256
    || cellRef.arm !== cell.arm
    || cellRef.isolation_sha256 !== cell.isolation.isolation_sha256) {
    fail("receipt_binding_invalid");
  }
  expectCanonicalTimestamp(receipt.started_at, "agent_exit_started_at");
  expectCanonicalTimestamp(receipt.exited_at, "agent_exit_exited_at");
  if (Date.parse(receipt.exited_at) < Date.parse(receipt.started_at)
    || !Number.isSafeInteger(receipt.os_process_id) || receipt.os_process_id < 1
    || !new Set([
      "applied", "no_safe_change", "patch_rejected", "response_rejected", "executor_crashed",
    ]).has(receipt.execution_status)) fail("receipt_execution_invalid");
  if (receipt.exit_code !== null
    && (!Number.isSafeInteger(receipt.exit_code) || receipt.exit_code < 0
      || receipt.exit_code > 255)) fail("receipt_exit_code_invalid");
  if (receipt.signal !== null) expectText(receipt.signal, "agent_exit_signal");
  for (const field of [
    "action_trace_sha256", "agent_exit_authority_principal_sha256",
    "agent_exit_receipt_sha256", "assistant_content_sha256",
    "provider_response_receipt_sha256", "stderr_sha256", "stdout_sha256",
    "workspace_after_sha256", "workspace_before_sha256",
  ]) expectSha256(receipt[field], `agent_exit_${field}`);
  if (receipt.decoded_action_sha256 !== null) {
    expectSha256(receipt.decoded_action_sha256, "agent_exit_decoded_action_sha256");
  }
  if (new Set(["applied", "no_safe_change"]).has(receipt.execution_status)) {
    if (receipt.exit_code !== 0 || receipt.signal !== null
      || receipt.decoded_action_sha256 === null) fail("receipt_success_contradiction");
  } else if (new Set(["patch_rejected", "response_rejected"])
    .has(receipt.execution_status)
    && (receipt.exit_code === 0 || receipt.signal !== null)) {
    fail("receipt_rejection_contradiction");
  }
  if (new Set(["no_safe_change", "patch_rejected", "response_rejected"])
    .has(receipt.execution_status)
    && receipt.workspace_before_sha256 !== receipt.workspace_after_sha256) {
    fail("receipt_rejected_workspace_mutation");
  }
  const body = Object.fromEntries(
    Object.entries(receipt).filter(([key]) => key !== "agent_exit_receipt_sha256"),
  );
  if (canonicalSha256(body) !== receipt.agent_exit_receipt_sha256) {
    fail("receipt_integrity_invalid");
  }
  return canonicalClone(receipt);
}
