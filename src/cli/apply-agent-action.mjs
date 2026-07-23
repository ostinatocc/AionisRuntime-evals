#!/usr/bin/env node

import { spawnSync } from "node:child_process";

import { decodeAgentActionV1, agentActionSha256V1 } from "../agent-action.mjs";
import { canonicalJson, expectExactRecord } from "../canonical.mjs";

function finish(value, status = 0) {
  process.stdout.write(`${canonicalJson(value)}\n`);
  process.exit(status);
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 1_048_576) throw new Error("aionis_eval_agent_executor_input_too_large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

try {
  const gitExecutable = process.argv[2];
  if (process.argv.length !== 3 || typeof gitExecutable !== "string"
    || !gitExecutable.startsWith("/")) {
    throw new Error("aionis_eval_agent_executor_git_authority_invalid");
  }
  const envelope = expectExactRecord(
    JSON.parse(await readStdin()),
    ["assistant_content"],
    "agent_executor_input",
  );
  const action = decodeAgentActionV1(envelope.assistant_content);
  const actionSha256 = agentActionSha256V1(action);
  if (action.action.kind === "no_safe_change") {
    finish({
      schema_version: "aionis_pilot_agent_executor_result_v1",
      status: "no_safe_change",
      action_sha256: actionSha256,
    });
  }
  const check = spawnSync(gitExecutable, [
    "apply", "--check", "--whitespace=error-all", "-",
  ], {
    cwd: process.cwd(),
    input: action.action.patch,
    encoding: "utf8",
    maxBuffer: 1_048_576,
    timeout: 25_000,
    killSignal: "SIGKILL",
  });
  if (check.status !== 0 || check.signal !== null || check.error !== undefined) {
    process.stderr.write(check.stderr ?? check.error?.message ?? "git apply --check failed\n");
    finish({
      schema_version: "aionis_pilot_agent_executor_result_v1",
      status: "patch_rejected",
      action_sha256: actionSha256,
    }, 65);
  }
  const applied = spawnSync(gitExecutable, ["apply", "--whitespace=error-all", "-"], {
    cwd: process.cwd(),
    input: action.action.patch,
    encoding: "utf8",
    maxBuffer: 1_048_576,
    timeout: 25_000,
    killSignal: "SIGKILL",
  });
  if (applied.status !== 0 || applied.signal !== null || applied.error !== undefined) {
    process.stderr.write(applied.stderr ?? applied.error?.message ?? "git apply failed\n");
    finish({
      schema_version: "aionis_pilot_agent_executor_result_v1",
      status: "patch_rejected",
      action_sha256: actionSha256,
    }, 65);
  }
  finish({
    schema_version: "aionis_pilot_agent_executor_result_v1",
    status: "applied",
    action_sha256: actionSha256,
  });
} catch (error) {
  const code = typeof error?.message === "string" && error.message.startsWith("aionis_eval_")
    ? error.message
    : "aionis_eval_agent_executor_invalid_response";
  finish({
    schema_version: "aionis_pilot_agent_executor_result_v1",
    status: "response_rejected",
    error_code: code,
  }, 64);
}
