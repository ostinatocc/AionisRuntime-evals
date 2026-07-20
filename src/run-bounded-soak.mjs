#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  COMMIT_RE,
  EVAL_REPOSITORY_SLUG,
  PAID_EXECUTION_ACK,
  PROTECTED_ENVIRONMENT,
  buildTrialPlan,
  readJsonFile,
  sha256,
  validateFrozenContracts,
} from "./contracts.mjs";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const mode = argv[0];
  const args = { mode, execute: false };
  const valueOptions = new Set(["--lock", "--authority", "--workload", "--harness-commit", "--approval"]);
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--execute") {
      args.execute = true;
      continue;
    }
    if (!valueOptions.has(token)) throw new Error(`unknown argument: ${token}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${token} requires a value`);
    args[token.slice(2).replaceAll("-", "_")] = value;
    index += 1;
  }
  return args;
}

function required(value, field) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field} is required`);
  return value;
}

function requireExactEnvironment(env, key, expected) {
  if (env[key] !== expected) throw new Error(`${key} must equal the frozen value`);
}

function repositoryFile(value, field) {
  const absolute = path.resolve(REPOSITORY_ROOT, required(value, field));
  const relative = path.relative(REPOSITORY_ROOT, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error(`${field} must stay inside the authority repository`);
  let current = REPOSITORY_ROOT;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    if (fs.lstatSync(current).isSymbolicLink()) throw new Error(`${field} path must not contain symlinks`);
  }
  return absolute;
}

export function authorizePaidExecution({ mode, args, env, lock, repositoryHead }) {
  if (mode !== "pilot" && mode !== "soak") throw new Error("paid execution is valid only for pilot or soak");
  if (args.approval !== PAID_EXECUTION_ACK) throw new Error("explicit paid-execution approval is missing");
  const harnessCommit = required(args.harness_commit, "--harness-commit");
  if (!COMMIT_RE.test(harnessCommit)) throw new Error("--harness-commit must be an immutable 40-character commit");
  requireExactEnvironment(env, "CI", "true");
  requireExactEnvironment(env, "GITHUB_ACTIONS", "true");
  requireExactEnvironment(env, "GITHUB_EVENT_NAME", "workflow_dispatch");
  requireExactEnvironment(env, "GITHUB_REPOSITORY", EVAL_REPOSITORY_SLUG);
  requireExactEnvironment(env, "GITHUB_SHA", harnessCommit);
  if (repositoryHead !== harnessCommit) throw new Error("checked-out authority HEAD must equal the harness commit");
  requireExactEnvironment(env, "AIONIS_PROTECTED_ENVIRONMENT", PROTECTED_ENVIRONMENT);
  requireExactEnvironment(env, "AIONIS_PAID_EXECUTION_APPROVED", "true");
  requireExactEnvironment(env, "AIONIS_CANDIDATE_COMMIT", lock.candidate.commit);
  requireExactEnvironment(env, "AIONIS_CANDIDATE_DIGEST", lock.candidate.digest);
  requireExactEnvironment(env, "AIONIS_AGENT_MODEL", lock.providers.agent.requested_model);
  requireExactEnvironment(env, "AIONIS_EMBEDDING_MODEL", lock.providers.embedding.model);
  requireExactEnvironment(env, "AIONIS_MAX_CHAT_CALLS", String(lock.execution_limits.maximum_chat_calls));
  requireExactEnvironment(env, "AIONIS_MAX_COST_USD", String(lock.execution_limits.maximum_cost_usd));
  requireExactEnvironment(
    env,
    "AIONIS_PHASE_CHAT_CALLS",
    String(mode === "pilot" ? lock.execution_limits.pilot_chat_calls : lock.execution_limits.soak_chat_calls),
  );
  if (!/^\d+$/.test(env.GITHUB_RUN_ID ?? "") || !/^\d+$/.test(env.GITHUB_RUN_ATTEMPT ?? "")) {
    throw new Error("GitHub run identity is required");
  }
  return { harnessCommit, runId: Number(env.GITHUB_RUN_ID), runAttempt: Number(env.GITHUB_RUN_ATTEMPT) };
}

function checkedOutHead() {
  const result = spawnSync("git", ["rev-parse", "HEAD^{commit}"], { cwd: REPOSITORY_ROOT, encoding: "utf8" });
  if (result.status !== 0) throw new Error("authority repository HEAD is unavailable");
  return result.stdout.trim();
}

export function evaluateRunner({ args, env = process.env, repositoryHead = null }) {
  if (!["validate", "pilot", "soak"].includes(args.mode)) throw new Error("mode must be validate, pilot, or soak");
  if (process.versions.node.split(".")[0] !== "24") throw new Error("Node.js 24 is required");
  const lockDocument = readJsonFile(repositoryFile(args.lock, "--lock"), "release lock");
  const authorityDocument = readJsonFile(repositoryFile(args.authority, "--authority"), "authority manifest");
  const workloadDocument = readJsonFile(repositoryFile(args.workload, "--workload"), "workload manifest");
  const { value: lock } = lockDocument;
  const { value: authority } = authorityDocument;
  const { value: workload } = workloadDocument;
  validateFrozenContracts({ lock, authority, workload });
  if (sha256(authorityDocument.source) !== lock.protocol_artifacts.authority_manifest.sha256) {
    throw new Error("authority manifest raw hash does not match the release lock");
  }
  if (sha256(workloadDocument.source) !== lock.protocol_artifacts.workload_manifest.sha256) {
    throw new Error("workload manifest raw hash does not match the release lock");
  }
  if (args.mode === "validate") {
    if (args.execute) throw new Error("validate mode never accepts --execute");
    return { ok: true, mode: "validate", candidate: lock.candidate, providers: lock.providers, limits: lock.execution_limits };
  }
  const plan = buildTrialPlan(args.mode, workload);
  if (!args.execute) {
    return { ok: true, mode: args.mode, execution: false, planned_chat_calls: plan.length };
  }
  const authorization = authorizePaidExecution({
    mode: args.mode,
    args,
    env,
    lock,
    repositoryHead: repositoryHead ?? checkedOutHead(),
  });
  throw new Error(
    `PAID_EXECUTOR_UNAVAILABLE: ${args.mode} preflight passed for run ${authorization.runId}; `
    + "this scaffold intentionally contains no provider executor",
  );
}

function main() {
  try {
    const result = evaluateRunner({ args: parseArgs(process.argv.slice(2)) });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) main();
