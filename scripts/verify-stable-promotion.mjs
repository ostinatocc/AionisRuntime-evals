#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  anonymousArtifactProvenanceFetcher,
  anonymousWorkflowRunFetcher,
  verifyStablePromotion,
  workflowRunFetcherFromEvidenceFile,
} from "../src/stable-promotion.mjs";

const AUTHORITY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const args = { allow_anonymous_workflow_fetch: false };
  const allowed = new Set(["--runtime-root", "--create-root", "--expected-runtime-commit", "--workflow-evidence"]);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--allow-anonymous-workflow-fetch") {
      args.allow_anonymous_workflow_fetch = true;
      continue;
    }
    if (!allowed.has(token)) throw new Error(`unknown argument: ${token}`);
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

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.workflow_evidence && args.allow_anonymous_workflow_fetch) {
    throw new Error("choose --workflow-evidence or --allow-anonymous-workflow-fetch, not both");
  }
  if (!args.workflow_evidence && !args.allow_anonymous_workflow_fetch) {
    throw new Error("--workflow-evidence is required; anonymous lookup requires explicit local-only opt-in");
  }
  const workflowRunFetcher = args.workflow_evidence
    ? workflowRunFetcherFromEvidenceFile(path.resolve(args.workflow_evidence))
    : anonymousWorkflowRunFetcher;
  const artifactProvenanceFetcher = args.workflow_evidence
    ? workflowRunFetcher.artifactProvenanceFetcher
    : anonymousArtifactProvenanceFetcher;
  const result = await verifyStablePromotion({
    runtimeRoot: path.resolve(required(args.runtime_root, "--runtime-root")),
    createRoot: path.resolve(required(args.create_root, "--create-root")),
    expectedRuntimeCommit: required(args.expected_runtime_commit, "--expected-runtime-commit"),
    authorityRoot: AUTHORITY_ROOT,
    releaseLockPath: path.join(AUTHORITY_ROOT, "config/v0.3.12-release-lock.json"),
    workflowRunFetcher,
    artifactProvenanceFetcher,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
