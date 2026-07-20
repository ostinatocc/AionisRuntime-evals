#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  COMMIT_RE,
  EVAL_REPOSITORY_SLUG,
  PUBLISHER_ENVIRONMENT,
  assertNoSecretMaterial,
  readJsonFile,
  sha256,
  validateArtifactBundleManifest,
  validateReleaseLock,
} from "./contracts.mjs";

function parseArgs(argv) {
  const args = { artifacts: [] };
  const values = new Set(["--lock", "--artifact-root", "--artifact", "--release-tag", "--harness-commit", "--out"]);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!values.has(token)) throw new Error(`unknown argument: ${token}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${token} requires a value`);
    if (token === "--artifact") args.artifacts.push(value);
    else args[token.slice(2).replaceAll("-", "_")] = value;
    index += 1;
  }
  return args;
}

function required(value, field) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field} is required`);
  return value;
}

function assertPathInside(root, candidate, field) {
  const relative = path.relative(root, candidate);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${field} must resolve to a file below --artifact-root`);
  }
}

function readSafeArtifact(root, sourcePath, kind) {
  const absolute = path.resolve(root, sourcePath);
  assertPathInside(root, absolute, `artifact ${kind}`);
  let current = root;
  for (const part of path.relative(root, absolute).split(path.sep)) {
    current = path.join(current, part);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error(`artifact ${kind} path must not contain symlinks`);
  }
  const stat = fs.statSync(absolute);
  if (!stat.isFile() || stat.size < 1) throw new Error(`artifact ${kind} must be a non-empty regular file`);
  const source = fs.readFileSync(absolute);
  assertNoSecretMaterial(source, `artifact ${kind}`);
  return { absolute, source };
}

function workflowIdentity(env, harnessCommit) {
  if (env.GITHUB_ACTIONS !== "true" || env.GITHUB_EVENT_NAME !== "workflow_dispatch") {
    throw new Error("artifact manifest generation requires workflow_dispatch GitHub Actions context");
  }
  if (env.GITHUB_REPOSITORY !== EVAL_REPOSITORY_SLUG || env.GITHUB_SHA !== harnessCommit) {
    throw new Error("artifact manifest workflow identity does not match the harness commit");
  }
  if (!/^\d+$/.test(env.GITHUB_RUN_ID ?? "") || !/^\d+$/.test(env.GITHUB_RUN_ATTEMPT ?? "")) {
    throw new Error("artifact manifest requires GitHub run identity");
  }
  if (
    env.AIONIS_EXECUTION_PHASE !== "soak"
    || env.GITHUB_JOB !== "paid-preflight"
    || env.AIONIS_PROTECTED_ENVIRONMENT !== "bounded-soak"
  ) throw new Error("artifact manifest requires the protected soak job");
  return {
    repository: EVAL_REPOSITORY_SLUG,
    run_id: Number(env.GITHUB_RUN_ID),
    run_attempt: Number(env.GITHUB_RUN_ATTEMPT),
    head_sha: harnessCommit,
    phase: "soak",
    job: "paid-preflight",
    environment: "bounded-soak",
  };
}

function publisherIdentity(sourceWorkflow) {
  return {
    repository: EVAL_REPOSITORY_SLUG,
    run_id: sourceWorkflow.run_id,
    run_attempt: sourceWorkflow.run_attempt,
    head_sha: sourceWorkflow.head_sha,
    phase: "publisher",
    job: "evidence-publisher",
    environment: PUBLISHER_ENVIRONMENT,
  };
}

export function buildArtifactManifest({ lock, artifactRoot, artifactBindings, releaseTag, harnessCommit, env }) {
  validateReleaseLock(lock);
  if (!COMMIT_RE.test(harnessCommit)) throw new Error("harness commit must be an immutable 40-character commit");
  const expectedReleaseTag = `soak-v${lock.candidate.version}-${harnessCommit}`;
  if (releaseTag !== expectedReleaseTag) throw new Error(`release tag must equal ${expectedReleaseTag}`);
  const root = fs.realpathSync(artifactRoot);
  const bindings = new Map();
  for (const binding of artifactBindings) {
    const separator = binding.indexOf("=");
    if (separator < 1 || separator === binding.length - 1) throw new Error(`invalid --artifact binding: ${binding}`);
    const kind = binding.slice(0, separator);
    const sourcePath = binding.slice(separator + 1);
    if (bindings.has(kind)) throw new Error(`duplicate artifact kind: ${kind}`);
    bindings.set(kind, sourcePath);
  }
  const expectedKinds = [...lock.artifact_contract.required_kinds].sort();
  const actualKinds = [...bindings.keys()].sort();
  if (JSON.stringify(actualKinds) !== JSON.stringify(expectedKinds)) {
    throw new Error(`artifact kinds must be exactly ${expectedKinds.join(", ")}`);
  }
  const entries = expectedKinds.map((kind) => {
    const { absolute, source } = readSafeArtifact(root, bindings.get(kind), kind);
    const hash = sha256(source);
    const extension = path.extname(absolute).toLowerCase();
    if (extension !== ".jsonl") throw new Error(`artifact ${kind} must use the canonical .jsonl format`);
    const asset = `${kind}-${hash}${extension}`;
    return {
      kind,
      uri: `${lock.artifact_contract.release_repository}/releases/download/${releaseTag}/${asset}`,
      sha256: hash,
      bytes: source.byteLength,
    };
  });
  const sourceWorkflow = workflowIdentity(env, harnessCommit);
  const manifest = {
    schema_version: "aionis_soak_artifact_bundle_manifest_v1",
    generated_at: new Date().toISOString(),
    candidate: { commit: lock.candidate.commit, digest: lock.candidate.digest },
    harness_commit: harnessCommit,
    source_workflow: sourceWorkflow,
    publisher_workflow: publisherIdentity(sourceWorkflow),
    entries,
  };
  validateArtifactBundleManifest(manifest, lock, harnessCommit);
  return manifest;
}

function writeAtomic(outPath, manifest) {
  const absolute = path.resolve(outPath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true, mode: 0o700 });
  if (fs.existsSync(absolute)) throw new Error("artifact manifest output already exists");
  const temporary = `${absolute}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  fs.renameSync(temporary, absolute);
}

function main() {
  try {
    if (process.versions.node.split(".")[0] !== "24") throw new Error("Node.js 24 is required");
    const args = parseArgs(process.argv.slice(2));
    const lock = readJsonFile(path.resolve(required(args.lock, "--lock")), "release lock").value;
    const artifactRoot = path.resolve(required(args.artifact_root, "--artifact-root"));
    const manifest = buildArtifactManifest({
      lock,
      artifactRoot,
      artifactBindings: args.artifacts,
      releaseTag: required(args.release_tag, "--release-tag"),
      harnessCommit: required(args.harness_commit, "--harness-commit"),
      env: process.env,
    });
    writeAtomic(required(args.out, "--out"), manifest);
    process.stdout.write(`${JSON.stringify({ ok: true, output: path.resolve(args.out), sha256: sha256(Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)) })}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) main();
