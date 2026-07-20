import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildArtifactManifest } from "../src/build-artifact-manifest.mjs";
import { readJsonFile, validateArtifactBundleManifest } from "../src/contracts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOCK_PATH = path.join(ROOT, "config/v0.3.12-release-lock.json");
const LOCK = readJsonFile(LOCK_PATH).value;
const HARNESS_COMMIT = "a".repeat(40);
const RELEASE_TAG = `soak-v0.3.12-${HARNESS_COMMIT}`;
const ENV = {
  GITHUB_ACTIONS: "true",
  GITHUB_EVENT_NAME: "workflow_dispatch",
  GITHUB_REPOSITORY: "ostinatocc/AionisRuntime-evals",
  GITHUB_SHA: HARNESS_COMMIT,
  GITHUB_RUN_ID: "12345",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_JOB: "paid-preflight",
  AIONIS_EXECUTION_PHASE: "soak",
  AIONIS_PROTECTED_ENVIRONMENT: "bounded-soak",
};

function artifactFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aionis-artifacts-"));
  const bindings = LOCK.artifact_contract.required_kinds.map((kind) => {
    fs.writeFileSync(path.join(root, `${kind}.jsonl`), `${JSON.stringify({ kind, sanitized: true })}\n`);
    return `${kind}=${kind}.jsonl`;
  });
  return { root, bindings };
}

test("artifact builder emits six unique content-addressed entries bound to workflow HEAD", () => {
  const fixture = artifactFixture();
  const manifest = buildArtifactManifest({
    lock: LOCK,
    artifactRoot: fixture.root,
    artifactBindings: fixture.bindings,
    releaseTag: RELEASE_TAG,
    harnessCommit: HARNESS_COMMIT,
    env: ENV,
  });
  assert.equal(manifest.entries.length, 6);
  assert.equal(new Set(manifest.entries.map((entry) => entry.kind)).size, 6);
  assert.equal(manifest.source_workflow.head_sha, manifest.harness_commit);
  assert.doesNotThrow(() => validateArtifactBundleManifest(manifest, LOCK, HARNESS_COMMIT));
  for (const entry of manifest.entries) assert.match(entry.uri, new RegExp(`${entry.kind}-${entry.sha256}\\.jsonl$`));
});

test("artifact builder rejects duplicate/missing kinds, wrong tag, workflow drift, secrets, and symlinks", () => {
  const fixture = artifactFixture();
  assert.throws(() => buildArtifactManifest({
    lock: LOCK,
    artifactRoot: fixture.root,
    artifactBindings: fixture.bindings.slice(1),
    releaseTag: RELEASE_TAG,
    harnessCommit: HARNESS_COMMIT,
    env: ENV,
  }), /artifact kinds must be exactly/);
  assert.throws(() => buildArtifactManifest({
    lock: LOCK,
    artifactRoot: fixture.root,
    artifactBindings: [...fixture.bindings, fixture.bindings[0]],
    releaseTag: RELEASE_TAG,
    harnessCommit: HARNESS_COMMIT,
    env: ENV,
  }), /duplicate artifact kind/);
  assert.throws(() => buildArtifactManifest({
    lock: LOCK,
    artifactRoot: fixture.root,
    artifactBindings: fixture.bindings,
    releaseTag: `soak-v0.3.12-${"b".repeat(40)}`,
    harnessCommit: HARNESS_COMMIT,
    env: ENV,
  }), /release tag must equal/);
  assert.throws(() => buildArtifactManifest({
    lock: LOCK,
    artifactRoot: fixture.root,
    artifactBindings: fixture.bindings,
    releaseTag: RELEASE_TAG,
    harnessCommit: HARNESS_COMMIT,
    env: { ...ENV, GITHUB_SHA: "b".repeat(40) },
  }), /workflow identity/);
  fs.writeFileSync(path.join(fixture.root, "raw_agent_streams.jsonl"), JSON.stringify({ api_key: "generic-value-that-is-long" }));
  assert.throws(() => buildArtifactManifest({
    lock: LOCK,
    artifactRoot: fixture.root,
    artifactBindings: fixture.bindings,
    releaseTag: RELEASE_TAG,
    harnessCommit: HARNESS_COMMIT,
    env: ENV,
  }), /secret-like material/);
  fs.writeFileSync(path.join(fixture.root, "raw_agent_streams.jsonl"), `${JSON.stringify({ sanitized: true })}\n`);
  fs.writeFileSync(path.join(fixture.root, "outside.jsonl"), "sanitized\n");
  fs.unlinkSync(path.join(fixture.root, "worker_state.jsonl"));
  fs.symlinkSync(path.join(fixture.root, "outside.jsonl"), path.join(fixture.root, "worker_state.jsonl"));
  assert.throws(() => buildArtifactManifest({
    lock: LOCK,
    artifactRoot: fixture.root,
    artifactBindings: fixture.bindings,
    releaseTag: RELEASE_TAG,
    harnessCommit: HARNESS_COMMIT,
    env: ENV,
  }), /symlinks/);
});

test("artifact validator rejects duplicate kinds and a hash hidden outside the asset basename", () => {
  const fixture = artifactFixture();
  const manifest = buildArtifactManifest({ lock: LOCK, artifactRoot: fixture.root, artifactBindings: fixture.bindings, releaseTag: RELEASE_TAG, harnessCommit: HARNESS_COMMIT, env: ENV });
  const duplicate = structuredClone(manifest);
  duplicate.entries[1] = structuredClone(duplicate.entries[0]);
  assert.throws(() => validateArtifactBundleManifest(duplicate, LOCK, HARNESS_COMMIT), /entry kinds/);
  const mutableName = structuredClone(manifest);
  mutableName.entries[0].uri = `${LOCK.artifact_contract.release_repository}/releases/download/${RELEASE_TAG}/mutable.jsonl`;
  assert.throws(() => validateArtifactBundleManifest(mutableName, LOCK, HARNESS_COMMIT), /content addressed/);
  const oversized = structuredClone(manifest);
  oversized.entries[0].bytes = 8 * 1024 * 1024 + 1;
  assert.throws(() => validateArtifactBundleManifest(oversized, LOCK, HARNESS_COMMIT), /exceeds 8 MiB/);
});

test("artifact CLI refuses to overwrite an existing manifest", () => {
  const fixture = artifactFixture();
  const output = path.join(fixture.root, "manifest.json");
  const args = [
    path.join(ROOT, "src/build-artifact-manifest.mjs"),
    "--lock", LOCK_PATH,
    "--artifact-root", fixture.root,
    "--release-tag", RELEASE_TAG,
    "--harness-commit", HARNESS_COMMIT,
    "--out", output,
    ...fixture.bindings.flatMap((binding) => ["--artifact", binding]),
  ];
  const first = spawnSync(process.execPath, args, { cwd: ROOT, env: { ...process.env, ...ENV }, encoding: "utf8" });
  assert.equal(first.status, 0, first.stderr);
  const second = spawnSync(process.execPath, args, { cwd: ROOT, env: { ...process.env, ...ENV }, encoding: "utf8" });
  assert.notEqual(second.status, 0);
  assert.match(second.stderr, /already exists/);
});
