import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  EVAL_SOURCE_CLOSURE_ENCODING_V1,
  captureReleaseEvalRepositoryProvenanceV1,
  verifyReleaseEvalRepositoryCapturePlanBindingV1,
} from "../src/release-eval-repository-provenance.mjs";

const execFileAsync = promisify(execFile);

async function trustedGitExecutable() {
  for (const candidate of ["/usr/bin/git", "/bin/git"]) {
    try {
      await access(candidate, constants.X_OK);
      return await realpath(candidate);
    } catch { /* try the next root-owned system path */ }
  }
  throw new Error("trusted_system_git_not_available");
}

async function git(gitExecutablePath, repositoryRoot, args) {
  return (await execFileAsync(gitExecutablePath, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      HOME: "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
  })).stdout;
}

async function cleanRepositoryFixture(prefix, { large = false } = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), prefix)));
  const gitExecutablePath = await trustedGitExecutable();
  await git(gitExecutablePath, root, ["init", "--quiet"]);
  await git(gitExecutablePath, root, ["config", "user.name", "Aionis Eval"]);
  await git(gitExecutablePath, root, ["config", "user.email", "eval@example.invalid"]);
  await mkdir(path.join(root, "src"), { mode: 0o700 });
  await writeFile(path.join(root, "src", "entry.mjs"), "export const value = 1;\n", {
    mode: 0o600,
  });
  if (large) {
    await writeFile(path.join(root, "src", "large.bin"), Buffer.alloc(16_777_216, 0x61), {
      mode: 0o600,
    });
  }
  await git(gitExecutablePath, root, ["add", "--all"]);
  await git(gitExecutablePath, root, ["commit", "--quiet", "-m", "frozen"]);
  return { gitExecutablePath, root };
}

function planForCapture(capture, overrides = {}) {
  return {
    plan_sha256: "a".repeat(64),
    eval_binding: {
      git_commit_sha: capture.git_commit_sha,
      git_tree_sha: capture.git_tree_sha,
      worktree_clean: true,
      closure_sha256: capture.closure_sha256,
      git_executable_path: capture.git_executable_path,
      git_executable_sha256: capture.git_executable_sha256,
      git_executable_identity_sha256: capture.git_executable_identity_sha256,
      ...overrides,
    },
  };
}

test("release eval provenance captures exact clean commit, tree, source closure, and Git identity",
  async () => {
    const fixture = await cleanRepositoryFixture("aionis-eval-provenance-clean-");
    try {
      const capture = await captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: fixture.gitExecutablePath,
        repositoryRoot: fixture.root,
      });
      assert.equal(capture.schema_version, "aionis_release_eval_repository_capture_v1");
      assert.equal(capture.worktree_clean, true);
      assert.equal(capture.closure_encoding, EVAL_SOURCE_CLOSURE_ENCODING_V1);
      assert.equal(capture.tracked_file_count, 1);
      assert.match(capture.git_commit_sha, /^[0-9a-f]{40}$/u);
      assert.match(capture.git_tree_sha, /^[0-9a-f]{40}$/u);
      assert.match(capture.closure_sha256, /^[0-9a-f]{64}$/u);
      assert.match(capture.source_identity_epoch_sha256, /^[0-9a-f]{64}$/u);
      assert.equal(verifyReleaseEvalRepositoryCapturePlanBindingV1({
        capture,
        configuredGitExecutablePath: fixture.gitExecutablePath,
        plan: planForCapture(capture),
      }), true);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

test("release eval provenance rejects tracked dirt and every untracked path", async () => {
  for (const mutation of [
    async (root) => writeFile(path.join(root, "src", "entry.mjs"), "changed\n"),
    async (root) => writeFile(path.join(root, "src", "untracked.mjs"), "untracked\n"),
  ]) {
    const fixture = await cleanRepositoryFixture("aionis-eval-provenance-dirty-");
    try {
      await mutation(fixture.root);
      await assert.rejects(() => captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: fixture.gitExecutablePath,
        repositoryRoot: fixture.root,
      }), /worktree_dirty|tracked_file_git_blob_mismatch/u);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("filesystem identity epoch detects tracked content changed and restored between gates",
  async () => {
    const fixture = await cleanRepositoryFixture("aionis-eval-provenance-epoch-");
    const tracked = path.join(fixture.root, "src", "entry.mjs");
    try {
      const before = await captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: fixture.gitExecutablePath,
        repositoryRoot: fixture.root,
      });
      const original = await readFile(tracked);
      await writeFile(tracked, "transient replacement\n", { mode: 0o600 });
      await writeFile(tracked, original, { mode: 0o600 });
      original.fill(0);
      const after = await captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: fixture.gitExecutablePath,
        repositoryRoot: fixture.root,
      });
      assert.equal(after.git_commit_sha, before.git_commit_sha);
      assert.equal(after.git_tree_sha, before.git_tree_sha);
      assert.equal(after.closure_sha256, before.closure_sha256);
      assert.notEqual(
        after.source_identity_epoch_sha256,
        before.source_identity_epoch_sha256,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

test("release eval plan binding rejects wrong commit, tree, closure, and Git executable binding",
  async () => {
    const fixture = await cleanRepositoryFixture("aionis-eval-provenance-binding-");
    try {
      const capture = await captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: fixture.gitExecutablePath,
        repositoryRoot: fixture.root,
      });
      for (const overrides of [
        { git_commit_sha: "b".repeat(40) },
        { git_tree_sha: "c".repeat(40) },
        { closure_sha256: "d".repeat(64) },
        { git_executable_sha256: "e".repeat(64) },
        { git_executable_identity_sha256: "f".repeat(64) },
      ]) {
        assert.throws(() => verifyReleaseEvalRepositoryCapturePlanBindingV1({
          capture,
          configuredGitExecutablePath: fixture.gitExecutablePath,
          plan: planForCapture(capture, overrides),
        }), /plan_binding_mismatch/u);
      }
      assert.throws(() => verifyReleaseEvalRepositoryCapturePlanBindingV1({
        capture,
        configuredGitExecutablePath: "/usr/bin/false",
        plan: planForCapture(capture),
      }), /plan_binding_mismatch/u);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

test("caller executable and symlink aliases are rejected before they can impersonate Git",
  async () => {
    const fixture = await cleanRepositoryFixture("aionis-eval-provenance-git-reject-");
    const maliciousDirectory = path.join(fixture.root, "caller-bin");
    const malicious = path.join(maliciousDirectory, "git");
    const marker = path.join(fixture.root, "malicious-executed");
    const alias = path.join(fixture.root, "git-alias");
    try {
      await mkdir(maliciousDirectory, { mode: 0o700 });
      await writeFile(malicious, `#!/bin/sh\ntouch '${marker}'\nexit 0\n`, { mode: 0o700 });
      await chmod(malicious, 0o700);
      await assert.rejects(() => captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: malicious,
        repositoryRoot: fixture.root,
      }), /git_executable_posture_invalid/u);
      await assert.rejects(access(marker), /ENOENT/u);

      await symlink(fixture.gitExecutablePath, alias);
      await assert.rejects(() => captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: alias,
        repositoryRoot: fixture.root,
      }), /git_executable_posture_invalid/u);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

test("concurrent repository mutation cannot cross the two-pass provenance TOCTOU fence",
  async () => {
    const fixture = await cleanRepositoryFixture("aionis-eval-provenance-toctou-", {
      large: true,
    });
    const transient = path.join(fixture.root, "src", "transient-untracked");
    let mutate = true;
    const mutator = (async () => {
      while (mutate) {
        await writeFile(transient, "changed\n", { mode: 0o600 });
        await new Promise((resolve) => setImmediate(resolve));
        await rm(transient, { force: true });
        await new Promise((resolve) => setImmediate(resolve));
      }
    })();
    try {
      await assert.rejects(() => captureReleaseEvalRepositoryProvenanceV1({
        gitExecutablePath: fixture.gitExecutablePath,
        repositoryRoot: fixture.root,
      }), /worktree_dirty|repository_changed/u);
    } finally {
      mutate = false;
      await mutator;
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
