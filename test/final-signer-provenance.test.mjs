import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  chmod,
  cp,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalClone, canonicalSha256 } from "../src/canonical.mjs";
import { runnerAuthorityPublicKeyPrincipalSha256V1 } from "../src/runner-signature.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import {
  TEST_RUNNER_KEYS_V1,
  buildTestExecutionManifestV1,
  buildTestPilotPlanV1,
} from "./support/pilot-plan-fixture.mjs";

const execFileAsync = promisify(execFile);
const sourceRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "src",
);

async function trustedGitExecutable() {
  for (const candidate of ["/usr/bin/git", "/bin/git"]) {
    try {
      await access(candidate, constants.X_OK);
      return await realpath(candidate);
    } catch { /* try next */ }
  }
  throw new Error("trusted_system_git_not_available");
}

async function git(executable, repositoryRoot, args) {
  await execFileAsync(executable, args, {
    cwd: repositoryRoot,
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      HOME: "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
  });
}

async function frozenSignerFixture() {
  const repositoryRoot = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-final-signer-provenance-source-",
  )));
  const authorityRoot = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-final-signer-provenance-authority-",
  )));
  const gitExecutablePath = await trustedGitExecutable();
  await cp(sourceRoot, path.join(repositoryRoot, "src"), {
    recursive: true,
    force: false,
  });
  await git(gitExecutablePath, repositoryRoot, ["init", "--quiet"]);
  await git(gitExecutablePath, repositoryRoot, ["config", "user.name", "Aionis Eval"]);
  await git(
    gitExecutablePath,
    repositoryRoot,
    ["config", "user.email", "eval@example.invalid"],
  );
  await git(gitExecutablePath, repositoryRoot, ["add", "--all"]);
  await git(gitExecutablePath, repositoryRoot, ["commit", "--quiet", "-m", "frozen"]);

  const provenanceModule = await import(pathToFileURL(path.join(
    repositoryRoot,
    "src",
    "release-eval-repository-provenance.mjs",
  )).href);
  const signerModule = await import(pathToFileURL(path.join(
    repositoryRoot,
    "src",
    "final-signer-process.mjs",
  )).href);
  const capture = await provenanceModule.captureReleaseEvalRepositoryProvenanceV1({
    gitExecutablePath,
    repositoryRoot,
  });
  const verifierKeys = Array.from({ length: 3 }, () => generateKeyPairSync("ed25519"));
  const cases = verifierKeys.map((keys, index) => buildTestPilotCaseV1({
    caseId: `signer-provenance-${index + 1}`,
    verifierPrivateKey: keys.privateKey,
    verifierPublicKey: keys.publicKey,
  }));
  const initial = buildTestPilotPlanV1(cases, {
    pilotId: "pilot-final-signer-provenance-test",
  });
  const plan = buildTestPilotPlanV1(cases, {
    pilotId: initial.pilot_id,
    evalBinding: {
      ...initial.eval_binding,
      git_commit_sha: capture.git_commit_sha,
      git_tree_sha: capture.git_tree_sha,
      closure_sha256: capture.closure_sha256,
      git_executable_path: capture.git_executable_path,
      git_executable_sha256: capture.git_executable_sha256,
      git_executable_identity_sha256: capture.git_executable_identity_sha256,
      runner_authority_public_key_principal_sha256:
        runnerAuthorityPublicKeyPrincipalSha256V1(TEST_RUNNER_KEYS_V1.publicKey),
    },
  });
  const lease = await provenanceModule.issueCurrentReleaseEvalRepositoryProvenanceV1({
    configuredGitExecutablePath: gitExecutablePath,
    plan,
  });
  const provenanceReceipt =
    await provenanceModule.verifyCurrentReleaseEvalRepositoryProvenanceLeaseV1({
      plan,
      provenanceAuthority: lease,
    });
  const initialManifest = buildTestExecutionManifestV1(plan);
  const manifestBody = canonicalClone({
    ...Object.fromEntries(Object.entries(initialManifest).filter(
      ([key]) => key !== "manifest_report_sha256",
    )),
    eval_repository_provenance_sha256: provenanceReceipt.provenance_sha256,
    runner_authority: {
      ...initialManifest.runner_authority,
      eval_repository_provenance: provenanceReceipt,
    },
  });
  const executionManifest = canonicalClone({
    ...manifestBody,
    manifest_report_sha256: canonicalSha256(manifestBody),
  });
  const keyPath = path.join(authorityRoot, "runner-key.der");
  await writeFile(keyPath, TEST_RUNNER_KEYS_V1.privateKey.export({
    format: "der",
    type: "pkcs8",
  }), { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const keyHandle = await open(keyPath, "r");
  return {
    authorityRoot,
    cases,
    executionManifest,
    keyHandle,
    plan,
    repositoryRoot,
    signerModule,
    verifierKeys,
  };
}

test("final signer child refuses a claim after tracked or untracked eval source drift", async () => {
  for (const mutate of [
    async (root) => writeFile(
      path.join(root, "src", "cli", "check-source.mjs"),
      "export const tampered = true;\n",
      { mode: 0o600 },
    ),
    async (root) => writeFile(
      path.join(root, "src", "untracked-before-final.mjs"),
      "export const untracked = true;\n",
      { mode: 0o600 },
    ),
    async (root) => {
      const tracked = path.join(root, "src", "cli", "check-source.mjs");
      const original = await readFile(tracked);
      await writeFile(tracked, "export const transient = true;\n", { mode: 0o600 });
      await writeFile(tracked, original, { mode: 0o600 });
      original.fill(0);
    },
  ]) {
    const fixture = await frozenSignerFixture();
    try {
      const authorization =
        await fixture.signerModule.runSealedPilotExecutionAuthorizationSignerProcessV1({
          authorityRoot: fixture.authorityRoot,
          executionManifest: fixture.executionManifest,
          plan: fixture.plan,
          runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
          runnerSigningKeyFd: fixture.keyHandle.fd,
        });
      assert.equal(authorization.claim_eligible, true);

      await mutate(fixture.repositoryRoot);
      await assert.rejects(() =>
        fixture.signerModule.runSealedPilotFinalSignerProcessV1({
          authorityRoot: fixture.authorityRoot,
          cases: fixture.cases,
          executionManifest: fixture.executionManifest,
          plan: fixture.plan,
          runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
          runnerSigningKeyFd: fixture.keyHandle.fd,
          verifierPublicKeys: fixture.verifierKeys.map((keys) => keys.publicKey),
        }), /release_repository_provenance|child_process_failed/u);
      await assert.rejects(
        access(path.join(fixture.authorityRoot, "final-manifest.json")),
        /ENOENT/u,
      );
    } finally {
      await fixture.keyHandle.close();
      await Promise.all([
        rm(fixture.repositoryRoot, { recursive: true, force: true }),
        rm(fixture.authorityRoot, { recursive: true, force: true }),
      ]);
    }
  }
});
