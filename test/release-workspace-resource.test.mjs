import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  access,
  chmod,
  link,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalClone, sha256Bytes } from "../src/canonical.mjs";
import { buildPilotCaseV1 } from "../src/pilot-contract.mjs";
import {
  claimReleaseWorkspaceResourceOwnerV1,
  disposeReleaseWorkspaceResourceOwnerV1,
  materializeReleasePilotWorkspacesV1,
} from "../src/release-workspace-resource.mjs";
import {
  RELEASE_WORKSPACE_OWNER_INCOMPLETE_FILE_V1,
  RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1,
} from "../src/release-workspace-owner-manifest.mjs";
import {
  captureWorkspaceEvidenceV1,
  captureWorkspaceInodeSetV1,
} from "../src/workspace-evidence.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

const execFileAsync = promisify(execFile);
const VERIFIER_KEYS = generateKeyPairSync("ed25519");

async function findGitExecutable() {
  for (const directory of (process.env.PATH ?? "").split(path.delimiter)) {
    if (directory === "") continue;
    const candidate = path.join(directory, "git");
    try {
      await access(candidate, constants.X_OK);
      return realpath(candidate);
    } catch { /* try the next PATH entry */ }
  }
  throw new Error("git_executable_not_found_for_release_workspace_test");
}

async function git(gitExecutablePath, cwd, args, options = {}) {
  const result = await execFileAsync(gitExecutablePath, args, {
    cwd,
    encoding: options.encoding ?? "utf8",
    maxBuffer: 1_048_576,
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      LANG: "C",
      LC_ALL: "C",
    },
  });
  return result.stdout;
}

async function writeWorkingTree(root, caseId) {
  const fixture = Buffer.from(`${JSON.stringify({ case_id: caseId, expected: "accepted" })}\n`);
  await mkdir(path.join(root, "fixtures", "v1"), { recursive: true, mode: 0o700 });
  await mkdir(path.join(root, "src"), { mode: 0o700 });
  await writeFile(path.join(root, "README.md"), `# ${caseId}\n`, { mode: 0o600 });
  await writeFile(path.join(root, "src", "program.txt"), `program:${caseId}\n`, {
    mode: 0o600,
  });
  await writeFile(path.join(root, "run.sh"), "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(path.join(root, "fixtures", "v1", `${caseId}.json`), fixture, {
    mode: 0o600,
  });
  return fixture;
}

function rebuildCase(pilotCase, overrides = {}) {
  const body = canonicalClone(pilotCase);
  delete body.schema_version;
  delete body.case_sha256;
  if (overrides.workspace !== undefined) {
    body.workspace = { ...body.workspace, ...overrides.workspace };
    if (overrides.workspace.prepared_tree_sha256 !== undefined) {
      body.public_agent_input.workspace_projection_sha256 =
        overrides.workspace.prepared_tree_sha256;
    }
  }
  if (overrides.source_fixture !== undefined) {
    body.source_fixture = { ...body.source_fixture, ...overrides.source_fixture };
  }
  return buildPilotCaseV1(body);
}

async function buildRealCase(root, gitExecutablePath, caseId) {
  const templatePath = path.join(root, "templates", caseId);
  const projectionPath = path.join(root, "projections", caseId);
  await mkdir(templatePath, { recursive: true, mode: 0o700 });
  await mkdir(projectionPath, { recursive: true, mode: 0o700 });
  const fixture = await writeWorkingTree(templatePath, caseId);
  await writeWorkingTree(projectionPath, caseId);
  await git(gitExecutablePath, templatePath, ["init", "--quiet"]);
  await git(gitExecutablePath, templatePath, ["config", "user.name", "Aionis Eval"]);
  await git(gitExecutablePath, templatePath, ["config", "user.email", "eval@example.invalid"]);
  const repositoryUrl = `https://github.com/aionis-evals/${caseId}.git`;
  await git(gitExecutablePath, templatePath, ["remote", "add", "origin", repositoryUrl]);
  await git(gitExecutablePath, templatePath, ["add", "--all"]);
  await git(gitExecutablePath, templatePath, ["commit", "--quiet", "-m", "frozen fixture"]);
  const baseCommitSha = (await git(
    gitExecutablePath,
    templatePath,
    ["rev-parse", "--verify", "HEAD"],
  )).trim();
  const cleanStatus = await git(
    gitExecutablePath,
    templatePath,
    ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    { encoding: "buffer" },
  );
  const workspaceEvidence = await captureWorkspaceEvidenceV1(await realpath(projectionPath));
  const baseCase = buildTestPilotCaseV1({
    caseId,
    fixtureSha256: sha256Bytes(fixture),
    verifierPublicKey: VERIFIER_KEYS.publicKey,
    workspaceSha256: workspaceEvidence.workspace_sha256,
  });
  const pilotCase = rebuildCase(baseCase, {
    workspace: {
      repository_url: repositoryUrl,
      base_commit_sha: baseCommitSha,
      clean_status_sha256: sha256Bytes(cleanStatus),
    },
  });
  return { fixture, pilotCase, templatePath: await realpath(templatePath) };
}

async function fixture(t, label) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), `aionis-release-${label}-`)));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const privateRunRoot = path.join(root, "private-run-root");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  const gitExecutablePath = await findGitExecutable();
  const built = [];
  for (const caseId of ["case-one", "case-two", "case-three"]) {
    built.push(await buildRealCase(root, gitExecutablePath, caseId));
  }
  const cases = built.map((entry) => entry.pilotCase);
  const workspaceTemplates = Object.fromEntries(
    built.map((entry) => [entry.pilotCase.case_id, entry.templatePath]),
  );
  return {
    built,
    cases,
    gitExecutablePath,
    orchestrationOwnerId: sha256Bytes(`workspace-owner:${label}`).slice(0, 32),
    plan: buildTestPilotPlanV1(cases, { pilotId: `release-workspace-${label}` }),
    privateRunRoot: await realpath(privateRunRoot),
    root,
    workspaceTemplates,
  };
}

function materializerInput(value, overrides = {}) {
  const cases = overrides.cases ?? value.cases;
  return {
    plan: overrides.plan ?? buildTestPilotPlanV1(cases, {
      pilotId: overrides.pilotId ?? value.plan.pilot_id,
    }),
    cases,
    privateRunRoot: value.privateRunRoot,
    workspaceTemplates: value.workspaceTemplates,
    gitExecutablePath: value.gitExecutablePath,
    orchestrationOwnerId: overrides.orchestrationOwnerId
      ?? value.orchestrationOwnerId,
  };
}

async function assertPrivateRunRootEmpty(privateRunRoot) {
  assert.deepEqual(await readdir(privateRunRoot), []);
  assert.equal((await stat(privateRunRoot)).isDirectory(), true);
}

test("release workspace materializer creates nine real isolated workspaces and owns cleanup", async (t) => {
  const value = await fixture(t, "happy");
  const callerOwned = path.join(value.privateRunRoot, "caller-owned.txt");
  await writeFile(callerOwned, "keep\n", { mode: 0o600 });
  const handle = await materializeReleasePilotWorkspacesV1({
    plan: value.plan,
    cases: value.cases,
    privateRunRoot: value.privateRunRoot,
    workspaceTemplates: value.workspaceTemplates,
    gitExecutablePath: value.gitExecutablePath,
    orchestrationOwnerId: value.orchestrationOwnerId,
  });
  assert.equal(Object.getPrototypeOf(handle), null);
  assert.equal("resources" in handle, false);
  assert.equal("closeAll" in handle, false);
  assert.throws(
    () => claimReleaseWorkspaceResourceOwnerV1({
      plan: value.plan,
      workspaceOwner: { ...handle },
    }),
    /owner_brand_invalid/u,
  );
  const materialized = claimReleaseWorkspaceResourceOwnerV1({
    plan: value.plan,
    workspaceOwner: handle,
  });
  assert.throws(
    () => claimReleaseWorkspaceResourceOwnerV1({
      plan: value.plan,
      workspaceOwner: handle,
    }),
    /already_claimed/u,
  );

  assert.equal(materialized.schema_version, "aionis_release_workspace_resources_v1");
  assert.equal(materialized.plan_sha256, value.plan.plan_sha256);
  assert.equal(materialized.resources.length, 9);
  assert.equal(materialized.authorities.length, 9);
  assert.equal(new Set(materialized.resources.map((entry) => entry.workspacePath)).size, 9);
  assert.equal(Number((await stat(materialized.resource_root)).mode & 0o777), 0o700);
  assert.equal(Object.isFrozen(materialized), true);
  assert.equal(Object.isFrozen(materialized.resources), true);
  assert.equal(Object.isFrozen(materialized.resources[0].inodeSet.inode_identifiers), true);
  assert.equal(Object.isFrozen(materialized.authorities[0].workspace_identity), true);

  const allInodes = new Set();
  for (const [index, resource] of materialized.resources.entries()) {
    const pilotCase = value.cases.find((entry) => entry.case_id === resource.cell.case_id);
    assert.equal(resource.cell.opaque_cell_id, value.plan.schedule[index].opaque_cell_id);
    assert.equal(resource.workspaceEvidence.workspace_sha256,
      pilotCase.workspace.prepared_tree_sha256);
    assert.equal(resource.authority.source_fixture_sha256,
      pilotCase.source_fixture.fixture_sha256);
    assert.equal(resource.workspacePath.startsWith(`${materialized.resource_root}${path.sep}`), true);
    assert.equal(await access(path.join(resource.workspacePath, ".git")).then(
      () => false,
      () => true,
    ), true);
    const independentlyCaptured = await captureWorkspaceInodeSetV1(resource.workspacePath);
    assert.deepEqual(independentlyCaptured, resource.inodeSet);
    for (const inode of independentlyCaptured.inode_identifiers) {
      assert.equal(allInodes.has(inode), false);
      allInodes.add(inode);
    }
    assert.equal("inode_identifiers" in resource.authority, false);
    assert.equal(JSON.stringify(resource.authority).includes("inode_identifiers"), false);
  }

  await Promise.all([
    materialized.resources[0].close(),
    materialized.resources[0].close(),
  ]);
  await assert.rejects(() => stat(materialized.resources[0].workspacePath), {
    code: "ENOENT",
  });
  assert.equal((await stat(materialized.resources[1].workspacePath)).isDirectory(), true);
  const manifestPath = path.join(
    value.privateRunRoot,
    RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1,
  );
  await chmod(manifestPath, 0o644);
  await assert.rejects(
    disposeReleaseWorkspaceResourceOwnerV1(handle),
    /manifest_posture_invalid/u,
  );
  assert.equal((await stat(materialized.resource_root)).isDirectory(), true);
  assert.equal((await stat(path.join(
    value.privateRunRoot,
    RELEASE_WORKSPACE_OWNER_INCOMPLETE_FILE_V1,
  ))).mode & 0o777, 0o600);
  await chmod(manifestPath, 0o600);
  await Promise.all([
    materialized.closeAll(),
    materialized.closeAll(),
    disposeReleaseWorkspaceResourceOwnerV1(handle),
  ]);
  await materialized.closeAll();
  await assert.rejects(() => stat(materialized.resource_root), { code: "ENOENT" });
  assert.equal((await stat(value.privateRunRoot)).isDirectory(), true);
  assert.equal((await stat(callerOwned)).isFile(), true);
});

test("release workspace materializer rejects prepared-tree and fixture digest mismatches with cleanup",
  async (t) => {
    const preparedValue = await fixture(t, "prepared-digest");
    const preparedCases = [...preparedValue.cases];
    preparedCases[0] = rebuildCase(preparedCases[0], {
      workspace: { prepared_tree_sha256: "f".repeat(64) },
    });
    await assert.rejects(
      () => materializeReleasePilotWorkspacesV1(materializerInput(preparedValue, {
        cases: preparedCases,
        pilotId: "release-workspace-prepared-digest-mismatch",
      })),
      /aionis_eval_release_workspace_resource_workspace_prepared_tree_sha256_mismatch/u,
    );
    await assertPrivateRunRootEmpty(preparedValue.privateRunRoot);

    const fixtureValue = await fixture(t, "fixture-digest");
    const fixtureCases = [...fixtureValue.cases];
    fixtureCases[0] = rebuildCase(fixtureCases[0], {
      source_fixture: { fixture_sha256: "f".repeat(64) },
    });
    await assert.rejects(
      () => materializeReleasePilotWorkspacesV1(materializerInput(fixtureValue, {
        cases: fixtureCases,
        pilotId: "release-workspace-fixture-digest-mismatch",
      })),
      /aionis_eval_release_workspace_resource_source_fixture_sha256_mismatch/u,
    );
    await assertPrivateRunRootEmpty(fixtureValue.privateRunRoot);
  });

test("release workspace materializer rejects symlinked working-tree entries and cleans partial state",
  async (t) => {
    const value = await fixture(t, "symlink");
    const target = path.join(value.built[0].templatePath, "README.md");
    await symlink(target, path.join(value.built[0].templatePath, "unsafe-link.txt"));
    const status = await git(
      value.gitExecutablePath,
      value.built[0].templatePath,
      ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
      { encoding: "buffer" },
    );
    const cases = [...value.cases];
    cases[0] = rebuildCase(cases[0], {
      workspace: { clean_status_sha256: sha256Bytes(status) },
    });
    await assert.rejects(
      () => materializeReleasePilotWorkspacesV1(materializerInput(value, {
        cases,
        pilotId: "release-workspace-symlink-rejection",
      })),
      /aionis_eval_release_workspace_resource_source_symlink_forbidden/u,
    );
    await assertPrivateRunRootEmpty(value.privateRunRoot);
  });

test("release workspace materializer rejects hardlinked working-tree entries and cleans partial state",
  async (t) => {
    const value = await fixture(t, "hardlink");
    const target = path.join(value.built[0].templatePath, "README.md");
    await link(target, path.join(value.built[0].templatePath, "unsafe-hardlink.txt"));
    const status = await git(
      value.gitExecutablePath,
      value.built[0].templatePath,
      ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
      { encoding: "buffer" },
    );
    const cases = [...value.cases];
    cases[0] = rebuildCase(cases[0], {
      workspace: { clean_status_sha256: sha256Bytes(status) },
    });
    await assert.rejects(
      () => materializeReleasePilotWorkspacesV1(materializerInput(value, {
        cases,
        pilotId: "release-workspace-hardlink-rejection",
      })),
      /aionis_eval_release_workspace_resource_source_hardlink_forbidden/u,
    );
    await assertPrivateRunRootEmpty(value.privateRunRoot);
  });

test("release workspace materializer binds exact Git origin, HEAD, and raw status digest", async (t) => {
  const originValue = await fixture(t, "origin");
  await git(originValue.gitExecutablePath, originValue.built[0].templatePath, [
    "remote", "set-url", "origin", "https://github.com/aionis-evals/not-the-case.git",
  ]);
  await assert.rejects(
    () => materializeReleasePilotWorkspacesV1(materializerInput(originValue)),
    /aionis_eval_release_workspace_resource_git_origin_mismatch/u,
  );
  await assertPrivateRunRootEmpty(originValue.privateRunRoot);

  const statusValue = await fixture(t, "status");
  await writeFile(path.join(statusValue.built[0].templatePath, "untracked.txt"), "changed\n", {
    mode: 0o600,
  });
  await assert.rejects(
    () => materializeReleasePilotWorkspacesV1(materializerInput(statusValue)),
    /aionis_eval_release_workspace_resource_git_status_sha256_mismatch/u,
  );
  await assertPrivateRunRootEmpty(statusValue.privateRunRoot);

  const headValue = await fixture(t, "head");
  await writeFile(path.join(headValue.built[0].templatePath, "second.txt"), "second\n", {
    mode: 0o600,
  });
  await git(headValue.gitExecutablePath, headValue.built[0].templatePath, ["add", "--all"]);
  await git(headValue.gitExecutablePath, headValue.built[0].templatePath, [
    "commit", "--quiet", "-m", "unexpected head",
  ]);
  await assert.rejects(
    () => materializeReleasePilotWorkspacesV1(materializerInput(headValue)),
    /aionis_eval_release_workspace_resource_git_head_mismatch/u,
  );
  await assertPrivateRunRootEmpty(headValue.privateRunRoot);
});
