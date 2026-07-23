import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalSha256 } from "../src/canonical.mjs";
import {
  RELEASE_WORKSPACE_OWNER_ACTIVATION_FILE_V1,
  RELEASE_WORKSPACE_OWNER_INCOMPLETE_FILE_V1,
  RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1,
  activateReleaseWorkspaceOwnerManifestV1,
  beginReleaseWorkspaceOwnerManifestV1,
  readActiveReleaseWorkspaceOwnerManifestV1,
  reconcileReleaseWorkspaceOwnerV1,
  resolveReleaseWorkspaceOwnerManifestV1,
} from "../src/release-workspace-owner-manifest.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

function plan(label) {
  return buildTestPilotPlanV1([
    { case_id: `${label}-a`, case_sha256: canonicalSha256(`${label}-a`) },
    { case_id: `${label}-b`, case_sha256: canonicalSha256(`${label}-b`) },
    { case_id: `${label}-c`, case_sha256: canonicalSha256(`${label}-c`) },
  ], { pilotId: `workspace-owner-${label}` });
}

async function fixture(t, label) {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    `aionis-workspace-owner-${label}-`,
  )));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const privateRunRoot = path.join(root, "private-run");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  const gitExecutablePath = path.join(root, "trusted-git");
  await writeFile(gitExecutablePath, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await chmod(gitExecutablePath, 0o700);
  return {
    gitExecutablePath: await realpath(gitExecutablePath),
    ownerId: canonicalSha256(`owner:${label}`).slice(0, 32),
    plan: plan(label),
    privateRunRoot: await realpath(privateRunRoot),
    root,
  };
}

function beginInput(value) {
  return {
    plan: value.plan,
    privateRunRoot: value.privateRunRoot,
    gitExecutablePath: value.gitExecutablePath,
    orchestrationOwnerId: value.ownerId,
  };
}

function reconcileInput(value, overrides = {}) {
  return {
    privateRunRoot: value.privateRunRoot,
    gitExecutablePath: value.gitExecutablePath,
    expectedOwnerId: overrides.expectedOwnerId ?? value.ownerId,
    expectedPlanSha256: overrides.expectedPlanSha256 ?? value.plan.plan_sha256,
  };
}

test("prepared workspace owner is durable and reconciliation never prefix-scans", async (t) => {
  const value = await fixture(t, "prepared");
  const foreign = path.join(
    value.privateRunRoot,
    `.aionis-release-workspace-owner-${"f".repeat(32)}`,
  );
  await mkdir(foreign, { mode: 0o700 });
  await writeFile(path.join(foreign, "foreign.txt"), "preserve\n", { mode: 0o600 });

  const handle = await beginReleaseWorkspaceOwnerManifestV1(beginInput(value));
  const resolved = resolveReleaseWorkspaceOwnerManifestV1(handle);
  assert.equal(resolved.activation, null);
  await assert.rejects(() => stat(resolved.resourceRoot), /ENOENT/u);
  const manifestPath = path.join(
    value.privateRunRoot,
    RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1,
  );
  assert.equal((await stat(manifestPath)).mode & 0o777, 0o600);
  assert.equal(
    await readFile(manifestPath, "utf8"),
    `${canonicalJson(resolved.manifest)}\n`,
  );

  const result = await reconcileReleaseWorkspaceOwnerV1(reconcileInput(value));
  assert.equal(result.status, "prepared_owner_cleared");
  assert.equal(result.cleanup_confirmed, true);
  assert.equal(await readActiveReleaseWorkspaceOwnerManifestV1({
    privateRunRoot: value.privateRunRoot,
  }), null);
  assert.equal(await readFile(path.join(foreign, "foreign.txt"), "utf8"), "preserve\n");
});

test("prepared crash window cleans only an empty exact root and retries non-empty", async (t) => {
  const empty = await fixture(t, "prepared-empty-root");
  const emptyHandle = await beginReleaseWorkspaceOwnerManifestV1(beginInput(empty));
  const emptyRoot = resolveReleaseWorkspaceOwnerManifestV1(emptyHandle).resourceRoot;
  await mkdir(emptyRoot, { mode: 0o700 });
  await chmod(emptyRoot, 0o700);
  const emptyResult = await reconcileReleaseWorkspaceOwnerV1(reconcileInput(empty));
  assert.equal(emptyResult.status, "prepared_owner_cleared");
  await assert.rejects(() => stat(emptyRoot), /ENOENT/u);

  const occupied = await fixture(t, "prepared-occupied-root");
  const occupiedHandle = await beginReleaseWorkspaceOwnerManifestV1(beginInput(occupied));
  const occupiedRoot = resolveReleaseWorkspaceOwnerManifestV1(occupiedHandle).resourceRoot;
  await mkdir(occupiedRoot, { mode: 0o700 });
  await chmod(occupiedRoot, 0o700);
  const child = path.join(occupiedRoot, "unknown.txt");
  await writeFile(child, "do-not-delete\n", { mode: 0o600 });
  await assert.rejects(
    reconcileReleaseWorkspaceOwnerV1(reconcileInput(occupied)),
    /prepared_root_not_empty/u,
  );
  assert.equal(await readFile(child, "utf8"), "do-not-delete\n");
  assert.equal(
    (await stat(path.join(
      occupied.privateRunRoot,
      RELEASE_WORKSPACE_OWNER_INCOMPLETE_FILE_V1,
    ))).mode & 0o777,
    0o600,
  );
  await rm(child);
  const retry = await reconcileReleaseWorkspaceOwnerV1(reconcileInput(occupied));
  assert.equal(retry.cleanup_confirmed, true);
  await assert.rejects(() => stat(occupiedRoot), /ENOENT/u);
});

test("active workspace owner persists root identity and reconciles across pilot plans", async (t) => {
  const value = await fixture(t, "active-cross-plan");
  const handle = await beginReleaseWorkspaceOwnerManifestV1(beginInput(value));
  const active = await activateReleaseWorkspaceOwnerManifestV1(handle);
  assert.notEqual(active.activation, null);
  assert.equal(active.activation.owner_id, value.ownerId);
  assert.equal(active.activation.plan_sha256, value.plan.plan_sha256);
  assert.equal((await stat(active.resourceRoot)).mode & 0o777, 0o700);
  const activationPath = path.join(
    value.privateRunRoot,
    RELEASE_WORKSPACE_OWNER_ACTIVATION_FILE_V1,
  );
  assert.equal(
    await readFile(activationPath, "utf8"),
    `${canonicalJson(active.activation)}\n`,
  );
  await mkdir(path.join(active.resourceRoot, "cell-01"), { mode: 0o700 });
  await writeFile(path.join(active.resourceRoot, "cell-01", "result.txt"), "partial\n");

  const unrelatedNewPlan = plan("new-pilot-after-crash");
  assert.notEqual(unrelatedNewPlan.plan_sha256, value.plan.plan_sha256);
  await assert.rejects(
    reconcileReleaseWorkspaceOwnerV1(reconcileInput(value, {
      expectedPlanSha256: unrelatedNewPlan.plan_sha256,
    })),
    /recovery_authority_mismatch/u,
  );
  assert.equal((await stat(active.resourceRoot)).isDirectory(), true);

  const recovered = await reconcileReleaseWorkspaceOwnerV1(reconcileInput(value));
  assert.equal(recovered.status, "active_owner_recovered");
  assert.equal(recovered.cleanup_confirmed, true);
  await assert.rejects(() => stat(active.resourceRoot), /ENOENT/u);
  assert.deepEqual(await readdir(value.privateRunRoot), []);
});

test("tampered or foreign active workspace roots are preserved until exact retry", async (t) => {
  const value = await fixture(t, "tamper");
  const handle = await beginReleaseWorkspaceOwnerManifestV1(beginInput(value));
  const active = await activateReleaseWorkspaceOwnerManifestV1(handle);
  const manifestPath = path.join(
    value.privateRunRoot,
    RELEASE_WORKSPACE_OWNER_MANIFEST_FILE_V1,
  );
  await chmod(manifestPath, 0o644);
  await assert.rejects(
    reconcileReleaseWorkspaceOwnerV1(reconcileInput(value)),
    /manifest_posture_invalid/u,
  );
  assert.equal((await stat(active.resourceRoot)).isDirectory(), true);
  await chmod(manifestPath, 0o600);

  const originalRoot = path.join(value.root, "original-root-preserved");
  await rename(active.resourceRoot, originalRoot);
  await mkdir(active.resourceRoot, { mode: 0o700 });
  await chmod(active.resourceRoot, 0o700);
  await writeFile(path.join(active.resourceRoot, "foreign.txt"), "foreign\n", {
    mode: 0o600,
  });
  await assert.rejects(
    reconcileReleaseWorkspaceOwnerV1(reconcileInput(value)),
    /resource_root_identity_mismatch/u,
  );
  assert.equal(
    await readFile(path.join(active.resourceRoot, "foreign.txt"), "utf8"),
    "foreign\n",
  );
  assert.equal((await stat(originalRoot)).isDirectory(), true);

  await rm(active.resourceRoot, { recursive: true });
  await rename(originalRoot, active.resourceRoot);
  const retried = await reconcileReleaseWorkspaceOwnerV1(reconcileInput(value));
  assert.equal(retried.cleanup_confirmed, true);
  assert.deepEqual(await readdir(value.privateRunRoot), []);
});
