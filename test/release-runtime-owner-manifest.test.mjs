import assert from "node:assert/strict";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  unlink,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson, canonicalSha256 } from "../src/canonical.mjs";
import {
  RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1,
  RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
  RELEASE_RUNTIME_OWNER_LABEL_V1,
  RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1,
  RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1,
  beginReleaseRuntimeOwnerManifestV1,
  confirmReleaseRuntimeOwnerCleanupV1,
  persistReleaseRuntimeCleanupIncompleteV1,
  readActiveReleaseRuntimeOwnerManifestV1,
  resolveReleaseRuntimeOwnerManifestV1,
} from "../src/release-runtime-owner-manifest.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const OWNER_ID = "0123456789abcdef0123456789abcdef";

function testPlan() {
  return buildTestPilotPlanV1([
    { case_id: "owner-case-a", case_sha256: canonicalSha256("owner-case-a") },
    { case_id: "owner-case-b", case_sha256: canonicalSha256("owner-case-b") },
    { case_id: "owner-case-c", case_sha256: canonicalSha256("owner-case-c") },
  ], { pilotId: "runtime-owner-manifest-pilot" });
}

test("runtime owner manifest is durable, exclusive, exact-label bound, and cleanup gated", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-runtime-owner-manifest-",
  )));
  const privateRunRoot = path.join(root, "private-run");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  const plan = testPlan();
  try {
    const owner = await beginReleaseRuntimeOwnerManifestV1({
      ociEngineExecutionContextSha256: SHA_A,
      ociRuntimeAuthoritySha256: SHA_B,
      orchestrationOwnerId: OWNER_ID,
      plan,
      privateRunRoot,
      runtimeImageDigest: `sha256:${SHA_A}`,
    });
    assert.match(owner.owner_id, /^[0-9a-f]{32}$/u);
    assert.equal(owner.plan_sha256, plan.plan_sha256);
    assert.throws(
      () => resolveReleaseRuntimeOwnerManifestV1({ ...owner }),
      /owner_handle_invalid/u,
    );

    const resolved = resolveReleaseRuntimeOwnerManifestV1(owner);
    const manifestPath = path.join(privateRunRoot, RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1);
    const rootIdentityPath = path.join(
      privateRunRoot,
      RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1,
    );
    assert.equal((await lstat(privateRunRoot)).mode & 0o777, 0o700);
    assert.equal((await lstat(resolved.resourceRoot)).mode & 0o777, 0o700);
    assert.equal((await lstat(manifestPath)).mode & 0o777, 0o600);
    assert.equal((await lstat(rootIdentityPath)).mode & 0o777, 0o600);
    const manifestText = await readFile(manifestPath, "utf8");
    assert.equal(manifestText, `${canonicalJson(resolved.manifest)}\n`);
    assert.equal(resolved.manifest.owner_label, RELEASE_RUNTIME_OWNER_LABEL_V1);
    assert.equal(resolved.manifest.plan_sha256, plan.plan_sha256);
    assert.equal(resolved.manifest.oci_runtime_authority_sha256, SHA_B);
    assert.equal(resolved.manifest.oci_engine_execution_context_sha256, SHA_A);
    assert.equal(resolved.manifest.scheduled_cells.length, 9);
    assert.deepEqual(
      resolved.manifest.container_label_contract.keys,
      RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1,
    );
    assert.deepEqual(
      resolved.manifest.container_label_contract.resource_kinds,
      ["daemon", "provisioning"],
    );

    const recovered = await readActiveReleaseRuntimeOwnerManifestV1({ privateRunRoot });
    assert.deepEqual(recovered.manifest, resolved.manifest);
    assert.equal(recovered.resourceRoot, resolved.resourceRoot);
    await assert.rejects(
      beginReleaseRuntimeOwnerManifestV1({
        ociEngineExecutionContextSha256: SHA_A,
        ociRuntimeAuthoritySha256: SHA_B,
        orchestrationOwnerId: OWNER_ID,
        plan,
        privateRunRoot,
        runtimeImageDigest: `sha256:${SHA_A}`,
      }),
      /active_owner_exists/u,
    );

    const incomplete = await persistReleaseRuntimeCleanupIncompleteV1(owner, {
      discoveredContainerCount: 3,
      failureStage: "container_removal",
      removedContainerCount: 2,
    });
    assert.equal(incomplete.cleanup_confirmed, false);
    assert.equal(incomplete.state, "cleanup_incomplete_new_pilot_forbidden");
    const incompletePath = path.join(
      privateRunRoot,
      RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
    );
    assert.equal((await lstat(incompletePath)).mode & 0o777, 0o600);
    assert.equal(
      await readFile(incompletePath, "utf8"),
      `${canonicalJson(incomplete)}\n`,
    );

    await assert.rejects(
      confirmReleaseRuntimeOwnerCleanupV1(owner),
      /resource_root_still_exists/u,
    );
    await rm(resolved.resourceRoot, { recursive: true, force: true });
    const confirmation = await confirmReleaseRuntimeOwnerCleanupV1(owner);
    assert.equal(confirmation.cleanup_confirmed, true);
    assert.equal(
      await readActiveReleaseRuntimeOwnerManifestV1({ privateRunRoot }),
      null,
    );
    await assert.rejects(readFile(incompletePath, "utf8"), /ENOENT/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("manifest is the last cleanup barrier and orphan identity metadata fails closed", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-runtime-owner-manifest-order-",
  )));
  const privateRunRoot = path.join(root, "private-run");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  try {
    const owner = await beginReleaseRuntimeOwnerManifestV1({
      ociEngineExecutionContextSha256: SHA_A,
      ociRuntimeAuthoritySha256: SHA_B,
      orchestrationOwnerId: OWNER_ID,
      plan: testPlan(),
      privateRunRoot,
      runtimeImageDigest: `sha256:${SHA_A}`,
    });
    const resolved = resolveReleaseRuntimeOwnerManifestV1(owner);
    await unlink(path.join(privateRunRoot, RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1));
    await assert.rejects(
      readActiveReleaseRuntimeOwnerManifestV1({ privateRunRoot }),
      /orphan_metadata_without_manifest/u,
    );
    assert.equal(
      (await lstat(path.join(
        privateRunRoot,
        RELEASE_RUNTIME_OWNER_ROOT_IDENTITY_FILE_V1,
      ))).mode & 0o777,
      0o600,
    );
    await rm(resolved.resourceRoot, { recursive: true, force: true });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("unsafe owner manifest posture blocks recovery instead of being trusted", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-runtime-owner-manifest-posture-",
  )));
  const privateRunRoot = path.join(root, "private-run");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  let owner;
  try {
    owner = await beginReleaseRuntimeOwnerManifestV1({
      ociEngineExecutionContextSha256: SHA_A,
      ociRuntimeAuthoritySha256: SHA_B,
      orchestrationOwnerId: OWNER_ID,
      plan: testPlan(),
      privateRunRoot,
      runtimeImageDigest: `sha256:${SHA_A}`,
    });
    const manifestPath = path.join(privateRunRoot, RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1);
    await chmod(manifestPath, 0o644);
    await assert.rejects(
      readActiveReleaseRuntimeOwnerManifestV1({ privateRunRoot }),
      /manifest_posture_invalid/u,
    );
    await chmod(manifestPath, 0o600);
  } finally {
    if (owner !== undefined) {
      const resolved = resolveReleaseRuntimeOwnerManifestV1(owner);
      await rm(resolved.resourceRoot, { recursive: true, force: true });
      await confirmReleaseRuntimeOwnerCleanupV1(owner).catch(() => {});
    }
    await rm(root, { recursive: true, force: true });
  }
});
