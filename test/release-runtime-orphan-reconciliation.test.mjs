import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalJson, canonicalSha256 } from "../src/canonical.mjs";
import {
  reconcileReleaseRuntimeOciOwnerV1,
} from "../src/release-runtime-oci-resource.mjs";
import {
  RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1,
  RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
  RELEASE_RUNTIME_OWNER_LABEL_V1,
  beginReleaseRuntimeOwnerManifestV1,
  resolveReleaseRuntimeOwnerManifestV1,
} from "../src/release-runtime-owner-manifest.mjs";
import {
  OCI_ENGINE_EXECUTION_CONTEXT_V1,
  buildOciRuntimeAuthorityV1,
  canonicalOciEngineEnvironmentV1,
} from "../src/oci-verifier-process.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

const execFileAsync = promisify(execFile);
const DOCKER = "/Applications/Docker.app/Contents/Resources/bin/docker";
const IMAGE = "docker.io/library/aionis-continuation-runtime-v1:ci";

async function docker(args, options = {}) {
  return execFileAsync(DOCKER, args, {
    cwd: OCI_ENGINE_EXECUTION_CONTEXT_V1.working_directory,
    encoding: "utf8",
    env: canonicalOciEngineEnvironmentV1(),
    maxBuffer: 8 * 1024 * 1024,
    timeout: options.timeout ?? 180_000,
  });
}

async function liveDocker(t) {
  try {
    await access(DOCKER);
    await docker(["info", "--format", "{{json .ServerVersion}}"]);
    const inspected = JSON.parse((await docker([
      "inspect", "--type=image", IMAGE,
    ])).stdout);
    if (!Array.isArray(inspected) || inspected.length !== 1
      || !/^sha256:[0-9a-f]{64}$/u.test(inspected[0]?.Id)) throw new Error("image_invalid");
    return inspected[0].Id;
  } catch {
    t.skip("trusted Docker Desktop or the exact local Runtime image is unavailable");
    return null;
  }
}

function plan() {
  return buildTestPilotPlanV1([
    { case_id: "orphan-a", case_sha256: canonicalSha256("orphan-a") },
    { case_id: "orphan-b", case_sha256: canonicalSha256("orphan-b") },
    { case_id: "orphan-c", case_sha256: canonicalSha256("orphan-c") },
  ], { pilotId: "runtime-orphan-reconciliation" });
}

async function createOwnedContainer({
  cell,
  imageDigest,
  labelsOwnerId,
  manifestOwnerId,
  planSha256,
  resourceRoot,
}) {
  const cellRoot = path.join(
    resourceRoot,
    `cell-${String(cell.ordinal).padStart(2, "0")}`,
  );
  const data = path.join(cellRoot, "data");
  const authority = path.join(cellRoot, "authority");
  await mkdir(data, { recursive: true, mode: 0o700 });
  await mkdir(authority, { recursive: true, mode: 0o700 });
  const name = `aionis-run-${manifestOwnerId}-${cell.ordinal}`;
  await docker([
    "create",
    "--name", name,
    "--mount", `type=bind,src=${data},dst=/data`,
    "--mount", `type=bind,src=${authority},dst=/run/aionis,readonly`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner}=${RELEASE_RUNTIME_OWNER_LABEL_V1}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.owner_id}=${labelsOwnerId}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.plan_sha256}=${planSha256}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.cell_id}=${cell.opaque_cell_id}`,
    `--label=${RELEASE_RUNTIME_CONTAINER_LABEL_KEYS_V1.resource_kind}=daemon`,
    imageDigest,
  ]);
  return name;
}

test("orphan reconciliation removes only an exact authority/owner/plan/cell binding", async (t) => {
  const imageDigest = await liveDocker(t);
  if (imageDigest === null) return;
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-orphan-")));
  const privateRunRoot = path.join(root, "private-run");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  const runtimeAuthority = await buildOciRuntimeAuthorityV1({ executablePath: DOCKER });
  const pilotPlan = plan();
  const ownerId = "11111111111111111111111111111111";
  let containerName = null;
  try {
    const owner = await beginReleaseRuntimeOwnerManifestV1({
      ociEngineExecutionContextSha256: canonicalSha256(OCI_ENGINE_EXECUTION_CONTEXT_V1),
      ociRuntimeAuthoritySha256: runtimeAuthority.authority_sha256,
      orchestrationOwnerId: ownerId,
      plan: pilotPlan,
      privateRunRoot,
      runtimeImageDigest: imageDigest,
    });
    const resolved = resolveReleaseRuntimeOwnerManifestV1(owner);
    const cell = pilotPlan.schedule.at(-1);
    containerName = await createOwnedContainer({
      cell,
      imageDigest,
      labelsOwnerId: ownerId,
      manifestOwnerId: ownerId,
      planSha256: pilotPlan.plan_sha256,
      resourceRoot: resolved.resourceRoot,
    });
    const receipt = await reconcileReleaseRuntimeOciOwnerV1({
      ociExecutablePath: DOCKER,
      privateRunRoot,
    });
    assert.equal(receipt.status, "orphan_owner_reconciled");
    assert.equal(receipt.owner_id, ownerId);
    assert.equal(receipt.discovered_container_count, 1);
    assert.equal(receipt.removed_container_count, 1);
    assert.equal(receipt.cleanup_confirmed, true);
    assert.equal(receipt.new_pilot_permitted, true);
    await assert.rejects(docker(["inspect", containerName]), /Command failed/u);
    containerName = null;
    assert.deepEqual(await import("node:fs/promises").then(({ readdir }) =>
      readdir(privateRunRoot)), []);
  } finally {
    if (containerName !== null) {
      await docker(["rm", "--force", "--volumes", containerName]).catch(() => {});
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("label mismatch leaves the orphan and a private incomplete receipt", async (t) => {
  const imageDigest = await liveDocker(t);
  if (imageDigest === null) return;
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-orphan-bad-")));
  const privateRunRoot = path.join(root, "private-run");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  const runtimeAuthority = await buildOciRuntimeAuthorityV1({ executablePath: DOCKER });
  const pilotPlan = plan();
  const ownerId = "22222222222222222222222222222222";
  let containerName = null;
  try {
    const owner = await beginReleaseRuntimeOwnerManifestV1({
      ociEngineExecutionContextSha256: canonicalSha256(OCI_ENGINE_EXECUTION_CONTEXT_V1),
      ociRuntimeAuthoritySha256: runtimeAuthority.authority_sha256,
      orchestrationOwnerId: ownerId,
      plan: pilotPlan,
      privateRunRoot,
      runtimeImageDigest: imageDigest,
    });
    const resolved = resolveReleaseRuntimeOwnerManifestV1(owner);
    const cell = pilotPlan.schedule.at(-1);
    containerName = await createOwnedContainer({
      cell,
      imageDigest,
      labelsOwnerId: "33333333333333333333333333333333",
      manifestOwnerId: ownerId,
      planSha256: pilotPlan.plan_sha256,
      resourceRoot: resolved.resourceRoot,
    });
    await assert.rejects(
      reconcileReleaseRuntimeOciOwnerV1({
        ociExecutablePath: DOCKER,
        privateRunRoot,
      }),
      /orphan_container_binding_invalid/u,
    );
    const inspect = JSON.parse((await docker(["inspect", containerName])).stdout);
    assert.equal(inspect.length, 1, "mismatched container must not be removed");
    const incompletePath = path.join(
      privateRunRoot,
      RELEASE_RUNTIME_OWNER_INCOMPLETE_RECEIPT_FILE_V1,
    );
    assert.equal((await lstat(incompletePath)).mode & 0o777, 0o600);
    const text = await readFile(incompletePath, "utf8");
    const incomplete = JSON.parse(text);
    assert.equal(text, `${canonicalJson(incomplete)}\n`);
    assert.equal(incomplete.cleanup_confirmed, false);
    assert.equal(incomplete.failure_stage, "container_inspection");
    assert.equal(incomplete.discovered_container_count, 1);
    assert.equal(incomplete.removed_container_count, 0);
    assert.equal(incomplete.state, "cleanup_incomplete_new_pilot_forbidden");
  } finally {
    if (containerName !== null) {
      await docker(["rm", "--force", "--volumes", containerName]).catch(() => {});
    }
    await rm(root, { recursive: true, force: true });
  }
});
