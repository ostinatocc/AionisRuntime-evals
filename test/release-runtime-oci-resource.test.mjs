import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createPrivateKey, generateKeyPairSync } from "node:crypto";
import { watch } from "node:fs";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

import { canonicalSha256 } from "../src/canonical.mjs";
import { cellPolicyBundleSetSha256V1 } from "../src/pilot-contract.mjs";
import {
  createReleasePilotCancellationAuthorityV1,
  disposeReleasePilotSignalDrainV1,
  installReleasePilotSignalDrainV1,
  snapshotReleasePilotCancellationV1,
} from "../src/release-pilot-cancellation.mjs";
import {
  assertReleaseRuntimeDaemonEnvironmentFieldsV1,
  claimReleaseRuntimeOciResourceOwnerV1,
  preflightReleaseRuntimeOciImageV1,
  prepareReleaseRuntimeOciResourcesV1,
  reconcileReleaseRuntimeOciOwnerV1,
} from "../src/release-runtime-oci-resource.mjs";
import {
  RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1,
} from "../src/release-runtime-owner-manifest.mjs";
import {
  OCI_ENGINE_EXECUTION_CONTEXT_V1,
  canonicalOciEngineEnvironmentV1,
} from "../src/oci-verifier-process.mjs";
import {
  issueTrustedReleaseSdkClientAuthorityV1,
} from "../src/release-sdk-client-authority.mjs";
import { verifierPublicKeyPrincipalSha256V1 } from "../src/verifier-evidence.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

const execFileAsync = promisify(execFile);
const TRUSTED_DOCKER_PATH = "/Applications/Docker.app/Contents/Resources/bin/docker";
const DEFAULT_RUNTIME_IMAGE = "docker.io/library/aionis-continuation-runtime-v1:ci";
const FILE_ONLY_DAEMON_ENVIRONMENT = Object.freeze([
  "AIONIS_DATA_PATH",
  "AIONIS_HOST_API_KEY_FILE",
  "AIONIS_HOST_PRINCIPAL_ID",
  "AIONIS_HTTP_BODY_LIMIT_BYTES",
  "AIONIS_HTTP_HOST",
  "AIONIS_HTTP_PORT",
  "AIONIS_LOG_LEVEL",
  "AIONIS_OPERATOR_API_KEY_FILE",
  "AIONIS_OPERATOR_PRINCIPAL_ID",
  "AIONIS_SHUTDOWN_TIMEOUT_MS",
  "AIONIS_TENANT_ID",
  "AIONIS_TRUST_ROOT_PUBLIC_KEY_PATH",
  "AIONIS_TRUST_ROOT_SHA256",
]);

test("release Runtime daemon preflight accepts only the exact file-only token surface", () => {
  assert.deepEqual(
    assertReleaseRuntimeDaemonEnvironmentFieldsV1(FILE_ONLY_DAEMON_ENVIRONMENT),
    FILE_ONLY_DAEMON_ENVIRONMENT,
  );
  for (const invalid of [
    FILE_ONLY_DAEMON_ENVIRONMENT.map((field) => field === "AIONIS_HOST_API_KEY_FILE"
      ? "AIONIS_HOST_API_KEY"
      : field === "AIONIS_OPERATOR_API_KEY_FILE" ? "AIONIS_OPERATOR_API_KEY" : field),
    [...FILE_ONLY_DAEMON_ENVIRONMENT, "AIONIS_HOST_API_KEY", "AIONIS_OPERATOR_API_KEY"],
    [...FILE_ONLY_DAEMON_ENVIRONMENT, "AIONIS_UNREVIEWED_DAEMON_FIELD"],
  ]) {
    assert.throws(
      () => assertReleaseRuntimeDaemonEnvironmentFieldsV1(invalid),
      /aionis_eval_release_runtime_oci_resource_daemon_token_file_contract_invalid/u,
    );
  }
});

async function docker(args) {
  return execFileAsync(TRUSTED_DOCKER_PATH, args, {
    cwd: OCI_ENGINE_EXECUTION_CONTEXT_V1.working_directory,
    encoding: "utf8",
    env: canonicalOciEngineEnvironmentV1(),
    maxBuffer: 8 * 1024 * 1024,
    timeout: 120_000,
  });
}

async function execute(program, args, options = {}) {
  return execFileAsync(program, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: { ...process.env, LANG: "C", LC_ALL: "C" },
    maxBuffer: 8 * 1024 * 1024,
    timeout: options.timeout ?? 300_000,
  });
}

async function liveRuntimeImage(t) {
  try {
    await access(TRUSTED_DOCKER_PATH);
    await docker(["info", "--format", "{{json .ServerVersion}}"]);
  } catch {
    t.skip("trusted Docker Desktop release engine is unavailable");
    return null;
  }
  const reference = process.env.AIONIS_RELEASE_RUNTIME_TEST_IMAGE ?? DEFAULT_RUNTIME_IMAGE;
  let inspected;
  try {
    inspected = JSON.parse((await docker(["inspect", "--type=image", reference])).stdout);
  } catch {
    t.skip(`exact local Runtime image is absent: ${reference}`);
    return null;
  }
  if (!Array.isArray(inspected) || inspected.length !== 1
    || !/^sha256:[0-9a-f]{64}$/u.test(inspected[0]?.Id)) {
    t.skip(`exact local Runtime image has no stable image id: ${reference}`);
    return null;
  }
  let manifest;
  try {
    const output = await docker([
      "run", "--rm", "--pull=never", "--network=none", "--read-only",
      "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
      "--entrypoint=/bin/cat", inspected[0].Id,
      "/app/runtime-closure.manifest.json",
    ]);
    manifest = JSON.parse(output.stdout);
    manifest.rawSha256 = createHash("sha256").update(output.stdout).digest("hex");
  } catch {
    t.skip(`local image does not expose the exact Runtime closure contract: ${reference}`);
    return null;
  }
  let daemonEnvironmentFields;
  try {
    const source = "import('/app/dist/runtime-v1/config.js').then((m)=>console.log(JSON.stringify(m.CONTINUATION_RUNTIME_V1_DAEMON_ENV_FIELDS)))";
    daemonEnvironmentFields = JSON.parse((await docker([
      "run", "--rm", "--pull=never", "--network=none", "--read-only",
      "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
      "--entrypoint=node", inspected[0].Id,
      "--input-type=module", "--eval", source,
    ])).stdout);
  } catch {
    daemonEnvironmentFields = [];
  }
  return {
    closureSha256: manifest.closure_sha256,
    daemonEnvironmentFields,
    digest: inspected[0].Id,
    manifestSha256: manifest.rawSha256,
    reference,
  };
}

async function fixture(t, image) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-release-oci-")));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const privateRunRoot = path.join(root, "private-run");
  await mkdir(privateRunRoot, { mode: 0o700 });
  await chmod(privateRunRoot, 0o700);
  const trustRoot = generateKeyPairSync("ed25519");
  const trustRootPath = path.join(root, "trust-root-public.pem");
  await writeFile(trustRootPath, trustRoot.publicKey.export({
    format: "pem",
    type: "spki",
  }), { mode: 0o600 });
  await chmod(trustRootPath, 0o600);
  const verifierKeys = Array.from({ length: 3 }, () => generateKeyPairSync("ed25519"));
  const cases = verifierKeys.map((keys, index) => buildTestPilotCaseV1({
    caseId: `release-oci-case-${index + 1}`,
    verifierPrivateKey: keys.privateKey,
    verifierPublicKey: keys.publicKey,
  }));
  const trustRootSha256 = verifierPublicKeyPrincipalSha256V1(trustRoot.publicKey);
  const seedPlan = buildTestPilotPlanV1(cases, {
    pilotId: "release-runtime-oci-resource-live",
    trustRootSha256,
  });
  const plan = buildTestPilotPlanV1(cases, {
    pilotId: seedPlan.pilot_id,
    trustRootSha256,
    runtimeBinding: {
      ...seedPlan.runtime_binding,
      oci_image_digest: image.digest,
      oci_closure_manifest_sha256: image.manifestSha256,
      oci_closure_sha256: image.closureSha256,
    },
  });
  return {
    cases,
    plan,
    privateRunRoot: await realpath(privateRunRoot),
    trustRootPath: await realpath(trustRootPath),
  };
}

function preflightInput(image, plan) {
  return {
    plan,
    ociExecutablePath: TRUSTED_DOCKER_PATH,
    runtimeImageReference: image.reference,
  };
}

function imageHasExactFileOnlyDaemonEnvironment(image) {
  try {
    assertReleaseRuntimeDaemonEnvironmentFieldsV1(image.daemonEnvironmentFields);
    return true;
  } catch {
    return false;
  }
}

test("release Runtime owner rejects a real image whose resolved id is not the plan digest",
  async (t) => {
    const image = await liveRuntimeImage(t);
    if (image === null) return;
    const value = await fixture(t, image);
    const mismatchedPlan = buildTestPilotPlanV1(value.cases, {
      pilotId: value.plan.pilot_id,
      runtimeBinding: {
        ...value.plan.runtime_binding,
        oci_image_digest: `sha256:${"f".repeat(64)}`,
      },
    });
    await assert.rejects(
      () => preflightReleaseRuntimeOciImageV1(preflightInput(image, mismatchedPlan)),
      /aionis_eval_release_runtime_oci_resource_image_digest_mismatch/u,
    );
    assert.deepEqual(await readdir(value.privateRunRoot), []);
  });

test("release Runtime owner performs live image/closure preflight and fails closed on old token env",
  async (t) => {
    const image = await liveRuntimeImage(t);
    if (image === null) return;
    if (imageHasExactFileOnlyDaemonEnvironment(image)) {
      t.skip("exact image supports token files; full run requires the frozen signed 9-cell policy set");
      return;
    }
    const value = await fixture(t, image);
    await assert.rejects(
      () => preflightReleaseRuntimeOciImageV1(preflightInput(image, value.plan)),
      /aionis_eval_release_runtime_oci_resource_daemon_token_file_contract_invalid/u,
    );
    assert.deepEqual(await readdir(value.privateRunRoot), []);
  });

function runtimePrincipal(tenantId, principalKind, principalId) {
  return canonicalSha256({
    schema_version: "continuation_runtime_principal_v1",
    tenant_id: tenantId,
    principal_kind: principalKind,
    principal_id: principalId,
    authentication: "bearer_sha256_v1",
  });
}

function policyRequest(template, plan, cell, effectSignerSha256) {
  const value = structuredClone(template);
  const tenantId = plan.runtime_binding.tenant_id;
  const taskFamily = plan.runtime_binding.task_family;
  const identity = cell.isolation.isolation_sha256.slice(0, 20);
  const subject = canonicalSha256({
    schema_version: "continuation_authority_subject_v1",
    tenant_id: tenantId,
    scope: cell.isolation.runtime_scope,
    task_family: taskFamily,
  });
  Object.assign(value, {
    tenant_id: tenantId,
    scope: cell.isolation.runtime_scope,
    task_family: taskFamily,
    operation_id: `release-oci-install-${cell.ordinal}-${identity}`,
    operator_principal_id: `operator-eval-${identity}`,
  });
  for (const [artifact, kind] of [
    [value.compiler_policy, "compiler"],
    [value.evidence_policy, "evidence"],
  ]) {
    Object.assign(artifact, {
      artifact_id: `release-oci-${kind}-${cell.ordinal}-${identity}`,
      artifact_revision: 1,
      created_at: "2020-01-01T00:00:00.000Z",
      valid_from: "2020-01-02T00:00:00.000Z",
      expires_at: null,
    });
    artifact.payload.tenant_id = tenantId;
    artifact.payload.authority_subject_sha256 = subject;
  }
  value.compiler_policy.payload.trusted_observer_principals = {
    trusted_host_collector: [runtimePrincipal(
      tenantId,
      "trusted_host",
      `host-eval-${identity}`,
    )],
    external_verifier: [],
  };
  value.evidence_policy.payload.trusted_effect_verifier_principals = [
    effectSignerSha256,
  ];
  return value;
}

function refsFromCommand(command, cell) {
  return {
    ordinal: cell.ordinal,
    opaque_cell_id: cell.opaque_cell_id,
    runtime_scope: cell.isolation.runtime_scope,
    authority_subject_sha256: command.authority_subject_sha256,
    provisioning_command_sha256: canonicalSha256(command),
    compiler_policy_ref: {
      artifact_sha256: command.policy_bundle.compiler_policy.artifact_sha256,
      payload_sha256: command.policy_bundle.compiler_policy.payload_sha256,
    },
    evidence_policy_ref: {
      artifact_sha256: command.policy_bundle.evidence_policy.artifact_sha256,
      payload_sha256: command.policy_bundle.evidence_policy.payload_sha256,
    },
  };
}

async function packAndInstallRuntimeSdk(runtimeRoot, ownerRoot) {
  await execute("npm", ["run", "-s", "build:sdk"], {
    cwd: runtimeRoot,
    timeout: 600_000,
  });
  const packDirectory = path.join(ownerRoot, "sdk-pack");
  const consumerRoot = path.join(ownerRoot, "sdk-consumer");
  await mkdir(packDirectory, { mode: 0o700 });
  await mkdir(consumerRoot, { mode: 0o700 });
  await chmod(packDirectory, 0o700);
  await chmod(consumerRoot, 0o700);
  await writeFile(path.join(consumerRoot, "package.json"), `${JSON.stringify({
    name: "aionis-release-runtime-resource-sdk-consumer",
    private: true,
    type: "module",
  })}\n`, { mode: 0o600 });
  const packed = JSON.parse((await execute("npm", [
    "pack",
    "--json",
    "--ignore-scripts",
    "--pack-destination", packDirectory,
  ], {
    cwd: path.join(runtimeRoot, "packages", "sdk"),
  })).stdout);
  if (!Array.isArray(packed) || packed.length !== 1
    || typeof packed[0]?.filename !== "string"
    || typeof packed[0]?.name !== "string"
    || typeof packed[0]?.version !== "string"
    || !Array.isArray(packed[0]?.files) || packed[0].files.length < 1) {
    throw new Error("release_runtime_oci_resource_test_sdk_pack_report_invalid");
  }
  const sdkTarballPath = await realpath(path.join(packDirectory, packed[0].filename));
  await execute("npm", [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--prefix", consumerRoot,
    sdkTarballPath,
  ], { cwd: ownerRoot });
  const tarball = await readFile(sdkTarballPath);
  const result = {
    consumerRoot: await realpath(consumerRoot),
    sdkTarballPath,
    runtimeBinding: {
      sdk_package_name: packed[0].name,
      sdk_package_version: packed[0].version,
      sdk_entry_count: packed[0].files.length,
      sdk_tgz_sha256: createHash("sha256").update(tarball).digest("hex"),
      sdk_tgz_sha512: createHash("sha512").update(tarball).digest("hex"),
    },
  };
  tarball.fill(0);
  return result;
}

test("release Runtime owner preserves a foreign collision, provisions nine real containers, and cleans them",
  async (t) => {
    const runtimeRootInput = process.env.AIONIS_RELEASE_RUNTIME_SOURCE_ROOT;
    if (runtimeRootInput === undefined) {
      t.skip("set AIONIS_RELEASE_RUNTIME_SOURCE_ROOT to exercise the full signed Runtime image");
      return;
    }
    const image = await liveRuntimeImage(t);
    if (image === null) return;
    if (!imageHasExactFileOnlyDaemonEnvironment(image)) {
      t.skip("exact Runtime image does not implement the token-file daemon contract");
      return;
    }
    const runtimeRoot = await realpath(runtimeRootInput);
    const value = await fixture(t, image);
    const ownerRoot = path.dirname(value.privateRunRoot);
    const authorityRoot = path.join(ownerRoot, "offline-authority");
    const sdk = await packAndInstallRuntimeSdk(runtimeRoot, ownerRoot);
    await execute(process.execPath, [
      path.join(runtimeRoot, "tools/build-continuation-runtime-v1-authority.mjs"),
    ], { cwd: runtimeRoot });
    const generated = JSON.parse((await execute(process.execPath, [
      path.join(runtimeRoot, "tools/generate-continuation-runtime-v1-authority-keys.mjs"),
      authorityRoot,
    ], { cwd: runtimeRoot })).stdout);
    const privateKey = createPrivateKey(await readFile(path.join(authorityRoot, "root-private.pem")));
    const authorModule = await import(pathToFileURL(path.join(
      runtimeRoot,
      "dist-authority/tools/continuation-runtime-v1-authority-authoring.js",
    )).href);
    const template = JSON.parse(await readFile(path.join(
      runtimeRoot,
      "docs/examples/continuation-runtime-v1-policy-bundle-authoring-request.canonical.json",
    ), "utf8"));
    const seedPlan = buildTestPilotPlanV1(value.cases, {
      pilotId: "release-runtime-oci-resource-full-live",
      trustRootSha256: generated.trust_root_sha256,
    });
    const commands = seedPlan.schedule.map((cell) =>
      authorModule.authorContinuationRuntimeV1AuthorityCommand(
        policyRequest(template, seedPlan, cell, generated.effect_signer_sha256),
        privateKey,
      ));
    const bindings = commands.map((command, index) =>
      refsFromCommand(command, seedPlan.schedule[index]));
    const runtimeBinding = {
      ...seedPlan.runtime_binding,
      oci_image_digest: image.digest,
      oci_closure_manifest_sha256: image.manifestSha256,
      oci_closure_sha256: image.closureSha256,
      trust_root_sha256: generated.trust_root_sha256,
      ...sdk.runtimeBinding,
      cell_policy_bundle_set_sha256: cellPolicyBundleSetSha256V1({
        pilotId: seedPlan.pilot_id,
        tenantId: seedPlan.runtime_binding.tenant_id,
        taskFamily: seedPlan.runtime_binding.task_family,
        trustRootSha256: generated.trust_root_sha256,
        bindings,
      }),
    };
    const plan = buildTestPilotPlanV1(value.cases, {
      pilotId: seedPlan.pilot_id,
      runtimeBinding,
    });
    const sdkClientAuthority = await issueTrustedReleaseSdkClientAuthorityV1({
      plan,
      sdkTarballPath: sdk.sdkTarballPath,
      consumerRoot: sdk.consumerRoot,
    });
    const callerOwnedPath = path.join(value.privateRunRoot, "caller-owned.txt");
    await writeFile(callerOwnedPath, "preserve\n", { mode: 0o600 });
    const collisionOwnerId = "fedcfedcfedcfedcfedcfedcfedcfedc";
    const collisionName = `aionis-prov-${collisionOwnerId}-${plan.schedule[0].ordinal}`;
    let foreignContainerId = null;
    try {
      foreignContainerId = (await docker([
        "create",
        "--name", collisionName,
        "--label=io.aionis.eval.owner=foreign-owner",
        image.digest,
      ])).stdout.trim();
      assert.match(foreignContainerId, /^[0-9a-f]{64}$/u);
      await assert.rejects(
        prepareReleaseRuntimeOciResourcesV1({
          cancellationAuthority: createReleasePilotCancellationAuthorityV1(),
          plan,
          cases: value.cases,
          orchestrationOwnerId: collisionOwnerId,
          privateRunRoot: value.privateRunRoot,
          ociExecutablePath: TRUSTED_DOCKER_PATH,
          runtimeImageReference: image.reference,
          trustRootPublicKeyPath: await realpath(path.join(
            authorityRoot,
            "root-public.pem",
          )),
          cellPolicyCommands: commands,
          sdkClientAuthority,
        }),
        /aionis_eval_release_runtime_oci_resource_container_name_collision/u,
      );
      const collisionInspect = JSON.parse((await docker([
        "container", "inspect", collisionName,
      ])).stdout);
      assert.equal(collisionInspect.length, 1);
      assert.equal(collisionInspect[0].Id, foreignContainerId);
      assert.deepEqual(
        await readdir(value.privateRunRoot),
        [path.basename(callerOwnedPath)],
      );
    } finally {
      if (foreignContainerId !== null) {
        await docker([
          "container", "rm", "--force", "--volumes", foreignContainerId,
        ]).catch(() => {});
      }
    }
    const handle = await prepareReleaseRuntimeOciResourcesV1({
      cancellationAuthority: createReleasePilotCancellationAuthorityV1(),
      plan,
      cases: value.cases,
      orchestrationOwnerId: "1234567890abcdef1234567890abcdef",
      privateRunRoot: value.privateRunRoot,
      ociExecutablePath: TRUSTED_DOCKER_PATH,
      runtimeImageReference: image.reference,
      trustRootPublicKeyPath: await realpath(path.join(authorityRoot, "root-public.pem")),
      cellPolicyCommands: commands,
      sdkClientAuthority,
    });
    assert.equal(Object.getPrototypeOf(handle), null);
    assert.equal("brokers" in handle, false);
    assert.equal("closeAll" in handle, false);
    const resources = claimReleaseRuntimeOciResourceOwnerV1({
      plan,
      runtimeOwner: handle,
    });
    assert.throws(
      () => claimReleaseRuntimeOciResourceOwnerV1({
        plan,
        runtimeOwner: handle,
      }),
      /already_claimed/u,
    );
    assert.equal(resources.brokers.length, 9);
    assert.equal(resources.authorities.length, 9);
    assert.equal(new Set(resources.authorities.map((entry) => entry.container_id)).size, 9);
    assert.equal(new Set(resources.brokers.map((entry) => entry.dataPath)).size, 9);
    assert.equal(resources.authorities.every((entry) =>
      entry.token_transport === "read_only_file_mount_v1"), true);
    assert.equal(JSON.stringify(resources.authorities).includes("api-key"), false);
    // Simulate a crashed owner: the in-memory owner is intentionally not
    // disposed. Startup reconciliation must recover the nine live daemons
    // solely from the durable manifest and exact labels.
    const recovered = await reconcileReleaseRuntimeOciOwnerV1({
      ociExecutablePath: TRUSTED_DOCKER_PATH,
      privateRunRoot: value.privateRunRoot,
    });
    assert.equal(recovered.status, "orphan_owner_reconciled");
    assert.equal(recovered.discovered_container_count, 9);
    assert.equal(recovered.removed_container_count, 9);
    assert.equal(recovered.cleanup_confirmed, true);
    const repeated = await reconcileReleaseRuntimeOciOwnerV1({
      ociExecutablePath: TRUSTED_DOCKER_PATH,
      privateRunRoot: value.privateRunRoot,
    });
    assert.equal(repeated.status, "no_orphan_owner_present");
    assert.equal(repeated.discovered_container_count, 0);
    assert.deepEqual(await readdir(value.privateRunRoot), [path.basename(callerOwnedPath)]);

    // A real SIGTERM delivered after the durable manifest appears must be
    // drained through closeAll in the current process, not left for restart.
    const signalDrain = installReleasePilotSignalDrainV1();
    let manifestWatcher;
    try {
      const signalObserved = new Promise((resolve) => {
        manifestWatcher = watch(value.privateRunRoot, (_event, filename) => {
          if (filename?.toString() !== RELEASE_RUNTIME_OWNER_MANIFEST_FILE_V1) return;
          manifestWatcher.close();
          process.kill(process.pid, "SIGTERM");
          resolve();
        });
      });
      await assert.rejects(
        prepareReleaseRuntimeOciResourcesV1({
          cancellationAuthority: signalDrain.cancellationAuthority,
          plan,
          cases: value.cases,
          orchestrationOwnerId: "abcdefabcdefabcdefabcdefabcdefab",
          privateRunRoot: value.privateRunRoot,
          ociExecutablePath: TRUSTED_DOCKER_PATH,
          runtimeImageReference: image.reference,
          trustRootPublicKeyPath: await realpath(path.join(
            authorityRoot,
            "root-public.pem",
          )),
          cellPolicyCommands: commands,
          sdkClientAuthority,
        }),
        /aionis_eval_release_pilot_cancellation_requested/u,
      );
      await signalObserved;
      assert.equal(
        snapshotReleasePilotCancellationV1(
          signalDrain.cancellationAuthority,
        ).signal,
        "SIGTERM",
      );
      assert.deepEqual(await readdir(value.privateRunRoot), [path.basename(callerOwnedPath)]);
    } finally {
      manifestWatcher?.close();
      disposeReleasePilotSignalDrainV1(signalDrain);
    }
  });
