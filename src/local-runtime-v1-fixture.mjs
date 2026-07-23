import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
  expectPositiveInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { loadPackedContinuationSdk } from "./sdk-loader.mjs";

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const PRIVATE_TOKEN_MIN_BYTES = 32;
const PRIVATE_TOKEN_MAX_BYTES = 512;

function fail(code, details = "") {
  throw new Error(`aionis_eval_local_runtime_${code}${details === "" ? "" : `:${details.slice(0, 2_048)}`}`);
}

function retainedEnvironment(extra = {}) {
  const environment = Object.create(null);
  for (const name of ["HOME", "PATH", "SystemRoot", "TMP", "TMPDIR"]) {
    if (process.env[name] !== undefined) environment[name] = process.env[name];
  }
  return { ...environment, ...extra };
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env ?? retainedEnvironment(),
    input: options.input,
    maxBuffer: MAX_OUTPUT_BYTES,
    stdio: options.stdio,
    timeout: options.timeout ?? 180_000,
  });
  if (result.error) fail(`${options.label ?? "command"}_spawn_failed`, result.error.message);
  if (result.status !== 0) {
    fail(
      `${options.label ?? "command"}_failed`,
      `${result.signal ?? result.status}\n${result.stdout ?? ""}\n${result.stderr ?? ""}`,
    );
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function oneJsonLine(output, field) {
  const lines = output.split("\n").map((line) => line.trim()).filter(Boolean);
  const jsonLines = lines.filter((line) => line.startsWith("{") && line.endsWith("}"));
  if (jsonLines.length !== 1) fail(`${field}_json_line_invalid`);
  const value = JSON.parse(jsonLines[0]);
  if (canonicalJson(value) !== jsonLines[0]) fail(`${field}_not_canonical`);
  return value;
}

function readLock(lockPath) {
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  expectExactRecord(lock, [
    "authority_authoring_module_relative_path",
    "authority_build_closure_sha256",
    "authority_build_entrypoint",
    "authority_build_file_count",
    "authority_build_manifest_file_sha256",
    "authority_build_manifest_relative_path",
    "oci_closure_manifest_sha256",
    "oci_closure_sha256",
    "oci_image",
    "runtime_directory",
    "runtime_git_commit_sha",
    "runtime_git_tree_sha",
    "runtime_package_lock_sha256",
    "runtime_repository",
    "schema_manifest_file_sha256",
    "schema_manifest_relative_path",
    "schema_sha256",
    "schema_version",
    "sdk_entry_count",
    "sdk_package_name",
    "sdk_package_version",
    "sdk_tgz_sha256",
    "sdk_tgz_sha512",
  ], "runtime_lock");
  if (lock.schema_version !== "aionis_eval_runtime_v1_lock_v1") fail("runtime_lock_invalid");
  return lock;
}

function fileSha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function assertRuntimeBinding(runtimeRoot, lock) {
  const commit = run("git", ["rev-parse", "HEAD"], {
    cwd: runtimeRoot,
    label: "runtime_commit",
  }).stdout.trim();
  const tree = run("git", ["rev-parse", "HEAD^{tree}"], {
    cwd: runtimeRoot,
    label: "runtime_tree",
  }).stdout.trim();
  const status = run("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: runtimeRoot,
    label: "runtime_status",
  }).stdout;
  if (commit !== lock.runtime_git_commit_sha || tree !== lock.runtime_git_tree_sha
    || status !== "") fail("runtime_git_binding_mismatch");
  if (fileSha256(path.join(runtimeRoot, "package-lock.json"))
      !== lock.runtime_package_lock_sha256) fail("runtime_package_lock_mismatch");
  const schemaManifestPath = path.join(runtimeRoot, lock.schema_manifest_relative_path);
  if (fileSha256(schemaManifestPath) !== lock.schema_manifest_file_sha256) {
    fail("runtime_schema_manifest_file_mismatch");
  }
  const schemaManifest = JSON.parse(readFileSync(schemaManifestPath, "utf8"));
  if (schemaManifest.schema_sha256 !== lock.schema_sha256
    || schemaManifest.tables?.length !== 17) fail("runtime_schema_identity_mismatch");
  return { commit, tree };
}

async function reservePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address !== "object") fail("port_reservation_failed");
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return address.port;
}

function prepareSdk(runtimeRoot, root, lock) {
  const npmCache = path.join(root, "npm-cache");
  mkdirSync(npmCache, { mode: 0o700 });
  const npmEnvironment = retainedEnvironment({ npm_config_cache: npmCache });
  run("npm", ["run", "-s", "build:sdk"], {
    cwd: runtimeRoot,
    env: npmEnvironment,
    label: "runtime_sdk_build",
    timeout: 300_000,
  });
  const packDirectory = path.join(root, "sdk-pack");
  const consumer = path.join(root, "sdk-consumer");
  mkdirSync(packDirectory, { mode: 0o700 });
  mkdirSync(consumer, { mode: 0o700 });
  const report = JSON.parse(run("npm", [
    "pack", "--json", "--ignore-scripts", "--pack-destination", packDirectory,
  ], {
    cwd: path.join(runtimeRoot, "packages/sdk"),
    env: npmEnvironment,
    label: "runtime_sdk_pack",
  }).stdout);
  if (!Array.isArray(report) || report.length !== 1
    || report[0].name !== lock.sdk_package_name
    || report[0].version !== lock.sdk_package_version
    || report[0].entryCount !== lock.sdk_entry_count) fail("runtime_sdk_pack_invalid");
  const tarball = path.join(packDirectory, report[0].filename);
  if (!existsSync(tarball)) fail("runtime_sdk_tarball_missing");
  writeFileSync(path.join(consumer, "package.json"), `${JSON.stringify({
    private: true,
    type: "module",
  })}\n`, { mode: 0o600 });
  run("npm", [
    "install", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", consumer, tarball,
  ], {
    cwd: runtimeRoot,
    env: npmEnvironment,
    label: "runtime_sdk_consumer_install",
  });
  const bytes = readFileSync(tarball);
  const tarballSha256 = createHash("sha256").update(bytes).digest("hex");
  const tarballSha512 = createHash("sha512").update(bytes).digest("hex");
  if (tarballSha256 !== lock.sdk_tgz_sha256
    || tarballSha512 !== lock.sdk_tgz_sha512) {
    fail("runtime_sdk_tarball_binding_mismatch");
  }
  return {
    consumer,
    tarball,
    tarballSha256,
    tarballSha512,
  };
}

function buildAuthority(runtimeRoot, lock) {
  const built = run(process.execPath, [
    path.join(runtimeRoot, "tools/build-continuation-runtime-v1-authority.mjs"),
  ], { cwd: runtimeRoot, label: "authority_build", timeout: 300_000 });
  const event = oneJsonLine(built.stdout, "authority_build");
  expectExactRecord(event, [
    "closure_sha256", "entrypoint", "event", "file_count", "schema_version",
  ], "authority_build_event");
  if (event.schema_version !== "continuation_runtime_v1_authority_build_event_v1"
    || event.event !== "authority_build_complete") fail("authority_build_event_invalid");
  expectText(event.entrypoint, "authority_build_entrypoint");
  expectPositiveInteger(event.file_count, "authority_build_file_count");
  expectSha256(event.closure_sha256, "authority_build_closure_sha256");
  const manifestPath = path.join(
    runtimeRoot,
    ...lock.authority_build_manifest_relative_path.split("/"),
  );
  if (fileSha256(manifestPath) !== lock.authority_build_manifest_file_sha256
    || event.closure_sha256 !== lock.authority_build_closure_sha256
    || event.entrypoint !== lock.authority_build_entrypoint
    || event.file_count !== lock.authority_build_file_count) {
    fail("authority_build_lock_mismatch");
  }
  return event;
}

function authorityMaterial(runtimeRoot, root) {
  const authorityDirectory = path.join(root, "offline-authority");
  const result = run(process.execPath, [
    path.join(runtimeRoot, "tools/generate-continuation-runtime-v1-authority-keys.mjs"),
    authorityDirectory,
  ], { cwd: runtimeRoot, label: "authority_keygen" });
  const event = oneJsonLine(result.stdout, "authority_keygen");
  expectExactRecord(event, [
    "directory_mode", "effect_signer_sha256", "event", "private_file_mode",
    "public_file_mode", "schema_version", "trust_root_sha256",
  ], "authority_keygen_event");
  if (event.schema_version !== "continuation_runtime_v1_authority_key_generation_event_v1"
    || event.event !== "authority_keys_generated"
    || event.directory_mode !== "0700"
    || event.private_file_mode !== "0600"
    || event.public_file_mode !== "0600") fail("authority_keygen_event_invalid");
  expectSha256(event.trust_root_sha256, "trust_root_sha256");
  expectSha256(event.effect_signer_sha256, "effect_signer_sha256");
  return { directory: authorityDirectory, event };
}

function authoritySubject(tenantId, scope, taskFamily) {
  return canonicalSha256({
    schema_version: "continuation_authority_subject_v1",
    tenant_id: tenantId,
    scope,
    task_family: taskFamily,
  });
}

function principal(tenantId, kind, id) {
  return canonicalSha256({
    schema_version: "continuation_runtime_principal_v1",
    tenant_id: tenantId,
    principal_kind: kind,
    principal_id: id,
    authentication: "bearer_sha256_v1",
  });
}

function policyRequest(runtimeRoot, binding) {
  const template = JSON.parse(readFileSync(path.join(
    runtimeRoot,
    "docs/examples/continuation-runtime-v1-policy-bundle-authoring-request.canonical.json",
  ), "utf8"));
  Object.assign(template, {
    tenant_id: binding.tenantId,
    scope: binding.scope,
    task_family: binding.taskFamily,
    operation_id: `eval-fixture-install-${binding.cellIdentity}`,
    operator_principal_id: binding.operatorId,
  });
  for (const [draft, id] of [
    [template.compiler_policy, `eval-fixture-compiler-${binding.cellIdentity}`],
    [template.evidence_policy, `eval-fixture-evidence-${binding.cellIdentity}`],
  ]) {
    Object.assign(draft, {
      artifact_id: id,
      artifact_revision: 1,
      created_at: "2020-01-01T00:00:00.000Z",
      valid_from: "2020-01-02T00:00:00.000Z",
      expires_at: null,
    });
    draft.payload.tenant_id = binding.tenantId;
    draft.payload.authority_subject_sha256 = binding.subject;
  }
  template.compiler_policy.payload.trusted_observer_principals = {
    trusted_host_collector: [binding.hostPrincipalSha256],
    external_verifier: [],
  };
  template.evidence_policy.payload.trusted_effect_verifier_principals = [
    binding.effectSignerSha256,
  ];
  return template;
}

function signPolicy(runtimeRoot, authorityDirectory, request) {
  const privateKey = path.join(authorityDirectory, "root-private.pem");
  const descriptor = openSync(privateKey, "r");
  try {
    const result = run(process.execPath, [path.join(
      runtimeRoot,
      "dist-authority/tools/author-continuation-runtime-v1-authority.js",
    )], {
      cwd: runtimeRoot,
      label: "authority_sign",
      input: `${canonicalJson(request)}\n`,
      stdio: ["pipe", "pipe", "pipe", descriptor],
    });
    return oneJsonLine(result.stdout, "authority_sign");
  } finally {
    closeSync(descriptor);
  }
}

function provision(runtimeRoot, environment, signedPolicy) {
  const result = run(process.execPath, [path.join(
    runtimeRoot,
    "dist/runtime-v1/provisioning-entry.js",
  )], {
    cwd: runtimeRoot,
    label: "policy_provision",
    env: environment,
    input: `${canonicalJson(signedPolicy)}\n`,
  });
  const event = oneJsonLine(result.stdout, "policy_provision");
  if (event.event !== "provisioning_complete" || event.operation?.status !== "created") {
    fail("policy_provision_event_invalid");
  }
  const resultValue = event.operation?.receipt?.result;
  if (resultValue?.decision_kind !== "policy_bundle_install") {
    fail("policy_provision_result_invalid");
  }
  return resultValue;
}

async function waitReady(port, child) {
  const deadline = Date.now() + 45_000;
  let last = "not_attempted";
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      fail("daemon_exited_before_ready", String(child.exitCode ?? child.signalCode));
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/readyz`, {
        signal: AbortSignal.timeout(1_000),
      });
      const body = await response.text();
      last = `${response.status}:${body}`;
      if (response.status === 200) {
        const parsed = JSON.parse(body);
        if (parsed.schema_version === "continuation_runtime_readiness_v1"
          && parsed.status === "ready" && parsed.reason_codes?.length === 0) return;
      }
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail("daemon_readiness_timeout", last);
}

async function stopDaemon(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exit = new Promise((resolve) => {
    const onExit = (code, signal) => resolve({ code, signal });
    child.once("exit", onExit);
    if (child.exitCode !== null || child.signalCode !== null) {
      child.off("exit", onExit);
      resolve({ code: child.exitCode, signal: child.signalCode });
    }
  });
  child.kill("SIGTERM");
  const result = await Promise.race([
    exit,
    new Promise((resolve) => setTimeout(() => resolve(null), 15_000)),
  ]);
  if (result === null) {
    child.kill("SIGKILL");
    fail("daemon_shutdown_timeout");
  }
  if (result.code !== 0 || result.signal !== null) fail("daemon_shutdown_invalid");
}

function preservePrivateDirectoryPosture(directory) {
  chmodSync(directory, 0o700);
  const status = lstatSync(directory);
  if (!status.isDirectory() || status.isSymbolicLink()
    || (status.mode & 0o777) !== 0o700) fail("private_directory_posture_invalid");
}

function createPrivateDirectory(directory) {
  mkdirSync(directory, { mode: 0o700, recursive: false });
  preservePrivateDirectoryPosture(directory);
}

function writePrivateTokenFile(file, token) {
  const bytes = Buffer.from(token, "utf8");
  try {
    if (bytes.length < PRIVATE_TOKEN_MIN_BYTES || bytes.length > PRIVATE_TOKEN_MAX_BYTES
      || !/^[\x21-\x7e]+$/u.test(token)) fail("private_token_value_invalid");
    writeFileSync(file, bytes, { flag: "wx", mode: 0o600 });
    chmodSync(file, 0o600);
    const status = lstatSync(file);
    if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1
      || (status.mode & 0o777) !== 0o600 || status.size !== bytes.length
      || (typeof process.getuid === "function" && status.uid !== process.getuid())) {
      fail("private_token_file_posture_invalid");
    }
  } finally {
    bytes.fill(0);
  }
}

function preserveSqlitePosture(dataPath) {
  for (const file of [dataPath, `${dataPath}-wal`, `${dataPath}-shm`]) {
    if (!existsSync(file)) continue;
    const before = lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink()) fail("data_file_posture_invalid");
    chmodSync(file, 0o600);
    const after = lstatSync(file);
    if (!after.isFile() || after.isSymbolicLink()
      || (after.mode & 0o777) !== 0o600) fail("data_file_posture_invalid");
  }
}

function cellIdentity(config) {
  return canonicalSha256({
    schema_version: "aionis_eval_local_runtime_cell_identity_v1",
    cell_id: config.cellId,
    scope: config.scope,
    task_family: config.taskFamily,
    tenant_id: config.tenantId,
  }).slice(0, 32);
}

export async function prepareLocalRuntimeV1FixtureAuthorityV1(options) {
  const config = expectExactRecord(options, ["lockPath", "runtimeRoot"],
    "local_runtime_authority_options");
  const runtimeRoot = path.resolve(config.runtimeRoot);
  const lock = readLock(path.resolve(config.lockPath));
  const runtimeBinding = assertRuntimeBinding(runtimeRoot, lock);
  const root = mkdtempSync(path.join(tmpdir(), "aionis-eval-runtime-v1-"));
  preservePrivateDirectoryPosture(root);
  try {
    const sdkArtifact = prepareSdk(runtimeRoot, root, lock);
    const sdk = await loadPackedContinuationSdk(sdkArtifact.consumer);
    const authorityBuild = buildAuthority(runtimeRoot, lock);
    const authority = authorityMaterial(runtimeRoot, root);
    const cellsDirectory = path.join(root, "cells");
    createPrivateDirectory(cellsDirectory);
    const sharedBinding = Object.freeze({
      runtime_repository: lock.runtime_repository,
      runtime_directory: lock.runtime_directory,
      runtime_git_commit_sha: runtimeBinding.commit,
      runtime_git_tree_sha: runtimeBinding.tree,
      runtime_package_lock_sha256: lock.runtime_package_lock_sha256,
      sdk_package_name: lock.sdk_package_name,
      sdk_package_version: lock.sdk_package_version,
      sdk_entry_count: lock.sdk_entry_count,
      sdk_tgz_sha256: sdkArtifact.tarballSha256,
      sdk_tgz_sha512: sdkArtifact.tarballSha512,
      schema_manifest_relative_path: lock.schema_manifest_relative_path,
      schema_manifest_file_sha256: lock.schema_manifest_file_sha256,
      schema_sha256: lock.schema_sha256,
      oci_image: lock.oci_image,
      oci_closure_manifest_sha256: lock.oci_closure_manifest_sha256,
      oci_closure_sha256: lock.oci_closure_sha256,
      authority_build_entrypoint: authorityBuild.entrypoint,
      authority_build_file_count: authorityBuild.file_count,
      authority_build_closure_sha256: authorityBuild.closure_sha256,
      trust_root_sha256: authority.event.trust_root_sha256,
      effect_signer_sha256: authority.event.effect_signer_sha256,
    });
    const cellRecords = [];
    const usedCellIds = new Set();
    const pendingStarts = new Set();
    let ownerClosed = false;
    let ownerClosePromise = null;
    let cellOrdinal = 0;

    async function startCellInternal(cellOptions) {
      const cellConfig = expectExactRecord(cellOptions, [
        "cellId", "scope", "taskFamily", "tenantId",
      ],
        "local_runtime_cell_options");
      const cellId = expectText(cellConfig.cellId, "local_runtime_cell_id", {
        maximumBytes: 512,
      });
      const scope = expectText(cellConfig.scope, "local_runtime_cell_scope", {
        maximumBytes: 512,
      });
      const taskFamily = expectText(cellConfig.taskFamily, "local_runtime_cell_task_family", {
        maximumBytes: 512,
      });
      const tenantId = expectText(cellConfig.tenantId, "local_runtime_cell_tenant_id", {
        maximumBytes: 256,
      });
      if (ownerClosed) fail("authority_owner_closed");
      if (usedCellIds.has(cellId)) fail("cell_id_reused");
      usedCellIds.add(cellId);
      cellOrdinal += 1;
      const ordinal = cellOrdinal;
      const identity = cellIdentity({ cellId, scope, taskFamily, tenantId });
      const cellRoot = path.join(
        cellsDirectory,
        `${String(ordinal).padStart(2, "0")}-${identity}`,
      );
      let daemon = null;
      try {
        createPrivateDirectory(cellRoot);
        const dataDirectory = path.join(cellRoot, "data");
        createPrivateDirectory(dataDirectory);
        const dataPath = path.join(dataDirectory, "runtime.sqlite");
        const hostId = `host-eval-${identity}`;
        const operatorId = `operator-eval-${identity}`;
        const hostToken = randomBytes(32).toString("base64url");
        const operatorToken = randomBytes(32).toString("base64url");
        const hostTokenPath = path.join(cellRoot, "host-api-key");
        const operatorTokenPath = path.join(cellRoot, "operator-api-key");
        writePrivateTokenFile(hostTokenPath, hostToken);
        writePrivateTokenFile(operatorTokenPath, operatorToken);
        const subject = authoritySubject(tenantId, scope, taskFamily);
        const hostPrincipalSha256 = principal(tenantId, "trusted_host", hostId);
        const signedPolicy = signPolicy(runtimeRoot, authority.directory, policyRequest(runtimeRoot, {
          cellIdentity: identity,
          tenantId,
          scope,
          taskFamily,
          operatorId,
          subject,
          hostPrincipalSha256,
          effectSignerSha256: authority.event.effect_signer_sha256,
        }));
        const authorityEnvironment = retainedEnvironment({
          AIONIS_DATA_PATH: dataPath,
          AIONIS_TRUST_ROOT_PUBLIC_KEY_PATH: path.join(authority.directory, "root-public.pem"),
          AIONIS_TRUST_ROOT_SHA256: authority.event.trust_root_sha256,
        });
        const policyRefs = provision(runtimeRoot, authorityEnvironment, signedPolicy);
        preserveSqlitePosture(dataPath);
        const port = await reservePort();
        const daemonEnvironment = {
          ...authorityEnvironment,
          AIONIS_TENANT_ID: tenantId,
          AIONIS_HOST_PRINCIPAL_ID: hostId,
          AIONIS_HOST_API_KEY_FILE: hostTokenPath,
          AIONIS_OPERATOR_PRINCIPAL_ID: operatorId,
          AIONIS_OPERATOR_API_KEY_FILE: operatorTokenPath,
          AIONIS_HTTP_HOST: "127.0.0.1",
          AIONIS_HTTP_PORT: String(port),
          AIONIS_HTTP_BODY_LIMIT_BYTES: "1048576",
          AIONIS_LOG_LEVEL: "silent",
          AIONIS_SHUTDOWN_TIMEOUT_MS: "10000",
        };
        daemon = spawn(process.execPath, [path.join(
          runtimeRoot,
          "dist/runtime-v1/daemon-entry.js",
        )], {
          cwd: runtimeRoot,
          env: daemonEnvironment,
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        daemon.stdout.setEncoding("utf8");
        daemon.stderr.setEncoding("utf8");
        daemon.stdout.on("data", (chunk) => {
          stdout = `${stdout}${chunk}`.slice(-MAX_OUTPUT_BYTES);
        });
        daemon.stderr.on("data", (chunk) => {
          stderr = `${stderr}${chunk}`.slice(-MAX_OUTPUT_BYTES);
        });
        await waitReady(port, daemon);
        preserveSqlitePosture(dataPath);
        const client = sdk.createClient({
          baseUrl: `http://127.0.0.1:${port}`,
          apiKey: hostToken,
          timeoutMs: 10_000,
          requestBodyLimitBytes: 1_048_576,
          responseBodyLimitBytes: 5_242_880,
        });
        let closePromise = null;
        const record = {
          ordinal,
          async close() {
            if (closePromise !== null) return closePromise;
            closePromise = (async () => {
              try { await stopDaemon(daemon); } finally {
                rmSync(cellRoot, { recursive: true, force: true });
              }
            })();
            return closePromise;
          },
        };
        cellRecords.push(record);
        const fixture = Object.freeze({
          cellId,
          client,
          dataPath,
          scope,
          taskFamily,
          tenantId,
          binding: Object.freeze({
            ...sharedBinding,
            compiler_policy_ref: policyRefs.compiler_policy_ref,
            evidence_policy_ref: policyRefs.evidence_policy_ref,
            cohort_installed: false,
          }),
          close: record.close,
          diagnostics() {
            return Object.freeze({
              stdout_sha256: sha256Bytes(stdout),
              stderr_sha256: sha256Bytes(stderr),
            });
          },
        });
        if (ownerClosed) {
          await fixture.close();
          fail("authority_owner_closed");
        }
        return fixture;
      } catch (error) {
        try { if (daemon !== null) await stopDaemon(daemon); } catch { /* preserve original error */ }
        rmSync(cellRoot, { recursive: true, force: true });
        throw error;
      }
    }

    function startCell(cellOptions) {
      if (ownerClosed) fail("authority_owner_closed");
      const pending = startCellInternal(cellOptions);
      pendingStarts.add(pending);
      void pending.then(
        () => pendingStarts.delete(pending),
        () => pendingStarts.delete(pending),
      );
      return pending;
    }

    async function closeOwner() {
      if (ownerClosePromise !== null) return ownerClosePromise;
      ownerClosed = true;
      ownerClosePromise = (async () => {
        const errors = [];
        await Promise.allSettled([...pendingStarts]);
        const reverseCreationOrder = [...cellRecords]
          .sort((left, right) => right.ordinal - left.ordinal);
        for (const record of reverseCreationOrder) {
          try { await record.close(); } catch (error) { errors.push(error); }
        }
        try { rmSync(root, { recursive: true, force: true }); } catch (error) { errors.push(error); }
        if (errors.length > 0) {
          throw new AggregateError(errors, "aionis_eval_local_runtime_authority_close_failed");
        }
      })();
      return ownerClosePromise;
    }

    return Object.freeze({
      binding: sharedBinding,
      startCell,
      closeAll: closeOwner,
      close: closeOwner,
    });
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

export async function startLocalRuntimeV1Fixture(options) {
  const config = expectExactRecord(options, ["lockPath", "runtimeRoot", "scope", "taskFamily"],
    "local_runtime_options");
  const owner = await prepareLocalRuntimeV1FixtureAuthorityV1({
    runtimeRoot: config.runtimeRoot,
    lockPath: config.lockPath,
  });
  try {
    const fixture = await owner.startCell({
      cellId: "backward-compatible-local-runtime-fixture",
      scope: config.scope,
      taskFamily: config.taskFamily,
      tenantId: "tenant-eval-integration",
    });
    let closePromise = null;
    return Object.freeze({
      ...fixture,
      async close() {
        if (closePromise === null) closePromise = owner.close();
        return closePromise;
      },
    });
  } catch (error) {
    try { await owner.close(); } catch { /* preserve original error */ }
    throw error;
  }
}
