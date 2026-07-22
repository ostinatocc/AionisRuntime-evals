import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
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
  expectSha256,
  sha256Bytes,
} from "./canonical.mjs";
import { loadPackedContinuationSdk } from "./sdk-loader.mjs";

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

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
  run("npm", ["run", "-s", "build:sdk"], {
    cwd: runtimeRoot,
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
    label: "runtime_sdk_pack",
  }).stdout);
  if (!Array.isArray(report) || report.length !== 1
    || report[0].entryCount !== lock.sdk_entry_count) fail("runtime_sdk_pack_invalid");
  const tarball = path.join(packDirectory, report[0].filename);
  if (!existsSync(tarball)) fail("runtime_sdk_tarball_missing");
  writeFileSync(path.join(consumer, "package.json"), `${JSON.stringify({
    private: true,
    type: "module",
  })}\n`, { mode: 0o600 });
  run("npm", [
    "install", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", consumer, tarball,
  ], { cwd: runtimeRoot, label: "runtime_sdk_consumer_install" });
  const bytes = readFileSync(tarball);
  return {
    consumer,
    tarball,
    tarballSha256: createHash("sha256").update(bytes).digest("hex"),
    tarballSha512: createHash("sha512").update(bytes).digest("hex"),
  };
}

function buildAuthority(runtimeRoot) {
  const built = run(process.execPath, [
    path.join(runtimeRoot, "tools/build-continuation-runtime-v1-authority.mjs"),
  ], { cwd: runtimeRoot, label: "authority_build", timeout: 300_000 });
  const event = oneJsonLine(built.stdout, "authority_build");
  if (event.event !== "authority_build_complete") fail("authority_build_event_invalid");
  return event;
}

function authorityMaterial(runtimeRoot, root) {
  const authorityDirectory = path.join(root, "offline-authority");
  const result = run(process.execPath, [
    path.join(runtimeRoot, "tools/generate-continuation-runtime-v1-authority-keys.mjs"),
    authorityDirectory,
  ], { cwd: runtimeRoot, label: "authority_keygen" });
  const event = oneJsonLine(result.stdout, "authority_keygen");
  if (event.event !== "authority_keys_generated") fail("authority_keygen_event_invalid");
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
    operation_id: "eval-integration-install-policy-v1",
    operator_principal_id: binding.operatorId,
  });
  for (const [draft, id] of [
    [template.compiler_policy, "eval-integration-compiler-policy"],
    [template.evidence_policy, "eval-integration-evidence-policy"],
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
    if (child.exitCode !== null) fail("daemon_exited_before_ready", String(child.exitCode));
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
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  const result = await Promise.race([
    new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal }))),
    new Promise((resolve) => setTimeout(() => resolve(null), 15_000)),
  ]);
  if (result === null) {
    child.kill("SIGKILL");
    fail("daemon_shutdown_timeout");
  }
  if (result.code !== 0 || result.signal !== null) fail("daemon_shutdown_invalid");
}

export async function startLocalRuntimeV1Fixture(options) {
  const config = expectExactRecord(options, ["lockPath", "runtimeRoot", "scope", "taskFamily"],
    "local_runtime_options");
  const runtimeRoot = path.resolve(config.runtimeRoot);
  const lock = readLock(path.resolve(config.lockPath));
  const binding = assertRuntimeBinding(runtimeRoot, lock);
  const root = mkdtempSync(path.join(tmpdir(), "aionis-eval-runtime-v1-"));
  chmodSync(root, 0o700);
  let daemon = null;
  try {
    const sdkArtifact = prepareSdk(runtimeRoot, root, lock);
    const sdk = await loadPackedContinuationSdk(sdkArtifact.consumer);
    const authorityBuild = buildAuthority(runtimeRoot);
    const authority = authorityMaterial(runtimeRoot, root);
    const dataDirectory = path.join(root, "data");
    mkdirSync(dataDirectory, { mode: 0o700 });
    const dataPath = path.join(dataDirectory, "runtime.sqlite");
    const tenantId = "tenant-eval-integration";
    const scope = config.scope;
    const taskFamily = config.taskFamily;
    const hostId = "host-eval-integration";
    const operatorId = "operator-eval-integration";
    const hostToken = randomBytes(32).toString("base64url");
    const operatorToken = randomBytes(32).toString("base64url");
    const subject = authoritySubject(tenantId, scope, taskFamily);
    const hostPrincipalSha256 = principal(tenantId, "trusted_host", hostId);
    const signedPolicy = signPolicy(runtimeRoot, authority.directory, policyRequest(runtimeRoot, {
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
    const port = await reservePort();
    const daemonEnvironment = {
      ...authorityEnvironment,
      AIONIS_TENANT_ID: tenantId,
      AIONIS_HOST_PRINCIPAL_ID: hostId,
      AIONIS_HOST_API_KEY: hostToken,
      AIONIS_OPERATOR_PRINCIPAL_ID: operatorId,
      AIONIS_OPERATOR_API_KEY: operatorToken,
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
    daemon.stdout.on("data", (chunk) => { stdout = `${stdout}${chunk}`.slice(-MAX_OUTPUT_BYTES); });
    daemon.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-MAX_OUTPUT_BYTES); });
    await waitReady(port, daemon);
    const client = sdk.createClient({
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: hostToken,
      timeoutMs: 10_000,
      requestBodyLimitBytes: 1_048_576,
      responseBodyLimitBytes: 5_242_880,
    });
    let closed = false;
    return Object.freeze({
      client,
      scope,
      taskFamily,
      tenantId,
      binding: Object.freeze({
        runtime_git_commit_sha: binding.commit,
        runtime_git_tree_sha: binding.tree,
        sdk_tgz_sha256: sdkArtifact.tarballSha256,
        sdk_tgz_sha512: sdkArtifact.tarballSha512,
        schema_manifest_file_sha256: lock.schema_manifest_file_sha256,
        schema_sha256: lock.schema_sha256,
        oci_closure_manifest_sha256: lock.oci_closure_manifest_sha256,
        oci_closure_sha256: lock.oci_closure_sha256,
        authority_build_closure_sha256: authorityBuild.closure_sha256,
        compiler_policy_ref: policyRefs.compiler_policy_ref,
        evidence_policy_ref: policyRefs.evidence_policy_ref,
        cohort_installed: false,
      }),
      async close() {
        if (closed) return;
        closed = true;
        try { await stopDaemon(daemon); } finally {
          rmSync(root, { recursive: true, force: true });
        }
      },
      diagnostics() {
        return Object.freeze({ stdout_sha256: sha256Bytes(stdout), stderr_sha256: sha256Bytes(stderr) });
      },
    });
  } catch (error) {
    try { if (daemon !== null) await stopDaemon(daemon); } catch { /* preserve original error */ }
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}
