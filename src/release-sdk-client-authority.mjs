import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

import {
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { verifyPilotPlanV1 } from "./pilot-contract.mjs";

const RELEASE_SDK_AUTHORITIES = new WeakMap();
const NON_RELEASE_SDK_AUTHORITIES = new WeakMap();
const SDK_METHODS = Object.freeze([
  "createContinuation",
  "decideAuthority",
  "readDecision",
  "recordObservations",
  "recordOutcome",
]);
const SDK_CHILD_PATH = fileURLToPath(new URL("./release-sdk-child-process.mjs", import.meta.url));
const MAX_TARBALL_BYTES = 16 * 1024 * 1024;
const MAX_EXPANDED_TAR_BYTES = 64 * 1024 * 1024;
const MAX_PACKAGE_FILE_BYTES = 16 * 1024 * 1024;
const MAX_PACKAGE_CLOSURE_BYTES = 64 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 4_096;
const MAX_CHILD_STDIN_BYTES = 4 * 1024 * 1024;
const MAX_CHILD_STDOUT_BYTES = 5_500_000;
const MAX_CHILD_STDERR_BYTES = 65_536;
const CHILD_TIMEOUT_MS = 20_000;

function fail(code) {
  throw new Error(`aionis_eval_release_sdk_client_authority_${code}`);
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function tarText(bytes) {
  const nul = bytes.indexOf(0);
  const content = bytes.subarray(0, nul < 0 ? bytes.length : nul);
  if (nul >= 0 && bytes.subarray(nul).some((value) => value !== 0)) {
    fail("sdk_tarball_archive_invalid");
  }
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(content); } catch {
    fail("sdk_tarball_archive_invalid");
  }
  if (/[\u0000-\u001f\u007f]/u.test(text)) fail("sdk_tarball_archive_invalid");
  return text;
}

function tarOctal(bytes) {
  if (bytes[0] >= 0x80) fail("sdk_tarball_archive_invalid");
  const text = bytes.toString("ascii");
  if (/^[ \0]+$/u.test(text)) return 0;
  const match = /^ *([0-7]+)[ \0]*$/u.exec(text);
  if (match === null) fail("sdk_tarball_archive_invalid");
  const value = Number.parseInt(match[1], 8);
  if (!Number.isSafeInteger(value) || value < 0) fail("sdk_tarball_archive_invalid");
  return value;
}

function verifyTarChecksum(header) {
  const expected = tarOctal(header.subarray(148, 156));
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (actual !== expected) fail("sdk_tarball_archive_checksum_invalid");
}

function tarRelativePath(value, directory) {
  if (!value.startsWith("package/") || value.includes("\\")
    || (!directory && value.endsWith("/"))) fail("sdk_tarball_archive_path_invalid");
  const raw = value.slice("package/".length).replace(/\/$/u, "");
  if (raw === "" || raw.length > 255 || raw.split("/").some((part) =>
    part === "" || part === "." || part === "..")) fail("sdk_tarball_archive_path_invalid");
  const normalized = path.posix.normalize(raw);
  if (normalized !== raw || path.posix.isAbsolute(raw)) fail("sdk_tarball_archive_path_invalid");
  return raw;
}

function tarballModuleManifest(tarball) {
  if (tarball.length < 1 || tarball.length > MAX_TARBALL_BYTES) {
    fail("sdk_tarball_size_invalid");
  }
  let expanded;
  try {
    expanded = gunzipSync(tarball, { maxOutputLength: MAX_EXPANDED_TAR_BYTES });
  } catch {
    fail("sdk_tarball_archive_invalid");
  }
  const files = [];
  const archivePaths = new Set();
  let terminated = false;
  try {
    if (expanded.length < 1_024 || expanded.length % 512 !== 0) {
      fail("sdk_tarball_archive_termination_invalid");
    }
    for (let offset = 0; offset < expanded.length;) {
      if (offset + 512 > expanded.length) fail("sdk_tarball_archive_invalid");
      const header = expanded.subarray(offset, offset + 512);
      if (header.every((value) => value === 0)) {
        if (offset + 1_024 > expanded.length
          || !expanded.subarray(offset + 512, offset + 1_024).every((value) => value === 0)
          || !expanded.subarray(offset + 1_024).every((value) => value === 0)) {
          fail("sdk_tarball_archive_termination_invalid");
        }
        terminated = true;
        break;
      }
      if (files.length >= MAX_ARCHIVE_ENTRIES || archivePaths.size >= MAX_ARCHIVE_ENTRIES) {
        fail("sdk_tarball_archive_entry_limit");
      }
      verifyTarChecksum(header);
      if (!header.subarray(257, 263).equals(Buffer.from("ustar\0", "ascii"))
        || !header.subarray(263, 265).equals(Buffer.from("00", "ascii"))) {
        fail("sdk_tarball_archive_profile_invalid");
      }
      const name = tarText(header.subarray(0, 100));
      const prefix = tarText(header.subarray(345, 500));
      const archivePath = prefix === "" ? name : `${prefix}/${name}`;
      const size = tarOctal(header.subarray(124, 136));
      const mode = tarOctal(header.subarray(100, 108));
      const uid = tarOctal(header.subarray(108, 116));
      const gid = tarOctal(header.subarray(116, 124));
      tarOctal(header.subarray(136, 148));
      const type = header[156];
      const directory = type === 53;
      if ((type !== 0 && type !== 48 && !directory)
        || tarText(header.subarray(157, 257)) !== ""
        || tarText(header.subarray(265, 297)) !== ""
        || tarText(header.subarray(297, 329)) !== ""
        || tarOctal(header.subarray(329, 337)) !== 0
        || tarOctal(header.subarray(337, 345)) !== 0
        || uid !== 0 || gid !== 0
        || (directory && (size !== 0 || mode !== 0o755))
        || (!directory && mode !== 0o644 && mode !== 0o755)) {
        fail("sdk_tarball_archive_entry_invalid");
      }
      const relative = tarRelativePath(archivePath, directory);
      if (archivePaths.has(relative)) fail("sdk_tarball_archive_manifest_invalid");
      archivePaths.add(relative);
      const contentStart = offset + 512;
      const contentEnd = contentStart + size;
      const nextOffset = contentStart + Math.ceil(size / 512) * 512;
      if (contentEnd > expanded.length || nextOffset > expanded.length
        || !expanded.subarray(contentEnd, nextOffset).every((value) => value === 0)) {
        fail("sdk_tarball_archive_padding_invalid");
      }
      if (!directory) {
        files.push({
          path: relative,
          sha256: sha256Bytes(expanded.subarray(contentStart, contentEnd)),
        });
      }
      offset = nextOffset;
    }
  } finally {
    expanded.fill(0);
  }
  files.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  if (!terminated || files.length === 0 || !files.some((entry) => entry.path === "package.json")) {
    fail("sdk_tarball_archive_manifest_invalid");
  }
  return files;
}

async function readStablePrivateRegularFile(absolute, field, maximumBytes = MAX_PACKAGE_FILE_BYTES) {
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    fail(`${field}_no_follow_unsupported`);
  }
  let beforePath;
  try { beforePath = await lstat(absolute, { bigint: true }); } catch { fail(`${field}_missing`); }
  if (!beforePath.isFile() || beforePath.isSymbolicLink() || beforePath.nlink !== 1n
    || beforePath.size < 0n || beforePath.size > BigInt(maximumBytes)
    || (typeof process.getuid === "function" && beforePath.uid !== BigInt(process.getuid()))) {
    fail(`${field}_posture_invalid`);
  }
  let handle;
  try {
    handle = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    fail(`${field}_open_failed`);
  }
  let bytes = null;
  try {
    const before = await handle.stat({ bigint: true });
    if (!sameSnapshot(beforePath, before) || before.size > BigInt(maximumBytes)) {
      fail(`${field}_identity_changed`);
    }
    const size = Number(before.size);
    bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const read = await handle.read(bytes, offset, size - offset, offset);
      if (read.bytesRead < 1) fail(`${field}_short_read`);
      offset += read.bytesRead;
    }
    const probe = Buffer.alloc(1);
    const extra = await handle.read(probe, 0, 1, size);
    probe.fill(0);
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(absolute, { bigint: true });
    if (extra.bytesRead !== 0 || !sameSnapshot(before, after) || !sameSnapshot(after, afterPath)) {
      fail(`${field}_changed_during_read`);
    }
    return bytes;
  } catch (error) {
    bytes?.fill(0);
    throw error;
  } finally {
    await handle.close().catch(() => {});
  }
}

function captureClient(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || SDK_METHODS.some((method) => typeof value[method] !== "function")) {
    fail("sdk_client_surface_invalid");
  }
  return Object.freeze(Object.fromEntries(SDK_METHODS.map((method) => [
    method,
    (...args) => value[method](...args),
  ])));
}

function captureNonReleaseFactory(value) {
  if (typeof value !== "function") fail("sdk_factory_invalid");
  return async ({ apiKey, baseUrl }) => {
    const resolvedBaseUrl = expectText(baseUrl, "sdk_base_url", { maximumBytes: 2_048 });
    const resolvedApiKey = expectText(apiKey, "sdk_api_key", { maximumBytes: 512, trimmed: false });
    return captureClient(await value({
      baseUrl: resolvedBaseUrl,
      apiKey: resolvedApiKey,
      timeoutMs: 10_000,
      requestBodyLimitBytes: 1_048_576,
      responseBodyLimitBytes: 5_242_880,
    }));
  };
}

function publicHandle({ closureSha256, plan }) {
  return Object.freeze(Object.assign(Object.create(null), {
    schema_version: "aionis_release_sdk_client_authority_handle_v1",
    authority_class: "release_packed_sdk_client_authority_v1",
    claim_eligible: true,
    plan_sha256: plan.plan_sha256,
    sdk_authority_closure_sha256: closureSha256,
  }));
}

function runtimeSdkBinding(plan) {
  const binding = plan.runtime_binding;
  if (binding === null || typeof binding !== "object"
    || typeof binding.sdk_package_name !== "string"
    || typeof binding.sdk_package_version !== "string"
    || !Number.isSafeInteger(binding.sdk_entry_count)
    || binding.sdk_entry_count < 1 || binding.sdk_entry_count > MAX_ARCHIVE_ENTRIES) {
    fail("formal_plan_sdk_binding_missing");
  }
  return {
    sdk_package_name: expectText(binding.sdk_package_name, "sdk_package_name"),
    sdk_package_version: expectText(binding.sdk_package_version, "sdk_package_version"),
    sdk_entry_count: binding.sdk_entry_count,
    sdk_tgz_sha256: expectSha256(binding.sdk_tgz_sha256, "sdk_tgz_sha256"),
    sdk_tgz_sha512: expectText(binding.sdk_tgz_sha512, "sdk_tgz_sha512"),
  };
}

async function packedFileClosure(packageRoot) {
  const entries = [];
  let totalBytes = 0;
  async function visit(relative) {
    const absolute = relative === "" ? packageRoot : path.join(packageRoot, relative);
    const children = await readdir(absolute, { withFileTypes: true });
    children.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const child of children) {
      if (child.isSymbolicLink() || (!child.isDirectory() && !child.isFile())) {
        fail("sdk_package_entry_invalid");
      }
      const childRelative = relative === "" ? child.name : path.join(relative, child.name);
      const childAbsolute = path.join(packageRoot, childRelative);
      if (child.isDirectory()) await visit(childRelative);
      else {
        const bytes = await readStablePrivateRegularFile(childAbsolute, "sdk_package_file");
        totalBytes += bytes.length;
        if (totalBytes > MAX_PACKAGE_CLOSURE_BYTES || entries.length >= MAX_ARCHIVE_ENTRIES) {
          bytes.fill(0);
          fail("sdk_package_closure_limit");
        }
        entries.push({ path: childRelative, sha256: sha256Bytes(bytes) });
        bytes.fill(0);
      }
    }
  }
  await visit("");
  entries.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  return {
    files: entries,
    fileCount: entries.length,
    closureSha256: canonicalSha256({
      schema_version: "aionis_packed_sdk_module_closure_v1",
      files: entries,
    }),
  };
}

async function verifyPackedSdkModule({ consumerRoot, expected, tarballFiles }) {
  const root = expectText(consumerRoot, "sdk_consumer_root", { maximumBytes: 16_384 });
  const canonicalRoot = await realpath(root).catch(() => fail("sdk_consumer_root_missing"));
  if (canonicalRoot !== root) fail("sdk_consumer_root_alias_forbidden");
  const packageRoot = path.join(root, "node_modules", "@aionis", "continuation-sdk");
  const manifestPath = path.join(packageRoot, "package.json");
  let manifestBytes;
  let manifest;
  try {
    manifestBytes = await readStablePrivateRegularFile(manifestPath, "sdk_package_manifest", 1_048_576);
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    manifestBytes?.fill(0);
    fail("sdk_package_manifest_invalid");
  }
  const entry = manifest?.exports?.["."]?.import;
  if (manifest?.name !== expected.sdk_package_name || manifest?.private !== true
    || manifest?.version !== expected.sdk_package_version
    || typeof entry !== "string" || !entry.startsWith("./") || entry.includes("..")) {
    manifestBytes.fill(0);
    fail("sdk_package_binding_invalid");
  }
  const entryPath = path.join(packageRoot, entry);
  const canonicalEntryPath = await realpath(entryPath).catch(() => fail("sdk_entry_missing"));
  if (canonicalEntryPath !== entryPath || !entryPath.startsWith(`${packageRoot}${path.sep}`)) {
    manifestBytes.fill(0);
    fail("sdk_entry_alias_forbidden");
  }
  const entryBytes = await readStablePrivateRegularFile(entryPath, "sdk_entry");
  const moduleClosure = await packedFileClosure(packageRoot);
  const manifestSha256 = sha256Bytes(manifestBytes);
  const entrySha256 = sha256Bytes(entryBytes);
  manifestBytes.fill(0);
  entryBytes.fill(0);
  if (moduleClosure.fileCount !== expected.sdk_entry_count
    || moduleClosure.fileCount !== tarballFiles.length
    || canonicalSha256(moduleClosure.files) !== canonicalSha256(tarballFiles)) {
    fail("sdk_tarball_install_binding_invalid");
  }
  return {
    packageRoot,
    entryPath,
    entryRelativePath: entry.split("/").slice(1).join("/"),
    entrySha256,
    manifestSha256,
    moduleClosureSha256: moduleClosure.closureSha256,
  };
}

function sameModule(left, right) {
  return left.entryPath === right.entryPath
    && left.entrySha256 === right.entrySha256
    && left.manifestSha256 === right.manifestSha256
    && left.moduleClosureSha256 === right.moduleClosureSha256;
}

function sparseChildEnvironment() {
  return Object.freeze({ LANG: "C", LC_ALL: "C", TZ: "UTC" });
}

function moduleBindingForChild(state) {
  return {
    package_root: state.module.packageRoot,
    entry_relative_path: state.module.entryRelativePath,
    entry_sha256: state.module.entrySha256,
    manifest_sha256: state.module.manifestSha256,
    module_closure_sha256: state.module.moduleClosureSha256,
    files: state.tarballFiles.map((entry) => ({ ...entry })),
  };
}

function containsSecret(value, secret, seen = new Set()) {
  if (typeof value === "string") return value.includes(secret);
  if (value === null || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "string" && key.includes(secret)) return true;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor && containsSecret(descriptor.value, secret, seen)) return true;
  }
  return false;
}

async function runSdkChild(request) {
  let encoded;
  try { encoded = Buffer.from(`${canonicalJson(request)}\n`, "utf8"); } catch {
    fail("sdk_child_request_invalid");
  }
  if (encoded.length > MAX_CHILD_STDIN_BYTES) {
    encoded.fill(0);
    fail("sdk_child_input_limit");
  }
  const child = spawn(process.execPath, [SDK_CHILD_PATH], {
    cwd: "/",
    env: sparseChildEnvironment(),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let overflow = false;
  let timedOut = false;
  const result = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, CHILD_TIMEOUT_MS);
    timer.unref?.();
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_CHILD_STDOUT_BYTES) stdout.push(chunk);
      else { overflow = true; child.kill("SIGKILL"); }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAX_CHILD_STDERR_BYTES) stderr.push(chunk);
      else { overflow = true; child.kill("SIGKILL"); }
    });
    child.stdin.on("error", () => {});
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({ exitCode, signal });
    });
    child.stdin.end(encoded, () => encoded.fill(0));
  }).catch(() => {
    encoded.fill(0);
    fail("sdk_child_spawn_failed");
  });
  encoded.fill(0);
  const stdoutBuffer = Buffer.concat(stdout);
  const stderrBuffer = Buffer.concat(stderr);
  const secret = request.operation === "invoke" ? request.config.api_key : null;
  const secretBytes = secret === null ? null : Buffer.from(secret, "utf8");
  const escapedSecretBytes = secret === null
    ? null : Buffer.from(JSON.stringify(secret).slice(1, -1), "utf8");
  try {
    if (timedOut) fail("sdk_child_timeout");
    if (overflow) fail("sdk_child_output_limit");
    if (result.exitCode !== 0 || result.signal !== null || stderrBuffer.length !== 0) {
      fail("sdk_child_process_failed");
    }
    if (secretBytes !== null && (stdoutBuffer.includes(secretBytes)
      || stderrBuffer.includes(secretBytes)
      || stdoutBuffer.includes(escapedSecretBytes)
      || stderrBuffer.includes(escapedSecretBytes))) {
      fail("sdk_child_secret_egress_forbidden");
    }
    const text = stdoutBuffer.toString("utf8");
    if (!text.endsWith("\n") || text.slice(0, -1).includes("\n")) {
      fail("sdk_child_protocol_invalid");
    }
    let response;
    try { response = JSON.parse(text); } catch { fail("sdk_child_protocol_invalid"); }
    if (canonicalJson(response) !== text.slice(0, -1)) fail("sdk_child_protocol_invalid");
    if (secret !== null && containsSecret(response, secret)) {
      fail("sdk_child_secret_egress_forbidden");
    }
    return response;
  } finally {
    secretBytes?.fill(0);
    escapedSecretBytes?.fill(0);
    stdoutBuffer.fill(0);
    stderrBuffer.fill(0);
    for (const chunk of stdout) chunk.fill(0);
    for (const chunk of stderr) chunk.fill(0);
  }
}

function verifyAttestationResponse(value) {
  expectExactRecord(value, ["export_names", "operation", "schema_version", "status"],
    "sdk_child_attestation_response");
  if (value.schema_version !== "aionis_release_sdk_child_response_v1"
    || value.operation !== "attest" || value.status !== "ok"
    || JSON.stringify(value.export_names) !== JSON.stringify([
      "AionisRuntimeV1ClientError", "createAionisRuntimeV1Client",
    ])) fail("sdk_export_surface_invalid");
}

function childClientError(detail) {
  const error = new Error(`aionis_eval_release_sdk_client_authority_sdk_call_${detail.code}`);
  error.name = "AionisReleaseSdkClientError";
  Object.assign(error, {
    kind: detail.kind,
    code: detail.code,
    statusCode: detail.status_code,
    operationId: detail.operation_id,
    requestId: detail.request_id,
  });
  return error;
}

function verifyInvocationResponse(value) {
  if (value !== null && typeof value === "object" && value.status === "ok") {
    expectExactRecord(value, ["operation", "result", "schema_version", "status"],
      "sdk_child_invocation_response");
    if (value.schema_version === "aionis_release_sdk_child_response_v1"
      && value.operation === "invoke") return value.result;
  }
  if (value !== null && typeof value === "object" && value.status === "sdk_error") {
    expectExactRecord(value, ["error", "operation", "schema_version", "status"],
      "sdk_child_invocation_response");
    const detail = expectExactRecord(value.error, [
      "code", "kind", "operation_id", "request_id", "status_code",
    ], "sdk_child_invocation_error");
    if (value.schema_version !== "aionis_release_sdk_child_response_v1"
      || value.operation !== "invoke"
      || !new Set(["configuration", "aborted", "timeout", "transport", "protocol", "runtime"])
        .has(detail.kind)
      || typeof detail.code !== "string" || !/^[A-Za-z0-9._:-]{1,256}$/u.test(detail.code)
      || (detail.status_code !== null && (!Number.isSafeInteger(detail.status_code)
        || detail.status_code < 100 || detail.status_code > 599))
      || (detail.operation_id !== null && (typeof detail.operation_id !== "string"
        || !/^[A-Za-z0-9._:-]{1,256}$/u.test(detail.operation_id)))
      || (detail.request_id !== null && (typeof detail.request_id !== "string"
        || !/^[A-Za-z0-9._:-]{1,256}$/u.test(detail.request_id)))) {
      fail("sdk_child_protocol_invalid");
    }
    throw childClientError(detail);
  }
  fail("sdk_child_protocol_invalid");
}

function createFormalFactory(state) {
  return async ({ apiKey, baseUrl }) => {
    const resolvedBaseUrl = expectText(baseUrl, "sdk_base_url", { maximumBytes: 2_048 });
    const resolvedApiKey = expectText(apiKey, "sdk_api_key", { maximumBytes: 512, trimmed: false });
    const invoke = async (method, args) => {
      if (!SDK_METHODS.includes(method) || args.length !== 1) fail("sdk_method_call_invalid");
      const before = await verifyPackedSdkModule(state);
      if (!sameModule(before, state.module)) fail("sdk_module_live_binding_invalid");
      let response;
      let childError;
      try {
        response = await runSdkChild({
          schema_version: "aionis_release_sdk_child_request_v1",
          operation: "invoke",
          module_binding: moduleBindingForChild(state),
          config: {
            base_url: resolvedBaseUrl,
            api_key: resolvedApiKey,
            timeout_ms: 10_000,
            request_body_limit_bytes: 1_048_576,
            response_body_limit_bytes: 5_242_880,
          },
          method,
          input: args[0],
        });
      } catch (error) {
        childError = error;
      }
      const after = await verifyPackedSdkModule(state);
      if (!sameModule(after, state.module)) fail("sdk_module_changed_during_call");
      if (childError !== undefined) throw childError;
      return verifyInvocationResponse(response);
    };
    return Object.freeze(Object.fromEntries(SDK_METHODS.map((method) => [
      method,
      function sdkMethod(...args) { return invoke(method, args); },
    ])));
  };
}

/**
 * Verify an installed frozen SDK without importing it in the formal parent.
 * Export attestation and every later SDK method execute in a fresh one-shot
 * sparse-environment child. Secrets/config travel only in bounded stdin.
 */
export async function issueTrustedReleaseSdkClientAuthorityV1(options) {
  const input = expectExactRecord(options, [
    "consumerRoot", "plan", "sdkTarballPath",
  ], "release_sdk_authority_issuer_input");
  const plan = verifyPilotPlanV1(input.plan);
  const expected = runtimeSdkBinding(plan);
  const tarballPath = expectText(input.sdkTarballPath, "sdk_tarball_path", { maximumBytes: 16_384 });
  const tarball = await readStablePrivateRegularFile(tarballPath, "sdk_tarball", MAX_TARBALL_BYTES);
  let tarballFiles;
  try {
    const tarballSha256 = sha256Bytes(tarball);
    const tarballSha512 = createHash("sha512").update(tarball).digest("hex");
    if (tarballSha256 !== expected.sdk_tgz_sha256 || tarballSha512 !== expected.sdk_tgz_sha512) {
      fail("sdk_tarball_binding_invalid");
    }
    tarballFiles = tarballModuleManifest(tarball);
  } finally {
    tarball.fill(0);
  }
  const verificationInput = Object.freeze({
    consumerRoot: input.consumerRoot,
    expected: Object.freeze(expected),
    tarballFiles: Object.freeze(tarballFiles.map((entry) => Object.freeze({ ...entry }))),
  });
  const module = await verifyPackedSdkModule(verificationInput);
  verifyAttestationResponse(await runSdkChild({
    schema_version: "aionis_release_sdk_child_request_v1",
    operation: "attest",
    module_binding: moduleBindingForChild({ module, tarballFiles }),
  }));
  const afterAttestation = await verifyPackedSdkModule(verificationInput);
  if (!sameModule(afterAttestation, module)) fail("sdk_module_changed_during_attestation");
  const closure = canonicalSha256({
    schema_version: "aionis_release_packed_sdk_client_closure_v1",
    plan_sha256: plan.plan_sha256,
    sdk_package_name: expected.sdk_package_name,
    sdk_package_version: expected.sdk_package_version,
    sdk_entry_count: expected.sdk_entry_count,
    sdk_tgz_sha256: expected.sdk_tgz_sha256,
    sdk_tgz_sha512: expected.sdk_tgz_sha512,
    sdk_manifest_sha256: module.manifestSha256,
    sdk_entry_sha256: module.entrySha256,
    sdk_module_closure_sha256: module.moduleClosureSha256,
  });
  const state = Object.freeze({
    ...verificationInput,
    module: Object.freeze(module),
    closureSha256: closure,
    planSha256: plan.plan_sha256,
  });
  const handle = publicHandle({ closureSha256: closure, plan });
  RELEASE_SDK_AUTHORITIES.set(handle, Object.freeze({
    ...state,
    createClient: createFormalFactory(state),
  }));
  return handle;
}

/** Test-only path. Its branded handles are never accepted by the formal OCI owner. */
export function issueNonReleaseSdkClientAuthorityForTestV1(options) {
  const input = expectExactRecord(options, ["createClient", "plan"],
    "non_release_sdk_authority_issuer_input");
  const plan = verifyPilotPlanV1(input.plan);
  const handle = Object.freeze(Object.assign(Object.create(null), {
    schema_version: "aionis_non_release_sdk_client_authority_handle_v1",
    authority_class: "non_release_sdk_client_authority_v1",
    claim_eligible: false,
    plan_sha256: plan.plan_sha256,
  }));
  NON_RELEASE_SDK_AUTHORITIES.set(handle, Object.freeze({
    createClient: captureNonReleaseFactory(input.createClient),
    planSha256: plan.plan_sha256,
  }));
  return handle;
}

export function resolveReleaseSdkClientAuthorityV1(handle, { plan: planValue }) {
  const plan = verifyPilotPlanV1(planValue);
  if (handle !== null && typeof handle === "object" && NON_RELEASE_SDK_AUTHORITIES.has(handle)) {
    fail("formal_non_release_authority_forbidden");
  }
  const state = handle !== null && typeof handle === "object"
    ? RELEASE_SDK_AUTHORITIES.get(handle)
    : undefined;
  if (state === undefined) fail("brand_invalid");
  if (handle.authority_class !== "release_packed_sdk_client_authority_v1"
    || handle.claim_eligible !== true
    || handle.plan_sha256 !== plan.plan_sha256
    || state.planSha256 !== plan.plan_sha256
    || handle.sdk_authority_closure_sha256 !== state.closureSha256) {
    fail("live_binding_invalid");
  }
  return Object.freeze({ createClient: state.createClient });
}
