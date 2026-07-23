import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson, canonicalSha256, sha256Bytes } from "./canonical.mjs";

const MAX_STDIN_BYTES = 4 * 1024 * 1024;
const MAX_STDOUT_BYTES = 5_500_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_CLOSURE_BYTES = 64 * 1024 * 1024;
const MAX_FILES = 4_096;
const SDK_METHODS = new Set([
  "createContinuation",
  "decideAuthority",
  "readDecision",
  "recordObservations",
  "recordOutcome",
]);
const SPARSE_ENVIRONMENT_NAMES = new Set(["LANG", "LC_ALL", "TZ"]);

for (const name of Object.keys(process.env)) {
  if (!SPARSE_ENVIRONMENT_NAMES.has(name)) delete process.env[name];
}

function exactRecord(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function boundedText(value, maximumBytes) {
  return typeof value === "string" && value.length > 0
    && Buffer.byteLength(value, "utf8") <= maximumBytes
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

async function readStableFile(absolute) {
  const pathStats = await lstat(absolute, { bigint: true });
  if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1n
    || pathStats.size < 0n || pathStats.size > BigInt(MAX_FILE_BYTES)
    || (typeof process.getuid === "function" && pathStats.uid !== BigInt(process.getuid()))) {
    throw new Error("file_posture_invalid");
  }
  const handle = await open(
    absolute,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  let bytes = null;
  try {
    const before = await handle.stat({ bigint: true });
    if (!sameSnapshot(pathStats, before)) throw new Error("file_identity_changed");
    const size = Number(before.size);
    bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const read = await handle.read(bytes, offset, size - offset, offset);
      if (read.bytesRead < 1) throw new Error("file_short_read");
      offset += read.bytesRead;
    }
    const probe = Buffer.alloc(1);
    const extra = await handle.read(probe, 0, 1, size);
    probe.fill(0);
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(absolute, { bigint: true });
    if (extra.bytesRead !== 0 || !sameSnapshot(before, after)
      || !sameSnapshot(after, afterPath)) throw new Error("file_changed_during_read");
    return bytes;
  } catch (error) {
    bytes?.fill(0);
    throw error;
  } finally {
    await handle.close().catch(() => {});
  }
}

function safeRelativePath(value) {
  return boundedText(value, 255) && !value.includes("\\") && !path.posix.isAbsolute(value)
    && path.posix.normalize(value) === value
    && value.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function verifyModuleBinding(value) {
  if (!exactRecord(value, [
    "entry_relative_path",
    "entry_sha256",
    "files",
    "manifest_sha256",
    "module_closure_sha256",
    "package_root",
  ])
    || !boundedText(value.package_root, 16_384) || !path.isAbsolute(value.package_root)
    || path.normalize(value.package_root) !== value.package_root
    || !safeRelativePath(value.entry_relative_path)
    || !/^[0-9a-f]{64}$/u.test(value.entry_sha256)
    || !/^[0-9a-f]{64}$/u.test(value.manifest_sha256)
    || !/^[0-9a-f]{64}$/u.test(value.module_closure_sha256)
    || !Array.isArray(value.files) || value.files.length < 1 || value.files.length > MAX_FILES) {
    throw new Error("module_binding_invalid");
  }
  const files = value.files.map((entry) => {
    if (!exactRecord(entry, ["path", "sha256"]) || !safeRelativePath(entry.path)
      || !/^[0-9a-f]{64}$/u.test(entry.sha256)) throw new Error("module_file_invalid");
    return { path: entry.path, sha256: entry.sha256 };
  });
  const sorted = [...files].sort((left, right) =>
    Buffer.from(left.path).compare(Buffer.from(right.path)));
  if (JSON.stringify(files) !== JSON.stringify(sorted)
    || new Set(files.map((entry) => entry.path)).size !== files.length
    || !files.some((entry) => entry.path === "package.json")
    || !files.some((entry) => entry.path === value.entry_relative_path)
    || canonicalSha256({
      schema_version: "aionis_packed_sdk_module_closure_v1",
      files,
    }) !== value.module_closure_sha256) {
    throw new Error("module_file_manifest_invalid");
  }
  const byPath = new Map(files.map((entry) => [entry.path, entry.sha256]));
  if (byPath.get("package.json") !== value.manifest_sha256
    || byPath.get(value.entry_relative_path) !== value.entry_sha256) {
    throw new Error("module_entry_binding_invalid");
  }
  return Object.freeze({ ...value, files: Object.freeze(files.map(Object.freeze)) });
}

async function listFiles(root) {
  const entries = [];
  async function visit(relative) {
    const absolute = relative === "" ? root : path.join(root, relative);
    const children = await readdir(absolute, { withFileTypes: true });
    children.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const child of children) {
      if (child.isSymbolicLink() || (!child.isDirectory() && !child.isFile())) {
        throw new Error("module_entry_invalid");
      }
      const childRelative = relative === "" ? child.name : `${relative}/${child.name}`;
      if (!safeRelativePath(childRelative)) throw new Error("module_path_invalid");
      if (child.isDirectory()) await visit(childRelative);
      else {
        if (entries.length >= MAX_FILES) throw new Error("module_file_limit");
        entries.push(childRelative);
      }
    }
  }
  await visit("");
  entries.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  return entries;
}

async function verifyAndMaybeCopy(rootValue, binding, snapshotRoot = null) {
  const root = await realpath(rootValue);
  if (root !== rootValue) throw new Error("module_root_alias");
  const actualPaths = await listFiles(root);
  if (JSON.stringify(actualPaths) !== JSON.stringify(binding.files.map((entry) => entry.path))) {
    throw new Error("module_file_set_changed");
  }
  let totalBytes = 0;
  const observed = [];
  for (const expected of binding.files) {
    const bytes = await readStableFile(path.join(root, expected.path));
    try {
      totalBytes += bytes.length;
      if (totalBytes > MAX_CLOSURE_BYTES || sha256Bytes(bytes) !== expected.sha256) {
        throw new Error("module_file_hash_changed");
      }
      observed.push({ path: expected.path, sha256: expected.sha256 });
      if (snapshotRoot !== null) {
        const destination = path.join(snapshotRoot, expected.path);
        await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
        await writeFile(destination, bytes, { flag: "wx", mode: 0o400 });
      }
    } finally {
      bytes.fill(0);
    }
  }
  if (canonicalSha256({
    schema_version: "aionis_packed_sdk_module_closure_v1",
    files: observed,
  }) !== binding.module_closure_sha256) throw new Error("module_closure_changed");
}

async function withVerifiedSnapshot(bindingValue, callback) {
  const binding = verifyModuleBinding(bindingValue);
  const createdRoot = await mkdtemp(path.join(tmpdir(), "aionis-release-sdk-child-"));
  const snapshotRoot = await realpath(createdRoot);
  try {
    await verifyAndMaybeCopy(binding.package_root, binding, snapshotRoot);
    await verifyAndMaybeCopy(snapshotRoot, binding);
    const result = await callback(path.join(snapshotRoot, binding.entry_relative_path));
    await verifyAndMaybeCopy(snapshotRoot, binding);
    await verifyAndMaybeCopy(binding.package_root, binding);
    return result;
  } finally {
    await rm(snapshotRoot, { recursive: true, force: true });
  }
}

async function readRequest() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_STDIN_BYTES) throw new Error("stdin_limit");
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  try {
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length || text.includes("\u0000")) {
      throw new Error("stdin_encoding");
    }
    return JSON.parse(text);
  } finally {
    bytes.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function importSdk(entryPath) {
  const sdk = await import(pathToFileURL(entryPath).href);
  const exportNames = Object.keys(sdk).sort();
  if (JSON.stringify(exportNames) !== JSON.stringify([
    "AionisRuntimeV1ClientError", "createAionisRuntimeV1Client",
  ])
    || typeof sdk.createAionisRuntimeV1Client !== "function"
    || typeof sdk.AionisRuntimeV1ClientError !== "function") {
    throw new Error("export_surface_invalid");
  }
  return sdk;
}

function safeError(error, sdk) {
  if (error instanceof sdk.AionisRuntimeV1ClientError) {
    const kind = typeof error.kind === "string" && /^[a-z_]{1,32}$/u.test(error.kind)
      ? error.kind : "protocol";
    const code = typeof error.code === "string" && /^[A-Za-z0-9._:-]{1,256}$/u.test(error.code)
      ? error.code : "sdk_error_invalid";
    const statusCode = Number.isSafeInteger(error.statusCode)
      && error.statusCode >= 100 && error.statusCode <= 599 ? error.statusCode : null;
    const operationId = typeof error.operationId === "string"
      && /^[A-Za-z0-9._:-]{1,256}$/u.test(error.operationId) ? error.operationId : null;
    const requestId = typeof error.requestId === "string"
      && /^[A-Za-z0-9._:-]{1,256}$/u.test(error.requestId) ? error.requestId : null;
    return { kind, code, status_code: statusCode, operation_id: operationId, request_id: requestId };
  }
  return null;
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

async function execute(request) {
  if (!exactRecord(request, ["module_binding", "operation", "schema_version"])
    && !exactRecord(request, [
      "config", "input", "method", "module_binding", "operation", "schema_version",
    ])) throw new Error("request_shape_invalid");
  if (request.schema_version !== "aionis_release_sdk_child_request_v1") {
    throw new Error("request_schema_invalid");
  }
  if (request.operation === "attest") {
    if (!exactRecord(request, ["module_binding", "operation", "schema_version"])) {
      throw new Error("attest_shape_invalid");
    }
    return withVerifiedSnapshot(request.module_binding, async (entryPath) => {
      await importSdk(entryPath);
      return {
        schema_version: "aionis_release_sdk_child_response_v1",
        operation: "attest",
        status: "ok",
        export_names: ["AionisRuntimeV1ClientError", "createAionisRuntimeV1Client"],
      };
    });
  }
  if (request.operation !== "invoke"
    || !SDK_METHODS.has(request.method)
    || !exactRecord(request.config, [
      "api_key", "base_url", "request_body_limit_bytes", "response_body_limit_bytes", "timeout_ms",
    ])
    || !boundedText(request.config.api_key, 512)
    || !boundedText(request.config.base_url, 2_048)
    || request.config.timeout_ms !== 10_000
    || request.config.request_body_limit_bytes !== 1_048_576
    || request.config.response_body_limit_bytes !== 5_242_880) {
    throw new Error("invoke_request_invalid");
  }
  const apiKey = request.config.api_key;
  try {
    const response = await withVerifiedSnapshot(request.module_binding, async (entryPath) => {
      const sdk = await importSdk(entryPath);
      try {
        const client = sdk.createAionisRuntimeV1Client({
          baseUrl: request.config.base_url,
          apiKey,
          timeoutMs: request.config.timeout_ms,
          requestBodyLimitBytes: request.config.request_body_limit_bytes,
          responseBodyLimitBytes: request.config.response_body_limit_bytes,
        });
        if (client === null || typeof client !== "object" || Array.isArray(client)
          || [...SDK_METHODS].some((method) => typeof client[method] !== "function")) {
          throw new Error("client_surface_invalid");
        }
        const result = await client[request.method](request.input);
        return {
          schema_version: "aionis_release_sdk_child_response_v1",
          operation: "invoke",
          status: "ok",
          result,
        };
      } catch (error) {
        const detail = safeError(error, sdk);
        if (detail === null) throw error;
        return {
          schema_version: "aionis_release_sdk_child_response_v1",
          operation: "invoke",
          status: "sdk_error",
          error: detail,
        };
      }
    });
    if (containsSecret(response, apiKey)) throw new Error("secret_egress_forbidden");
    return response;
  } finally {
    request.config.api_key = "";
  }
}

function finish(value) {
  let encoded;
  try {
    encoded = `${canonicalJson(value)}\n`;
    if (Buffer.byteLength(encoded, "utf8") > MAX_STDOUT_BYTES) {
      encoded = `${canonicalJson({
        schema_version: "aionis_release_sdk_child_response_v1",
        operation: "protocol",
        status: "failure",
        failure_code: "output_limit",
      })}\n`;
    }
  } catch {
    encoded = `${canonicalJson({
      schema_version: "aionis_release_sdk_child_response_v1",
      operation: "protocol",
      status: "failure",
      failure_code: "result_not_canonical",
    })}\n`;
  }
  process.stdout.write(encoded, () => process.exit(0));
}

try {
  finish(await execute(await readRequest()));
} catch {
  finish({
    schema_version: "aionis_release_sdk_child_response_v1",
    operation: "protocol",
    status: "failure",
    failure_code: "child_execution_failed",
  });
}
