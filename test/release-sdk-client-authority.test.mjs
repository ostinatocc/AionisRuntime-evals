import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { gzipSync } from "node:zlib";
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  issueTrustedReleaseSdkClientAuthorityV1,
  issueNonReleaseSdkClientAuthorityForTestV1,
  resolveReleaseSdkClientAuthorityV1,
} from "../src/release-sdk-client-authority.mjs";
import { sha256Bytes } from "../src/canonical.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

function writeAscii(target, offset, length, value) {
  const bytes = Buffer.from(value, "ascii");
  assert.ok(bytes.length <= length);
  bytes.copy(target, offset);
}

function writeOctal(target, offset, length, value) {
  writeAscii(target, offset, length, `${value.toString(8).padStart(length - 1, "0")}\0`);
}

function tarHeader(name, size, type = "0") {
  const header = Buffer.alloc(512);
  writeAscii(header, 0, 100, name);
  writeOctal(header, 100, 8, type === "5" ? 0o755 : 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  writeAscii(header, 156, 1, type);
  writeAscii(header, 257, 6, "ustar\0");
  writeAscii(header, 263, 2, "00");
  let checksum = 0;
  for (const value of header) checksum += value;
  writeAscii(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  return header;
}

function packTar(files, options = {}) {
  const blocks = [];
  for (const [relative, text] of Object.entries(files)) {
    const content = Buffer.from(text, "utf8");
    const header = tarHeader(`package/${relative}`, content.length);
    if (options.corruptChecksumFor === relative) header[0] ^= 1;
    blocks.push(header, content, Buffer.alloc((512 - (content.length % 512)) % 512));
  }
  const zeroBlocks = options.zeroBlocks ?? 2;
  for (let index = 0; index < zeroBlocks; index += 1) blocks.push(Buffer.alloc(512));
  if (options.trailingNonzero === true) {
    const trailing = Buffer.alloc(512);
    trailing[0] = 1;
    blocks.push(trailing);
  }
  return gzipSync(Buffer.concat(blocks));
}

function packageFiles(marker) {
  return {
    "package.json": `${JSON.stringify({
      name: "@aionis/continuation-sdk",
      version: "1.0.0-alpha.1",
      private: true,
      type: "module",
      exports: { ".": { import: "./index.js" } },
    })}\n`,
    "index.js": `
import { marker } from "./marker.js";
export class AionisRuntimeV1ClientError extends Error {}
export function createAionisRuntimeV1Client(config) {
  const methods = ["createContinuation", "decideAuthority", "readDecision", "recordObservations", "recordOutcome"];
  return Object.freeze(Object.fromEntries(methods.map((method) => [method, async (input) => ({
    marker, method, input, pid: process.pid, argv: [...process.argv], env: { ...process.env },
    received_base_url: config.baseUrl,
    ...(marker === "LEAK" ? { forbidden_echo: config.apiKey } : {}),
  })])));
}
`,
    "marker.js": `export const marker = ${JSON.stringify(marker)};\n`,
  };
}

async function installPackage(consumerRoot, files) {
  const packageRoot = path.join(
    consumerRoot, "node_modules", "@aionis", "continuation-sdk",
  );
  await rm(packageRoot, { recursive: true, force: true });
  await mkdir(packageRoot, { recursive: true, mode: 0o700 });
  for (const [relative, content] of Object.entries(files)) {
    const absolute = path.join(packageRoot, relative);
    await mkdir(path.dirname(absolute), { recursive: true, mode: 0o700 });
    await writeFile(absolute, content, { mode: 0o600 });
  }
}

function sdkPlan(cases, tarball, fileCount, pilotId) {
  const seed = buildTestPilotPlanV1(cases, { pilotId });
  return buildTestPilotPlanV1(cases, {
    pilotId,
    runtimeBinding: {
      ...seed.runtime_binding,
      sdk_entry_count: fileCount,
      sdk_tgz_sha256: sha256Bytes(tarball),
      sdk_tgz_sha512: createHash("sha512").update(tarball).digest("hex"),
    },
  });
}

async function fixture(t, marker = "A", options = {}) {
  const created = await mkdtemp(path.join(os.tmpdir(), "aionis-sdk-authority-"));
  t.after(() => rm(created, { recursive: true, force: true }));
  const root = await realpath(created);
  const consumerRoot = path.join(root, "consumer");
  await mkdir(consumerRoot, { recursive: true, mode: 0o700 });
  const files = packageFiles(marker);
  await installPackage(consumerRoot, files);
  const tarball = options.tarball ?? packTar(files, options.tarOptions);
  const sdkTarballPath = path.join(root, "sdk.tgz");
  await writeFile(sdkTarballPath, tarball, { mode: 0o600 });
  const cases = [1, 2, 3].map((index) => buildTestPilotCaseV1({
    caseId: `sdk-formal-${index}`,
    verifierPublicKey: generateKeyPairSync("ed25519").publicKey,
  }));
  return {
    root,
    consumerRoot,
    files,
    tarball,
    sdkTarballPath,
    cases,
    plan: sdkPlan(cases, tarball, Object.keys(files).length, options.pilotId ?? "sdk-child-test"),
  };
}

function client() {
  return Object.fromEntries([
    "createContinuation",
    "decideAuthority",
    "readDecision",
    "recordObservations",
    "recordOutcome",
  ].map((method) => [method, async () => ({ method })]));
}

test("formal Runtime resolver rejects non-release SDK capability before it can create a client", () => {
  const cases = [1, 2, 3].map((index) => buildTestPilotCaseV1({
    caseId: `sdk-authority-${index}`,
    verifierPublicKey: generateKeyPairSync("ed25519").publicKey,
  }));
  const plan = buildTestPilotPlanV1(cases, { pilotId: "release-sdk-authority-test" });
  let factoryCalls = 0;
  const nonRelease = issueNonReleaseSdkClientAuthorityForTestV1({
    plan,
    async createClient() {
      factoryCalls += 1;
      return client();
    },
  });
  assert.equal(nonRelease.claim_eligible, false);
  assert.throws(
    () => resolveReleaseSdkClientAuthorityV1(nonRelease, { plan }),
    /formal_non_release_authority_forbidden/u,
  );
  assert.equal(factoryCalls, 0);
});

test("formal SDK calls use a fresh sparse child and transport config only through stdin", async (t) => {
  const value = await fixture(t);
  const handle = await issueTrustedReleaseSdkClientAuthorityV1({
    consumerRoot: value.consumerRoot,
    plan: value.plan,
    sdkTarballPath: value.sdkTarballPath,
  });
  const authority = resolveReleaseSdkClientAuthorityV1(handle, { plan: value.plan });
  const secret = "k".repeat(48);
  const baseUrl = "http://127.0.0.1:34567";
  const sdk = await authority.createClient({ apiKey: secret, baseUrl });
  const first = await sdk.recordObservations({ call: 1 });
  const second = await sdk.readDecision({ call: 2 });
  assert.equal(first.marker, "A");
  assert.equal(second.marker, "A");
  assert.notEqual(first.pid, process.pid);
  assert.notEqual(second.pid, process.pid);
  assert.notEqual(first.pid, second.pid);
  assert.deepEqual(Object.keys(first.env).sort(), ["LANG", "LC_ALL", "TZ"]);
  assert.equal(JSON.stringify(first.env).includes(secret), false);
  assert.equal(JSON.stringify(first.argv).includes(secret), false);
  assert.equal(JSON.stringify(first.env).includes(baseUrl), false);
  assert.equal(JSON.stringify(first.argv).includes(baseUrl), false);
  assert.equal(first.received_base_url, baseUrl);
  assert.throws(() => process.kill(first.pid, 0), (error) => error?.code === "ESRCH");
  assert.throws(() => process.kill(second.pid, 0), (error) => error?.code === "ESRCH");
  assert.equal(JSON.stringify(handle).includes(secret), false);
});

test("same-path A to B replacement cannot reuse main-entry or relative-dependency ESM cache", async (t) => {
  const value = await fixture(t, "A", { pilotId: "sdk-cache-a" });
  const authorityAHandle = await issueTrustedReleaseSdkClientAuthorityV1({
    consumerRoot: value.consumerRoot,
    plan: value.plan,
    sdkTarballPath: value.sdkTarballPath,
  });
  const authorityA = resolveReleaseSdkClientAuthorityV1(authorityAHandle, { plan: value.plan });
  const clientA = await authorityA.createClient({
    apiKey: "a".repeat(48),
    baseUrl: "http://127.0.0.1:3001",
  });
  assert.equal((await clientA.recordOutcome({ sequence: "A" })).marker, "A");

  const filesB = packageFiles("B");
  const tarballB = packTar(filesB);
  await installPackage(value.consumerRoot, filesB);
  await writeFile(value.sdkTarballPath, tarballB, { mode: 0o600 });
  const planB = sdkPlan(value.cases, tarballB, Object.keys(filesB).length, "sdk-cache-b");
  const authorityBHandle = await issueTrustedReleaseSdkClientAuthorityV1({
    consumerRoot: value.consumerRoot,
    plan: planB,
    sdkTarballPath: value.sdkTarballPath,
  });
  const authorityB = resolveReleaseSdkClientAuthorityV1(authorityBHandle, { plan: planB });
  const clientB = await authorityB.createClient({
    apiKey: "b".repeat(48),
    baseUrl: "http://127.0.0.1:3002",
  });
  assert.equal((await clientB.createContinuation({ sequence: "B" })).marker, "B");
  await assert.rejects(
    () => clientA.recordOutcome({ sequence: "A-after-replacement" }),
    /sdk_(?:module_live_binding|tarball_install_binding)_invalid/u,
  );
});

test("SDK child blocks API-key egress before any result reaches the formal parent", async (t) => {
  const value = await fixture(t, "LEAK", { pilotId: "sdk-secret-egress" });
  const handle = await issueTrustedReleaseSdkClientAuthorityV1({
    consumerRoot: value.consumerRoot,
    plan: value.plan,
    sdkTarballPath: value.sdkTarballPath,
  });
  const sdk = await resolveReleaseSdkClientAuthorityV1(handle, { plan: value.plan })
    .createClient({ apiKey: "never-echo-this-key-material-1234567890", baseUrl: "http://127.0.0.1:3003" });
  let observed;
  await assert.rejects(
    () => sdk.recordObservations({ sequence: "leak" }),
    (error) => {
      observed = error;
      return /sdk_child_protocol_invalid/u.test(error.message);
    },
  );
  assert.equal(JSON.stringify(observed).includes("never-echo-this-key-material"), false);
  assert.equal(observed.message.includes("never-echo-this-key-material"), false);
});

test("SDK authority rejects malformed tar checksum and termination", async (t) => {
  const badChecksum = await fixture(t, "checksum", {
    tarOptions: { corruptChecksumFor: "marker.js" },
    pilotId: "sdk-bad-checksum",
  });
  await assert.rejects(
    () => issueTrustedReleaseSdkClientAuthorityV1({
      consumerRoot: badChecksum.consumerRoot,
      plan: badChecksum.plan,
      sdkTarballPath: badChecksum.sdkTarballPath,
    }),
    /sdk_tarball_archive_checksum_invalid/u,
  );

  const badTermination = await fixture(t, "termination", {
    tarOptions: { zeroBlocks: 1 },
    pilotId: "sdk-bad-termination",
  });
  await assert.rejects(
    () => issueTrustedReleaseSdkClientAuthorityV1({
      consumerRoot: badTermination.consumerRoot,
      plan: badTermination.plan,
      sdkTarballPath: badTermination.sdkTarballPath,
    }),
    /sdk_tarball_archive_termination_invalid/u,
  );
});

test("SDK authority rejects a compressed archive expanding beyond the formal bound", async (t) => {
  const expandedBomb = Buffer.alloc(64 * 1024 * 1024 + 512);
  const bomb = gzipSync(expandedBomb, { level: 9 });
  expandedBomb.fill(0);
  const value = await fixture(t, "bomb", {
    tarball: bomb,
    pilotId: "sdk-zip-bomb",
  });
  await assert.rejects(
    () => issueTrustedReleaseSdkClientAuthorityV1({
      consumerRoot: value.consumerRoot,
      plan: value.plan,
      sdkTarballPath: value.sdkTarballPath,
    }),
    /sdk_tarball_archive_invalid/u,
  );
});
