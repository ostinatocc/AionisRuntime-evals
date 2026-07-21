import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  EVIDENCE_CAS_MAX_BYTES,
  putEvidenceJsonBody,
  readEvidenceJsonBody,
  validateEvidenceCasRef,
  verifyEvidenceJsonBody,
} from "../src/evidence-cas.mjs";

const MODULE_URL = new URL("../src/evidence-cas.mjs", import.meta.url).href;

function fixture(t, { createCampaignRoot = true } = {}) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aionis-evidence-cas-"));
  const campaignRoot = path.join(parent, "campaign");
  if (createCampaignRoot) fs.mkdirSync(campaignRoot, { mode: 0o700 });
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return { parent, campaignRoot };
}

function mode(target) {
  return fs.lstatSync(target).mode & 0o777;
}

function casFile(campaignRoot, ref) {
  return path.join(campaignRoot, ...ref.cas_path.split("/"));
}

test("raw JSON bodies are content-addressed by exact whitespace bytes with private durable layout", (t) => {
  const { campaignRoot } = fixture(t, { createCampaignRoot: false });
  const compact = Buffer.from('{"a":1}', "utf8");
  const spaced = new Uint8Array(Buffer.from('{\n  "a": 1\n}\n', "utf8"));
  const compactRef = putEvidenceJsonBody({ campaignRoot, body: compact });
  const spacedRef = putEvidenceJsonBody({ campaignRoot, body: spaced });

  assert.notEqual(compactRef.sha256, spacedRef.sha256);
  assert.deepEqual(Object.keys(compactRef), ["sha256", "bytes", "cas_path"]);
  assert.equal(compactRef.cas_path, `evidence/sha256/${compactRef.sha256}`);
  assert.equal(spacedRef.cas_path, `evidence/sha256/${spacedRef.sha256}`);
  assert.deepEqual(readEvidenceJsonBody({ campaignRoot, ref: compactRef }), compact);
  assert.deepEqual(readEvidenceJsonBody({ campaignRoot, ref: spacedRef }), Buffer.from(spaced));
  assert.deepEqual(verifyEvidenceJsonBody({ campaignRoot, ref: compactRef }), compactRef);

  assert.equal(mode(campaignRoot), 0o700);
  assert.equal(mode(path.join(campaignRoot, "evidence")), 0o700);
  assert.equal(mode(path.join(campaignRoot, "evidence", "sha256")), 0o700);
  assert.equal(mode(casFile(campaignRoot, compactRef)), 0o600);
  assert.equal(mode(casFile(campaignRoot, spacedRef)), 0o600);
  assert.deepEqual(
    fs.readdirSync(path.join(campaignRoot, "evidence", "sha256")).sort(),
    [compactRef.sha256, spacedRef.sha256].sort(),
  );

  const inode = fs.lstatSync(casFile(campaignRoot, compactRef)).ino;
  assert.deepEqual(putEvidenceJsonBody({ campaignRoot, body: compact }), compactRef);
  assert.equal(fs.lstatSync(casFile(campaignRoot, compactRef)).ino, inode, "idempotent put must validate, not replace");
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot, body: compact, headers: { authorization: "forbidden" } }),
    /keys must be exactly/,
  );
});

test("a separate Node process verifies and reads the same durable object after restart", (t) => {
  const { campaignRoot } = fixture(t);
  const body = Buffer.from('{"restart":"durable"}\n', "utf8");
  const ref = putEvidenceJsonBody({ campaignRoot, body });
  const script = `
    const { readEvidenceJsonBody, verifyEvidenceJsonBody } = await import(process.env.MODULE_URL);
    const ref = JSON.parse(process.env.CAS_REF);
    const verified = verifyEvidenceJsonBody({ campaignRoot: process.env.CAMPAIGN_ROOT, ref });
    const bytes = readEvidenceJsonBody({ campaignRoot: process.env.CAMPAIGN_ROOT, ref });
    process.stdout.write(JSON.stringify({ verified, base64: bytes.toString("base64") }));
  `;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    env: {
      ...process.env,
      MODULE_URL,
      CAMPAIGN_ROOT: campaignRoot,
      CAS_REF: JSON.stringify(ref),
    },
  });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.deepEqual(result.verified, ref);
  assert.deepEqual(Buffer.from(result.base64, "base64"), body);
});

test("body admission enforces byte type, UTF-8, BOM, JSON, and the exact 1..8 MiB bounds", (t) => {
  const { campaignRoot } = fixture(t);
  assert.throws(() => putEvidenceJsonBody({ campaignRoot, body: "{}" }), /Buffer or Uint8Array/);
  assert.throws(() => putEvidenceJsonBody({ campaignRoot, body: Buffer.alloc(0) }), /between 1 byte and 8 MiB/);
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot, body: Buffer.alloc(EVIDENCE_CAS_MAX_BYTES + 1, 0x20) }),
    /between 1 byte and 8 MiB/,
  );
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot, body: Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]) }),
    /must not contain a UTF-8 BOM/,
  );
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot, body: Buffer.from([0xc3, 0x28]) }),
    /must be valid UTF-8/,
  );
  assert.throws(() => putEvidenceJsonBody({ campaignRoot, body: Buffer.from("{") }), /must be valid JSON/);
  assert.throws(() => putEvidenceJsonBody({ campaignRoot, body: Buffer.from(" \n\t") }), /must be valid JSON/);
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot, body: Buffer.from('{"operation_id":"first","operation_id":"second"}') }),
    /duplicate object key "operation_id"/,
  );

  const oneByte = putEvidenceJsonBody({ campaignRoot, body: Buffer.from("0") });
  assert.equal(oneByte.bytes, 1);
  const maximum = Buffer.alloc(EVIDENCE_CAS_MAX_BYTES, 0x61);
  maximum[0] = 0x22;
  maximum[maximum.length - 1] = 0x22;
  const maximumRef = putEvidenceJsonBody({ campaignRoot, body: maximum });
  assert.equal(maximumRef.bytes, EVIDENCE_CAS_MAX_BYTES);
  assert.deepEqual(readEvidenceJsonBody({ campaignRoot, ref: maximumRef }), maximum);
});

test("tampered, truncated, or permissive existing objects fail closed and are never repaired by put", (t) => {
  const { campaignRoot } = fixture(t);
  const body = Buffer.from('{"a":1}', "utf8");
  const ref = putEvidenceJsonBody({ campaignRoot, body });
  const target = casFile(campaignRoot, ref);

  fs.writeFileSync(target, Buffer.from('{"a":2}'), { mode: 0o600 });
  assert.throws(() => readEvidenceJsonBody({ campaignRoot, ref }), /SHA-256 mismatch/);
  assert.throws(() => verifyEvidenceJsonBody({ campaignRoot, ref }), /SHA-256 mismatch/);
  assert.throws(() => putEvidenceJsonBody({ campaignRoot, body }), /SHA-256 mismatch/);

  fs.writeFileSync(target, body.subarray(0, body.length - 1), { mode: 0o600 });
  assert.throws(() => readEvidenceJsonBody({ campaignRoot, ref }), /size mismatch/);
  fs.writeFileSync(target, body, { mode: 0o600 });
  fs.chmodSync(target, 0o644);
  assert.throws(() => readEvidenceJsonBody({ campaignRoot, ref }), /permissions must be 600/);
  assert.throws(() => putEvidenceJsonBody({ campaignRoot, body }), /permissions must be 600/);
});

test("a racing CAS publisher is verified and never overwritten", (t) => {
  const { campaignRoot } = fixture(t);
  const body = Buffer.from('{"race":true}', "utf8");
  const racedBody = Buffer.from('{"race":null}', "utf8");
  const originalLink = fs.linkSync;
  let racedTarget;
  fs.linkSync = function injectCompetingPublisher(source, target) {
    racedTarget = target;
    fs.writeFileSync(target, racedBody, { mode: 0o600, flag: "wx" });
    const error = new Error("simulated no-clobber race");
    error.code = "EEXIST";
    throw error;
  };
  try {
    assert.throws(
      () => putEvidenceJsonBody({ campaignRoot, body }),
      /SHA-256 mismatch/,
    );
  } finally {
    fs.linkSync = originalLink;
  }
  assert.deepEqual(fs.readFileSync(racedTarget), racedBody);
  assert.equal(
    fs.readdirSync(path.dirname(racedTarget)).some((name) => name.endsWith(".tmp")),
    false,
  );
});

test("campaign, evidence, hash, and object symlinks or permissive directories are rejected", (t) => {
  const rootFixture = fixture(t, { createCampaignRoot: false });
  const realRoot = path.join(rootFixture.parent, "real-campaign");
  fs.mkdirSync(realRoot, { mode: 0o700 });
  fs.symlinkSync(realRoot, rootFixture.campaignRoot);
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot: rootFixture.campaignRoot, body: Buffer.from("{}") }),
    /campaign root must be a real non-symlink directory/,
  );

  const evidenceFixture = fixture(t);
  const externalEvidence = path.join(evidenceFixture.parent, "external-evidence");
  fs.mkdirSync(externalEvidence, { mode: 0o700 });
  fs.symlinkSync(externalEvidence, path.join(evidenceFixture.campaignRoot, "evidence"));
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot: evidenceFixture.campaignRoot, body: Buffer.from("{}") }),
    /evidence directory must be a real non-symlink directory/,
  );

  const hashFixture = fixture(t);
  const evidence = path.join(hashFixture.campaignRoot, "evidence");
  fs.mkdirSync(evidence, { mode: 0o700 });
  const externalHash = path.join(hashFixture.parent, "external-hash");
  fs.mkdirSync(externalHash, { mode: 0o700 });
  fs.symlinkSync(externalHash, path.join(evidence, "sha256"));
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot: hashFixture.campaignRoot, body: Buffer.from("{}") }),
    /SHA-256 directory must be a real non-symlink directory/,
  );

  const objectFixture = fixture(t);
  const ref = putEvidenceJsonBody({ campaignRoot: objectFixture.campaignRoot, body: Buffer.from("{}") });
  const target = casFile(objectFixture.campaignRoot, ref);
  const externalObject = path.join(objectFixture.parent, "external-object.json");
  fs.writeFileSync(externalObject, "{}", { mode: 0o600 });
  fs.unlinkSync(target);
  fs.symlinkSync(externalObject, target);
  assert.throws(
    () => readEvidenceJsonBody({ campaignRoot: objectFixture.campaignRoot, ref }),
    /regular non-symlink file/,
  );
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot: objectFixture.campaignRoot, body: Buffer.from("{}") }),
    /regular non-symlink file/,
  );

  const modeFixture = fixture(t);
  fs.chmodSync(modeFixture.campaignRoot, 0o755);
  assert.throws(
    () => putEvidenceJsonBody({ campaignRoot: modeFixture.campaignRoot, body: Buffer.from("{}") }),
    /campaign root permissions must be 700/,
  );
  fs.chmodSync(modeFixture.campaignRoot, 0o700);
  const modeRef = putEvidenceJsonBody({ campaignRoot: modeFixture.campaignRoot, body: Buffer.from("{}") });
  fs.chmodSync(path.join(modeFixture.campaignRoot, "evidence", "sha256"), 0o755);
  assert.throws(
    () => readEvidenceJsonBody({ campaignRoot: modeFixture.campaignRoot, ref: modeRef }),
    /SHA-256 directory permissions must be 700/,
  );
  fs.chmodSync(path.join(modeFixture.campaignRoot, "evidence", "sha256"), 0o700);
  fs.chmodSync(path.join(modeFixture.campaignRoot, "evidence"), 0o755);
  assert.throws(
    () => readEvidenceJsonBody({ campaignRoot: modeFixture.campaignRoot, ref: modeRef }),
    /evidence directory permissions must be 700/,
  );
});

test("strict refs reject digest, size, path traversal, extra fields, and read-option drift", (t) => {
  const { campaignRoot, parent } = fixture(t);
  const body = Buffer.from('{"strict":true}', "utf8");
  const ref = putEvidenceJsonBody({ campaignRoot, body });
  assert.deepEqual(validateEvidenceCasRef(ref), ref);

  assert.throws(() => validateEvidenceCasRef({ ...ref, headers: {} }), /keys must be exactly/);
  assert.throws(() => validateEvidenceCasRef({ ...ref, sha256: ref.sha256.toUpperCase() }), /lowercase SHA-256/);
  assert.throws(() => validateEvidenceCasRef({ ...ref, bytes: 0 }), /bytes must be an integer/);
  assert.throws(() => validateEvidenceCasRef({ ...ref, bytes: 1.5 }), /bytes must be an integer/);
  assert.throws(() => validateEvidenceCasRef({ ...ref, cas_path: `../${ref.sha256}` }), /derived from sha256/);
  assert.throws(() => validateEvidenceCasRef({ ...ref, cas_path: path.join(parent, "outside") }), /derived from sha256/);
  assert.throws(
    () => readEvidenceJsonBody({ campaignRoot, ref, headers: {} }),
    /keys must be exactly/,
  );
  assert.throws(
    () => readEvidenceJsonBody({ campaignRoot, ref: { ...ref, bytes: ref.bytes + 1 } }),
    /size mismatch/,
  );
  assert.throws(
    () => readEvidenceJsonBody({ campaignRoot, ref: { ...ref, cas_path: `evidence/sha256/../../outside` } }),
    /derived from sha256/,
  );
  assert.equal(fs.existsSync(path.join(parent, "outside")), false);
});
