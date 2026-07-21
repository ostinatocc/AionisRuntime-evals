import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

export const EVIDENCE_CAS_MAX_BYTES = 8 * 1024 * 1024;

const SHA256_RE = /^[a-f0-9]{64}$/;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const EVIDENCE_DIRECTORY = "evidence";
const HASH_DIRECTORY = "sha256";
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const JSON_NUMBER_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u;

function fail(message) {
  throw new Error(message);
}

function assertPlainObject(value, field) {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) fail(`${field} must be a plain object`);
}

function assertExactKeys(value, keys, field) {
  assertPlainObject(value, field);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${field} keys must be exactly ${expected.join(", ")}`);
  }
}

function exactMode(stat, mode, field) {
  if ((stat.mode & 0o777) !== mode) fail(`${field} permissions must be ${mode.toString(8)}`);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requiredRoot(value) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || value.includes("\0")) {
    fail("campaignRoot must be a non-empty trimmed path");
  }
  return path.resolve(value);
}

class StrictJsonParser {
  constructor(source, field) {
    this.source = source;
    this.field = field;
    this.index = 0;
  }

  error(message) {
    fail(`${this.field} must be valid JSON: ${message} at character ${this.index}`);
  }

  whitespace() {
    while (/^[\u0009\u000a\u000d\u0020]$/u.test(this.source[this.index] ?? "")) this.index += 1;
  }

  parse() {
    this.whitespace();
    if (this.index === this.source.length) this.error("document is empty");
    const value = this.value(0);
    this.whitespace();
    if (this.index !== this.source.length) this.error("document contains trailing data");
    return value;
  }

  value(depth) {
    if (depth > 128) this.error("document exceeds the maximum nesting depth");
    const token = this.source[this.index];
    if (token === "{") return this.object(depth + 1);
    if (token === "[") return this.array(depth + 1);
    if (token === '"') return this.string();
    if (this.source.startsWith("true", this.index)) {
      this.index += 4;
      return true;
    }
    if (this.source.startsWith("false", this.index)) {
      this.index += 5;
      return false;
    }
    if (this.source.startsWith("null", this.index)) {
      this.index += 4;
      return null;
    }
    const number = JSON_NUMBER_RE.exec(this.source.slice(this.index));
    if (number) {
      this.index += number[0].length;
      return JSON.parse(number[0]);
    }
    this.error("value is invalid");
  }

  string() {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const token = this.source[this.index];
      if (token === '"') {
        this.index += 1;
        try {
          return JSON.parse(this.source.slice(start, this.index));
        } catch (error) {
          this.error(error.message);
        }
      }
      if (token === "\\") {
        this.index += 2;
      } else {
        this.index += 1;
      }
    }
    this.error("string is unterminated");
  }

  object(depth) {
    const value = {};
    const keys = new Set();
    this.index += 1;
    this.whitespace();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return value;
    }
    while (true) {
      if (this.source[this.index] !== '"') this.error("object key must be a string");
      const key = this.string();
      if (keys.has(key)) fail(`${this.field} contains duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.whitespace();
      if (this.source[this.index] !== ":") this.error("object key is missing a colon");
      this.index += 1;
      this.whitespace();
      Object.defineProperty(value, key, {
        value: this.value(depth),
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.whitespace();
      const separator = this.source[this.index];
      if (separator === "}") {
        this.index += 1;
        return value;
      }
      if (separator !== ",") this.error("object entry is missing a separator");
      this.index += 1;
      this.whitespace();
    }
  }

  array(depth) {
    const value = [];
    this.index += 1;
    this.whitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return value;
    }
    while (true) {
      value.push(this.value(depth));
      this.whitespace();
      const separator = this.source[this.index];
      if (separator === "]") {
        this.index += 1;
        return value;
      }
      if (separator !== ",") this.error("array entry is missing a separator");
      this.index += 1;
      this.whitespace();
    }
  }
}

function lstatIfPresent(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function syncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function ensurePrivateDirectory(directory, field, { create, parent } = {}) {
  let stat = lstatIfPresent(directory);
  if (!stat) {
    if (!create) fail(`${field} does not exist`);
    try {
      fs.mkdirSync(directory, { mode: DIRECTORY_MODE });
      fs.chmodSync(directory, DIRECTORY_MODE);
      if (parent) syncDirectory(parent);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
    stat = lstatIfPresent(directory);
  }
  if (!stat || stat.isSymbolicLink() || !stat.isDirectory()) {
    fail(`${field} must be a real non-symlink directory`);
  }
  exactMode(stat, DIRECTORY_MODE, field);
}

function ensureCasLayout(campaignRoot, create) {
  const root = requiredRoot(campaignRoot);
  ensurePrivateDirectory(root, "campaign root", {
    create,
    parent: create ? path.dirname(root) : undefined,
  });
  const evidence = path.join(root, EVIDENCE_DIRECTORY);
  ensurePrivateDirectory(evidence, "evidence directory", { create, parent: root });
  const sha256 = path.join(evidence, HASH_DIRECTORY);
  ensurePrivateDirectory(sha256, "evidence SHA-256 directory", { create, parent: evidence });
  return { root, evidence, sha256 };
}

function validateJsonBytes(value, field) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    fail(`${field} must be supplied as Buffer or Uint8Array`);
  }
  const bytes = Buffer.from(value);
  if (bytes.length < 1 || bytes.length > EVIDENCE_CAS_MAX_BYTES) {
    fail(`${field} size must be between 1 byte and 8 MiB`);
  }
  if (bytes.length >= UTF8_BOM.length && bytes.subarray(0, UTF8_BOM.length).equals(UTF8_BOM)) {
    fail(`${field} must not contain a UTF-8 BOM`);
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${field} must be valid UTF-8`);
  }
  const parsed = new StrictJsonParser(source, field).parse();
  return { bytes, value: parsed };
}

export function parseStrictJsonBytes(value, field = "JSON body") {
  return validateJsonBytes(value, field);
}

function casPath(sha256) {
  return `${EVIDENCE_DIRECTORY}/${HASH_DIRECTORY}/${sha256}`;
}

export function validateEvidenceCasRef(ref) {
  assertExactKeys(ref, ["sha256", "bytes", "cas_path"], "evidence CAS ref");
  if (!SHA256_RE.test(ref.sha256 ?? "")) fail("evidence CAS ref sha256 must be a lowercase SHA-256");
  if (!Number.isSafeInteger(ref.bytes) || ref.bytes < 1 || ref.bytes > EVIDENCE_CAS_MAX_BYTES) {
    fail("evidence CAS ref bytes must be an integer between 1 and 8 MiB");
  }
  const expectedPath = casPath(ref.sha256);
  if (ref.cas_path !== expectedPath) fail("evidence CAS ref cas_path must be derived from sha256");
  return { sha256: ref.sha256, bytes: ref.bytes, cas_path: expectedPath };
}

function filePath(layout, sha256) {
  return path.join(layout.sha256, sha256);
}

function readVerifiedFile(layout, ref, expectedBytes) {
  const target = filePath(layout, ref.sha256);
  const before = lstatIfPresent(target);
  if (!before) fail("evidence CAS object does not exist");
  if (before.isSymbolicLink() || !before.isFile()) {
    fail("evidence CAS object must be a regular non-symlink file");
  }
  exactMode(before, FILE_MODE, "evidence CAS object");
  if (before.size !== ref.bytes) fail("evidence CAS object size mismatch");

  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile()) fail("evidence CAS object must remain a regular file");
    exactMode(opened, FILE_MODE, "evidence CAS object");
    if (opened.size !== ref.bytes) fail("evidence CAS object size mismatch");
    const bytes = fs.readFileSync(descriptor);
    if (bytes.length !== ref.bytes) fail("evidence CAS object size mismatch");
    if (digest(bytes) !== ref.sha256) fail("evidence CAS object SHA-256 mismatch");
    if (expectedBytes && !bytes.equals(expectedBytes)) fail("existing evidence CAS object bytes mismatch");
    validateJsonBytes(bytes, "evidence CAS object");

    const after = fs.lstatSync(target);
    if (
      after.isSymbolicLink()
      || !after.isFile()
      || after.dev !== opened.dev
      || after.ino !== opened.ino
    ) fail("evidence CAS object changed during verification");
    exactMode(after, FILE_MODE, "evidence CAS object");
    return bytes;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function installCasObject(layout, ref, bytes) {
  const target = filePath(layout, ref.sha256);
  if (lstatIfPresent(target)) {
    readVerifiedFile(layout, ref, bytes);
    syncDirectory(layout.sha256);
    return;
  }

  const temporary = path.join(
    layout.sha256,
    `.${ref.sha256}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      FILE_MODE,
    );
    fs.fchmodSync(descriptor, FILE_MODE);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    const temporaryStat = fs.fstatSync(descriptor);
    if (!temporaryStat.isFile() || temporaryStat.size !== bytes.length) {
      fail("temporary evidence CAS object was not written completely");
    }
    exactMode(temporaryStat, FILE_MODE, "temporary evidence CAS object");
    fs.closeSync(descriptor);
    descriptor = undefined;

    try {
      // Hard-link publication is atomic and no-clobber. A pathname that wins
      // the race can only be verified; it is never repaired or overwritten.
      fs.linkSync(temporary, target);
      syncDirectory(layout.sha256);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
    readVerifiedFile(layout, ref, bytes);
    syncDirectory(layout.sha256);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try {
      fs.unlinkSync(temporary);
      syncDirectory(layout.sha256);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
}

export function putEvidenceJsonBody(options) {
  assertExactKeys(options, ["campaignRoot", "body"], "put evidence CAS options");
  const { bytes } = validateJsonBytes(options.body, "evidence JSON body");
  const sha256 = digest(bytes);
  const ref = {
    sha256,
    bytes: bytes.length,
    cas_path: casPath(sha256),
  };
  const layout = ensureCasLayout(options.campaignRoot, true);
  installCasObject(layout, ref, bytes);
  return ref;
}

function loadEvidenceJsonBody(options) {
  assertExactKeys(options, ["campaignRoot", "ref"], "read evidence CAS options");
  const ref = validateEvidenceCasRef(options.ref);
  const layout = ensureCasLayout(options.campaignRoot, false);
  const bytes = readVerifiedFile(layout, ref);
  return { ref, bytes };
}

export function verifyEvidenceJsonBody(options) {
  return loadEvidenceJsonBody(options).ref;
}

export function readEvidenceJsonBody(options) {
  return loadEvidenceJsonBody(options).bytes;
}
