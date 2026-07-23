import { createHash } from "node:crypto";

export class CanonicalContractError extends Error {
  constructor(code) {
    super(`aionis_eval_${code}`);
    this.name = "CanonicalContractError";
    this.code = code;
  }
}

function fail(code) {
  throw new CanonicalContractError(code);
}

export function assertUnicodeScalarString(value, field = "text") {
  if (typeof value !== "string") fail(`${field}_invalid`);
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail(`${field}_invalid`);
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail(`${field}_invalid`);
    }
  }
  return value;
}

function ownDataKeys(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${field}_shape_invalid`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(`${field}_shape_invalid`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) fail(`${field}_shape_invalid`);
  for (const key of keys) {
    assertUnicodeScalarString(key, `${field}_key`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      fail(`${field}_shape_invalid`);
    }
  }
  return keys;
}

function arrayValues(value, field) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail(`${field}_shape_invalid`);
  }
  const keys = Reflect.ownKeys(value);
  const expected = new Set(["length"]);
  for (let index = 0; index < value.length; index += 1) expected.add(String(index));
  if (keys.length !== expected.size
    || keys.some((key) => typeof key !== "string" || !expected.has(key))) {
    fail(`${field}_shape_invalid`);
  }
  return value;
}

function compareUtf8(left, right) {
  return Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"));
}

function encode(value, field) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    assertUnicodeScalarString(value, field);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail(`${field}_number_invalid`);
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${arrayValues(value, field)
      .map((item, index) => encode(item, `${field}_${index}`)).join(",")}]`;
  }
  const keys = ownDataKeys(value, field).sort(compareUtf8);
  return `{${keys.map((key) => `${JSON.stringify(key)}:${encode(value[key], `${field}_${key}`)}`)
    .join(",")}}`;
}

export function canonicalJson(value) {
  return encode(value, "canonical_value");
}

export function canonicalClone(value) {
  return JSON.parse(canonicalJson(value));
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalSha256(value) {
  return sha256Bytes(Buffer.from(canonicalJson(value), "utf8"));
}

export function expectExactRecord(value, expectedKeys, field) {
  const keys = ownDataKeys(value, field);
  const expected = new Set(expectedKeys);
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) {
    fail(`${field}_shape_invalid`);
  }
  return value;
}

export function expectArray(value, field, options = {}) {
  const array = arrayValues(value, field);
  const minimum = options.minimum ?? 0;
  const maximum = options.maximum ?? Number.MAX_SAFE_INTEGER;
  if (array.length < minimum || array.length > maximum) fail(`${field}_length_invalid`);
  return array;
}

export function expectText(value, field, options = {}) {
  assertUnicodeScalarString(value, field);
  const minimumBytes = options.minimumBytes ?? 1;
  const maximumBytes = options.maximumBytes ?? 4_096;
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < minimumBytes || bytes > maximumBytes
    || (options.trimmed !== false && value !== value.trim())
    || (options.controls !== true && /[\u0000-\u001f\u007f]/u.test(value))) {
    fail(`${field}_invalid`);
  }
  return value;
}

export function expectSha256(value, field) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`${field}_invalid`);
  }
  return value;
}

export function expectPositiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${field}_invalid`);
  return value;
}

export function expectNonNegativeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${field}_invalid`);
  return value;
}

export function expectCanonicalTimestamp(value, field) {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || Number.isNaN(Date.parse(value))
    || new Date(value).toISOString() !== value) {
    fail(`${field}_invalid`);
  }
  return value;
}

export function expectSelfHash(value, hashField, field) {
  const record = expectExactRecord(value, Reflect.ownKeys(value), field);
  const expected = expectSha256(record[hashField], `${field}_${hashField}`);
  const body = Object.fromEntries(
    Object.entries(record).filter(([key]) => key !== hashField),
  );
  if (canonicalSha256(body) !== expected) fail(`${field}_${hashField}_mismatch`);
  return record;
}
