import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
} from "../src/canonical.mjs";

test("canonical encoding is deterministic, detached, and rejects non-data values", () => {
  const left = { z: [3, { b: true, a: "value" }], a: null };
  const right = { a: null, z: [3, { a: "value", b: true }] };
  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(canonicalSha256(left), canonicalSha256(right));
  const clone = canonicalClone(left);
  left.z[1].a = "changed";
  assert.equal(clone.z[1].a, "value");
  assert.throws(() => canonicalJson({ value: 1.5 }), /number_invalid/u);
  assert.throws(() => canonicalJson({ value: -0 }), /number_invalid/u);
  assert.throws(() => canonicalJson({ value: "\ud800" }), /invalid/u);
  const accessor = {};
  Object.defineProperty(accessor, "value", { enumerable: true, get: () => 1 });
  assert.throws(() => canonicalJson(accessor), /shape_invalid/u);
});
