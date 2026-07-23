#!/usr/bin/env node

import { createPrivateKey } from "node:crypto";
import { closeSync, readFileSync } from "node:fs";

import { canonicalJson } from "../canonical.mjs";
import { executePrivateVerifierChildV1 } from "../verifier-process.mjs";

const MAX_STDIN_BYTES = 4_194_304;
const MAX_KEY_BYTES = 16_384;

async function readInput() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_STDIN_BYTES) throw new Error("input_too_large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function main() {
  const input = await readInput();
  const keyBytes = readFileSync(3);
  closeSync(3);
  if (keyBytes.length === 0 || keyBytes.length > MAX_KEY_BYTES) {
    keyBytes.fill(0);
    throw new Error("key_invalid");
  }
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: keyBytes, format: "der", type: "pkcs8" });
  } finally {
    keyBytes.fill(0);
  }
  const evidence = await executePrivateVerifierChildV1(input, privateKey);
  process.stdout.write(`${canonicalJson(evidence)}\n`);
}

main().catch(() => {
  process.stderr.write("aionis_eval_private_verifier_process_failed\n");
  process.exitCode = 1;
});
