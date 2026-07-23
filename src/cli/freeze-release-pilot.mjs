#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";

import { canonicalJson, expectArray } from "../canonical.mjs";
import {
  freezeReleasePilotArtifactsV1,
  verifyReleasePilotFreezeBlueprintV1,
} from "../release-pilot-freezer.mjs";

function fail(code) {
  throw new Error(`aionis_eval_release_pilot_freezer_cli_${code}`);
}

function decimalFd(value) {
  if (typeof value !== "string" || !/^[3-9][0-9]*$/u.test(value)) {
    fail("root_signing_key_fd_invalid");
  }
  const fd = Number(value);
  if (!Number.isSafeInteger(fd)) fail("root_signing_key_fd_invalid");
  return fd;
}

function parseArguments(argvValue) {
  const argv = expectArray(argvValue, "release_pilot_freezer_cli_argv", {
    minimum: 6,
    maximum: 6,
  });
  const parsed = {
    blueprintPath: null,
    outputRoot: null,
    rootSigningKeyFd: null,
  };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (typeof value !== "string" || value.startsWith("--")) fail("arguments_invalid");
    if (flag === "--blueprint" && parsed.blueprintPath === null) {
      parsed.blueprintPath = path.resolve(value);
    } else if (flag === "--output" && parsed.outputRoot === null) {
      parsed.outputRoot = path.resolve(value);
    } else if (flag === "--root-signing-key-fd" && parsed.rootSigningKeyFd === null) {
      parsed.rootSigningKeyFd = decimalFd(value);
    } else {
      fail("arguments_invalid");
    }
  }
  if (Object.values(parsed).includes(null)) fail("arguments_invalid");
  return Object.freeze(parsed);
}

function assertEnvironment(environment) {
  const forbidden = new Set([
    "AIONIS_ROOT_PRIVATE_KEY",
    "AIONIS_ROOT_PRIVATE_KEY_PATH",
    "AIONIS_RUNNER_SIGNING_KEY",
    "AIONIS_RUNNER_SIGNING_KEY_PATH",
    "AIONIS_VERIFIER_PRIVATE_KEY",
    "AIONIS_VERIFIER_PRIVATE_KEY_PATH",
  ]);
  if (Object.keys(environment).some((name) => forbidden.has(name.toUpperCase()))) {
    fail("secret_environment_forbidden");
  }
}

async function readBlueprint(file) {
  const bytes = await readFile(file);
  try {
    const text = bytes.toString("utf8");
    let value;
    try { value = JSON.parse(text); } catch { fail("blueprint_json_invalid"); }
    if (text !== `${canonicalJson(value)}\n`) fail("blueprint_not_canonical");
    return verifyReleasePilotFreezeBlueprintV1(value);
  } finally {
    bytes.fill(0);
  }
}

assertEnvironment(process.env);
const args = parseArguments(process.argv.slice(2));
const evalRepositoryRoot = path.resolve(import.meta.dirname, "../..");
const result = await freezeReleasePilotArtifactsV1({
  blueprint: await readBlueprint(args.blueprintPath),
  evalRepositoryRoot,
  outputRoot: args.outputRoot,
  rootSigningKeyFd: args.rootSigningKeyFd,
});
process.stdout.write(`${canonicalJson({
  schema_version: "aionis_release_pilot_freezer_cli_result_v1",
  receipt: result.receipt,
  artifact_preflight: result.artifactPreflight,
})}\n`);
