#!/usr/bin/env node

import { readFileSync } from "node:fs";
import path from "node:path";

import { canonicalJson } from "../canonical.mjs";
import { preflightPilotArtifactsV1 } from "../pilot-preflight.mjs";

function fail(code) {
  throw new Error(`aionis_eval_pilot_preflight_cli_${code}`);
}

function argumentsV1(argv) {
  let planPath = null;
  const casePaths = [];
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const candidate = argv[index + 1];
    if ((flag !== "--plan" && flag !== "--case") || candidate === undefined
      || candidate.startsWith("--")) fail("arguments_invalid");
    index += 1;
    if (flag === "--plan") {
      if (planPath !== null) fail("plan_argument_duplicate");
      planPath = path.resolve(candidate);
    } else {
      casePaths.push(path.resolve(candidate));
    }
  }
  if (planPath === null || casePaths.length !== 3
    || new Set(casePaths).size !== casePaths.length) fail("arguments_invalid");
  return { planPath, casePaths };
}

function readCanonicalArtifact(file, field) {
  const bytes = readFileSync(file, "utf8");
  if (!bytes.endsWith("\n") || bytes.slice(0, -1).includes("\n")) {
    fail(`${field}_encoding_invalid`);
  }
  const value = JSON.parse(bytes);
  if (`${canonicalJson(value)}\n` !== bytes) fail(`${field}_not_canonical`);
  return value;
}

const args = argumentsV1(process.argv.slice(2));
const report = preflightPilotArtifactsV1({
  plan: readCanonicalArtifact(args.planPath, "plan"),
  cases: args.casePaths.map((file, index) =>
    readCanonicalArtifact(file, `case_${index + 1}`)),
});
process.stdout.write(`${canonicalJson(report)}\n`);
