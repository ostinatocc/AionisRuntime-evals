#!/usr/bin/env node

import path from "node:path";

import { canonicalJson, expectArray } from "../canonical.mjs";
import {
  recoverReleasePilotOrphansFromCanonicalConfigV1,
} from "../release-pilot-orchestrator.mjs";
import {
  disposeReleasePilotSignalDrainV1,
  installReleasePilotSignalDrainV1,
  snapshotReleasePilotCancellationV1,
} from "../release-pilot-cancellation.mjs";

function parseArguments(value) {
  const argv = expectArray(value, "release_pilot_recovery_argv", {
    minimum: 2,
    maximum: 2,
  });
  if (argv[0] !== "--config" || typeof argv[1] !== "string"
    || argv[1].startsWith("--")) {
    throw new Error("aionis_eval_release_pilot_recovery_arguments_invalid");
  }
  return Object.freeze({ configPath: path.resolve(argv[1]) });
}

function writeStream(stream, text) {
  return new Promise((resolve, reject) => {
    stream.write(text, (error) => error ? reject(error) : resolve());
  });
}

function signalExitCode(snapshot) {
  if (snapshot.signal === "SIGINT") return 130;
  if (snapshot.signal === "SIGTERM") return 143;
  return null;
}

async function main() {
  const signalDrain = installReleasePilotSignalDrainV1();
  try {
    const result = await recoverReleasePilotOrphansFromCanonicalConfigV1(
      parseArguments(process.argv.slice(2)),
    );
    await writeStream(process.stdout, `${canonicalJson(result)}\n`);
    const exitCode = signalExitCode(snapshotReleasePilotCancellationV1(
      signalDrain.cancellationAuthority,
    ));
    if (exitCode !== null) process.exitCode = exitCode;
  } catch {
    await writeStream(process.stderr, "aionis_eval_release_pilot_recovery_failed\n");
    const exitCode = signalExitCode(snapshotReleasePilotCancellationV1(
      signalDrain.cancellationAuthority,
    ));
    process.exitCode = exitCode ?? 1;
  } finally {
    disposeReleasePilotSignalDrainV1(signalDrain);
  }
}

main().catch(async () => {
  await writeStream(
    process.stderr,
    "aionis_eval_release_pilot_recovery_failed\n",
  ).catch(() => {});
  process.exitCode = 1;
});
