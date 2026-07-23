#!/usr/bin/env node

import { canonicalJson } from "../canonical.mjs";
import {
  parseReleasePilotCliArgumentsV1,
  runReleasePilotFromCanonicalConfigWithCancellationV1,
} from "../release-pilot-orchestrator.mjs";
import {
  disposeReleasePilotSignalDrainV1,
  installReleasePilotSignalDrainV1,
  releasePilotSignalExitCodeV1,
} from "../release-pilot-cancellation.mjs";

function writeStream(stream, text) {
  return new Promise((resolve, reject) => {
    stream.write(text, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function main() {
  const signalDrain = installReleasePilotSignalDrainV1();
  try {
    const input = parseReleasePilotCliArgumentsV1(process.argv.slice(2), process.env);
    const result = await runReleasePilotFromCanonicalConfigWithCancellationV1(
      input,
      signalDrain.cancellationAuthority,
    );
    await writeStream(process.stdout, `${canonicalJson(result)}\n`);
    // The cancellation authority owns the final-manifest linearization state;
    // a post-commit shutdown signal cannot turn a durable success into 143.
    const exitCode = releasePilotSignalExitCodeV1(signalDrain.cancellationAuthority);
    if (exitCode !== null) process.exitCode = exitCode;
  } catch {
    // Formal stderr is intentionally constant: paths, argv, environment,
    // credentials, provider payloads, and private-key parsing errors never leak.
    await writeStream(process.stderr, "aionis_eval_release_pilot_cli_failed\n");
    const exitCode = releasePilotSignalExitCodeV1(signalDrain.cancellationAuthority);
    process.exitCode = exitCode ?? 1;
  } finally {
    disposeReleasePilotSignalDrainV1(signalDrain);
  }
}

main().catch(async () => {
  await writeStream(process.stderr, "aionis_eval_release_pilot_cli_failed\n").catch(() => {});
  process.exitCode = 1;
});
