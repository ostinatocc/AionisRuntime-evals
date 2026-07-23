import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  checkpointReleasePilotCancellationV1,
  commitReleasePilotFinalManifestV1,
  createReleasePilotCancellationAuthorityV1,
  releasePilotSignalExitCodeV1,
  requestReleasePilotCancellationV1,
  snapshotReleasePilotCancellationV1,
} from "../src/release-pilot-cancellation.mjs";

const cancellationModuleUrl = pathToFileURL(fileURLToPath(new URL(
  "../src/release-pilot-cancellation.mjs",
  import.meta.url,
))).href;

function waitForText(stream, expected) {
  return new Promise((resolve, reject) => {
    let text = "";
    const onData = (chunk) => {
      text += chunk.toString("utf8");
      if (text.includes(expected)) {
        stream.off("data", onData);
        resolve(text);
      }
    };
    stream.on("data", onData);
    stream.once("error", reject);
  });
}

test("cancellation authority is opaque, downgrade-only, and first-signal stable", () => {
  const authority = createReleasePilotCancellationAuthorityV1();
  assert.equal(snapshotReleasePilotCancellationV1(authority).cancellation_requested, false);
  assert.equal(snapshotReleasePilotCancellationV1(authority).final_manifest_committed, false);
  assert.equal(checkpointReleasePilotCancellationV1(authority), true);
  const first = requestReleasePilotCancellationV1(authority, { signal: "SIGTERM" });
  assert.equal(first.cancellation_requested, true);
  assert.equal(first.signal, "SIGTERM");
  const second = requestReleasePilotCancellationV1(authority, { signal: "SIGINT" });
  assert.equal(second.signal, "SIGTERM");
  assert.throws(
    () => checkpointReleasePilotCancellationV1(authority),
    /aionis_eval_release_pilot_cancellation_requested/u,
  );
  assert.throws(
    () => snapshotReleasePilotCancellationV1({ ...authority }),
    /authority_invalid/u,
  );
});

test("durable final-manifest commit is the signal and CLI-exit linearization point", () => {
  const cancelled = createReleasePilotCancellationAuthorityV1();
  requestReleasePilotCancellationV1(cancelled, { signal: "SIGTERM" });
  assert.throws(
    () => commitReleasePilotFinalManifestV1(cancelled),
    /aionis_eval_release_pilot_cancellation_requested/u,
  );
  assert.equal(releasePilotSignalExitCodeV1(cancelled), 143);

  const committed = createReleasePilotCancellationAuthorityV1();
  const commitSnapshot = commitReleasePilotFinalManifestV1(committed);
  assert.equal(commitSnapshot.final_manifest_committed, true);
  const postCommit = requestReleasePilotCancellationV1(committed, { signal: "SIGTERM" });
  assert.equal(postCommit.cancellation_requested, false);
  assert.equal(postCommit.signal, null);
  assert.equal(postCommit.post_commit_signal, "SIGTERM");
  assert.equal(releasePilotSignalExitCodeV1(committed), null);
  assert.equal(checkpointReleasePilotCancellationV1(committed), true);
});

test("real SIGTERM requests drain and does not exit from the signal handler", async () => {
  const source = `
    import {
      disposeReleasePilotSignalDrainV1,
      installReleasePilotSignalDrainV1,
      snapshotReleasePilotCancellationV1,
    } from ${JSON.stringify(cancellationModuleUrl)};
    const drain = installReleasePilotSignalDrainV1();
    process.stdout.write("ready\\n");
    while (!snapshotReleasePilotCancellationV1(
      drain.cancellationAuthority,
    ).cancellation_requested) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    process.stdout.write("cancellation-observed\\n");
    await new Promise((resolve) => setTimeout(resolve, 150));
    const snapshot = disposeReleasePilotSignalDrainV1(drain);
    process.stdout.write("drain-complete:" + snapshot.signal + "\\n");
    process.exitCode = 143;
  `;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", source], {
    cwd: "/",
    env: { LANG: "C", LC_ALL: "C", TZ: "UTC" },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  await waitForText(child.stdout, "ready\n");
  const signaledAt = Date.now();
  assert.equal(child.kill("SIGTERM"), true);
  const [exitCode, signal] = await once(child, "close");
  const output = Buffer.concat(stdout).toString("utf8");
  assert.equal(signal, null);
  assert.equal(exitCode, 143);
  assert.match(output, /cancellation-observed\n/u);
  assert.match(output, /drain-complete:SIGTERM\n/u);
  assert.ok(Date.now() - signaledAt >= 100, "handler must wait for drain completion");
  assert.equal(Buffer.concat(stderr).toString("utf8"), "");
});

test("real SIGTERM after final commit drains without changing successful exit", async () => {
  const source = `
    import {
      commitReleasePilotFinalManifestV1,
      disposeReleasePilotSignalDrainV1,
      installReleasePilotSignalDrainV1,
      releasePilotSignalExitCodeV1,
      snapshotReleasePilotCancellationV1,
    } from ${JSON.stringify(cancellationModuleUrl)};
    const drain = installReleasePilotSignalDrainV1();
    commitReleasePilotFinalManifestV1(drain.cancellationAuthority);
    process.stdout.write("committed\\n");
    while (snapshotReleasePilotCancellationV1(
      drain.cancellationAuthority,
    ).post_commit_signal === null) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    const snapshot = disposeReleasePilotSignalDrainV1(drain);
    process.stdout.write("post-commit:" + snapshot.post_commit_signal + "\\n");
    process.exitCode = releasePilotSignalExitCodeV1(
      drain.cancellationAuthority,
    ) ?? 0;
  `;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", source], {
    cwd: "/",
    env: { LANG: "C", LC_ALL: "C", TZ: "UTC" },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  await waitForText(child.stdout, "committed\n");
  assert.equal(child.kill("SIGTERM"), true);
  const [exitCode, signal] = await once(child, "close");
  const output = Buffer.concat(stdout).toString("utf8");
  assert.equal(signal, null);
  assert.equal(exitCode, 0);
  assert.match(output, /post-commit:SIGTERM\n/u);
  assert.equal(Buffer.concat(stderr).toString("utf8"), "");
});
