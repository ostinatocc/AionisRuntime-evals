import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, open, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  FINAL_SIGNER_PROCESS_CONTRACT_V1,
  attestRunnerSigningKeyFdV1,
  runSealedPilotExecutionAuthorizationSignerProcessV1,
} from "../src/final-signer-process.mjs";
import {
  runnerAuthorityPublicKeyPrincipalSha256V1,
} from "../src/runner-signature.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import {
  TEST_RUNNER_KEYS_V1,
  buildTestExecutionManifestV1,
  buildTestPilotPlanV1,
} from "./support/pilot-plan-fixture.mjs";

function fixture() {
  const verifierKeys = Array.from({ length: 3 }, () => generateKeyPairSync("ed25519"));
  const cases = verifierKeys.map((keys, index) => buildTestPilotCaseV1({
    caseId: `authorization-signer-${index + 1}`,
    verifierPublicKey: keys.publicKey,
  }));
  const plan = buildTestPilotPlanV1(cases, {
    pilotId: "pilot-formal-authorization-signer-test",
  });
  return {
    executionManifest: buildTestExecutionManifestV1(plan),
    plan,
  };
}

test("formal runner FD attests, preserves offset, and rejects a non-live eval declaration",
  async () => {
    const root = await realpath(await mkdtemp(path.join(
      os.tmpdir(),
      "aionis-authorization-signer-",
    )));
    const keyPath = path.join(root, "runner-key.der");
    const keyBytes = Buffer.from(TEST_RUNNER_KEYS_V1.privateKey.export({
      format: "der",
      type: "pkcs8",
    }));
    try {
      await writeFile(keyPath, keyBytes, { mode: 0o600 });
      await chmod(keyPath, 0o600);
      const handle = await open(keyPath, "r");
      try {
        const value = fixture();
        const expectedPrincipal = runnerAuthorityPublicKeyPrincipalSha256V1(
          TEST_RUNNER_KEYS_V1.publicKey,
        );
        const receipt = await attestRunnerSigningKeyFdV1({
          expectedPublicKeyPrincipalSha256: expectedPrincipal,
          runnerSigningKeyFd: handle.fd,
        });
        assert.equal(receipt.public_key_principal_sha256, expectedPrincipal);
        assert.equal(
          FINAL_SIGNER_PROCESS_CONTRACT_V1.formal_private_key_read_policy,
          "stable_positional_read_without_shared_offset_mutation",
        );
        assert.equal(
          FINAL_SIGNER_PROCESS_CONTRACT_V1.formal_private_key_fd_reuse_policy,
          "authorization_then_final_or_abort",
        );
        assert.equal(
          FINAL_SIGNER_PROCESS_CONTRACT_V1.release_eval_repository_recheck,
          "authorization_child_and_terminal_final_child_before_signature",
        );
        await assert.rejects(() => runSealedPilotExecutionAuthorizationSignerProcessV1({
          authorityRoot: root,
          executionManifest: value.executionManifest,
          plan: value.plan,
          runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
          runnerSigningKeyFd: handle.fd,
        }), /execution_authorization_signer_child_process_failed/u);

        const firstByte = Buffer.alloc(1);
        const read = await handle.read(firstByte, 0, 1, null);
        assert.equal(read.bytesRead, 1);
        assert.equal(firstByte[0], keyBytes[0]);
      } finally {
        await handle.close();
      }
    } finally {
      keyBytes.fill(0);
      await rm(root, { recursive: true, force: true });
    }
  });

test("formal runner FD rejects wrong authority and unsafe file posture", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-authorization-signer-reject-",
  )));
  const wrongKeys = generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "wrong-key.der");
  try {
    await writeFile(keyPath, wrongKeys.privateKey.export({
      format: "der",
      type: "pkcs8",
    }), { mode: 0o600 });
    await chmod(keyPath, 0o600);
    const handle = await open(keyPath, "r");
    try {
      await assert.rejects(() => attestRunnerSigningKeyFdV1({
        expectedPublicKeyPrincipalSha256: runnerAuthorityPublicKeyPrincipalSha256V1(
          TEST_RUNNER_KEYS_V1.publicKey,
        ),
        runnerSigningKeyFd: handle.fd,
      }), /runner_private_key_attestation_receipt_invalid/u);
    } finally {
      await handle.close();
    }

    await chmod(keyPath, 0o644);
    const unsafeHandle = await open(keyPath, "r");
    try {
      await assert.rejects(() => attestRunnerSigningKeyFdV1({
        expectedPublicKeyPrincipalSha256:
          runnerAuthorityPublicKeyPrincipalSha256V1(wrongKeys.publicKey),
        runnerSigningKeyFd: unsafeHandle.fd,
      }), /runner_signing_key_fd_mode_invalid/u);
    } finally {
      await unsafeHandle.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
