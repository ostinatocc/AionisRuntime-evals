import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalClone,
  canonicalSha256,
} from "../src/canonical.mjs";
import {
  buildPilotCaseV1,
} from "../src/pilot-contract.mjs";
import {
  verifyAndSignPreseededPriorStateV1,
  verifyPriorEpisodeVerifiedStateEnvelopeV1,
} from "../src/prior-episode-evidence.mjs";
import {
  verifierPublicKeyPrincipalSha256V1,
} from "../src/verifier-evidence.mjs";
import {
  buildTestPilotCaseV1,
} from "./support/pilot-fixture.mjs";

function digest(label) {
  return canonicalSha256({
    schema_version: "aionis_prior_episode_evidence_test_digest_v1",
    label,
  });
}

function metrics(overrides = {}) {
  return {
    accepted_direction: null,
    action_completion: null,
    rediscovery_steps: null,
    unsafe_direct_use: null,
    wrong_branch_attention: null,
    wrong_branch_write: null,
    ...overrides,
  };
}

test("preseeded prior state is statically read in a fresh child and signed", async (t) => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-prior-state-",
  )));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "src"), { mode: 0o700 });
  await writeFile(
    path.join(root, "src", "continuation.mjs"),
    "export function selected() { return \"accepted\"; }\n",
    { mode: 0o600 },
  );
  const keys = generateKeyPairSync("ed25519");
  const configuredArgv = [
    "/usr/local/bin/node",
    "--input-type=module",
    "--eval",
    [
      'import { readFile } from "node:fs/promises";',
      'const source = await readFile(process.argv[1], "utf8");',
      'process.exitCode = source.includes("return \\"accepted\\"") ? 0 : 1;',
    ].join(" "),
    "/workspace/src/continuation.mjs",
  ];
  const envelope = await verifyAndSignPreseededPriorStateV1({
    caseId: "prior-state-case",
    episodeId: "prior-state-case-episode-1",
    observedAt: "2026-07-23T00:00:00.000Z",
    privateKey: keys.privateKey,
    seedWorkspaceSha256: digest("seed-workspace"),
    semanticClaim: {
      accepted_symbol: "selected",
      rejected_symbol: "rejected",
    },
    sourceFixtureSha256: digest("fixture"),
    sourceTaskSha256: digest("task"),
    verifiedSourceRelativePath: "src/continuation.mjs",
    verifiedWorkspacePath: root,
    checks: [{
      check_id: "static-accepted-state",
      argv: configuredArgv,
      timeout_ms: 5_000,
      output_limit_bytes: 4_096,
      metric_mapping: {
        passed: metrics({
          accepted_direction: true,
          action_completion: true,
          rediscovery_steps: 0,
          unsafe_direct_use: false,
          wrong_branch_attention: false,
          wrong_branch_write: false,
        }),
        failed: metrics({
          accepted_direction: false,
          action_completion: false,
          rediscovery_steps: 1,
          unsafe_direct_use: false,
          wrong_branch_attention: true,
          wrong_branch_write: true,
        }),
      },
    }],
  });
  const verified = verifyPriorEpisodeVerifiedStateEnvelopeV1(envelope);
  assert.equal(verified.source_kind, "preseeded_verified_state");
  assert.equal(verified.signed_evidence.verdict, "passed");
  assert.equal(
    verified.signed_evidence.verifier_process.execution_mode,
    "host_node_static_reader_subprocess_v1",
  );
  assert.equal(
    verified.signed_evidence.verifier_process.target_source_imported,
    false,
  );
  assert.equal(
    verified.signed_evidence.checks[0].configured_argv_sha256,
    canonicalSha256(configuredArgv),
  );
  assert.notEqual(
    verified.signed_evidence.checks[0].configured_argv_sha256,
    verified.signed_evidence.checks[0].executed_argv_sha256,
  );

  const tampered = canonicalClone(verified);
  tampered.signed_evidence.metrics.accepted_direction = false;
  assert.throws(
    () => verifyPriorEpisodeVerifiedStateEnvelopeV1(tampered),
    /signed_evidence_digest_invalid/u,
  );

  const forged = canonicalClone(verified);
  forged.signed_evidence.signature = `${
    forged.signed_evidence.signature.slice(0, -1)
  }${forged.signed_evidence.signature.endsWith("A") ? "B" : "A"}`;
  forged.signed_evidence_sha256 = canonicalSha256(forged.signed_evidence);
  assert.throws(
    () => verifyPriorEpisodeVerifiedStateEnvelopeV1(forged),
    /signature_invalid/u,
  );

  const wrongKeys = generateKeyPairSync("ed25519");
  const wrongKey = canonicalClone(verified);
  wrongKey.verifier_public_key_spki_der_base64url = Buffer.from(
    wrongKeys.publicKey.export({ format: "der", type: "spki" }),
  ).toString("base64url");
  assert.throws(
    () => verifyPriorEpisodeVerifiedStateEnvelopeV1(wrongKey),
    /public_key_invalid/u,
  );
});

test("pilot case binds every source hash and the prior signer to case authority", () => {
  const keys = generateKeyPairSync("ed25519");
  const pilotCase = buildTestPilotCaseV1({
    caseId: "prior-binding-case",
    verifierPrivateKey: keys.privateKey,
    verifierPublicKey: keys.publicKey,
  });
  const sourceTampered = canonicalClone(pilotCase);
  delete sourceTampered.schema_version;
  delete sourceTampered.case_sha256;
  sourceTampered.runtime_input.record_observations_body.host_task
    .source_event_sha256 = digest("wrong-source-event");
  sourceTampered.runtime_input.record_observations_body_sha256 = canonicalSha256(
    sourceTampered.runtime_input.record_observations_body,
  );
  assert.throws(
    () => buildPilotCaseV1(sourceTampered),
    /case_prior_verified_state_binding_invalid/u,
  );

  const wrongKeys = generateKeyPairSync("ed25519");
  const authorityTampered = canonicalClone(pilotCase);
  delete authorityTampered.schema_version;
  delete authorityTampered.case_sha256;
  authorityTampered.private_verifier.verifier_public_key_principal_sha256 =
    verifierPublicKeyPrincipalSha256V1(wrongKeys.publicKey);
  assert.throws(
    () => buildPilotCaseV1(authorityTampered),
    /case_prior_verified_state_binding_invalid/u,
  );
});
