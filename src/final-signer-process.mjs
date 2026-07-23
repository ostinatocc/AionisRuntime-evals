import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign,
} from "node:crypto";
import { closeSync, fstatSync, readFileSync, readSync } from "node:fs";
import { spawn } from "node:child_process";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectExactRecord,
} from "./canonical.mjs";
import { verifyPilotPlanV1 } from "./pilot-contract.mjs";
import {
  buildSignedRunnerExecutionAuthorizationV1,
  buildSignedRunnerAbortManifestForSignerV1,
  runnerAuthorityPublicKeyPrincipalSha256V1,
  verifySignedRunnerExecutionAuthorizationV1,
  verifySignedRunnerAbortManifestV1,
  verifySignedRunnerFinalManifestV1,
} from "./runner-signature.mjs";
import { replayPilotRunBeforeFinalSignatureV1 } from "./sealed-pilot-run.mjs";
import { verifyReleaseEvalRepositoryProvenanceReceiptLiveV1 } from
  "./release-eval-repository-provenance.mjs";

const modulePath = fileURLToPath(import.meta.url);
const CHILD_MODE = "--sealed-final-signer-child";
const ABORT_CHILD_MODE = "--sealed-abort-signer-child";
const AUTHORIZATION_CHILD_MODE = "--sealed-execution-authorization-signer-child";
const PRIVATE_KEY_ATTESTATION_CHILD_MODE = "--runner-private-key-attestation-child";
const MAX_STDIN_BYTES = 33_554_432;
const MAX_STDOUT_BYTES = 1_048_576;
const MAX_STDERR_BYTES = 65_536;
const MAX_KEY_BYTES = 16_384;
const PROCESS_TIMEOUT_MS = 120_000;
const RELEASE_EVENT_COUNT = 58;
const FINAL_SCHEMA_VERSION = "aionis_pilot_runner_final_manifest_v1";
const FINAL_SIGNATURE_PAYLOAD_SCHEMA_VERSION =
  "aionis_pilot_runner_final_manifest_signature_payload_v1";
const PRIVATE_KEY_ATTESTATION_RECEIPT_SCHEMA_VERSION =
  "aionis_runner_private_key_attestation_receipt_v1";

const PROCESS_CONTRACT_BODY = Object.freeze({
  schema_version: "aionis_pilot_final_signer_process_contract_v1",
  process_role: "single_use_runner_authorization_or_terminal_manifest_signer",
  pre_signature_authority: "full_sealed_ledger_replay_inside_signer_process",
  authorization_pre_signature_authority:
    "live_plan_manifest_ledger_root_and_public_principal_inside_signer_process",
  release_eval_repository_authority:
    "module_fixed_commit_tree_closure_clean_and_git_identity_live_receipt_v1",
  release_eval_repository_recheck:
    "authorization_child_and_terminal_final_child_before_signature",
  caller_ledger_snapshot_policy: "forbidden",
  caller_verdict_policy: "forbidden",
  private_key_transport: "inherited_fd_3_only",
  private_key_environment_visibility: "forbidden",
  private_key_argv_visibility: "forbidden",
  private_key_artifact_persistence: "forbidden",
  formal_parent_private_key_read_policy: "forbidden",
  formal_parent_private_key_export_policy: "forbidden",
  formal_private_key_source: "caller_owned_existing_fd_mapped_directly_to_child_fd_3",
  formal_private_key_read_policy: "stable_positional_read_without_shared_offset_mutation",
  formal_private_key_fd_reuse_policy: "authorization_then_final_or_abort",
  non_release_key_object_path: "explicit_contract_test_entrypoint_only",
  release_event_count: RELEASE_EVENT_COUNT,
  shell_execution: false,
});

export const FINAL_SIGNER_PROCESS_CONTRACT_V1 = Object.freeze({
  ...PROCESS_CONTRACT_BODY,
  contract_sha256: canonicalSha256(PROCESS_CONTRACT_BODY),
});

function fail(code) {
  throw new Error(`aionis_eval_final_signer_process_${code}`);
}

function asPrivateKey(value) {
  try {
    const key = value instanceof KeyObject ? value : createPrivateKey(value);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      fail("private_key_invalid");
    }
    return key;
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_final_signer_process_")) throw error;
    fail("private_key_invalid");
  }
}

function asNonReleaseContractTestPrivateKey(value) {
  if (!(value instanceof KeyObject)) fail("non_release_private_key_object_required");
  return asPrivateKey(value);
}

function runnerSigningKeyFdStat(value) {
  if (!Number.isInteger(value) || value < 3) fail("runner_signing_key_fd_invalid");
  let stat;
  try {
    stat = fstatSync(value, { bigint: true });
  } catch {
    fail("runner_signing_key_fd_invalid");
  }
  if (!stat.isFile()) fail("runner_signing_key_fd_not_regular_file");
  if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) {
    fail("runner_signing_key_fd_owner_invalid");
  }
  if (stat.nlink !== 1n) fail("runner_signing_key_fd_link_count_invalid");
  const permissionMode = stat.mode & 0o7777n;
  if (permissionMode !== 0o400n && permissionMode !== 0o600n) {
    fail("runner_signing_key_fd_mode_invalid");
  }
  if (stat.size < 1n || stat.size > BigInt(MAX_KEY_BYTES)) {
    fail("runner_signing_key_fd_size_invalid");
  }
  return stat;
}

function sameRunnerSigningKeyFdSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid && left.gid === right.gid
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function runnerSigningKeyFd(value) {
  runnerSigningKeyFdStat(value);
  return value;
}

export function assertExistingRunnerSigningKeyFdV1(value) {
  return runnerSigningKeyFd(value);
}

function readRunnerSigningKeyFdPositionally(fd) {
  let keyBytes;
  let overflowProbe;
  try {
    const before = runnerSigningKeyFdStat(fd);
    const length = Number(before.size);
    keyBytes = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      const count = readSync(fd, keyBytes, offset, length - offset, offset);
      if (count === 0) fail("child_key_invalid");
      offset += count;
    }
    overflowProbe = Buffer.alloc(1);
    if (readSync(fd, overflowProbe, 0, 1, length) !== 0) {
      fail("child_key_invalid");
    }
    const after = runnerSigningKeyFdStat(fd);
    if (!sameRunnerSigningKeyFdSnapshot(before, after)) {
      fail("child_key_changed_during_read");
    }
    return keyBytes;
  } catch (error) {
    keyBytes?.fill(0);
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_final_signer_process_")) throw error;
    fail("child_key_invalid");
  } finally {
    overflowProbe?.fill(0);
    try { closeSync(fd); } catch { /* Child is already failing closed. */ }
  }
}

function readChildSigningKeyFd(fd, allowNonReleasePipe) {
  let stat;
  try { stat = fstatSync(fd); } catch { fail("child_key_invalid"); }
  if (stat.isFile()) return readRunnerSigningKeyFdPositionally(fd);
  // Non-release contract tests deliberately transport their synthetic key via
  // a pipe. Formal parents can only pass a posture-checked regular-file FD.
  // Node implements extra stdio pipes as a Unix socket on macOS and as a FIFO
  // on other supported hosts. The already-parsed manifest class is the guard;
  // a release child never accepts either transport.
  if (!allowNonReleasePipe || (!stat.isFIFO() && !stat.isSocket())) {
    fail("child_key_invalid");
  }
  let keyBytes;
  try {
    keyBytes = readFileSync(fd);
    closeSync(fd);
    if (keyBytes.length === 0 || keyBytes.length > MAX_KEY_BYTES) {
      keyBytes.fill(0);
      fail("child_key_invalid");
    }
    return keyBytes;
  } catch (error) {
    keyBytes?.fill(0);
    try { closeSync(fd); } catch { /* Child is already failing closed. */ }
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_final_signer_process_")) throw error;
    fail("child_key_invalid");
  }
}

function publicKeyDer(value) {
  try {
    const key = value instanceof KeyObject
      ? (value.type === "public" ? value : createPublicKey(value))
      : createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      fail("public_key_invalid");
    }
    return Buffer.from(key.export({ format: "der", type: "spki" }));
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_final_signer_process_")) throw error;
    fail("public_key_invalid");
  }
}

function decodePublicKey(value, field) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{32,2048}$/u.test(value)) {
    fail(`${field}_invalid`);
  }
  let bytes;
  try {
    bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value) fail(`${field}_invalid`);
    return createPublicKey({ key: bytes, format: "der", type: "spki" });
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_final_signer_process_")) throw error;
    fail(`${field}_invalid`);
  } finally {
    bytes?.fill(0);
  }
}

function sparseEnvironment() {
  return {
    LANG: "C",
    LC_ALL: "C",
    TZ: "UTC",
  };
}

function signerEnvelope(value) {
  const input = expectExactRecord(value, [
    "authority_root",
    "cases",
    "execution_manifest",
    "plan",
    "runner_public_key_spki_der_base64url",
    "schema_version",
    "verifier_public_key_spki_der_base64urls",
  ], "final_signer_child_envelope");
  if (input.schema_version !== "aionis_pilot_final_signer_child_envelope_v1"
    || !Array.isArray(input.verifier_public_key_spki_der_base64urls)
    || input.verifier_public_key_spki_der_base64urls.length !== 3) {
    fail("child_envelope_invalid");
  }
  const plan = verifyPilotPlanV1(input.plan);
  const runnerPublicKey = decodePublicKey(
    input.runner_public_key_spki_der_base64url,
    "runner_public_key",
  );
  const verifierPublicKeys = input.verifier_public_key_spki_der_base64urls.map(
    (encoded) => decodePublicKey(encoded, "verifier_public_key"),
  );
  if (runnerAuthorityPublicKeyPrincipalSha256V1(runnerPublicKey)
    !== plan.eval_binding.runner_authority_public_key_principal_sha256) {
    fail("runner_public_key_plan_binding_invalid");
  }
  return {
    authorityRoot: input.authority_root,
    cases: input.cases,
    executionManifest: input.execution_manifest,
    plan,
    runnerPublicKey,
    verifierPublicKeys,
  };
}

function authorizationSignerEnvelope(value) {
  const input = expectExactRecord(value, [
    "authority_root",
    "execution_manifest",
    "plan",
    "runner_public_key_spki_der_base64url",
    "schema_version",
  ], "execution_authorization_signer_child_envelope");
  if (input.schema_version
      !== "aionis_pilot_execution_authorization_signer_child_envelope_v1") {
    fail("authorization_child_envelope_invalid");
  }
  const plan = verifyPilotPlanV1(input.plan);
  const runnerPublicKey = decodePublicKey(
    input.runner_public_key_spki_der_base64url,
    "runner_public_key",
  );
  if (runnerAuthorityPublicKeyPrincipalSha256V1(runnerPublicKey)
      !== plan.eval_binding.runner_authority_public_key_principal_sha256) {
    fail("runner_public_key_plan_binding_invalid");
  }
  if (input.execution_manifest?.evidence_authority_class !== "release_authority_v1") {
    fail("formal_non_release_authority_forbidden");
  }
  return {
    authorityRoot: input.authority_root,
    executionManifest: input.execution_manifest,
    plan,
    runnerPublicKey,
  };
}

function assertPrivateKeyOutsidePublicSurfaces(keyBytes, stdinBytes) {
  const secretEncodings = [
    keyBytes.toString("base64"),
    keyBytes.toString("base64url"),
    keyBytes.toString("hex"),
  ];
  const publicSurfaces = [
    stdinBytes.toString("utf8"),
    ...process.argv,
    ...Object.entries(process.env).flat(),
  ];
  if (publicSurfaces.some((surface) => secretEncodings.some((secret) =>
    typeof surface === "string" && surface.includes(secret)))) {
    fail("private_key_public_surface_exposure");
  }
}

async function readStdinBounded() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_STDIN_BYTES) fail("child_input_too_large");
    chunks.push(chunk);
  }
  const inputBytes = Buffer.concat(chunks);
  let value;
  try {
    value = JSON.parse(inputBytes.toString("utf8"));
  } catch {
    inputBytes.fill(0);
    fail("child_input_invalid");
  }
  if (inputBytes.toString("utf8") !== `${canonicalJson(value)}\n`) {
    inputBytes.fill(0);
    fail("child_input_noncanonical");
  }
  return { inputBytes, value };
}

function signerTimestamp() {
  return new Date().toISOString();
}

function assertPrivateKeyMatchesPublicKey(privateKey, publicKey) {
  const derived = publicKeyDer(createPublicKey(privateKey));
  const expected = publicKeyDer(publicKey);
  const matches = derived.equals(expected);
  derived.fill(0);
  expected.fill(0);
  if (!matches) fail("private_key_authority_mismatch");
}

async function executeAuthorizationSignerChild(envelopeValue, privateKeyInput) {
  if (path.resolve(process.argv[1] ?? "") !== modulePath
    || process.argv[2] !== AUTHORIZATION_CHILD_MODE) {
    fail("child_entrypoint_invalid");
  }
  const input = authorizationSignerEnvelope(envelopeValue);
  const privateKey = asPrivateKey(privateKeyInput);
  assertPrivateKeyMatchesPublicKey(privateKey, input.runnerPublicKey);
  await verifyReleaseEvalRepositoryProvenanceReceiptLiveV1({
    plan: input.plan,
    provenanceReceipt: input.executionManifest.runner_authority
      .eval_repository_provenance,
  });
  return buildSignedRunnerExecutionAuthorizationV1({
    plan: input.plan,
    executionManifest: input.executionManifest,
    fixedLedgerAuthorityRoot: input.authorityRoot,
    issuedAt: signerTimestamp(),
  }, privateKey);
}

function finalSignaturePayload(manifestSha256, principal) {
  return canonicalJson({
    schema_version: FINAL_SIGNATURE_PAYLOAD_SCHEMA_VERSION,
    final_manifest_sha256: manifestSha256,
    runner_authority_public_key_principal_sha256: principal,
  });
}

function finalManifestBody(input, replay, sealedAt) {
  const runnerPrincipal = runnerAuthorityPublicKeyPrincipalSha256V1(input.runnerPublicKey);
  const releaseAuthority = input.executionManifest.evidence_authority_class
    === "release_authority_v1";
  if (releaseAuthority && replay.ledger_snapshot.event_count !== RELEASE_EVENT_COUNT) {
    fail("release_event_count_invalid");
  }
  const claimEligible = releaseAuthority
    && replay.execution_authorization.claim_eligible === true
    && replay.verdict.verdict === "promote";
  return canonicalClone({
    schema_version: FINAL_SCHEMA_VERSION,
    status: "completed",
    claim_eligible: claimEligible,
    evidence_authority_class: input.executionManifest.evidence_authority_class,
    pilot_id: input.plan.pilot_id,
    plan_sha256: input.plan.plan_sha256,
    execution_authorization_sha256:
      replay.execution_authorization.execution_authorization_sha256,
    execution_manifest_sha256: input.executionManifest.manifest_report_sha256,
    runner_authority_public_key_principal_sha256: runnerPrincipal,
    runner_transport_authority:
      replay.execution_authorization.runner_transport_authority,
    run_started_event_sha256: replay.ledger_snapshot.run_started_event_sha256,
    event_count: replay.ledger_snapshot.event_count,
    event_chain_head_sha256: replay.ledger_snapshot.event_chain_head_sha256,
    run_closed_event_sha256: replay.run_closure.run_closed_event_sha256,
    cleanup_receipt_sha256: replay.run_closure.cleanup_receipt_sha256,
    provider_attempt_count: replay.run_closure.counts.provider_attempt_count,
    cell_result_count: replay.run_closure.counts.cell_result_count,
    runtime_observation_count: replay.run_closure.counts.runtime_observation_count,
    treatment_ledger_closed_count:
      replay.run_closure.counts.treatment_ledger_closed_count,
    verdict_sha256: replay.verdict.verdict_sha256,
    sealed_at: sealedAt,
  });
}

async function executeFinalSignerChild(envelopeValue, privateKeyInput) {
  if (path.resolve(process.argv[1] ?? "") !== modulePath || process.argv[2] !== CHILD_MODE) {
    fail("child_entrypoint_invalid");
  }
  const input = signerEnvelope(envelopeValue);
  const privateKey = asPrivateKey(privateKeyInput);
  const derivedPublicKey = createPublicKey(privateKey);
  if (canonicalJson(publicKeyDer(derivedPublicKey).toString("base64url"))
      !== canonicalJson(publicKeyDer(input.runnerPublicKey).toString("base64url"))) {
    fail("private_key_authority_mismatch");
  }
  if (input.executionManifest.evidence_authority_class === "release_authority_v1") {
    await verifyReleaseEvalRepositoryProvenanceReceiptLiveV1({
      plan: input.plan,
      provenanceReceipt: input.executionManifest.runner_authority
        .eval_repository_provenance,
    });
  }
  const replay = await replayPilotRunBeforeFinalSignatureV1({
    authorityRoot: input.authorityRoot,
    cases: input.cases,
    executionManifest: input.executionManifest,
    plan: input.plan,
    runnerPublicKey: input.runnerPublicKey,
    verifierPublicKeys: input.verifierPublicKeys,
  });
  if (replay.terminal_state !== "completed") fail("completed_terminal_required");
  if (input.executionManifest.evidence_authority_class === "release_authority_v1") {
    await verifyReleaseEvalRepositoryProvenanceReceiptLiveV1({
      plan: input.plan,
      provenanceReceipt: input.executionManifest.runner_authority
        .eval_repository_provenance,
    });
  }
  const sealedAt = signerTimestamp();
  const body = finalManifestBody(input, replay, sealedAt);
  const finalManifestSha256 = canonicalSha256(body);
  const signingPayload = finalSignaturePayload(
    finalManifestSha256,
    body.runner_authority_public_key_principal_sha256,
  );
  const signature = sign(
    null,
    Buffer.from(signingPayload, "utf8"),
    privateKey,
  ).toString("base64url");
  const finalManifest = canonicalClone({
    ...body,
    final_manifest_sha256: finalManifestSha256,
    signature_algorithm: "ed25519",
    signature,
  });
  return verifySignedRunnerFinalManifestV1(finalManifest, {
    plan: input.plan,
    executionManifest: input.executionManifest,
    executionAuthorization: replay.execution_authorization,
    fixedLedgerAuthorityRoot: input.authorityRoot,
    ledgerSnapshot: replay.ledger_snapshot,
    runClosure: replay.run_closure,
    verdict: replay.verdict,
    sealedAt: finalManifest.sealed_at,
    publicKey: input.runnerPublicKey,
  });
}

async function executeAbortSignerChild(envelopeValue, privateKeyInput) {
  if (path.resolve(process.argv[1] ?? "") !== modulePath || process.argv[2] !== ABORT_CHILD_MODE) {
    fail("child_entrypoint_invalid");
  }
  const input = signerEnvelope(envelopeValue);
  const privateKey = asPrivateKey(privateKeyInput);
  const derivedPublicKey = createPublicKey(privateKey);
  if (canonicalJson(publicKeyDer(derivedPublicKey).toString("base64url"))
      !== canonicalJson(publicKeyDer(input.runnerPublicKey).toString("base64url"))) {
    fail("private_key_authority_mismatch");
  }
  const replay = await replayPilotRunBeforeFinalSignatureV1({
    authorityRoot: input.authorityRoot,
    cases: input.cases,
    executionManifest: input.executionManifest,
    plan: input.plan,
    runnerPublicKey: input.runnerPublicKey,
    verifierPublicKeys: input.verifierPublicKeys,
  });
  if (replay.terminal_state !== "aborted") fail("aborted_terminal_required");
  const sealedAt = signerTimestamp();
  return buildSignedRunnerAbortManifestForSignerV1({
    plan: input.plan,
    executionManifest: input.executionManifest,
    executionAuthorization: replay.execution_authorization,
    fixedLedgerAuthorityRoot: input.authorityRoot,
    ledgerSnapshot: replay.ledger_snapshot,
    runAbort: replay.run_abort,
    sealedAt,
  }, privateKey);
}

function collectSignerProcess(child, inputText, keyBytes = null) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    let settled = false;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      keyBytes?.fill(0);
      callback();
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_STDOUT_BYTES) stdout.push(chunk);
      else if (!overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAX_STDERR_BYTES) stderr.push(chunk);
      else if (!overflow) {
        overflow = true;
        child.kill("SIGKILL");
      }
    });
    child.stdin.on("error", () => {});
    child.stdio[3]?.on("error", () => {});
    child.once("error", (error) => finish(() => reject(error)));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, PROCESS_TIMEOUT_MS);
    timer.unref?.();
    child.once("close", (exitCode, signal) => finish(() => resolve({
      exitCode,
      overflow,
      signal,
      stderr: Buffer.concat(stderr),
      stdout: Buffer.concat(stdout),
      timedOut,
    })));
    child.stdin.end(inputText);
    if (keyBytes !== null) {
      child.stdio[3].end(keyBytes, () => keyBytes.fill(0));
    }
  });
}

function parseCanonicalChildOutput(result, field) {
  if (result.exitCode !== 0 || result.signal !== null
    || result.overflow || result.timedOut) fail(`${field}_child_process_failed`);
  try {
    const outputText = result.stdout.toString("utf8");
    const value = JSON.parse(outputText);
    if (outputText !== `${canonicalJson(value)}\n`) fail(`${field}_child_output_noncanonical`);
    return value;
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_final_signer_process_")) throw error;
    fail(`${field}_child_output_invalid`);
  }
}

function spawnFdOnlySignerChild(mode, fd, cwd, inputText = "") {
  let child;
  try {
    child = spawn(process.execPath, [modulePath, mode], {
      cwd,
      env: sparseEnvironment(),
      shell: false,
      stdio: ["pipe", "pipe", "pipe", fd],
      windowsHide: true,
    });
  } catch {
    fail("child_process_failed");
  }
  return collectSignerProcess(child, inputText).then((result) => ({ child, result }));
}

/**
 * Proves that a caller-owned formal runner FD contains the exact plan-bound
 * Ed25519 key. The parent process never reads or exports private-key bytes and
 * the child performs positional reads so the same descriptor remains reusable.
 */
export async function attestRunnerSigningKeyFdV1(options) {
  const value = expectExactRecord(options, [
    "expectedPublicKeyPrincipalSha256", "runnerSigningKeyFd",
  ], "runner_private_key_attestation_options");
  if (typeof value.expectedPublicKeyPrincipalSha256 !== "string"
    || !/^[0-9a-f]{64}$/u.test(value.expectedPublicKeyPrincipalSha256)) {
    fail("runner_private_key_expected_principal_invalid");
  }
  const fd = runnerSigningKeyFd(value.runnerSigningKeyFd);
  const { child, result } = await spawnFdOnlySignerChild(
    PRIVATE_KEY_ATTESTATION_CHILD_MODE,
    fd,
    "/",
  );
  const receipt = expectExactRecord(
    parseCanonicalChildOutput(result, "runner_private_key_attestation"),
    [
      "attester_process_id",
      "private_key_transport",
      "public_key_principal_sha256",
      "schema_version",
    ],
    "runner_private_key_attestation_receipt",
  );
  if (receipt.schema_version !== PRIVATE_KEY_ATTESTATION_RECEIPT_SCHEMA_VERSION
    || receipt.attester_process_id !== child.pid
    || receipt.private_key_transport !== "inherited_fd_3_positional_read_only"
    || receipt.public_key_principal_sha256
      !== value.expectedPublicKeyPrincipalSha256) {
    fail("runner_private_key_attestation_receipt_invalid");
  }
  return canonicalClone(receipt);
}

function prepareAuthorizationParentInvocation(value) {
  const plan = verifyPilotPlanV1(value.plan);
  const runnerPublicKeyBytes = publicKeyDer(value.runnerPublicKey);
  try {
    if (runnerAuthorityPublicKeyPrincipalSha256V1(value.runnerPublicKey)
        !== plan.eval_binding.runner_authority_public_key_principal_sha256) {
      fail("runner_public_key_plan_binding_invalid");
    }
    const envelope = canonicalClone({
      schema_version: "aionis_pilot_execution_authorization_signer_child_envelope_v1",
      authority_root: value.authorityRoot,
      execution_manifest: value.executionManifest,
      plan,
      runner_public_key_spki_der_base64url: runnerPublicKeyBytes.toString("base64url"),
    });
    return { inputText: `${canonicalJson(envelope)}\n`, plan };
  } finally {
    runnerPublicKeyBytes.fill(0);
  }
}

export async function runSealedPilotExecutionAuthorizationSignerProcessV1(options) {
  const value = expectExactRecord(options, [
    "authorityRoot",
    "executionManifest",
    "plan",
    "runnerPublicKey",
    "runnerSigningKeyFd",
  ], "execution_authorization_signer_process_options");
  const fd = runnerSigningKeyFd(value.runnerSigningKeyFd);
  const { inputText, plan } = prepareAuthorizationParentInvocation(value);
  const { result } = await spawnFdOnlySignerChild(
    AUTHORIZATION_CHILD_MODE,
    fd,
    value.authorityRoot,
    inputText,
  );
  const authorization = parseCanonicalChildOutput(
    result,
    "execution_authorization_signer",
  );
  return verifySignedRunnerExecutionAuthorizationV1(authorization, {
    plan,
    executionManifest: value.executionManifest,
    fixedLedgerAuthorityRoot: value.authorityRoot,
    publicKey: value.runnerPublicKey,
  });
}

function prepareParentInvocation(value) {
  const plan = verifyPilotPlanV1(value.plan);
  if (!Array.isArray(value.verifierPublicKeys)
    || value.verifierPublicKeys.length !== 3) fail("verifier_public_key_count_invalid");
  const runnerPublicKeyBytes = publicKeyDer(value.runnerPublicKey);
  if (runnerAuthorityPublicKeyPrincipalSha256V1(value.runnerPublicKey)
      !== plan.eval_binding.runner_authority_public_key_principal_sha256) {
    runnerPublicKeyBytes.fill(0);
    fail("runner_public_key_plan_binding_invalid");
  }
  const verifierPublicKeyEncodings = value.verifierPublicKeys.map((key) => {
    const bytes = publicKeyDer(key);
    const encoded = bytes.toString("base64url");
    bytes.fill(0);
    return encoded;
  });
  const envelope = canonicalClone({
    schema_version: "aionis_pilot_final_signer_child_envelope_v1",
    authority_root: value.authorityRoot,
    cases: value.cases,
    execution_manifest: value.executionManifest,
    plan,
    runner_public_key_spki_der_base64url: runnerPublicKeyBytes.toString("base64url"),
    verifier_public_key_spki_der_base64urls: verifierPublicKeyEncodings,
  });
  runnerPublicKeyBytes.fill(0);
  return {
    inputText: `${canonicalJson(envelope)}\n`,
    plan,
  };
}

async function runSignerChildAndVerify(
  value,
  plan,
  inputText,
  fdEntry,
  { childMode, terminalState },
  keyBytes = null,
) {
  const child = spawn(process.execPath, [modulePath, childMode], {
    cwd: value.authorityRoot,
    env: sparseEnvironment(),
    shell: false,
    stdio: ["pipe", "pipe", "pipe", fdEntry],
    windowsHide: true,
  });
  let result;
  try {
    result = await collectSignerProcess(child, inputText, keyBytes);
  } catch {
    keyBytes?.fill(0);
    fail("child_process_failed");
  }
  if (result.exitCode !== 0 || result.signal !== null
    || result.overflow || result.timedOut) {
    const diagnostic = result.stderr.toString("utf8")
      .match(/aionis_eval_[a-z0-9_]+/u)?.[0] ?? null;
    fail(`child_process_failed${diagnostic === null ? "" : `_${diagnostic}`}`);
  }
  let finalManifest;
  try {
    const outputText = result.stdout.toString("utf8");
    finalManifest = JSON.parse(outputText);
    if (outputText !== `${canonicalJson(finalManifest)}\n`) fail("child_output_noncanonical");
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_final_signer_process_")) throw error;
    fail("child_output_invalid");
  }
  const replay = await replayPilotRunBeforeFinalSignatureV1({
    authorityRoot: value.authorityRoot,
    cases: value.cases,
    executionManifest: value.executionManifest,
    plan,
    runnerPublicKey: value.runnerPublicKey,
    verifierPublicKeys: value.verifierPublicKeys,
  });
  if (replay.terminal_state !== terminalState) fail("terminal_state_mismatch");
  if (terminalState === "aborted") {
    return verifySignedRunnerAbortManifestV1(finalManifest, {
      plan,
      executionManifest: value.executionManifest,
      executionAuthorization: replay.execution_authorization,
      fixedLedgerAuthorityRoot: value.authorityRoot,
      ledgerSnapshot: replay.ledger_snapshot,
      runAbort: replay.run_abort,
      sealedAt: finalManifest.sealed_at,
      publicKey: value.runnerPublicKey,
    });
  }
  return verifySignedRunnerFinalManifestV1(finalManifest, {
    plan,
    executionManifest: value.executionManifest,
    executionAuthorization: replay.execution_authorization,
    fixedLedgerAuthorityRoot: value.authorityRoot,
    ledgerSnapshot: replay.ledger_snapshot,
    runClosure: replay.run_closure,
    verdict: replay.verdict,
    sealedAt: finalManifest.sealed_at,
    publicKey: value.runnerPublicKey,
  });
}

export async function runSealedPilotFinalSignerProcessV1(options) {
  const value = expectExactRecord(options, [
    "authorityRoot",
    "cases",
    "executionManifest",
    "plan",
    "runnerPublicKey",
    "runnerSigningKeyFd",
    "verifierPublicKeys",
  ], "final_signer_process_options");
  const signingKeyFd = runnerSigningKeyFd(value.runnerSigningKeyFd);
  if (value.executionManifest?.evidence_authority_class !== "release_authority_v1") {
    fail("formal_non_release_authority_forbidden");
  }
  const { inputText, plan } = prepareParentInvocation(value);
  return runSignerChildAndVerify(value, plan, inputText, signingKeyFd, {
    childMode: CHILD_MODE,
    terminalState: "completed",
  });
}

export async function runNonReleaseContractTestSealedPilotFinalSignerProcessV1(options) {
  const value = expectExactRecord(options, [
    "authorityRoot",
    "cases",
    "executionManifest",
    "nonReleaseContractTestRunnerPrivateKey",
    "plan",
    "runnerPublicKey",
    "verifierPublicKeys",
  ], "non_release_contract_test_final_signer_process_options");
  if (value.executionManifest?.evidence_authority_class
      !== "non_release_contract_test_authority_v1") {
    fail("non_release_authority_required");
  }
  const privateKey = asNonReleaseContractTestPrivateKey(
    value.nonReleaseContractTestRunnerPrivateKey,
  );
  const { inputText, plan } = prepareParentInvocation(value);
  const runnerPublicKeyBytes = publicKeyDer(value.runnerPublicKey);
  const derivedPublicKeyBytes = publicKeyDer(createPublicKey(privateKey));
  if (!runnerPublicKeyBytes.equals(derivedPublicKeyBytes)) {
    runnerPublicKeyBytes.fill(0);
    derivedPublicKeyBytes.fill(0);
    fail("private_key_authority_mismatch");
  }
  runnerPublicKeyBytes.fill(0);
  derivedPublicKeyBytes.fill(0);
  const keyBytes = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
  return runSignerChildAndVerify(value, plan, inputText, "pipe", {
    childMode: CHILD_MODE,
    terminalState: "completed",
  }, keyBytes);
}

export async function runSealedPilotAbortSignerProcessV1(options) {
  const value = expectExactRecord(options, [
    "authorityRoot",
    "cases",
    "executionManifest",
    "plan",
    "runnerPublicKey",
    "runnerSigningKeyFd",
    "verifierPublicKeys",
  ], "abort_signer_process_options");
  const signingKeyFd = runnerSigningKeyFd(value.runnerSigningKeyFd);
  if (value.executionManifest?.evidence_authority_class !== "release_authority_v1") {
    fail("formal_non_release_authority_forbidden");
  }
  const { inputText, plan } = prepareParentInvocation(value);
  return runSignerChildAndVerify(value, plan, inputText, signingKeyFd, {
    childMode: ABORT_CHILD_MODE,
    terminalState: "aborted",
  });
}

export async function runNonReleaseContractTestSealedPilotAbortSignerProcessV1(options) {
  const value = expectExactRecord(options, [
    "authorityRoot",
    "cases",
    "executionManifest",
    "nonReleaseContractTestRunnerPrivateKey",
    "plan",
    "runnerPublicKey",
    "verifierPublicKeys",
  ], "non_release_contract_test_abort_signer_process_options");
  if (value.executionManifest?.evidence_authority_class
      !== "non_release_contract_test_authority_v1") {
    fail("non_release_authority_required");
  }
  const privateKey = asNonReleaseContractTestPrivateKey(
    value.nonReleaseContractTestRunnerPrivateKey,
  );
  const { inputText, plan } = prepareParentInvocation(value);
  const runnerPublicKeyBytes = publicKeyDer(value.runnerPublicKey);
  const derivedPublicKeyBytes = publicKeyDer(createPublicKey(privateKey));
  if (!runnerPublicKeyBytes.equals(derivedPublicKeyBytes)) {
    runnerPublicKeyBytes.fill(0);
    derivedPublicKeyBytes.fill(0);
    fail("private_key_authority_mismatch");
  }
  runnerPublicKeyBytes.fill(0);
  derivedPublicKeyBytes.fill(0);
  const keyBytes = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
  return runSignerChildAndVerify(value, plan, inputText, "pipe", {
    childMode: ABORT_CHILD_MODE,
    terminalState: "aborted",
  }, keyBytes);
}

async function childMain() {
  const { inputBytes, value } = await readStdinBounded();
  const allowNonReleasePipe = process.argv[2] !== AUTHORIZATION_CHILD_MODE
    && value?.execution_manifest?.evidence_authority_class
      === "non_release_contract_test_authority_v1";
  const keyBytes = readChildSigningKeyFd(3, allowNonReleasePipe);
  assertPrivateKeyOutsidePublicSurfaces(keyBytes, inputBytes);
  inputBytes.fill(0);
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: keyBytes, format: "der", type: "pkcs8" });
  } finally {
    keyBytes.fill(0);
  }
  let result;
  if (process.argv[2] === AUTHORIZATION_CHILD_MODE) {
    result = await executeAuthorizationSignerChild(value, privateKey);
  } else if (process.argv[2] === ABORT_CHILD_MODE) {
    result = await executeAbortSignerChild(value, privateKey);
  } else {
    result = await executeFinalSignerChild(value, privateKey);
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
}

async function privateKeyAttestationChildMain() {
  if (path.resolve(process.argv[1] ?? "") !== modulePath
    || process.argv[2] !== PRIVATE_KEY_ATTESTATION_CHILD_MODE) {
    fail("child_entrypoint_invalid");
  }
  const inputBytes = Buffer.alloc(0);
  const keyBytes = readRunnerSigningKeyFdPositionally(3);
  assertPrivateKeyOutsidePublicSurfaces(keyBytes, inputBytes);
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: keyBytes, format: "der", type: "pkcs8" });
  } finally {
    keyBytes.fill(0);
  }
  const receipt = canonicalClone({
    schema_version: PRIVATE_KEY_ATTESTATION_RECEIPT_SCHEMA_VERSION,
    attester_process_id: process.pid,
    private_key_transport: "inherited_fd_3_positional_read_only",
    public_key_principal_sha256:
      runnerAuthorityPublicKeyPrincipalSha256V1(createPublicKey(privateKey)),
  });
  process.stdout.write(`${canonicalJson(receipt)}\n`);
}

if (path.resolve(process.argv[1] ?? "") === modulePath
  && [
    CHILD_MODE,
    ABORT_CHILD_MODE,
    AUTHORIZATION_CHILD_MODE,
    PRIVATE_KEY_ATTESTATION_CHILD_MODE,
  ].includes(process.argv[2])) {
  const run = process.argv[2] === PRIVATE_KEY_ATTESTATION_CHILD_MODE
    ? privateKeyAttestationChildMain
    : childMain;
  run().catch((error) => {
    const diagnostic = error instanceof Error
      && /^aionis_eval_[a-z0-9_]+$/u.test(error.message)
      ? error.message
      : "aionis_eval_final_signer_process_failed";
    process.stderr.write(`${diagnostic}\n`);
    process.exitCode = 1;
  });
}
