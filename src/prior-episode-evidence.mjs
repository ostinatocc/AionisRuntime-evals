import { spawn } from "node:child_process";
import {
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign,
  verify,
} from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectNonNegativeInteger,
  expectPositiveInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { captureWorkspaceEvidenceV1 } from "./workspace-evidence.mjs";

const EVIDENCE_SCHEMA_VERSION =
  "aionis_prior_episode_verified_state_evidence_v1";
const ENVELOPE_SCHEMA_VERSION =
  "aionis_prior_episode_verified_state_envelope_v1";
const SIGNATURE_PAYLOAD_SCHEMA_VERSION =
  "aionis_prior_episode_verified_state_signature_payload_v1";

const METRIC_KEYS = Object.freeze([
  "accepted_direction",
  "action_completion",
  "rediscovery_steps",
  "unsafe_direct_use",
  "wrong_branch_attention",
  "wrong_branch_write",
]);

const BODY_KEYS = Object.freeze([
  "case_id",
  "checks",
  "episode_id",
  "failure_class",
  "metrics",
  "observed_at",
  "schema_version",
  "seed_workspace_sha256",
  "semantic_claim",
  "source_fixture_sha256",
  "source_kind",
  "source_task_sha256",
  "verdict",
  "verified_source_relative_path",
  "verified_source_sha256",
  "verified_workspace_sha256",
  "verifier_process",
  "verifier_public_key_principal_sha256",
]);

const EVIDENCE_KEYS = Object.freeze([
  ...BODY_KEYS,
  "evidence_sha256",
  "signature",
  "signature_algorithm",
]);

const BUILD_INPUT_KEYS = Object.freeze(
  BODY_KEYS.filter((key) => ![
    "schema_version",
    "verifier_public_key_principal_sha256",
  ].includes(key)),
);

function fail(code) {
  throw new Error(`aionis_eval_prior_episode_evidence_${code}`);
}

function asPrivateKey(value) {
  const key = value instanceof KeyObject ? value : createPrivateKey(value);
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    fail("private_key_invalid");
  }
  return key;
}

function asPublicKey(value) {
  const key = value instanceof KeyObject
    ? (value.type === "public" ? value : createPublicKey(value))
    : createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    fail("public_key_invalid");
  }
  return key;
}

function publicKeyPrincipalSha256(publicKeyInput) {
  const der = asPublicKey(publicKeyInput).export({ format: "der", type: "spki" });
  return sha256Bytes(der);
}

function signaturePayload(evidenceSha256, principalSha256) {
  return canonicalJson({
    schema_version: SIGNATURE_PAYLOAD_SCHEMA_VERSION,
    evidence_sha256: evidenceSha256,
    verifier_public_key_principal_sha256: principalSha256,
  });
}

function nullableBoolean(value, field) {
  if (value !== null && typeof value !== "boolean") fail(`${field}_invalid`);
}

function nullableCount(value, field) {
  if (value !== null) expectNonNegativeInteger(value, field);
}

function verifyMetrics(value) {
  const metrics = expectExactRecord(value, METRIC_KEYS, "prior_episode_metrics");
  for (const field of METRIC_KEYS.filter((name) => name !== "rediscovery_steps")) {
    nullableBoolean(metrics[field], `prior_episode_metric_${field}`);
  }
  nullableCount(
    metrics.rediscovery_steps,
    "prior_episode_metric_rediscovery_steps",
  );
  return metrics;
}

function verifySemanticClaim(value) {
  const claim = expectExactRecord(value, [
    "accepted_symbol",
    "rejected_symbol",
  ], "prior_episode_semantic_claim");
  const accepted = expectText(
    claim.accepted_symbol,
    "prior_episode_accepted_symbol",
  );
  const rejected = expectText(
    claim.rejected_symbol,
    "prior_episode_rejected_symbol",
  );
  if (accepted === rejected) fail("semantic_claim_symbols_reused");
  return claim;
}

function verifyVerifierProcess(value) {
  const processRecord = expectExactRecord(value, [
    "check_process_count",
    "execution_mode",
    "fresh_process_per_check",
    "node_executable_sha256",
    "source_access",
    "target_source_imported",
    "verifier_check_set_sha256",
  ], "prior_episode_verifier_process");
  expectPositiveInteger(
    processRecord.check_process_count,
    "prior_episode_check_process_count",
  );
  if (processRecord.fresh_process_per_check !== true
    || processRecord.target_source_imported !== false
    || processRecord.execution_mode !== "host_node_static_reader_subprocess_v1"
    || processRecord.source_access !== "static_read_only") {
    fail("verifier_process_posture_invalid");
  }
  expectSha256(
    processRecord.node_executable_sha256,
    "prior_episode_node_executable_sha256",
  );
  expectSha256(
    processRecord.verifier_check_set_sha256,
    "prior_episode_verifier_check_set_sha256",
  );
  return processRecord;
}

function verifyCheckResults(value, expectedCount) {
  const checks = expectArray(value, "prior_episode_checks", {
    minimum: 1,
    maximum: 32,
  });
  if (checks.length !== expectedCount) fail("check_count_mismatch");
  const ids = new Set();
  for (const [index, checkValue] of checks.entries()) {
    const check = expectExactRecord(checkValue, [
      "check_id",
      "configured_argv_sha256",
      "executed_argv_sha256",
      "exit_code",
      "status",
      "stderr_sha256",
      "stdout_sha256",
    ], `prior_episode_check_${index}`);
    const checkId = expectText(check.check_id, `prior_episode_check_${index}_id`);
    if (ids.has(checkId)) fail("check_id_duplicate");
    ids.add(checkId);
    expectSha256(
      check.configured_argv_sha256,
      `prior_episode_check_${index}_argv_sha256`,
    );
    expectSha256(
      check.executed_argv_sha256,
      `prior_episode_check_${index}_executed_argv_sha256`,
    );
    if (!Number.isSafeInteger(check.exit_code)
      || check.exit_code < 0
      || check.exit_code > 255
      || !new Set(["passed", "failed"]).has(check.status)
      || (check.status === "passed" && check.exit_code !== 0)
      || (check.status === "failed" && check.exit_code === 0)) {
      fail("check_result_invalid");
    }
    expectSha256(check.stdout_sha256, `prior_episode_check_${index}_stdout_sha256`);
    expectSha256(check.stderr_sha256, `prior_episode_check_${index}_stderr_sha256`);
  }
  return checks;
}

function verifyBody(value) {
  const record = expectExactRecord(value, BODY_KEYS, "prior_episode_evidence_body");
  if (record.schema_version !== EVIDENCE_SCHEMA_VERSION
    || record.source_kind !== "preseeded_verified_state") {
    fail("schema_or_source_kind_invalid");
  }
  expectText(record.case_id, "prior_episode_case_id");
  expectText(record.episode_id, "prior_episode_episode_id");
  expectCanonicalTimestamp(record.observed_at, "prior_episode_observed_at");
  for (const field of [
    "seed_workspace_sha256",
    "source_fixture_sha256",
    "source_task_sha256",
    "verified_source_sha256",
    "verified_workspace_sha256",
    "verifier_public_key_principal_sha256",
  ]) expectSha256(record[field], `prior_episode_${field}`);
  const relativePath = expectText(
    record.verified_source_relative_path,
    "prior_episode_verified_source_relative_path",
    { maximumBytes: 1_024 },
  );
  if (path.posix.isAbsolute(relativePath)
    || path.posix.normalize(relativePath) !== relativePath
    || relativePath.startsWith("../")
    || relativePath.includes("/../")) {
    fail("verified_source_relative_path_invalid");
  }
  verifySemanticClaim(record.semantic_claim);
  const processRecord = verifyVerifierProcess(record.verifier_process);
  const checks = verifyCheckResults(
    record.checks,
    processRecord.check_process_count,
  );
  const metrics = verifyMetrics(record.metrics);
  if (!new Set(["passed", "failed"]).has(record.verdict)
    || !new Set(["none", "semantic_mismatch"]).has(record.failure_class)
    || (record.verdict === "passed" && record.failure_class !== "none")
    || (record.verdict === "failed"
      && record.failure_class !== "semantic_mismatch")) {
    fail("verdict_invalid");
  }
  if (record.verdict === "passed"
    && (checks.some((check) => check.status !== "passed")
      || metrics.action_completion !== true
      || metrics.accepted_direction !== true
      || metrics.wrong_branch_write !== false
      || metrics.wrong_branch_attention !== false
      || metrics.unsafe_direct_use !== false)) {
    fail("passed_evidence_contradiction");
  }
  return canonicalClone(record);
}

export function buildSignedPriorEpisodeVerifiedStateV1(input, privateKeyInput) {
  const record = expectExactRecord(
    input,
    BUILD_INPUT_KEYS,
    "prior_episode_evidence_input",
  );
  const privateKey = asPrivateKey(privateKeyInput);
  const principalSha256 = publicKeyPrincipalSha256(createPublicKey(privateKey));
  const body = verifyBody({
    ...record,
    schema_version: EVIDENCE_SCHEMA_VERSION,
    verifier_public_key_principal_sha256: principalSha256,
  });
  const evidenceSha256 = canonicalSha256(body);
  const signature = sign(
    null,
    Buffer.from(signaturePayload(evidenceSha256, principalSha256), "utf8"),
    privateKey,
  ).toString("base64url");
  return verifySignedPriorEpisodeVerifiedStateV1({
    ...body,
    evidence_sha256: evidenceSha256,
    signature_algorithm: "ed25519",
    signature,
  }, createPublicKey(privateKey));
}

export function verifySignedPriorEpisodeVerifiedStateV1(value, publicKeyInput) {
  const record = expectExactRecord(
    value,
    EVIDENCE_KEYS,
    "signed_prior_episode_evidence",
  );
  const bodyValue = Object.fromEntries(
    Object.entries(record).filter(([key]) => ![
      "evidence_sha256",
      "signature",
      "signature_algorithm",
    ].includes(key)),
  );
  expectSha256(record.evidence_sha256, "prior_episode_evidence_sha256");
  if (canonicalSha256(bodyValue) !== record.evidence_sha256) {
    fail("evidence_integrity_invalid");
  }
  const body = verifyBody(bodyValue);
  if (record.signature_algorithm !== "ed25519"
    || typeof record.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/u.test(record.signature)) {
    fail("signature_invalid");
  }
  const publicKey = asPublicKey(publicKeyInput);
  const principalSha256 = publicKeyPrincipalSha256(publicKey);
  if (principalSha256 !== body.verifier_public_key_principal_sha256) {
    fail("public_key_invalid");
  }
  let signatureBytes;
  try {
    signatureBytes = Buffer.from(record.signature, "base64url");
  } catch {
    fail("signature_invalid");
  }
  if (signatureBytes.length !== 64
    || signatureBytes.toString("base64url") !== record.signature
    || !verify(
      null,
      Buffer.from(
        signaturePayload(record.evidence_sha256, principalSha256),
        "utf8",
      ),
      publicKey,
      signatureBytes,
    )) {
    fail("signature_invalid");
  }
  return canonicalClone(record);
}

export function buildPriorEpisodeVerifiedStateEnvelopeV1(
  evidenceValue,
  publicKeyInput,
) {
  const publicKey = asPublicKey(publicKeyInput);
  const evidence = verifySignedPriorEpisodeVerifiedStateV1(
    evidenceValue,
    publicKey,
  );
  const der = Buffer.from(publicKey.export({ format: "der", type: "spki" }));
  try {
    return verifyPriorEpisodeVerifiedStateEnvelopeV1({
      schema_version: ENVELOPE_SCHEMA_VERSION,
      source_kind: "preseeded_verified_state",
      signed_evidence: evidence,
      signed_evidence_sha256: canonicalSha256(evidence),
      verifier_public_key_spki_der_base64url: der.toString("base64url"),
    });
  } finally {
    der.fill(0);
  }
}

export function verifyPriorEpisodeVerifiedStateEnvelopeV1(value) {
  const envelope = expectExactRecord(value, [
    "schema_version",
    "signed_evidence",
    "signed_evidence_sha256",
    "source_kind",
    "verifier_public_key_spki_der_base64url",
  ], "prior_episode_verified_state_envelope");
  if (envelope.schema_version !== ENVELOPE_SCHEMA_VERSION
    || envelope.source_kind !== "preseeded_verified_state") {
    fail("envelope_schema_or_source_kind_invalid");
  }
  expectSha256(
    envelope.signed_evidence_sha256,
    "prior_episode_signed_evidence_sha256",
  );
  if (canonicalSha256(envelope.signed_evidence)
      !== envelope.signed_evidence_sha256) {
    fail("signed_evidence_digest_invalid");
  }
  if (typeof envelope.verifier_public_key_spki_der_base64url !== "string"
    || !/^[A-Za-z0-9_-]{32,2048}$/u.test(
      envelope.verifier_public_key_spki_der_base64url,
    )) {
    fail("envelope_public_key_invalid");
  }
  let der;
  let publicKey;
  try {
    der = Buffer.from(
      envelope.verifier_public_key_spki_der_base64url,
      "base64url",
    );
    if (der.toString("base64url")
        !== envelope.verifier_public_key_spki_der_base64url) {
      fail("envelope_public_key_invalid");
    }
    publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
  } catch (error) {
    if (error instanceof Error
      && error.message.startsWith("aionis_eval_prior_episode_evidence_")) {
      throw error;
    }
    fail("envelope_public_key_invalid");
  } finally {
    der?.fill(0);
  }
  verifySignedPriorEpisodeVerifiedStateV1(
    envelope.signed_evidence,
    publicKey,
  );
  return canonicalClone(envelope);
}

function verifyConfiguredChecks(value) {
  const checks = expectArray(value, "prior_episode_configured_checks", {
    minimum: 1,
    maximum: 32,
  });
  const ids = new Set();
  for (const [index, checkValue] of checks.entries()) {
    const field = `prior_episode_configured_check_${index}`;
    const check = expectExactRecord(checkValue, [
      "argv",
      "check_id",
      "metric_mapping",
      "output_limit_bytes",
      "timeout_ms",
    ], field);
    const checkId = expectText(check.check_id, `${field}_id`);
    if (ids.has(checkId)) fail("configured_check_id_duplicate");
    ids.add(checkId);
    const argv = expectArray(check.argv, `${field}_argv`, {
      minimum: 5,
      maximum: 5,
    });
    for (const [argumentIndex, argument] of argv.entries()) {
      expectText(argument, `${field}_argv_${argumentIndex}`, {
        controls: false,
        maximumBytes: 65_536,
        trimmed: false,
      });
    }
    if (!path.posix.isAbsolute(argv[0])
      || argv[1] !== "--input-type=module"
      || argv[2] !== "--eval"
      || argv[4] !== "/workspace/src/continuation.mjs"
      || !argv[3].includes("readFile(process.argv[1]")
      || /pathToFileURL|await\s+import\s*\(|import\s*\(\s*process\.argv|child_process|writeFile|appendFile|unlink|rename|chmod|process\.env|fetch\s*\(/u
        .test(argv[3])) {
      fail("configured_check_static_read_contract_invalid");
    }
    expectPositiveInteger(check.timeout_ms, `${field}_timeout_ms`);
    expectPositiveInteger(check.output_limit_bytes, `${field}_output_limit_bytes`);
    if (check.timeout_ms > 30_000 || check.output_limit_bytes > 1_048_576) {
      fail("configured_check_budget_invalid");
    }
    const mapping = expectExactRecord(
      check.metric_mapping,
      ["failed", "passed"],
      `${field}_metric_mapping`,
    );
    verifyMetrics(mapping.passed);
    verifyMetrics(mapping.failed);
  }
  return canonicalClone(checks);
}

export function priorEpisodeVerifierCheckSetSha256V1(value) {
  return canonicalSha256(verifyConfiguredChecks(value));
}

function collectChild(child, timeoutMs, outputLimitBytes) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    timer.unref?.();
    const account = (chunks, name) => (chunk) => {
      if (name === "stdout") stdoutBytes += chunk.length;
      else stderrBytes += chunk.length;
      if (stdoutBytes <= outputLimitBytes && stderrBytes <= outputLimitBytes) {
        chunks.push(chunk);
      } else {
        overflow = true;
        child.kill("SIGKILL");
      }
    };
    child.stdout.on("data", account(stdout, "stdout"));
    child.stderr.on("data", account(stderr, "stderr"));
    child.once("error", reject);
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode,
        signal,
        overflow,
        timedOut,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      });
    });
  });
}

function mergeMetrics(target, projection) {
  for (const field of METRIC_KEYS) {
    const value = projection[field];
    if (value === null) continue;
    if (target[field] !== null && target[field] !== value) {
      fail("metric_projection_conflict");
    }
    target[field] = value;
  }
}

async function executableSha256() {
  let resolved;
  try {
    resolved = await realpath(process.execPath);
  } catch {
    fail("node_executable_missing");
  }
  const bytes = await readFile(resolved);
  try {
    return sha256Bytes(bytes);
  } finally {
    bytes.fill(0);
  }
}

async function executeStaticCheck(check, sourcePath) {
  const executedArgv = [
    process.execPath,
    check.argv[1],
    check.argv[2],
    check.argv[3],
    sourcePath,
  ];
  let child;
  try {
    child = spawn(executedArgv[0], executedArgv.slice(1), {
      cwd: "/",
      env: {
        HOME: "/nonexistent",
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin",
        TZ: "UTC",
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
  } catch {
    fail("check_process_spawn_failed");
  }
  let result;
  try {
    result = await collectChild(
      child,
      check.timeout_ms,
      check.output_limit_bytes,
    );
  } catch {
    child.kill("SIGKILL");
    fail("check_process_failed");
  }
  if (result.signal !== null
    || result.exitCode === null
    || result.overflow
    || result.timedOut
    || !Number.isSafeInteger(result.exitCode)
    || result.exitCode < 0
    || result.exitCode > 255) {
    fail("check_process_failed");
  }
  const status = result.exitCode === 0 ? "passed" : "failed";
  return {
    result: canonicalClone({
      check_id: check.check_id,
      configured_argv_sha256: canonicalSha256(check.argv),
      executed_argv_sha256: canonicalSha256(executedArgv),
      exit_code: result.exitCode,
      status,
      stdout_sha256: sha256Bytes(result.stdout),
      stderr_sha256: sha256Bytes(result.stderr),
    }),
    metricProjection: check.metric_mapping[status],
  };
}

export async function verifyAndSignPreseededPriorStateV1(options) {
  const input = expectExactRecord(options, [
    "caseId",
    "checks",
    "episodeId",
    "observedAt",
    "privateKey",
    "seedWorkspaceSha256",
    "semanticClaim",
    "sourceFixtureSha256",
    "sourceTaskSha256",
    "verifiedSourceRelativePath",
    "verifiedWorkspacePath",
  ], "verify_preseeded_prior_state_input");
  const caseId = expectText(input.caseId, "preseeded_case_id");
  const episodeId = expectText(input.episodeId, "preseeded_episode_id");
  const observedAt = expectCanonicalTimestamp(
    input.observedAt,
    "preseeded_observed_at",
  );
  for (const field of [
    "seedWorkspaceSha256",
    "sourceFixtureSha256",
    "sourceTaskSha256",
  ]) expectSha256(input[field], `preseeded_${field}`);
  const semanticClaim = verifySemanticClaim(input.semanticClaim);
  const checks = verifyConfiguredChecks(input.checks);
  const relativePath = expectText(
    input.verifiedSourceRelativePath,
    "preseeded_verified_source_relative_path",
    { maximumBytes: 1_024 },
  );
  if (path.posix.isAbsolute(relativePath)
    || path.posix.normalize(relativePath) !== relativePath
    || relativePath.startsWith("../")
    || relativePath.includes("/../")) {
    fail("verified_source_relative_path_invalid");
  }
  let workspacePath;
  try {
    workspacePath = await realpath(input.verifiedWorkspacePath);
  } catch {
    fail("verified_workspace_missing");
  }
  if (workspacePath !== input.verifiedWorkspacePath) {
    fail("verified_workspace_alias_forbidden");
  }
  const sourcePath = path.join(
    workspacePath,
    ...relativePath.split("/"),
  );
  if (await realpath(sourcePath).catch(() => null) !== sourcePath) {
    fail("verified_source_missing_or_aliased");
  }
  const workspaceBefore = await captureWorkspaceEvidenceV1(workspacePath);
  const sourceBytes = await readFile(sourcePath);
  const verifiedSourceSha256 = sha256Bytes(sourceBytes);
  sourceBytes.fill(0);
  const metrics = Object.fromEntries(METRIC_KEYS.map((field) => [field, null]));
  const checkResults = [];
  for (const check of checks) {
    const executed = await executeStaticCheck(check, sourcePath);
    checkResults.push(executed.result);
    mergeMetrics(metrics, executed.metricProjection);
  }
  const workspaceAfter = await captureWorkspaceEvidenceV1(workspacePath);
  if (canonicalJson(workspaceAfter) !== canonicalJson(workspaceBefore)) {
    fail("verifier_mutated_workspace");
  }
  const passed = checkResults.every((check) => check.status === "passed")
    && metrics.action_completion === true
    && metrics.accepted_direction === true
    && metrics.wrong_branch_write === false
    && metrics.wrong_branch_attention === false
    && metrics.unsafe_direct_use === false;
  const evidence = buildSignedPriorEpisodeVerifiedStateV1({
    case_id: caseId,
    episode_id: episodeId,
    observed_at: observedAt,
    source_kind: "preseeded_verified_state",
    source_fixture_sha256: input.sourceFixtureSha256,
    source_task_sha256: input.sourceTaskSha256,
    seed_workspace_sha256: input.seedWorkspaceSha256,
    verified_workspace_sha256: workspaceBefore.workspace_sha256,
    verified_source_relative_path: relativePath,
    verified_source_sha256: verifiedSourceSha256,
    semantic_claim: semanticClaim,
    verifier_process: {
      check_process_count: checkResults.length,
      execution_mode: "host_node_static_reader_subprocess_v1",
      fresh_process_per_check: true,
      target_source_imported: false,
      source_access: "static_read_only",
      node_executable_sha256: await executableSha256(),
      verifier_check_set_sha256: canonicalSha256(checks),
    },
    checks: checkResults,
    metrics,
    verdict: passed ? "passed" : "failed",
    failure_class: passed ? "none" : "semantic_mismatch",
  }, input.privateKey);
  return buildPriorEpisodeVerifiedStateEnvelopeV1(
    evidence,
    createPublicKey(asPrivateKey(input.privateKey)),
  );
}
