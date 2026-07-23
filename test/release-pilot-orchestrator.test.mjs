import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  sha256Bytes,
} from "../src/canonical.mjs";
import { attestDeepSeekApiKeyFdV1 } from "../src/deepseek-provider.mjs";
import { buildPilotCaseV1 } from "../src/pilot-contract.mjs";
import {
  assertReleasePilotEnvironmentV1,
  disposeReleasePilotOrchestrationResourcesV1,
  parseReleasePilotCliArgumentsV1,
  recoverReleasePilotOrphansFromCanonicalConfigV1,
  runReleasePilotFromCanonicalConfigV1,
} from "../src/release-pilot-orchestrator.mjs";
import {
  activateReleaseWorkspaceOwnerManifestV1,
  beginReleaseWorkspaceOwnerManifestV1,
  readActiveReleaseWorkspaceOwnerManifestV1,
} from "../src/release-workspace-owner-manifest.mjs";
import {
  materializeReleasePilotWorkspacesV1,
} from "../src/release-workspace-resource.mjs";
import { captureWorkspaceEvidenceV1 } from "../src/workspace-evidence.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

const execFileAsync = promisify(execFile);

function recoveryConfig(privateRunRoot, gitExecutablePath) {
  const root = path.dirname(privateRunRoot);
  const body = canonicalClone({
    schema_version: "aionis_release_pilot_orchestration_config_v1",
    authority_root: path.join(root, "authority"),
    case_artifact_paths: [1, 2, 3].map((index) =>
      path.join(root, `case-${index}.json`)),
    git_executable_path: gitExecutablePath,
    oci_executable_path: path.join(root, "unused-docker"),
    pilot_plan_artifact_path: path.join(root, "plan.json"),
    policy_bundle_set_artifact_path: path.join(root, "policies.json"),
    private_run_root: privateRunRoot,
    runner_public_authority_artifact_path: path.join(root, "runner.json"),
    runtime_image_reference: "unused/runtime@sha256:" + "a".repeat(64),
    sdk_consumer_root: path.join(root, "sdk-consumer"),
    sdk_tarball_path: path.join(root, "sdk.tgz"),
    trust_root_public_key_path: path.join(root, "trust.pem"),
    verifier_public_authority_artifact_paths: [1, 2, 3].map((index) =>
      path.join(root, `verifier-${index}.json`)),
    workspace_templates: [1, 2, 3].map((index) => ({
      case_id: `recovery-case-${index}`,
      workspace_template_path: path.join(root, `template-${index}`),
    })),
  });
  return canonicalClone({ ...body, artifact_sha256: canonicalSha256(body) });
}

async function withSafeReleaseEnvironment(operation) {
  const removed = new Map();
  for (const name of Object.keys(process.env)) {
    if (/^NODE_/u.test(name)
      || /^(?:SSLKEYLOGFILE|OPENSSL_CONF|SSL_CERT_FILE|SSL_CERT_DIR)$/u.test(name)
      || /^(?:HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$/u.test(name)
      || /^DYLD_/u.test(name)
      || /^(?:LD_PRELOAD|LD_LIBRARY_PATH)$/u.test(name)) {
      removed.set(name, process.env[name]);
      delete process.env[name];
    }
  }
  try { return await operation(); } finally {
    for (const [name, value] of removed) process.env[name] = value;
  }
}

function validArgv(extra = []) {
  return [
    "--verifier-private-key-fd", "7",
    "--config", "/tmp/aionis-release-config.json",
    "--deepseek-key-fd", "3",
    "--verifier-private-key-fd", "6",
    "--runner-signing-key-fd", "4",
    "--verifier-private-key-fd", "5",
    ...extra,
  ];
}

test("release CLI accepts only FD numbers for all five secrets", () => {
  const parsed = parseReleasePilotCliArgumentsV1(validArgv(["--preflight-only"]), {});
  assert.equal(parsed.configPath, "/tmp/aionis-release-config.json");
  assert.equal(parsed.deepSeekApiKeyFd, 3);
  assert.equal(parsed.runnerSigningKeyFd, 4);
  assert.deepEqual(parsed.verifierPrivateKeyFds, [7, 6, 5]);
  assert.equal(parsed.preflightOnly, true);
  assert.equal(JSON.stringify(parsed).includes("private-key-path"), false);

  assert.throws(() => parseReleasePilotCliArgumentsV1([
    ...validArgv(), "--deepseek-api-key", "plaintext-secret",
  ], {}), /arguments_invalid|argv_length_invalid/u);
  assert.throws(() => parseReleasePilotCliArgumentsV1([
    ...validArgv().slice(0, -2), "--verifier-private-key-fd", "4",
  ], {}), /arguments_invalid/u);
  assert.throws(() => parseReleasePilotCliArgumentsV1([
    ...validArgv(), "--preflight-only", "--preflight-only",
  ], {}), /arguments_invalid|argv_length_invalid/u);
  assert.throws(() => parseReleasePilotCliArgumentsV1(validArgv(), {
    DEEPSEEK_API_KEY: "must-not-be-read",
  }), /unsafe_environment_forbidden/u);
  for (const name of [
    "NODE_OPTIONS",
    "node_tls_reject_unauthorized",
    "SSLKEYLOGFILE",
    "OpenSSL_Conf",
    "SSL_CERT_FILE",
    "http_proxy",
    "HTTPS_PROXY",
    "All_Proxy",
    "no_proxy",
    "DYLD_INSERT_LIBRARIES",
    "LD_PRELOAD",
  ]) {
    assert.throws(
      () => assertReleasePilotEnvironmentV1({ [name]: "unsafe" }),
      /unsafe_environment_forbidden/u,
    );
  }
  assert.equal(assertReleasePilotEnvironmentV1({
    HOME: "/nonexistent",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
    TZ: "UTC",
  }), true);
});

test("old workspace orphan is reconciled before invalid key or current provenance", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-release-pilot-fd-preflight-",
  )));
  const privateRunRoot = path.join(root, "private-run");
  const handles = [];
  try {
    await mkdir(privateRunRoot, { mode: 0o700 });
    await chmod(privateRunRoot, 0o700);
    const gitExecutable = await findGitExecutable();
    const oldPlan = buildTestPilotPlanV1([
      { case_id: "recovery-case-1", case_sha256: canonicalSha256("recovery-1") },
      { case_id: "recovery-case-2", case_sha256: canonicalSha256("recovery-2") },
      { case_id: "recovery-case-3", case_sha256: canonicalSha256("recovery-3") },
    ], { pilotId: "old-orphan-before-invalid-key" });
    const oldOwner = await beginReleaseWorkspaceOwnerManifestV1({
      gitExecutablePath: gitExecutable,
      orchestrationOwnerId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      plan: oldPlan,
      privateRunRoot,
    });
    await activateReleaseWorkspaceOwnerManifestV1(oldOwner);
    const configPath = path.join(root, "recovery-config.json");
    const config = recoveryConfig(privateRunRoot, gitExecutable);
    await writeFile(configPath, `${canonicalJson(config)}\n`, { mode: 0o600 });
    const badApiKeyPath = path.join(root, "bad-api-key");
    await writeFile(badApiKeyPath, Buffer.alloc(8), { mode: 0o600 });
    await chmod(badApiKeyPath, 0o600);
    handles.push(await open(badApiKeyPath, "r"));
    for (let index = 0; index < 4; index += 1) {
      const keys = generateKeyPairSync("ed25519");
      const file = path.join(root, `private-key-${index}.der`);
      await writeFile(file, keys.privateKey.export({ format: "der", type: "pkcs8" }), {
        mode: 0o600,
      });
      await chmod(file, 0o600);
      handles.push(await open(file, "r"));
    }
    await withSafeReleaseEnvironment(() => assert.rejects(
      runReleasePilotFromCanonicalConfigV1({
        configPath,
        deepSeekApiKeyFd: handles[0].fd,
        preflightOnly: true,
        runnerSigningKeyFd: handles[1].fd,
        verifierPrivateKeyFds: handles.slice(2).map((handle) => handle.fd),
      }),
      /aionis_eval_deepseek_api_key_attestation_child_failed/u,
    ));
    assert.equal(
      await readActiveReleaseWorkspaceOwnerManifestV1({ privateRunRoot }),
      null,
    );
    assert.deepEqual(await readdir(privateRunRoot), []);
    const firstByte = Buffer.alloc(1);
    assert.equal((await handles[0].read(firstByte, 0, 1, null)).bytesRead, 1);
    assert.equal(firstByte[0], 0);

    const recoverOnlyOwner = await beginReleaseWorkspaceOwnerManifestV1({
      gitExecutablePath: gitExecutable,
      orchestrationOwnerId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      plan: oldPlan,
      privateRunRoot,
    });
    await activateReleaseWorkspaceOwnerManifestV1(recoverOnlyOwner);
    const recovery = await withSafeReleaseEnvironment(() =>
      recoverReleasePilotOrphansFromCanonicalConfigV1({ configPath }));
    assert.equal(recovery.claim_eligible, false);
    assert.equal(recovery.ledger_created, false);
    assert.equal(recovery.provider_request_count, 0);
    assert.equal(recovery.new_owner_created, false);
    assert.equal(recovery.workspace_reconciliation.cleanup_confirmed, true);
    assert.deepEqual(await readdir(privateRunRoot), []);
  } finally {
    await Promise.all(handles.map((handle) => handle.close()));
    await rm(root, { recursive: true, force: true });
  }
});

test("DeepSeek FD attestation is child-only, redacted, and offset preserving", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-release-pilot-api-key-attestation-",
  )));
  const keyPath = path.join(root, "api-key");
  const apiKey = "test-only-deepseek-credential";
  try {
    await writeFile(keyPath, apiKey, { mode: 0o600 });
    await chmod(keyPath, 0o600);
    const handle = await open(keyPath, "r");
    try {
      const receipt = await attestDeepSeekApiKeyFdV1({ apiKeyFd: handle.fd });
      assert.equal(receipt.credential_validated, true);
      assert.equal(JSON.stringify(receipt).includes(apiKey), false);
      assert.equal(Object.hasOwn(receipt, "credential_sha256"), false);
      const firstByte = Buffer.alloc(1);
      assert.equal((await handle.read(firstByte, 0, 1, null)).bytesRead, 1);
      assert.equal(firstByte.toString("utf8"), apiKey[0]);
    } finally {
      await handle.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function findGitExecutable() {
  for (const directory of (process.env.PATH ?? "").split(path.delimiter)) {
    if (directory === "") continue;
    const candidate = path.join(directory, "git");
    try {
      await access(candidate, constants.X_OK);
      return realpath(candidate);
    } catch { /* try next */ }
  }
  throw new Error("git_not_found_for_release_orchestrator_test");
}

async function git(executable, cwd, args, encoding = "utf8") {
  return (await execFileAsync(executable, args, {
    cwd,
    encoding,
    maxBuffer: 1_048_576,
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_OPTIONAL_LOCKS: "0",
      HOME: "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
  })).stdout;
}

async function writeWorkspace(root, caseId) {
  const fixture = Buffer.from(`${JSON.stringify({ case_id: caseId })}\n`);
  await mkdir(path.join(root, "fixtures", "v1"), { recursive: true, mode: 0o700 });
  await writeFile(path.join(root, "README.md"), `${caseId}\n`, { mode: 0o600 });
  await writeFile(path.join(root, "fixtures", "v1", `${caseId}.json`), fixture, {
    mode: 0o600,
  });
  return fixture;
}

async function realWorkspaceFixture(root, gitExecutable, caseId, verifierKeys) {
  const template = path.join(root, "templates", caseId);
  const projection = path.join(root, "projections", caseId);
  await mkdir(template, { recursive: true, mode: 0o700 });
  await mkdir(projection, { recursive: true, mode: 0o700 });
  const fixture = await writeWorkspace(template, caseId);
  await writeWorkspace(projection, caseId);
  await git(gitExecutable, template, ["init", "--quiet"]);
  await git(gitExecutable, template, ["config", "user.name", "Aionis Eval"]);
  await git(gitExecutable, template, ["config", "user.email", "eval@example.invalid"]);
  const repositoryUrl = `https://github.com/aionis-evals/${caseId}.git`;
  await git(gitExecutable, template, ["remote", "add", "origin", repositoryUrl]);
  await git(gitExecutable, template, ["add", "--all"]);
  await git(gitExecutable, template, ["commit", "--quiet", "-m", "frozen"]);
  const head = (await git(gitExecutable, template, ["rev-parse", "HEAD"])).trim();
  const status = await git(gitExecutable, template, [
    "status", "--porcelain=v1", "-z", "--untracked-files=all",
  ], "buffer");
  const evidence = await captureWorkspaceEvidenceV1(await realpath(projection));
  const base = buildTestPilotCaseV1({
    caseId,
    fixtureSha256: sha256Bytes(fixture),
    verifierPrivateKey: verifierKeys.privateKey,
    verifierPublicKey: verifierKeys.publicKey,
    workspaceSha256: evidence.workspace_sha256,
  });
  const body = canonicalClone(base);
  delete body.schema_version;
  delete body.case_sha256;
  body.workspace.repository_url = repositoryUrl;
  body.workspace.base_commit_sha = head;
  body.workspace.clean_status_sha256 = sha256Bytes(status);
  return {
    pilotCase: buildPilotCaseV1(body),
    template: await realpath(template),
  };
}

test("orchestration cleanup disposes a real opaque workspace owner idempotently", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-release-pilot-cleanup-",
  )));
  try {
    const privateRunRoot = path.join(root, "private-run");
    await mkdir(privateRunRoot, { mode: 0o700 });
    await chmod(privateRunRoot, 0o700);
    const gitExecutable = await findGitExecutable();
    const verifier = generateKeyPairSync("ed25519");
    const built = [];
    for (const caseId of ["cleanup-one", "cleanup-two", "cleanup-three"]) {
      built.push(await realWorkspaceFixture(root, gitExecutable, caseId, verifier));
    }
    const cases = built.map((entry) => entry.pilotCase);
    const plan = buildTestPilotPlanV1(cases, {
      pilotId: "release-pilot-orchestration-cleanup-test",
    });
    const templates = Object.create(null);
    for (const entry of built) templates[entry.pilotCase.case_id] = entry.template;
    const workspaceOwner = await materializeReleasePilotWorkspacesV1({
      cases,
      gitExecutablePath: gitExecutable,
      orchestrationOwnerId: "cccccccccccccccccccccccccccccccc",
      plan,
      privateRunRoot: await realpath(privateRunRoot),
      workspaceTemplates: templates,
    });
    assert.equal((await readdir(privateRunRoot)).length, 3);
    const firstReceipts = await disposeReleasePilotOrchestrationResourcesV1({
      cellResourceAuthority: null,
      runtimeOwner: null,
      workspaceOwner,
    });
    assert.equal(firstReceipts.length, 1);
    assert.equal(firstReceipts[0].kind, "workspace_owner");
    const secondReceipts = await disposeReleasePilotOrchestrationResourcesV1({
      cellResourceAuthority: null,
      runtimeOwner: null,
      workspaceOwner,
    });
    assert.equal(secondReceipts.length, 1);
    assert.equal(secondReceipts[0].kind, "workspace_owner");
    assert.deepEqual(await readdir(privateRunRoot), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
