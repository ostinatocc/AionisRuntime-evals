import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  buildAgentExecutionAuthorityV1,
  executeAgentActionV1,
} from "../src/agent-execution.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import {
  OCI_ENGINE_EXECUTION_CONTEXT_V1,
  OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
  OCI_ENGINE_TRUST_POLICY_SHA256_V1,
  OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
  OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1,
  assertExistingOciVerifierPrivateKeyFdV1,
  attestOciVerifierPrivateKeyFdV1,
  buildOciPrivateVerifierBindingV1,
  buildOciPrivateVerifierConfigV1,
  buildNonReleaseContractTestOciRuntimeAuthorityV1,
  buildOciRuntimeAuthorityV1,
  inspectOciContainerPresenceV1,
  ociPrivateVerifierConfigSha256V1,
  recoverOciContainerAbsentV1,
  runNonReleaseContractTestOciPrivateVerifierProcessV1,
  runOciPrivateVerifierProcessV1,
  verifyNonReleaseContractTestOciRuntimeAuthorityLiveV1,
  verifyOciRuntimeAuthorityLiveV1,
} from "../src/oci-verifier-process.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import {
  verifierPublicKeyPrincipalSha256V1,
  verifySignedVerifierEvidenceV1,
} from "../src/verifier-evidence.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

const OCI_VERIFIER_MODULE_PATH = fileURLToPath(
  new URL("../src/oci-verifier-process.mjs", import.meta.url),
);
const FORMAL_OCI_VERIFIER_CHILD_MODE = "__aionis_oci_verifier_child_v1__";

const PASSED_METRICS = Object.freeze({
  accepted_direction: true,
  action_completion: true,
  rediscovery_steps: 0,
  unsafe_direct_use: false,
  wrong_branch_attention: false,
  wrong_branch_write: false,
});

const FAILED_METRICS = Object.freeze({
  accepted_direction: false,
  action_completion: false,
  rediscovery_steps: 1,
  unsafe_direct_use: false,
  wrong_branch_attention: true,
  wrong_branch_write: true,
});

function digest(label) {
  return canonicalSha256({ schema_version: "oci_verifier_test_digest_v1", label });
}

function assistantAction() {
  return JSON.stringify({
    schema_version: "aionis_pilot_agent_action_v2",
    summary: "Apply the independently verifiable state.",
    action: {
      kind: "replace_text",
      path: "state.txt",
      old_text: "old",
      new_text: "accepted",
    },
  });
}

function fakeRuntimeSource(logPath) {
  return `#!${process.execPath}
const fs = require("node:fs");
const argv = process.argv.slice(2);
const statePath = ${JSON.stringify(`${logPath}.state`)};
const containerId = "a".repeat(64);
let fd3Bytes = null;
try { fd3Bytes = fs.readFileSync(3).length; } catch { fd3Bytes = -1; }
const secretEnvKeys = Object.keys(process.env).filter((key) =>
  /(API|AUTH|CREDENTIAL|KEY|PASSWORD|SECRET|TOKEN)/u.test(key));
fs.appendFileSync(${JSON.stringify(logPath)}, JSON.stringify({
  argv,
  cwd: process.cwd(),
  fd3_bytes: fd3Bytes,
  environment: process.env,
  secret_env_keys: secretEnvKeys,
}) + "\\n", { encoding: "utf8", mode: 0o600 });
if (argv[0] === "container" && argv[1] === "inspect") {
  const reference = argv.at(-1);
  let state = null;
  try { state = JSON.parse(fs.readFileSync(statePath, "utf8")); } catch {}
  if (state !== null && new Set([state.name, state.container_id]).has(reference)) {
    process.stdout.write(JSON.stringify(state.container_id) + "\\n");
    process.exit(0);
  }
  process.stdout.write("\\n");
  process.stderr.write("Error response from daemon: " + JSON.stringify({
    message: "No such container: " + reference,
  }) + "\\n");
  process.exit(1);
}
if (argv[0] === "container" && argv[1] === "kill") process.exit(0);
if (argv[0] === "container" && argv[1] === "rm") {
  try { fs.unlinkSync(statePath); } catch {}
  process.exit(0);
}
if (argv[0] !== "run") process.exit(1);
const mode = argv.at(-1);
if (mode === "pass") {
  process.stdout.write("verified");
  process.exit(0);
}
if (mode === "reject") {
  process.stderr.write("rejected");
  process.exit(7);
}
if (mode === "runtime-error") {
  fs.writeFileSync(statePath, JSON.stringify({
    name: argv[argv.indexOf("--name") + 1], container_id: containerId,
  }));
  process.stderr.write("container runtime failed");
  process.exit(125);
}
if (mode === "overflow") {
  fs.writeFileSync(statePath, JSON.stringify({
    name: argv[argv.indexOf("--name") + 1], container_id: containerId,
  }));
  process.stdout.write(Buffer.alloc(16_384, 120));
  setInterval(() => {}, 1_000);
}
if (mode === "hang") {
  fs.writeFileSync(statePath, JSON.stringify({
    name: argv[argv.indexOf("--name") + 1], container_id: containerId,
  }));
  setInterval(() => {}, 1_000);
}
process.exitCode = 9;
`;
}

function plausibleFakeDockerSource(logPath) {
  return `#!${process.execPath}
const fs = require("node:fs");
const argv = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(logPath)}, JSON.stringify(argv) + "\\n");
if (argv[0] === "version") {
  process.stdout.write(JSON.stringify({
    Client: { Version: "99.0.0", GitCommit: "fake-client", Os: "darwin", Arch: "arm64" },
    Server: {
      Version: "99.0.0",
      GitCommit: "fake-server",
      Os: "linux",
      Arch: "arm64",
      Platform: { Name: "Docker Engine - Community" },
    },
  }));
  process.exit(0);
}
if (argv[0] === "info") {
  process.stdout.write(JSON.stringify({
    ID: "FAKE:ENGINE:ID",
    Name: "plausible-docker-desktop",
    ServerVersion: "99.0.0",
    OperatingSystem: "Docker Desktop",
    OSType: "linux",
    Architecture: "aarch64",
    Driver: "overlay2",
    CgroupVersion: "2",
  }));
  process.exit(0);
}
process.exit(1);
`;
}

function cleanupFakeDockerSource(logPath, controlPath, statePath) {
  return `#!${process.execPath}
const fs = require("node:fs");
const argv = process.argv.slice(2);
const controlPath = ${JSON.stringify(controlPath)};
const statePath = ${JSON.stringify(statePath)};
const logPath = ${JSON.stringify(logPath)};
fs.appendFileSync(logPath, JSON.stringify({
  argv, cwd: process.cwd(), environment: process.env,
}) + "\\n", { mode: 0o600 });
const mode = fs.readFileSync(controlPath, "utf8").trim();
const readState = () => {
  try { return JSON.parse(fs.readFileSync(statePath, "utf8")); } catch { return null; }
};
if (argv[0] === "container" && argv[1] === "inspect") {
  const reference = argv.at(-1);
  if (mode === "daemon_error") {
    process.stderr.write("Cannot connect to the Docker daemon at unix:///var/run/docker.sock\\n");
    process.exit(1);
  }
  if (mode === "permission_error") {
    process.stderr.write("permission denied while trying to connect to the Docker daemon socket\\n");
    process.exit(1);
  }
  const state = readState();
  if (state !== null && new Set([state.name, state.container_id]).has(reference)) {
    process.stdout.write(JSON.stringify(state.container_id) + "\\n");
    process.exit(0);
  }
  process.stdout.write("\\n");
  process.stderr.write("Error response from daemon: " + JSON.stringify({
    message: "No such container: " + reference,
  }) + "\\n");
  process.exit(1);
}
if (argv[0] === "container" && new Set(["kill", "stop"]).has(argv[1])) {
  process.exit(0);
}
if (argv[0] === "container" && argv[1] === "rm") {
  if (mode === "remove_success" || mode === "remove_then_daemon_error") {
    try { fs.unlinkSync(statePath); } catch {}
  }
  if (mode === "remove_then_daemon_error") {
    fs.writeFileSync(controlPath, "daemon_error\\n");
  }
  process.exit(0);
}
process.exit(2);
`;
}

async function readCalls(logPath) {
  const text = await readFile(logPath, "utf8");
  return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

test("formal OCI verifier private-key FD rejects unsafe posture before child spawn", async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-oci-key-fd-")));
  const keyPath = path.join(root, "verifier-key.pk8");
  const linkedPath = path.join(root, "verifier-key-link.pk8");
  const emptyPath = path.join(root, "empty-key.pk8");
  const keyBytes = Buffer.from(
    generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }),
  );
  let keyFile;
  let emptyFile;
  try {
    await writeFile(keyPath, keyBytes, { mode: 0o600 });
    await chmod(keyPath, 0o600);
    keyFile = await open(keyPath, "r");
    assert.equal(assertExistingOciVerifierPrivateKeyFdV1(keyFile.fd), keyFile.fd);

    await chmod(keyPath, 0o644);
    assert.throws(
      () => assertExistingOciVerifierPrivateKeyFdV1(keyFile.fd),
      /private_key_fd_mode_invalid/u,
    );
    await chmod(keyPath, 0o600);

    await link(keyPath, linkedPath);
    assert.throws(
      () => assertExistingOciVerifierPrivateKeyFdV1(keyFile.fd),
      /private_key_fd_link_count_invalid/u,
    );
    await rm(linkedPath);
    assert.equal(assertExistingOciVerifierPrivateKeyFdV1(keyFile.fd), keyFile.fd);

    await writeFile(emptyPath, Buffer.alloc(0), { mode: 0o600 });
    await chmod(emptyPath, 0o600);
    emptyFile = await open(emptyPath, "r");
    assert.throws(
      () => assertExistingOciVerifierPrivateKeyFdV1(emptyFile.fd),
      /private_key_fd_size_invalid/u,
    );
    assert.throws(
      () => assertExistingOciVerifierPrivateKeyFdV1(-1),
      /private_key_fd_invalid/u,
    );
  } finally {
    keyBytes.fill(0);
    await emptyFile?.close();
    await keyFile?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("formal OCI verifier preflight attests a reusable FD and rejects a wrong key before pilot work", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-oci-key-attestation-",
  )));
  const expectedKeys = generateKeyPairSync("ed25519");
  const wrongKeys = generateKeyPairSync("ed25519");
  const expectedKeyBytes = Buffer.from(
    expectedKeys.privateKey.export({ format: "der", type: "pkcs8" }),
  );
  const wrongKeyBytes = Buffer.from(
    wrongKeys.privateKey.export({ format: "der", type: "pkcs8" }),
  );
  const expectedKeyPath = path.join(root, "expected-key.pk8");
  const wrongKeyPath = path.join(root, "wrong-key.pk8");
  let expectedKeyFile;
  let wrongKeyFile;
  try {
    await writeFile(expectedKeyPath, expectedKeyBytes, { mode: 0o600 });
    await writeFile(wrongKeyPath, wrongKeyBytes, { mode: 0o600 });
    await chmod(expectedKeyPath, 0o600);
    await chmod(wrongKeyPath, 0o600);
    expectedKeyFile = await open(expectedKeyPath, "r");
    wrongKeyFile = await open(wrongKeyPath, "r");
    const expectedPrincipal = verifierPublicKeyPrincipalSha256V1(
      expectedKeys.publicKey,
    );

    const firstByte = Buffer.alloc(1);
    assert.equal((await expectedKeyFile.read(firstByte, 0, 1, null)).bytesRead, 1);
    assert.equal(firstByte[0], expectedKeyBytes[0]);
    const first = await attestOciVerifierPrivateKeyFdV1({
      privateKeyFd: expectedKeyFile.fd,
      expectedPublicKeyPrincipalSha256: expectedPrincipal,
    });
    const second = await attestOciVerifierPrivateKeyFdV1({
      privateKeyFd: expectedKeyFile.fd,
      expectedPublicKeyPrincipalSha256: expectedPrincipal,
    });
    assert.equal(first.public_key_principal_sha256, expectedPrincipal);
    assert.equal(second.public_key_principal_sha256, expectedPrincipal);
    assert.notEqual(first.attester_process_id, second.attester_process_id);
    const nextByte = Buffer.alloc(1);
    assert.equal((await expectedKeyFile.read(nextByte, 0, 1, null)).bytesRead, 1);
    assert.equal(nextByte[0], expectedKeyBytes[1]);

    await assert.rejects(
      attestOciVerifierPrivateKeyFdV1({
        privateKeyFd: wrongKeyFile.fd,
        expectedPublicKeyPrincipalSha256: expectedPrincipal,
      }),
      /private_key_authority_mismatch/u,
    );
  } finally {
    expectedKeyBytes.fill(0);
    wrongKeyBytes.fill(0);
    await wrongKeyFile?.close();
    await expectedKeyFile?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("formal OCI verifier children positionally reuse one FD without consuming its offset", async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-oci-key-offset-")));
  const keyPath = path.join(root, "verifier-key.pk8");
  const keyBytes = Buffer.from(
    generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }),
  );
  let keyFile;
  try {
    await writeFile(keyPath, keyBytes, { mode: 0o600 });
    await chmod(keyPath, 0o600);
    keyFile = await open(keyPath, "r");
    const firstByte = Buffer.alloc(1);
    assert.equal((await keyFile.read(firstByte, 0, 1, null)).bytesRead, 1);
    assert.equal(firstByte[0], keyBytes[0]);

    for (let invocation = 0; invocation < 2; invocation += 1) {
      const result = spawnSync(
        process.execPath,
        [OCI_VERIFIER_MODULE_PATH, FORMAL_OCI_VERIFIER_CHILD_MODE],
        {
          cwd: root,
          encoding: "utf8",
          input: "{}\n",
          stdio: ["pipe", "pipe", "pipe", keyFile.fd],
        },
      );
      assert.equal(result.status, 1);
      assert.match(result.stderr, /aionis_eval_oci_private_verifier_process_failed/u);
    }

    const nextByte = Buffer.alloc(1);
    assert.equal((await keyFile.read(nextByte, 0, 1, null)).bytesRead, 1);
    assert.equal(nextByte[0], keyBytes[1]);
  } finally {
    keyBytes.fill(0);
    await keyFile?.close();
    await rm(root, { recursive: true, force: true });
  }
});

async function scenario(options) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-oci-verifier-")));
  const workspace = path.join(root, "workspace");
  const runtimePath = path.join(root, "fake-container-runtime");
  const logPath = path.join(root, "runtime-calls.jsonl");
  let formalKeyFile;
  let formalKeyBytes;
  try {
    await mkdir(workspace, { mode: 0o700 });
    await writeFile(runtimePath, fakeRuntimeSource(logPath), { mode: 0o700 });
    await chmod(runtimePath, 0o700);
    await writeFile(path.join(workspace, "state.txt"), "old\n", "utf8");

    const keys = generateKeyPairSync("ed25519");
    const verifierImageDigest = `sha256:${digest(`${options.caseId}:image`)}`;
    const verifierImageReference = `registry.invalid/aionis/verifier@${verifierImageDigest}`;
    const config = buildOciPrivateVerifierConfigV1({
      verifierId: `${options.caseId}-verifier`,
      verifierImageDigest,
      verifierImageReference,
      checks: [{
        check_id: "independent-oci-check",
        argv: ["/opt/aionis/bin/check", options.mode],
        timeout_ms: options.timeoutMs ?? 2_000,
        output_limit_bytes: options.outputLimitBytes ?? 4_096,
        metric_mapping: {
          passed: PASSED_METRICS,
          failed: FAILED_METRICS,
        },
      }],
    });
    const pilotCase = buildTestPilotCaseV1({
      caseId: options.caseId,
      verifierPrivateKey: keys.privateKey,
      verifierPublicKey: keys.publicKey,
      verifierContractSha256: OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
      verifierConfigSha256: ociPrivateVerifierConfigSha256V1(config),
      verifierImageDigest,
      verifiedSourceRelativePath: "state.txt",
    });
    const cell = buildPilotCellV1({
      pilot_id: `pilot-${options.caseId}`,
      opaque_cell_id: `cell-${options.caseId}`,
      ordinal: 1,
      case_id: pilotCase.case_id,
      case_sha256: pilotCase.case_sha256,
      arm: "treatment",
    });
    const agentReceipt = await executeAgentActionV1({
      cell,
      pilotCase,
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell,
        pilotCase,
        workspacePath: workspace,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent: assistantAction(),
      providerResponseReceiptSha256: digest(`${options.caseId}:provider-receipt`),
    });
    const binding = buildOciPrivateVerifierBindingV1({
      cell,
      pilotCase,
      cellExecutionRef: {
        pilot_id: cell.pilot_id,
        opaque_cell_id: cell.opaque_cell_id,
        case_id: cell.case_id,
        case_sha256: cell.case_sha256,
        arm: cell.arm,
        decision_id: `decision-${options.caseId}`,
        contract_sha256: digest(`${options.caseId}:contract`),
        render_result_sha256: digest(`${options.caseId}:render`),
        exposure_event_sha256: digest(`${options.caseId}:exposure`),
      },
    });
    const runtimeAuthority = options.releaseRuntimeAuthority
      ?? await buildNonReleaseContractTestOciRuntimeAuthorityV1({
        runtimeKind: "docker",
        executablePath: runtimePath,
      });
    const input = {
      schema_version: "aionis_oci_private_verifier_process_input_v1",
      binding,
      agent_exit_receipt: agentReceipt,
      workspace: { path: workspace },
      verifier_config: config,
      runtime_authority: runtimeAuthority,
    };
    let evidence;
    let repeatedEvidence = null;
    let formalKeyFdOffsetPreserved = null;
    if (options.releaseRuntimeAuthority !== undefined) {
      formalKeyBytes = Buffer.from(
        keys.privateKey.export({ format: "der", type: "pkcs8" }),
      );
      const formalKeyPath = path.join(root, "formal-verifier-key.pk8");
      await writeFile(formalKeyPath, formalKeyBytes, { mode: 0o600 });
      await chmod(formalKeyPath, 0o600);
      formalKeyFile = await open(formalKeyPath, "r");
      evidence = await runOciPrivateVerifierProcessV1({
        input,
        privateKeyFd: formalKeyFile.fd,
      });
      if (options.repeatFormalInvocation === true) {
        repeatedEvidence = await runOciPrivateVerifierProcessV1({
          input,
          privateKeyFd: formalKeyFile.fd,
        });
      }
      const offsetProbe = Buffer.alloc(1);
      const { bytesRead } = await formalKeyFile.read(offsetProbe, 0, 1, null);
      formalKeyFdOffsetPreserved = bytesRead === 1
        && offsetProbe[0] === formalKeyBytes[0];
    } else {
      evidence = await runNonReleaseContractTestOciPrivateVerifierProcessV1({
        input,
        privateKey: keys.privateKey,
      });
    }
    return await options.assertions({
      agentReceipt,
      config,
      evidence,
      formalKeyFdOffsetPreserved,
      input,
      keys,
      logPath,
      pilotCase,
      runtimeAuthority,
      repeatedEvidence,
      verifierImageReference,
      workspace,
    });
  } finally {
    formalKeyBytes?.fill(0);
    await formalKeyFile?.close();
    await rm(root, { recursive: true, force: true });
  }
}

test("OCI verifier executes a digest-pinned image with enforced isolation argv", async () => {
  await scenario({
    caseId: "oci-pass",
    mode: "pass",
    async assertions({
      evidence,
      keys,
      logPath,
      runtimeAuthority,
      verifierImageReference,
      workspace,
    }) {
      const calls = await readCalls(logPath);
      assert.equal(calls.length, 1);
      const call = calls[0];
      assert.equal(call.argv[0], "run");
      assert.equal(call.cwd, OCI_ENGINE_EXECUTION_CONTEXT_V1.working_directory);
      const childEnvironment = { ...call.environment };
      delete childEnvironment.__CF_USER_TEXT_ENCODING;
      assert.deepEqual(childEnvironment, OCI_ENGINE_EXECUTION_CONTEXT_V1.environment);
      assert.ok(new Set([-1, 0]).has(call.fd3_bytes));
      assert.deepEqual(call.secret_env_keys, []);
      for (const argument of [
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=256",
        "--ipc=none",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=67108864",
        "--workdir=/workspace",
      ]) assert.ok(call.argv.includes(argument), `missing ${argument}`);
      assert.ok(call.argv.includes(`--user=${process.getuid()}:${process.getgid()}`));
      const mountIndex = call.argv.indexOf("--mount");
      assert.equal(
        call.argv[mountIndex + 1],
        `type=bind,src=${workspace},dst=/workspace,readonly`,
      );
      const entrypointIndex = call.argv.indexOf("--entrypoint");
      assert.equal(call.argv[entrypointIndex + 1], "/opt/aionis/bin/check");
      assert.equal(call.argv[entrypointIndex + 2], verifierImageReference);
      assert.equal(call.argv[entrypointIndex + 3], "pass");
      assert.equal(call.argv.some((argument) => /(?:^|\/)sh$/u.test(argument)), false);
      assert.equal(evidence.verdict, "passed");
      assert.equal(evidence.failure_class, "none");
      assert.deepEqual(evidence.metrics, PASSED_METRICS);
      assert.equal(
        evidence.checks[0].command_argv_sha256,
        canonicalSha256({
          schema_version: "aionis_oci_verifier_invocation_v1",
          runtime_authority_sha256: runtimeAuthority.authority_sha256,
          argv: call.argv,
        }),
      );
      assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
      const privateKeyDer = keys.privateKey.export({ format: "der", type: "pkcs8" });
      assert.doesNotMatch(await readFile(logPath, "utf8"), new RegExp(
        privateKeyDer.toString("hex"),
        "u",
      ));
      assert.doesNotMatch(JSON.stringify(evidence), /PRIVATE KEY/u);
    },
  });
});

test("OCI verifier maps a container rejection to signed product-failure evidence", async () => {
  await scenario({
    caseId: "oci-reject",
    mode: "reject",
    async assertions({ evidence, keys, logPath }) {
      const calls = await readCalls(logPath);
      assert.equal(calls.length, 1);
      assert.equal(evidence.verdict, "failed");
      assert.equal(evidence.failure_class, "product");
      assert.equal(evidence.checks[0].exit_code, 7);
      assert.equal(evidence.checks[0].status, "failed");
      assert.deepEqual(evidence.metrics, FAILED_METRICS);
      assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
    },
  });
});

test("OCI runtime-reserved exit codes are infrastructure, never product failure", async () => {
  await scenario({
    caseId: "oci-runtime-error",
    mode: "runtime-error",
    async assertions({ evidence, logPath }) {
      const calls = await readCalls(logPath);
      assert.deepEqual(calls.map((call) => call.argv.slice(0, 2).join(" ")), [
        "run --rm",
        "container inspect",
        "container kill",
        "container rm",
        "container inspect",
      ]);
      assert.equal(evidence.verdict, "inconclusive");
      assert.equal(evidence.failure_class, "verifier_infrastructure");
      assert.equal(evidence.checks[0].exit_code, null);
      assert.equal(evidence.checks[0].status, "indeterminate");
    },
  });
});

test("OCI verifier SIGKILLs a timed-out CLI and force-cleans the named container", async () => {
  await scenario({
    caseId: "oci-timeout",
    mode: "hang",
    timeoutMs: 2_000,
    async assertions({ evidence, keys, logPath }) {
      const calls = await readCalls(logPath);
      assert.deepEqual(calls.map((call) => call.argv.slice(0, 2).join(" ")), [
        "run --rm",
        "container inspect",
        "container kill",
        "container rm",
        "container inspect",
      ]);
      const name = calls[0].argv[calls[0].argv.indexOf("--name") + 1];
      assert.equal(calls[1].argv.at(-1), name);
      assert.deepEqual(calls[2].argv, [
        "container", "kill", "--signal=KILL", "a".repeat(64),
      ]);
      assert.deepEqual(calls[3].argv, [
        "container", "rm", "--force", "--volumes", "a".repeat(64),
      ]);
      assert.equal(calls[4].argv.at(-1), name);
      assert.equal(evidence.verdict, "inconclusive");
      assert.equal(evidence.failure_class, "verifier_infrastructure");
      assert.equal(evidence.checks[0].exit_code, null);
      assert.equal(evidence.checks[0].status, "indeterminate");
      assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
    },
  });
});

test("OCI verifier enforces the combined stdout/stderr byte limit and cleans up", async () => {
  await scenario({
    caseId: "oci-overflow",
    mode: "overflow",
    outputLimitBytes: 128,
    async assertions({ evidence, logPath }) {
      const calls = await readCalls(logPath);
      assert.deepEqual(calls.map((call) => call.argv.slice(0, 2).join(" ")), [
        "run --rm",
        "container inspect",
        "container kill",
        "container rm",
        "container inspect",
      ]);
      assert.equal(evidence.verdict, "inconclusive");
      assert.equal(evidence.failure_class, "verifier_infrastructure");
      assert.equal(evidence.checks[0].exit_code, null);
      assert.equal(evidence.checks[0].status, "indeterminate");
    },
  });
});

test("OCI verifier refuses mutable image tags, fake release engines, and changed executables", async () => {
  const sha = `sha256:${digest("mutable-image")}`;
  assert.equal(buildOciPrivateVerifierConfigV1({
    verifierId: "immutable-local-image-verifier",
    verifierImageDigest: sha,
    verifierImageReference: sha,
    checks: [{
      check_id: "check",
      argv: ["/bin/true"],
      timeout_ms: 1_000,
      output_limit_bytes: 1_024,
      metric_mapping: { passed: PASSED_METRICS, failed: FAILED_METRICS },
    }],
  }).verifier_image_reference, sha);
  assert.throws(() => buildOciPrivateVerifierConfigV1({
    verifierId: "invalid-image-verifier",
    verifierImageDigest: sha,
    verifierImageReference: "registry.invalid/aionis/verifier:latest",
    checks: [{
      check_id: "check",
      argv: ["/bin/true"],
      timeout_ms: 1_000,
      output_limit_bytes: 1_024,
      metric_mapping: { passed: PASSED_METRICS, failed: FAILED_METRICS },
    }],
  }), /image_reference_invalid/u);

  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-oci-authority-")));
  const runtimePath = path.join(root, "runtime");
  const fakeDockerPath = path.join(root, "docker");
  const fakeDockerLogPath = path.join(root, "fake-docker-calls.jsonl");
  try {
    await writeFile(runtimePath, `#!${process.execPath}\nprocess.exit(0);\n`, { mode: 0o700 });
    await chmod(runtimePath, 0o700);
    await assert.rejects(
      buildOciRuntimeAuthorityV1({ executablePath: runtimePath }),
      /runtime_executable_name_invalid/u,
    );
    await writeFile(
      fakeDockerPath,
      plausibleFakeDockerSource(fakeDockerLogPath),
      { mode: 0o700 },
    );
    await chmod(fakeDockerPath, 0o700);
    const plausibleVersion = spawnSync(fakeDockerPath, [
      "version", "--format", "{{json .}}",
    ], { encoding: "utf8" });
    const plausibleInfo = spawnSync(fakeDockerPath, [
      "info", "--format", "{{json .}}",
    ], { encoding: "utf8" });
    assert.equal(plausibleVersion.status, 0);
    assert.equal(plausibleInfo.status, 0);
    assert.equal(JSON.parse(plausibleVersion.stdout).Server.Os, "linux");
    assert.equal(JSON.parse(plausibleInfo.stdout).OSType, "linux");
    await writeFile(fakeDockerLogPath, "", "utf8");
    await assert.rejects(
      buildOciRuntimeAuthorityV1({ executablePath: fakeDockerPath }),
      /runtime_engine_trust_policy_mismatch/u,
    );
    assert.equal(await readFile(fakeDockerLogPath, "utf8"), "");
    const authority = await buildNonReleaseContractTestOciRuntimeAuthorityV1({
      runtimeKind: "podman",
      executablePath: runtimePath,
    });
    assert.equal(
      authority.authority_class,
      OCI_RUNTIME_AUTHORITY_CLASS_CONTRACT_TEST_V1,
    );
    await assert.rejects(
      verifyOciRuntimeAuthorityLiveV1(authority),
      /runtime_authority_invalid/u,
    );
    await writeFile(runtimePath, `#!${process.execPath}\nprocess.exit(1);\n`, { mode: 0o700 });
    await assert.rejects(
      verifyNonReleaseContractTestOciRuntimeAuthorityLiveV1(authority),
      /runtime_authority_live_mismatch/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("OCI authority cleanup accepts only authority-fenced absence and is retryable", async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-oci-cleanup-")));
  const runtimePath = path.join(root, "docker");
  const logPath = path.join(root, "calls.jsonl");
  const controlPath = path.join(root, "control.txt");
  const statePath = path.join(root, "container-state.json");
  const containerName = "aionis-cleanup-contract-test";
  const containerId = "b".repeat(64);
  const callerEnvironment = {
    HOME: process.env.HOME,
    DOCKER_CONFIG: process.env.DOCKER_CONFIG,
    DOCKER_CONTEXT: process.env.DOCKER_CONTEXT,
    DOCKER_HOST: process.env.DOCKER_HOST,
  };
  const restoreEnvironment = () => {
    for (const [name, value] of Object.entries(callerEnvironment)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  };
  try {
    await writeFile(
      runtimePath,
      cleanupFakeDockerSource(logPath, controlPath, statePath),
      { mode: 0o700 },
    );
    await chmod(runtimePath, 0o700);
    await writeFile(controlPath, "absent\n", "utf8");
    const authority = await buildNonReleaseContractTestOciRuntimeAuthorityV1({
      runtimeKind: "docker",
      executablePath: runtimePath,
    });
    assert.deepEqual(
      authority.engine_execution_context,
      OCI_ENGINE_EXECUTION_CONTEXT_V1,
    );

    process.env.HOME = path.join(root, "caller-home");
    process.env.DOCKER_CONFIG = path.join(root, "caller-docker-config");
    process.env.DOCKER_CONTEXT = "caller-context";
    process.env.DOCKER_HOST = "tcp://127.0.0.1:1";

    assert.deepEqual(await inspectOciContainerPresenceV1({
      runtimeAuthority: authority,
      containerReference: containerName,
    }), { presence: "absent", container_id: null });

    await writeFile(controlPath, "permission_error\n", "utf8");
    const beforePermissionCalls = (await readCalls(logPath)).length;
    await assert.rejects(
      recoverOciContainerAbsentV1({
        runtimeAuthority: authority,
        containerReference: containerName,
        terminationMode: "graceful_then_force_remove",
      }),
      /container_inspect_inconclusive/u,
    );
    assert.deepEqual(
      (await readCalls(logPath)).slice(beforePermissionCalls).map((call) =>
        call.argv.slice(0, 2)),
      [["container", "inspect"]],
    );

    await writeFile(statePath, JSON.stringify({
      name: containerName,
      container_id: containerId,
    }), "utf8");
    await writeFile(controlPath, "remove_stuck\n", "utf8");
    await assert.rejects(
      recoverOciContainerAbsentV1({
        runtimeAuthority: authority,
        containerReference: containerName,
        terminationMode: "graceful_then_force_remove",
      }),
      /container_remove_not_confirmed/u,
    );
    assert.equal(JSON.parse(await readFile(statePath, "utf8")).container_id, containerId);

    await writeFile(controlPath, "remove_success\n", "utf8");
    const recovered = await recoverOciContainerAbsentV1({
      runtimeAuthority: authority,
      containerReference: containerName,
      terminationMode: "graceful_then_force_remove",
    });
    assert.equal(recovered.presence, "absent");
    assert.equal(recovered.removal_attempted, true);
    assert.equal(recovered.initial_container_id, containerId);

    await writeFile(statePath, JSON.stringify({
      name: containerName,
      container_id: containerId,
    }), "utf8");
    await writeFile(controlPath, "remove_then_daemon_error\n", "utf8");
    await assert.rejects(
      recoverOciContainerAbsentV1({
        runtimeAuthority: authority,
        containerReference: containerName,
        terminationMode: "kill_then_force_remove",
      }),
      /container_inspect_inconclusive/u,
    );
    await assert.rejects(() => readFile(statePath), /ENOENT/u);
    await writeFile(controlPath, "absent\n", "utf8");
    const retried = await recoverOciContainerAbsentV1({
      runtimeAuthority: authority,
      containerReference: containerName,
      terminationMode: "kill_then_force_remove",
    });
    assert.equal(retried.presence, "absent");
    assert.equal(retried.removal_attempted, false);

    const calls = await readCalls(logPath);
    assert.ok(calls.length > 0);
    for (const call of calls) {
      assert.equal(call.cwd, OCI_ENGINE_EXECUTION_CONTEXT_V1.working_directory);
      const environment = { ...call.environment };
      delete environment.__CF_USER_TEXT_ENCODING;
      assert.deepEqual(environment, OCI_ENGINE_EXECUTION_CONTEXT_V1.environment);
      assert.notEqual(call.environment.HOME, process.env.HOME);
      assert.notEqual(call.environment.DOCKER_CONTEXT, process.env.DOCKER_CONTEXT);
      assert.notEqual(call.environment.DOCKER_HOST, process.env.DOCKER_HOST);
    }
  } finally {
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

test("release OCI authority is derived from a live Docker engine attestation", async (t) => {
  const which = spawnSync("/usr/bin/which", ["docker"], { encoding: "utf8" });
  if (which.status !== 0 || which.stdout.trim().length === 0) {
    t.skip("Docker CLI unavailable");
    return;
  }
  let authority;
  try {
    authority = await buildOciRuntimeAuthorityV1({
      executablePath: which.stdout.trim(),
    });
  } catch (error) {
    t.skip(`live Docker engine unavailable: ${error.message}`);
    return;
  }
  assert.equal(authority.authority_class, OCI_RUNTIME_AUTHORITY_CLASS_RELEASE_V1);
  assert.equal(authority.runtime_kind, "docker");
  assert.equal(
    authority.engine_trust.trust_policy_sha256,
    OCI_ENGINE_TRUST_POLICY_SHA256_V1,
  );
  assert.equal(authority.engine_trust.host_platform, process.platform);
  assert.equal(authority.engine_trust.host_arch, process.arch);
  assert.equal(authority.engine_trust.macos_codesign.identifier, "docker");
  assert.equal(authority.engine_trust.macos_codesign.team_identifier, "9BNSXJN65R");
  assert.equal(authority.engine_attestation.version_projection.server_os, "linux");
  assert.equal(authority.engine_attestation.info_projection.os_type, "linux");
  assert.deepEqual(await verifyOciRuntimeAuthorityLiveV1(authority), authority);

  await scenario({
    caseId: "oci-formal-fd",
    mode: "pass",
    releaseRuntimeAuthority: authority,
    repeatFormalInvocation: true,
    async assertions({
      evidence,
      formalKeyFdOffsetPreserved,
      keys,
      repeatedEvidence,
    }) {
      assert.equal(formalKeyFdOffsetPreserved, true);
      assert.equal(evidence.verdict, "inconclusive");
      assert.equal(evidence.failure_class, "verifier_infrastructure");
      assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
      assert.equal(repeatedEvidence.verdict, "inconclusive");
      assert.deepEqual(
        verifySignedVerifierEvidenceV1(repeatedEvidence, keys.publicKey),
        repeatedEvidence,
      );
    },
  });
});
