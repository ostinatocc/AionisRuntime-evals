import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildOciPrivateVerifierConfigV1, OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1 } from
  "../src/oci-verifier-process.mjs";
import { provisionReleaseCellResourcesV1 } from
  "../src/release-cell-resource-provisioner.mjs";
import { claimReleaseRuntimeOciResourceOwnerV1 } from
  "../src/release-runtime-oci-resource.mjs";
import { claimReleaseWorkspaceResourceOwnerV1 } from
  "../src/release-workspace-resource.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

function metrics() {
  return {
    accepted_direction: null,
    action_completion: null,
    rediscovery_steps: null,
    unsafe_direct_use: null,
    wrong_branch_attention: null,
    wrong_branch_write: null,
  };
}

function verifierConfig(caseId, imageDigest) {
  return buildOciPrivateVerifierConfigV1({
    verifierId: `${caseId}-verifier`,
    verifierImageDigest: imageDigest,
    verifierImageReference: `example.invalid/${caseId}@${imageDigest}`,
    checks: [{
      check_id: "controlled-fixture-check",
      argv: ["/bin/true"],
      timeout_ms: 1,
      output_limit_bytes: 1_024,
      metric_mapping: { passed: metrics(), failed: metrics() },
    }],
  });
}

test("caller-shaped owner objects cannot inject release brokers or cleanup capabilities", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aionis-release-provisioner-"));
  const files = [];
  try {
    const caseKeys = [1, 2, 3].map(() => generateKeyPairSync("ed25519"));
    const configs = [1, 2, 3].map((index) => {
      const image = `sha256:${canonicalSha256({ image: index })}`;
      return verifierConfig(`provisioner-${index}`, image);
    });
    const cases = configs.map((config, index) => buildTestPilotCaseV1({
      caseId: `provisioner-${index + 1}`,
      verifierPublicKey: caseKeys[index].publicKey,
      verifierConfigSha256: canonicalSha256(config),
      verifierContractSha256: OCI_PRIVATE_VERIFIER_CONTRACT_SHA256_V1,
      verifierImageDigest: config.verifier_image_digest,
    }));
    const plan = buildTestPilotPlanV1(cases, { pilotId: "release-provisioner-key-test" });
    const wrongKeys = [1, 2, 3].map(() => generateKeyPairSync("ed25519"));
    const fds = [];
    for (const [index, key] of wrongKeys.entries()) {
      const filename = path.join(root, `key-${index}.pem`);
      files.push(filename);
      await writeFile(filename, key.privateKey.export({ type: "pkcs8", format: "der" }), {
        mode: 0o600,
      });
      await chmod(filename, 0o600);
      fds.push(await open(filename, "r"));
    }
    const invoked = { runtime: 0, workspace: 0 };
    const runtimeOwner = { closeAll: async () => { invoked.runtime += 1; } };
    const workspaceOwner = { closeAll: async () => { invoked.workspace += 1; } };
    assert.throws(
      () => claimReleaseRuntimeOciResourceOwnerV1({ plan, runtimeOwner }),
      /owner_brand_invalid/u,
    );
    assert.throws(
      () => claimReleaseWorkspaceResourceOwnerV1({ plan, workspaceOwner }),
      /owner_brand_invalid/u,
    );
    await assert.rejects(
      () => provisionReleaseCellResourcesV1({
        plan,
        cases,
        evalProvenanceAuthority: {},
        gitExecutablePath: "/usr/bin/git",
        policyBundleSet: null,
        runtimeOwner,
        workspaceOwner,
        verifierResources: cases.map((pilotCase, index) => ({
          caseId: pilotCase.case_id,
          verifierConfig: configs[index],
          verifierPublicKey: caseKeys[index].publicKey,
          privateKeyFd: fds[index].fd,
        })),
      }),
      /provision_and_cleanup_failed/u,
    );
    assert.deepEqual(invoked, { runtime: 0, workspace: 0 });
    await Promise.all(fds.map((handle) => handle.close()));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
