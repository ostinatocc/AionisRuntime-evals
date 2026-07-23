import assert from "node:assert/strict";
import {
  link,
  mkdir,
  mkdtemp,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalSha256 } from "../src/canonical.mjs";
import {
  captureWorkspaceEvidenceV1,
  captureWorkspaceInodeSetV1,
} from "../src/workspace-evidence.mjs";

async function temporaryWorkspace(prefix) {
  return realpath(await mkdtemp(path.join(os.tmpdir(), prefix)));
}

test("workspace capture is deterministic while content and inode identities stay separate", async () => {
  const firstRoot = await temporaryWorkspace("aionis-workspace-evidence-");
  const secondRoot = await temporaryWorkspace("aionis-workspace-copy-");
  try {
    for (const root of [firstRoot, secondRoot]) {
      await mkdir(path.join(root, "nested"), { mode: 0o700 });
      await writeFile(path.join(root, "alpha.txt"), "alpha\n", { mode: 0o600 });
      await writeFile(path.join(root, "nested", "beta.txt"), "beta\n", { mode: 0o600 });
    }

    const first = await captureWorkspaceEvidenceV1(firstRoot);
    const repeated = await captureWorkspaceEvidenceV1(firstRoot);
    const copy = await captureWorkspaceEvidenceV1(secondRoot);
    const firstInodes = await captureWorkspaceInodeSetV1(firstRoot);
    const copyInodes = await captureWorkspaceInodeSetV1(secondRoot);
    assert.deepEqual(repeated, first);
    assert.equal("inode_identifiers" in first, false);
    assert.match(first.inode_set_sha256, /^[0-9a-f]{64}$/u);
    assert.equal(first.inode_set_sha256, firstInodes.inode_set_sha256);
    assert.equal(firstInodes.inode_set_sha256, canonicalSha256({
      schema_version: firstInodes.schema_version,
      inode_identifiers: firstInodes.inode_identifiers,
    }));
    assert.deepEqual(firstInodes.inode_identifiers, [
      ...firstInodes.inode_identifiers,
    ].sort((left, right) => Buffer.from(left).compare(Buffer.from(right))));
    assert.equal(
      new Set(firstInodes.inode_identifiers).size,
      firstInodes.inode_identifiers.length,
    );
    assert.equal(firstInodes.inode_identifiers.some(
      (identifier) => copyInodes.inode_identifiers.includes(identifier),
    ), false);
    assert.equal(first.file_count, 2);
    assert.equal(first.workspace_sha256, canonicalSha256({
      schema_version: first.schema_version,
      file_count: first.file_count,
      entry_set_sha256: first.entry_set_sha256,
    }));
    assert.equal(copy.workspace_sha256, first.workspace_sha256);
    assert.notEqual(copy.inode_set_sha256, first.inode_set_sha256);

    const replacement = path.join(firstRoot, "replacement.txt");
    await writeFile(replacement, "alpha\n", { mode: 0o600 });
    await rename(replacement, path.join(firstRoot, "alpha.txt"));
    const replaced = await captureWorkspaceEvidenceV1(firstRoot);
    assert.equal(replaced.workspace_sha256, first.workspace_sha256);
    assert.notEqual(replaced.inode_set_sha256, first.inode_set_sha256);
  } finally {
    await rm(firstRoot, { recursive: true, force: true });
    await rm(secondRoot, { recursive: true, force: true });
  }
});

test("workspace capture rejects symlinks and hardlinks", async () => {
  const root = await temporaryWorkspace("aionis-workspace-links-");
  try {
    const target = path.join(root, "target.txt");
    await writeFile(target, "target\n", { mode: 0o600 });
    await symlink(target, path.join(root, "alias.txt"));
    await assert.rejects(
      () => captureWorkspaceEvidenceV1(root),
      /aionis_eval_workspace_symlink_forbidden/u,
    );
    await rm(path.join(root, "alias.txt"));

    await link(target, path.join(root, "hardlink.txt"));
    await assert.rejects(
      () => captureWorkspaceEvidenceV1(root),
      /aionis_eval_workspace_hardlink_forbidden/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("workspace capture rejects git metadata and control-character path components", async () => {
  const root = await temporaryWorkspace("aionis-workspace-paths-");
  try {
    await mkdir(path.join(root, ".git"), { mode: 0o700 });
    await assert.rejects(
      () => captureWorkspaceEvidenceV1(root),
      /aionis_eval_workspace_git_metadata_forbidden/u,
    );
    await rm(path.join(root, ".git"), { recursive: true });

    await writeFile(path.join(root, "line\nbreak.txt"), "unsafe\n", { mode: 0o600 });
    await assert.rejects(
      () => captureWorkspaceEvidenceV1(root),
      /aionis_eval_workspace_path_component_control_forbidden/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
