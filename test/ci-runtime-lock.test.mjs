import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("CI integration checkout is pinned to the Runtime V1 lock", () => {
  const lock = JSON.parse(readFileSync(path.join(
    root,
    "config/runtime-v1-lock.json",
  ), "utf8"));
  const workflow = readFileSync(path.join(
    root,
    ".github/workflows/ci.yml",
  ), "utf8");
  const refs = [...workflow.matchAll(/^\s+ref: ([0-9a-f]{40})$/gmu)]
    .map((match) => match[1]);
  assert.deepEqual(refs, [lock.runtime_git_commit_sha]);
  assert.match(workflow, /repository: ostinatocc\/Aionis$/mu);
  assert.doesNotMatch(workflow, /DEEPSEEK_API_KEY|OPENROUTER_API_KEY|secrets\./u);
});
