import assert from "node:assert/strict";
import test from "node:test";
import { evaluateRunner } from "../src/run-bounded-soak.mjs";

const BASE = {
  lock: "config/v0.3.12-release-lock.json",
  authority: "fixtures/v0.3.12/authority-manifest.json",
  workload: "fixtures/v0.3.12/workload-manifest.json",
};
const HARNESS_COMMIT = "a".repeat(40);

function exactEnvironment(phaseCalls) {
  return {
    CI: "true",
    GITHUB_ACTIONS: "true",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REPOSITORY: "ostinatocc/AionisRuntime-evals",
    GITHUB_SHA: HARNESS_COMMIT,
    GITHUB_RUN_ID: "12345",
    GITHUB_RUN_ATTEMPT: "1",
    AIONIS_PROTECTED_ENVIRONMENT: "bounded-soak",
    AIONIS_PAID_EXECUTION_APPROVED: "true",
    AIONIS_CANDIDATE_COMMIT: "6f3557014117af85c19f1589a48173e87bd84b70",
    AIONIS_CANDIDATE_DIGEST: "sha256:f40c5a1f14af23674fab5e59414bbe4187a0d56dcf8a2798afd02c1563c4a5d6",
    AIONIS_AGENT_MODEL: "deepseek/deepseek-v4-pro",
    AIONIS_EMBEDDING_MODEL: "qwen3.7-text-embedding",
    AIONIS_MAX_CHAT_CALLS: "90",
    AIONIS_MAX_COST_USD: "50",
    AIONIS_PHASE_CHAT_CALLS: String(phaseCalls),
  };
}

test("validate and dry plans perform no paid execution", () => {
  assert.equal(evaluateRunner({ args: { mode: "validate", ...BASE }, env: {} }).mode, "validate");
  assert.deepEqual(
    evaluateRunner({ args: { mode: "pilot", ...BASE }, env: {} }),
    { ok: true, mode: "pilot", execution: false, planned_chat_calls: 9 },
  );
  assert.deepEqual(
    evaluateRunner({ args: { mode: "soak", ...BASE }, env: {} }),
    { ok: true, mode: "soak", execution: false, planned_chat_calls: 81 },
  );
});

test("paid execution rejects missing approval and every non-exact protected coordinate", () => {
  const args = { mode: "pilot", ...BASE, execute: true, harness_commit: HARNESS_COMMIT };
  assert.throws(() => evaluateRunner({ args, env: exactEnvironment(9), repositoryHead: HARNESS_COMMIT }), /approval is missing/);
  const approved = { ...args, approval: "RUN_EXACT_FROZEN_BOUNDED_SOAK" };
  const mutations = [
    ["GITHUB_EVENT_NAME", "push"],
    ["GITHUB_SHA", "b".repeat(40)],
    ["AIONIS_PROTECTED_ENVIRONMENT", "unprotected"],
    ["AIONIS_CANDIDATE_COMMIT", "b".repeat(40)],
    ["AIONIS_CANDIDATE_DIGEST", `sha256:${"b".repeat(64)}`],
    ["AIONIS_AGENT_MODEL", "fallback-model"],
    ["AIONIS_EMBEDDING_MODEL", "different-embedding"],
    ["AIONIS_MAX_COST_USD", "51"],
    ["AIONIS_PHASE_CHAT_CALLS", "81"],
  ];
  for (const [key, value] of mutations) {
    assert.throws(() => evaluateRunner({ args: approved, env: { ...exactEnvironment(9), [key]: value }, repositoryHead: HARNESS_COMMIT }));
  }
});

test("even an exact protected context cannot spend because the executor is absent", () => {
  const pilot = {
    mode: "pilot",
    ...BASE,
    execute: true,
    harness_commit: HARNESS_COMMIT,
    approval: "RUN_EXACT_FROZEN_BOUNDED_SOAK",
  };
  assert.throws(
    () => evaluateRunner({ args: pilot, env: exactEnvironment(9), repositoryHead: HARNESS_COMMIT }),
    /PAID_EXECUTOR_UNAVAILABLE/,
  );
  assert.throws(
    () => evaluateRunner({ args: { ...pilot, mode: "soak" }, env: exactEnvironment(81), repositoryHead: HARNESS_COMMIT }),
    /PAID_EXECUTOR_UNAVAILABLE/,
  );
});

test("paid execution binds the actual checked-out authority HEAD", () => {
  const args = {
    mode: "pilot",
    ...BASE,
    execute: true,
    harness_commit: HARNESS_COMMIT,
    approval: "RUN_EXACT_FROZEN_BOUNDED_SOAK",
  };
  assert.throws(
    () => evaluateRunner({ args, env: exactEnvironment(9), repositoryHead: "b".repeat(40) }),
    /checked-out authority HEAD/,
  );
});

test("runner refuses repository path escape before loading a contract", () => {
  assert.throws(
    () => evaluateRunner({ args: { mode: "validate", ...BASE, lock: "../../outside.json" }, env: {} }),
    /stay inside the authority repository/,
  );
});
