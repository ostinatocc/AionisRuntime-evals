import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import {
  COMMIT_RE,
  DIGEST_RE,
  EVAL_REPOSITORY,
  MAX_ARTIFACT_BYTES,
  PUBLISHER_ENVIRONMENT,
  SHA256_RE,
  TAG_RE,
  assertNoSecretMaterial,
  readJsonFile,
  sha256,
  validateArtifactBundleManifest,
  validateAuthorityManifest,
  validateReleaseLock,
  validateWorkloadManifest,
} from "./contracts.mjs";
import { reduceArtifactEvidence } from "./artifact-evidence.mjs";

const EVALUATION_GIT_REPOSITORY = `${EVAL_REPOSITORY}.git`;
const VERIFIER_PATH = "scripts/verify-stable-promotion.mjs";
const ALLOWED_POST_CANDIDATE_FILES = new Set([
  ".gitignore",
  ".github/workflows/ci.yml",
  ".github/workflows/docker.yml",
  ".github/workflows/exact-main-embedding-smoke.yml",
  ".github/workflows/release-smoke.yml",
  "CHANGELOG.md",
  "package-lock.json",
  "package.json",
  "README.md",
  "RELEASE_NOTES.md",
  "docs/AIONIS_ADMISSION_DATASET_EXPORT_QUICKSTART.md",
  "docs/AIONIS_HTTP_QUICKSTART.md",
  "docs/AIONIS_INSTALL.md",
  "docs/AIONIS_OBSERVE_GUIDE_AUDIT_QUICKSTART.md",
  "docs/AIONIS_PRODUCT_API_USAGE.md",
  "docs/AIONIS_QUICKSTART_MATRIX.md",
  "docs/AIONIS_RELEASES.md",
  "docs/AIONIS_SDK_QUICKSTART.md",
  "docs/architecture/runtime-complexity-budget.json",
  "docs/examples/minimal-agent.ts",
  "docs/plans/2026-07-20-v0.3.12-bounded-soak-and-stable-promotion.md",
  "release-train.json",
  "runtime-manifest.json",
  "scripts/ci/docker-recovery-smoke.sh",
  "scripts/ci/docker-release-smoke.sh",
  "scripts/ci/release-package-artifacts.sh",
  "scripts/ci/release-artifact-gate.mjs",
  "scripts/ci/release-artifact-gate.test.mjs",
  "scripts/ci/release-version-docs.test.mjs",
  "scripts/ci/release-workflow-contract.test.mjs",
  "scripts/ci/runtime-complexity-budget.test.mjs",
  "scripts/ci/sdk-contract-ownership.test.mjs",
]);

function fail(message) {
  throw new Error(message);
}

function expect(actual, expected, field) {
  if (!isDeepStrictEqual(actual, expected)) fail(`${field} does not match the frozen promotion contract`);
}

function expectKeys(value, keys, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${field} must be an object`);
  expect(Object.keys(value).sort(), [...keys].sort(), `${field} keys`);
}

function requiredString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) fail(`${field} must be a non-empty trimmed string`);
  return value;
}

function git(root, args, label, { buffer = false } = {}) {
  const result = spawnSync("git", args, { cwd: root, encoding: buffer ? null : "utf8", maxBuffer: 8 * 1024 * 1024 });
  if (result.status !== 0) {
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString("utf8") : result.stderr;
    fail(`${label} failed: ${stderr.trim() || `exit ${result.status}`}`);
  }
  return buffer ? result.stdout : result.stdout.trim();
}

function parseJson(source, field) {
  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${field} is not valid JSON: ${error.message}`);
  }
}

function readRepositoryFile(root, relativePath, field) {
  if (typeof relativePath !== "string" || path.isAbsolute(relativePath)) fail(`${field} path must be repository-relative`);
  const absoluteRoot = fs.realpathSync(root);
  const absolute = path.resolve(absoluteRoot, relativePath);
  const relative = path.relative(absoluteRoot, absolute);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) fail(`${field} path escapes its repository`);
  let current = absoluteRoot;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) fail(`${field} path must not contain symlinks`);
  }
  const stat = fs.statSync(absolute);
  if (!stat.isFile()) fail(`${field} must be a regular file`);
  return { absolute, source: fs.readFileSync(absolute) };
}

function readRootJson(root, relativePath, field) {
  const document = readRepositoryFile(root, relativePath, field);
  assertNoSecretMaterial(document.source, field);
  return { ...document, value: parseJson(document.source.toString("utf8"), field) };
}

function readBoundJson(root, binding, field) {
  const relativePath = requiredString(binding?.path, `${field}.path`);
  const expectedHash = requiredString(binding?.sha256, `${field}.sha256`);
  if (!/^docs\/releases\/[0-9A-Za-z._-]+\.json$/.test(relativePath)) fail(`${field}.path must be directly under docs/releases`);
  if (!SHA256_RE.test(expectedHash)) fail(`${field}.sha256 is invalid`);
  const document = readRootJson(root, relativePath, field);
  const actualHash = sha256(document.source);
  if (actualHash !== expectedHash) fail(`${field} raw hash mismatch`);
  return { path: relativePath, sha256: actualHash, value: document.value, source: document.source };
}

function compareVersions(left, right) {
  const parse = (value) => /^\d+\.\d+\.\d+$/.test(value ?? "") ? value.split(".").map(Number) : null;
  const a = parse(left);
  const b = parse(right);
  if (!a || !b) fail("stable and candidate versions must use x.y.z form");
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

function canonicalGitUrl(value) {
  return value.replace(/^git@github\.com:/, "https://github.com/").replace(/\.git$/, "");
}

function normalizedWorkflowPath(value) {
  if (typeof value !== "string") return value;
  const match = value.match(/^(\.github\/workflows\/bounded-soak\.yml)(?:@[A-Za-z0-9._/-]+)?$/);
  return match ? match[1] : value;
}

function assertCandidateAnnotatedTag(runtimeRoot, candidate) {
  const reference = `refs/tags/${candidate.runtime.tag}`;
  expect(git(runtimeRoot, ["cat-file", "-t", reference], "candidate tag type"), "tag", "candidate tag type");
  expect(git(runtimeRoot, ["rev-parse", `${reference}^{commit}`], "candidate tag commit"), candidate.runtime.commit, "candidate tag commit");
  expect(git(runtimeRoot, ["rev-parse", `${reference}^{tag}`], "candidate tag object"), candidate.runtime.tag_object_oid, "candidate tag object");
  expect(git(runtimeRoot, ["show-ref", "--verify", "--hash", reference], "candidate tag reference"), candidate.runtime.tag_object_oid, "candidate tag reference");
  const tagObject = git(runtimeRoot, ["cat-file", "-p", reference], "candidate annotated tag");
  const headers = new Map();
  for (const line of tagObject.split("\n")) {
    if (line === "") break;
    const space = line.indexOf(" ");
    if (space > 0 && !headers.has(line.slice(0, space))) headers.set(line.slice(0, space), line.slice(space + 1));
  }
  expect(headers.get("object"), candidate.runtime.commit, "candidate annotated tag object");
  expect(headers.get("type"), "commit", "candidate annotated tag target type");
  expect(headers.get("tag"), candidate.runtime.tag, "candidate annotated tag name");
}

function assertFirstParent(runtimeRoot, candidateCommit, stableCommit) {
  const firstParent = git(runtimeRoot, ["rev-list", "--first-parent", stableCommit], "stable first-parent history").split("\n");
  if (!firstParent.includes(candidateCommit)) fail("candidate commit is not on stable first-parent history");
}

function assertPostCandidateAllowlist(runtimeRoot, candidateCommit, stableCommit, allowedReleaseFiles) {
  const output = git(
    runtimeRoot,
    ["diff", "--name-status", "--no-renames", "-z", `${candidateCommit}..${stableCommit}`],
    "post-candidate change inventory",
    { buffer: true },
  );
  const records = output.toString("utf8").split("\0").filter(Boolean);
  if (records.length % 2 !== 0) fail("post-candidate change inventory is malformed");
  const forbidden = [];
  for (let index = 0; index < records.length; index += 2) {
    const status = records[index];
    const file = records[index + 1];
    if (!/^[AMD]$/.test(status)) fail(`post-candidate change ${status} is not allowed for ${file}`);
    if (!allowedReleaseFiles.has(file) && !ALLOWED_POST_CANDIDATE_FILES.has(file)) forbidden.push(file);
  }
  if (forbidden.length > 0) fail(`Runtime behavior changed after soak: ${forbidden.join(", ")}`);
}

function assertGovernanceArtifacts(runtimeRoot, lock) {
  for (const binding of lock.stable_governance_artifacts) {
    const document = readRepositoryFile(runtimeRoot, binding.path, `stable governance artifact ${binding.path}`);
    if (sha256(document.source) !== binding.sha256) fail(`stable governance artifact ${binding.path} raw hash mismatch`);
  }
}

function assertComplexityRatchet(runtimeRoot, candidateCommit) {
  const relativePath = "docs/architecture/runtime-complexity-budget.json";
  const candidate = parseJson(git(runtimeRoot, ["show", `${candidateCommit}:${relativePath}`], "candidate complexity budget"), "candidate complexity budget");
  const stable = readRootJson(runtimeRoot, relativePath, "stable complexity budget").value;
  expect(stable.schema_version, candidate.schema_version, "complexity budget schema");
  expect(stable.baseline_commit, candidate.baseline_commit, "complexity budget baseline");
  expect(stable.intent, candidate.intent, "complexity budget intent");
  expect(Object.keys(stable.thresholds ?? {}).sort(), Object.keys(candidate.thresholds ?? {}).sort(), "complexity budget threshold keys");
  for (const [key, candidateValue] of Object.entries(candidate.thresholds ?? {})) {
    const stableValue = stable.thresholds[key];
    if (!Number.isFinite(candidateValue) || !Number.isFinite(stableValue) || candidateValue < 0 || stableValue < 0) {
      fail(`complexity budget threshold ${key} must be a non-negative finite number`);
    }
    if (stableValue > candidateValue) fail(`complexity budget threshold ${key} moved upward`);
  }
}

function normalizedPackage(value) {
  const normalized = structuredClone(value);
  delete normalized.version;
  return normalized;
}

function normalizedLock(value) {
  const normalized = structuredClone(value);
  delete normalized.version;
  if (normalized.packages?.[""]) delete normalized.packages[""].version;
  return normalized;
}

function normalizedRuntimeManifest(value) {
  const normalized = structuredClone(value);
  for (const key of ["version", "status", "source_tag", "docker_tag", "default_installer_ref"]) {
    delete normalized.release?.[key];
  }
  return normalized;
}

function assertSemanticNoDrift(runtimeRoot, candidateCommit, stableFiles) {
  const candidatePackage = parseJson(git(runtimeRoot, ["show", `${candidateCommit}:package.json`], "candidate package.json"), "candidate package.json");
  const candidateLock = parseJson(git(runtimeRoot, ["show", `${candidateCommit}:package-lock.json`], "candidate package-lock.json"), "candidate package-lock.json");
  const candidateManifest = parseJson(git(runtimeRoot, ["show", `${candidateCommit}:runtime-manifest.json`], "candidate runtime-manifest.json"), "candidate runtime-manifest.json");
  expect(normalizedPackage(stableFiles.packageJson), normalizedPackage(candidatePackage), "package.json except version");
  expect(normalizedLock(stableFiles.packageLock), normalizedLock(candidateLock), "package-lock dependency graph");
  expect(normalizedRuntimeManifest(stableFiles.runtimeManifest), normalizedRuntimeManifest(candidateManifest), "runtime-manifest behavior surface");
}

function assertReleaseTrainTransition(runtimeRoot, candidateCommit, stableTrain) {
  const candidateTrain = parseJson(git(runtimeRoot, ["show", `${candidateCommit}:release-train.json`], "candidate release-train.json"), "candidate release-train.json");
  if (candidateTrain.schema_version !== "aionis_release_train_v1" || candidateTrain.status !== "candidate") fail("soaked commit is not a candidate train");
  if (stableTrain.schema_version !== "aionis_release_train_v2" || stableTrain.status !== "stable") fail("target train is not stable v2");
  const allowedRuntimeChanges = new Set(["version", "source_tag", "docker_tag", "default_installer_ref"]);
  expect(Object.keys(stableTrain.runtime).sort(), Object.keys(candidateTrain.runtime).sort(), "release train Runtime keys");
  for (const key of Object.keys(candidateTrain.runtime)) {
    if (!allowedRuntimeChanges.has(key)) expect(stableTrain.runtime[key], candidateTrain.runtime[key], `release train Runtime ${key}`);
  }
  expect(Object.keys(stableTrain.packages).sort(), Object.keys(candidateTrain.packages).sort(), "release train package keys");
  for (const key of Object.keys(candidateTrain.packages)) {
    if (key !== "create") expect(stableTrain.packages[key], candidateTrain.packages[key], `release train package ${key}`);
  }
  const candidateCreate = candidateTrain.packages.create;
  const stableCreate = stableTrain.packages.create;
  for (const key of ["name", "repository", "package_path"]) expect(stableCreate[key], candidateCreate[key], `Create package ${key}`);
  if (!/^\d+\.\d+\.\d+$/.test(stableCreate.version ?? "") || stableCreate.source_ref !== `v${stableCreate.version}` || !COMMIT_RE.test(stableCreate.source_commit ?? "")) {
    fail("stable Create coordinates are not immutable semantic coordinates");
  }
}

function validateCandidatePublication(candidate, lock) {
  if (candidate.schema_version !== "aionis_release_publication_evidence_v1" || candidate.release_status !== "candidate") fail("candidate publication receipt schema/status is invalid");
  expect(
    [candidate.runtime?.version, candidate.runtime?.tag, candidate.runtime?.commit],
    [lock.candidate.version, lock.candidate.tag, lock.candidate.commit],
    "candidate Runtime coordinates",
  );
  if (!COMMIT_RE.test(candidate.runtime?.tag_object_oid ?? "")) fail("candidate annotated tag object is invalid");
  expect([candidate.main_ci?.conclusion, candidate.main_ci?.head_sha], ["success", lock.candidate.commit], "candidate main CI");
  expect(
    [
      candidate.provider_evidence?.conclusion,
      candidate.provider_evidence?.head_sha,
      candidate.provider_evidence?.provider,
      candidate.provider_evidence?.model,
      candidate.provider_evidence?.persisted_model,
      candidate.provider_evidence?.dimensions,
      candidate.provider_evidence?.embedding_status,
    ],
    [
      "success",
      lock.candidate.commit,
      lock.providers.embedding.provider,
      lock.providers.embedding.model,
      lock.providers.embedding.persisted_model,
      lock.providers.embedding.dimensions,
      "ready",
    ],
    "candidate embedding evidence",
  );
  expect(
    [candidate.docker?.image, candidate.docker?.release_tag, candidate.docker?.digest, candidate.docker?.platforms, candidate.docker?.latest_promoted],
    [lock.candidate.image, lock.candidate.tag, lock.candidate.digest, [lock.candidate.platform], false],
    "candidate Docker publication",
  );
  expect(
    [candidate.docker?.source_workflow?.conclusion, candidate.docker?.source_workflow?.head_branch, candidate.docker?.source_workflow?.head_sha],
    ["success", lock.candidate.tag, lock.candidate.commit],
    "candidate Docker workflow",
  );
  expect(candidate.docker?.source_workflow?.completed_exact_digest_gates, {
    build: true,
    immutable_subject_verification: true,
    release_smoke: true,
    process_death_recovery: true,
    cross_version_upgrade: true,
    release_tag_promotion: true,
  }, "candidate exact-digest gates");
  expect(
    [candidate.github_release?.target_commitish, candidate.github_release?.prerelease, candidate.github_release?.latest, candidate.github_release?.draft],
    [lock.candidate.commit, true, false, false],
    "candidate GitHub prerelease",
  );
  const previousLatest = candidate.docker?.latest_at_verification;
  if (
    previousLatest?.tag !== "latest"
    || previousLatest?.platform !== lock.candidate.platform
    || !DIGEST_RE.test(previousLatest?.digest ?? "")
    || !TAG_RE.test(previousLatest?.version ?? "")
    || !COMMIT_RE.test(previousLatest?.commit ?? "")
  ) fail("candidate previous latest coordinates are invalid");
  assertNoSecretMaterial(candidate, "candidate publication receipt");
  return previousLatest;
}

function complete(metric, field, expectedTotal = null) {
  if (!Number.isInteger(metric?.passed) || !Number.isInteger(metric?.total) || metric.total < 1 || metric.passed !== metric.total) {
    fail(`${field} is not complete`);
  }
  if (expectedTotal !== null && metric.total !== expectedTotal) fail(`${field} denominator must be ${expectedTotal}`);
}

export async function anonymousWorkflowRunFetcher(sourceWorkflow) {
  const base = `https://api.github.com/repos/ostinatocc/AionisRuntime-evals/actions/runs/${sourceWorkflow.run_id}/attempts/${sourceWorkflow.run_attempt}`;
  const request = (url) => fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "aionis-runtime-evals-stable-verifier",
    },
    redirect: "error",
    signal: AbortSignal.timeout(120_000),
  });
  const [runResponse, jobsResponse] = await Promise.all([request(base), request(`${base}/jobs?per_page=100`)]);
  for (const response of [runResponse, jobsResponse]) {
    if (!response.ok) {
      const remaining = response.headers.get("x-ratelimit-remaining");
      fail(`source workflow lookup failed with HTTP ${response.status}${remaining === "0" ? " (anonymous GitHub API rate limit exhausted)" : ""}`);
    }
  }
  const [run, jobs] = await Promise.all([runResponse.json(), jobsResponse.json()]);
  return { run, jobs: jobs.jobs };
}

function anonymousGitHubRequest(url, field) {
  return fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "aionis-runtime-evals-stable-verifier",
    },
    redirect: "error",
    signal: AbortSignal.timeout(120_000),
  }).then(async (response) => {
    if (!response.ok) {
      const remaining = response.headers.get("x-ratelimit-remaining");
      fail(`${field} lookup failed with HTTP ${response.status}${remaining === "0" ? " (anonymous GitHub API rate limit exhausted)" : ""}`);
    }
    return response.json();
  });
}

export async function anonymousArtifactProvenanceFetcher(manifest) {
  const firstUri = new URL(manifest.entries[0].uri);
  const releaseTag = firstUri.pathname.split("/").filter(Boolean).at(-2);
  const [release, artifactResponse] = await Promise.all([
    anonymousGitHubRequest(
      `https://api.github.com/repos/ostinatocc/AionisRuntime-evals/releases/tags/${encodeURIComponent(releaseTag)}`,
      "release asset metadata",
    ),
    anonymousGitHubRequest(
      `https://api.github.com/repos/ostinatocc/AionisRuntime-evals/actions/runs/${manifest.source_workflow.run_id}/artifacts?per_page=100`,
      "Actions artifact metadata",
    ),
  ]);
  expect(release.tag_name, releaseTag, "anonymous release asset tag");
  const expectedArtifactNames = new Set(manifest.entries.map((entry) => actionsArtifactName(manifest, entry)));
  return {
    fetched_at: new Date().toISOString(),
    release: {
      id: release.id,
      tag_name: release.tag_name,
      target_commitish: release.target_commitish,
      draft: release.draft,
      prerelease: release.prerelease,
      immutable: release.immutable,
      created_at: release.created_at,
      published_at: release.published_at,
      author: release.author?.login,
    },
    assets: (release.assets ?? []).map((asset) => ({
      id: asset.id,
      name: asset.name,
      size: asset.size,
      digest: asset.digest,
      state: asset.state,
      created_at: asset.created_at,
      updated_at: asset.updated_at,
      uploader: asset.uploader?.login,
      download_url: asset.browser_download_url,
    })),
    artifacts: (artifactResponse.artifacts ?? []).filter((artifact) => expectedArtifactNames.has(artifact.name)).map((artifact) => ({
      id: artifact.id,
      name: artifact.name,
      size_in_bytes: artifact.size_in_bytes,
      digest: artifact.digest,
      expired: artifact.expired,
      created_at: artifact.created_at,
      updated_at: artifact.updated_at,
      expires_at: artifact.expires_at,
      workflow_run_id: artifact.workflow_run?.id,
      workflow_run_head_sha: artifact.workflow_run?.head_sha,
    })),
  };
}

export function workflowRunFetcherFromEvidenceFile(file) {
  const evidencePath = path.resolve(file);
  const evidenceStat = fs.lstatSync(evidencePath);
  if (evidenceStat.isSymbolicLink() || !evidenceStat.isFile()) fail("workflow run evidence must be a regular non-symlink file");
  if ((evidenceStat.mode & 0o077) !== 0) fail("workflow run evidence permissions must be 0600 or stricter");
  const evidence = readJsonFile(evidencePath, "workflow run evidence").value;
  expectKeys(evidence, ["schema_version", "repository", "fetched_at", "records", "release", "artifacts", "assets"], "workflow run evidence");
  expect(evidence.schema_version, "aionis_workflow_run_evidence_v1", "workflow run evidence schema");
  expect(evidence.repository, "ostinatocc/AionisRuntime-evals", "workflow run evidence repository");
  const fetchedAt = Date.parse(evidence.fetched_at);
  if (!Number.isFinite(fetchedAt)) fail("workflow run evidence fetched_at is invalid");
  if (!Array.isArray(evidence.records) || evidence.records.length !== 3) {
    fail("workflow run evidence must contain exactly pilot, soak, and publisher records");
  }
  if (!Array.isArray(evidence.assets) || evidence.assets.length !== 6) {
    fail("workflow run evidence must contain exactly six release assets");
  }
  if (!Array.isArray(evidence.artifacts) || evidence.artifacts.length !== 6) {
    fail("workflow run evidence must contain exactly six Actions artifacts");
  }
  expectKeys(evidence.release, [
    "id",
    "tag_name",
    "target_commitish",
    "draft",
    "prerelease",
    "immutable",
    "created_at",
    "published_at",
    "author",
  ], "workflow run evidence.release");
  const releasePublishedAt = Date.parse(evidence.release.published_at);
  if (!Number.isFinite(releasePublishedAt) || releasePublishedAt > fetchedAt) {
    fail("workflow run evidence release was not published when evidence was fetched");
  }
  for (const [index, asset] of evidence.assets.entries()) {
    const field = `workflow run evidence.assets[${index}]`;
    expectKeys(asset, [
      "id",
      "name",
      "size",
      "digest",
      "state",
      "created_at",
      "updated_at",
      "uploader",
      "download_url",
    ], field);
    const updatedAt = Date.parse(asset.updated_at);
    if (!Number.isFinite(updatedAt) || updatedAt > fetchedAt) fail(`${field} was not uploaded when evidence was fetched`);
  }
  for (const [index, artifact] of evidence.artifacts.entries()) {
    const field = `workflow run evidence.artifacts[${index}]`;
    expectKeys(artifact, [
      "id",
      "name",
      "size_in_bytes",
      "digest",
      "expired",
      "created_at",
      "updated_at",
      "expires_at",
      "workflow_run_id",
      "workflow_run_head_sha",
    ], field);
    const updatedAt = Date.parse(artifact.updated_at);
    const expiresAt = Date.parse(artifact.expires_at);
    if (!Number.isFinite(updatedAt) || updatedAt > fetchedAt) fail(`${field} was not uploaded when evidence was fetched`);
    if (!Number.isFinite(expiresAt) || expiresAt <= fetchedAt) fail(`${field} is expired or expires before verification`);
  }
  const records = new Map();
  const phases = [];
  for (const [index, record] of evidence.records.entries()) {
    const field = `workflow run evidence.records[${index}]`;
    expectKeys(record, ["source", "run", "job"], field);
    expectKeys(record.source, ["repository", "run_id", "run_attempt", "head_sha", "phase", "job", "environment"], `${field}.source`);
    if (!new Set(["pilot", "soak", "publisher"]).has(record.source.phase)) fail(`${field}.source.phase is invalid`);
    validateWorkflowSource(record.source, record.source.phase, record.source.head_sha);
    expectKeys(record.run, [
      "id",
      "run_attempt",
      "event",
      "status",
      "conclusion",
      "head_sha",
      "repository",
      "path",
      "created_at",
      "updated_at",
    ], `${field}.run`);
    expectKeys(record.job, [
      "id",
      "run_id",
      "run_attempt",
      "head_sha",
      "name",
      "status",
      "conclusion",
      "labels",
      "runner_id",
      "runner_group_name",
      "started_at",
      "completed_at",
    ], `${field}.job`);
    expect(
      [
        record.run.id,
        record.run.run_attempt,
        record.run.event,
        record.run.status,
        record.run.conclusion,
        record.run.head_sha,
        record.run.repository,
        normalizedWorkflowPath(record.run.path),
      ],
      [
        record.source.run_id,
        record.source.run_attempt,
        "workflow_dispatch",
        "completed",
        "success",
        record.source.head_sha,
        "ostinatocc/AionisRuntime-evals",
        ".github/workflows/bounded-soak.yml",
      ],
      `${field}.run identity`,
    );
    const expectedJobName = record.source.phase === "publisher"
      ? "Protected evidence publisher"
      : `Protected ${record.source.phase} preflight`;
    expect(
      [
        record.job.run_id,
        record.job.run_attempt,
        record.job.head_sha,
        record.job.name,
        record.job.status,
        record.job.conclusion,
      ],
      [
        record.source.run_id,
        record.source.run_attempt,
        record.source.head_sha,
        expectedJobName,
        "completed",
        "success",
      ],
      `${field}.job identity`,
    );
    if (!Number.isSafeInteger(record.job.id) || record.job.id < 1) fail(`${field}.job.id is invalid`);
    if (!Number.isSafeInteger(record.job.runner_id) || record.job.runner_id < 1) fail(`${field}.job.runner_id is invalid`);
    if (record.job.runner_group_name !== null && typeof record.job.runner_group_name !== "string") {
      fail(`${field}.job.runner_group_name must be string or null`);
    }
    if (!Array.isArray(record.job.labels) || record.job.labels.some((label) => typeof label !== "string")) {
      fail(`${field}.job.labels must be an array of strings`);
    }
    const updatedAt = Date.parse(record.run.updated_at);
    if (!Number.isFinite(updatedAt) || updatedAt > fetchedAt) fail(`${field}.run was not complete when evidence was fetched`);
    const key = `${record.source.phase}:${record.source.run_id}:${record.source.run_attempt}`;
    if (records.has(key)) fail(`workflow run evidence has duplicate run identity ${key}`);
    records.set(key, record);
    phases.push(record.source.phase);
  }
  expect(phases.sort(), ["pilot", "publisher", "soak"], "workflow run evidence phases");
  const fetcher = async (source) => {
    const record = records.get(`${source.phase}:${source.run_id}:${source.run_attempt}`);
    if (!record) fail(`workflow run evidence has no record for ${source.run_id} attempt ${source.run_attempt}`);
    expect(record.source, source, `${source.phase} workflow evidence source`);
    return {
      run: { ...record.run, repository: { full_name: record.run.repository } },
      jobs: [record.job],
    };
  };
  Object.defineProperty(fetcher, "artifactProvenanceFetcher", {
    value: async () => ({
      fetched_at: evidence.fetched_at,
      release: structuredClone(evidence.release),
      assets: structuredClone(evidence.assets),
      artifacts: structuredClone(evidence.artifacts),
    }),
    enumerable: false,
  });
  return fetcher;
}

async function defaultArtifactFetcher(entry) {
  const response = await fetch(entry.uri, {
    headers: { "User-Agent": "aionis-runtime-evals-stable-verifier" },
    redirect: "follow",
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok || response.body === null) fail(`artifact ${entry.kind} download failed with HTTP ${response.status}`);
  return response.body;
}

function validateWorkflowSource(source, phase, harnessCommit) {
  const publisher = phase === "publisher";
  expect(
    source,
    {
      repository: "ostinatocc/AionisRuntime-evals",
      run_id: source?.run_id,
      run_attempt: source?.run_attempt,
      head_sha: harnessCommit,
      phase,
      job: publisher ? "evidence-publisher" : "paid-preflight",
      environment: publisher ? PUBLISHER_ENVIRONMENT : "bounded-soak",
    },
    `${phase} workflow source`,
  );
  if (!Number.isInteger(source.run_id) || source.run_id < 1 || !Number.isInteger(source.run_attempt) || source.run_attempt < 1) {
    fail(`${phase} workflow source run identity is invalid`);
  }
}

async function verifyWorkflowRun(source, phase, harnessCommit, workflowRunFetcher) {
  validateWorkflowSource(source, phase, harnessCommit);
  const result = await workflowRunFetcher(source);
  const run = result?.run;
  const jobs = result?.jobs;
  expect(
    [
      run?.id,
      run?.run_attempt,
      run?.event,
      run?.status,
      run?.conclusion,
      run?.head_sha,
      run?.repository?.full_name,
      normalizedWorkflowPath(run?.path),
    ],
    [
      source.run_id,
      source.run_attempt,
      "workflow_dispatch",
      "completed",
      "success",
      harnessCommit,
      "ostinatocc/AionisRuntime-evals",
      ".github/workflows/bounded-soak.yml",
    ],
    "artifact source workflow run",
  );
  if (!Array.isArray(jobs)) fail(`artifact source workflow jobs are missing for ${phase}`);
  const expectedJobName = phase === "publisher" ? "Protected evidence publisher" : `Protected ${phase} preflight`;
  const matchingJobs = jobs.filter((job) => job?.name === expectedJobName);
  if (matchingJobs.length !== 1) fail(`source workflow must contain exactly one protected ${phase} job`);
  const job = matchingJobs[0];
  expect([job.status, job.conclusion], ["completed", "success"], `protected ${phase} job result`);
  expect(
    [job.run_id, job.run_attempt, job.head_sha],
    [source.run_id, source.run_attempt, harnessCommit],
    `protected ${phase} job source`,
  );
  if (!Number.isSafeInteger(job.id) || job.id < 1) fail(`protected ${phase} job id is invalid`);
  const labels = Array.isArray(job.labels) ? job.labels : [];
  if (phase === "publisher") {
    if (labels.length === 0 || labels.includes("self-hosted")) fail("protected publisher job must use a GitHub-hosted runner");
  } else {
    for (const label of ["self-hosted", "linux", "x64", "aionis-soak-persistent"]) {
      if (!labels.includes(label)) fail(`protected ${phase} job is missing runner label ${label}`);
    }
  }
  const created = Date.parse(run?.created_at);
  const updated = Date.parse(run?.updated_at);
  const jobStarted = Date.parse(job.started_at);
  const jobCompleted = Date.parse(job.completed_at);
  if (!(created <= jobStarted && jobStarted < jobCompleted && jobCompleted <= updated)) fail(`protected ${phase} job timestamps are invalid`);
  return { runStarted: created, runCompleted: updated, jobStarted, jobCompleted };
}

async function verifyArtifactBytes(entry, artifactFetcher) {
  if (entry.bytes > MAX_ARTIFACT_BYTES) fail(`artifact ${entry.kind} exceeds the 8 MiB authority limit`);
  const payload = await artifactFetcher(entry);
  const iterable = typeof payload === "string" || Buffer.isBuffer(payload) || payload instanceof Uint8Array
    ? [Buffer.from(payload)]
    : payload;
  if (!iterable || typeof iterable[Symbol.asyncIterator] !== "function" && typeof iterable[Symbol.iterator] !== "function") {
    fail(`artifact ${entry.kind} fetcher returned no byte stream`);
  }
  const hash = createHash("sha256");
  const chunks = [];
  let bytes = 0;
  let scanTail = "";
  for await (const value of iterable) {
    const chunk = Buffer.from(value);
    bytes += chunk.byteLength;
    if (bytes > entry.bytes) fail(`artifact ${entry.kind} exceeds its declared byte length`);
    hash.update(chunk);
    chunks.push(chunk);
    const scanWindow = `${scanTail}${chunk.toString("utf8")}`;
    assertNoSecretMaterial(scanWindow, `artifact ${entry.kind}`);
    scanTail = scanWindow.slice(-2048);
  }
  if (bytes !== entry.bytes) fail(`artifact ${entry.kind} byte length mismatch`);
  if (hash.digest("hex") !== entry.sha256) fail(`artifact ${entry.kind} SHA-256 mismatch`);
  return Buffer.concat(chunks, bytes);
}

function verifyReleaseAssetProvenance(manifest, assets, window, releaseWindow, fetchedAt) {
  if (!Array.isArray(assets) || assets.length !== manifest.entries.length) {
    fail("release asset metadata must contain exactly six assets");
  }
  const byName = new Map();
  const ids = new Set();
  for (const [index, asset] of assets.entries()) {
    const field = `release asset metadata[${index}]`;
    expectKeys(asset, [
      "id",
      "name",
      "size",
      "digest",
      "state",
      "created_at",
      "updated_at",
      "uploader",
      "download_url",
    ], field);
    if (!Number.isSafeInteger(asset.id) || asset.id < 1 || ids.has(asset.id)) fail(`${field}.id must be a unique positive safe integer`);
    ids.add(asset.id);
    if (typeof asset.name !== "string" || byName.has(asset.name)) fail(`${field}.name must be unique`);
    byName.set(asset.name, asset);
  }
  for (const entry of manifest.entries) {
    const assetName = path.posix.basename(new URL(entry.uri).pathname);
    const asset = byName.get(assetName);
    if (!asset) fail(`release asset metadata is missing ${assetName}`);
    expect(
      [asset.size, asset.digest, asset.state, asset.uploader, asset.download_url],
      [entry.bytes, `sha256:${entry.sha256}`, "uploaded", "github-actions[bot]", entry.uri],
      `release asset ${entry.kind} server metadata`,
    );
    const created = Date.parse(asset.created_at);
    const updated = Date.parse(asset.updated_at);
    if (!(window.jobStarted <= created && created <= updated && updated <= window.jobCompleted)) {
      fail(`release asset ${entry.kind} was not created and finalized inside the protected publisher job`);
    }
    if (!(releaseWindow.created <= created && updated <= releaseWindow.published)) {
      fail(`release asset ${entry.kind} was not finalized before the immutable release was published`);
    }
    if (updated > fetchedAt) fail(`release asset ${entry.kind} was not complete when provenance was fetched`);
  }
}

function verifyReleaseProvenance(manifest, release, window, fetchedAt) {
  expectKeys(release, [
    "id",
    "tag_name",
    "target_commitish",
    "draft",
    "prerelease",
    "immutable",
    "created_at",
    "published_at",
    "author",
  ], "release metadata");
  if (!Number.isSafeInteger(release.id) || release.id < 1) fail("release metadata id must be a positive safe integer");
  const expectedTag = new URL(manifest.entries[0].uri).pathname.split("/").filter(Boolean).at(-2);
  expect(
    [
      release.tag_name,
      release.target_commitish,
      release.draft,
      release.prerelease,
      release.immutable,
      release.author,
    ],
    [expectedTag, manifest.harness_commit, false, true, true, "github-actions[bot]"],
    "immutable soak release metadata",
  );
  const created = Date.parse(release.created_at);
  const published = Date.parse(release.published_at);
  if (!(window.jobStarted <= created && created <= published && published <= window.jobCompleted)) {
    fail("immutable soak release was not created and published inside the protected publisher job");
  }
  if (published > fetchedAt) fail("immutable soak release was not published when provenance was fetched");
  return { created, published };
}

function actionsArtifactName(manifest, entry) {
  const source = manifest.source_workflow;
  return `soak-${entry.kind}-${manifest.harness_commit}-${source.run_id}-${source.run_attempt}-${entry.sha256}`;
}

function verifyActionsArtifactProvenance(manifest, artifacts, window, fetchedAt) {
  if (!Array.isArray(artifacts) || artifacts.length !== manifest.entries.length) {
    fail("Actions artifact metadata must contain exactly six artifacts");
  }
  const byName = new Map();
  const ids = new Set();
  for (const [index, artifact] of artifacts.entries()) {
    const field = `Actions artifact metadata[${index}]`;
    expectKeys(artifact, [
      "id",
      "name",
      "size_in_bytes",
      "digest",
      "expired",
      "created_at",
      "updated_at",
      "expires_at",
      "workflow_run_id",
      "workflow_run_head_sha",
    ], field);
    if (!Number.isSafeInteger(artifact.id) || artifact.id < 1 || ids.has(artifact.id)) {
      fail(`${field}.id must be a unique positive safe integer`);
    }
    ids.add(artifact.id);
    if (typeof artifact.name !== "string" || byName.has(artifact.name)) fail(`${field}.name must be unique`);
    byName.set(artifact.name, artifact);
    if (!Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes < 1) {
      fail(`${field}.size_in_bytes must be a positive safe integer`);
    }
    if (!/^sha256:[a-f0-9]{64}$/.test(artifact.digest ?? "")) fail(`${field}.digest is invalid`);
    if (artifact.expired !== false) fail(`${field} is expired`);
    expect(
      [artifact.workflow_run_id, artifact.workflow_run_head_sha],
      [manifest.source_workflow.run_id, manifest.harness_commit],
      `${field} workflow ownership`,
    );
    const created = Date.parse(artifact.created_at);
    const updated = Date.parse(artifact.updated_at);
    const expires = Date.parse(artifact.expires_at);
    if (!(window.jobStarted <= created && created <= updated && updated <= window.jobCompleted)) {
      fail(`${field} was not created and finalized inside the protected soak producer job`);
    }
    if (!(updated < expires)) fail(`${field}.expires_at must follow upload completion`);
    if (updated > fetchedAt || expires <= fetchedAt) fail(`${field} was unavailable when provenance was fetched`);
  }
  for (const entry of manifest.entries) {
    if (!byName.has(actionsArtifactName(manifest, entry))) {
      fail(`Actions artifact metadata is missing the content-addressed ${entry.kind} upload`);
    }
  }
}

async function verifyExternalArtifactAuthority(manifest, {
  workflowRunFetcher,
  artifactProvenanceFetcher,
  artifactFetcher,
}) {
  const producerWindow = await verifyWorkflowRun(manifest.source_workflow, "soak", manifest.harness_commit, workflowRunFetcher);
  const publisherWindow = await verifyWorkflowRun(manifest.publisher_workflow, "publisher", manifest.harness_commit, workflowRunFetcher);
  const generated = Date.parse(manifest.generated_at);
  if (!(producerWindow.jobStarted <= generated && generated <= producerWindow.jobCompleted)) fail("artifact manifest was not generated inside the protected soak job");
  if (producerWindow.jobCompleted > publisherWindow.jobStarted) fail("evidence publisher did not start after the protected soak producer completed");
  const provenance = await artifactProvenanceFetcher(manifest);
  expectKeys(provenance, ["fetched_at", "release", "artifacts", "assets"], "artifact provenance");
  const fetchedAt = Date.parse(provenance.fetched_at);
  if (!Number.isFinite(fetchedAt)) fail("artifact provenance fetched_at is invalid");
  verifyActionsArtifactProvenance(manifest, provenance.artifacts, producerWindow, fetchedAt);
  const releaseWindow = verifyReleaseProvenance(manifest, provenance.release, publisherWindow, fetchedAt);
  verifyReleaseAssetProvenance(manifest, provenance.assets, publisherWindow, releaseWindow, fetchedAt);
  const payloads = new Map();
  for (const entry of manifest.entries) payloads.set(entry.kind, await verifyArtifactBytes(entry, artifactFetcher));
  return { producerWindow, publisherWindow, payloads };
}

function validateSoakEvidence({ evidence, lock, publication, publicationBinding, authorityCommit, runtimeRoot }) {
  if (evidence.schema_version !== "aionis_release_bounded_soak_evidence_v1") fail("bounded soak receipt schema is invalid");
  expect([evidence.authority?.decision, evidence.authority?.publication_authority], ["pass", false], "bounded soak authority decision");
  expect(evidence.candidate_publication_receipt, { path: publicationBinding.path, sha256: publicationBinding.sha256 }, "bounded soak publication binding");
  expect(
    evidence.candidate,
    {
      version: lock.candidate.version,
      tag: lock.candidate.tag,
      commit: lock.candidate.commit,
      image: lock.candidate.image,
      digest: lock.candidate.digest,
      platform: lock.candidate.platform,
      oci_revision: lock.candidate.oci_revision,
      oci_version: lock.candidate.oci_version,
    },
    "bounded soak candidate",
  );
  expect(
    evidence.harness,
    {
      repository: EVAL_REPOSITORY,
      commit: authorityCommit,
      real_tools: true,
      deterministic_outcome_verifier: true,
    },
    "bounded soak harness",
  );
  expect(evidence.providers?.embedding, lock.providers.embedding, "bounded soak embedding provider");
  expect(
    evidence.providers?.agent,
    {
      provider: lock.providers.agent.provider,
      requested_model: lock.providers.agent.requested_model,
      returned_models: lock.providers.agent.allowed_returned_models,
      fallback_used: false,
    },
    "bounded soak Agent provider",
  );
  const protocol = evidence.protocol;
  for (const key of ["authority_manifest", "workload_manifest", "artifact_bundle_manifest"]) {
    if (!protocol?.[key]) fail(`bounded soak protocol ${key} binding is missing`);
  }
  expect(protocol.authority_manifest_sha256, protocol.authority_manifest.sha256, "authority manifest duplicate hash");
  expect(protocol.workload_manifest_sha256, protocol.workload_manifest.sha256, "workload manifest duplicate hash");
  expect(protocol.artifact_bundle_sha256, protocol.artifact_bundle_manifest.sha256, "artifact bundle duplicate hash");
  expect(
    [
      protocol.groups,
      protocol.scenarios,
      protocol.product_invariants,
      protocol.pilot_chat_calls,
      protocol.soak_chat_calls,
      protocol.soak_waves,
    ],
    [
      lock.protocol.groups,
      lock.protocol.scenarios,
      lock.protocol.product_invariants,
      lock.execution_limits.pilot_chat_calls,
      lock.execution_limits.soak_chat_calls,
      lock.execution_limits.soak_waves,
    ],
    "bounded soak protocol denominators",
  );
  expect(
    [
      evidence.pilot?.passed,
      evidence.pilot?.semantic_chat_calls,
      evidence.pilot?.aionis_action_completion,
      evidence.pilot?.wrong_direct_use,
      evidence.pilot?.failed_direct_use,
      evidence.pilot?.negative_direct_use,
      evidence.pilot?.terminal_backlog,
      evidence.pilot?.semantic_retries,
      evidence.pilot?.worker_errors,
    ],
    [
      true,
      lock.execution_limits.pilot_chat_calls,
      { passed: lock.protocol.pilot.aionis_trials, total: lock.protocol.pilot.aionis_trials },
      0,
      0,
      { unsafe_direct_uses: 0, total: 1 },
      { dead_letter: 0, provider_mismatch: 0, exhausted: 0 },
      0,
      0,
    ],
    "bounded soak protected pilot",
  );
  for (const field of ["inspect_coverage", "outcome_coverage", "feedback_coverage", "measure_coverage", "durable_exact_replay"]) {
    complete(evidence.pilot?.[field], `pilot ${field}`, lock.protocol.pilot.aionis_trials);
  }
  if (!Number.isFinite(evidence.pilot?.cost_usd) || evidence.pilot.cost_usd < 0) fail("pilot cost must be a non-negative finite number");
  if (!Array.isArray(evidence.waves) || evidence.waves.length !== lock.protocol.soak.waves) fail("bounded soak must contain exactly three waves");
  evidence.waves.forEach((wave, index) => {
    expect(
      [wave.index, wave.semantic_chat_calls, wave.aionis_action_completion?.total, wave.wrong_direct_use],
      [index + 1, lock.protocol.soak.semantic_chat_calls_per_wave, lock.protocol.soak.aionis_trials_per_wave, 0],
      `bounded soak wave ${index + 1}`,
    );
    expect(
      wave.negative_direct_use,
      { unsafe_direct_uses: 0, total: lock.protocol.soak.negative_transfer_trials / lock.protocol.soak.waves },
      `bounded soak wave ${index + 1} negative direct-use`,
    );
    if (
      !Number.isInteger(wave.aionis_action_completion?.passed)
      || wave.aionis_action_completion.passed < 8
      || wave.aionis_action_completion.passed > lock.protocol.soak.aionis_trials_per_wave
    ) {
      fail(`bounded soak wave ${index + 1} action completion is below 8/9`);
    }
  });
  const results = evidence.results;
  const aggregatePassed = results?.aionis_action_completion?.passed;
  const wavePassed = evidence.waves.reduce((total, wave) => total + wave.aionis_action_completion.passed, 0);
  if (
    results?.aionis_action_completion?.total !== lock.protocol.soak.total_aionis_trials
    || !Number.isInteger(aggregatePassed)
    || aggregatePassed < 26
    || aggregatePassed > lock.protocol.soak.total_aionis_trials
    || aggregatePassed !== wavePassed
  ) {
    fail("bounded soak aggregate action completion is below 26/27");
  }
  complete(results?.product_invariants, "product invariants", lock.protocol.product_invariants.length);
  complete(results?.restart_recovery, "restart recovery", lock.execution_limits.soak_waves);
  for (const field of ["inspect_coverage", "outcome_coverage", "feedback_coverage", "measure_coverage", "durable_exact_replay"]) {
    complete(results?.[field], field, lock.protocol.soak.total_aionis_trials);
  }
  expect(
    results?.negative_direct_use,
    { unsafe_direct_uses: 0, total: lock.protocol.soak.negative_transfer_trials },
    "bounded soak negative direct-use",
  );
  const waveNegativeTotal = evidence.waves.reduce((total, wave) => total + wave.negative_direct_use.total, 0);
  if (waveNegativeTotal !== results.negative_direct_use.total) fail("bounded soak negative direct-use wave totals are inconsistent");
  expect(
    [
      results?.wrong_direct_use,
      results?.terminal_backlog,
      results?.graceful_replacement_recovery,
      results?.sigkill_replacement_recovery,
      results?.offline_sqlite_verify,
      results?.semantic_retries,
      results?.worker_errors,
      evidence.critical_incidents,
    ],
    [
      0,
      { dead_letter: 0, provider_mismatch: 0, exhausted: 0 },
      true,
      true,
      true,
      0,
      0,
      [],
    ],
    "bounded soak recovery, backlog, and incident results",
  );
  if (
    !Number.isInteger(results?.context_tokens?.aionis)
    || !Number.isInteger(results?.context_tokens?.full_history)
    || results.context_tokens.aionis < 1
    || results.context_tokens.full_history < 1
    || !(results.context_tokens.aionis < results.context_tokens.full_history)
  ) fail("Aionis context is not a positive integer shorter than Full History");
  const execution = evidence.execution;
  validateWorkflowSource(evidence.pilot?.source_workflow, "pilot", authorityCommit);
  validateWorkflowSource(execution?.source_workflow, "soak", authorityCommit);
  const pilotStarted = Date.parse(evidence.pilot?.started_at);
  const pilotCompleted = Date.parse(evidence.pilot?.completed_at);
  const started = Date.parse(execution?.started_at);
  const completed = Date.parse(execution?.completed_at);
  const generated = Date.parse(evidence.generated_at);
  const durationSeconds = (completed - started) / 1000;
  expect(execution?.limits, lock.execution_limits, "bounded soak execution limits");
  expect(
    execution?.observed,
    {
      duration_seconds: durationSeconds,
      chat_calls: lock.execution_limits.soak_chat_calls,
      campaign_chat_calls: lock.execution_limits.maximum_chat_calls,
      planned_waves: lock.execution_limits.soak_waves,
      completed_waves: lock.execution_limits.soak_waves,
      cost_usd: execution?.observed?.cost_usd,
      campaign_cost_usd: execution?.observed?.campaign_cost_usd,
    },
    "bounded soak observed execution",
  );
  if (
    !Number.isFinite(durationSeconds)
    || durationSeconds < lock.execution_limits.minimum_duration_seconds
    || durationSeconds > lock.execution_limits.maximum_duration_seconds
    || !Number.isFinite(execution.observed.cost_usd)
    || execution.observed.cost_usd < 0
    || !Number.isFinite(execution.observed.campaign_cost_usd)
    || execution.observed.campaign_cost_usd < 0
    || Math.abs(evidence.pilot.cost_usd + execution.observed.cost_usd - execution.observed.campaign_cost_usd) > 1e-9
    || execution.observed.campaign_cost_usd > lock.execution_limits.maximum_cost_usd
    || execution.persistent_volume !== true
  ) fail("bounded soak execution exceeded its frozen bounds");
  const publicationTime = Date.parse(publication.github_release?.published_at);
  if (!(publicationTime < pilotStarted && pilotStarted < pilotCompleted && pilotCompleted <= started && started < completed && completed <= generated)) {
    fail("bounded soak receipt timestamps violate causal order");
  }
  assertNoSecretMaterial(evidence, "bounded soak receipt");
  return {
    protocol,
    started,
    completed,
    generated,
    pilotStarted,
    pilotCompleted,
    pilotSource: evidence.pilot.source_workflow,
    soakSource: execution.source_workflow,
  };
}

function assertDerivedArtifactEvidence(evidence, derived) {
  expect(
    {
      returned_models: evidence.providers?.agent?.returned_models,
      fallback_used: evidence.providers?.agent?.fallback_used,
    },
    derived.providers,
    "artifact-derived provider result",
  );
  const {
    started_at: pilotStarted,
    completed_at: pilotCompleted,
    source_workflow: pilotSource,
    ...reportedPilot
  } = evidence.pilot ?? {};
  void pilotStarted;
  void pilotCompleted;
  void pilotSource;
  expect(reportedPilot, derived.pilot, "artifact-derived pilot result");
  expect(evidence.waves, derived.waves, "artifact-derived wave results");
  expect(evidence.results, derived.results, "artifact-derived aggregate results");
  const {
    duration_seconds: durationSeconds,
    planned_waves: plannedWaves,
    completed_waves: completedWaves,
    ...reportedExecution
  } = evidence.execution?.observed ?? {};
  void durationSeconds;
  void plannedWaves;
  void completedWaves;
  expect(
    reportedExecution,
    {
      chat_calls: derived.execution.soak_chat_calls,
      campaign_chat_calls: derived.execution.campaign_chat_calls,
      cost_usd: derived.execution.soak_cost_usd,
      campaign_cost_usd: derived.execution.campaign_cost_usd,
    },
    "artifact-derived execution totals",
  );
  expect(evidence.pilot.semantic_chat_calls, derived.execution.pilot_chat_calls, "artifact-derived pilot calls");
}

function assertCreateDefault(createRoot, stableTrain) {
  const entry = stableTrain.packages?.create;
  if (!entry) fail("stable release train has no Create package");
  const root = fs.realpathSync(createRoot);
  expect(git(root, ["status", "--porcelain"], "Create worktree"), "", "Create worktree");
  expect(git(root, ["rev-parse", "HEAD^{commit}"], "Create HEAD"), entry.source_commit, "Create HEAD");
  expect(git(root, ["rev-parse", `${entry.source_ref}^{commit}`], "Create source ref"), entry.source_commit, "Create source ref");
  expect(canonicalGitUrl(git(root, ["remote", "get-url", "origin"], "Create origin")), canonicalGitUrl(entry.repository), "Create origin");
  const packageRoot = path.resolve(root, entry.package_path);
  const relativePackage = path.relative(root, packageRoot);
  if (relativePackage.startsWith("..") || path.isAbsolute(relativePackage)) fail("Create package path escapes checkout");
  const packageJson = readRepositoryFile(packageRoot, "package.json", "Create package.json");
  const packageValue = parseJson(packageJson.source.toString("utf8"), "Create package.json");
  expect([packageValue.name, packageValue.version], [entry.name, entry.version], "Create package identity");
  const index = readRepositoryFile(packageRoot, "src/index.ts", "Create src/index.ts").source.toString("utf8");
  const executableSource = index.replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
  const matches = [...executableSource.matchAll(/^\s*export const DEFAULT_RUNTIME_REF\s*=\s*["']([^"']+)["'];?\s*$/gmu)];
  if (matches.length !== 1) fail("Create checkout must export exactly one executable DEFAULT_RUNTIME_REF");
  expect(matches[0][1], stableTrain.runtime.source_tag, "Create default Runtime ref");
}

export async function verifyStablePromotion({
  runtimeRoot,
  createRoot,
  expectedRuntimeCommit,
  authorityRoot,
  authorityCommit = null,
  releaseLockPath,
  workflowRunFetcher,
  artifactProvenanceFetcher,
  artifactFetcher = defaultArtifactFetcher,
}) {
  if (process.versions.node.split(".")[0] !== "24") fail("Node.js 24 is required");
  if (typeof workflowRunFetcher !== "function") fail("a trusted workflow run evidence fetcher is required");
  if (typeof artifactProvenanceFetcher !== "function") fail("trusted artifact provenance is required");
  const resolvedRuntimeRoot = fs.realpathSync(runtimeRoot);
  const resolvedAuthorityRoot = fs.realpathSync(authorityRoot);
  const stableCommit = requiredString(expectedRuntimeCommit, "expected Runtime commit");
  if (!COMMIT_RE.test(stableCommit)) fail("expected Runtime commit must be immutable");
  expect(git(resolvedRuntimeRoot, ["rev-parse", "HEAD^{commit}"], "stable Runtime HEAD"), stableCommit, "stable Runtime HEAD");
  expect(git(resolvedRuntimeRoot, ["status", "--porcelain"], "stable Runtime worktree"), "", "stable Runtime worktree");
  expect(git(resolvedRuntimeRoot, ["rev-parse", "--is-shallow-repository"], "Runtime shallow check"), "false", "Runtime shallow check");
  const mainCommit = git(resolvedRuntimeRoot, ["rev-parse", "refs/remotes/origin/main^{commit}"], "origin/main");
  if (!git(resolvedRuntimeRoot, ["rev-list", "--first-parent", mainCommit], "origin/main first-parent history").split("\n").includes(stableCommit)) {
    fail("stable Runtime commit is not on origin/main first-parent history");
  }
  const resolvedAuthorityCommit = authorityCommit ?? git(resolvedAuthorityRoot, ["rev-parse", "HEAD^{commit}"], "authority HEAD");
  if (!COMMIT_RE.test(resolvedAuthorityCommit)) fail("authority commit must be immutable");

  const lock = readJsonFile(releaseLockPath, "release lock").value;
  validateReleaseLock(lock);
  expect(
    canonicalGitUrl(git(resolvedRuntimeRoot, ["remote", "get-url", "origin"], "Runtime origin")),
    canonicalGitUrl(lock.candidate.repository),
    "Runtime origin",
  );
  const packageJson = readRootJson(resolvedRuntimeRoot, "package.json", "stable package.json").value;
  const packageLock = readRootJson(resolvedRuntimeRoot, "package-lock.json", "stable package-lock.json").value;
  const runtimeManifest = readRootJson(resolvedRuntimeRoot, "runtime-manifest.json", "stable runtime-manifest.json").value;
  const stableTrain = readRootJson(resolvedRuntimeRoot, "release-train.json", "stable release-train.json").value;
  if (stableTrain.schema_version !== "aionis_release_train_v2" || stableTrain.status !== "stable") fail("release train is not stable v2");
  const stableVersion = requiredString(stableTrain.runtime?.version, "stable Runtime version");
  const stableTag = requiredString(stableTrain.runtime?.source_tag, "stable Runtime tag");
  if (stableTag !== `v${stableVersion}` || compareVersions(stableVersion, lock.candidate.version) <= 0) fail("stable Runtime must be newer than the candidate");
  expect(git(resolvedRuntimeRoot, ["cat-file", "-t", `refs/tags/${stableTag}`], "stable tag type"), "tag", "stable tag type");
  expect(git(resolvedRuntimeRoot, ["rev-parse", `refs/tags/${stableTag}^{commit}`], "stable tag commit"), stableCommit, "stable tag commit");
  expect([packageJson.version, runtimeManifest.release?.version, runtimeManifest.release?.status], [stableVersion, stableVersion, "stable"], "stable Runtime metadata");
  expect(
    [runtimeManifest.release?.source_tag, runtimeManifest.release?.docker_tag, runtimeManifest.release?.default_installer_ref],
    [stableTag, stableTag, stableTag],
    "stable Runtime release coordinates",
  );

  const promotion = stableTrain.stable_promotion;
  if (promotion?.schema_version !== "aionis_stable_promotion_authority_v1") fail("stable promotion authority schema is invalid");
  expect(
    promotion.verifier,
    {
      repository: EVALUATION_GIT_REPOSITORY,
      source_ref: resolvedAuthorityCommit,
      source_commit: resolvedAuthorityCommit,
      verifier_path: VERIFIER_PATH,
    },
    "stable promotion verifier coordinates",
  );
  expect(promotion.candidate_publication, lock.candidate_publication_receipt, "stable candidate publication binding");

  const publication = readBoundJson(resolvedRuntimeRoot, promotion.candidate_publication, "candidate publication receipt");
  const soak = readBoundJson(resolvedRuntimeRoot, promotion.bounded_soak, "bounded soak receipt");
  const allowedReleaseFiles = new Set([
    publication.path,
    soak.path,
    soak.value.protocol?.authority_manifest?.path,
    soak.value.protocol?.workload_manifest?.path,
    soak.value.protocol?.artifact_bundle_manifest?.path,
    `docs/releases/${lock.candidate.tag}.md`,
    `docs/releases/${stableTag}.md`,
  ]);
  const previousLatest = validateCandidatePublication(publication.value, lock);
  assertCandidateAnnotatedTag(resolvedRuntimeRoot, publication.value);
  assertFirstParent(resolvedRuntimeRoot, lock.candidate.commit, stableCommit);
  assertPostCandidateAllowlist(resolvedRuntimeRoot, lock.candidate.commit, stableCommit, allowedReleaseFiles);
  assertGovernanceArtifacts(resolvedRuntimeRoot, lock);
  assertComplexityRatchet(resolvedRuntimeRoot, lock.candidate.commit);
  assertSemanticNoDrift(resolvedRuntimeRoot, lock.candidate.commit, { packageJson, packageLock, runtimeManifest });
  assertReleaseTrainTransition(resolvedRuntimeRoot, lock.candidate.commit, stableTrain);
  assertCreateDefault(createRoot, stableTrain);

  const soakValidation = validateSoakEvidence({
    evidence: soak.value,
    lock,
    publication: publication.value,
    publicationBinding: publication,
    authorityCommit: resolvedAuthorityCommit,
    runtimeRoot: resolvedRuntimeRoot,
  });
  const authorityDocument = readBoundJson(resolvedRuntimeRoot, soakValidation.protocol.authority_manifest, "soak authority manifest");
  const workloadDocument = readBoundJson(resolvedRuntimeRoot, soakValidation.protocol.workload_manifest, "soak workload manifest");
  const artifactDocument = readBoundJson(resolvedRuntimeRoot, soakValidation.protocol.artifact_bundle_manifest, "soak artifact bundle manifest");
  expect(authorityDocument.sha256, lock.protocol_artifacts.authority_manifest.sha256, "frozen authority manifest hash");
  expect(workloadDocument.sha256, lock.protocol_artifacts.workload_manifest.sha256, "frozen workload manifest hash");
  validateAuthorityManifest(authorityDocument.value, lock);
  validateWorkloadManifest(workloadDocument.value, lock);
  validateArtifactBundleManifest(artifactDocument.value, lock, resolvedAuthorityCommit);
  expect(soakValidation.soakSource, artifactDocument.value.source_workflow, "soak receipt/artifact workflow binding");
  const artifactAuthority = await verifyExternalArtifactAuthority(
    artifactDocument.value,
    { workflowRunFetcher, artifactProvenanceFetcher, artifactFetcher },
  );
  const soakWindow = artifactAuthority.producerWindow;
  const pilotWindow = await verifyWorkflowRun(
    soakValidation.pilotSource,
    "pilot",
    resolvedAuthorityCommit,
    workflowRunFetcher,
  );
  if (
    !(pilotWindow.jobStarted <= soakValidation.pilotStarted
      && soakValidation.pilotStarted < soakValidation.pilotCompleted
      && soakValidation.pilotCompleted <= pilotWindow.jobCompleted)
  ) fail("pilot execution was not contained inside the protected pilot job");
  if (
    !(soakWindow.jobStarted <= soakValidation.started
      && soakValidation.started < soakValidation.completed
      && soakValidation.completed <= soakWindow.jobCompleted)
  ) fail("soak execution was not contained inside the protected soak job");
  const derivedEvidence = reduceArtifactEvidence({
    payloads: artifactAuthority.payloads,
    manifest: artifactDocument.value,
    lock,
    workload: workloadDocument.value,
    pilotSource: soakValidation.pilotSource,
    soakSource: soakValidation.soakSource,
  });
  assertDerivedArtifactEvidence(soak.value, derivedEvidence);
  const publicationTime = Date.parse(publication.value.github_release.published_at);
  const authorityTime = Date.parse(authorityDocument.value.authorized_at);
  const workloadTime = Date.parse(workloadDocument.value.frozen_at);
  const artifactTime = Date.parse(artifactDocument.value.generated_at);
  if (!(publicationTime < authorityTime && authorityTime <= workloadTime && workloadTime < soakValidation.started)) {
    fail("authority/workload timestamps violate causal order");
  }
  if (!(soakValidation.completed <= artifactTime && artifactTime <= soakValidation.generated)) {
    fail("artifact manifest timestamps violate causal order");
  }

  return {
    schema_version: "aionis_stable_promotion_verification_v1",
    ok: true,
    status: "stable",
    stable_commit: stableCommit,
    authority_commit: resolvedAuthorityCommit,
    candidate_tag: lock.candidate.tag,
    candidate_commit: lock.candidate.commit,
    candidate_digest: lock.candidate.digest,
    expected_previous_latest: previousLatest,
  };
}
