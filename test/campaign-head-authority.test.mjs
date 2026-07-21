import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  appendCampaignHead,
  auditCampaignHeadJournal,
  campaignHeadAuthorityInfo,
  claimCampaignRun,
  markCampaignHeadProjected,
  openCampaignHeadAuthority,
  provisionCampaignHeadAuthority,
  readCampaignHead,
  registerCampaignHead,
  withCampaignHeadAuthority,
} from "../src/campaign-head-authority.mjs";

const CAMPAIGN_ID = `campaign-${"a".repeat(40)}`;
const PILOT_SOURCE = Object.freeze({
  repository: "ostinatocc/AionisRuntime-evals",
  run_id: 9001,
  run_attempt: 1,
  head_sha: "b".repeat(40),
  phase: "pilot",
  job: "bounded-soak-pilot",
  environment: "bounded-soak",
});

function temporaryDirectory(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aionis-${label}-`));
}

function initialPayload() {
  return {
    campaign_id: CAMPAIGN_ID,
    revision: 0,
    events: [],
    frozen: { candidate: "sha256:fixture" },
  };
}

function setupAuthority() {
  const authorityDirectory = temporaryDirectory("head-authority");
  const campaignDirectory = temporaryDirectory("head-campaign");
  const authority = provisionCampaignHeadAuthority({ directory: authorityDirectory });
  let campaign;
  withCampaignHeadAuthority(authority, { campaignRoot: campaignDirectory }, (session) => {
    const registered = registerCampaignHead(session, {
      campaignId: CAMPAIGN_ID,
      runScope: PILOT_SOURCE,
      initialPayload: initialPayload(),
    });
    assert.equal(registered.created, true);
    campaign = markCampaignHeadProjected(session, { head: registered.head });
  });
  return { authority, authorityDirectory, campaignDirectory, campaign };
}

function appendOne(authority, campaignDirectory, label = "accepted", runScope = PILOT_SOURCE) {
  let result;
  withCampaignHeadAuthority(authority, { campaignRoot: campaignDirectory }, (session) => {
    const current = readCampaignHead(session);
    const actor = claimCampaignRun(session, {
      campaignId: CAMPAIGN_ID,
      runScope,
    });
    const event = { revision: current.payload.revision + 1, type: "advance", label };
    const payload = structuredClone(current.payload);
    payload.revision += 1;
    payload.events.push(event);
    const appended = appendCampaignHead(session, {
      expectedHead: current.head,
      actorRunScopeId: actor.run_scope_id,
      event,
      nextPayload: payload,
    });
    result = markCampaignHeadProjected(session, { head: appended.head });
  });
  return result;
}

function headFiles(authorityDirectory, campaign) {
  const directory = path.join(
    authorityDirectory,
    "journal",
    "heads",
    CAMPAIGN_ID,
    campaign.head.generation,
  );
  return fs.readdirSync(directory).sort().map((name) => path.join(directory, name));
}

test("authority provisioning is explicit, private, and permanently blocked for admission", () => {
  const absent = path.join(temporaryDirectory("head-absent-parent"), "absent");
  assert.throws(
    () => openCampaignHeadAuthority({ directory: absent }),
    /must be a real non-symlink directory/,
  );

  const { authority, authorityDirectory, campaignDirectory, campaign } = setupAuthority();
  const info = campaignHeadAuthorityInfo(authority);
  assert.equal(info.admission_mode, "blocked_groundwork");
  assert.equal(info.directory, fs.realpathSync(authorityDirectory));
  assert.equal(fs.statSync(authorityDirectory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(authorityDirectory, "campaign-authority.sqlite")).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(authorityDirectory, ".campaign-authority.lock")).mode & 0o777, 0o600);
  for (const target of headFiles(authorityDirectory, campaign)) {
    assert.equal(fs.statSync(target).mode & 0o777, 0o400);
  }
  assert.throws(
    () => withCampaignHeadAuthority(authority, { campaignRoot: authorityDirectory }, () => {}),
    /must be disjoint/,
  );
  assert.throws(
    () => withCampaignHeadAuthority(authority, { campaignRoot: campaignDirectory }, async () => {}),
    /must be synchronous/,
  );
  assert.throws(
    () => withCampaignHeadAuthority(authority, { campaignRoot: campaignDirectory }, () => ({ then() {} })),
    /must not return a promise or thenable/,
  );
  assert.equal(readHead(authority, campaignDirectory).head.revision, 0);
});

function readHead(authority, campaignDirectory) {
  let current;
  withCampaignHeadAuthority(authority, { campaignRoot: campaignDirectory }, (session) => {
    current = readCampaignHead(session);
  });
  return current;
}

test("immutable journal repairs a rolled-back SQLite index without resetting generation", () => {
  const setup = setupAuthority();
  const database = path.join(setup.authorityDirectory, "campaign-authority.sqlite");
  const backup = path.join(temporaryDirectory("head-db-backup"), "revision-zero.sqlite");
  fs.copyFileSync(database, backup);
  fs.chmodSync(backup, 0o600);

  const revisionOne = appendOne(setup.authority, setup.campaignDirectory);
  assert.equal(revisionOne.head.revision, 1);
  fs.copyFileSync(backup, database);
  fs.chmodSync(database, 0o600);

  const reopened = openCampaignHeadAuthority({ directory: setup.authorityDirectory });
  const recovered = readHead(reopened, setup.campaignDirectory);
  assert.equal(recovered.head.revision, 1);
  assert.equal(recovered.head.generation, revisionOne.head.generation);
  assert.equal(recovered.head.head_sha256, revisionOne.head.head_sha256);
  assert.notEqual(recovered.projected_at, null);

  withCampaignHeadAuthority(reopened, { campaignRoot: setup.campaignDirectory }, (session) => {
    const current = readCampaignHead(session);
    const projected = markCampaignHeadProjected(session, { head: current.head });
    assert.notEqual(projected.projected_at, null);
  });
  assert.equal(readHead(reopened, setup.campaignDirectory).head.head_sha256, revisionOne.head.head_sha256);
});

test("projection acknowledgements recover an arbitrary SQLite suffix including a new actor run", () => {
  const setup = setupAuthority();
  const database = path.join(setup.authorityDirectory, "campaign-authority.sqlite");
  const backup = path.join(temporaryDirectory("head-db-deep-backup"), "revision-zero.sqlite");
  fs.copyFileSync(database, backup);
  fs.chmodSync(backup, 0o600);
  const soakSource = {
    ...PILOT_SOURCE,
    run_id: 9002,
    phase: "soak",
    job: "bounded-soak-soak",
  };
  const revisionOne = appendOne(setup.authority, setup.campaignDirectory, "soak-actor", soakSource);
  const revisionTwo = appendOne(setup.authority, setup.campaignDirectory, "second");
  const revisionThree = appendOne(setup.authority, setup.campaignDirectory, "third");
  assert.deepEqual(
    [revisionOne.head.revision, revisionTwo.head.revision, revisionThree.head.revision],
    [1, 2, 3],
  );

  fs.copyFileSync(backup, database);
  fs.chmodSync(database, 0o600);
  const reopened = openCampaignHeadAuthority({ directory: setup.authorityDirectory });
  const recovered = readHead(reopened, setup.campaignDirectory);
  assert.equal(recovered.head.revision, 3);
  assert.equal(recovered.head.head_sha256, revisionThree.head.head_sha256);
  assert.notEqual(recovered.projected_at, null);

  const indexed = new DatabaseSync(database, { readOnly: true });
  try {
    assert.equal(indexed.prepare("SELECT count(*) AS count FROM aionis_campaign_head_index").get().count, 4);
    assert.equal(indexed.prepare("SELECT count(*) AS count FROM aionis_campaign_run_claims").get().count, 2);
  } finally {
    indexed.close();
  }
});

test("a durable projection acknowledgement repairs SQLite after its update was locked", () => {
  const setup = setupAuthority();
  let unprojected;
  withCampaignHeadAuthority(setup.authority, { campaignRoot: setup.campaignDirectory }, (session) => {
    const current = readCampaignHead(session);
    const actor = claimCampaignRun(session, { campaignId: CAMPAIGN_ID, runScope: PILOT_SOURCE });
    const event = { revision: 1, type: "advance", label: "ack-before-index" };
    const payload = structuredClone(current.payload);
    payload.revision = 1;
    payload.events.push(event);
    unprojected = appendCampaignHead(session, {
      expectedHead: current.head,
      actorRunScopeId: actor.run_scope_id,
      event,
      nextPayload: payload,
    });
  });

  const databasePath = path.join(setup.authorityDirectory, "campaign-authority.sqlite");
  withCampaignHeadAuthority(setup.authority, { campaignRoot: setup.campaignDirectory }, (session) => {
    const current = readCampaignHead(session);
    assert.equal(current.head.revision, 1);
    assert.equal(current.projected_at, null);
    const blocker = new DatabaseSync(databasePath);
    blocker.exec("BEGIN IMMEDIATE");
    try {
      assert.throws(
        () => markCampaignHeadProjected(session, { head: current.head }),
        /database is locked/,
      );
    } finally {
      blocker.exec("ROLLBACK");
      blocker.close();
    }
  });

  const reopened = openCampaignHeadAuthority({ directory: setup.authorityDirectory });
  let recovered;
  withCampaignHeadAuthority(reopened, { campaignRoot: setup.campaignDirectory }, (session) => {
    recovered = readCampaignHead(session, {
      projection: { head: unprojected.head, payload: unprojected.payload },
    });
  });
  assert.equal(recovered.head.head_sha256, unprojected.head.head_sha256);
  assert.notEqual(recovered.projected_at, null);
  const indexed = new DatabaseSync(databasePath, { readOnly: true });
  try {
    assert.notEqual(indexed.prepare(`SELECT projected_at FROM aionis_campaign_head_index
      WHERE revision = 1`).get().projected_at, null);
  } finally {
    indexed.close();
  }
});

test("SQLite ahead of journal and writable or changed journal records fail closed", () => {
  const ahead = setupAuthority();
  const revisionOne = appendOne(ahead.authority, ahead.campaignDirectory);
  const files = headFiles(ahead.authorityDirectory, revisionOne);
  assert.equal(files.length, 2);
  fs.unlinkSync(files[1]);
  const reopenedAhead = openCampaignHeadAuthority({ directory: ahead.authorityDirectory });
  assert.throws(
    () => readHead(reopenedAhead, ahead.campaignDirectory),
    /SQLite head index is ahead|projection acknowledgements are ahead/,
  );

  const writable = setupAuthority();
  const [initialHead] = headFiles(writable.authorityDirectory, writable.campaign);
  fs.chmodSync(initialHead, 0o600);
  assert.throws(
    () => readHead(writable.authority, writable.campaignDirectory),
    /permissions must be exactly 400/,
  );

  const changed = setupAuthority();
  const [changedHead] = headFiles(changed.authorityDirectory, changed.campaign);
  fs.chmodSync(changedHead, 0o600);
  const record = JSON.parse(fs.readFileSync(changedHead, "utf8"));
  record.mutation.payload.frozen.candidate = "sha256:tampered";
  fs.writeFileSync(changedHead, `${JSON.stringify(record, null, 2)}\n`);
  fs.chmodSync(changedHead, 0o400);
  assert.throws(
    () => readHead(changed.authority, changed.campaignDirectory),
    /payload SHA-256 mismatch|head SHA-256 mismatch/,
  );
});

test("open handles reject authority database inode replacement", () => {
  const setup = setupAuthority();
  const database = path.join(setup.authorityDirectory, "campaign-authority.sqlite");
  const replacement = path.join(setup.authorityDirectory, ".replacement.sqlite");
  fs.copyFileSync(database, replacement);
  fs.chmodSync(replacement, 0o600);
  fs.renameSync(replacement, database);
  assert.throws(
    () => readHead(setup.authority, setup.campaignDirectory),
    /authority database identity changed/,
  );

  const reopened = openCampaignHeadAuthority({ directory: setup.authorityDirectory });
  assert.equal(readHead(reopened, setup.campaignDirectory).head.revision, 0);
});

test("open handles reject fixed journal-directory inode replacement", () => {
  const setup = setupAuthority();
  const heads = path.join(setup.authorityDirectory, "journal", "heads");
  const original = path.join(setup.authorityDirectory, "journal", ".heads-original");
  fs.renameSync(heads, original);
  fs.mkdirSync(heads, { mode: 0o700 });
  try {
    assert.throws(
      () => readHead(setup.authority, setup.campaignDirectory),
      /authority heads identity changed/,
    );
  } finally {
    fs.rmdirSync(heads);
    fs.renameSync(original, heads);
  }
  assert.equal(readHead(setup.authority, setup.campaignDirectory).head.revision, 0);
});

test("authority rejects a same-name weakened SQLite index definition", () => {
  const setup = setupAuthority();
  const databasePath = path.join(setup.authorityDirectory, "campaign-authority.sqlite");
  const database = new DatabaseSync(databasePath);
  try {
    database.exec(`DROP INDEX aionis_campaign_instances_run_scope_uq;
      CREATE INDEX aionis_campaign_instances_run_scope_uq
      ON aionis_campaign_instances(run_scope_id)`);
  } finally {
    database.close();
  }
  assert.throws(
    () => openCampaignHeadAuthority({ directory: setup.authorityDirectory }),
    /SQLite schema definition is invalid/,
  );
});

test("stale private staging files are removed only under the authority lock", () => {
  const setup = setupAuthority();
  const pending = path.join(
    setup.authorityDirectory,
    "journal",
    "run-claims",
    `.aionis-json-${process.pid}-${"c".repeat(32)}.pending`,
  );
  fs.writeFileSync(pending, "incomplete", { mode: 0o600 });
  assert.equal(fs.existsSync(pending), true);
  assert.equal(readHead(setup.authority, setup.campaignDirectory).head.revision, 0);
  assert.equal(fs.existsSync(pending), false);
});

test("full audit rejects orphan campaign and generation namespaces", () => {
  const setup = setupAuthority();
  const orphan = path.join(
    setup.authorityDirectory,
    "journal",
    "heads",
    `campaign-${"d".repeat(40)}`,
  );
  fs.mkdirSync(orphan, { mode: 0o700 });
  assert.throws(
    () => withCampaignHeadAuthority(
      setup.authority,
      { campaignRoot: setup.campaignDirectory },
      (session) => auditCampaignHeadJournal(session),
    ),
    /not a bijection with immutable campaign claims/,
  );
  fs.rmdirSync(orphan);
  withCampaignHeadAuthority(
    setup.authority,
    { campaignRoot: setup.campaignDirectory },
    (session) => assert.equal(auditCampaignHeadJournal(session).head.revision, 0),
  );
});

test("run singleton binds the full first attempt while hashing the run series", () => {
  const setup = setupAuthority();
  withCampaignHeadAuthority(setup.authority, { campaignRoot: setup.campaignDirectory }, (session) => {
    const first = claimCampaignRun(session, { campaignId: CAMPAIGN_ID, runScope: PILOT_SOURCE });
    const same = claimCampaignRun(session, { campaignId: CAMPAIGN_ID, runScope: PILOT_SOURCE });
    assert.deepEqual(same, first);
    assert.throws(
      () => claimCampaignRun(session, {
        campaignId: CAMPAIGN_ID,
        runScope: { ...PILOT_SOURCE, run_attempt: 2 },
      }),
      /run series is already bound to another attempt/,
    );
    assert.throws(
      () => claimCampaignRun(session, {
        campaignId: CAMPAIGN_ID,
        runScope: { ...PILOT_SOURCE, phase: "soak", job: "bounded-soak-soak" },
      }),
      /run series is already bound to another attempt/,
    );
  });
});
