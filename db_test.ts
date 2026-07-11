/**
 * Tests for @vcjdeboer/session-ingest db.ts.
 * Skip-guarded when sqlite3 is absent or < 3.33 (hermetic on a fresh machine).
 * Builds its own fixture DBs via sqlite3 — never touches real Claude Science data.
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  assertQuiescent,
  buildManifest,
  classifyTurn,
  cloneDb,
  preflightSqlite,
  PROJ_ID_RE,
  QUERIES,
  readViaClone,
  resolveProject,
  SECRET_TOKENS,
} from "./db.ts";

const pre = await preflightSqlite();
const HAVE_SQLITE = pre.ok;

async function sqlite(db: string, sql: string): Promise<void> {
  const out = await new Deno.Command("sqlite3", { args: [db, sql] }).output();
  if (!out.success) throw new Error(new TextDecoder().decode(out.stderr));
}

/**
 * A fixture org dir with operon-cli.db. opts.drift drops artifact_versions.
 * opts.multiSession adds a SECOND parentless OPERON session (its own headline +
 * reviewer child + one verification check) so multi-session behaviour is testable.
 */
async function fixture(
  opts: { drift?: boolean; empty?: boolean; multiSession?: boolean } = {},
): Promise<string> {
  const orgDir = await Deno.makeTempDir({ prefix: "ing-fixture-" });
  await Deno.mkdir(`${orgDir}/orgs/org1`, { recursive: true });
  await Deno.mkdir(`${orgDir}/orgs/org1/artifacts/proj_abc123/a`, {
    recursive: true,
  });
  // one artifact file present, one will be "missing"
  await Deno.writeTextFile(
    `${orgDir}/orgs/org1/artifacts/proj_abc123/a/v1.csv`,
    "x",
  );
  const db = `${orgDir}/orgs/org1/operon-cli.db`;
  // WAL mode so the fixture leaves a real .db + -wal + -shm triplet — this is
  // the scenario invariant A must defend (checkpoint-on-close mutation).
  let sql = `
    PRAGMA journal_mode=WAL;
    CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
    INSERT INTO projects VALUES ('proj_abc123','gdh','multi
line
desc',1,2,'f1');
    CREATE TABLE frames (id TEXT,parent_frame_id TEXT,root_frame_id TEXT,agent_name TEXT,delegate_name TEXT,conversation_type TEXT,model TEXT,effort TEXT,status TEXT,compute_enabled TEXT,project_id TEXT,name TEXT,created_at INT);
    INSERT INTO frames VALUES ('${ROOT}',NULL,'${ROOT}','OPERON',NULL,'agent','opus','high','completed',NULL,'proj_abc123','Analyze gdh',100);
    CREATE TABLE user_secrets (id TEXT,provider TEXT,encrypted_value TEXT);
    INSERT INTO user_secrets VALUES ('s1','openalex','SUPERSECRETCIPHERTEXT');
    CREATE TABLE verification_checks (id TEXT,root_frame_id TEXT,verdict TEXT);
    CREATE TABLE frame_messages (frame_id TEXT,idx INT,msg_json TEXT);
    INSERT INTO frame_messages VALUES
      ('${ROOT}',0,'{"role":"user","_intent_id":"i1","content":"tell me how gdh"}'),
      ('${ROOT}',1,'{"role":"assistant","content":"analysis text"}'),
      ('${ROOT}',2,'{"role":"user","_harness_notice":"sys","content":"[System] plan approved"}'),
      ('${ROOT}',3,'{"role":"user","content":[{"type":"tool_result","content":"output"}]}'),
      ('${ROOT}',4,'{"role":"system","content":"boot"}');
  `;
  if (!opts.empty) {
    sql += `
      INSERT INTO frames VALUES ('${REV}','${ROOT}','${ROOT}','REVIEWER','reviewer','agent','sonnet',NULL,'completed',1,'proj_abc123',NULL,101);
      INSERT INTO verification_checks VALUES ('c1','${ROOT}','pass'),('c2','${ROOT}','pass'),('c3','${ROOT}','warn');
      INSERT INTO frame_messages VALUES
        ('${REV}',0,'{"role":"user","_harness_prompt":"rev","content":"You are reviewing"}'),
        ('${REV}',1,'{"role":"assistant","content":"findings"}');
    `;
  }
  if (opts.multiSession) {
    // a SECOND parentless OPERON session: own headline, own reviewer child, 1 check.
    // ROOT2 carries root_frame_id='' (empty string, allowed by FrameRow) — regression
    // guard: sessionIdOf must fall back to the frame's own id (|| not ??) so the root
    // counts ITSELF in its session's nFrames. With ?? this session would report 1 frame.
    sql += `
      INSERT INTO frames VALUES ('${ROOT2}',NULL,'','OPERON',NULL,'agent','opus','high','completed',NULL,'proj_abc123','Diving physiology lit review',200);
      INSERT INTO frames VALUES ('${REV2}','${ROOT2}','${ROOT2}','REVIEWER','reviewer','agent','sonnet',NULL,'completed',NULL,'proj_abc123',NULL,201);
      INSERT INTO verification_checks VALUES ('c4','${ROOT2}','pass');
    `;
  }
  if (!opts.drift && !opts.empty) {
    sql += `
      CREATE TABLE artifact_versions (storage_path TEXT,checksum TEXT,language TEXT,env_snapshot_hash TEXT,artifact_id TEXT,is_intermediate INT);
      INSERT INTO artifact_versions VALUES
        ('proj_abc123/a/v1.csv','sha1','python','envA','art1',0),
        ('proj_abc123/a/v2.png','sha2','python','envA','art2',0),
        ('proj_abc123/a/v3.R','sha3','r','envB','art3',0),
        ('proj_abc123/a/v4.tmp','sha4','python','envA','art4',1);
    `;
  } else if (opts.empty) {
    sql +=
      `CREATE TABLE artifact_versions (storage_path TEXT,checksum TEXT,language TEXT,env_snapshot_hash TEXT,artifact_id TEXT,is_intermediate INT);`;
  }
  await sqlite(db, sql);
  return orgDir;
}
/** Fixed UUIDs so verification_checks.root_frame_id passes FRAME_ID_RE. */
const ROOT = "6b2bd51d-1111-4111-8111-111111111111";
const REV = "aaaaaaaa-2222-4222-8222-222222222222";
/** A second session's root + reviewer (opts.multiSession). */
const ROOT2 = "cccccccc-3333-4333-8333-333333333333";
const REV2 = "dddddddd-4444-4444-8444-444444444444";

async function md5(path: string): Promise<string> {
  const buf = await Deno.readFile(path);
  const h = await crypto.subtle.digest("MD5" as unknown as string, buf).catch(
    async () => {
      // MD5 may be unavailable; fall back to SHA-256 for a stable fingerprint
      return await crypto.subtle.digest("SHA-256", buf);
    },
  );
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

Deno.test("preflight detects sqlite3 (or reports why not)", () => {
  assert(pre.ok || typeof pre.error === "string");
});

Deno.test({
  name: "registry allowlist: no SELECT * and no secret token in any query",
  fn: () => {
    for (const [name, build] of Object.entries(QUERIES)) {
      const sql = (build as (p?: string) => string)("proj_deadbeef");
      assert(!/select\s+\*/i.test(sql), `${name} must not use SELECT *`);
      for (const tok of SECRET_TOKENS) {
        assert(
          !sql.toLowerCase().includes(tok),
          `${name} must not name secret token ${tok}`,
        );
      }
    }
  },
});

async function sqliteJson(
  db: string,
  sql: string,
): Promise<Record<string, unknown>[]> {
  const out = await new Deno.Command("sqlite3", {
    args: ["-json", db, sql],
    stdout: "piped",
    stderr: "piped",
  }).output();
  const t = new TextDecoder().decode(out.stdout).trim();
  return t ? JSON.parse(t) : [];
}

Deno.test({
  name:
    "host_calls_by_project: json_valid guard (no abort on malformed) + server derivation + scoping",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await Deno.makeTempDir({ prefix: "hcl-" });
    const db = `${org}/operon-cli.db`;
    await new Deno.Command("sqlite3", {
      args: [
        db,
        `CREATE TABLE frames (id TEXT,project_id TEXT);
         INSERT INTO frames VALUES ('R1','proj_abc123'),('RO','proj_other');
         CREATE TABLE execution_log (id TEXT,frame_id TEXT);
         INSERT INTO execution_log VALUES ('E1','R1'),('E2','RO');
         CREATE TABLE host_call_log (id INTEGER PRIMARY KEY AUTOINCREMENT,execution_log_id TEXT NOT NULL,seq INT,method TEXT,args_json TEXT,error TEXT,bytes INT,created_at INT);
         INSERT INTO host_call_log (execution_log_id,seq,method,args_json,error,bytes,created_at) VALUES
           ('E1',1,'mcp','["pubmed","q"]',NULL,5,10),
           ('E1',2,'mcp','{malformed',NULL,5,20),
           ('E1',3,'get_user_email','["x"]','boom',0,30),
           ('E2',1,'mcp','["otherproj","q"]',NULL,9,40);`,
      ],
    }).output();
    try {
      // Must NOT abort despite the malformed row (json_valid guard).
      const rows = await sqliteJson(
        db,
        QUERIES.host_calls_by_project("proj_abc123"),
      );
      assertEquals(rows.length, 3, "only this project's 3 calls (E2 excluded)");
      const byMethod = rows.map((r) =>
        `${r.method}|${r.mcp_server ?? "null"}|${r.is_error}`
      );
      assert(
        byMethod.includes("mcp|pubmed|0"),
        "valid mcp → server derived in SQL",
      );
      assert(
        byMethod.includes("mcp|null|0"),
        "malformed mcp → NULL server (no abort)",
      );
      assert(
        byMethod.includes("get_user_email|null|1"),
        "non-mcp → no server; error → is_error=1",
      );
      assert(
        !JSON.stringify(rows).includes("otherproj"),
        "other project's call scoped out",
      );
      // never selects raw args_json content
      assert(
        !JSON.stringify(rows).includes('"q"') &&
          !Object.keys(rows[0]).includes("args_json"),
        "args_json never selected",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "classifyTurn agrees with the messages_typed SQL CASE (no-drift floor)",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      const sqlTally: Record<string, number> = {};
      for (
        const r of await sqliteJson(db, QUERIES.messages_typed("proj_abc123"))
      ) {
        sqlTally[String(r.kind)] = Number(r.n);
      }
      const tsTally: Record<string, number> = {};
      const rows = await sqliteJson(
        db,
        "SELECT msg_json FROM frame_messages WHERE frame_id IN (SELECT id FROM frames WHERE project_id='proj_abc123') AND json_valid(msg_json)",
      );
      for (const r of rows) {
        const k = classifyTurn(JSON.parse(String(r.msg_json)));
        tsTally[k] = (tsTally[k] ?? 0) + 1;
      }
      assertEquals(
        tsTally,
        sqlTally,
        "classifyTurn diverged from the SQL CASE",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "cloneDb clones a static copy and cleans up; source untouched",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      const before = await md5(db);
      const { path, cleanup } = await cloneDb(db);
      assert(await Deno.stat(path).catch(() => null), "clone should exist");
      const rows = await sqliteJson(path, "SELECT count(*) n FROM projects");
      assertEquals(Number(rows[0].n), 1);
      await cleanup();
      assert(
        !(await Deno.stat(path).catch(() => null)),
        "clone dir should be removed",
      );
      assertEquals(
        await md5(db),
        before,
        "source must be untouched by cloneDb",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "sec-1: cloneDb scrubs secret tables from the on-disk clone (no ciphertext, no secret table)",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      const { path, cleanup } = await cloneDb(db);
      try {
        // the secret tables are gone from the clone
        const tables = (await sqliteJson(
          path,
          "SELECT name FROM sqlite_master WHERE type='table'",
        )).map((r) => String(r.name));
        assert(
          !tables.includes("user_secrets"),
          "user_secrets dropped from clone",
        );
        // and no ciphertext byte survives in the clone file itself (VACUUM reclaimed it)
        const bytes = await Deno.readFile(path);
        const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
        assert(
          !text.includes("SUPERSECRETCIPHERTEXT"),
          "ciphertext scrubbed from clone bytes",
        );
        // non-secret content still readable
        assertEquals(
          Number(
            (await sqliteJson(path, "SELECT count(*) n FROM projects"))[0].n,
          ),
          1,
        );
      } finally {
        await cleanup();
      }
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test("proj_id regex is the injection gate", () => {
  assert(PROJ_ID_RE.test("proj_f9092b4ea127"));
  assert(PROJ_ID_RE.test("proj_0fbe3bb9e459"));
  assert(!PROJ_ID_RE.test("proj_abc'; DROP TABLE x;--"));
  assert(!PROJ_ID_RE.test("../../etc"));
});

Deno.test({
  name: "buildManifest: correct counts on a normal fixture",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture();
    try {
      const m = await buildManifest(org, "gdh");
      assertEquals(m.origin.project.id, "proj_abc123");
      assertEquals(m.origin.project.name, "gdh");
      assertEquals(m.artifacts.versions, 4);
      assertEquals(m.artifacts.distinct, 4);
      assertEquals(m.artifacts.saved, 3); // is_intermediate=0
      assertEquals(m.artifacts.intermediate, 1); // is_intermediate=1 (CS hides these)
      assertEquals(m.artifacts.byLanguage, { python: 3, r: 1 });
      assertEquals(m.nDistinctEnvs, 2);
      assertEquals(m.nFrames, 2);
      assertEquals(m.framesByRole, { OPERON: 1, REVIEWER: 1 }); // generic role breakdown
      assertEquals(m.verificationChecks.total, 3);
      assertEquals(m.verificationChecks.byVerdict, { pass: 2, warn: 1 });
      // single-session project: exactly one session, headline + per-session breakdown captured
      assertEquals(m.sessions.length, 1);
      assertEquals(m.sessions[0].rootFrameId, ROOT);
      assertEquals(m.sessions[0].headline, "Analyze gdh");
      assertEquals(m.sessions[0].createdAt, 100);
      assertEquals(m.sessions[0].nFrames, 2);
      assertEquals(m.sessions[0].framesByRole, { OPERON: 1, REVIEWER: 1 });
      assertEquals(m.sessions[0].verificationChecks, {
        total: 3,
        byVerdict: { pass: 2, warn: 1 },
      });
      // 7 turns, every one NAMED, zero catch-all remainder
      assertEquals(m.messages, {
        total: 7,
        userTyped: 1,
        assistant: 2,
        toolResults: 1,
        systemNotice: 1,
        harnessInjected: 1,
        unclassified: 1, // the role=system tripwire turn
      });
      assertEquals(m.remoteCompute, true); // reviewer frame has compute_enabled=1
      assertEquals(
        m.missingFiles.slice().sort(),
        ["proj_abc123/a/v2.png", "proj_abc123/a/v3.R", "proj_abc123/a/v4.tmp"]
          .sort(),
      );
      assertEquals(m.credentialsScope, "deferred-to-capture");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "buildManifest: multi-session project splits headlines + reviewer checks per session",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture({ multiSession: true });
    try {
      const m = await buildManifest(org, "gdh");
      // two separate sessions, ordered by created_at (100 then 200)
      assertEquals(m.sessions.length, 2);
      assertEquals(m.sessions.map((s) => s.headline), [
        "Analyze gdh",
        "Diving physiology lit review",
      ]);
      assertEquals(m.sessions.map((s) => s.rootFrameId), [ROOT, ROOT2]);
      // per-session reviewer checks are NOT blurred together
      assertEquals(m.sessions[0].verificationChecks.total, 3);
      assertEquals(m.sessions[1].verificationChecks.total, 1);
      // per-session frame attribution (root + its reviewer child)
      assertEquals(m.sessions[0].nFrames, 2);
      assertEquals(m.sessions[1].nFrames, 2);
      assertEquals(m.sessions[1].framesByRole, { OPERON: 1, REVIEWER: 1 });
      // project-level roll-up sums BOTH sessions (never drops the 2nd session's check)
      assertEquals(m.verificationChecks.total, 4);
      assertEquals(m.verificationChecks.byVerdict, { pass: 3, warn: 1 });
      assertEquals(m.nFrames, 4);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "resolver: by name and by proj_id; unknown/malicious -> null",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      assertEquals((await resolveProject(db, "gdh"))?.id, "proj_abc123");
      assertEquals(
        (await resolveProject(db, "proj_abc123"))?.id,
        "proj_abc123",
      );
      assertEquals(await resolveProject(db, "nope"), null);
      // injection attempt is just a name that matches nothing — never reaches SQL
      assertEquals(
        await resolveProject(
          db,
          "'; SELECT encrypted_value FROM user_secrets;--",
        ),
        null,
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

/** Fingerprint (bytes+mtime) of every existing file in `paths`. */
async function fingerprint(paths: string[]): Promise<Record<string, string>> {
  const fp: Record<string, string> = {};
  for (const p of paths) {
    const st = await Deno.stat(p).catch(() => null);
    if (st) fp[p] = `${await md5(p)}:${st.mtime?.getTime()}`;
  }
  return fp;
}
/** Count leftover session-ingest- clone dirs in the OS temp base. */
async function cloneDirCount(): Promise<number> {
  const probe = await Deno.makeTempDir();
  const base = probe.replace(/\/[^/]+$/, "");
  await Deno.remove(probe);
  let n = 0;
  for (const e of Deno.readDirSync(base)) {
    if (e.isDirectory && e.name.startsWith("session-ingest-")) n++;
  }
  return n;
}

/**
 * Leave genuinely un-checkpointed WAL frames with NO held connection — the
 * "crashed CS" scenario (pa3-1). A clean close would checkpoint and truncate
 * -wal to 0 (vacuous); SIGKILL before close leaves real pending frames, so our
 * read becomes the LAST connection — where a read-write open WOULD checkpoint
 * and rewrite .db (verified: read-write MUTATES, -readonly does not).
 */
async function crashLeavesPendingWal(db: string): Promise<void> {
  const p = new Deno.Command("sqlite3", {
    args: [db],
    stdin: "piped",
    stdout: "null",
    stderr: "null",
  }).spawn();
  const w = p.stdin.getWriter();
  await w.write(new TextEncoder().encode(
    "PRAGMA journal_mode=WAL;\n" +
      "INSERT INTO frames VALUES('crash',NULL,'crash','OPERON',NULL,'agent','opus','high','completed',NULL,'proj_abc123',NULL,300);\n",
  ));
  await new Promise((r) => setTimeout(r, 400)); // let the commit reach -wal
  p.kill("SIGKILL"); // crash before the close-checkpoint runs
  await p.status;
  try {
    await w.close();
  } catch { /* stdin orphaned by the kill */ }
}

Deno.test({
  name:
    "INVARIANT A: buildManifest never mutates .db/-wal with PENDING WAL frames (crashed-writer)",
  ignore: !HAVE_SQLITE,
  sanitizeResources: false, // intentional SIGKILL of a child leaves the pipe
  sanitizeOps: false,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    // Immutability is asserted over the DURABLE files: .db (content) + -wal (log).
    // -shm is SQLite's VOLATILE index (rebuilt from -wal, touched even under
    // -readonly) — not database content, so excluded from the tamper baseline.
    const durable = [db, `${db}-wal`];
    try {
      await crashLeavesPendingWal(db);
      const walSize = (await Deno.stat(`${db}-wal`)).size;
      assert(
        walSize > 0,
        `NON-VACUITY: fixture must carry pending WAL frames (got ${walSize}B)`,
      );
      const before = await fingerprint(durable);
      await buildManifest(org, "gdh"); // our -readonly path, as LAST connection
      assertEquals(
        await fingerprint(durable),
        before,
        "source .db or -wal changed (mutating open!)",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "ca-2: readViaClone reads via a disposable clone and deletes it (success)",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      const before = await cloneDirCount();
      const rows = await readViaClone(
        db,
        "SELECT count(*) n FROM projects",
      ) as { n: number }[];
      assertEquals(rows[0].n, 1);
      assertEquals(
        await cloneDirCount(),
        before,
        "clone dir left behind on success",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "ca-2: readViaClone deletes the clone even when the read throws (finally)",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      const before = await cloneDirCount();
      await assertRejects(
        () => readViaClone(db, "SELECT bad syntax (("),
        Error,
      );
      assertEquals(
        await cloneDirCount(),
        before,
        "clone dir left behind on throw",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "readViaClone refuses SQL naming a secret token",
  fn: async () => {
    await assertRejects(
      () =>
        readViaClone(
          "/nonexistent.db",
          "SELECT encrypted_value FROM user_secrets",
        ),
      Error,
      "secret token",
    );
  },
});

Deno.test({
  name: "INVARIANT B: no secret ever read; no leftover temp clone",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const tmp = await Deno.makeTempDir(); // proxy for TMPDIR scan
    const org = await fixture();
    try {
      const m = await buildManifest(org, "gdh");
      // the whole manifest, serialized, must not contain the secret ciphertext
      assert(
        !JSON.stringify(m).includes("SUPERSECRETCIPHERTEXT"),
        "secret leaked into manifest",
      );
      // no session-ingest clone dir left behind in the OS temp base
      const base = tmp.replace(/[^/]+$/, "");
      let leftover = false;
      for (const e of Deno.readDirSync(base)) {
        if (e.isDirectory && e.name.startsWith("session-ingest-")) {
          leftover = true;
        }
      }
      assert(!leftover, "a session-ingest- temp clone was left behind");
    } finally {
      await Deno.remove(org, { recursive: true });
      await Deno.remove(tmp, { recursive: true });
    }
  },
});

Deno.test({
  name: "empty project -> well-formed zero manifest",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture({ empty: true });
    try {
      const m = await buildManifest(org, "gdh");
      assertEquals(m.artifacts.versions, 0);
      assertEquals(m.artifacts.saved, 0);
      assertEquals(m.artifacts.intermediate, 0);
      assertEquals(m.artifacts.byLanguage, {});
      assertEquals(m.nDistinctEnvs, 0);
      assertEquals(m.nFrames, 1); // just the OPERON root
      assertEquals(m.framesByRole, { OPERON: 1 });
      assertEquals(m.verificationChecks.total, 0);
      // 5 root turns, fully named
      assertEquals(m.messages, {
        total: 5,
        userTyped: 1,
        assistant: 1,
        toolResults: 1,
        systemNotice: 1,
        harnessInjected: 0,
        unclassified: 1,
      });
      assertEquals(m.missingFiles, []);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "drift: missing artifact_versions table degrades, does not throw",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const org = await fixture({ drift: true });
    try {
      const m = await buildManifest(org, "gdh");
      assertEquals(m.artifacts.versions, 0);
      assertEquals(m.nFrames, 2); // frames still counted
      assert(
        m.warnings.some((w) => /degraded/.test(w)),
        "expected a degrade warning",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "quiescence: no -wal passes; an actively-growing -wal is refused",
  ignore: !HAVE_SQLITE,
  fn: async () => {
    const dir = await Deno.makeTempDir();
    const db = `${dir}/operon-cli.db`;
    await Deno.writeTextFile(db, "x");
    try {
      await assertQuiescent(db, 50); // no -wal -> resolves
      const wal = `${db}-wal`;
      await Deno.writeTextFile(wal, "0");
      // grow the -wal during the sample window
      const grow = (async () => {
        await new Promise((r) => setTimeout(r, 40));
        await Deno.writeTextFile(wal, "0".repeat(5000));
      })();
      await assertRejects(
        () => assertQuiescent(db, 200),
        Error,
        "actively written",
      );
      await grow;
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});
