/**
 * Tests for @vcjdeboer/session-ingest external.ts (capture_external).
 * Skip-guarded on sqlite3. Builds its own fixture operon-cli.db (projects/frames/
 * execution_log/host_call_log/host_grants); never touches real Claude Science data.
 * The load-bearing test is SECRET EXCLUSION: secrets planted in args_json[1+],
 * data_inline, data_ref, and credential-method args must NEVER appear in the record.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { captureExternal, type External, type ExternalSink } from "./external.ts";
import { preflightSqlite } from "./db.ts";

const HAVE = (await preflightSqlite()).ok;

async function sqlite(db: string, sql: string): Promise<void> {
  const out = await new Deno.Command("sqlite3", { args: [db, sql] }).output();
  if (!out.success) throw new Error(new TextDecoder().decode(out.stderr));
}

function fakeSink() {
  const resources: Record<string, unknown> = {};
  const logs: { msg: string; props?: Record<string, unknown> }[] = [];
  const sink: ExternalSink = {
    writeResource: (spec, inst, data) => {
      resources[`${spec}/${inst}`] = data;
      return Promise.resolve({ version: 1 });
    },
    logger: { info: (msg, props) => logs.push({ msg, props }) },
  };
  return { sink, resources, logs };
}

// Secret markers planted in call CONTENT — none may appear anywhere in the record.
const SECRETS = [
  "SECRET-QUERY-skAAA", // args_json[1] of an mcp call
  "SECRET-CRED-TOKEN", // credentials_request args
  "vincent-AT-xdomain", // get_user_email args
  "SECRET-OBJ", // structured args_json[0]
  "SECRET-LLM", // llm args
  "SECRET-INLINE", // data_inline
  "SECRET-REF", // data_ref
  "shouldnotappear", // OTHER project's mcp server (scoping)
];

async function fixture(): Promise<string> {
  const org = await Deno.makeTempDir({ prefix: "ext-fixture-" });
  const orgDir = `${org}/orgs/org1`;
  await Deno.mkdir(orgDir, { recursive: true });
  const db = `${orgDir}/operon-cli.db`;
  await sqlite(
    db,
    `PRAGMA journal_mode=WAL;
     CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
     INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL),('proj_other','other',NULL,1,2,NULL);
     CREATE TABLE frames (id TEXT,parent_frame_id TEXT,project_id TEXT);
     INSERT INTO frames VALUES ('R1',NULL,'proj_abc123'),('RO',NULL,'proj_other'),('RN',NULL,NULL);
     CREATE TABLE execution_log (id TEXT,frame_id TEXT);
     INSERT INTO execution_log VALUES ('E1','R1'),('E2','RO'),('EN','RN');
     CREATE TABLE host_call_log (id INTEGER PRIMARY KEY AUTOINCREMENT,execution_log_id TEXT NOT NULL,seq INT NOT NULL,method TEXT NOT NULL,args_json TEXT NOT NULL,derivable INT DEFAULT 0 NOT NULL,data_inline TEXT,data_ref TEXT,error TEXT,bytes INT NOT NULL,created_at INT NOT NULL);
     INSERT INTO host_call_log (execution_log_id,seq,method,args_json,data_inline,data_ref,error,bytes,created_at) VALUES
       ('E1',1,'mcp','["pubmed","SECRET-QUERY-skAAA"]',NULL,NULL,NULL,100,10),
       ('E1',2,'mcp','["opentargets","q2"]',NULL,NULL,NULL,200,20),
       ('E1',3,'mcp','["pubmed","q3"]',NULL,NULL,NULL,50,30),
       ('E1',4,'credentials_request','["SECRET-CRED-TOKEN"]',NULL,NULL,NULL,0,40),
       ('E1',5,'get_user_email','["vincent-AT-xdomain"]',NULL,NULL,NULL,0,50),
       ('E1',6,'mcp','{bad json',NULL,NULL,NULL,10,60),
       ('E1',7,'mcp','[{"q":"SECRET-OBJ"},"x"]',NULL,NULL,NULL,10,70),
       ('E1',8,'llm','["prompt SECRET-LLM"]','SECRET-INLINE','SECRET-REF','boom',5,80),
       ('E2',1,'mcp','["shouldnotappear","x"]',NULL,NULL,NULL,999,90),
       ('EN',1,'get_user_email','["x"]',NULL,NULL,NULL,0,100);
     CREATE TABLE host_grants (id TEXT,user_id TEXT,host_path TEXT,mount_name TEXT,created_at INT,mode TEXT DEFAULT 'ro');
     INSERT INTO host_grants VALUES ('g1','u1','/Users/vincent/secret-mount','data',1,'ro');
     CREATE TABLE user_secrets (id TEXT,provider TEXT,encrypted_value TEXT);
     INSERT INTO user_secrets VALUES ('s1','openalex','SUPERSECRETCIPHERTEXT');`,
  );
  return org;
}

const bySource = (c: External, name: string) => c.sources.find((s) => s.source === name);

Deno.test({
  name: "external: STRICT counts-only — NO call content leaks (args_json[1+]/data_inline/data_ref/creds)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, resources } = fakeSink();
      const { external: c } = await captureExternal(org, "gdh", undefined, sink);
      assertEquals(resources["external/proj_abc123"], c);
      const blob = JSON.stringify(c);
      for (const s of SECRETS) assert(!blob.includes(s), `secret/content leaked: ${s}`);
      // sanity: the safe server names ARE present (proves we captured, not just emptied)
      assert(blob.includes("pubmed") && blob.includes("opentargets"), "servers captured");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "external: per-source aggregation + project scoping + byMethod histogram",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { external: c } = await captureExternal(org, "gdh", undefined, sink);
      // pubmed aggregated across its two calls
      const pub = bySource(c, "pubmed")!;
      assertEquals([pub.kind, pub.callCount, pub.totalBytes, pub.firstAt, pub.lastAt], ["mcp", 2, 150, 10, 30]);
      assertEquals(bySource(c, "opentargets")!.callCount, 1);
      // OTHER project's call is excluded (scoping)
      assertEquals(bySource(c, "shouldnotappear"), undefined);
      assert(!c.sources.some((s) => s.callCount === 1 && s.totalBytes === 999), "other-project call excluded");
      // in-scope totals: mcp5 + credentials_request1 + get_user_email1 + llm1 = 8
      assertEquals(c.totals.calls, 8);
      assertEquals(c.totals.byMethod, { credentials_request: 1, get_user_email: 1, llm: 1, mcp: 5 });
      // credential/email methods counted by NAME, kind=method, never parsed
      assertEquals(bySource(c, "credentials_request")!.kind, "method");
      assertEquals(bySource(c, "get_user_email")!.callCount, 1); // orphan EN row NOT counted
      // llm error → is_error boolean → errorCount
      assertEquals(bySource(c, "llm")!.errorCount, 1);
      // sources sorted by key
      assertEquals([...c.sources.map((s) => s.source)], [...c.sources.map((s) => s.source)].sort());
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "external: malformed args_json does NOT abort (json_valid guard) → mcp:malformed bucket",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { external: c } = await captureExternal(org, "gdh", undefined, sink); // must not throw
      assertEquals(bySource(c, "mcp:malformed")!.callCount, 1);
      assert(c.warnings.some((w) => /mcp:malformed/.test(w)), "malformed row warned");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "external: a structured args_json[0] → mcp:unrecognized, object text NOT leaked",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { external: c } = await captureExternal(org, "gdh", undefined, sink);
      assertEquals(bySource(c, "mcp:unrecognized")!.callCount, 1);
      assert(!JSON.stringify(c).includes("SECRET-OBJ"), "structured $[0] content not leaked");
      assert(c.warnings.some((w) => /mcp:unrecognized/.test(w)), "unrecognized row warned");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "external: orphan (frame with no project) counted + warned, not silently dropped",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { external: c } = await captureExternal(org, "gdh", undefined, sink);
      assertEquals(c.totals.orphanCallCount, 1); // the EN/get_user_email row on a project-less frame
      assert(c.warnings.some((w) => /unattributable to any project/.test(w)), "orphan warned");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "external: host_grants labeled filesystem mounts, host_path DROPPED (no abs path in record)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { external: c } = await captureExternal(org, "gdh", undefined, sink);
      assertEquals(c.filesystemMountGrants, [{ mountName: "data", mode: "ro", userId: "u1" }]);
      assert(!JSON.stringify(c).includes("/Users/vincent/secret-mount"), "host_path not in the portable record");
      // releasePin: fillable null on mcp sources only; absent on method sources
      assertEquals(bySource(c, "pubmed")!.releasePin, null);
      assertEquals(bySource(c, "llm")!.releasePin, undefined);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "external: secret-shaped args_json[0] → bucketed mcp:secret-shaped (never emitted) + valid-non-array → mcp:malformed",
  ignore: !HAVE,
  fn: async () => {
    const org = await Deno.makeTempDir({ prefix: "ext-ss-" });
    const orgDir = `${org}/orgs/org1`;
    await Deno.mkdir(orgDir, { recursive: true });
    await sqlite(
      `${orgDir}/operon-cli.db`,
      `PRAGMA journal_mode=WAL;
       CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
       INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL);
       CREATE TABLE frames (id TEXT,parent_frame_id TEXT,project_id TEXT);
       INSERT INTO frames VALUES ('R1',NULL,'proj_abc123');
       CREATE TABLE execution_log (id TEXT,frame_id TEXT);
       INSERT INTO execution_log VALUES ('E1','R1');
       CREATE TABLE host_call_log (id INTEGER PRIMARY KEY AUTOINCREMENT,execution_log_id TEXT NOT NULL,seq INT NOT NULL,method TEXT NOT NULL,args_json TEXT NOT NULL,derivable INT DEFAULT 0 NOT NULL,data_inline TEXT,data_ref TEXT,error TEXT,bytes INT NOT NULL,created_at INT NOT NULL);
       INSERT INTO host_call_log (execution_log_id,seq,method,args_json,bytes,created_at) VALUES
         ('E1',1,'mcp','["sk-abcdefghijklmnop","q"]',5,10),
         ('E1',2,'mcp','{}',5,20),
         ('E1',3,'mcp','123',5,30);
       CREATE TABLE host_grants (id TEXT,user_id TEXT,host_path TEXT,mount_name TEXT,created_at INT,mode TEXT DEFAULT 'ro');`,
    );
    try {
      const { sink } = fakeSink();
      const { external: c } = await captureExternal(org, "gdh", undefined, sink);
      // a servername-shaped-BUT-secret-shaped $[0] → tripped + bucketed, raw value never emitted
      assertEquals(c.totals.secretShapedCount, 1);
      assertEquals(bySource(c, "mcp:secret-shaped")!.callCount, 1);
      assert(!JSON.stringify(c).includes("sk-abcdefghijklmnop"), "secret-shaped server never emitted as a key");
      // valid-JSON-but-non-array ({} and 123) → NULL server → mcp:malformed (no abort)
      assertEquals(bySource(c, "mcp:malformed")!.callCount, 2);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "external: deterministic two-run byte-identical; source DB + no secret ciphertext leak",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    const dbPath = `${org}/orgs/org1/operon-cli.db`;
    const dbBefore = await Deno.readFile(dbPath);
    try {
      const a = fakeSink();
      const r1 = await captureExternal(org, "gdh", undefined, a.sink);
      const b = fakeSink();
      const r2 = await captureExternal(org, "gdh", undefined, b.sink);
      assertEquals(JSON.stringify(r1.external), JSON.stringify(r2.external), "two runs byte-identical");
      assert(!JSON.stringify(r1.external).includes("SUPERSECRETCIPHERTEXT"), "no user_secrets ciphertext");
      assertEquals(await Deno.readFile(dbPath), dbBefore, "source DB byte-unmutated");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});
