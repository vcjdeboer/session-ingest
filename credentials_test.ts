/**
 * Tests for @vcjdeboer/session-ingest credentials.ts (capture_credentials).
 * Skip-guarded on sqlite3. Own fixture operon-cli.db; never touches real CS data.
 * The load-bearing test is SECRET EXCLUSION: nothing from args_json[1+] or the secret
 * tables (dropped from the clone) may appear in the record.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  captureCredentials,
  type Credentials,
  type CredentialsSink,
} from "./credentials.ts";
import { captureExternal, type ExternalSink } from "./external.ts";
import { preflightSqlite } from "./db.ts";

const HAVE = (await preflightSqlite()).ok;

async function sqlite(db: string, sql: string): Promise<void> {
  const out = await new Deno.Command("sqlite3", { args: [db, sql] }).output();
  if (!out.success) throw new Error(new TextDecoder().decode(out.stderr));
}

function fakeSink() {
  const resources: Record<string, unknown> = {};
  const logs: { msg: string; props?: Record<string, unknown> }[] = [];
  const sink: CredentialsSink & ExternalSink = {
    writeResource: (spec, inst, data) => {
      resources[`${spec}/${inst}`] = data;
      return Promise.resolve({ version: 1 });
    },
    logger: { info: (msg, props) => logs.push({ msg, props }) },
  };
  return { sink, resources, logs };
}

const SECRETS = [
  "SECRET-CRED-VALUE", // credentials_request args_json[1]
  "SUPERSECRETCIPHERTEXT", // user_secrets.encrypted_value (table dropped from clone)
  "sk-shouldnotleak12345", // a secret-shaped provider $[0]
];

async function fixture(): Promise<string> {
  const org = await Deno.makeTempDir({ prefix: "cred-fixture-" });
  const orgDir = `${org}/orgs/org1`;
  await Deno.mkdir(orgDir, { recursive: true });
  await sqlite(
    `${orgDir}/operon-cli.db`,
    `PRAGMA journal_mode=WAL;
     CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
     INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL),('proj_other','other',NULL,1,2,NULL);
     CREATE TABLE frames (id TEXT,parent_frame_id TEXT,project_id TEXT);
     INSERT INTO frames VALUES ('R1',NULL,'proj_abc123'),('RO',NULL,'proj_other');
     CREATE TABLE execution_log (id TEXT,frame_id TEXT);
     INSERT INTO execution_log VALUES ('E1','R1'),('E2','RO');
     CREATE TABLE host_call_log (id INTEGER PRIMARY KEY AUTOINCREMENT,execution_log_id TEXT NOT NULL,seq INT NOT NULL,method TEXT NOT NULL,args_json TEXT NOT NULL,derivable INT DEFAULT 0 NOT NULL,data_inline TEXT,data_ref TEXT,error TEXT,bytes INT NOT NULL,created_at INT NOT NULL);
     INSERT INTO host_call_log (execution_log_id,seq,method,args_json,bytes,created_at) VALUES
       ('E1',1,'credentials_request','["openalex","SECRET-CRED-VALUE"]',0,10),
       ('E1',2,'credentials_request','["github"]',0,20),
       ('E1',3,'credentials_request','["openalex"]',0,30),
       ('E1',4,'credentials_request','["sk-shouldnotleak12345"]',0,40),
       ('E1',5,'credentials_request','{bad json',0,50),
       ('E1',6,'get_user_email','["vincent-AT-x"]',0,60),
       ('E2',1,'credentials_request','["otherprojcred"]',0,70);
     CREATE TABLE host_grants (id TEXT,user_id TEXT,host_path TEXT,mount_name TEXT,created_at INT,mode TEXT DEFAULT 'ro');
     CREATE TABLE user_secrets (id TEXT,provider TEXT,encrypted_value TEXT);
     INSERT INTO user_secrets VALUES ('s1','openalex','SUPERSECRETCIPHERTEXT');`,
  );
  return org;
}

const byProvider = (c: Credentials, name: string) =>
  c.credentials.find((x) => x.provider === name);

Deno.test({
  name:
    "credentials: PRESENCE-only, NO secret leaks (args_json[1+], secret tables, secret-shaped $[0])",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, resources } = fakeSink();
      const { credentials: c } = await captureCredentials(
        org,
        "gdh",
        undefined,
        sink,
        { vault: "v" },
      );
      assertEquals(resources["credentials/proj_abc123"], c);
      const blob = JSON.stringify(c);
      for (const s of SECRETS) assert(!blob.includes(s), `secret leaked: ${s}`);
      assert(
        blob.includes("openalex") && blob.includes("github"),
        "real providers captured",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "credentials: per-provider aggregation + scoping + get_user_email excluded",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { credentials: c } = await captureCredentials(
        org,
        "gdh",
        undefined,
        sink,
      );
      assertEquals([
        byProvider(c, "openalex")!.requestCount,
        byProvider(c, "openalex")!.firstAt,
        byProvider(c, "openalex")!.lastAt,
      ], [2, 10, 30]);
      assertEquals(byProvider(c, "github")!.requestCount, 1);
      // other project excluded; get_user_email never counted
      assertEquals(byProvider(c, "otherprojcred"), undefined);
      assert(
        !JSON.stringify(c).includes("get_user_email") &&
          !JSON.stringify(c).includes("vincent-AT-x"),
        "get_user_email out of scope",
      );
      // in-scope credentials_request rows = 5 (openalex×2, github, sk-…, malformed) — E2 & get_user_email excluded
      assertEquals(c.totals.requests, 5);
      // sorted providers
      assertEquals(
        c.credentials.map((x) => x.provider),
        [...c.credentials.map((x) => x.provider)].sort(),
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "credentials: sentinel buckets NOT in vaultRefs/manifest; secret-shaped $[0] bucketed + value-free",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { credentials: c } = await captureCredentials(
        org,
        "gdh",
        undefined,
        sink,
        { vault: "v" },
      );
      // secret-shaped provider → bucketed 'secret-shaped', counted, raw value never emitted (record OR warnings)
      assertEquals(c.totals.secretShapedCount, 1);
      assert(
        byProvider(c, "secret-shaped") !== undefined,
        "secret-shaped bucket present as a diagnostic",
      );
      assert(
        !JSON.stringify(c.warnings).includes("sk-shouldnotleak12345"),
        "warnings are value-free",
      );
      // malformed bucket present (the {bad json row)
      assert(
        byProvider(c, "malformed") !== undefined,
        "malformed bucket present",
      );
      // vaultRefs + manifest ONLY for real providers (openalex, github) — never a sentinel
      assertEquals(Object.keys(c.vaultRefs).sort(), ["github", "openalex"]);
      for (const sentinel of ["malformed", "unrecognized", "secret-shaped"]) {
        assert(
          !(sentinel in c.vaultRefs),
          `${sentinel} must not be provisionable`,
        );
        assert(
          !c.provisioningManifest.some((m) => m.includes(sentinel)),
          `${sentinel} not in manifest`,
        );
      }
      // org-namespaced key + placeholder secret
      assertEquals(c.vaultRefs["openalex"], 'vault.get("v", "org1/openalex")');
      assert(
        c.provisioningManifest.includes(
          "swamp vault put v org1/openalex <SECRET>",
        ),
        "manifest org-namespaced + placeholder",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "credentials: sum(requestCount) == capture_external credentials_request callCount (cross-model consistency)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const a = fakeSink();
      const { credentials: c } = await captureCredentials(
        org,
        "gdh",
        undefined,
        a.sink,
      );
      const b = fakeSink();
      const { external: e } = await captureExternal(
        org,
        "gdh",
        undefined,
        b.sink,
      );
      const credTotal = c.credentials.reduce((n, x) => n + x.requestCount, 0);
      const extCred = e.sources.find((s) =>
        s.source === "credentials_request"
      )?.callCount ?? 0;
      assertEquals(
        credTotal,
        extCred,
        "the two records agree on credentials_request count",
      );
      assertEquals(credTotal, c.totals.requests);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "credentials: a hostile vault name is rejected fast (before any CEL/manifest interpolation)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      let threw = false;
      try {
        await captureCredentials(org, "gdh", undefined, sink, {
          vault: 'v" injected',
        });
      } catch {
        threw = true;
      }
      assert(threw, "hostile vault name throws");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "credentials: an org DIR name with unsafe chars → inventory kept, provisioning omitted + warned",
  ignore: !HAVE,
  fn: async () => {
    const root = await Deno.makeTempDir({ prefix: "cred-badorg-" });
    const badOrg = 'bad org"name';
    const orgDir = `${root}/orgs/${badOrg}`;
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
       INSERT INTO host_call_log (execution_log_id,seq,method,args_json,bytes,created_at) VALUES ('E1',1,'credentials_request','["openalex"]',0,10);`,
    );
    try {
      const { sink } = fakeSink();
      const { credentials: c } = await captureCredentials(
        root,
        "gdh",
        undefined,
        sink,
        { vault: "v" },
      );
      // inventory intact
      assertEquals(byProvider(c, "openalex")!.requestCount, 1);
      // provisioning omitted (org charset failed) + warned; no injectable string emitted
      assertEquals(c.vaultRefs, {});
      assertEquals(c.provisioningManifest, []);
      assert(
        c.warnings.some((w) => /org id has unexpected characters/.test(w)),
        "bad org warned",
      );
      assert(
        !JSON.stringify(c).includes("rm -rf") &&
          !JSON.stringify(c).includes('bad org"name'),
        "no injectable org string emitted",
      );
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  },
});

Deno.test({
  name:
    "credentials: empty (no credentials_request) → valid empty record; deterministic; source unmutated",
  ignore: !HAVE,
  fn: async () => {
    const org = await Deno.makeTempDir({ prefix: "cred-empty-" });
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
       CREATE TABLE host_call_log (id INTEGER PRIMARY KEY AUTOINCREMENT,execution_log_id TEXT NOT NULL,seq INT NOT NULL,method TEXT NOT NULL,args_json TEXT NOT NULL,derivable INT DEFAULT 0 NOT NULL,data_inline TEXT,data_ref TEXT,error TEXT,bytes INT NOT NULL,created_at INT NOT NULL);`,
    );
    const dbPath = `${orgDir}/operon-cli.db`;
    const before = await Deno.readFile(dbPath);
    try {
      const a = fakeSink();
      const r1 = await captureCredentials(org, "gdh", undefined, a.sink);
      const b = fakeSink();
      const r2 = await captureCredentials(org, "gdh", undefined, b.sink);
      assertEquals(r1.credentials.credentials, []);
      assertEquals(r1.credentials.vaultRefs, {});
      assertEquals(r1.credentials.totals, {
        requests: 0,
        providers: 0,
        realProviders: 0,
        secretShapedCount: 0,
      });
      assertEquals(
        JSON.stringify(r1.credentials),
        JSON.stringify(r2.credentials),
        "deterministic two-run",
      );
      assertEquals(await Deno.readFile(dbPath), before, "source db unmutated");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});
