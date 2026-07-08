/**
 * Tests for @vcjdeboer/session-ingest corpus.ts (capture_corpus).
 * Skip-guarded on sqlite3. Builds its own fixture org tree (DB + real files on
 * disk); never touches real Claude Science data.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { type Corpus, captureCorpus, type CorpusSink } from "./corpus.ts";
import { preflightSqlite } from "./db.ts";
import { sha256hexBytes } from "./store.ts";

const HAVE = (await preflightSqlite()).ok;

async function sqlite(db: string, sql: string): Promise<void> {
  const out = await new Deno.Command("sqlite3", { args: [db, sql] }).output();
  if (!out.success) throw new Error(new TextDecoder().decode(out.stderr));
}

function fakeSink() {
  const resources: Record<string, unknown> = {};
  const files: Record<string, Uint8Array> = {};
  const logs: { msg: string; props?: Record<string, unknown> }[] = [];
  const sink: CorpusSink = {
    writeResource: (spec, inst, data) => {
      resources[`${spec}/${inst}`] = data;
      return Promise.resolve({ version: 1 });
    },
    createFileWriter: (spec, inst) => ({
      writeAll: (c: Uint8Array) => {
        files[`${spec}/${inst}`] = c;
        return Promise.resolve({});
      },
      writeStream: async (s: ReadableStream<Uint8Array>) => {
        const chunks: Uint8Array[] = [];
        for await (const ch of s) chunks.push(ch);
        const total = chunks.reduce((n, c) => n + c.length, 0);
        const buf = new Uint8Array(total);
        let o = 0;
        for (const c of chunks) { buf.set(c, o); o += c.length; }
        files[`${spec}/${inst}`] = buf;
        return {};
      },
    }),
    logger: { info: (msg, props) => logs.push({ msg, props }) },
  };
  return { sink, resources, files, logs };
}

const enc = (s: string) => new TextEncoder().encode(s);

// artifact + workspace byte contents
const A_BYTES = enc("print('a')\n"); // A1 + A2 (duplicate → dedup)
const C_REAL = enc("REALBYTES"); // A3 on disk (checksum will be WRONG → drift)
const C_WRONG = enc("WRONGBYTES"); // A3 recorded checksum source
const D_BYTES = enc("dee"); // A4 (checksum sha256:-prefixed)
const E_BYTES = enc("eee"); // A5 (NULL checksum → unverifiable)
const BIG_BYTES = enc("X".repeat(500)); // A7 (big → maxFileBytes skip)
const WS_W1 = enc('{"k":1}'); // referenced + owned (dedup)
const WS_NOTE = enc("token: sk-ABCDEFGHIJKLMNOPQRSTUVWX here"); // tripwire
const WS_W2 = enc("a,b\n1,2\n"); // under the SECOND root (multi-root)
const WS_OTHER = enc('{"other":true}'); // other project → MUST NOT capture
const WS_MCP = enc('{"mcp":1}'); // shared orphan → MUST NOT capture
const WS_KEY = enc("-----BEGIN RSA PRIVATE KEY-----\nMIIabcd\n-----END RSA PRIVATE KEY-----\n"); // .pem → tripwire

// Root-frame ids are UUIDs in real CS (and corpus.ts gates them with FRAME_ID_RE).
const R1 = "aaaaaaaa-1111-4111-8111-111111111111";
const R2 = "bbbbbbbb-2222-4222-8222-222222222222";
const R3 = "cccccccc-3333-4333-8333-333333333333";
const RO = "dddddddd-4444-4444-8444-444444444444";

interface Opt { allPresent?: boolean; remote?: boolean; noDrift?: boolean }

async function fixture(opt: Opt = {}): Promise<{ org: string; shas: Record<string, string> }> {
  const org = await Deno.makeTempDir({ prefix: "corpus-fixture-" });
  const orgDir = `${org}/orgs/org1`;
  await Deno.mkdir(orgDir, { recursive: true });
  const mk = async (rel: string, bytes: Uint8Array) => {
    const p = `${orgDir}/${rel}`;
    await Deno.mkdir(p.slice(0, p.lastIndexOf("/")), { recursive: true });
    await Deno.writeFile(p, bytes);
  };
  // artifact files
  await mk("artifacts/proj_abc123/v1/a.py", A_BYTES);
  await mk("artifacts/proj_abc123/v2/b.py", A_BYTES);
  await mk("artifacts/proj_abc123/v3/c.bin", C_REAL);
  await mk("artifacts/proj_abc123/v4/d.txt", D_BYTES);
  await mk("artifacts/proj_abc123/v5/e.txt", E_BYTES);
  await mk("artifacts/proj_abc123/v7/big.bin", BIG_BYTES);
  // A6 (proj_abc123/v6/missing.txt) intentionally NOT written
  // workspaces
  await mk(`workspaces/${R1}/handoff/w1.json`, WS_W1);
  await mk(`workspaces/${R1}/note.txt`, WS_NOTE);
  await mk(`workspaces/${R1}/id_rsa.pem`, WS_KEY); // credential-extension → must trip the wire
  await mk(`workspaces/${R2}/w2.csv`, WS_W2);
  await mk(`workspaces/${RO}/secret_other.json`, WS_OTHER);
  await mk("workspaces/_mcp-x/tool.json", WS_MCP);
  // sweep-ledger: R3 = a target root whose dir is gone; RO = other project (must be ignored)
  await mk(`workspaces-sweep-ledger/${R3}`, enc('{"outcome":"swept","at":"2026-07-05T11:15:42Z"}'));
  await mk(`workspaces-sweep-ledger/${RO}`, enc('{"outcome":"swept","at":"2026-07-05T00:00:00Z"}'));

  const shas = {
    a: await sha256hexBytes(A_BYTES),
    cWrong: await sha256hexBytes(C_WRONG),
    d: await sha256hexBytes(D_BYTES),
    big: await sha256hexBytes(BIG_BYTES),
    w1: await sha256hexBytes(WS_W1),
  };
  const compute = opt.remote ? "1" : "0";
  const absW1 = `${orgDir}/workspaces/${R1}/handoff/w1.json`;
  const absGone = `${orgDir}/workspaces/${R1}/gone.json`;
  const filesWritten = JSON.stringify([
    { path: absW1, sha256: shas.w1 }, // present (also owned → dedup)
    { path: absGone }, // absent → lost
    { sha256: "deadbeef" }, // no path → warning
    { path: "/etc/hostname" }, // outside org tree → skip
  ]).replace(/'/g, "''");

  const a6checksum = opt.allPresent ? "" : "'" + (await sha256hexBytes(enc("A6"))) + "'";
  const a6row = opt.allPresent
    ? ""
    : `INSERT INTO artifact_versions VALUES ('A6','a6',1,NULL,'${R1}',${a6checksum},'proj_abc123/v6/missing.txt','python',0,NULL,NULL,NULL,6);`;
  const a3checksum = opt.noDrift ? await sha256hexBytes(C_REAL) : shas.cWrong;

  const db = `${orgDir}/operon-cli.db`;
  await sqlite(
    db,
    `PRAGMA journal_mode=WAL;
     CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
     INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL),('proj_other','other',NULL,1,2,NULL);
     CREATE TABLE frames (id TEXT,parent_frame_id TEXT,agent_name TEXT,delegate_name TEXT,conversation_type TEXT,model TEXT,effort TEXT,status TEXT,compute_enabled TEXT,created_at INT,project_id TEXT);
     INSERT INTO frames VALUES
       ('${R1}',NULL,'OPERON',NULL,NULL,NULL,NULL,NULL,'${compute}',1,'proj_abc123'),
       ('${R2}',NULL,'OPERON',NULL,NULL,NULL,NULL,NULL,'0',2,'proj_abc123'),
       ('${R3}',NULL,'OPERON',NULL,NULL,NULL,NULL,NULL,'0',3,'proj_abc123'),
       ('C1','${R1}','REVIEWER',NULL,NULL,NULL,NULL,NULL,'0',4,'proj_abc123'),
       ('${RO}',NULL,'OPERON',NULL,NULL,NULL,NULL,NULL,'0',5,'proj_other');
     CREATE TABLE artifact_versions (id TEXT,artifact_id TEXT,version_number INT,producing_cell_id TEXT,frame_id TEXT,checksum TEXT,storage_path TEXT,language TEXT,is_intermediate INT,env_snapshot_hash TEXT,parent_version_id TEXT,dependency_mappings TEXT,created_at INT);
     INSERT INTO artifact_versions VALUES
       ('A1','a1',1,NULL,'${R1}','${shas.a}','proj_abc123/v1/a.py','python',0,NULL,NULL,NULL,1),
       ('A2','a2',1,NULL,'${R1}','${shas.a}','proj_abc123/v2/b.py','python',0,NULL,NULL,NULL,2),
       ('A3','a3',1,NULL,'${R1}','${a3checksum}','proj_abc123/v3/c.bin','bin',0,NULL,NULL,NULL,3),
       ('A4','a4',1,NULL,'${R1}','sha256:${shas.d}','proj_abc123/v4/d.txt','text',0,NULL,NULL,NULL,4),
       ('A5','a5',1,NULL,'${R1}',NULL,'proj_abc123/v5/e.txt','text',0,NULL,NULL,NULL,5),
       ('A7','a7',1,NULL,'${R1}','${shas.big}','proj_abc123/v7/big.bin','bin',0,NULL,NULL,NULL,7);
     ${a6row}
     CREATE TABLE execution_log (id TEXT,frame_id TEXT,cell_index INT,kernel_id TEXT,conda_env TEXT,language TEXT,source TEXT,stdout TEXT,stderr TEXT,exit_status INT,error_lineno INT,files_written TEXT,files_read TEXT,origin TEXT);
     INSERT INTO execution_log VALUES ('E1','${R1}',0,'k','python','python','src','','',0,NULL,'${filesWritten}','[]','local');
     CREATE TABLE user_secrets (id TEXT,provider TEXT,encrypted_value TEXT);
     INSERT INTO user_secrets VALUES ('s1','openalex','SUPERSECRETCIPHERTEXT');`,
  );
  return { org, shas };
}

async function sha256File(p: string): Promise<string> {
  return await sha256hexBytes(await Deno.readFile(p));
}

Deno.test({
  name: "corpus: artifact bytes copied + deduped + drift + prefix-normalize + unverifiable + missing",
  ignore: !HAVE,
  fn: async () => {
    const { org, shas } = await fixture();
    try {
      const { sink, resources, files } = fakeSink();
      const { corpus: c } = await captureCorpus(org, "gdh", undefined, sink);
      assertEquals(resources["corpus/proj_abc123"], c);
      const by = (id: string) => c.artifacts.find((a) => a.versionId === id)!;
      // present artifact copied to a blob keyed by ACTUAL sha; bytes verbatim
      assertEquals(by("A1").actualSha, shas.a);
      assertEquals(files[`blob/${shas.a}`], A_BYTES);
      // dedup: A1 + A2 identical bytes -> ONE blob
      assert(by("A1").drift !== true);
      assert(by("A2").drift !== true);
      assertEquals(c.writeManifest.filter((s) => s === shas.a).length, 1);
      assert(c.totals.deduped >= 1);
      // drift: A3 on-disk != recorded checksum
      assertEquals(by("A3").drift, true);
      assertEquals(by("A3").actualSha, await sha256hexBytes(C_REAL));
      // sha256:-prefix normalizes → NO false drift on A4
      assert(by("A4").drift !== true);
      assert(by("A4").unverifiable !== true);
      // NULL checksum → unverifiable (not drift) on A5
      assertEquals(by("A5").unverifiable, true);
      assert(by("A5").drift !== true);
      // missing file A6 → present:false, no throw
      assertEquals(by("A6").present, false);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "corpus: workspaces project-scoped (multi-root), path-safety, no-path bucket, lost, tripwire",
  ignore: !HAVE,
  fn: async () => {
    const { org } = await fixture();
    try {
      const { sink, files } = fakeSink();
      const { corpus: c } = await captureCorpus(org, "gdh", undefined, sink);
      const rels = c.workspace.map((w) => w.relPath);
      // owned across BOTH roots (R1 + R2) captured
      assert(rels.some((r) => r.endsWith(`workspaces/${R1}/handoff/w1.json`)), "R1 file");
      assert(rels.some((r) => r.endsWith(`workspaces/${R1}/note.txt`)), "R1 note");
      assert(rels.some((r) => r.endsWith(`workspaces/${R2}/w2.csv`)), "R2 file (multi-root)");
      // other project + shared orphan NOT captured
      assert(!rels.some((r) => r.includes("secret_other")), "other project excluded");
      assert(!rels.some((r) => r.includes("_mcp-x")), "shared orphan excluded");
      assert(!Object.values(files).some((b) => b === WS_OTHER), "other bytes not stored");
      // path-safety: /etc/hostname (outside org) never captured
      assert(!rels.some((r) => r.includes("hostname")), "outside-org path skipped");
      // referenced-but-absent → lost
      assert(c.lost.some((l) => (l.relPath ?? "").endsWith("gone.json")), "absent ref → lost");
      // swept root R3 from ledger → lost; other project's swept RO NOT
      assert(c.lost.some((l) => l.workspaceId === R3 && l.outcome === "swept"), "R3 swept lost");
      assert(!c.lost.some((l) => l.workspaceId === RO), "other project swept ignored");
      // no-path descriptor → a warning
      assert(c.warnings.some((w) => /no-path descriptor/.test(w)), "no-path warned");
      // tripwire: note.txt (sk- token) AND id_rsa.pem (PRIVATE KEY, credential extension) → counted
      assert(c.totals.secretShapedCount >= 2, "tripwire counted note.txt + .pem");
      assert(rels.some((r) => r.endsWith("id_rsa.pem")), ".pem still copied (sensitive bundle)");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "corpus: maxFileBytes records the big file by-reference (skipped, not stored)",
  ignore: !HAVE,
  fn: async () => {
    const { org, shas } = await fixture();
    try {
      const { sink, files } = fakeSink();
      const { corpus: c } = await captureCorpus(org, "gdh", undefined, sink, { maxFileBytes: 100 });
      const a7 = c.artifacts.find((a) => a.versionId === "A7")!;
      assertEquals(a7.skipped, true);
      assertEquals(a7.actualSha, shas.big); // still content-addressed
      assert(!(`blob/${shas.big}` in files), "over-cap blob not stored");
      // small files still copied
      assert(`blob/${shas.a}` in files);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "corpus: type-stamp — witnessed on missing / DRIFT / remote; replayable only when clean + present + local",
  ignore: !HAVE,
  fn: async () => {
    const check = async (opt: Parameters<typeof fixture>[0], want: string, why: string) => {
      const f = await fixture(opt);
      try {
        const { sink } = fakeSink();
        const { corpus: c } = await captureCorpus(f.org, "gdh", undefined, sink);
        assertEquals(c.typeStamp, want, why);
      } finally {
        await Deno.remove(f.org, { recursive: true });
      }
    };
    await check({}, "witnessed", "a checksummed artifact is missing (A6)");
    // drift alone MUST force witnessed even with everything present + local (adv-1)
    await check({ allPresent: true }, "witnessed", "A3 drifts (tamper evidence)");
    await check({ allPresent: true, remote: true }, "witnessed", "remote compute");
    // the ONLY replayable case: all present, local, and NO drift
    await check({ allPresent: true, noDrift: true }, "replayable", "clean + present + local");
  },
});

Deno.test({
  name: "corpus: source DB + files byte-unchanged; no user_secrets ciphertext leak; deterministic",
  ignore: !HAVE,
  fn: async () => {
    const { org } = await fixture();
    const orgDir = `${org}/orgs/org1`;
    try {
      const dbBefore = await sha256File(`${orgDir}/operon-cli.db`);
      const fileBefore = await sha256File(`${orgDir}/artifacts/proj_abc123/v1/a.py`);
      const a = fakeSink();
      const r1 = await captureCorpus(org, "gdh", undefined, a.sink);
      const b = fakeSink();
      const r2 = await captureCorpus(org, "gdh", undefined, b.sink);
      // non-mutation
      assertEquals(await sha256File(`${orgDir}/operon-cli.db`), dbBefore, "DB untouched");
      assertEquals(await sha256File(`${orgDir}/artifacts/proj_abc123/v1/a.py`), fileBefore, "artifact untouched");
      // no secret leak
      const blob = JSON.stringify(a.resources) +
        Object.values(a.files).map((f) => new TextDecoder().decode(f)).join("");
      assert(!blob.includes("SUPERSECRETCIPHERTEXT"), "credential ciphertext leaked");
      // determinism
      assertEquals(JSON.stringify(r1.corpus), JSON.stringify(r2.corpus), "two runs byte-identical");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "corpus: a per-file copy failure warns WITHOUT leaking an absolute org path (H1-class, portable record)",
  ignore: !HAVE,
  fn: async () => {
    const { org } = await fixture();
    const orgDir = `${org}/orgs/org1`;
    const blocked = `${orgDir}/workspaces/${R1}/handoff/w1.json`;
    await Deno.chmod(blocked, 0o000); // unreadable → copyFileToBlob throws on the per-file error path
    try {
      const { sink } = fakeSink();
      const { corpus: c } = await captureCorpus(org, "gdh", undefined, sink);
      // the failure is surfaced (root-relative) …
      assert(c.warnings.some((w) => /w1\.json.*degraded/.test(w)), "the failing file is warned");
      // … but NO absolute org path leaks into the sealed, PORTABLE record (org-relative only)
      assert(!JSON.stringify(c.warnings).includes(orgDir), "no abs org path in warnings (H1-class)");
      assert(!JSON.stringify(c).includes(org), "no abs path anywhere in the record");
    } finally {
      await Deno.chmod(blocked, 0o600).catch(() => {});
      await Deno.remove(org, { recursive: true });
    }
  },
});
