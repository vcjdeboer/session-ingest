/**
 * Tests for @vcjdeboer/session-ingest provenance.ts (capture_provenance).
 * Skip-guarded on sqlite3. Builds its own fixture DB; never touches real CS data.
 *
 * Reconstructs the turn->execution->artifact->env graph. The CELL node is
 * COLLAPSED into EXECUTION (canonical node = execution_log keyed by id).
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  captureProvenance,
  type Provenance,
  type ProvSink,
} from "./provenance.ts";
import { preflightSqlite } from "./db.ts";

const HAVE = (await preflightSqlite()).ok;

async function sqlite(db: string, sql: string): Promise<void> {
  const out = await new Deno.Command("sqlite3", { args: [db, sql] }).output();
  if (!out.success) throw new Error(new TextDecoder().decode(out.stderr));
}

function fakeSink() {
  const resources: Record<string, unknown> = {};
  const files: Record<string, Uint8Array> = {};
  const logs: { msg: string; props?: Record<string, unknown> }[] = [];
  const sink: ProvSink = {
    writeResource: (spec, inst, data) => {
      resources[`${spec}/${inst}`] = data;
      return Promise.resolve({ version: 1 });
    },
    createFileWriter: (spec, inst) => ({
      writeAll: (c: Uint8Array) => {
        files[`${spec}/${inst}`] = c;
        return Promise.resolve({});
      },
    }),
    logger: { info: (msg, props) => logs.push({ msg, props }) },
  };
  return { sink, resources, files, logs };
}

const ROOT = "6b2bd51d-1111-4111-8111-111111111111";
const EXEC = "eeeeeeee-2222-4222-8222-222222222222";
const ARTV1 = "a1a1a1a1-1111-4111-8111-111111111111";
const ARTV2 = "a2a2a2a2-2222-4222-8222-222222222222";
const DEP0 = "a0a0a0a0-0000-4000-8000-000000000000"; // dependency_mappings target (outside node set)
const ENVH = "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01"; // 64 hex
const CHK1 = "1".repeat(64);
const CHK2 = "2".repeat(64);
const BIG = "S".repeat(3000); // > BODY_INLINE_CAP (2000) — offloads
// a large env snapshot so packages offload
const PKGS = Array.from({ length: 120 }, (_, i) => `{"name":"biopython${i}","version":"1.${i}","channel":"bioconda"}`).join(",");
const ENV_CONTENT = `{"environment_name":"python","packages":[${PKGS}]}`;

interface FixtureOpts {
  badIds?: boolean; // producing_cell_id / env_snapshot_hash not UUID/hash
  missingRows?: boolean; // producing_cell_id + env hash reference absent rows
  malformedDeps?: boolean; // dependency_mappings is not JSON
  objectFiles?: boolean; // files_written/read as CS descriptors {path,sha256} (real shape)
}

const WROTE_PATH = "/w/out/fig1.png";
const READ_PATH = "/w/in/data.csv";

async function fixture(opts: FixtureOpts = {}): Promise<string> {
  const orgDir = await Deno.makeTempDir({ prefix: "prov-fixture-" });
  await Deno.mkdir(`${orgDir}/orgs/org1`, { recursive: true });
  const db = `${orgDir}/orgs/org1/operon-cli.db`;
  const producing = opts.badIds
    ? "not-a-uuid"
    : (opts.missingRows ? "ffffffff-9999-4999-8999-999999999999" : EXEC);
  const envHash = opts.badIds
    ? "NOTAHASH"
    : (opts.missingRows ? "0".repeat(64) : ENVH);
  const deps = opts.malformedDeps
    ? "this is not json"
    : `{"inputs":[{"workspace_path":"/w/a1.py","filename":"a1.py","artifact_id":"${DEP0}"}]}`;
  const filesWritten = opts.objectFiles
    ? `[{"path":"${WROTE_PATH}","sha256":"${CHK2}","preview_content_type":"image/jpeg"}]`
    : `["${ARTV2}"]`;
  const filesRead = opts.objectFiles ? `[{"path":"${READ_PATH}"}]` : `["${ARTV1}"]`;
  await sqlite(
    db,
    `PRAGMA journal_mode=WAL;
     CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
     INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL);
     CREATE TABLE frames (id TEXT,parent_frame_id TEXT,agent_name TEXT,created_at INT,project_id TEXT);
     INSERT INTO frames VALUES ('${ROOT}',NULL,'OPERON',1,'proj_abc123');
     CREATE TABLE frame_messages (frame_id TEXT,idx INT,msg_json TEXT);
     INSERT INTO frame_messages VALUES
       ('${ROOT}',0,'{"role":"assistant","content":"made a2","_artifact_refs":{"a2.py":{"artifact_id":"A2","version_id":"${ARTV2}"}}}'),
       ('${ROOT}',1,'{"role":"user","_intent_id":"i1","content":"go"}');
     CREATE TABLE artifact_versions (
       id TEXT,artifact_id TEXT,version_number INT,producing_cell_id TEXT,frame_id TEXT,
       checksum TEXT,storage_path TEXT,language TEXT,is_intermediate INT,env_snapshot_hash TEXT,
       parent_version_id TEXT,dependency_mappings TEXT,created_at INT);
     INSERT INTO artifact_versions VALUES
       ('${ARTV1}','A1',1,NULL,'${ROOT}','${CHK1}','proj_abc123/a1.py','python',1,'${envHash}',NULL,NULL,1),
       ('${ARTV2}','A2',1,'${producing}','${ROOT}','${CHK2}','proj_abc123/a2.py','python',0,'${envHash}','${ARTV1}','${deps}',2);
     CREATE TABLE execution_log (
       id TEXT,frame_id TEXT,cell_index INT,kernel_id TEXT,conda_env TEXT,language TEXT,
       source TEXT,stdout TEXT,stderr TEXT,exit_status INT,error_lineno INT,
       files_written TEXT,files_read TEXT,origin TEXT);
     INSERT INTO execution_log VALUES
       ('${EXEC}','${ROOT}',0,'k1','python','python','${BIG}','ok','',0,NULL,'${filesWritten}','${filesRead}','local');
     CREATE TABLE content_snapshots (hash TEXT,content TEXT,size_bytes INT);
     INSERT INTO content_snapshots VALUES ('${ENVH}','${ENV_CONTENT}',${ENV_CONTENT.length});
     CREATE TABLE user_secrets (id TEXT,provider TEXT,encrypted_value TEXT);
     INSERT INTO user_secrets VALUES ('s1','openalex','SUPERSECRETCIPHERTEXT_MUST_NOT_APPEAR');`,
  );
  return orgDir;
}

async function sha256File(p: string): Promise<string> {
  const h = await crypto.subtle.digest("SHA-256", await Deno.readFile(p));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const edgeKinds = (p: Provenance) => new Set(p.edges.map((e) => e.kind));
const hasEdge = (p: Provenance, from: string, to: string, kind: string) =>
  p.edges.some((e) => e.from === from && e.to === to && e.kind === kind);

Deno.test({
  name: "provenance: nodes (cell collapsed into execution) + all edge kinds",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, resources } = fakeSink();
      const { provenance: p } = await captureProvenance(org, "gdh", undefined, sink);
      assertEquals(resources["provenance/proj_abc123"], p);

      // nodes: two artifacts, one execution (cell collapsed, keyed by execution_log.id), one env
      assertEquals(p.nodes.artifacts.map((a) => a.id).sort(), [ARTV1, ARTV2].sort());
      assertEquals(p.nodes.executions.map((e) => e.id), [EXEC]);
      assertEquals(p.nodes.envs.map((e) => e.id), [ENVH]);

      // ALL edge kinds present + correct
      assertEquals(
        edgeKinds(p),
        new Set(["produces", "producedBy", "wrote", "read", "inEnv", "ranInEnv", "dependsOn"]),
      );
      assert(hasEdge(p, ROOT, ARTV2, "produces"), "turn->artifact via _artifact_refs.version_id");
      assert(hasEdge(p, ARTV2, EXEC, "producedBy"), "artifact->execution via producing_cell_id");
      assert(hasEdge(p, EXEC, ARTV2, "wrote"), "execution->file via files_written");
      assert(hasEdge(p, EXEC, ARTV1, "read"), "execution->file via files_read");
      assert(hasEdge(p, ARTV1, ENVH, "inEnv"), "artifact->env via env_snapshot_hash");
      assert(hasEdge(p, ARTV2, ENVH, "inEnv"), "artifact->env via env_snapshot_hash");
      assert(hasEdge(p, EXEC, "python", "ranInEnv"), "execution->env via conda_env (name; drift-exposing)");
      // dependsOn from BOTH parent_version_id and dependency_mappings.inputs[].artifact_id
      assert(hasEdge(p, ARTV2, ARTV1, "dependsOn"), "dependsOn via parent_version_id");
      assert(hasEdge(p, ARTV2, DEP0, "dependsOn"), "dependsOn via dependency_mappings.artifact_id");

      // env packages captured
      const env = p.nodes.envs[0];
      assertEquals(env.environmentName, "python");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "provenance: wrote/read edges resolve CS file DESCRIPTORS {path,sha256} to the path (never [object Object])",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture({ objectFiles: true });
    try {
      const { sink } = fakeSink();
      const { provenance: p } = await captureProvenance(org, "gdh", undefined, sink);
      assert(hasEdge(p, EXEC, WROTE_PATH, "wrote"), "wrote edge targets the descriptor path");
      assert(hasEdge(p, EXEC, READ_PATH, "read"), "read edge targets the descriptor path");
      assert(
        !p.edges.some((e) => e.to.includes("[object Object]")),
        "no edge target was stringified from an object",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "provenance: large source + env packages offloaded to content-addressed files (verbatim)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, files } = fakeSink();
      const { provenance: p } = await captureProvenance(org, "gdh", undefined, sink);
      // execution source offloaded
      const exec = p.nodes.executions[0];
      assert(exec.sourceFileRef, "large source offloaded");
      assert(!exec.source, "offloaded source not inline");
      assert(p.writeManifest.includes(exec.sourceFileRef!), "manifest lists the source sha");
      assertEquals(new TextDecoder().decode(files[`body/${exec.sourceFileRef}`]), BIG);
      // env packages offloaded (large list)
      const env = p.nodes.envs[0];
      assert(env.packagesFileRef, "large env packages offloaded");
      assert(p.writeManifest.includes(env.packagesFileRef!), "manifest lists the env sha");
      assert(
        new TextDecoder().decode(files[`body/${env.packagesFileRef}`]).includes("biopython0"),
        "offloaded env body holds verbatim packages",
      );
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "provenance: deterministic node/edge order across two runs",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const a = fakeSink();
      const r1 = await captureProvenance(org, "gdh", undefined, a.sink);
      const b = fakeSink();
      const r2 = await captureProvenance(org, "gdh", undefined, b.sink);
      assertEquals(JSON.stringify(r1.provenance), JSON.stringify(r2.provenance));
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "provenance: non-mutation — source .db/-wal untouched",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      const before = await sha256File(db);
      const { sink } = fakeSink();
      await captureProvenance(org, "gdh", undefined, sink);
      assertEquals(await sha256File(db), before, "source DB must be untouched");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "provenance: injection gates skip a bad producing_cell_id / env hash (warn, not inject)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture({ badIds: true });
    try {
      const { sink } = fakeSink();
      const { provenance: p } = await captureProvenance(org, "gdh", undefined, sink);
      // no execution node (producing_cell_id failed FRAME_ID_RE), no env node (hash failed HASH_RE)
      assertEquals(p.nodes.executions.length, 0);
      assertEquals(p.nodes.envs.length, 0);
      assert(!p.edges.some((e) => e.kind === "producedBy"), "no producedBy for a bad id");
      assert(!p.edges.some((e) => e.kind === "inEnv"), "no inEnv for a bad hash");
      assert(p.warnings.some((w) => /producing_cell_id|frame id|FRAME_ID/i.test(w)));
      assert(p.warnings.some((w) => /hash|HASH/i.test(w)));
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "provenance: drift — missing rows + malformed dependency_mappings degrade+warn (no throw)",
  ignore: !HAVE,
  fn: async () => {
    // missing execution_log + content_snapshots rows
    let org = await fixture({ missingRows: true });
    try {
      const { sink } = fakeSink();
      const { provenance: p } = await captureProvenance(org, "gdh", undefined, sink);
      assertEquals(p.nodes.executions.length, 0, "absent execution_log row -> no node");
      assertEquals(p.nodes.envs.length, 0, "absent content_snapshots row -> no node");
      assert(p.warnings.length > 0, "drift warns");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
    // malformed dependency_mappings
    org = await fixture({ malformedDeps: true });
    try {
      const { sink } = fakeSink();
      const { provenance: p } = await captureProvenance(org, "gdh", undefined, sink);
      // parent_version_id dependsOn still emitted; the malformed inputs degrade
      assert(hasEdge(p, ARTV2, ARTV1, "dependsOn"), "parent backbone survives malformed deps");
      assert(p.warnings.some((w) => /dependency_mappings/i.test(w)));
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "provenance: never reads user_secrets (no ciphertext anywhere)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, resources, files } = fakeSink();
      await captureProvenance(org, "gdh", undefined, sink);
      const blob = JSON.stringify(resources) +
        Object.values(files).map((f) => new TextDecoder().decode(f)).join("");
      assert(!blob.includes("SUPERSECRETCIPHERTEXT_MUST_NOT_APPEAR"), "credential ciphertext leaked");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});
