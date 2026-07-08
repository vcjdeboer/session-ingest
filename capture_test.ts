/**
 * Tests for @vcjdeboer/session-ingest capture.ts (capture_messages).
 * Skip-guarded on sqlite3. Builds its own fixture DB; never touches real CS data.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { captureMessages, type Sink, type Transcript } from "./capture.ts";
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
  const sink: Sink = {
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
const REV = "aaaaaaaa-2222-4222-8222-222222222222";
const UPL = "cccccccc-3333-4333-8333-333333333333";
const ORPHAN = "dddddddd-4444-4444-8444-444444444444";
const BIG = "X".repeat(3000); // > BODY_INLINE_CAP (2000)
const SECRET = "config token sk-ABCDEFGHIJKLMNOPQRSTUVWX done";

async function fixture(): Promise<string> {
  const orgDir = await Deno.makeTempDir({ prefix: "cap-fixture-" });
  await Deno.mkdir(`${orgDir}/orgs/org1`, { recursive: true });
  const db = `${orgDir}/orgs/org1/operon-cli.db`;
  await sqlite(
    db,
    `PRAGMA journal_mode=WAL;
     CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
     INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL);
     CREATE TABLE frames (id TEXT,parent_frame_id TEXT,agent_name TEXT,created_at INT,project_id TEXT);
     INSERT INTO frames VALUES
       ('${UPL}',NULL,'UPLOADS',0,'proj_abc123'),
       ('${ROOT}',NULL,'OPERON',1,'proj_abc123'),
       ('${REV}','${ROOT}','REVIEWER',2,'proj_abc123'),
       ('${ORPHAN}','nonexistent-parent-uuid-000000000000','OPERON',3,'proj_abc123');
     CREATE TABLE frame_messages (frame_id TEXT,idx INT,msg_json TEXT);
     INSERT INTO frame_messages VALUES
       ('${ROOT}',0,'{"role":"user","_intent_id":"i1","content":"tell me"}'),
       ('${ROOT}',1,'{"role":"assistant","content":[{"type":"text","text":"analysis"},{"type":"tool_use","name":"bash","input":{"cmd":"ls"}}]}'),
       ('${ROOT}',1,'{"role":"assistant","content":"second turn at same idx"}'),
       ('${ROOT}',2,'{"role":"user","content":[{"type":"tool_result","content":"tool output here"}]}'),
       ('${ROOT}',3,'{"role":"assistant","content":"${BIG}"}'),
       ('${ROOT}',4,'{"role":"assistant","content":"${SECRET}"}'),
       ('${ROOT}',5,'{"role":"assistant","content":[{"type":"tool_use","name":"write","input":{"data":"${BIG}"}}]}'),
       ('${REV}',0,'{"role":"user","_harness_prompt":"rev","content":"You are reviewing"}'),
       ('${UPL}',0,'{"role":"user","content":[{"type":"text","text":"uploaded file note"}]}'),
       ('${ORPHAN}',0,'{"role":"assistant","content":"orphan turn"}');
     CREATE TABLE user_secrets (id TEXT,provider TEXT,encrypted_value TEXT);
     INSERT INTO user_secrets VALUES ('s1','openalex','SUPERSECRETCIPHERTEXT_MUST_NOT_APPEAR');`,
  );
  return orgDir;
}

async function md5(p: string): Promise<string> {
  const h = await crypto.subtle.digest("SHA-256", await Deno.readFile(p));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.test({
  name: "capture: coverage, typing, canonical order, orphan",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, resources } = fakeSink();
      const { transcript } = await captureMessages(org, "gdh", undefined, sink);
      const t = resources["transcript/proj_abc123"] as Transcript;
      assert(t, "transcript resource written under proj_abc123");
      assertEquals(t.nTurns, 10);
      // every frame's messages captured (coverage: UPLOADS + orphan included)
      const frameIds = new Set(t.turns.map((x) => x.frameId));
      for (const f of [ROOT, REV, UPL, ORPHAN]) assert(frameIds.has(f), `missing frame ${f}`);
      // typing reconciles
      assertEquals(t.byType, { userTyped: 1, assistant: 6, toolResults: 2, harnessInjected: 1 });
      // canonical order: seq monotonic; frames by created_at (UPL0, ROOT1, REV2, ORPHAN3)
      assertEquals(t.turns.map((x) => x.seq), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
      assertEquals(t.turns[0].frameId, UPL);
      assertEquals(t.turns[t.turns.length - 1].frameId, ORPHAN);
      // duplicate idx within ROOT resolved by rowid (two idx=1 turns, both present, in insert order)
      const rootIdx1 = t.turns.filter((x) => x.frameId === ROOT && x.idx === 1);
      assertEquals(rootIdx1.length, 2);
      assert(rootIdx1[0].rowid < rootIdx1[1].rowid, "duplicate idx ordered by rowid");
      // orphan flagged, not dropped
      assertEquals(t.turns.find((x) => x.frameId === ORPHAN)?.orphan, true);
      assertEquals(t.turns.find((x) => x.frameId === REV)?.depth, 1);
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "capture: VERBATIM + warn-only tripwire (no mutation)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      const { transcript: t } = await captureMessages(org, "gdh", undefined, sink);
      // the secret-shaped turn is stored UNCHANGED (verbatim)
      const secretTurn = t.turns.find((x) => x.blocks.some((b) => b.text?.includes("sk-ABCDEFGHIJKLMNOPQRSTUVWX")));
      assert(secretTurn, "secret text captured verbatim, unredacted");
      // and the tripwire WARNED without mutating
      assert(t.warnings.some((w) => /secret-shaped/.test(w)), "tripwire should warn");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "capture: large body offloaded to a content-addressed file; index references it",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, files } = fakeSink();
      const { transcript: t } = await captureMessages(org, "gdh", undefined, sink);
      const bigTurn = t.turns.find((x) => x.blocks.some((b) => b.bodyFileRef));
      assert(bigTurn, "a large body should be offloaded");
      const ref = bigTurn.blocks.find((b) => b.bodyFileRef)!.bodyFileRef!;
      assert(bigTurn.blocks.every((b) => !b.text || b.text.length <= 2000), "offloaded body not inline");
      assert(t.writeManifest.includes(ref), "writeManifest lists the sha");
      const file = files[`body/${ref}`];
      assert(file, "body file was written (files-first)");
      assertEquals(new TextDecoder().decode(file), BIG, "offloaded file holds the verbatim body");
      // large tool_use.input offloaded (ca-3); small one stays inline
      const toolUses = t.turns.flatMap((x) => x.blocks).filter((b) => b.type === "tool_use");
      assert(toolUses.some((b) => b.bodyFileRef && b.input === undefined), "large tool_use.input offloaded");
      assert(toolUses.some((b) => b.input !== undefined && !b.bodyFileRef), "small tool_use.input inline");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "capture: idempotent re-run (same shas, no orphan) + source non-mutation",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    const db = `${org}/orgs/org1/operon-cli.db`;
    try {
      const before = await md5(db);
      const a = fakeSink();
      const r1 = await captureMessages(org, "gdh", undefined, a.sink);
      const b = fakeSink();
      const r2 = await captureMessages(org, "gdh", undefined, b.sink);
      assertEquals(r1.transcript.writeManifest.sort(), r2.transcript.writeManifest.sort());
      assertEquals(Object.keys(a.files).sort(), Object.keys(b.files).sort());
      assertEquals(await md5(db), before, "source DB must be untouched by capture");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "capture: never reads user_secrets (no ciphertext anywhere)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, resources, files } = fakeSink();
      await captureMessages(org, "gdh", undefined, sink);
      const blob = JSON.stringify(resources) +
        Object.values(files).map((f) => new TextDecoder().decode(f)).join("");
      assert(!blob.includes("SUPERSECRETCIPHERTEXT_MUST_NOT_APPEAR"), "credential ciphertext leaked");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});
