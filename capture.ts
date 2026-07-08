/**
 * @vcjdeboer/session-ingest — capture.ts
 *
 * `capture_messages`: the VERBATIM, typed, ordered message transcript of a
 * QUIESCENT Claude Science session. Hybrid storage (approach C): a `transcript`
 * INDEX resource + large text bodies / inline image bytes offloaded to
 * content-addressed (sha256) FILES.
 *
 * DECISIONS (settled through review):
 *  - VERBATIM: content is stored unchanged, so the transcript is deterministic
 *    and witness-sealable. A WARN-ONLY tripwire flags secret-shaped content
 *    WITHOUT mutating it; the `transcript`/`body`/`image` resources are marked
 *    sensitive (private bundle). Credentials never enter content (user_secrets is
 *    never read).
 *  - Reads a STATIC clone (db.ts cloneDb) — source never mutated, no live-WAL
 *    TOCTOU. Rows are cursored per frame (bounded memory).
 *  - Typing uses the SINGLE shared db.ts classifyTurn (no drift vs inspect).
 *  - Order is canonical + deterministic: frames by (created_at,id); turns by
 *    (idx,rowid); each turn carries frameId/parentFrameId/depth so consumers can
 *    reconstruct the tree (reviewer children nested, never interleaved/dropped).
 *  - Image→artifact resolution is DEFERRED to #31; here images are captured
 *    verbatim (metadata + inline bytes offloaded if present).
 * @module
 */
import { z } from "npm:zod@4";
import {
  assertQuiescent,
  classifyTurn,
  cloneDb,
  FRAME_ID_RE,
  preflightSqlite,
  PROJ_ID_RE,
  QUERIES,
  readClone,
  resolveOrgDir,
  type TurnKind,
} from "./db.ts";
import { makeStore, secretTripwire } from "./store.ts";

const BODY_INLINE_CAP = 2000; // chars; larger text offloads to a content-addressed file
const PAGE = 500; // per-frame row-cursor batch size

/* ---- schemas (declared so the transcript resource validates; bodyFileRef is a
   first-class field, not prose) ---- */
export const BlockSchema = z.object({
  type: z.enum(["text", "tool_use", "tool_result", "image"]),
  text: z.string().optional(),
  name: z.string().optional(),
  input: z.unknown().optional(),
  output: z.string().optional(),
  artifactRef: z.string().optional(), // image saved-artifact hint (resolution deferred to #31)
  bodyFileRef: z.string().optional(), // sha of an offloaded large text body
  imageFileRef: z.string().optional(), // sha of offloaded inline image bytes
}).passthrough();
export type Block = z.infer<typeof BlockSchema>;

export const TurnSchema = z.object({
  seq: z.number(),
  frameId: z.string(),
  parentFrameId: z.string().nullable(),
  depth: z.number(),
  orphan: z.boolean(),
  idx: z.number(),
  rowid: z.number(),
  uuid: z.string().nullable(),
  type: z.string(),
  role: z.string().nullable(),
  tokens: z.number().nullable(),
  blocks: z.array(BlockSchema),
  artifactRefs: z.array(z.string()),
});
export type Turn = z.infer<typeof TurnSchema>;

export const TranscriptSchema = z.object({
  sensitive: z.literal(true), // private bundle: contains verbatim conversation content
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  nTurns: z.number(),
  byType: z.record(z.string(), z.number()),
  writeManifest: z.array(z.string()), // shas of offloaded body/image files
  turns: z.array(TurnSchema),
  warnings: z.array(z.string()),
});
export type Transcript = z.infer<typeof TranscriptSchema>;

/** What capture needs from the model's execute context. */
export interface Sink {
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<{ version: number }>;
  createFileWriter: (
    spec: string,
    instance: string,
    overrides?: { contentType?: string },
  ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
  logger: { info: (msg: string, props?: Record<string, unknown>) => void };
}

/* ---- content normalization (verbatim) ---- */
type Offload = (text: string) => Promise<string>; // returns sha; registers the file
type Warn = (m: string) => void;

const tripwire = secretTripwire;

async function textBlock(
  type: "text" | "tool_result",
  text: string,
  offload: Offload,
  warn: Warn,
): Promise<Block> {
  tripwire(text, warn, type);
  const key = type === "text" ? "text" : "output";
  if (text.length > BODY_INLINE_CAP) {
    return { type, bodyFileRef: await offload(text) };
  }
  return { type, [key]: text } as Block;
}

/** tool_result content as a faithful, round-trippable string (structure preserved, not flattened). */
function toolResultText(b: Record<string, unknown>): string {
  const c = b.content;
  if (typeof c === "string") return c;
  return c == null ? "" : JSON.stringify(c);
}

async function imageBlock(
  b: Record<string, unknown>,
  offload: Offload,
): Promise<Block> {
  const src = b.source as Record<string, unknown> | undefined;
  const data = typeof src?.data === "string" ? src.data : undefined; // base64
  const artifactRef = typeof b.artifactRef === "string"
    ? b.artifactRef
    : (typeof b.version_id === "string" ? b.version_id : undefined);
  const blk: Block = { type: "image" };
  if (artifactRef) blk.artifactRef = artifactRef; // resolution deferred to #31
  if (data && data.length > BODY_INLINE_CAP) {
    blk.imageFileRef = await offload(data);
  } else if (data) {
    blk.text = data; // small inline image kept verbatim
  }
  return blk;
}

async function normalize(
  content: unknown,
  offload: Offload,
  warn: Warn,
): Promise<Block[]> {
  if (content == null) return [];
  if (typeof content === "string") {
    return [await textBlock("text", content, offload, warn)];
  }
  if (Array.isArray(content)) {
    const out: Block[] = [];
    for (const raw of content) {
      const b = raw as Record<string, unknown>;
      switch (b?.type) {
        case "text":
          out.push(
            await textBlock("text", String(b.text ?? ""), offload, warn),
          );
          break;
        case "tool_use": {
          const name = typeof b.name === "string" ? b.name : undefined;
          const inputStr = JSON.stringify(b.input ?? "");
          tripwire(inputStr, warn, "tool_use.input");
          // honor the offload cap for large inputs (full file contents / big JSON args)
          if (inputStr.length > BODY_INLINE_CAP) {
            out.push({
              type: "tool_use",
              name,
              bodyFileRef: await offload(inputStr),
            });
          } else {
            out.push({ type: "tool_use", name, input: b.input });
          }
          break;
        }
        case "tool_result":
          out.push(
            await textBlock("tool_result", toolResultText(b), offload, warn),
          );
          break;
        case "image":
          out.push(await imageBlock(b, offload));
          break;
        default:
          // unknown block preserved verbatim, capped + tripwired via textBlock
          out.push(await textBlock("text", JSON.stringify(b), offload, warn));
      }
    }
    return out;
  }
  return [{ type: "text", text: JSON.stringify(content) }];
}

/* ---- frame tree depth ---- */
function depthInfo(
  f: { id: string; parent_frame_id: string | null | undefined },
  byId: Map<string, { parent_frame_id: string | null | undefined }>,
): { depth: number; orphan: boolean } {
  let depth = 0;
  let cur: { parent_frame_id: string | null | undefined } | undefined = f;
  const seen = new Set<string>([f.id]);
  let orphan = false;
  while (cur?.parent_frame_id) {
    if (!byId.has(cur.parent_frame_id)) {
      orphan = true;
      break;
    } // parent not in project frame set
    if (seen.has(cur.parent_frame_id)) break; // cycle guard
    seen.add(cur.parent_frame_id);
    cur = byId.get(cur.parent_frame_id);
    depth++;
  }
  return { depth, orphan };
}

/* ---- the capture ---- */
export async function captureMessages(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: Sink,
): Promise<{ transcript: Transcript; dataHandles: unknown[] }> {
  const warnings: string[] = [];
  const warn: Warn = (m) => warnings.push(m);

  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  await assertQuiescent(dbPath);

  const { path: clone, cleanup } = await cloneDb(dbPath); // static copy; source never touched
  try {
    // resolve project — match in TS (no user input in SQL)
    const projects = (await readClone(clone, QUERIES.projects_all())) as Record<
      string,
      unknown
    >[];
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);
    const projName = (proj.name ?? null) as string | null;

    const frames = (await readClone(clone, QUERIES.frames_ordered(pid))) as {
      id: string;
      parent_frame_id: string | null | undefined;
    }[];
    const byId = new Map(frames.map((f) => [f.id, f]));

    // offloaded files, deduped by sha (content-addressed) — shared store primitive
    const store = makeStore();
    const offload: Offload = store.offload;

    const turns: Turn[] = [];
    const byType: Record<string, number> = {};
    let seq = 0;

    for (const f of frames) {
      if (!FRAME_ID_RE.test(f.id)) {
        warn(`skipping frame with non-UUID id: ${f.id}`);
        continue;
      }
      const { depth, orphan } = depthInfo(f, byId);
      try {
        let offset = 0;
        while (true) {
          const rows = (await readClone(
            clone,
            QUERIES.messages_by_frame(f.id, PAGE, offset),
          )) as { idx: number; rowid: number; msg_json: string }[];
          if (rows.length === 0) break;
          for (const r of rows) {
            const idx = Number(r.idx);
            const rowid = Number(r.rowid);
            let type: TurnKind = "unclassified";
            let role: string | null = null;
            let uuid: string | null = null;
            let tokens: number | null = null;
            let artifactRefs: string[] = [];
            let blocks: Block[] = [];
            try {
              const parsed = JSON.parse(String(r.msg_json)) as Record<
                string,
                unknown
              >;
              type = classifyTurn(parsed);
              role = (parsed.role ?? null) as string | null;
              uuid = (parsed._uuid ?? null) as string | null;
              tokens = typeof parsed._tokens === "number"
                ? parsed._tokens
                : null;
              artifactRefs = Array.isArray(parsed._artifact_refs)
                ? (parsed._artifact_refs as unknown[]).map(String)
                : [];
              blocks = await normalize(parsed.content, offload, warn);
            } catch (e) {
              warn(
                `malformed msg_json at frame ${f.id.slice(0, 8)} idx ${idx}: ${
                  e instanceof Error ? e.message : String(e)
                }`,
              );
            }
            byType[type] = (byType[type] ?? 0) + 1;
            turns.push({
              seq: seq++,
              frameId: f.id,
              parentFrameId: (f.parent_frame_id ?? null) as string | null,
              depth,
              orphan,
              idx,
              rowid,
              uuid,
              type,
              role,
              tokens,
              blocks,
              artifactRefs,
            });
          }
          if (rows.length < PAGE) break;
          offset += PAGE;
        }
      } catch (e) {
        warn(
          `frame ${f.id.slice(0, 8)} read degraded (skipped): ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
    }

    // WRITE PROTOCOL: files FIRST (content-addressed, idempotent), then the index.
    const writeManifest = await store.flush(sink);

    const transcript: Transcript = {
      sensitive: true,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: projName },
      },
      nTurns: turns.length,
      byType,
      writeManifest,
      turns,
      warnings,
    };
    const handle = await sink.writeResource("transcript", pid, transcript);
    sink.logger.info(`captured ${turns.length} turns for ${projName ?? pid}`, {
      project: pid,
      turns: turns.length,
      offloadedFiles: writeManifest.length,
      warnings: warnings.length,
    });
    return { transcript, dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
