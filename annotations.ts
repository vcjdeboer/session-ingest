/**
 * @vcjdeboer/session-ingest — annotations.ts
 *
 * `capture_annotations`: freeze the user's own marks on a session — artifact
 * COMMENTS and thread BOOKMARKS/highlights (CS's `transcript_annotations`) into a
 * SENSITIVE `annotations` resource. Each carries its kind (comment/bookmark/…),
 * what it anchors to (message, offsets, or a tool artifact), the note text, who
 * made it, and when. anchor_text/note are user prose — never a credential.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  assertQuiescent,
  cloneDb,
  preflightSqlite,
  PROJ_ID_RE,
  QUERIES,
  readClone,
  resolveOrgDir,
} from "./db.ts";

export const AnnotationSchema = z.object({
  kind: z.string(), // bookmark | comment | highlight | …
  source: z.string().default(""), // user | assistant | tool
  toolName: z.string().nullable().default(null),
  messageUuid: z.string().nullable().default(null),
  messageIndex: z.number().nullable().default(null),
  blockIndex: z.number().nullable().default(null),
  anchorText: z.string().default(""),
  startOffset: z.number().nullable().default(null),
  endOffset: z.number().nullable().default(null),
  note: z.string().default(""),
  origin: z.string().default("user"),
  createdAt: z.number().nullable().default(null),
  updatedAt: z.number().nullable().default(null),
});
export type Annotation = z.infer<typeof AnnotationSchema>;

export const AnnotationsSchema = z.object({
  sensitive: z.literal(true),
  session: z.string(),
  total: z.number(),
  byKind: z.record(z.string(), z.number()),
  annotations: z.array(AnnotationSchema).default([]),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
});
export type Annotations = z.infer<typeof AnnotationsSchema>;

interface RawRow {
  kind?: unknown;
  source?: unknown;
  tool_name?: unknown;
  message_uuid?: unknown;
  message_index?: unknown;
  block_index?: unknown;
  anchor_text?: unknown;
  start_offset?: unknown;
  end_offset?: unknown;
  note?: unknown;
  origin?: unknown;
  created_at?: unknown;
  updated_at?: unknown;
}

const num = (v: unknown): number | null =>
  v == null || v === "" ? null : Number(v);
const str = (v: unknown, d = ""): string => (v == null ? d : String(v));

/** Shape raw transcript_annotations rows into the sealed annotations + a kind tally. Pure. */
export function buildAnnotations(
  rows: RawRow[],
): { annotations: Annotation[]; byKind: Record<string, number> } {
  const annotations: Annotation[] = [];
  const byKind: Record<string, number> = {};
  for (const r of rows) {
    const kind = str(r.kind);
    byKind[kind] = (byKind[kind] ?? 0) + 1;
    annotations.push({
      kind,
      source: str(r.source),
      toolName: r.tool_name == null ? null : String(r.tool_name),
      messageUuid: r.message_uuid == null ? null : String(r.message_uuid),
      messageIndex: num(r.message_index),
      blockIndex: num(r.block_index),
      anchorText: str(r.anchor_text),
      startOffset: num(r.start_offset),
      endOffset: num(r.end_offset),
      note: str(r.note),
      origin: str(r.origin, "user"),
      createdAt: num(r.created_at),
      updatedAt: num(r.updated_at),
    });
  }
  return { annotations, byKind };
}

interface AnnotationsSink {
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** Capture the project's user annotations (comments + bookmarks) into an `annotations` resource. */
export async function captureAnnotations(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: AnnotationsSink,
): Promise<{ dataHandles: unknown[] }> {
  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  await assertQuiescent(dbPath);
  const { path: clone, cleanup } = await cloneDb(dbPath);
  try {
    const projects = (await readClone(clone, QUERIES.projects_all())) as Array<
      { id?: unknown; name?: unknown }
    >;
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);

    const rows = (await readClone(
      clone,
      QUERIES.annotations(pid),
    )) as RawRow[];
    const { annotations, byKind } = buildAnnotations(rows);

    const record: Annotations = {
      sensitive: true,
      session: pid,
      total: annotations.length,
      byKind,
      annotations,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: (proj.name ?? null) as string | null },
      },
    };
    AnnotationsSchema.parse(record);
    const handle = await sink.writeResource("annotations", pid, record);
    sink.logger.info("capture_annotations done", {
      total: annotations.length,
      byKind,
    });
    return { dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
