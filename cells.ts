/**
 * @vcjdeboer/session-ingest — cells.ts
 *
 * `capture_cells`: freeze the FULL ordered execution sequence of a session — every
 * cell's source + language + cellIndex — as a `cells` resource. This is the replay
 * SCRIPT that complements the provenance GRAPH: `capture_provenance` keeps only the
 * artifact-linked graph nodes, dropping the setup/helper cells (which define
 * namespace globals a full replay needs). Reads a static scrubbed clone; source
 * never mutated. Large source offloads to content-addressed `body` blobs.
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
import { makeStore } from "./store.ts";

const BODY_INLINE_CAP = 2000; // chars; larger source offloads to a body blob

export const CellSchema = z.object({
  cellIndex: z.number().int(),
  language: z.string(),
  /** Inline source when small; empty when offloaded to `bodyRef`. */
  source: z.string().default(""),
  /** sha of the offloaded `body` blob when source is large; empty otherwise. */
  bodyRef: z.string().default(""),
});
export type Cell = z.infer<typeof CellSchema>;

export const CellsSchema = z.object({
  session: z.string(),
  cells: z.array(CellSchema).default([]),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  /** shas of offloaded `body` blobs. */
  writeManifest: z.array(z.string()).default([]),
});
export type Cells = z.infer<typeof CellsSchema>;

/** One raw execution_log row (id/cell_index/language/source). */
interface Row {
  cell_index?: unknown;
  language?: unknown;
  source?: unknown;
}

/**
 * Turn ordered execution_log rows into typed cells, offloading large source to
 * content-addressed blobs. Pure over `rows` + the injected `offload`; preserves
 * input order (the query orders by cell_index).
 */
export async function readCells(
  rows: Row[],
  offload: (text: string) => Promise<string>,
): Promise<{ cells: Cell[] }> {
  const cells: Cell[] = [];
  for (const r of rows) {
    const source = String(r.source ?? "");
    const cell: Cell = {
      cellIndex: Number(r.cell_index) || 0,
      language: String(r.language ?? ""),
      source: "",
      bodyRef: "",
    };
    if (source.length > BODY_INLINE_CAP) cell.bodyRef = await offload(source);
    else cell.source = source;
    cells.push(cell);
  }
  return { cells };
}

interface CellsSink {
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  createFileWriter: (
    s: string,
    i: string,
    o?: { contentType?: string },
  ) => { writeAll: (b: Uint8Array) => Promise<unknown> };
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/**
 * Capture the full ordered cell sequence into a `cells` resource (+ body blobs).
 * Mirrors capture_provenance's read discipline: preflight, quiescence, static
 * scrubbed clone, project resolved in TS (no user input in SQL).
 */
export async function captureCells(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: CellsSink,
): Promise<{ dataHandles: unknown[] }> {
  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  try {
    await Deno.stat(dbPath);
  } catch {
    throw new Error(`operon-cli.db not found at ${dbPath}`);
  }
  await assertQuiescent(dbPath);
  sink.logger.info("capture_cells start", { project: projectArg, org });

  const { path: clone, cleanup } = await cloneDb(dbPath);
  const store = makeStore();
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

    const rows =
      (await readClone(clone, QUERIES.cells_by_project(pid))) as Row[];
    const { cells } = await readCells(rows, (t) => store.offload(t));
    const writeManifest = await store.flush(sink);

    const record: Cells = {
      session: pid,
      cells,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: (proj.name ?? null) as string | null },
      },
      writeManifest,
    };
    const handle = await sink.writeResource("cells", pid, record);
    sink.logger.info("capture_cells done", {
      cells: cells.length,
      offloaded: writeManifest.length,
    });
    return { dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
