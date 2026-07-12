/**
 * @vcjdeboer/session-ingest — extras.ts
 *
 * `capture_extras`: freeze the remaining lower-frequency CS metadata tables into
 * one SENSITIVE `extras` resource so nothing a session recorded is silently
 * dropped:
 *   - `compute_usage`   — remote GPU/CPU jobs (environment provenance for offloaded work)
 *   - `session_claims`  — falsifiable claims extracted (incl. UNCHECKED ones, which
 *                         `verification_checks` / capture_review omits)
 *   - `memories`        — durable agent beliefs scoped to this project
 *   - `artifact_folders`— artifact folder organization (structure only)
 *
 * Each table is read under its own guard: a table absent on this build degrades
 * to an empty list + a warning, never a failed capture. Rows are stored verbatim
 * (already scoped, non-secret metadata; claims/memories prose is SENSITIVE).
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

type Row = Record<string, unknown>;

export const ExtrasSchema = z.object({
  sensitive: z.literal(true),
  session: z.string(),
  counts: z.record(z.string(), z.number()),
  compute: z.array(z.record(z.string(), z.unknown())).default([]),
  claims: z.array(z.record(z.string(), z.unknown())).default([]),
  memories: z.array(z.record(z.string(), z.unknown())).default([]),
  folders: z.array(z.record(z.string(), z.unknown())).default([]),
  warnings: z.array(z.string()).default([]),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
});
export type Extras = z.infer<typeof ExtrasSchema>;

interface ExtrasSink {
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** Read a query under a guard — a missing table (or any read error) degrades to []. Pure-ish. */
async function guardedRead(
  clone: string,
  label: string,
  sql: string,
  warnings: string[],
): Promise<Row[]> {
  try {
    return (await readClone(clone, sql)) as Row[];
  } catch (e) {
    warnings.push(
      `${label}: unavailable (${e instanceof Error ? e.message : String(e)})`,
    );
    return [];
  }
}

/** Capture the lower-frequency metadata tables into one SENSITIVE `extras` resource. */
export async function captureExtras(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: ExtrasSink,
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

    const warnings: string[] = [];
    const compute = await guardedRead(
      clone,
      "compute_usage",
      QUERIES.compute_usage_by_project(pid),
      warnings,
    );
    const claims = await guardedRead(
      clone,
      "session_claims",
      QUERIES.session_claims_by_project(pid),
      warnings,
    );
    const memories = await guardedRead(
      clone,
      "memories",
      QUERIES.memories_by_project(pid),
      warnings,
    );
    const folders = await guardedRead(
      clone,
      "artifact_folders",
      QUERIES.artifact_folders_by_project(pid),
      warnings,
    );

    const counts = {
      compute: compute.length,
      claims: claims.length,
      memories: memories.length,
      folders: folders.length,
    };
    const record: Extras = {
      sensitive: true,
      session: pid,
      counts,
      compute,
      claims,
      memories,
      folders,
      warnings,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: (proj.name ?? null) as string | null },
      },
    };
    ExtrasSchema.parse(record);
    const handle = await sink.writeResource("extras", pid, record);
    sink.logger.info("capture_extras done", {
      counts,
      warnings: warnings.length,
    });
    return { dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
