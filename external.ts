/**
 * @vcjdeboer/session-ingest — external.ts
 *
 * `capture_external` (doc-2 gap-3 INVENTORY): aggregate THIS project's
 * `host_call_log` into a per-external-source manifest — COUNTS + metadata ONLY,
 * call content NEVER persisted.
 *
 * SECRET EXCLUSION IS STRUCTURAL (at the SQL layer, not by TS discipline): the
 * registry query `host_calls_by_project` extracts the MCP server via
 * `json_extract(args_json,'$[0]')` ONLY for method='mcp' AND ONLY when
 * `json_valid(args_json)` (json_extract aborts the whole statement on malformed
 * JSON — the guard degrades a bad row to a NULL server, not a failed capture),
 * and NEVER selects raw `args_json[1+]` / `data_inline` / `data_ref` / `error`
 * (error → an `is_error` boolean). `credentials_request` / `get_user_email` are
 * counted by method name, never parsed. The extracted server is further shape-
 * validated (a structured/plaintext `$[0]` under schema drift → `mcp:unrecognized`,
 * never emitted raw) and tripwired as defense-in-depth.
 *
 * SCOPE HONESTY: this is gap-3 INVENTORY (sources touched + access dates + call
 * counts), NOT closure — the app-surface Network allowlist (Source B) and real
 * per-source release-pin CLOSURE are deferred follow-ups. `releasePin` is a
 * fillable per-mcp-source slot (always null at capture) so the gap is closable.
 *
 * Read-only over a scrubbed static clone; deterministic (ORDER BY + sorted keys);
 * SENSITIVE resource. `host_grants` is snapshotted as a correctly-labeled
 * filesystem-mount table (user/org-wide, host_path DROPPED, NOT a network allowlist).
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
import { secretTripwire } from "./store.ts";

/** A well-formed MCP server name — bounds the source keyspace so a drifted/structured
 * args_json[0] can never become a raw source key. The real servers (pubmed, opentargets,
 * structures-interactions, human-genetics, mcp-omics-archives, genes-ontologies, …) all match. */
const SERVER_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/* ============================ schema ============================ */
export const SourceEntry = z.object({
  source: z.string(),
  kind: z.enum(["mcp", "method"]),
  callCount: z.number(),
  totalBytes: z.number(),
  firstAt: z.number(),
  lastAt: z.number(),
  errorCount: z.number(),
  /** Fillable per-source release/version slot — ONLY on kind:'mcp' (external services that
   * have a pinnable release). Always null at capture; a governed edit closes gap 3 per source. */
  releasePin: z.string().nullable().optional(),
});
export const MountGrant = z.object({
  mountName: z.string(),
  mode: z.string(),
  userId: z.string(),
  // host_path is DELIBERATELY absent — an absolute fs path must not enter a portable record.
});
export const ExternalSchema = z.object({
  sensitive: z.literal(true),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  /** Per external source (an MCP server, or an internal method), sorted by source key. */
  sources: z.array(SourceEntry),
  /** Filesystem mount grants — user/org-wide, identical across projects, NOT a network allowlist. */
  filesystemMountGrants: z.array(MountGrant),
  totals: z.object({
    calls: z.number(),
    sources: z.number(),
    bytes: z.number(),
    /** Global method histogram (sorted keys) — the one useful breakdown counts-only allows. */
    byMethod: z.record(z.string(), z.number()),
    /** Host calls attributable to NO project (invariant tripwire; 0 in a healthy DB). */
    orphanCallCount: z.number(),
    secretShapedCount: z.number(),
  }),
  warnings: z.array(z.string()),
});
export type External = z.infer<typeof ExternalSchema>;

/** What capture_external needs from the model's execute context (DB-only — no file writers). */
export interface ExternalSink {
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (msg: string, props?: Record<string, unknown>) => void };
}

type Row = Record<string, unknown>;
type Warn = (m: string) => void;
/** Path-safe error label — never let a Deno/sqlite error's absolute path enter the record. */
const errName = (e: unknown): string => (e instanceof Error ? e.name : "error");

/* ============================ the capture ============================ */
export async function captureExternal(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: ExternalSink,
): Promise<{ external: External; dataHandles: unknown[] }> {
  const warnings: string[] = [];
  const warn: Warn = (m) => warnings.push(m);

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
  sink.logger.info("capture_external start", { project: projectArg, org });

  const { path: clone, cleanup } = await cloneDb(dbPath); // static scrubbed copy; source never touched
  try {
    // resolve project OFF THE CLONE (single static copy; no second live-DB open)
    const projects = (await readClone(clone, QUERIES.projects_all())) as Row[];
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);
    const projName = (proj.name ?? null) as string | null;

    // ---- host calls (scoped to this project's executions) — degrade+warn on schema drift ----
    let rows: Row[] = [];
    try {
      rows =
        (await readClone(clone, QUERIES.host_calls_by_project(pid))) as Row[];
    } catch (e) {
      warn(`host_calls degraded: ${errName(e)}`);
    }
    type Agg = {
      kind: "mcp" | "method";
      callCount: number;
      totalBytes: number;
      firstAt: number;
      lastAt: number;
      errorCount: number;
    };
    const bySource = new Map<string, Agg>();
    const byMethod = new Map<string, number>();
    let secretShapedCount = 0;

    for (const r of rows) {
      const method = String(r.method);
      byMethod.set(method, (byMethod.get(method) ?? 0) + 1);

      let key: string;
      let kind: "mcp" | "method";
      if (method === "mcp") {
        kind = "mcp";
        const server = r.mcp_server;
        if (server === null || server === undefined) {
          key = "mcp:malformed"; // json_valid=0 or non-array args_json → server is NULL
          warn(
            "an mcp call has malformed/missing args_json[0] — bucketed mcp:malformed",
          );
        } else if (typeof server === "string" && SERVER_RE.test(server)) {
          // defense-in-depth: a $[0] that is BOTH servername-shaped AND secret-shaped is
          // BUCKETED, never emitted as a raw source key (and the warn text carries no value).
          const before = warnings.length;
          secretTripwire(server, warn, "an mcp source key");
          if (warnings.length > before) {
            secretShapedCount++;
            key = "mcp:secret-shaped";
          } else {
            key = server;
          }
        } else {
          key = "mcp:unrecognized"; // structured/oversized $[0] — never emit the raw value
          warn(
            "an mcp call has a non-servername args_json[0] — bucketed mcp:unrecognized",
          );
        }
      } else {
        kind = "method";
        key = method;
      }

      const a = bySource.get(key) ??
        {
          kind,
          callCount: 0,
          totalBytes: 0,
          firstAt: Infinity,
          lastAt: -Infinity,
          errorCount: 0,
        };
      a.callCount++;
      a.totalBytes += Number(r.bytes) || 0;
      const at = Number(r.created_at) || 0;
      a.firstAt = Math.min(a.firstAt, at);
      a.lastAt = Math.max(a.lastAt, at);
      a.errorCount += Number(r.is_error) || 0;
      bySource.set(key, a);
    }

    const sources = [...bySource.keys()].sort().map(
      (key): z.infer<typeof SourceEntry> => {
        const a = bySource.get(key)!;
        const e: z.infer<typeof SourceEntry> = {
          source: key,
          kind: a.kind,
          callCount: a.callCount,
          totalBytes: a.totalBytes,
          firstAt: a.firstAt,
          lastAt: a.lastAt,
          errorCount: a.errorCount,
        };
        if (a.kind === "mcp") e.releasePin = null; // fillable slot, mcp sources only
        return e;
      },
    );

    const byMethodObj: Record<string, number> = {};
    for (const m of [...byMethod.keys()].sort()) {
      byMethodObj[m] = byMethod.get(m)!;
    }

    // ---- orphan invariant: host calls attributable to NO project ----
    let orphanCallCount = 0;
    try {
      const o =
        (await readClone(clone, QUERIES.host_calls_orphan_count())) as Row[];
      orphanCallCount = Number(o[0]?.n) || 0;
    } catch (e) {
      warn(`orphan-count degraded: ${errName(e)}`);
    }
    if (orphanCallCount > 0) {
      warn(
        `${orphanCallCount} host call(s) unattributable to any project — surfaced, not silently dropped`,
      );
    }

    // ---- filesystem mount grants (host_path DROPPED; user/org-wide; not a network allowlist) ----
    let grantRows: Row[] = [];
    try {
      grantRows = (await readClone(clone, QUERIES.host_grants_all())) as Row[];
    } catch (e) {
      warn(`host_grants degraded: ${errName(e)}`);
    }
    const filesystemMountGrants = grantRows.map((
      g,
    ): z.infer<typeof MountGrant> => ({
      mountName: String(g.mount_name ?? ""),
      mode: String(g.mode ?? ""),
      userId: String(g.user_id ?? ""),
    }));

    const external: External = {
      sensitive: true,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: projName },
      },
      sources,
      filesystemMountGrants,
      totals: {
        calls: rows.length,
        sources: sources.length,
        bytes: sources.reduce((n, s) => n + s.totalBytes, 0),
        byMethod: byMethodObj,
        orphanCallCount,
        secretShapedCount,
      },
      warnings,
    };
    ExternalSchema.parse(external); // validate before write (no partial/invalid record)
    const handle = await sink.writeResource("external", pid, external);
    sink.logger.info(`external for ${projName ?? pid}`, {
      project: pid,
      calls: rows.length,
      sources: sources.length,
      orphanCallCount,
      secretShaped: secretShapedCount,
      grants: filesystemMountGrants.length,
      warnings: warnings.length,
    });
    return { external, dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
