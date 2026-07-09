/**
 * @vcjdeboer/session-ingest — hostcalls.ts
 *
 * `capture_host_calls`: freeze a session's host_call_log request+response into a
 * `host_calls` resource in the shape the session-execute host-replay shim consumes
 * (`{method, args, response, isError}`), so host.* calls (mcp, query_db, …) replay
 * offline. Responses come inline (`data_inline`) or from a `data_ref` tape file on
 * disk. SECRET-SAFE: `credentials_request` responses are scrubbed to presence only
 * — a token is never frozen.
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

export const HostCallSchema = z.object({
  method: z.string(),
  args: z.array(z.unknown()).default([]),
  response: z.unknown().optional(),
  isError: z.boolean().default(false),
  error: z.string().default(""),
  /** true when a secret-bearing response (credentials_request) was scrubbed. */
  hasSecret: z.boolean().default(false),
});
export type HostCall = z.infer<typeof HostCallSchema>;

export const HostCallsSchema = z.object({
  session: z.string(),
  calls: z.array(HostCallSchema).default([]),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
});
export type HostCalls = z.infer<typeof HostCallsSchema>;

interface RawRow {
  method?: unknown;
  args_json?: unknown;
  data_inline?: unknown;
  data_ref?: unknown;
  error?: unknown;
}

function parseJson(s: unknown): unknown {
  try {
    return JSON.parse(String(s));
  } catch {
    return s == null ? null : String(s);
  }
}

/**
 * Turn host_call_log rows into replayable calls. `credentials_request` responses
 * are dropped (presence only). Otherwise the response is `data_inline` parsed, or
 * resolved from its `data_ref` tape via the injected `resolveRef`. Pure over rows
 * + resolveRef.
 */
export async function buildHostCalls(
  rows: RawRow[],
  resolveRef: (refPath: string) => Promise<unknown>,
): Promise<HostCall[]> {
  const calls: HostCall[] = [];
  for (const r of rows) {
    const method = String(r.method ?? "");
    const args = parseJson(r.args_json);
    const isError = r.error != null && String(r.error) !== "";
    const call: HostCall = {
      method,
      args: Array.isArray(args) ? args : [args],
      response: null,
      isError,
      error: isError ? String(r.error) : "",
      hasSecret: method === "credentials_request",
    };
    if (!call.hasSecret && !isError) {
      if (r.data_inline != null) call.response = parseJson(r.data_inline);
      else if (r.data_ref != null) {
        call.response = await resolveRef(String(r.data_ref));
      }
    }
    calls.push(call);
  }
  return calls;
}

interface HostCallsSink {
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/**
 * Capture the project's replayable host calls into a `host_calls` resource.
 * `data_ref` tapes live at `<orgDir>/artifacts/<pid>/<data_ref>` (read-only).
 */
export async function captureHostCalls(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: HostCallsSink,
): Promise<{ dataHandles: unknown[] }> {
  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  await assertQuiescent(dbPath); // refuse a session that is actively writing (mid-run)
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
      QUERIES.host_calls_full(pid),
    )) as RawRow[];
    const tapesBase = `${orgDir}/artifacts/${pid}`;
    const resolveRef = async (refPath: string): Promise<unknown> => {
      // Refs are relative paths under the project's artifact dir; refuse escape.
      if (refPath.includes("..")) return null;
      const t = await Deno.readTextFile(`${tapesBase}/${refPath}`).catch(() =>
        ""
      );
      return t ? parseJson(t) : null;
    };
    const calls = await buildHostCalls(rows, resolveRef);

    const record: HostCalls = {
      session: pid,
      calls,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: (proj.name ?? null) as string | null },
      },
    };
    const handle = await sink.writeResource("host_calls", pid, record);
    sink.logger.info("capture_host_calls done", {
      calls: calls.length,
      scrubbed: calls.filter((c) => c.hasSecret).length,
    });
    return { dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
