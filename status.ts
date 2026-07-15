/**
 * @vcjdeboer/session-ingest — status.ts
 *
 * `status`: a read-only reconciliation between what is LIVE on Claude Science
 * (sessions in operon-cli.db) and what is captured LOCALLY in swamp (the ingest
 * facets). For each session it answers: live on CS? captured? and if captured,
 * is it `sealed` (has a bundle-manifest), `inspected` (a bare manifest only), or
 * `partial` (some capture facets, not yet sealed)?
 *
 * It never mutates and never REFUSES on a pinging DB — a listing needs no
 * consistent snapshot, so it reads read-only and just flags `dbQuiescent`. The
 * pure `deriveState`/`reconcile` are unit-tested; the two readers are injected
 * seams (the live DB via db.ts, the local captures via the swamp CLI).
 * @module
 */
import { z } from "npm:zod@4";
import { listLiveSessions, PROJ_ID_RE } from "./db.ts";
import { swampJson } from "./bundle.ts";

export const StatusArgsSchema = z.object({
  csRoot: z.string().default(""),
  orgId: z.string().default(""),
});

const CaptureState = z.enum(["sealed", "inspected", "partial"]);

export const StatusSchema = z.object({
  dbQuiescent: z.boolean(),
  live: z.array(z.object({
    projectId: z.string(),
    name: z.string().nullable(),
  })),
  local: z.array(z.object({
    projectId: z.string(),
    name: z.string().nullable(),
    state: CaptureState,
    facets: z.array(z.string()),
  })),
  reconciliation: z.object({
    liveAndCaptured: z.array(z.string()),
    liveNotCaptured: z.array(z.string()),
    capturedNotLive: z.array(z.string()),
  }),
  counts: z.object({
    live: z.number(),
    local: z.number(),
    sealed: z.number(),
    inspected: z.number(),
    partial: z.number(),
  }),
});

export type LiveSession = { projectId: string; name: string | null };
export type LocalSession = {
  projectId: string;
  name: string | null;
  state: z.infer<typeof CaptureState>;
  facets: string[];
};

/** Derive a capture state from the set of facet specNames present for a session. */
export function deriveState(facets: string[]): z.infer<typeof CaptureState> {
  if (facets.includes("bundle-manifest")) return "sealed";
  // any real capture facet (transcript/corpus/cells/...) beyond a bare inspect manifest
  if (facets.some((f) => f !== "manifest" && f !== "status")) return "partial";
  return "inspected";
}

/** PURE reconciliation of live-vs-local. Sorted, deterministic. */
export function reconcile(
  dbQuiescent: boolean,
  live: LiveSession[],
  local: LocalSession[],
): z.infer<typeof StatusSchema> {
  const liveIds = new Set(live.map((l) => l.projectId));
  const localIds = new Set(local.map((l) => l.projectId));
  const byProj = <T extends { projectId: string }>(a: T, b: T) =>
    a.projectId < b.projectId ? -1 : a.projectId > b.projectId ? 1 : 0;
  return {
    dbQuiescent,
    live: [...live].sort(byProj),
    local: [...local].sort(byProj),
    reconciliation: {
      liveAndCaptured: [...liveIds].filter((id) => localIds.has(id)).sort(),
      liveNotCaptured: [...liveIds].filter((id) => !localIds.has(id)).sort(),
      capturedNotLive: [...localIds].filter((id) => !liveIds.has(id)).sort(),
    },
    counts: {
      live: live.length,
      local: local.length,
      sealed: local.filter((l) => l.state === "sealed").length,
      inspected: local.filter((l) => l.state === "inspected").length,
      partial: local.filter((l) => l.state === "partial").length,
    },
  };
}

/** Real reader: enumerate locally-captured sessions from swamp's ingest data. */
async function defaultLocalEnumerate(modelId: string): Promise<LocalSession[]> {
  const mres = (await swampJson(["model", "get", modelId, "--json"])) as
    | { name?: string }
    | null;
  const model = mres?.name ?? modelId;
  const raw = (await swampJson(
    ["data", "query", `modelName == "${model}"`, "--json"],
  )) as Array<{ name?: string }> | { data?: Array<{ name?: string }> } | null;
  const list = Array.isArray(raw) ? raw : raw?.data ?? [];
  const projIds = [
    ...new Set(
      list.map((r) => String(r.name ?? "")).filter((n) => PROJ_ID_RE.test(n)),
    ),
  ];
  const out: LocalSession[] = [];
  for (const pid of projIds) {
    const vres = (await swampJson(
      ["data", "versions", model, pid, "--json"],
    )) as { versions?: Array<{ version: number }> } | null;
    const versions = (vres?.versions ?? []).slice().sort((a, b) =>
      b.version - a.version
    );
    const facets = new Set<string>();
    let name: string | null = null;
    for (const v of versions) {
      const got = (await swampJson(
        ["data", "get", model, pid, "--version", String(v.version), "--json"],
      )) as
        | {
          tags?: { specName?: string };
          content?: { origin?: { project?: { name?: string } } };
        }
        | null;
      const spec = got?.tags?.specName;
      if (spec) facets.add(spec);
      if (!name && got?.content?.origin?.project?.name) {
        name = got.content.origin.project.name;
      }
    }
    out.push({
      projectId: pid,
      name,
      state: deriveState([...facets]),
      facets: [...facets].sort(),
    });
  }
  return out;
}

export interface StatusContext {
  modelId: string;
  globalArgs?: { csRoot?: string; orgId?: string };
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** The `status` method. Injected `_live`/`_local` seams keep it unit-testable. */
export async function runStatus(
  args: z.input<typeof StatusArgsSchema> & {
    _live?: (
      csRoot: string,
      orgId?: string,
    ) => Promise<{ dbQuiescent: boolean; sessions: LiveSession[] }>;
    _local?: (modelId: string) => Promise<LocalSession[]>;
  },
  context: StatusContext,
): Promise<{ dataHandles: unknown[] }> {
  const csRoot = args.csRoot || context.globalArgs?.csRoot || "";
  const orgId = args.orgId || context.globalArgs?.orgId || undefined;

  const liveFn = args._live ??
    (async (r: string, o?: string) => {
      const { dbQuiescent, sessions } = await listLiveSessions(r, o);
      return {
        dbQuiescent,
        sessions: sessions.map((s) => ({ projectId: s.id, name: s.name })),
      };
    });
  const localFn = args._local ?? defaultLocalEnumerate;

  const { dbQuiescent, sessions } = await liveFn(csRoot, orgId);
  const local = await localFn(context.modelId);
  const status = reconcile(dbQuiescent, sessions, local);

  const handle = await context.writeResource("status", "status", status);
  context.logger.info(
    "status: {live} live / {local} local (sealed {sealed}, inspected {inspected}, " +
      "partial {partial}); dbQuiescent={q}",
    {
      live: status.counts.live,
      local: status.counts.local,
      sealed: status.counts.sealed,
      inspected: status.counts.inspected,
      partial: status.counts.partial,
      q: dbQuiescent,
    },
  );
  return { dataHandles: [handle] };
}
