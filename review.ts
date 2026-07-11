/**
 * @vcjdeboer/session-ingest — review.ts
 *
 * `capture_review`: freeze a session's INDEPENDENT-REVIEWER verdicts — Claude
 * Science runs an out-of-band model over the analysis and records
 * `verification_checks` (claim / verdict / severity / evidence). This seals them
 * into a SENSITIVE `review` resource so the capture-report (and any auditor) can
 * show WHAT was reviewed and WHY, from sealed data alone — not just the tally the
 * manifest carries. claim + evidence are analysis prose, never a credential.
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

export const ReviewCheckSchema = z.object({
  verdict: z.string(), // fail | warn | pass (whatever CS recorded)
  severity: z.string().default(""),
  claim: z.string().default(""),
  evidence: z.string().default(""),
  reviewerModel: z.string().default(""),
  reviewerKind: z.string().default(""),
  status: z.string().default(""),
});
export type ReviewCheck = z.infer<typeof ReviewCheckSchema>;

export const ReviewSchema = z.object({
  sensitive: z.literal(true),
  session: z.string(),
  total: z.number(),
  byVerdict: z.record(z.string(), z.number()),
  checks: z.array(ReviewCheckSchema).default([]),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
});
export type Review = z.infer<typeof ReviewSchema>;

interface RawCheck {
  verdict?: unknown;
  severity?: unknown;
  claim?: unknown;
  evidence?: unknown;
  reviewer_model?: unknown;
  reviewer_kind?: unknown;
  status?: unknown;
}

/** Shape raw verification_checks rows into the sealed review checks + verdict tally. Pure. */
export function buildReview(
  rows: RawCheck[],
): { checks: ReviewCheck[]; byVerdict: Record<string, number> } {
  const checks: ReviewCheck[] = [];
  const byVerdict: Record<string, number> = {};
  for (const r of rows) {
    const verdict = String(r.verdict ?? "");
    byVerdict[verdict] = (byVerdict[verdict] ?? 0) + 1;
    checks.push({
      verdict,
      severity: String(r.severity ?? ""),
      claim: String(r.claim ?? ""),
      evidence: String(r.evidence ?? ""),
      reviewerModel: String(r.reviewer_model ?? ""),
      reviewerKind: String(r.reviewer_kind ?? ""),
      status: String(r.status ?? ""),
    });
  }
  return { checks, byVerdict };
}

interface ReviewSink {
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** Capture the project's reviewer verdicts into a SENSITIVE `review` resource. */
export async function captureReview(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: ReviewSink,
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
      QUERIES.review_checks(pid),
    )) as RawCheck[];
    const { checks, byVerdict } = buildReview(rows);

    const record: Review = {
      sensitive: true,
      session: pid,
      total: checks.length,
      byVerdict,
      checks,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: (proj.name ?? null) as string | null },
      },
    };
    ReviewSchema.parse(record);
    const handle = await sink.writeResource("review", pid, record);
    sink.logger.info("capture_review done", {
      total: checks.length,
      byVerdict,
    });
    return { dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
