/**
 * @vcjdeboer/session-ingest — skills.ts
 *
 * `capture_skills`: freeze the CS SKILLS a session used — the injected context that
 * defines functions/globals no user cell does (e.g. `figure-style` →
 * `apply_figure_style()`). Skill-loads are NOT recorded in host_call_log, so the
 * USED set is inferred: a skill is used if any symbol its `kernel.py` exports
 * appears in the session's cell source. Each used skill's `kernel.py` is frozen
 * (content-addressed) so a replay can prepend it as preamble. Read-only from disk.
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

export const SkillSchema = z.object({
  name: z.string(),
  /** sha of the offloaded `body` blob holding the skill's kernel.py. */
  kernelRef: z.string(),
  /** Top-level symbols the kernel exports (why it was judged used). */
  symbols: z.array(z.string()).default([]),
});

export const SkillsSchema = z.object({
  session: z.string(),
  skills: z.array(SkillSchema).default([]),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  writeManifest: z.array(z.string()).default([]),
});
export type Skills = z.infer<typeof SkillsSchema>;

/** Escape a symbol for a word-boundary regex (identifiers only, defensive). */
function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Top-level `def NAME` / `NAME =` symbols a kernel.py exports (no leading indent). */
export function extractSymbols(src: string): string[] {
  const syms = new Set<string>();
  for (const line of src.split("\n")) {
    const d = line.match(/^def (\w+)/);
    if (d) {
      syms.add(d[1]);
      continue;
    }
    const a = line.match(/^([A-Za-z_]\w*)\s*=/);
    if (a) syms.add(a[1]);
  }
  return [...syms];
}

/** Skills whose any exported symbol appears (word-boundary) in the cell source. */
export function usedSkills(
  skillSymbols: Record<string, string[]>,
  sources: string[],
): string[] {
  const blob = sources.join("\n");
  const used: string[] = [];
  for (const [name, syms] of Object.entries(skillSymbols)) {
    if (
      syms.some((s) => new RegExp(`\\b${escapeRe(s)}\\b`).test(blob))
    ) used.push(name);
  }
  return used;
}

interface SkillsSink {
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
 * Capture the CS skills a session used into a `skills` resource (+ kernel blobs).
 * Reads the session's cell source (from the db clone) to infer the used set, then
 * freezes each used skill's kernel.py from `<orgDir>/skills/<name>/kernel.py`.
 */
export async function captureSkills(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: SkillsSink,
): Promise<{ dataHandles: unknown[] }> {
  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  await assertQuiescent(dbPath); // refuse a session that is actively writing (mid-run)
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
      (await readClone(clone, QUERIES.cells_by_project(pid))) as Array<
        { source?: unknown }
      >;
    const sources = rows.map((r) => String(r.source ?? ""));

    // Enumerate skills on disk + their exported symbols.
    const skillsDir = `${orgDir}/skills`;
    const symbolsBySkill: Record<string, string[]> = {};
    const kernelBySkill: Record<string, string> = {};
    const names: string[] = [];
    try {
      for await (const entry of Deno.readDir(skillsDir)) {
        if (entry.isDirectory) names.push(entry.name);
      }
    } catch { /* no skills dir → capture nothing */ }
    for (const name of names) {
      const kernel = await Deno.readTextFile(`${skillsDir}/${name}/kernel.py`)
        .catch(() => "");
      if (!kernel) continue;
      symbolsBySkill[name] = extractSymbols(kernel);
      kernelBySkill[name] = kernel;
    }

    const used = usedSkills(symbolsBySkill, sources);
    const skills = [];
    for (const name of used) {
      const kernelRef = await store.offload(kernelBySkill[name]);
      skills.push({ name, kernelRef, symbols: symbolsBySkill[name] });
    }
    const writeManifest = await store.flush(sink);

    const record: Skills = {
      session: pid,
      skills,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: (proj.name ?? null) as string | null },
      },
      writeManifest,
    };
    const handle = await sink.writeResource("skills", pid, record);
    sink.logger.info("capture_skills done", {
      used: used.length,
      offloaded: writeManifest.length,
    });
    return { dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
