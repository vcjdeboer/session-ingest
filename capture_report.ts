/**
 * @vcjdeboer/session-ingest — capture_report.ts
 *
 * A swamp-native report that renders a captured Claude Science session (the
 * session-ingest facets) into a readable capture report: the sealed facets, the
 * independent reviewer's verdict tally, your verbatim prompts, and a handful of
 * the captured figures embedded inline. Reads ONLY sealed swamp data via
 * `dataRepository` — nothing from the live app.
 *
 * Method-scope: runs after a session-ingest method (e.g. `seal`), resolving the
 * project from `methodArgs.project`, falling back to the most recent bundle.
 * @module
 */

/** Minimal shape of the report context we use (mirrors ReportContext). */
export interface RepoLike {
  getContent(
    type: string,
    modelId: string,
    dataName: string,
    version?: number,
  ): Promise<Uint8Array | null>;
  findAllForModel(
    type: string,
    modelId: string,
  ): Promise<
    Array<{ name: string; version: number; tags?: Record<string, string> }>
  >;
}
export interface CaptureReportContext {
  modelType: string;
  modelId: string;
  dataRepository: RepoLike;
  methodArgs?: Record<string, unknown>;
  logger?: { info: (m: string, p?: unknown) => void };
}
export interface ReportResult {
  markdown: string;
  json: Record<string, unknown>;
}

const dec = new TextDecoder();
const PNG_SIG = [0x89, 0x50, 0x4e, 0x47]; // \x89 P N G
const isPng = (b: Uint8Array) =>
  b.length > 8 && PNG_SIG.every((v, i) => b[i] === v);

function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  // btoa is available in Deno's global scope
  return btoa(s);
}

/** Pull the readable text out of a captured transcript turn. */
function turnText(t: Record<string, unknown>): string {
  const blocks = (t.blocks as Array<Record<string, unknown>>) ?? [];
  return blocks
    .filter((b) => b.type === "text")
    .map((b) => String(b.text ?? ""))
    .join(" ")
    .trim();
}

/** Known analysis CLIs worth surfacing (bioinformatics-leaning; extend freely). */
const CLI_TOOLS = [
  "hyphy",
  "salmon",
  "kallisto",
  "mafft",
  "muscle",
  "iqtree",
  "raxml",
  "fasttree",
  "trimal",
  "hmmsearch",
  "hmmscan",
  "blastp",
  "blastn",
  "makeblastdb",
  "samtools",
  "bcftools",
  "bwa",
  "STAR",
  "fasterq-dump",
  "prefetch",
  "sra-tools",
  "datasets",
  "efetch",
  "esearch",
  "seqkit",
  "mmseqs",
  "codeml",
  "paml",
  "gatk",
  "bedtools",
  "minimap2",
];

/** Sort a count-map into a descending [name, n] list. */
function topCounts(m: Map<string, number>): Array<[string, number]> {
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

/** Mine tools, R/Python packages and CLI invocations out of the captured cell sources. */
function mineToolsFromSources(
  sources: Array<{ language?: string; source: string }>,
): {
  cli: Array<[string, number]>;
  rPkgs: string[];
  pyPkgs: Array<[string, number]>;
} {
  const cli = new Map<string, number>();
  const rPkgs = new Set<string>();
  const py = new Map<string, number>();
  const cliRe = new RegExp(`\\b(${CLI_TOOLS.join("|")})\\b`, "g");
  const rLibRe = /(?:library|require)\(([A-Za-z0-9._]+)\)|([A-Za-z0-9._]+)::/g;
  const pyRe = /^\s*(?:import|from)\s+([A-Za-z0-9_]+)/gm;
  for (const c of sources) {
    const src = c.source ?? "";
    if (!src) continue;
    if (c.language === "bash") {
      for (const m of src.matchAll(cliRe)) {
        cli.set(m[1], (cli.get(m[1]) ?? 0) + 1);
      }
    } else if (c.language === "r") {
      for (const m of src.matchAll(rLibRe)) {
        const pkg = m[1] ?? m[2];
        if (pkg && !["base", "utils", "stats"].includes(pkg)) rPkgs.add(pkg);
      }
    } else if (c.language === "python") {
      for (const m of src.matchAll(pyRe)) {
        const p = m[1];
        if (p && p !== "host") py.set(p, (py.get(p) ?? 0) + 1);
      }
    }
  }
  return {
    cli: topCounts(cli),
    rPkgs: [...rPkgs].sort(),
    pyPkgs: topCounts(py).slice(0, 12),
  };
}

async function readJson(
  ctx: CaptureReportContext,
  dataName: string,
  version?: number,
): Promise<Record<string, unknown> | null> {
  const raw = await ctx.dataRepository.getContent(
    ctx.modelType,
    ctx.modelId,
    dataName,
    version,
  );
  if (!raw) return null;
  try {
    return JSON.parse(dec.decode(raw)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export const report = {
  description:
    "Render a captured CS session (session-ingest facets) into a readable report: sealed facets, the reviewer's verdict tally, your verbatim prompts, and a few captured figures embedded inline. Reads only sealed swamp data.",
  scope: "method" as const,
  labels: ["capture", "session-ingest", "provenance"],

  async execute(ctx: CaptureReportContext): Promise<ReportResult> {
    const { modelType, modelId } = ctx;
    const all = await ctx.dataRepository.findAllForModel(modelType, modelId);

    // Each captured session lives under ONE resource name (its proj_id), with a
    // separate version per facet (specName). `latestSpec` finds the newest
    // version of a given facet for a resource.
    const latestSpec = (name: string, spec: string) =>
      all.filter((d) => d.name === name && d.tags?.specName === spec)
        .sort((a, b) => b.version - a.version)[0];
    const sessionNames = [
      ...new Set(
        all.filter((d) => d.tags?.specName === "bundle-manifest").map((d) =>
          d.name
        ),
      ),
    ];
    if (!sessionNames.length) {
      return {
        markdown:
          "# Capture report\n\n_No captured session (bundle-manifest) found for this model._\n",
        json: { error: "no captured session" },
      };
    }

    // Resolve the target session by name / proj_id (via each session's manifest).
    const wantProj = String(ctx.methodArgs?.project ?? "");
    const nameOf = async (rn: string) => {
      const mh = latestSpec(rn, "manifest");
      const man = mh ? await readJson(ctx, rn, mh.version) : null;
      const proj = (man?.origin as Record<string, unknown>)?.project as
        | Record<string, unknown>
        | undefined;
      return {
        man,
        pname: proj?.name as string ?? null,
        pid: proj?.id as string ?? rn,
      };
    };
    let resourceName = sessionNames[0];
    let manifest: Record<string, unknown> | null = null;
    let matched = false;
    for (const rn of sessionNames) {
      const { man, pname, pid } = await nameOf(rn);
      if (
        wantProj && (pname === wantProj || pid === wantProj || rn === wantProj)
      ) {
        resourceName = rn;
        manifest = man;
        matched = true;
        break;
      }
    }
    if (!matched) {
      // no explicit match → newest bundle-manifest wins
      resourceName = sessionNames
        .map((rn) => ({
          rn,
          v: latestSpec(rn, "bundle-manifest")?.version ?? 0,
        }))
        .sort((a, b) => b.v - a.v)[0].rn;
      manifest = (await nameOf(resourceName)).man;
    }

    const bundleH = latestSpec(resourceName, "bundle-manifest");
    const bundle = bundleH
      ? (await readJson(ctx, resourceName, bundleH.version)) ?? {}
      : {};
    const items = (bundle.items as Array<{ name: string; ref: string }>) ?? [];

    const readFacet = async (spec: string) => {
      const h = latestSpec(resourceName, spec);
      return h ? await readJson(ctx, resourceName, h.version) : null;
    };
    const transcript = await readFacet("transcript");
    const corpus = await readFacet("corpus");
    const cellsFacet = await readFacet("cells");
    const skillsFacet = await readFacet("skills");
    const lockFacet = await readFacet("lockenv");

    // ---- tools, packages & skills (mined from the sealed cells/skills/lockenv) ----
    const rawCells = (cellsFacet?.cells as Array<Record<string, unknown>>) ??
      [];
    const sources: Array<{ language?: string; source: string }> = [];
    for (const c of rawCells) {
      let src = String(c.source ?? "");
      if (!src && c.bodyRef) {
        const b = await ctx.dataRepository.getContent(
          modelType,
          modelId,
          String(c.bodyRef),
          1,
        );
        if (b) src = dec.decode(b);
      }
      sources.push({ language: c.language as string | undefined, source: src });
    }
    const tools = mineToolsFromSources(sources);
    const skills =
      ((skillsFacet?.skills as Array<Record<string, unknown>>) ?? [])
        .map((s) => ({
          name: String(s.name ?? ""),
          symbols: (s.symbols as string[])?.length ?? 0,
        }));
    const envs = ((lockFacet?.locks as Array<Record<string, unknown>>) ?? [])
      .map((l) => ({
        name: String(l.environmentName ?? ""),
        py: String(l.pythonVersion ?? ""),
        pkgs: Number(l.packageCount ?? 0),
      }));

    const sessionName =
      ((manifest?.origin as Record<string, unknown>)?.project as Record<
        string,
        unknown
      >)
        ?.name as string ?? resourceName;

    // ---- prompts (userTyped turns, verbatim) ----
    const turns = (transcript?.turns as Array<Record<string, unknown>>) ?? [];
    const prompts: string[] = [];
    for (const t of turns) {
      if (t.type === "userTyped") {
        const txt = turnText(t);
        if (txt && !txt.startsWith("[System]") && !txt.startsWith("<")) {
          prompts.push(txt);
        }
      }
    }

    // ---- reviewer tally (from the manifest — sealed) ----
    const vc = (manifest?.verificationChecks as Record<string, unknown>) ?? {};
    const byVerdict = (vc.byVerdict as Record<string, number>) ?? {};

    // ---- print a few captured figures (PNG-sniff the corpus blobs) ----
    const figures: Array<{ sha: string; dataUri: string; kb: number }> = [];
    const arts = (corpus?.artifacts as Array<Record<string, unknown>>) ?? [];
    const seen = new Set<string>();
    for (const a of arts) {
      if (figures.length >= 6) break;
      const sha = String(a.checksum ?? "");
      const size = Number(a.size ?? 0);
      const present = a.present === true || a.present === "True";
      if (!sha || !present || seen.has(sha) || size > 300 * 1024) continue;
      seen.add(sha);
      const bytes = await ctx.dataRepository.getContent(
        modelType,
        modelId,
        sha,
        1,
      );
      if (bytes && isPng(bytes)) {
        figures.push({
          sha: sha.slice(0, 12),
          dataUri: `data:image/png;base64,${b64(bytes)}`,
          kb: Math.round(size / 1024),
        });
      }
    }

    // ---- markdown ----
    const md: string[] = [];
    md.push(`# Capture report — ${sessionName}`);
    md.push(
      `\n_Sealed session-ingest bundle · ${items.length} facets · stamp \`${
        String(bundle.stamp ?? "?")
      }\`_\n`,
    );
    md.push(`## What was captured\n`);
    md.push(`| facet | checksum |`);
    md.push(`| --- | --- |`);
    for (const it of items) {
      md.push(
        `| ${it.name} | \`${
          String((it as { checksum?: string }).checksum ?? "").slice(0, 12)
        }\` |`,
      );
    }
    const msg = (manifest?.messages as Record<string, number>) ?? {};
    const art = (manifest?.artifacts as Record<string, number>) ?? {};
    md.push(
      `\n**${art.distinct ?? "?"}** artifacts · **${
        manifest?.nFrames ?? "?"
      }** frames · **${msg.total ?? "?"}** messages · **${
        msg.userTyped ?? prompts.length
      }** your prompts · **${manifest?.nDistinctEnvs ?? "?"}** conda envs\n`,
    );

    md.push(`## Tools, packages & skills\n`);
    if (tools.cli.length) {
      md.push(
        `**Command-line tools** — ` +
          tools.cli.map(([n, c]) => `\`${n}\` (${c})`).join(" · ") + "\n",
      );
    }
    if (envs.length) {
      md.push(
        `**Environments** — ` +
          envs.map((e) => `\`${e.name}\` (py ${e.py}, ${e.pkgs} pkgs)`).join(
            " · ",
          ) + "\n",
      );
    }
    if (tools.rPkgs.length) {
      md.push(
        `**R packages** — ` + tools.rPkgs.map((p) => `\`${p}\``).join(" · ") +
          "\n",
      );
    }
    if (tools.pyPkgs.length) {
      md.push(
        `**Python** — ` +
          tools.pyPkgs.map(([n, c]) => `\`${n}\` (${c})`).join(" · ") + "\n",
      );
    }
    if (skills.length) {
      md.push(
        `**CS skills loaded** — ` +
          skills.map((s) => `\`${s.name}\` (${s.symbols} fns)`).join(" · ") +
          "\n",
      );
    }

    md.push(`## The independent reviewer\n`);
    md.push(
      `**${vc.total ?? 0}** checks by an out-of-band model — ` +
        `❌ ${byVerdict.fail ?? 0} fail · ⚠️ ${byVerdict.warn ?? 0} warn · ✅ ${
          byVerdict.pass ?? 0
        } pass\n`,
    );
    md.push(
      `> Per-check claims + evidence are not in this bundle yet (only the tally is sealed); a \`capture_review\` facet would seal the detail.\n`,
    );

    md.push(`## Your prompts (${prompts.length}, verbatim)\n`);
    for (const p of prompts) md.push(`- ${p.replace(/\n+/g, " ")}`);

    md.push(`\n## Captured figures (${figures.length})\n`);
    for (const f of figures) {
      md.push(`![captured figure ${f.sha} — ${f.kb} KB](${f.dataUri})\n`);
    }

    return {
      markdown: md.join("\n"),
      json: {
        session: sessionName,
        resource: resourceName,
        facets: items.map((i) => i.name),
        stamp: bundle.stamp ?? null,
        counts: {
          artifacts: art.distinct ?? null,
          frames: manifest?.nFrames ?? null,
          messages: msg.total ?? null,
          prompts: prompts.length,
        },
        reviewer: { total: vc.total ?? 0, byVerdict },
        tools: {
          cli: tools.cli,
          rPackages: tools.rPkgs,
          python: tools.pyPkgs,
          environments: envs,
          skills,
        },
        prompts,
        figuresEmbedded: figures.length,
      },
    };
  },
};

export default report;
