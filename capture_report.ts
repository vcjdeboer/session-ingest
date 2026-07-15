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
  name: "@vcjdeboer/capture-report",
  description:
    "Render a captured CS session (session-ingest facets) into a readable report: the narrative arc (research question -> plan -> conclusion), the tools/packages/skills the session loaded, the independent reviewer's detail, your verbatim prompts, and a few captured figures embedded inline. Reads only sealed swamp data.",
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
    // Sessions that have been SEALED carry a `bundle-manifest` and the full report.
    // `inspect` only writes a `manifest`, so an inspected-but-unsealed session is a
    // candidate too — and must resolve to ITSELF, never fall back to another
    // session's sealed bundle.
    const sealedNames = new Set(
      all.filter((d) => d.tags?.specName === "bundle-manifest").map((d) =>
        d.name
      ),
    );
    const sessionNames = [
      ...new Set(
        all.filter((d) =>
          d.tags?.specName === "bundle-manifest" ||
          d.tags?.specName === "manifest"
        ).map((d) => d.name),
      ),
    ];
    if (!sessionNames.length) {
      return {
        markdown:
          "# Capture report\n\n_No captured session (manifest) found for this model._\n",
        json: { error: "no captured session" },
      };
    }

    // Resolve the target session by name / proj_id (via each session's manifest).
    // Capture methods pass `project`; `seal` passes `session` — accept either.
    const wantProj = String(
      ctx.methodArgs?.project ?? ctx.methodArgs?.session ?? "",
    );
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
      if (wantProj) {
        // A project was explicitly requested but nothing matches it. Do NOT render
        // a different session under its name — that silently mislabels one capture
        // as another (e.g. an `inspect` on session A rendering sealed session B).
        return {
          markdown:
            `# Capture report — ${wantProj}\n\n_No captured session matches \`${wantProj}\` in this model — it may not have been captured or sealed yet._\n`,
          json: { error: "session not found", requested: wantProj },
        };
      }
      // No project requested → newest bundle wins (prefer a sealed bundle; else the
      // newest inspected manifest).
      const pool = sealedNames.size ? [...sealedNames] : sessionNames;
      resourceName = pool
        .map((rn) => ({
          rn,
          v: latestSpec(rn, "bundle-manifest")?.version ??
            latestSpec(rn, "manifest")?.version ?? 0,
        }))
        .sort((a, b) => b.v - a.v)[0].rn;
      manifest = (await nameOf(resourceName)).man;
    }
    const isSealed = sealedNames.has(resourceName);

    // The bundle-manifest is the LATEST version of the resource. Real
    // dataRepository.findAllForModel only surfaces the latest version per name,
    // so we resolve each facet's version from the bundle's item refs
    // ("corpus/proj_x@4" → 4) rather than a per-spec lookup.
    const bundleH = latestSpec(resourceName, "bundle-manifest");
    const bundle =
      (bundleH
        ? await readJson(ctx, resourceName, bundleH.version)
        : await readJson(ctx, resourceName)) ?? {};
    const items = (bundle.items as Array<{ name: string; ref: string }>) ?? [];
    const facetVer: Record<string, number> = {};
    for (const it of items) {
      const v = /@(\d+)$/.exec(it.ref ?? "")?.[1];
      if (v) facetVer[it.name] = Number(v);
    }
    const readFacet = async (spec: string) =>
      facetVer[spec] != null
        ? await readJson(ctx, resourceName, facetVer[spec])
        : null;
    const transcript = await readFacet("transcript");
    const corpus = await readFacet("corpus");
    const cellsFacet = await readFacet("cells");
    const skillsFacet = await readFacet("skills");
    const lockFacet = await readFacet("lockenv");
    const reviewFacet = await readFacet("review");
    const annFacet = await readFacet("annotations");
    const settingsFacet = await readFacet("settings");

    // ---- the plan artifact (RQ + intent + task list). CS saves a `plan_*.json`
    // artifact with task_summary (the research question) and phases→steps (the plan);
    // it lives in the sealed corpus, so we read its bytes by checksum. ----
    let plan:
      | {
        rq: string;
        steps: Array<{ title: string; description: string }>;
        outputs: string[];
      }
      | null = null;
    {
      const arts = (corpus?.artifacts as Array<Record<string, unknown>>) ?? [];
      const planArt = arts.find((a) =>
        String(a.storagePath ?? "").includes("plan_") &&
        (a.present === true || a.present === "True")
      );
      if (planArt?.checksum) {
        const bytes = await ctx.dataRepository.getContent(
          modelType,
          modelId,
          String(planArt.checksum),
          1,
        );
        if (bytes) {
          try {
            const pj = JSON.parse(dec.decode(bytes)) as Record<string, unknown>;
            const steps = ((pj.phases as Array<Record<string, unknown>>) ?? [])
              .flatMap((ph) =>
                ((ph.delegations as Array<Record<string, unknown>>) ?? [])
                  .flatMap((dl) =>
                    (dl.steps as Array<Record<string, unknown>>) ?? []
                  )
              );
            const outs = (pj.desired_outputs as Array<unknown>) ?? [];
            plan = {
              rq: String(pj.task_summary ?? ""),
              steps: steps.map((s) => ({
                title: String(s.title ?? ""),
                description: String(s.description ?? ""),
              })),
              outputs: outs.map((o) =>
                typeof o === "string"
                  ? o
                  : String((o as Record<string, unknown>)?.name ?? "")
              ).filter(Boolean),
            };
          } catch { /* not the structured plan shape */ }
        }
      }
    }

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

    // manifest isn't a sealed facet (not in the bundle) and may be unavailable
    // via the real API — derive the display name from any facet's origin.
    const originOf = (f: Record<string, unknown> | null) =>
      ((f?.origin as Record<string, unknown>)?.project as Record<
        string,
        unknown
      >)?.name as string | undefined;
    const sessionName = originOf(manifest) ?? originOf(transcript) ??
      originOf(corpus) ?? originOf(settingsFacet) ?? resourceName;

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

    // ---- conclusion: the LAST main-thread (depth 0) assistant turn. The reviewer
    // runs as a sub-agent (depth > 0) AFTER the conclusion, so the last turn
    // overall is often the reviewer's sign-off — not the answer. depth 0 skips it.
    let conclusion = "";
    for (const t of turns) {
      if (t.type === "assistant" && String(t.depth ?? "") === "0") {
        const txt = turnText(t);
        if (txt) conclusion = txt;
      }
    }

    // ---- reviewer tally (from the manifest — sealed) ----
    const vc = (manifest?.verificationChecks as Record<string, unknown>) ?? {};
    const byVerdict = (vc.byVerdict as Record<string, number>) ?? {};

    // ---- print a few captured figures (PNG-sniff the corpus blobs) ----
    // Figures are LISTED here (checksum + size), not embedded — a swamp report is
    // stored/displayed as text and size-capped; base64 images would truncate it.
    // The visual (HTML) renderer embeds the actual bytes from the corpus.
    const figures: Array<{ sha: string; kb: number }> = [];
    const arts = (corpus?.artifacts as Array<Record<string, unknown>>) ?? [];
    const seen = new Set<string>();
    for (const a of arts) {
      if (figures.length >= 12) break;
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
        figures.push({ sha, kb: Math.round(size / 1024) });
      }
    }

    // ---- markdown ----
    const md: string[] = [];
    md.push(`# Capture report — ${sessionName}`);
    if (isSealed) {
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
    } else {
      md.push(
        `\n_Inspected (unsealed) — manifest only, no sealed facets. Run \`capture_*\` + \`seal\` for the full report (verbatim prompts, tools, plan, figures)._\n`,
      );
    }
    // Counts — prefer the manifest; else derive from the sealed facets so the
    // report is complete even when the manifest isn't reachable via the API.
    const msg = (manifest?.messages as Record<string, number>) ?? {};
    const art = (manifest?.artifacts as Record<string, number>) ?? {};
    const corpTotals = (corpus?.totals as Record<string, number>) ?? {};
    const tByType = (transcript?.byType as Record<string, number>) ?? {};
    const nArtifacts = art.distinct ?? corpTotals.files ?? "?";
    const nFrames = manifest?.nFrames ??
      (settingsFacet?.timeline as Record<string, unknown>)?.nFrames ?? "?";
    const nMessages: number | string = msg.total ??
      (transcript?.nTurns as number) ??
      (Object.values(tByType).reduce((a, b) => a + b, 0) || "?");
    const nEnvs = manifest?.nDistinctEnvs ??
      (lockFacet?.locks as unknown[])?.length ?? "?";
    md.push(
      `\n**${nArtifacts}** artifacts · **${nFrames}** frames · **${nMessages}** messages · **${
        msg.userTyped ?? prompts.length
      }** your prompts · **${nEnvs}** conda envs\n`,
    );

    // ---- the narrative arc: research question → plan → conclusion ----
    const rq = plan?.rq || prompts[0] || "";
    if (rq) {
      md.push(`## Research question\n`);
      md.push(`> ${rq.replace(/\n+/g, " ")}\n`);
    }
    if (plan?.steps.length) {
      md.push(`## The plan (${plan.steps.length} steps)\n`);
      plan.steps.forEach((s, i) => {
        md.push(
          `${i + 1}. **${s.title}** — ${
            s.description.replace(/\n+/g, " ").slice(0, 220)
          }${s.description.length > 220 ? "…" : ""}`,
        );
      });
      if (plan.outputs.length) {
        md.push(
          `\n_Desired outputs:_ ${
            plan.outputs.map((o) => `\`${o}\``).join(", ")
          }\n`,
        );
      }
    }

    if (conclusion) {
      md.push(`## The conclusion\n`);
      md.push(
        `_The main agent's final answer (last depth-0 turn — after this the reviewer signed off):_\n`,
      );
      md.push(
        conclusion.length > 1600 ? conclusion.slice(0, 1600) + "…" : conclusion,
      );
      md.push("");
    }

    // ---- how it was run (settings facet) ----
    if (settingsFacet) {
      const tl = settingsFacet.timeline as Record<string, unknown> | undefined;
      const models = (settingsFacet.models as Array<Record<string, unknown>>) ??
        [];
      const deleg =
        (settingsFacet.delegation as Array<Record<string, unknown>>) ??
          [];
      const toggles =
        (settingsFacet.toggles as Array<Record<string, unknown>>) ??
          [];
      const specs =
        (settingsFacet.specialists as Array<Record<string, unknown>>) ??
          [];
      md.push(`## How it was run\n`);
      if (tl?.startedAt) {
        const mins = tl.durationMs
          ? Math.round(Number(tl.durationMs) / 60000)
          : null;
        md.push(
          `**Timeline** — ${
            new Date(Number(tl.startedAt)).toISOString().slice(0, 16).replace(
              "T",
              " ",
            )
          } → ${new Date(Number(tl.endedAt)).toISOString().slice(11, 16)}${
            mins != null ? ` (${mins} min)` : ""
          } · ${tl.nFrames} frames\n`,
        );
      }
      if (models.length) {
        md.push(
          `**Model** — ` +
            models.map((m) =>
              `\`${m.model}\`${m.effort ? ` (${m.effort})` : ""} ×${m.count}`
            ).join(" · ") + "\n",
        );
      }
      if (deleg.length) {
        md.push(
          `**Delegation** — ` +
            deleg.map((d) => `\`${d.delegate}\` ×${d.count}`).join(" · ") +
            "\n",
        );
      }
      if (toggles.length) {
        md.push(
          `**Toggles** — ` +
            toggles.map((t) => `${t.key}: ${t.enabled ? "on" : "off"}`).join(
              " · ",
            ) + "\n",
        );
      }
      if (specs.length) {
        md.push(
          `**Specialists** — ` +
            specs.map((s) => `\`${s.agent}\`${s.enabled ? "" : " (off)"}`).join(
              " · ",
            ) + "\n",
        );
      }
    }

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

    // Prefer the sealed `review` facet (full detail); fall back to the manifest tally.
    const reviewChecks =
      (reviewFacet?.checks as Array<Record<string, unknown>>) ?? [];
    const reviewTally = (reviewFacet?.byVerdict as Record<string, number>) ??
      byVerdict;
    const reviewTotal = (reviewFacet?.total as number) ?? vc.total ?? 0;
    md.push(`## The independent reviewer\n`);
    md.push(
      `**${reviewTotal}** checks by an out-of-band model — ` +
        `❌ ${reviewTally.fail ?? 0} fail · ⚠️ ${
          reviewTally.warn ?? 0
        } warn · ✅ ${reviewTally.pass ?? 0} pass\n`,
    );
    if (reviewChecks.length) {
      const flagged = reviewChecks.filter((c) =>
        c.verdict === "fail" || c.verdict === "warn"
      );
      for (const c of flagged) {
        const icon = c.verdict === "fail" ? "❌" : "⚠️";
        md.push(
          `\n**${icon} ${String(c.verdict).toUpperCase()}** · ${
            String(c.severity ?? "")
          } · \`${String(c.reviewerModel ?? "")}\``,
        );
        md.push(`> ${String(c.claim ?? "").replace(/\n+/g, " ")}`);
        const ev = String(c.evidence ?? "").replace(/\n+/g, " ");
        if (ev) {
          md.push(`>\n> _${ev.slice(0, 600)}${ev.length > 600 ? "…" : ""}_`);
        }
      }
    } else {
      md.push(
        `> Per-check claims + evidence aren't in this bundle — run \`capture_review\` to seal the reviewer detail.\n`,
      );
    }

    md.push(`## Your prompts (${prompts.length}, verbatim)\n`);
    for (const p of prompts) md.push(`- ${p.replace(/\n+/g, " ")}`);

    // ---- your annotations (comments + bookmarks) ----
    const anns = (annFacet?.annotations as Array<Record<string, unknown>>) ??
      [];
    if (anns.length) {
      md.push(`\n## Your annotations (${anns.length})\n`);
      for (const a of anns) {
        const where = a.toolName
          ? `on \`${a.toolName}\``
          : a.messageIndex != null
          ? `at message ${a.messageIndex}`
          : "";
        md.push(
          `- **${String(a.kind)}** ${where} — “${
            String(a.anchorText ?? "").slice(0, 60)
          }”${a.note ? ` · _${String(a.note).replace(/\n+/g, " ")}_` : ""}`,
        );
      }
    }

    md.push(`\n## Captured figures (${figures.length})\n`);
    for (const f of figures) {
      md.push(`- \`${f.sha.slice(0, 12)}\` — ${f.kb} KB (PNG)`);
    }

    return {
      markdown: md.join("\n"),
      json: {
        session: sessionName,
        resource: resourceName,
        sealed: isSealed,
        facets: items.map((i) => i.name),
        stamp: bundle.stamp ?? null,
        counts: {
          artifacts: art.distinct ?? null,
          frames: manifest?.nFrames ?? null,
          messages: msg.total ?? null,
          prompts: prompts.length,
        },
        reviewer: {
          total: reviewTotal,
          byVerdict: reviewTally,
          detailSealed: reviewChecks.length > 0,
          flagged: reviewChecks.filter((c) =>
            c.verdict === "fail" || c.verdict === "warn"
          ).map((c) => ({
            verdict: c.verdict,
            severity: c.severity,
            claim: c.claim,
            reviewerModel: c.reviewerModel,
          })),
        },
        tools: {
          cli: tools.cli,
          rPackages: tools.rPkgs,
          python: tools.pyPkgs,
          environments: envs,
          skills,
        },
        researchQuestion: rq,
        plan: plan
          ? { steps: plan.steps.map((s) => s.title), outputs: plan.outputs }
          : null,
        conclusion,
        settings: settingsFacet
          ? {
            timeline: settingsFacet.timeline,
            models: settingsFacet.models,
            delegation: settingsFacet.delegation,
            toggles: settingsFacet.toggles,
            specialists: settingsFacet.specialists,
          }
          : null,
        annotations: anns.map((a) => ({
          kind: a.kind,
          anchorText: a.anchorText,
          note: a.note,
          origin: a.origin,
        })),
        prompts,
        figures,
        figuresEmbedded: figures.length,
      },
    };
  },
};

export default report;
