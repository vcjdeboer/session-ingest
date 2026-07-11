/**
 * @vcjdeboer/session-ingest — inputs.ts
 *
 * `capture_inputs`: freeze a session's Tier-1 `/private/tmp` inputs — the raw
 * working data (`quant`, `cds`, `sel`, …) that lives OUTSIDE the CS org tree and
 * is "days from deletion" (doc-2 §3), which `capture_corpus` deliberately skips.
 *
 * SECURITY MODEL (this reads a user-supplied allowlist of arbitrary external
 * roots, mostly world-writable /private/tmp):
 *  - ALLOWLIST BY LOCATION: a root's realPath MUST resolve under an approved base
 *    (default /private/tmp, /tmp). Anything else (incl. a plantable symlink under
 *    /tmp resolving into ~/.ssh) is REJECTED unless allowSensitiveRoot + the exact
 *    root is opted-in. (paths.ts validateRoot.)
 *  - CANONICAL everything: every walked file is realPath'd; the CANONICAL path is
 *    what gets lstat'd/copied/read, and containment is re-asserted on it. TOCTOU
 *    hardening on the world-writable tree: an `lstat`-not-symlink check guards each
 *    read (a post-canonicalization swap → symlink is refused, never followed), and
 *    small files are read from a SINGLE fd (noFollow, store.ts). Deno lacks
 *    `O_NOFOLLOW`, so a sub-millisecond lstat→open window remains — narrowed, not zero.
 *  - Files outside all accepted roots are COUNTED, never echoed (no absolute path
 *    leaks into the sealed record); all warnings use root-relative paths.
 * POLICY (doc-2 §6): copy-roots + accession files honor maxFileBytes (over-cap →
 * by-reference, so no accidental multi-GB hoard); a referenceRoot records path+size
 * only. Accession IDs (SRA runs, RefSeq GC[AF]_) are harvested for re-fetchability.
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
import { type BlobSink, makeBlobStore, secretTripwire } from "./store.ts";
import {
  containedRel,
  rootPrefixes,
  textLike,
  TRIPWIRE_MAX,
  validateRoot,
  walkSorted,
} from "./paths.ts";

const DEFAULT_MAX_FILE_BYTES = 256 * 1024 * 1024; // 256 MiB
/**
 * Files always copied (the frozen re-fetch RECIPE) — but still under maxFileBytes.
 * Deliberately NOT a bare `\.tsv$`: a generic data `.tsv` (kallisto `abundance.tsv`,
 * salmon `quant.genes.tsv`, count matrices) must honor referenceOver/referenceRoot and
 * NOT be hoarded. Only manifest/assemblies/dump-log/picks recipe files are unconditional.
 */
const ACCESSION_RE =
  /^manifest$|manifest\.tsv$|assemblies\.json$|\.dump\.log$|_picks\.json$/i;

/* ============================ schema ============================ */
export const CopiedEntry = z.object({
  relPath: z.string(),
  sha: z.string(),
  size: z.number(),
});
export const ReferencedEntry = z.object({
  relPath: z.string(),
  size: z.number(),
  sha: z.string().optional(),
});
export const RootEntry = z.object({
  root: z.string(),
  resolvedRoot: z.string(),
  copied: z.array(CopiedEntry),
  referenced: z.array(ReferencedEntry),
  totals: z.object({
    files: z.number(),
    copiedBytes: z.number(),
    referencedBytes: z.number(),
  }),
});
export const InputsSchema = z.object({
  sensitive: z.literal(true),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  capturedRoots: z.array(z.string()),
  referenceRoots: z.array(z.string()),
  referenceOver: z.number().nullable(),
  maxFileBytes: z.number(),
  roots: z.array(RootEntry),
  accessions: z.object({
    sra: z.array(z.string()),
    refseq: z.array(z.string()),
    ena: z.array(z.string()),
  }),
  totals: z.object({
    files: z.number(),
    copiedBytes: z.number(),
    referencedBytes: z.number(),
    secretShapedCount: z.number(),
    skippedOutside: z.number(),
  }),
  writeManifest: z.array(z.string()),
  warnings: z.array(z.string()),
});
export type Inputs = z.infer<typeof InputsSchema>;

/** What capture_inputs needs from the model's execute context. */
export interface InputsSink extends BlobSink {
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (msg: string, props?: Record<string, unknown>) => void };
}

export interface InputsOpts {
  roots: string[];
  referenceRoots?: string[];
  referenceOver?: number;
  maxFileBytes?: number;
  allowSensitiveRoot?: boolean;
  sensitiveRootOptIn?: string[];
  hashReferenced?: boolean;
  /** Override the allowed bases (TEST hook — Deno.makeTempDir lives outside /private/tmp). */
  allowedBases?: string[];
}

type Row = Record<string, unknown>;
type Warn = (m: string) => void;
/**
 * A PATH-SAFE error label. Deno FS error `.message` embeds the ABSOLUTE path
 * (`open '/private/tmp/...'`), which must never enter the sealed record — so we
 * surface only the error kind (`NotFound`, `PermissionDenied`, `SyntaxError`, …)
 * alongside the caller's already-root-relative context.
 */
const errName = (e: unknown): string => (e instanceof Error ? e.name : "error");
const uniqSorted = (a: string[]): string[] => [...new Set(a)].sort();

/* ============================ accession harvest ============================ */
const SRA_RE = /^(SRR|ERR|DRR)\d+$/;
const REFSEQ_RE = /^GC[AF]_\d+\.\d+$/;

function harvestManifestTsv(text: string, sra: Set<string>): void {
  // manifest.tsv is SPACE-delimited despite the name (verified on gdh/sirt) — split on
  // any whitespace, take field 0, keep only real run accessions (skips header/junk).
  for (const line of text.split("\n")) {
    const first = line.trim().split(/\s+/)[0];
    if (first && SRA_RE.test(first)) sra.add(first);
  }
}
function harvestAssembliesJson(
  text: string,
  refseq: Set<string>,
  warn: Warn,
  where: string,
): void {
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    for (const v of Object.values(obj)) {
      const a = (v as Row)?.assembly;
      if (typeof a === "string" && REFSEQ_RE.test(a)) refseq.add(a);
    }
  } catch {
    warn(`malformed ${where} (not JSON) — accessions degraded`);
  }
}

/* ============================ auto-derive roots ============================ */
const TMP_BASES = ["/private/tmp/", "/tmp/"];
/**
 * Zero-config path for the standard capture flow: when the caller supplies NO
 * roots, derive them from the session's OWN trace — the distinct top-level
 * `/tmp` working dirs this project's cells actually read or wrote
 * (`execution_log.files_read`/`files_written`). Only `/private/tmp`,`/tmp` bases
 * are considered, and every derived root is still run through `validateRoot`
 * downstream, so this never widens the security envelope — it only removes the
 * manual allowlist burden that got `capture_inputs` skipped. Deleted dirs (swept
 * from /tmp) simply fail validation → captured as empty, honestly.
 */
export function deriveTmpRoots(rows: Row[]): string[] {
  const roots = new Set<string>();
  const consider = (paths: unknown): void => {
    if (typeof paths !== "string" || !paths) return;
    let arr: unknown;
    try {
      arr = JSON.parse(paths);
    } catch {
      return;
    }
    if (!Array.isArray(arr)) return;
    for (const e of arr) {
      const p = typeof e === "string" ? e : (e as Row)?.path;
      if (typeof p !== "string") continue;
      for (const base of TMP_BASES) {
        if (p.startsWith(base)) {
          const seg = p.slice(base.length).split("/")[0];
          if (seg) roots.add(base + seg); // e.g. /private/tmp/quant
          break;
        }
      }
    }
  };
  for (const r of rows) {
    consider(r.files_written);
    consider(r.files_read);
  }
  return [...roots].sort();
}

/* ============================ the capture ============================ */
export async function captureInputs(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: InputsSink,
  opts: InputsOpts,
): Promise<{ inputs: Inputs; dataHandles: unknown[] }> {
  const warnings: string[] = [];
  const warn: Warn = (m) => warnings.push(m);
  const maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const referenceOver = opts.referenceOver ?? null;

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
  sink.logger.info("capture_inputs start", {
    project: projectArg,
    roots: opts.roots.length,
  });

  const { path: clone, cleanup } = await cloneDb(dbPath);
  const blobStore = makeBlobStore();
  try {
    const projects = (await readClone(clone, QUERIES.projects_all())) as Row[];
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);
    const projName = (proj.name ?? null) as string | null;

    // ---- zero-config: derive /tmp roots from the session's own trace ----
    // When no roots are supplied, freeze the /tmp working dirs this project
    // actually touched (per execution_log). Makes capture_inputs safe to run
    // unconditionally in the standard capture flow — no manual allowlist.
    let rootsIn = opts.roots;
    if (rootsIn.length === 0) {
      const files = (await readClone(
        clone,
        QUERIES.execution_files(pid),
      )) as Row[];
      rootsIn = deriveTmpRoots(files);
      sink.logger.info("capture_inputs auto-derived roots from trace", {
        derived: rootsIn.length,
      });
      if (rootsIn.length === 0) {
        warn("no /tmp roots found in trace — nothing to freeze");
      }
    }

    // ---- validate every root (allowlist) ----
    const accepted: { root: string; resolved: string; prefixes: string[] }[] =
      [];
    for (const root of rootsIn) {
      const v = await validateRoot(root, {
        allowedBases: opts.allowedBases,
        allowSensitiveRoot: opts.allowSensitiveRoot,
        sensitiveRootOptIn: opts.sensitiveRootOptIn,
      });
      if (v.ok) {
        accepted.push({
          root,
          resolved: v.resolved,
          prefixes: rootPrefixes(v.resolved),
        });
      } else warn(`root rejected (${v.reason})`); // no absolute path echoed
    }
    // most-specific first: a file under overlapping roots is owned by the longest resolved root
    accepted.sort((a, b) => b.resolved.length - a.resolved.length);
    // dedup roots that canonicalize to the SAME path (a root listed twice, or /tmp/x +
    // /private/tmp/x aliasing) — else per-root output double-counts the same bytes.
    {
      const seenResolved = new Set<string>();
      for (let i = accepted.length - 1; i >= 0; i--) {
        if (seenResolved.has(accepted[i].resolved)) accepted.splice(i, 1);
        else seenResolved.add(accepted[i].resolved);
      }
    }

    // ---- canonicalize referenceRoots; warn if not under any accepted root ----
    const refResolved: string[] = [];
    for (const rr of opts.referenceRoots ?? []) {
      const real = await Deno.realPath(rr).catch(() => null);
      if (!real) {
        warn("a referenceRoot does not exist / cannot be canonicalized");
        continue;
      }
      if (!accepted.some((a) => containedRel(a.prefixes, real) !== null)) {
        warn("a referenceRoot is under no accepted walk root — ignored");
        continue; // truly ignore it: never let it force in-tree files by-reference
      }
      refResolved.push(real);
    }
    const isReferenced = (canonical: string): boolean =>
      refResolved.some((r) => canonical === r || canonical.startsWith(r + "/"));

    // ---- merge + dedup by canonical path (most-specific owning root wins) ----
    const owned = new Map<string, { resolvedRoot: string; relPath: string }>();
    let skippedOutside = 0;
    for (const a of accepted) {
      for (const filePath of await walkSorted(a.resolved)) {
        const canonical = await Deno.realPath(filePath).catch(() => null);
        if (!canonical || owned.has(canonical)) continue; // dedup: first (most-specific) wins
        const rel = containedRel(a.prefixes, canonical);
        if (rel === null) {
          skippedOutside++; // escaped containment (e.g. symlinked file) — count, never echo
          continue;
        }
        owned.set(canonical, { resolvedRoot: a.resolved, relPath: rel });
      }
    }

    // ---- per-file: copy / reference / accession ----
    const byRoot = new Map<string, z.infer<typeof RootEntry>>();
    for (const a of accepted) {
      byRoot.set(a.resolved, {
        root: a.root,
        resolvedRoot: a.resolved,
        copied: [],
        referenced: [],
        totals: { files: 0, copiedBytes: 0, referencedBytes: 0 },
      });
    }
    const sraSet = new Set<string>();
    const refseqSet = new Set<string>();
    let copiedBytes = 0;
    let referencedBytes = 0;
    let secretShapedCount = 0;
    let frozen = 0; // files actually copied or referenced (NOT merely discovered)

    for (const canonical of [...owned.keys()].sort()) {
      const { resolvedRoot, relPath } = owned.get(canonical)!;
      const entry = byRoot.get(resolvedRoot)!;
      const base = relPath.slice(relPath.lastIndexOf("/") + 1);
      // lstat (NOT stat): if `canonical` was swapped for a symlink AFTER we realPath'd it
      // during the walk, we detect it here and refuse to follow — never redirect a copy
      // out of the tree (TOCTOU on the world-writable /tmp). A vanished/non-file owned path
      // is warned, not silently dropped (keeps totals honest + auditable).
      let stat: Deno.FileInfo;
      try {
        stat = await Deno.lstat(canonical);
      } catch {
        warn(`input ${relPath} vanished before capture — skipped`);
        continue;
      }
      if (stat.isSymlink) {
        skippedOutside++;
        warn(`input ${relPath} became a symlink before capture — skipped`);
        continue;
      }
      if (!stat.isFile) {
        warn(`input ${relPath} is not a regular file — skipped`);
        continue;
      }
      const isAccession = ACCESSION_RE.test(base);
      const wantReference = !isAccession &&
        (isReferenced(canonical) ||
          (referenceOver !== null && stat.size > referenceOver));

      try {
        if (wantReference) {
          let sha: string | undefined;
          if (opts.hashReferenced) {
            // maxFileBytes:0 → copyFileToBlob hashes without writing bytes
            sha = (await blobStore.copyFileToBlob(canonical, sink, {
              maxFileBytes: 0,
              noFollow: true,
            })).sha;
          }
          entry.referenced.push({
            relPath,
            size: stat.size,
            ...(sha ? { sha } : {}),
          });
          entry.totals.referencedBytes += stat.size;
          referencedBytes += stat.size;
        } else {
          const res = await blobStore.copyFileToBlob(canonical, sink, {
            maxFileBytes,
            noFollow: true,
          });
          if (res.skipped) {
            // over the cap → by-reference (no unbounded copy-root hoard)
            entry.referenced.push({ relPath, size: res.size, sha: res.sha });
            entry.totals.referencedBytes += res.size;
            referencedBytes += res.size;
          } else {
            entry.copied.push({ relPath, sha: res.sha, size: res.size });
            entry.totals.copiedBytes += res.size;
            copiedBytes += res.size;
            // Harvest + tripwire from the bytes we JUST froze (res.bytes) — never re-read
            // `canonical` (a re-read reopens the path → reintroduces the TOCTOU window the
            // noFollow copy just closed, and doubles the I/O). res.bytes is present for every
            // small copy; a manifest too large for the small path (>streamThreshold) is frozen
            // but not harvested inline (warned, auditable — a >64MiB manifest is pathological).
            if (res.bytes) {
              const text = new TextDecoder().decode(res.bytes);
              // accession harvest (small copied manifests only) — gate aligned with the copy
              // predicate so a bare `manifest` (no ext) is harvested, not just copied.
              if (/^manifest$|manifest.*\.tsv$/i.test(base)) {
                harvestManifestTsv(text, sraSet);
              } else if (base === "assemblies.json") {
                harvestAssembliesJson(text, refseqSet, warn, relPath);
              }
              // secret tripwire over small text-like copies (relPath as `where` — no abs)
              if (res.size < TRIPWIRE_MAX && textLike(canonical)) {
                const before = warnings.length;
                secretTripwire(text, warn, relPath);
                if (warnings.length > before) secretShapedCount++;
              }
            } else if (
              /^manifest$|manifest.*\.tsv$/i.test(base) ||
              base === "assemblies.json"
            ) {
              warn(
                `accessions not harvested for ${relPath} — file too large for inline scan`,
              );
            }
          }
        }
        entry.totals.files++;
        frozen++;
      } catch (e) {
        warn(`input ${relPath} degraded: ${errName(e)}`);
      }
    }

    const writeManifest = blobStore.manifest();
    const inputs: Inputs = {
      sensitive: true,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: projName },
      },
      capturedRoots: accepted.map((a) => a.root),
      referenceRoots: opts.referenceRoots ?? [],
      referenceOver,
      maxFileBytes,
      roots: accepted.map((a) => byRoot.get(a.resolved)!),
      accessions: {
        sra: uniqSorted([...sraSet]),
        refseq: uniqSorted([...refseqSet]),
        ena: [],
      },
      totals: {
        files: frozen, // files actually frozen (copied+referenced), not merely discovered
        copiedBytes,
        referencedBytes,
        secretShapedCount,
        skippedOutside,
      },
      writeManifest,
      warnings,
    };
    InputsSchema.parse(inputs);
    const handle = await sink.writeResource("inputs", pid, inputs);
    sink.logger.info(`inputs for ${projName ?? pid}`, {
      project: pid,
      roots: accepted.length,
      copiedBytes,
      referencedBytes,
      sra: sraSet.size,
      refseq: refseqSet.size,
      secretShaped: secretShapedCount,
      skippedOutside,
      warnings: warnings.length,
    });
    return { inputs, dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
