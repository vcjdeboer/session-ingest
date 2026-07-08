/**
 * @vcjdeboer/session-ingest — corpus.ts
 *
 * `capture_corpus`: a COMPLETE, IMMUTABLE, content-addressed byte COPY of a
 * quiescent Claude Science session into swamp's own store — so the record
 * survives a CS sweep / uninstall / upgrade. Real bytes, never symlinks (a link
 * dies when CS wipes the target and can't be witnessed).
 *
 * DECISIONS (settled through 3 plan-review cycles):
 *  - Copies ALL artifact_versions bytes + PROJECT-SCOPED workspace bytes (files
 *    this project's executions touched, via execution_log.files_written/read, +
 *    files present under workspace dirs OWNED by this project — basename = one of
 *    the project's parentless root frame ids). NEVER blanket workspaces/** (that
 *    dir is org-wide → would leak other projects + shared MCP tooling).
 *  - MEMORY-SAFE: streams via makeBlobStore (one file at a time, sha SET dedup,
 *    never a Map of bytes) → peak RSS bounded to a single file/chunk, not the
 *    multi-GB corpus. An opt-in maxFileBytes records over-cap files by-reference.
 *  - DRIFT/TAMPER: recompute sha256 and compare to CS's recorded checksum
 *    (normalized) → mismatch = drift evidence (feeds session-witness). null/absent
 *    checksum → 'unverifiable' (distinct from drift).
 *  - PATH SAFETY: every copy path is canonicalized and asserted to resolve UNDER
 *    the org tree; anything outside (a drifted/hostile files_written naming
 *    ~/.ssh) is warned + skipped. Stored paths are org-RELATIVE (portable).
 *  - DETERMINISTIC (sorted walks + ORDER BY queries) → witness-sealable.
 *  - Read-only over the file tree (the DB is cloned); source NEVER mutated.
 *    Sampled secret tripwire over small text-like files; resource SENSITIVE.
 * @module
 */
import { z } from "npm:zod@4";
import { normalize, resolve } from "jsr:@std/path@1.1.5";
import {
  artifactsBaseDir,
  assertQuiescent,
  cloneDb,
  FRAME_ID_RE,
  preflightSqlite,
  PROJ_ID_RE,
  QUERIES,
  readClone,
  remoteCompute,
  resolveOrgDir,
} from "./db.ts";
import { descriptorPath, jsonArray } from "./provenance.ts";
import { type BlobSink, makeBlobStore, secretTripwire } from "./store.ts";
import { containedRel, textLike, TRIPWIRE_MAX, walkSorted } from "./paths.ts";

/* ============================ schema ============================ */
export const ArtifactEntry = z.object({
  versionId: z.string().nullable(),
  artifactId: z.string().nullable(),
  storagePath: z.string().nullable(),
  checksum: z.string().nullable(),
  isIntermediate: z.boolean().nullable(),
  present: z.boolean(),
  actualSha: z.string().optional(),
  size: z.number().optional(),
  drift: z.boolean().optional(),
  unverifiable: z.boolean().optional(),
  skipped: z.boolean().optional(),
});
export const WorkspaceEntry = z.object({
  relPath: z.string(),
  sha: z.string().optional(),
  size: z.number().optional(),
  skipped: z.boolean().optional(),
});
export const LostEntry = z.object({
  workspaceId: z.string().optional(),
  relPath: z.string().optional(),
  outcome: z.string().optional(),
  at: z.string().optional(),
  reason: z.string(),
});
export const CorpusSchema = z.object({
  sensitive: z.literal(true),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  artifacts: z.array(ArtifactEntry),
  workspace: z.array(WorkspaceEntry),
  lost: z.array(LostEntry),
  totals: z.object({
    files: z.number(),
    bytes: z.number(),
    distinctBlobs: z.number(),
    deduped: z.number(),
    secretShapedCount: z.number(),
  }),
  typeStamp: z.enum(["replayable", "witnessed"]),
  writeManifest: z.array(z.string()),
  warnings: z.array(z.string()),
});
export type Corpus = z.infer<typeof CorpusSchema>;

/** What capture_corpus needs from the model's execute context. */
export interface CorpusSink extends BlobSink {
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (msg: string, props?: Record<string, unknown>) => void };
}

type Row = Record<string, unknown>;
type Warn = (m: string) => void;

const str = (v: unknown): string | null =>
  v === null || v === undefined || v === "" ? null : String(v);
/**
 * Error text with any ABSOLUTE filesystem path redacted to `<path>`. Deno IO errors embed the
 * absolute path in `.message` (`open '/Users/…/orgs/…'`) and this record is SEALED + PORTABLE
 * (org-RELATIVE paths only), so no absolute path may leak into a warning. The `≥2 segments`
 * pattern spares fractions/ratios ("3/4") while catching real paths, and keeps the useful
 * reason (IO kind, "no such table: …") intact.
 */
const safeErr = (e: unknown): string =>
  (e instanceof Error ? e.message : String(e)).replace(
    /\/[^\s'"]*(?:\/[^\s'"]*)+/g,
    "<path>",
  );

/** Normalize a recorded checksum for comparison: strip a leading `sha256:`, lowercase. null/"" → null (unverifiable). */
function normalizeChecksum(c: string | null): string | null {
  if (!c) return null;
  // trim FIRST so a leading-whitespace `  sha256:<hex>` still strips its prefix
  // (else the ^-anchored strip misses and every file falsely reports drift).
  return c.trim().replace(/^sha256:/i, "").trim().toLowerCase() || null;
}

/* ============================ the capture ============================ */
export async function captureCorpus(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: CorpusSink,
  opts: { maxFileBytes?: number } = {},
): Promise<{ corpus: Corpus; dataHandles: unknown[] }> {
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
  sink.logger.info("capture_corpus start", { project: projectArg, org });

  const { path: clone, cleanup } = await cloneDb(dbPath); // static copy; source never touched
  const blobStore = makeBlobStore();
  const orgResolved = resolve(orgDir);
  const orgReal = await Deno.realPath(orgDir).catch(() => orgResolved);
  const orgPrefixes = [...new Set([orgReal, orgResolved])];
  try {
    const projects = (await readClone(clone, QUERIES.projects_all())) as Row[];
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);
    const projName = (proj.name ?? null) as string | null;

    const artifacts: z.infer<typeof ArtifactEntry>[] = [];
    const workspace: z.infer<typeof WorkspaceEntry>[] = [];
    const lost: z.infer<typeof LostEntry>[] = [];
    let bytes = 0;
    let deduped = 0;
    let secretShapedCount = 0;
    let allChecksummedPresent = true;
    let hasDrift = false;
    let outsideOrg = 0;

    // ---- artifacts (ordered) ----
    const artBase = artifactsBaseDir(orgDir);
    let artRows: Row[] = [];
    try {
      artRows =
        (await readClone(clone, QUERIES.artifact_provenance(pid))) as Row[];
    } catch (e) {
      warn(`artifact_provenance degraded: ${safeErr(e)}`);
    }
    for (const r of artRows) {
      const base = {
        versionId: str(r.id),
        artifactId: str(r.artifact_id),
        storagePath: str(r.storage_path),
        checksum: str(r.checksum),
        isIntermediate:
          r.is_intermediate === null || r.is_intermediate === undefined
            ? null
            : Number(r.is_intermediate) === 1,
      };
      if (!base.storagePath) {
        artifacts.push({ ...base, present: false });
        warn(`artifact ${base.versionId} has no storage_path`);
        continue;
      }
      const abs = `${artBase}/${base.storagePath}`;
      let stat: Deno.FileInfo | null = null;
      try {
        stat = await Deno.stat(abs);
      } catch {
        stat = null;
      }
      if (!stat?.isFile) {
        artifacts.push({ ...base, present: false });
        if (base.checksum) allChecksummedPresent = false;
        continue;
      }
      try {
        const res = await blobStore.copyFileToBlob(abs, sink, opts);
        if (!res.skipped) bytes += res.size;
        if (res.deduped) deduped++;
        const entry: z.infer<typeof ArtifactEntry> = {
          ...base,
          present: true,
          actualSha: res.sha,
          size: res.size,
        };
        if (res.skipped) entry.skipped = true;
        const norm = normalizeChecksum(base.checksum);
        if (norm === null) entry.unverifiable = true;
        else if (norm !== res.sha) {
          entry.drift = true;
          hasDrift = true;
          warn(
            `DRIFT: ${base.storagePath} on-disk sha ${res.sha} != recorded ${norm}`,
          );
        }
        artifacts.push(entry);
      } catch (e) {
        warn(`artifact ${base.storagePath} copy degraded: ${safeErr(e)}`);
        artifacts.push({ ...base, present: true });
      }
    }

    // ---- workspaces (project-scoped) ----
    let rootFrames: string[] = [];
    try {
      rootFrames =
        ((await readClone(clone, QUERIES.project_root_frames(pid))) as Row[])
          .map((r) => String(r.id)).filter(Boolean);
    } catch (e) {
      warn(`project_root_frames degraded: ${safeErr(e)}`);
    }
    // gate every root-frame id: a drifted/hostile id like "../../../etc" must never
    // be interpolated into a workspace path (walkSorted would readDir outside the org
    // tree). One FRAME_ID_RE gate covers both the walk and the sweep-ledger match.
    rootFrames = rootFrames.filter((id) => {
      if (FRAME_ID_RE.test(id)) return true;
      warn(`skipping root frame with non-UUID id: ${id}`);
      return false;
    });
    const rootSet = new Set(rootFrames);

    const candidates = new Set<string>();
    // (a) referenced by THIS project's executions (the load-bearing scope)
    try {
      const execRows =
        (await readClone(clone, QUERIES.execution_files(pid))) as Row[];
      for (const r of execRows) {
        for (const col of ["files_written", "files_read"] as const) {
          for (const e of jsonArray(r[col], warn, `${col} for ${str(r.id)}`)) {
            const p = descriptorPath(e);
            if (p) candidates.add(p);
            else {warn(
                `no-path descriptor in ${col} for ${str(r.id)} — skipped`,
              );}
          }
        }
      }
    } catch (e) {
      warn(`execution_files degraded: ${safeErr(e)}`);
    }
    // (b) present files under workspace dirs OWNED by this project
    for (const fid of rootFrames) {
      const dir = `${orgDir}/workspaces/${fid}`;
      let st: Deno.FileInfo | null = null;
      try {
        st = await Deno.stat(dir);
      } catch {
        st = null;
      }
      if (st?.isDirectory) {
        for (const p of await walkSorted(dir)) candidates.add(p);
      }
    }

    for (const abs of [...candidates].sort()) {
      // path safety: resolve symlinks + require containment under the org tree. Operate on
      // the CANONICAL (realpath'd) path for stat/copy/read so the bytes we store are exactly
      // the ones that passed containment (no re-follow of a symlink in `abs` — TOCTOU-safe).
      const real = await Deno.realPath(abs).catch(() => null);
      const canonical = real ?? resolve(normalize(abs));
      const relPath = containedRel(orgPrefixes, canonical);
      if (relPath === null) {
        outsideOrg++; // count only — never echo the absolute out-of-tree path into the record
        continue;
      }
      let stat: Deno.FileInfo | null = null;
      try {
        stat = await Deno.stat(canonical);
      } catch {
        stat = null;
      }
      if (!stat?.isFile) {
        lost.push({ relPath, reason: "referenced workspace file absent" });
        continue;
      }
      try {
        const res = await blobStore.copyFileToBlob(canonical, sink, opts);
        if (!res.skipped) bytes += res.size;
        if (res.deduped) deduped++;
        const entry: z.infer<typeof WorkspaceEntry> = {
          relPath,
          sha: res.sha,
          size: res.size,
        };
        if (res.skipped) {
          entry.skipped = true;
          warn(`workspace file over cap, recorded by-reference: ${relPath}`);
        }
        workspace.push(entry);
        if (!res.skipped && stat.size < TRIPWIRE_MAX && textLike(canonical)) {
          try {
            const text = await Deno.readTextFile(canonical);
            const before = warnings.length;
            secretTripwire(text, warn, relPath);
            if (warnings.length > before) secretShapedCount++;
          } catch { /* unreadable text — ignore */ }
        }
      } catch (e) {
        warn(`workspace ${relPath} copy degraded: ${safeErr(e)}`);
      }
    }
    if (outsideOrg > 0) {
      warn(`skipped ${outsideOrg} path(s) resolving outside the org tree`);
    }

    // ---- provenance-of-loss: swept workspaces (this project's root frames) ----
    const ledgerDir = `${orgDir}/workspaces-sweep-ledger`;
    try {
      const names: string[] = [];
      for await (const e of Deno.readDir(ledgerDir)) {
        if (e.isFile) names.push(e.name);
      }
      names.sort();
      for (const name of names) {
        if (!rootSet.has(name)) continue; // only THIS project's swept root frames
        try {
          const j = JSON.parse(
            await Deno.readTextFile(`${ledgerDir}/${name}`),
          ) as Row;
          lost.push({
            workspaceId: name,
            outcome: str(j.outcome) ?? undefined,
            at: str(j.at) ?? undefined,
            reason: "workspace swept",
          });
        } catch {
          warn(`malformed sweep-ledger entry ${name}`);
        }
      }
    } catch { /* no ledger dir */ }

    // ---- type-stamp (shared remoteCompute predicate; no divergence vs inspect) ----
    let frames: Row[] = [];
    try {
      frames =
        (await readClone(clone, QUERIES.frames_by_project(pid))) as Row[];
    } catch (e) {
      warn(`frames degraded: ${safeErr(e)}`);
    }
    const remote = remoteCompute(frames);
    // 'replayable' is the CLEAN stamp: no remote compute, every checksummed artifact
    // present, AND no detected drift. Any drift is tamper evidence -> 'witnessed'.
    const typeStamp: "replayable" | "witnessed" =
      !remote && allChecksummedPresent && !hasDrift
        ? "replayable"
        : "witnessed";

    const writeManifest = blobStore.manifest();
    const corpus: Corpus = {
      sensitive: true,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: projName },
      },
      artifacts,
      workspace,
      lost,
      totals: {
        files: artifacts.filter((a) => a.present && !a.skipped).length +
          workspace.filter((w) => !w.skipped).length,
        bytes,
        distinctBlobs: writeManifest.length,
        deduped,
        secretShapedCount,
      },
      typeStamp,
      writeManifest,
      warnings,
    };
    CorpusSchema.parse(corpus); // validate before write (no partial/invalid record)
    const handle = await sink.writeResource("corpus", pid, corpus);
    sink.logger.info(`corpus for ${projName ?? pid}`, {
      project: pid,
      artifacts: artifacts.length,
      workspace: workspace.length,
      lost: lost.length,
      blobs: writeManifest.length,
      bytes,
      deduped,
      typeStamp,
      secretShaped: secretShapedCount,
      warnings: warnings.length,
    });
    return { corpus, dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
