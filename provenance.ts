/**
 * @vcjdeboer/session-ingest — provenance.ts
 *
 * `capture_provenance`: reconstruct the **turn -> execution -> artifact -> env**
 * provenance graph of a QUIESCENT Claude Science session as a typed, verbatim,
 * deterministic, witness-sealable `provenance` record.
 *
 * DECISIONS (settled through adversarial review):
 *  - The CELL node is COLLAPSED into EXECUTION. `artifact_versions.cell_sources`
 *    is a denormalized subset of `execution_log`; the canonical execution node is
 *    `execution_log` keyed by `id`. (producing_cell_id -> execution_log.id,
 *    verified 20/20 on gdh.)
 *  - Node-id scheme: artifact = `artifact_versions.id`; execution =
 *    `execution_log.id`; env = `env_snapshot_hash` (64hex). Edges carry
 *    `{from,to,kind}` over those ids.
 *  - VERBATIM + DETERMINISTIC: reads a STATIC clone (db.ts cloneDb; source never
 *    mutated), `artifact_provenance` is ORDER BY (created_at,id) and every derived
 *    set (distinct executions/envs, refs) is emitted in first-seen order, so two
 *    runs produce byte-identical output (sealable).
 *  - INJECTION-GATED at the readClone CALL SITE: a producing_cell_id / conda log
 *    id is validated FRAME_ID_RE and an env hash HASH_RE *before* it is ever
 *    interpolated into SQL; a value that fails the gate is skipped + warned, never
 *    interpolated.
 *  - Large `source`/`stdout`/`stderr`/env-package content is offloaded to
 *    content-addressed `body` files via the shared per-invocation `makeStore`
 *    (files-first-then-index); small content stays inline.
 *  - CONTENT_SECRET_RE tripwire (WARN-only) over captured text; the `provenance`
 *    resource is SENSITIVE. Per-item try/catch degrades + warns (drift-tolerant).
 * @module
 */
import { z } from "npm:zod@4";
import {
  assertQuiescent,
  cloneDb,
  FRAME_ID_RE,
  HASH_RE,
  preflightSqlite,
  PROJ_ID_RE,
  QUERIES,
  readClone,
  resolveOrgDir,
} from "./db.ts";
import {
  type FileSink,
  makeStore,
  secretTripwire,
  type Store,
} from "./store.ts";

const BODY_INLINE_CAP = 2000; // chars; larger text offloads to a content-addressed file

/* ============================ schema ============================ */
export const EdgeKind = z.enum([
  "produces", // turn (frame) -> artifact (via _artifact_refs.version_id)
  "producedBy", // artifact -> execution (via producing_cell_id)
  "dependsOn", // artifact -> artifact (dependency_mappings.artifact_id + parent_version_id)
  "wrote", // execution -> file PATH (files_written; a workspace-path id-space, not an artifact node id)
  "read", // execution -> file PATH (files_read; a workspace-path id-space, not an artifact node id)
  "inEnv", // artifact -> env (env_snapshot_hash)
  "ranInEnv", // execution -> env-name (conda_env; a NAME not a hash — exposes drift)
]);

export const ArtifactNode = z.object({
  id: z.string(), // artifact_versions.id
  artifactId: z.string().nullable(),
  versionNumber: z.number().nullable(),
  checksum: z.string().nullable(),
  storagePath: z.string().nullable(),
  language: z.string().nullable(),
  isIntermediate: z.boolean().nullable(),
  frameId: z.string().nullable(),
  envSnapshotHash: z.string().nullable(),
});
export const ExecutionNode = z.object({
  id: z.string(), // execution_log.id
  frameId: z.string().nullable(),
  cellIndex: z.number().nullable(),
  kernelId: z.string().nullable(),
  condaEnv: z.string().nullable(),
  language: z.string().nullable(),
  exitStatus: z.number().nullable(),
  errorLineno: z.number().nullable(),
  origin: z.string().nullable(),
  source: z.string().optional(),
  sourceFileRef: z.string().optional(),
  stdout: z.string().optional(),
  stdoutFileRef: z.string().optional(),
  stderr: z.string().optional(),
  stderrFileRef: z.string().optional(),
});
export const EnvNode = z.object({
  id: z.string(), // env_snapshot_hash (64hex)
  environmentName: z.string().nullable(),
  packages: z.array(z.unknown()).optional(),
  packagesFileRef: z.string().optional(),
});
export const EdgeSchema = z.object({
  from: z.string(),
  to: z.string(),
  kind: EdgeKind,
});

export const ProvenanceSchema = z.object({
  sensitive: z.literal(true),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  nodes: z.object({
    artifacts: z.array(ArtifactNode),
    executions: z.array(ExecutionNode),
    envs: z.array(EnvNode),
  }),
  edges: z.array(EdgeSchema),
  writeManifest: z.array(z.string()), // shas of offloaded body files
  warnings: z.array(z.string()),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;
export type Edge = z.infer<typeof EdgeSchema>;

/** What capture_provenance needs from the model's execute context. */
export interface ProvSink extends FileSink {
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (msg: string, props?: Record<string, unknown>) => void };
}

type Warn = (m: string) => void;
type Row = Record<string, unknown>;

const str = (v: unknown): string | null =>
  v === null || v === undefined || v === "" ? null : String(v);
const num = (v: unknown): number | null => {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};
export const jsonArray = (
  v: unknown,
  warn: (m: string) => void,
  where: string,
): unknown[] => {
  const s = str(v);
  if (!s) return [];
  try {
    const parsed = JSON.parse(s);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    warn(`malformed ${where} (not JSON) — degraded to empty`);
    return [];
  }
};

/**
 * The FILESYSTEM PATH of a CS file descriptor `{path, sha256, ...}` (or a bare
 * string) — path ONLY, never the sha (unlike `fileTarget`, whose sha fallback is
 * an EDGE identity). corpus copying needs the concrete path to open; a path-less
 * descriptor returns null (caller records it as a no-path descriptor).
 */
export function descriptorPath(entry: unknown): string | null {
  if (typeof entry === "string") return entry || null;
  if (entry && typeof entry === "object") {
    const o = entry as Row;
    return str(o.path);
  }
  return null;
}

/**
 * A files_written/files_read entry is a workspace file descriptor
 * `{path, sha256, ...}` (verified on gdh), or occasionally a bare path string.
 * Returns a stable file identity: path preferred, else the content sha, else the
 * raw string. Never `String(obj)` — that would emit "[object Object]" edges.
 */
function fileTarget(entry: unknown): string | null {
  if (typeof entry === "string") return entry || null;
  if (entry && typeof entry === "object") {
    const o = entry as Row;
    return str(o.path) ?? str(o.sha256) ?? null;
  }
  return null;
}

/** Offload text over the cap; return either an inline value or a *FileRef. */
async function inlineOrOffload(
  text: string | null,
  store: Store,
  warn: Warn,
  where: string,
): Promise<{ inline?: string; ref?: string }> {
  if (text === null) return {};
  secretTripwire(text, warn, where);
  if (text.length > BODY_INLINE_CAP) return { ref: await store.offload(text) };
  return { inline: text };
}

/* ============================ the capture ============================ */
export async function captureProvenance(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: ProvSink,
): Promise<{ provenance: Provenance; dataHandles: unknown[] }> {
  const warnings: string[] = [];
  const warn: Warn = (m) => warnings.push(m);

  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  // existence check with a clear message (parity with buildManifest) before cloneDb's raw ENOENT
  try {
    await Deno.stat(dbPath);
  } catch {
    throw new Error(`operon-cli.db not found at ${dbPath}`);
  }
  await assertQuiescent(dbPath);
  // entry log: a start/no-completion pair is visible if a drifted schema throws mid-capture
  sink.logger.info(`capture_provenance start`, { project: projectArg, org });

  const { path: clone, cleanup } = await cloneDb(dbPath); // static copy; source never touched
  const store = makeStore();
  try {
    // resolve project — match in TS (no user input in SQL)
    const projects = (await readClone(clone, QUERIES.projects_all())) as Row[];
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);
    const projName = (proj.name ?? null) as string | null;

    const artifacts: z.infer<typeof ArtifactNode>[] = [];
    const executions: z.infer<typeof ExecutionNode>[] = [];
    const envs: z.infer<typeof EnvNode>[] = [];
    const edges: Edge[] = [];
    const seenExec = new Set<string>(); // distinct producing_cell_ids, first-seen order
    const seenEnv = new Set<string>(); // distinct env hashes, first-seen order
    const pushEdge = (
      from: string,
      to: string,
      kind: z.infer<typeof EdgeKind>,
    ) => edges.push({ from, to, kind });

    // ---- artifacts (ordered created_at,id -> deterministic) ----
    // Defensive: the CS schema is foreign + unversioned; a dropped/renamed column
    // must degrade to a (possibly empty) record, never throw the whole method.
    let artRows: Row[] = [];
    try {
      artRows =
        (await readClone(clone, QUERIES.artifact_provenance(pid))) as Row[];
    } catch (e) {
      warn(
        `artifact_provenance degraded: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
    for (const r of artRows) {
      const id = str(r.id);
      if (!id) {
        warn("artifact_versions row with null id — skipped");
        continue;
      }
      const envHash = str(r.env_snapshot_hash);
      artifacts.push({
        id,
        artifactId: str(r.artifact_id),
        versionNumber: num(r.version_number),
        checksum: str(r.checksum),
        storagePath: str(r.storage_path),
        language: str(r.language),
        isIntermediate:
          r.is_intermediate === null || r.is_intermediate === undefined
            ? null
            : Number(r.is_intermediate) === 1,
        frameId: str(r.frame_id),
        envSnapshotHash: envHash,
      });

      // artifact -> execution (producing_cell_id), gated FRAME_ID_RE at the call site
      const producing = str(r.producing_cell_id);
      if (producing) {
        if (FRAME_ID_RE.test(producing)) {
          pushEdge(id, producing, "producedBy");
          if (!seenExec.has(producing)) seenExec.add(producing);
        } else {
          warn(`skipping producing_cell_id (failed FRAME_ID_RE): ${producing}`);
        }
      }

      // artifact -> env (env_snapshot_hash), gated HASH_RE at the call site
      if (envHash) {
        if (HASH_RE.test(envHash)) {
          pushEdge(id, envHash, "inEnv");
          if (!seenEnv.has(envHash)) seenEnv.add(envHash);
        } else {
          warn(`skipping env_snapshot_hash (failed HASH_RE): ${envHash}`);
        }
      }

      // artifact -> artifact (dependency_mappings.inputs[].artifact_id + parent_version_id backbone)
      const parent = str(r.parent_version_id);
      if (parent) pushEdge(id, parent, "dependsOn");
      const depsStr = str(r.dependency_mappings);
      if (depsStr) {
        try {
          const deps = JSON.parse(depsStr) as { inputs?: unknown[] };
          const inputs = Array.isArray(deps.inputs) ? deps.inputs : [];
          for (const inp of inputs) {
            const aid = str((inp as Row)?.artifact_id);
            if (aid) pushEdge(id, aid, "dependsOn");
          }
        } catch {
          warn(`malformed dependency_mappings for ${id} (not JSON) — degraded`);
        }
      }
    }

    // ---- artifact -> artifact: NORMALIZED version-precise dependency edges ----
    // artifact_dependencies is the authoritative version->version DAG CS records
    // (more precise than the artifact-level dependency_mappings above). Additive
    // and deduped against dependsOn edges already pushed; degrades if absent.
    const seenDep = new Set(
      edges.filter((e) => e.kind === "dependsOn").map((e) =>
        `${e.from}>${e.to}`
      ),
    );
    let depRows: Row[] = [];
    try {
      depRows = (await readClone(
        clone,
        QUERIES.artifact_dependency_edges(pid),
      )) as Row[];
    } catch (e) {
      warn(
        `artifact_dependencies degraded: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
    for (const r of depRows) {
      const from = str(r.artifact_version_id);
      const to = str(r.depends_on_version_id);
      if (!from || !to) continue;
      if (!FRAME_ID_RE.test(from) || !FRAME_ID_RE.test(to)) {
        warn(`skipping artifact_dependencies edge (bad UUID): ${from}->${to}`);
        continue;
      }
      const key = `${from}>${to}`;
      if (seenDep.has(key)) continue;
      seenDep.add(key);
      pushEdge(from, to, "dependsOn");
    }

    // ---- executions (distinct producing_cell_ids, first-seen order) ----
    for (const logId of seenExec) {
      try {
        const rows =
          (await readClone(clone, QUERIES.execution_by_id(logId))) as Row[];
        if (rows.length === 0) {
          warn(`execution_log row absent for ${logId} — no execution node`);
          continue;
        }
        const r = rows[0];
        const source = await inlineOrOffload(
          str(r.source),
          store,
          warn,
          "execution.source",
        );
        const stdout = await inlineOrOffload(
          str(r.stdout),
          store,
          warn,
          "execution.stdout",
        );
        const stderr = await inlineOrOffload(
          str(r.stderr),
          store,
          warn,
          "execution.stderr",
        );
        const node: z.infer<typeof ExecutionNode> = {
          id: logId,
          frameId: str(r.frame_id),
          cellIndex: num(r.cell_index),
          kernelId: str(r.kernel_id),
          condaEnv: str(r.conda_env),
          language: str(r.language),
          exitStatus: num(r.exit_status),
          errorLineno: num(r.error_lineno),
          origin: str(r.origin),
        };
        if (source.inline !== undefined) node.source = source.inline;
        if (source.ref !== undefined) node.sourceFileRef = source.ref;
        if (stdout.inline !== undefined) node.stdout = stdout.inline;
        if (stdout.ref !== undefined) node.stdoutFileRef = stdout.ref;
        if (stderr.inline !== undefined) node.stderr = stderr.inline;
        if (stderr.ref !== undefined) node.stderrFileRef = stderr.ref;
        executions.push(node);

        // execution -> file (files_written / files_read). CS stores these as file
        // DESCRIPTORS {path, sha256, ...} (verified on gdh), occasionally bare strings.
        // The edge target is the workspace file PATH (a distinct id-space from artifact
        // node ids — see EdgeKind), falling back to the content sha then the raw string.
        for (
          const w of jsonArray(
            r.files_written,
            warn,
            `files_written for ${logId}`,
          )
        ) {
          const t = fileTarget(w);
          if (t) pushEdge(logId, t, "wrote");
        }
        for (
          const rd of jsonArray(r.files_read, warn, `files_read for ${logId}`)
        ) {
          const t = fileTarget(rd);
          if (t) pushEdge(logId, t, "read");
        }
        // execution -> env-name (conda_env; a NAME, not a hash — exposes env drift)
        const condaEnv = str(r.conda_env);
        if (condaEnv) pushEdge(logId, condaEnv, "ranInEnv");
      } catch (e) {
        warn(
          `execution ${logId} degraded (skipped): ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
    }

    // ---- envs (distinct env hashes, first-seen order) ----
    for (const hash of seenEnv) {
      try {
        const rows =
          (await readClone(clone, QUERIES.env_content(hash))) as Row[];
        if (rows.length === 0) {
          warn(`content_snapshots row absent for ${hash} — no env node`);
          continue;
        }
        const content = str(rows[0].content);
        let environmentName: string | null = null;
        let packages: unknown[] | undefined;
        let packagesFileRef: string | undefined;
        if (content) {
          secretTripwire(content, warn, "env.content");
          try {
            const obj = JSON.parse(content) as {
              environment_name?: unknown;
              packages?: unknown;
            };
            environmentName = str(obj.environment_name);
            const pkgs = Array.isArray(obj.packages) ? obj.packages : [];
            const pkgText = JSON.stringify(pkgs);
            if (pkgText.length > BODY_INLINE_CAP) {
              packagesFileRef = await store.offload(pkgText);
            } else {
              packages = pkgs;
            }
          } catch {
            warn(`malformed env content for ${hash} (not JSON) — degraded`);
          }
        }
        const node: z.infer<typeof EnvNode> = { id: hash, environmentName };
        if (packages !== undefined) node.packages = packages;
        if (packagesFileRef !== undefined) {
          node.packagesFileRef = packagesFileRef;
        }
        envs.push(node);
      } catch (e) {
        warn(
          `env ${hash} degraded (skipped): ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
    }

    // ---- turn -> artifact (_artifact_refs.version_id), ordered (frame_id,idx) ----
    try {
      const refRows =
        (await readClone(clone, QUERIES.artifact_refs(pid))) as Row[];
      for (const r of refRows) {
        const frameId = str(r.frame_id);
        if (!frameId) continue;
        for (const versionId of extractVersionIds(r.refs, warn)) {
          pushEdge(frameId, versionId, "produces");
        }
      }
    } catch (e) {
      warn(
        `artifact_refs degraded: ${e instanceof Error ? e.message : String(e)}`,
      );
    }

    // WRITE PROTOCOL: files FIRST (content-addressed, idempotent), then the index.
    const writeManifest = await store.flush(sink);

    const provenance: Provenance = {
      sensitive: true,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: projName },
      },
      nodes: { artifacts, executions, envs },
      edges,
      writeManifest,
      warnings,
    };
    ProvenanceSchema.parse(provenance); // validate before write (no partial/invalid record)
    const handle = await sink.writeResource("provenance", pid, provenance);
    sink.logger.info(`provenance for ${projName ?? pid}`, {
      project: pid,
      artifacts: artifacts.length,
      executions: executions.length,
      envs: envs.length,
      edges: edges.length,
      offloadedFiles: writeManifest.length,
      warnings: warnings.length,
    });
    return { provenance, dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}

/**
 * `_artifact_refs` is `{ <filename>: { artifact_id, version_id }, … }` (verified on
 * gdh); tolerate an array-of-refs shape too. Returns the version_ids (artifact node ids).
 */
function extractVersionIds(refs: unknown, warn: Warn): string[] {
  const out: string[] = [];
  const take = (v: unknown) => {
    const id = str((v as Row)?.version_id);
    if (id) out.push(id);
  };
  let parsed: unknown = refs;
  if (typeof refs === "string") {
    try {
      parsed = JSON.parse(refs);
    } catch {
      warn("malformed _artifact_refs (not JSON) — degraded");
      return out;
    }
  }
  if (parsed && typeof parsed === "object") {
    if (Array.isArray(parsed)) parsed.forEach(take);
    else {for (const v of Object.values(parsed as Record<string, unknown>)) {
        take(v);
      }}
  }
  return out;
}
