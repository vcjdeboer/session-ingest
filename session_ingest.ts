/**
 * @vcjdeboer/session-ingest — lift a finished Claude Science research SESSION
 * out of the app's private, live, mutable SQLite store into an open, typed,
 * portable swamp record you own — one that reproduces without the app.
 *
 * The Ingest member of the `session-*` suite. This file is the thin swamp model;
 * the secret-safe, non-mutating reader lives in `./db.ts`.
 *
 * `inspect` (this release) is READ-ONLY: it resolves a project/session from a
 * QUIESCENT operon-cli.db and emits a `manifest` summary. It never opens the live
 * DB in a mutating way, never reads a secret, and refuses a DB a running session
 * is still writing. Later methods (capture/lock_env/replay/seal) build on the
 * same `db.ts` primitive; credentials that a replay needs live in swamp VAULTS,
 * never in these records.
 *
 * @module
 */
import { z } from "npm:zod@4";
import { buildManifest } from "./db.ts";
import { captureMessages, TranscriptSchema } from "./capture.ts";
import { captureProvenance, ProvenanceSchema } from "./provenance.ts";
import { captureCells, CellsSchema } from "./cells.ts";
import { captureSkills, SkillsSchema } from "./skills.ts";
import { captureHostCalls, HostCallsSchema } from "./hostcalls.ts";
import { captureReview, ReviewSchema } from "./review.ts";
import { captureNotifications, NotificationsSchema } from "./notifications.ts";
import { captureExtras, ExtrasSchema } from "./extras.ts";
import { AnnotationsSchema, captureAnnotations } from "./annotations.ts";
import { captureSettings, SettingsSchema } from "./settings.ts";
import {
  renderHtml,
  RenderHtmlArgsSchema,
  VisualSchema,
} from "./render_html.ts";
import { captureCorpus, CorpusSchema } from "./corpus.ts";
import { captureInputs, InputsSchema } from "./inputs.ts";
import { captureExternal, ExternalSchema } from "./external.ts";
import { captureCredentials, CredentialsSchema } from "./credentials.ts";
import { lockEnv, LockEnvSchema } from "./lockenv.ts";
import { BundleManifestSchema, runSeal, SealArgsSchema } from "./bundle.ts";

/** Parse a JSON-array-string method arg into a non-empty string[] (throws a clear error). */
function parseJsonStringArray(name: string, raw: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `${name} must be a JSON array of strings, e.g. '["/private/tmp/cds"]' — got: ${
        raw.slice(0, 60)
      }`,
    );
  }
  const arr = z.array(z.string().min(1)).safeParse(parsed);
  if (!arr.success || arr.data.length === 0) {
    throw new Error(
      `${name} must be a NON-EMPTY JSON array of non-empty strings`,
    );
  }
  return arr.data;
}

const GlobalArgsSchema = z.object({
  /** Claude Science data root. Default: $HOME/.claude-science. */
  csRoot: z.string().default(""),
  /** Org id under <csRoot>/orgs. Optional when there is exactly one org. */
  orgId: z.string().default(""),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const InspectArgsSchema = z.object({
  /** Project to inspect: a name (e.g. "gdh") or a proj_id (e.g. "proj_0fbe3bb9e459"). */
  project: z.string().min(1),
  /** Override csRoot for this call. */
  csRoot: z.string().default(""),
  /** Override orgId for this call. */
  orgId: z.string().default(""),
});

const ManifestSchema = z.object({
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  artifacts: z.object({
    saved: z.number(),
    intermediate: z.number(),
    distinct: z.number(),
    versions: z.number(),
    byLanguage: z.record(z.string(), z.number()),
  }),
  nDistinctEnvs: z.number(),
  nFrames: z.number(),
  framesByRole: z.record(z.string(), z.number()),
  verificationChecks: z.object({
    total: z.number(),
    byVerdict: z.record(z.string(), z.number()),
  }),
  // A project can hold several top-level sessions; each keeps its own headline +
  // reviewer checks so a multi-session project is not blurred into one.
  sessions: z.array(z.object({
    rootFrameId: z.string(),
    headline: z.string().nullable(),
    createdAt: z.number().nullable(),
    conversationType: z.string().nullable(),
    agentName: z.string().nullable(),
    nFrames: z.number(),
    framesByRole: z.record(z.string(), z.number()),
    verificationChecks: z.object({
      total: z.number(),
      byVerdict: z.record(z.string(), z.number()),
    }),
  })),
  messages: z.object({
    total: z.number(),
    userTyped: z.number(),
    assistant: z.number(),
    toolResults: z.number(),
    systemNotice: z.number(),
    harnessInjected: z.number(),
    unclassified: z.number(),
  }),
  missingFiles: z.array(z.string()),
  remoteCompute: z.boolean(),
  credentialsScope: z.literal("deferred-to-capture"),
  warnings: z.array(z.string()),
});

function resolveCsRoot(
  args: z.infer<typeof InspectArgsSchema>,
  g: GlobalArgs,
): string {
  const explicit = args.csRoot || g.csRoot;
  if (explicit) return explicit;
  const home = Deno.env.get("HOME");
  if (!home) {
    throw new Error(
      "cannot resolve csRoot: $HOME is unset. Pass --input csRoot=<path> or set globalArg csRoot.",
    );
  }
  return `${home}/.claude-science`;
}

const InputsArgsSchema = z.object({
  /** Project the /tmp inputs belong to: a name or a proj_id (keys the record). */
  project: z.string().min(1),
  /** JSON-array string of external roots to freeze, e.g. '["/private/tmp/cds","/private/tmp/sel"]'.
   * OPTIONAL: omit (or "") to AUTO-DERIVE the /tmp roots from the session's own
   * files_read/files_written trace — the zero-config standard-flow path. */
  roots: z.string().default(""),
  /** JSON-array string of roots recorded by-reference (path+size) instead of copied (e.g. the 10GB quant). */
  referenceRoots: z.string().default(""),
  /** Per-file byte threshold above which a file is recorded by-reference. */
  referenceOver: z.number().optional(),
  /** Per-file copy cap; over-cap files are recorded by-reference (default 256 MiB). */
  maxFileBytes: z.number().default(256 * 1024 * 1024),
  /** Allow roots OUTSIDE /private/tmp,/tmp — requires each such root in sensitiveRootOptIn. */
  allowSensitiveRoot: z.boolean().default(false),
  /** JSON-array string of exact sensitive roots explicitly permitted. */
  sensitiveRootOptIn: z.string().default(""),
  /** Also stream-hash referenced files (drift detection over the reference set); default off. */
  hashReferenced: z.boolean().default(false),
  csRoot: z.string().default(""),
  orgId: z.string().default(""),
});

export const model = {
  type: "@vcjdeboer/session-ingest",
  version: "2026.07.15.1",
  globalArguments: GlobalArgsSchema,
  // globalArguments (csRoot, orgId) are UNCHANGED across .11.6 -> .11.9; these releases
  // only touch OUTPUT/behaviour (.11.7 added manifest.sessions[]; .11.8 extends the seal
  // to cover cells/skills/host_calls; .11.9 makes capture_inputs.roots OPTIONAL — it
  // auto-derives /tmp roots from the session trace). No-op upgrades still advance typeVersion.
  upgrades: [
    {
      toVersion: "2026.07.11.7",
      description:
        "Multi-session manifest: additive sessions[] output field; no globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.8",
      description:
        "Seal covers cells/skills/host_calls; no globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.9",
      description:
        "capture_inputs.roots optional — auto-derives /tmp roots from the session trace; no globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.10",
      description:
        "Add the capture-report report (facets, tools/skills, reviewer tally, prompts, figures); no globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.11",
      description:
        "Add capture_review (seal the independent reviewer's verification_checks) + review facet in the seal; capture-report renders the sealed reviewer detail; no globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.12",
      description:
        "capture-report: add required `name` field so the report loads; render sealed review detail; no globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.13",
      description:
        "Add capture_annotations (artifact comments + thread bookmarks) + capture_settings (model/effort, delegation, compute, timeline, toggles, specialists); both in the seal; seal refuses an empty bundle (name-vs-proj_id guard); capture-report gains conclusion/annotations/settings. No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.14",
      description:
        "capture-report gains the narrative arc: research question + plan (from the sealed plan_*.json artifact) alongside the conclusion. No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.15",
      description:
        "capture-report resolves the session from methodArgs.project OR .session, so it renders the right session when triggered by seal. No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.16",
      description:
        "capture-report: resolve facet versions from bundle refs (works via the real dataRepository) + list figures instead of embedding base64 (fits the report store). No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.11.17",
      description:
        "Add render_html method (native Deno visual-HTML renderer of the capture-report, figures embedded); replaces the standalone python tool. No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.12.1",
      description:
        "Close ingest gaps found auditing against CS's own schema: capture_notifications (inter-agent host.delegate messages), capture_extras (compute_usage/session_claims/memories/artifact_folders, each guarded), and authoritative version->version provenance edges from artifact_dependencies (more precise than dependency_mappings). No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.15.1",
      description:
        "capture-report scoping fix: inspect-only (unsealed `manifest`) sessions are now candidates and resolve to THEMSELVES; a requested project never falls back to a different session's sealed bundle (previously an `inspect` on session A rendered the only sealed session B); absent requested project → scoped not-found; honest 'inspected (unsealed)' header + `sealed` flag in the report JSON. No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    "manifest": {
      description:
        "Read-only summary of a Claude Science project's provenance state (counts, frames, reviewer passes, missing artifact files, remote-compute flag) plus a per-session breakdown (each top-level session's headline + own frames + own reviewer checks). Instance key = proj_id. Versioned; sha256 pinning belongs to capture.",
      schema: ManifestSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "cells": {
      description:
        "SENSITIVE: the FULL ordered execution sequence of a session — EVERY cell's source + language + cellIndex (large source offloaded to `body` files). The replay SCRIPT (complements the provenance GRAPH). Instance key = proj_id.",
      schema: CellsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "host_calls": {
      description:
        "SENSITIVE: a session's REPLAYABLE host.* calls — each {method, args, response, isError} in call order, responses inlined from data_inline or resolved from data_ref tapes. Consumed by the session-execute host-replay shim. credentials_request responses scrubbed to presence only (no token). Instance key = proj_id.",
      schema: HostCallsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "review": {
      description:
        "SENSITIVE: the INDEPENDENT REVIEWER's verdicts — CS's out-of-band verification_checks ({verdict, severity, claim, evidence, reviewerModel} in time order) + the verdict tally. Seals WHAT was reviewed and WHY, so the capture-report shows reviewer detail from sealed data (not just the manifest tally). claim/evidence are analysis prose, never a credential. Instance key = proj_id.",
      schema: ReviewSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "notifications": {
      description:
        "SENSITIVE: the PARENT<->CHILD delegation messages (CS `notifications`) exchanged within a session's frame tree when it used host.delegate — the coordination layer (task payloads, results) the per-frame transcript doesn't carry, in time order + a per-type tally. payload is coordination/analysis prose, never a credential. Instance key = proj_id.",
      schema: NotificationsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "extras": {
      description:
        "SENSITIVE: the lower-frequency CS metadata tables sealed so nothing is silently dropped — remote-compute jobs (`compute_usage`), the falsifiable claims extracted incl. UNCHECKED ones (`session_claims`), durable agent beliefs (`memories`), and artifact folder structure (`artifact_folders`). Each read under its own guard: a table absent on this build degrades to an empty list + a warning. Instance key = proj_id.",
      schema: ExtrasSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "annotations": {
      description:
        "SENSITIVE: the user's own marks on a session — artifact COMMENTS + thread BOOKMARKS/highlights (kind, anchor, note, offsets, origin, timestamps). anchor_text/note are user prose. Instance key = proj_id.",
      schema: AnnotationsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "settings": {
      description:
        "HOW the session was run: LLM model(s) + effort, delegation (sub-agents like the reviewer), compute target, the session timeline (first→last frame), the user capability toggles (memory/delegation/auto-review) and bundled specialist agents. Counts + flags only, never a credential. Instance key = proj_id.",
      schema: SettingsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "visual": {
      description:
        "Provenance record for a render_html run: the .html path written, its size, and how many figures were embedded. The HTML itself is a file on disk (the visual companion to the capture-report). Instance key = proj_id.",
      schema: VisualSchema,
      lifetime: "30d",
      garbageCollection: 5,
    },
    "skills": {
      description:
        "SENSITIVE: the CS SKILLS a session used — each used skill's kernel.py (content-addressed body blob) + the exported symbols that judged it used. The injected context (e.g. figure-style -> apply_figure_style) a replay prepends. Instance key = proj_id.",
      schema: SkillsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "bundle-manifest": {
      description:
        "The logical, order-stable index of a sealed session: every captured resource (name + swamp content checksum + content-ref) in canonical order, plus the reproducibility stamp (witnessed / replayable-nix / replayable-docker) and origin. The witness DIGEST over these items is produced by @vcjdeboer/session-witness seal_manifest (the seal-bundle workflow). Instance key = proj_id.",
      schema: BundleManifestSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "transcript": {
      description:
        "SENSITIVE/PRIVATE: the VERBATIM, typed, ordered message transcript of a session (turns + typed content blocks; large bodies / inline images offloaded to `body` files). Instance key = proj_id. Verbatim -> deterministic -> witness-sealable. Contains conversation content; treat as private.",
      schema: TranscriptSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "provenance": {
      description:
        "SENSITIVE/PRIVATE: the reconstructed turn->execution->artifact->env provenance GRAPH of a session (artifact/execution/env nodes + typed edges; the cell node is collapsed into execution). Node ids: artifact=artifact_versions.id, execution=execution_log.id, env=env_snapshot_hash. Large source/stdout/stderr/env content offloaded to `body` files. Instance key = proj_id. Verbatim -> deterministic -> witness-sealable.",
      schema: ProvenanceSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "corpus": {
      description:
        "SENSITIVE/PRIVATE: the immutable, content-addressed byte CORPUS of a session — an index of every artifact_versions file + project-scoped workspace file copied into swamp's own `blob` store (sha, size, drift/unverifiable, present/skipped), plus provenance-of-loss for swept/missing files and a replayable/witnessed type-stamp. Instance key = proj_id. The record that survives a CS sweep/uninstall/upgrade; verbatim -> deterministic -> witness-sealable.",
      schema: CorpusSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "inputs": {
      description:
        "SENSITIVE/PRIVATE: the frozen Tier-1 /private/tmp INPUTS of a session (raw working data outside the org tree, days-from-deletion) — copied small files (sha,size) + by-reference records (path,size) for large/reference-root sets, plus harvested re-fetch accessions (SRA runs, RefSeq GC[AF]_). Captured from a user-supplied ALLOWLIST of external roots (default under /private/tmp). Instance key = proj_id; self-describing (capturedRoots). No CS checksum exists for /tmp, so entries are unverifiable by construction (no drift field).",
      schema: InputsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "external": {
      description:
        "SENSITIVE/PRIVATE: the gap-3 EXTERNAL-DATA INVENTORY of a session — this project's host_call_log aggregated into a per-external-source manifest (MCP server or internal method) with COUNTS + metadata ONLY (callCount, totalBytes, first/last access, errorCount, a global byMethod histogram), never any call CONTENT (args_json[1+]/data_inline/data_ref never selected; credentials_request/get_user_email counted by name, never parsed). Each mcp source carries a fillable releasePin slot (null at capture) so the release/version gap is CLOSABLE per source. Also a filesystem-mount-grants snapshot (mountName/mode/userId; host_path dropped) — user/org-wide, NOT a network allowlist. INVENTORY, not closure: the app-surface network allowlist + real release-pin closure are deferred. Instance key = proj_id; deterministic; read-only over a scrubbed clone.",
      schema: ExternalSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "credentials": {
      description:
        "SENSITIVE/PRIVATE: a PRESENCE-ONLY credential inventory — which credential PROVIDERS a session REQUESTED at runtime (host_call_log.credentials_request), per provider {requestCount, first/last}, NEVER any secret value (the secret tables are dropped from the read clone; only args_json[0]=provider is read under a json_valid guard; args_json[1+] never selected). Emits org-namespaced vault.get CEL references + a `swamp vault put` provisioning manifest for REAL providers only, so a replay re-provisions secrets BY VAULT, never embedded. get_user_email is out of scope (identity/PII). Instance key = proj_id; deterministic; read-only.",
      schema: CredentialsSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "lockenv": {
      description:
        "SENSITIVE/PRIVATE: portable ENV LOCK artifacts (#27, spec §9) transformed from a session's captured conda env snapshot — per distinct env: a version-PINNED Docker lock (environment.yml + Dockerfile via micromamba; re-solved, NOT build-locked) + a Nix SCAFFOLD (flake.nix, honestly not-exact). Lock files are emitted as content-addressed `environment.yml`/`dockerfile`/`flake.nix` file specs; this record indexes them per env with a type-stamp (starts `witnessed`; #28 replay validates → `replayable-docker`/`replayable-nix`). Instance key = proj_id; deterministic; read-only; source never mutated.",
      schema: LockEnvSchema,
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
  },
  files: {
    "body": {
      description:
        "SENSITIVE/PRIVATE: a content-addressed (sha256) offloaded large text body or inline image bytes referenced by transcript/provenance records via bodyFileRef/imageFileRef/sourceFileRef/packagesFileRef. Keyed by sha (one version per instance) so a version-count GC never evicts a referenced body — a sealable record never dangles.",
      contentType: "text/plain",
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "blob": {
      description:
        "SENSITIVE/PRIVATE: a content-addressed (sha256) BINARY artifact/workspace file copied verbatim from a CS session by capture_corpus. Keyed by sha (one version per instance) so a version-count GC never evicts a referenced blob. Streamed for large files.",
      contentType: "application/octet-stream",
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "environment.yml": {
      description:
        "SENSITIVE/PRIVATE: a content-addressed (sha256) reconstructed conda environment.yml emitted by lock_env — exact name=version per conda package + a pip: block + source channels (conda_history.channels). The version-pinned Docker lock's package manifest. Keyed by content sha.",
      contentType: "text/plain",
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "dockerfile": {
      description:
        "SENSITIVE/PRIVATE: a content-addressed (sha256) Dockerfile emitted by lock_env (FROM mambaorg/micromamba, micromamba install -f environment.yml). Env-independent — one shared file across a project's envs. Keyed by content sha.",
      contentType: "text/plain",
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
    "flake.nix": {
      description:
        "SENSITIVE/PRIVATE: a content-addressed (sha256) Nix flake SCAFFOLD emitted by lock_env — best-effort attrs + a pinned nixpkgs ref, honestly labeled NOT a reproducing lock (verify attrs; bioconda/python packages need fallbacks). Keyed by content sha.",
      contentType: "text/plain",
      lifetime: "infinite",
      garbageCollection: 100,
      sensitive: true,
    },
  },
  methods: {
    inspect: {
      description:
        "Read-only inspect of a QUIESCENT Claude Science session by name or proj_id; emits a `manifest`. Refuses a DB a running session is actively writing. Never mutates the source, never reads a credential.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;

        const manifest = await buildManifest(csRoot, args.project, orgId);
        const handle = await context.writeResource(
          "manifest",
          manifest.origin.project.id,
          manifest,
        );

        context.logger.info(
          `inspected ${
            manifest.origin.project.name ?? manifest.origin.project.id
          }`,
          {
            project: manifest.origin.project.id,
            sessions: manifest.sessions.length,
            savedArtifacts: manifest.artifacts.saved,
            intermediate: manifest.artifacts.intermediate,
            versions: manifest.artifacts.versions,
            frames: manifest.nFrames,
            checks: manifest.verificationChecks.total,
            userTyped: manifest.messages.userTyped,
            toolResults: manifest.messages.toolResults,
            messages: manifest.messages.total,
            unclassified: manifest.messages.unclassified,
            missingFiles: manifest.missingFiles.length,
            remoteCompute: manifest.remoteCompute,
            warnings: manifest.warnings.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    capture_messages: {
      description:
        "Capture the VERBATIM, typed, ordered message transcript of a QUIESCENT session into a SENSITIVE `transcript` resource (+ content-addressed `body` files for large content). Deterministic -> witness-sealable. Reads a static clone; source never mutated; never reads a credential.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          createFileWriter: (
            specName: string,
            instanceName: string,
            overrides?: { contentType?: string },
          ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureMessages(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            createFileWriter: context.createFileWriter,
            logger: context.logger,
          },
        );
        return { dataHandles };
      },
    },
    capture_corpus: {
      description:
        "Take a COMPLETE, IMMUTABLE, content-addressed byte COPY of a QUIESCENT session into a SENSITIVE `corpus` resource + content-addressed `blob` files: ALL artifact_versions bytes + PROJECT-SCOPED workspace files (touched by this project's executions, or under workspace dirs it owns), with drift detection (recomputed sha vs recorded checksum), provenance-of-loss for swept/missing, and a replayable/witnessed stamp. Streams large files (bounded memory); path-safety guards against copying outside the org tree; reads a static clone; source never mutated; never reads a credential.",
      arguments: InspectArgsSchema.extend({
        /** Files above this size are recorded by-reference (path+sha+size) instead of copied. Default: unlimited. */
        maxFileBytes: z.number().optional(),
      }),
      execute: async (
        args: z.infer<typeof InspectArgsSchema> & { maxFileBytes?: number },
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          createFileWriter: (
            specName: string,
            instanceName: string,
            overrides?: { contentType?: string },
          ) => {
            writeAll: (content: Uint8Array) => Promise<unknown>;
            writeStream?: (
              stream: ReadableStream<Uint8Array>,
            ) => Promise<unknown>;
          };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureCorpus(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            createFileWriter: context.createFileWriter,
            logger: context.logger,
          },
          { maxFileBytes: args.maxFileBytes },
        );
        return { dataHandles };
      },
    },
    capture_cells: {
      description:
        "Freeze the FULL ordered execution sequence of a QUIESCENT session (EVERY cell's source + language + cellIndex) into a SENSITIVE `cells` resource (+ content-addressed `body` files for large source) — the replay SCRIPT that complements the provenance GRAPH. capture_provenance keeps only artifact-linked graph nodes; this keeps the setup/helper cells (that define namespace globals) a full replay needs. Reads a static clone; source never mutated; never reads a credential.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          createFileWriter: (
            specName: string,
            instanceName: string,
            overrides?: { contentType?: string },
          ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureCells(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            createFileWriter: context.createFileWriter,
            logger: context.logger,
          },
        );
        return { dataHandles };
      },
    },
    capture_host_calls: {
      description:
        "Freeze a QUIESCENT session's REPLAYABLE host.* calls into a SENSITIVE `host_calls` resource ({method, args, response, isError} in call order; responses inlined from data_inline or resolved from data_ref tape files). Consumed by the session-execute host-replay shim so host.mcp/query_db/... replay offline. SECRET-SAFE: credentials_request responses scrubbed to presence only. Reads a static clone; source never mutated.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureHostCalls(
          csRoot,
          args.project,
          orgId,
          { writeResource: context.writeResource, logger: context.logger },
        );
        return { dataHandles };
      },
    },
    capture_review: {
      description:
        "Freeze a QUIESCENT session's INDEPENDENT-REVIEWER verdicts (CS's out-of-band verification_checks: verdict/severity/claim/evidence/reviewerModel, in time order) into a SENSITIVE `review` resource + verdict tally. Seals WHAT the reviewer flagged and WHY so the capture-report renders reviewer detail from sealed data, not just the manifest count. claim/evidence are analysis prose, never a credential. Reads a static clone; source never mutated.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureReview(
          csRoot,
          args.project,
          orgId,
          { writeResource: context.writeResource, logger: context.logger },
        );
        return { dataHandles };
      },
    },
    capture_notifications: {
      description:
        "Freeze a QUIESCENT session's PARENT<->CHILD delegation messages (CS `notifications`: task payloads + results exchanged via host.delegate) into a SENSITIVE `notifications` resource + per-type tally — the coordination layer the per-frame transcript doesn't carry. payload is coordination/analysis prose, never a credential. Reads a static clone; source never mutated.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureNotifications(
          csRoot,
          args.project,
          orgId,
          { writeResource: context.writeResource, logger: context.logger },
        );
        return { dataHandles };
      },
    },
    capture_extras: {
      description:
        "Freeze a QUIESCENT session's lower-frequency metadata (remote-compute jobs `compute_usage`, extracted claims incl. unchecked `session_claims`, durable beliefs `memories`, artifact folder structure `artifact_folders`) into one SENSITIVE `extras` resource so nothing is silently dropped. Each table read under its own guard — absent tables degrade to empty + a warning. Reads a static clone; source never mutated.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureExtras(
          csRoot,
          args.project,
          orgId,
          { writeResource: context.writeResource, logger: context.logger },
        );
        return { dataHandles };
      },
    },
    capture_annotations: {
      description:
        "Freeze a QUIESCENT session's USER ANNOTATIONS — artifact comments + thread bookmarks/highlights (transcript_annotations: kind/anchor/note/offsets/origin/timestamps) — into a SENSITIVE `annotations` resource. anchor_text/note are user prose, never a credential. Reads a static clone; source never mutated.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureAnnotations(
          csRoot,
          args.project,
          orgId,
          { writeResource: context.writeResource, logger: context.logger },
        );
        return { dataHandles };
      },
    },
    capture_settings: {
      description:
        "Freeze HOW a QUIESCENT session was run into a `settings` resource — the LLM model(s)+effort, delegation (reviewer/sub-agents), compute target, session timeline, the user capability toggles (memory/delegation/auto-review) and bundled specialists. Counts + flags only, never a credential. Reads a static clone; source never mutated.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureSettings(
          csRoot,
          args.project,
          orgId,
          { writeResource: context.writeResource, logger: context.logger },
        );
        return { dataHandles };
      },
    },
    render_html: {
      description:
        "Render the VISUAL companion to the capture-report: run the same report over the sealed facets, convert its markdown to a styled self-contained HTML page, and embed the captured PNG figures inline (from the corpus). Writes a single .html file (default <proj_id>_capture_report.html). Reads only sealed swamp data; nothing from the live app.",
      arguments: RenderHtmlArgsSchema,
      execute: async (
        args: z.infer<typeof RenderHtmlArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const { dataHandles } = await renderHtml(args, {
          writeResource: context.writeResource,
          logger: context.logger,
        });
        return { dataHandles };
      },
    },
    capture_skills: {
      description:
        "Freeze the CS SKILLS a QUIESCENT session used into a SENSITIVE `skills` resource (+ each used skill's kernel.py as a content-addressed `body` blob). Skill-loads aren't recorded, so the used set is inferred: a skill is used if any symbol its kernel.py exports appears in the session's cell source. The injected context (apply_figure_style etc.) a replay prepends. Read-only from disk; never a credential.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          createFileWriter: (
            specName: string,
            instanceName: string,
            overrides?: { contentType?: string },
          ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureSkills(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            createFileWriter: context.createFileWriter,
            logger: context.logger,
          },
        );
        return { dataHandles };
      },
    },
    capture_provenance: {
      description:
        "Reconstruct the turn->execution->artifact->env provenance GRAPH of a QUIESCENT session into a SENSITIVE `provenance` resource (+ content-addressed `body` files for large source/stdout/stderr/env content). The cell node is collapsed into execution (canonical node = execution_log.id). Verbatim, deterministic, injection-gated; reads a static clone; source never mutated; never reads a credential.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          createFileWriter: (
            specName: string,
            instanceName: string,
            overrides?: { contentType?: string },
          ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureProvenance(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            createFileWriter: context.createFileWriter,
            logger: context.logger,
          },
        );
        return { dataHandles };
      },
    },
    capture_inputs: {
      description:
        "Freeze a session's Tier-1 /private/tmp INPUTS (raw working data OUTSIDE the org tree, days-from-deletion) into `blob` files + a SENSITIVE `inputs` record. Roots come from an ALLOWLIST or, when `roots` is omitted, are AUTO-DERIVED from the session's own files_read/files_written trace (the zero-config standard-flow path) — derived roots are still validated. Roots must resolve under /private/tmp,/tmp (else allowSensitiveRoot + sensitiveRootOptIn); copy-roots + accession files honor maxFileBytes (over-cap -> by-reference), a referenceRoot records path+size only. Harvests SRA/RefSeq accessions for re-fetchability. Path-safe (canonical containment), read-only over the tree; source never mutated.",
      arguments: InputsArgsSchema,
      execute: async (
        args: z.infer<typeof InputsArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          createFileWriter: (
            specName: string,
            instanceName: string,
            overrides?: { contentType?: string },
          ) => {
            writeAll: (content: Uint8Array) => Promise<unknown>;
            writeStream?: (
              stream: ReadableStream<Uint8Array>,
            ) => Promise<unknown>;
          };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureInputs(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            createFileWriter: context.createFileWriter,
            logger: context.logger,
          },
          {
            roots: args.roots ? parseJsonStringArray("roots", args.roots) : [],
            referenceRoots: args.referenceRoots
              ? parseJsonStringArray("referenceRoots", args.referenceRoots)
              : undefined,
            referenceOver: args.referenceOver,
            maxFileBytes: args.maxFileBytes,
            allowSensitiveRoot: args.allowSensitiveRoot,
            sensitiveRootOptIn: args.sensitiveRootOptIn
              ? parseJsonStringArray(
                "sensitiveRootOptIn",
                args.sensitiveRootOptIn,
              )
              : undefined,
            hashReferenced: args.hashReferenced,
          },
        );
        return { dataHandles };
      },
    },
    capture_external: {
      description:
        "Inventory a session's EXTERNAL-DATA provenance (doc-2 gap 3): aggregate THIS project's host_call_log into a SENSITIVE `external` record — a per-source manifest (MCP server or internal method) with COUNTS + metadata ONLY, call CONTENT never persisted (args_json[1+]/data_inline/data_ref never selected — the MCP server is extracted in SQL via json_extract($[0]) under a json_valid guard; credentials_request/get_user_email counted by name, never parsed). Surfaces the release-pin gap as a fillable per-mcp-source slot + a labeled filesystem-mount-grants snapshot (host_path dropped; NOT a network allowlist). INVENTORY not closure. Deterministic, read-only over a scrubbed clone; source never mutated.",
      arguments: InspectArgsSchema,
      execute: async (
        args: z.infer<typeof InspectArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureExternal(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            logger: context.logger,
          },
        );
        return { dataHandles };
      },
    },
    capture_credentials: {
      description:
        "Inventory a session's credential PRESENCE (#23): which credential PROVIDERS THIS project REQUESTED at runtime (host_call_log.credentials_request) into a SENSITIVE `credentials` record — per provider {requestCount, first/last}, NEVER any secret (secret tables dropped from the read clone; only args_json[0]=provider read under a json_valid guard; args_json[1+] never selected; get_user_email out of scope). Emits org-namespaced vault.get CEL references + a `swamp vault put` provisioning manifest for REAL providers only, so a replay re-provisions secrets BY VAULT, never embedded. Deterministic, read-only; source never mutated.",
      arguments: InspectArgsSchema.extend({
        vault: z.string().default("session-ingest-creds"),
      }),
      execute: async (
        args: z.infer<typeof InspectArgsSchema> & { vault: string },
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await captureCredentials(
          csRoot,
          args.project,
          orgId,
          {
            writeResource: context.writeResource,
            logger: context.logger,
          },
          { vault: args.vault },
        );
        return { dataHandles };
      },
    },
    lock_env: {
      description:
        "Transform a session's captured conda env snapshot into PORTABLE reproducibility LOCK files (#27, spec §9): per distinct env, a version-PINNED Docker lock (environment.yml + Dockerfile via micromamba — re-solved, NOT build-locked) + a Nix SCAFFOLD (flake.nix, honestly not-exact). Emits content-addressed environment.yml/dockerfile/flake.nix files + a SENSITIVE `lockenv` record indexing them per env; type-stamp starts `witnessed` (unvalidated) until #28 replay validates. PURE TRANSFORM (no build/run). Deterministic, read-only; source never mutated. Supply a nixpkgsRev (40-hex) / micromambaDigest (64-hex) for full pinning.",
      arguments: InspectArgsSchema.extend({
        nixpkgsRev: z.string().optional(),
        micromambaDigest: z.string().optional(),
      }),
      execute: async (
        args: z.infer<typeof InspectArgsSchema> & {
          nixpkgsRev?: string;
          micromambaDigest?: string;
        },
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            instanceName: string,
            data: unknown,
          ) => Promise<{ version: number }>;
          createFileWriter: (
            specName: string,
            instanceName: string,
            overrides?: { contentType?: string },
          ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ): Promise<{ dataHandles: unknown[] }> => {
        const csRoot = resolveCsRoot(args, context.globalArgs);
        const orgId = args.orgId || context.globalArgs.orgId || undefined;
        const { dataHandles } = await lockEnv(csRoot, args.project, orgId, {
          writeResource: context.writeResource,
          createFileWriter: context.createFileWriter,
          logger: context.logger,
        }, {
          nixpkgsRev: args.nixpkgsRev,
          micromambaDigest: args.micromambaDigest,
        });
        return { dataHandles };
      },
    },
    seal: {
      description:
        "Seal a captured session (#29): read each captured resource's swamp content checksum in canonical order, assemble the order-stable `bundle-manifest` (items + reproducibility stamp + origin). The independent witness DIGEST over these items is produced by @vcjdeboer/session-witness seal_manifest, wired by the seal-bundle workflow. Reads in-process via queryData; writes only its own bundle-manifest.",
      arguments: SealArgsSchema,
      execute: runSeal,
    },
  },
};
