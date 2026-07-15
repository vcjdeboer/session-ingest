/**
 * @vcjdeboer/session-ingest — db.ts
 *
 * Secret-safe, non-mutating reader for a Claude Science `operon-cli.db` (SQLite).
 * Shared primitive for `inspect` (and later `capture`).
 *
 * DESIGN (settled through 4 adversarial review cycles + an empirical spike):
 *  - NEVER open the live DB in a way that can mutate it. A plain `sqlite3` open
 *    checkpoints on close (as last connection) and REWRITES the file — proven.
 *    We read with `sqlite3 -readonly` (non-mutating, verified); if that fails
 *    (e.g. WAL present without a usable -shm) we fall back to cloning the triplet
 *    into a private 0700 tempdir and reading the disposable clone, then deleting
 *    it. Either way the SOURCE bytes are never touched (invariant A) and no
 *    secret-bearing file is left behind (invariant B).
 *  - QUIESCENCE: reads require the DB not be actively written (a running CS
 *    session). `assertQuiescent` refuses if -wal is changing between two samples.
 *  - SECRETS: a positive ALLOWLIST of named queries (explicit columns, never a
 *    secret table/column, no `SELECT *`). No user input enters SQL — the resolver
 *    matches project name/id in TypeScript; only a DB-derived proj_id validated
 *    `^proj_[0-9a-f]+$` and single-quoted is interpolated. Defense in depth: a
 *    runtime guard rejects any SQL naming a secret token, and a post-fetch scrub
 *    REDACTS (never throws) any secret-shaped key.
 *
 * @module
 */
import { z } from "npm:zod@4";

/* ============================ secret denylist ============================ */
/** Secret TABLES dropped from any disposable clone (spec §6: no secret byte persists on disk). */
export const SECRET_TABLES = [
  "user_secrets",
  "oauth_tokens",
  "cloud_credentials",
  "anthropic_api_keys",
];
/** Tables/columns that must never be read. Belt-and-suspenders over the allowlist. */
export const SECRET_TOKENS = [
  ...SECRET_TABLES,
  "encrypted_value",
];
const SECRET_RE = new RegExp(SECRET_TOKENS.join("|"), "i");
/** Row keys whose VALUES get redacted post-fetch (drift columns that look secret). */
const SECRET_KEY_RE = /secret|token|password|encrypted|api[_-]?key|credential/i;

/* ============================ query registry ============================ */
/**
 * The ONLY SQL this module runs. Each entry: explicit columns, no `SELECT *`,
 * no secret table/column. `pid` (if used) is a DB-derived, regex-validated,
 * single-quoted project id — never user input.
 */
export const QUERIES = {
  projects_all: () =>
    "SELECT id,name,description,created_at,updated_at,uploads_frame_id FROM projects",
  frames_by_project: (pid: string) =>
    `SELECT id,parent_frame_id,root_frame_id,agent_name,delegate_name,conversation_type,model,effort,status,compute_enabled,name,created_at FROM frames WHERE project_id='${pid}'`,
  artifact_counts: (pid: string) =>
    `SELECT language,count(*) n FROM artifact_versions WHERE storage_path LIKE '${pid}/%' GROUP BY language`,
  // saved (is_intermediate=0) vs intermediate (=1): versions + distinct artifacts
  artifact_agg: (pid: string) =>
    `SELECT is_intermediate,count(*) versions,count(DISTINCT artifact_id) distinct_artifacts FROM artifact_versions WHERE storage_path LIKE '${pid}/%' GROUP BY is_intermediate`,
  distinct_envs: (pid: string) =>
    `SELECT count(DISTINCT env_snapshot_hash) n FROM artifact_versions WHERE storage_path LIKE '${pid}/%'`,
  artifact_paths: (pid: string) =>
    `SELECT storage_path,checksum FROM artifact_versions WHERE storage_path LIKE '${pid}/%'`,
  // reviewer/specialist "checks" (verdicts), keyed by the session's root frame id
  checks_by_root: (rootId: string) =>
    `SELECT verdict,count(*) n FROM verification_checks WHERE root_frame_id='${rootId}' GROUP BY verdict`,
  // thread turns — counted, NOT captured. total covers ALL rows (incl invalid JSON, so
  // the invalid ones surface as `unclassified`, never silently dropped).
  messages_total: (pid: string) =>
    `SELECT count(*) n FROM frame_messages WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}')`,
  // Complete, NAMED typing of every valid turn — no catch-all. Order matters:
  //  userTyped   = role=user + an intent id + no harness markers (your genuine prompts)
  //  harnessInjected = _harness_prompt present (e.g. reviewer instructions)
  //  systemNotice = _harness_notice present ([System] notices, tool errors)
  //  toolResults = remaining role=user (tool_result / data-feedback / context turns)
  //  unclassified = anything else (unknown role) — a tripwire, must be 0 in practice
  messages_typed: (pid: string) =>
    `SELECT CASE ` +
    `WHEN json_extract(msg_json,'$.role')='assistant' THEN 'assistant' ` +
    `WHEN json_extract(msg_json,'$.role')='user' AND json_extract(msg_json,'$._intent_id') IS NOT NULL AND json_extract(msg_json,'$._harness_prompt') IS NULL AND json_extract(msg_json,'$._harness_notice') IS NULL THEN 'userTyped' ` +
    `WHEN json_extract(msg_json,'$._harness_prompt') IS NOT NULL THEN 'harnessInjected' ` +
    `WHEN json_extract(msg_json,'$._harness_notice') IS NOT NULL THEN 'systemNotice' ` +
    `WHEN json_extract(msg_json,'$.role')='user' THEN 'toolResults' ` +
    `ELSE 'unclassified' END kind,count(*) n ` +
    `FROM frame_messages WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') AND json_valid(msg_json) GROUP BY kind`,
  // capture: canonical frame order across ALL project frames (same set inspect counts)
  frames_ordered: (pid: string) =>
    `SELECT id,parent_frame_id,agent_name,created_at FROM frames WHERE project_id='${pid}' ORDER BY created_at,id`,
  // capture: one frame's turns, row-cursor (idx,rowid stable order). frameId gated by FRAME_ID_RE;
  // limit/offset are coerced to integers (Number || default) so they cannot inject.
  messages_by_frame: (frameId: string, limit?: number, offset?: number) =>
    `SELECT idx,rowid,msg_json FROM frame_messages WHERE frame_id='${frameId}' ORDER BY idx,rowid LIMIT ${
      Number(limit) || 500
    } OFFSET ${Number(offset) || 0}`,
  // provenance: all artifact versions of a project, ordered (created_at,id) so the
  // node/edge stream is deterministic + witness-sealable. pid gated by PROJ_ID_RE.
  artifact_provenance: (pid: string) =>
    `SELECT id,artifact_id,version_number,producing_cell_id,frame_id,checksum,storage_path,language,is_intermediate,env_snapshot_hash,parent_version_id,dependency_mappings,created_at FROM artifact_versions WHERE storage_path LIKE '${pid}/%' ORDER BY created_at,id`,
  // provenance: one execution_log row by its id (a UUID; gated by FRAME_ID_RE at the call site).
  execution_by_id: (logId: string) =>
    `SELECT id,frame_id,cell_index,kernel_id,conda_env,language,source,stdout,stderr,exit_status,error_lineno,files_written,files_read,origin FROM execution_log WHERE id='${logId}'`,
  // provenance: a content_snapshot body by its content-address (64hex; gated by HASH_RE at the call site).
  env_content: (hash: string) =>
    `SELECT content FROM content_snapshots WHERE hash='${hash}'`,
  // provenance: message->artifact links (_artifact_refs) across a project's frames, ordered.
  artifact_refs: (pid: string) =>
    `SELECT frame_id,idx,json_extract(msg_json,'$._artifact_refs') refs FROM frame_messages WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') AND json_extract(msg_json,'$._artifact_refs') IS NOT NULL ORDER BY frame_id,idx`,
  // corpus: ALL of a project's parentless root frames (a project can have several) — the set
  // whose ids name the workspace dirs this project OWNS. Ordered for determinism.
  project_root_frames: (pid: string) =>
    `SELECT id FROM frames WHERE project_id='${pid}' AND parent_frame_id IS NULL ORDER BY id`,
  // corpus: per-project execution file descriptors (files_written/read) — the load-bearing
  // scope for which workspace files this project actually touched. Ordered for determinism.
  execution_files: (pid: string) =>
    `SELECT id,frame_id,files_written,files_read FROM execution_log WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') ORDER BY id`,
  // host-replay: this project's host_call_log with the REPLAYABLE request+response — args_json +
  // data_inline (small) or data_ref (a host_call_tapes file path) + error, in seq order. Distinct
  // from host_calls_by_project (counts-only inventory). data_inline for credentials_request is
  // scrubbed downstream (secret tokens never persist). pid gated PROJ_ID_RE.
  host_calls_full: (pid: string) =>
    `SELECT seq,method,args_json,` +
    `(CASE WHEN method='credentials_request' THEN NULL ELSE data_inline END) data_inline,` +
    `(CASE WHEN method='credentials_request' THEN NULL ELSE data_ref END) data_ref,` +
    `error FROM host_call_log WHERE execution_log_id IN (SELECT id FROM execution_log WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}')) ORDER BY created_at,id`,
  // cells: the FULL ordered execution sequence (every cell's source), the replay SCRIPT that
  // complements the provenance GRAPH. capture_provenance keeps only artifact-linked nodes; this
  // keeps ALL cells (incl. setup/helper cells that define namespace globals). pid gated PROJ_ID_RE.
  cells_by_project: (pid: string) =>
    `SELECT id,cell_index,language,source FROM execution_log WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') ORDER BY cell_index,id`,
  // external: this project's host_call_log rows, aggregated downstream into a per-source
  // manifest. STRICT counts-only — NEVER selects args_json[1+]/data_inline/data_ref/error.
  // The MCP server is extracted IN SQL via json_extract($[0]) ONLY for method='mcp' AND ONLY
  // when json_valid(args_json): json_extract ABORTS the whole statement on malformed JSON, so
  // the json_valid guard degrades a bad row to a NULL server instead of a failed capture.
  // `error` is reduced to an is_error boolean (no free-text auth-error egress). pid gated by
  // PROJ_ID_RE. Scoped this project's calls only (execution_log → frames → project_id).
  host_calls_by_project: (pid: string) =>
    `SELECT id,method,` +
    `(CASE WHEN method='mcp' AND json_valid(args_json) THEN json_extract(args_json,'$[0]') ELSE NULL END) mcp_server,` +
    `bytes,(CASE WHEN error IS NOT NULL AND error!='' THEN 1 ELSE 0 END) is_error,created_at ` +
    `FROM host_call_log WHERE execution_log_id IN (SELECT id FROM execution_log WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}')) ORDER BY created_at,id`,
  // external: host calls attributable to NO project (execution_log_id NULL, or its exec's frame
  // has no project) — upholds the never-silently-dropped invariant. pid-INDEPENDENT: a multi-
  // project org's OTHER-project calls are NOT orphans. 0 in a healthy DB.
  host_calls_orphan_count: () =>
    `SELECT count(*) n FROM host_call_log h WHERE h.execution_log_id IS NULL OR NOT EXISTS (SELECT 1 FROM execution_log e JOIN frames f ON e.frame_id=f.id WHERE e.id=h.execution_log_id AND f.project_id IS NOT NULL)`,
  // external: the filesystem mount grants — host_path DROPPED (no absolute path in a portable,
  // sealed record). user/org-wide, identical across projects, NOT a network allowlist. Usually empty.
  host_grants_all: () =>
    `SELECT id,user_id,mount_name,mode,created_at FROM host_grants ORDER BY created_at,id`,
  // credentials: this project's credentials_request calls -> per-provider PRESENCE (counts+timestamps).
  // provider = args_json[0] extracted IN SQL under json_valid (no whole-statement abort); NEVER selects
  // raw args_json/data_inline/data_ref (no secret content). get_user_email is DELIBERATELY excluded — its
  // result is identity/PII and must never be captured. pid gated PROJ_ID_RE. Names only host_call_log.
  credential_requests_by_project: (pid: string) =>
    `SELECT id,(CASE WHEN json_valid(args_json) THEN json_extract(args_json,'$[0]') ELSE NULL END) provider,created_at ` +
    `FROM host_call_log WHERE method='credentials_request' AND execution_log_id IN (SELECT id FROM execution_log WHERE frame_id IN (SELECT id FROM frames WHERE project_id='${pid}')) ORDER BY created_at,id`,
  // lock_env: the DISTINCT env-snapshot hashes this project's artifacts reference (in-tree scope,
  // same storage_path LIKE '<pid>/%' pattern as artifact_provenance). Deterministic; single column.
  project_env_hashes: (pid: string) =>
    `SELECT DISTINCT env_snapshot_hash FROM artifact_versions WHERE storage_path LIKE '${pid}/%' AND env_snapshot_hash IS NOT NULL ORDER BY env_snapshot_hash`,
  // review: the independent reviewer's verification_checks for this project, scoped by
  // root_frame_id ∈ the project's frames. claim + evidence are analysis prose (SENSITIVE),
  // never a credential. reviewer_model/kind + verdict/severity/status carry the audit. pid gated.
  review_checks: (pid: string) =>
    `SELECT id,verdict,severity,claim,evidence,reviewer_model,reviewer_kind,status,created_at ` +
    `FROM verification_checks WHERE root_frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') ORDER BY created_at,id`,
  // annotations: the user's artifact COMMENTS + thread BOOKMARKS/highlights for this project.
  // anchor_text/note are user prose (SENSITIVE). Scoped by root_frame_id ∈ project frames. pid gated.
  annotations: (pid: string) =>
    `SELECT id,kind,source,tool_name,message_uuid,message_index,block_index,anchor_text,start_offset,end_offset,note,origin,created_at,updated_at ` +
    `FROM transcript_annotations WHERE root_frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') ORDER BY created_at,id`,
  // settings: per-frame run configuration — model/effort, delegation (delegate_name), compute
  // target (compute_enabled), agent, timestamps. Aggregated in TS. pid gated. Single-table read.
  settings_frames: (pid: string) =>
    `SELECT model,effort,delegate_name,agent_name,compute_enabled,conversation_type,created_at ` +
    `FROM frames WHERE project_id='${pid}' ORDER BY created_at,id`,
  // settings: the user's capability toggles (memory / delegation / auto-review …). User-scoped
  // (no project column) — records the environment the session ran in. Non-secret flags only.
  capability_settings_all: () =>
    `SELECT kind,key,enabled,updated_at FROM capability_settings ORDER BY kind,key`,
  // settings: bundled specialist agents and whether each is enabled. User-scoped. Non-secret.
  bundled_agents_all: () =>
    `SELECT agent_name,enabled,updated_at FROM bundled_agent_settings ORDER BY agent_name`,
  // notifications: parent<->child delegation messages within this project's frame tree
  // (host.delegate coordination). payload is analysis/coordination prose (SENSITIVE), never a
  // credential. Scoped by root_frame_id in project frames. pid gated PROJ_ID_RE.
  notifications_by_project: (pid: string) =>
    `SELECT id,sender_frame_id,recipient_frame_id,root_frame_id,notification_type,payload,read_at,created_at ` +
    `FROM notifications WHERE root_frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') ORDER BY created_at,id`,
  // provenance: the NORMALIZED artifact->artifact dependency edges (version->version), the
  // authoritative DAG edges CS records — more precise than dependency_mappings (artifact-level,
  // partial). Scoped to this project's versions. pid gated PROJ_ID_RE.
  artifact_dependency_edges: (pid: string) =>
    `SELECT artifact_version_id,depends_on_version_id,reference_name ` +
    `FROM artifact_dependencies WHERE artifact_version_id IN (SELECT id FROM artifact_versions WHERE storage_path LIKE '${pid}/%') ORDER BY artifact_version_id,depends_on_version_id`,
  // extras: remote-compute jobs this project ran (GPU/CPU tier, provider, remote handle) — the
  // environment provenance for offloaded work. Scoped by project_id. pid gated PROJ_ID_RE.
  compute_usage_by_project: (pid: string) =>
    `SELECT job_id,environment,tier_type,provider,frame_id,state,remote_workdir,submit_cell_id,started_at,ended_at,expires_at ` +
    `FROM compute_usage WHERE project_id='${pid}' ORDER BY started_at,job_id`,
  // extras: the falsifiable claims extracted from this session (incl. unchecked ones, which
  // verification_checks omits). claim_text/entities are analysis prose (SENSITIVE). Scoped by
  // root_frame_id in project frames. pid gated PROJ_ID_RE.
  session_claims_by_project: (pid: string) =>
    `SELECT id,frame_id,step_id,claim_text,entities,source,created_at ` +
    `FROM session_claims WHERE root_frame_id IN (SELECT id FROM frames WHERE project_id='${pid}') ORDER BY created_at,id`,
  // extras: durable agent beliefs scoped to this project (may be absent on some builds — the
  // extras capture guards per-table). body is analysis prose (SENSITIVE). subject_project_id gated.
  memories_by_project: (pid: string) =>
    `SELECT id,body,subject_artifact_id,subject_version_id,subject_frame_id,origin,evidence,superseded_by,last_surfaced_at ` +
    `FROM memories WHERE subject_project_id='${pid}' ORDER BY id`,
  // extras: this project's artifact folder organization (structure only, cosmetic). Scoped by
  // project_id. pid gated PROJ_ID_RE.
  artifact_folders_by_project: (pid: string) =>
    `SELECT id,parent_id,name,root_frame_id,is_conversation_folder,is_user_uploads_folder,sort_order ` +
    `FROM artifact_folders WHERE project_id='${pid}' ORDER BY sort_order,id`,
} as const;

/* ============================ env snapshot parse (shared) ============================ */
export interface EnvPackage {
  name: string;
  version: string | null;
  channel: string | null;
}
/** A parsed content_snapshots.content env payload. Shared so lock_env (and, later, provenance)
 * read the SAME typed shape instead of re-implementing the JSON walk. */
export interface EnvSnapshot {
  environmentName: string | null;
  pythonVersion: string | null;
  packages: EnvPackage[];
  /** conda_history.channels — the SOURCE channels (conda-forge/bioconda), in RECORDED ORDER
   * (channel order is conda resolution priority; NEVER reorder). NOT packages[].channel (='conda'). */
  channels: string[];
}
/** Parse a content_snapshots.content JSON env payload; returns null on malformed/non-object. */
export function parseEnvSnapshot(content: string): EnvSnapshot | null {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object") return null;
  const rawPkgs = Array.isArray(obj.packages) ? obj.packages : [];
  const packages: EnvPackage[] = [];
  for (const p of rawPkgs) {
    if (p && typeof p === "object") {
      const pr = p as Record<string, unknown>;
      packages.push({
        name: typeof pr.name === "string" ? pr.name : "",
        version: typeof pr.version === "string" && pr.version
          ? pr.version
          : null,
        channel: typeof pr.channel === "string" ? pr.channel : null,
      });
    }
  }
  const hist = obj.conda_history && typeof obj.conda_history === "object"
    ? (obj.conda_history as Record<string, unknown>).channels
    : undefined;
  const channels = Array.isArray(hist)
    ? hist.filter((c): c is string => typeof c === "string")
    : [];
  return {
    environmentName: typeof obj.environment_name === "string"
      ? obj.environment_name
      : null,
    pythonVersion: typeof obj.python_version === "string"
      ? obj.python_version
      : null,
    packages,
    channels,
  };
}

/** A DB-derived project id. The regex is the sole injection gate for `pid`. */
export const PROJ_ID_RE = /^proj_[0-9a-f]+$/;
/** A DB-derived frame/root id (UUID). Sole injection gate for interpolated frame ids. */
export const FRAME_ID_RE = /^[0-9a-fA-F-]{36}$/;
/** A DB-derived content-address (sha256, 64 lowercase hex). Sole injection gate for interpolated hashes. */
export const HASH_RE = /^[0-9a-f]{64}$/;

export type TurnKind =
  | "assistant"
  | "userTyped"
  | "harnessInjected"
  | "systemNotice"
  | "toolResults"
  | "unclassified";

/**
 * Classify one parsed message turn. SINGLE source of truth — capture uses this
 * per turn; inspect keeps its `messages_typed` SQL CASE for counting, and a test
 * asserts the two agree (the equivalence floor). Semantics are pinned to MIRROR
 * SQL `json_extract(...) IS NOT NULL`: a field is "present" iff it is neither
 * `undefined` (path missing) nor `null` (JSON null → SQL NULL). Precedence order
 * matches the SQL CASE exactly.
 */
export function classifyTurn(m: Record<string, unknown>): TurnKind {
  const present = (v: unknown) => v !== undefined && v !== null;
  if (m.role === "assistant") return "assistant";
  if (
    m.role === "user" && present(m._intent_id) &&
    !present(m._harness_prompt) && !present(m._harness_notice)
  ) return "userTyped";
  if (present(m._harness_prompt)) return "harnessInjected";
  if (present(m._harness_notice)) return "systemNotice";
  if (m.role === "user") return "toolResults";
  return "unclassified";
}

/* ============================ row schemas ============================ */
/** Passthrough + optional so CS schema drift degrades instead of throwing. */
const ProjectRow = z.object({
  id: z.string(),
  name: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
  created_at: z.number().nullable().optional(),
  updated_at: z.number().nullable().optional(),
  uploads_frame_id: z.string().nullable().optional(),
}).passthrough();
const FrameRow = z.object({
  id: z.string().optional(),
  parent_frame_id: z.string().nullable().optional(),
  root_frame_id: z.string().nullable().optional(),
  agent_name: z.string().nullable().optional(),
  conversation_type: z.string().nullable().optional(),
  model: z.string().nullable().optional(),
  effort: z.string().nullable().optional(),
  status: z.string().nullable().optional(),
  compute_enabled: z.union([z.string(), z.number()]).nullable().optional(),
  // the session HEADLINE (CS's per-session title) + when the frame was created
  name: z.string().nullable().optional(),
  created_at: z.number().nullable().optional(),
}).passthrough();
const CountRow = z.object({ n: z.number().optional() }).passthrough();
const LangCountRow = z.object({
  language: z.string().nullable().optional(),
  n: z.number().optional(),
}).passthrough();

/* ============================ preflight ============================ */
export type Preflight = { ok: true; version: string } | {
  ok: false;
  error: string;
};
/** sqlite3 present AND >= 3.33 (the floor where `-json` output mode landed). */
export async function preflightSqlite(): Promise<Preflight> {
  let out: Deno.CommandOutput;
  try {
    out = await new Deno.Command("sqlite3", {
      args: ["--version"],
      stdout: "piped",
      stderr: "piped",
    }).output();
  } catch (e) {
    return {
      ok: false,
      error: `sqlite3 CLI not found on PATH (needed to read operon-cli.db): ${
        e instanceof Error ? e.message : String(e)
      }`,
    };
  }
  if (!out.success) {
    return { ok: false, error: "sqlite3 --version exited non-zero" };
  }
  const text = new TextDecoder().decode(out.stdout).trim();
  const m = text.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) {
    return { ok: false, error: `could not parse sqlite3 version: ${text}` };
  }
  const maj = Number(m[1]), min = Number(m[2]); // component-wise, not string/float
  if (maj < 3 || (maj === 3 && min < 33)) {
    return {
      ok: false,
      error: `sqlite3 ${m[0]} is < 3.33 (needs -json output mode)`,
    };
  }
  return { ok: true, version: m[0] };
}

/* ============================ quiescence ============================ */
async function statMaybe(p: string): Promise<Deno.FileInfo | null> {
  try {
    return await Deno.stat(p);
  } catch {
    return null;
  }
}
/**
 * Refuse to read a DB that a running CS session is actively writing.
 * No -wal, or a -wal unchanged across two samples => quiescent.
 */
export async function assertQuiescent(
  dbPath: string,
  sampleMs = 400,
): Promise<void> {
  const wal = `${dbPath}-wal`;
  const a = await statMaybe(wal);
  if (!a) return; // checkpointed / absent -> quiescent
  await new Promise((r) => setTimeout(r, sampleMs));
  const b = await statMaybe(wal);
  const changed = !b || a.size !== b.size ||
    a.mtime?.getTime() !== b.mtime?.getTime();
  if (changed) {
    throw new Error(
      `operon-cli.db appears to be actively written (its -wal changed over ${sampleMs}ms). ` +
        `session-ingest requires a quiescent DB: finish the Claude Science session (or quit CS) and retry.`,
    );
  }
}

/* ============================ non-mutating read ============================ */
function parseJsonRows(stdout: string): unknown[] {
  const t = stdout.trim();
  if (!t) return []; // sqlite3 -json emits '' (not '[]') for zero rows
  return JSON.parse(t);
}
async function runSqlite(args: string[]): Promise<Deno.CommandOutput> {
  return await new Deno.Command("sqlite3", {
    args,
    stdout: "piped",
    stderr: "piped",
  }).output();
}
/** Guard: never run SQL that names a secret table/column. */
function assertNoSecretSql(sql: string): void {
  if (SECRET_RE.test(sql)) {
    throw new Error(
      `refusing SQL that names a secret token: ${sql.slice(0, 60)}…`,
    );
  }
}

/**
 * Copy the DB triplet into a private, disposable clone dir (files 0600) AND
 * immediately DROP every secret table + VACUUM, so no secret byte persists in
 * any on-disk snapshot (spec §6: a file copy carries the secret tables
 * wholesale; a query-level allowlist alone is not enough). The clone is the
 * secret-scrubbed static copy both `inspect` and `capture`/`capture_provenance`
 * read from. Throws (caller cleans up) if the scrub itself fails — never leaves
 * an un-scrubbed clone readable.
 */
async function makeScrubbedClone(dbPath: string, dir: string): Promise<string> {
  await Deno.chmod(dir, 0o700).catch(() => {});
  const clone = `${dir}/db`;
  await Deno.copyFile(dbPath, clone);
  await Deno.chmod(clone, 0o600).catch(() => {});
  const wal = `${dbPath}-wal`;
  if (await statMaybe(wal)) {
    await Deno.copyFile(wal, `${clone}-wal`);
    await Deno.chmod(`${clone}-wal`, 0o600).catch(() => {});
  }
  const scrubSql =
    SECRET_TABLES.map((t) => `DROP TABLE IF EXISTS ${t};`).join(" ") +
    " VACUUM;";
  const out = await runSqlite([clone, scrubSql]); // mutates the DISPOSABLE clone only
  if (!out.success) {
    throw new Error(
      `failed to scrub secret tables from clone: ${
        new TextDecoder().decode(out.stderr).trim()
      }`,
    );
  }
  return clone;
}

/**
 * Path 2 (fallback): clone the triplet into a private 0700 tempdir (secret
 * tables dropped + VACUUMed), read the disposable clone, and delete the whole
 * dir on EVERY exit path (success or throw). Exported so tests can prove that
 * the one path which copies the DB to disk scrubs secrets and always cleans up.
 */
export async function readViaClone(
  dbPath: string,
  sql: string,
): Promise<unknown[]> {
  assertNoSecretSql(sql);
  const dir = await Deno.makeTempDir({ prefix: "session-ingest-" });
  try {
    const clone = await makeScrubbedClone(dbPath, dir);
    const out = await runSqlite(["-json", clone, sql]); // clone is disposable + scrubbed
    if (!out.success) {
      throw new Error(
        `sqlite3 read failed (clone): ${
          new TextDecoder().decode(out.stderr).trim()
        }`,
      );
    }
    const rows = parseJsonRows(new TextDecoder().decode(out.stdout)) as Record<
      string,
      unknown
    >[];
    scrub(rows); // defense-in-depth: redact any secret-shaped column on EVERY read path
    return rows;
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
}

/**
 * Clone the DB triplet (.db + -wal) into a private 0700 tempdir for a MULTI-query
 * static read (capture reads many frames from one consistent copy). `cp` never
 * opens the DB via SQLite, so the source is never checkpointed/mutated, and the
 * static copy sidesteps the quiescence TOCTOU of a long live read. Caller MUST
 * call `cleanup()` (finally). -shm is intentionally not copied (SQLite rebuilds it).
 */
export async function cloneDb(
  dbPath: string,
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const dir = await Deno.makeTempDir({ prefix: "session-ingest-" });
  try {
    const clone = await makeScrubbedClone(dbPath, dir); // secret tables dropped + VACUUMed
    return {
      path: clone,
      cleanup: () => Deno.remove(dir, { recursive: true }).catch(() => {}),
    };
  } catch (e) {
    // never leave a partial secret-bearing copy on an error path (invariant B)
    await Deno.remove(dir, { recursive: true }).catch(() => {});
    throw e;
  }
}

/** Run one allowlisted SQL string against an already-cloned DB; empty stdout → []. */
export async function readClone(
  clonePath: string,
  sql: string,
): Promise<unknown[]> {
  assertNoSecretSql(sql);
  const out = await runSqlite(["-json", clonePath, sql]);
  if (!out.success) {
    throw new Error(
      `clone read failed: ${new TextDecoder().decode(out.stderr).trim()}`,
    );
  }
  const rows = parseJsonRows(new TextDecoder().decode(out.stdout)) as Record<
    string,
    unknown
  >[];
  scrub(rows); // defense-in-depth: redact any secret-shaped column on EVERY read path
  return rows;
}

/**
 * Run one registry SQL string against `dbPath`, non-mutating over durable content.
 * Path 1: `sqlite3 -readonly` — leaves .db and -wal byte-identical (proven); may
 *   update/lazily create the VOLATILE -shm WAL index (scratch, rebuilt from -wal,
 *   not database content, outside the tamper baseline).
 * Path 2 (fallback, e.g. WAL present without a usable -shm): `readViaClone`.
 */
async function readRows(dbPath: string, sql: string): Promise<unknown[]> {
  assertNoSecretSql(sql);
  const ro = await runSqlite(["-readonly", "-json", dbPath, sql]);
  if (ro.success) return parseJsonRows(new TextDecoder().decode(ro.stdout));
  return await readViaClone(dbPath, sql);
}

/** Redact secret-shaped VALUES in fetched rows (drift defense; never throws). */
function scrub(
  rows: Record<string, unknown>[],
  warn?: (m: string) => void,
): void {
  for (const row of rows) {
    for (const k of Object.keys(row)) {
      if (SECRET_KEY_RE.test(k) && row[k] != null && row[k] !== "") {
        row[k] = "[REDACTED]";
        warn?.(`redacted secret-shaped column '${k}' from a fetched row`);
      }
    }
  }
}

/** Run a registry query, parse, scrub. The interpolated id is regex-validated by kind. */
async function query(
  dbPath: string,
  name: keyof typeof QUERIES,
  arg?: string,
  warn?: (m: string) => void,
): Promise<Record<string, unknown>[]> {
  if (arg !== undefined) {
    // checks_by_root + messages_by_frame interpolate a frame UUID; else a proj_id.
    const re = (name === "checks_by_root" || name === "messages_by_frame")
      ? FRAME_ID_RE
      : PROJ_ID_RE;
    if (!re.test(arg)) {
      throw new Error(`invalid id for '${name}' (failed ${re}): ${arg}`);
    }
  }
  const sql = (QUERIES[name] as (p?: string) => string)(arg);
  const rows = (await readRows(dbPath, sql)) as Record<string, unknown>[];
  scrub(rows, warn);
  return rows;
}

/* ============================ resolve + manifest ============================ */
export interface Manifest {
  origin: {
    tool: "claude-science";
    org: string;
    project: { id: string; name: string | null };
  };
  /** Honest artifact breakdown. CS's UI "artifacts" ≈ `saved` minus internal plan artifacts. */
  artifacts: {
    saved: number; // distinct artifact_id, is_intermediate=0 (user-facing; CS shows a curated subset)
    intermediate: number; // distinct artifact_id, is_intermediate=1 (CS hides these; kept for reproducibility)
    distinct: number; // distinct artifact_id total
    versions: number; // total artifact_versions rows
    byLanguage: Record<string, number>;
  };
  nDistinctEnvs: number;
  nFrames: number;
  /** Frame count per role (generic: OPERON/REVIEWER/UPLOADS/… + any added specialist). */
  framesByRole: Record<string, number>;
  /** Reviewer/specialist verification checks (verdicts) — matches CS's reviewer "N checks". */
  verificationChecks: { total: number; byVerdict: Record<string, number> };
  /**
   * The distinct SESSIONS this project holds. A CS project can contain several
   * top-level agent conversations (each a parentless `agent` frame), each with its
   * own HEADLINE (the frame `name`) and its own reviewer checks. The project-level
   * counts above are the ROLL-UP across these; here each session is kept separate
   * (its headline, when it started, its own frames + verification checks) so a
   * multi-session project is not blurred into one. Ordered by createdAt then id.
   */
  sessions: {
    rootFrameId: string;
    headline: string | null;
    createdAt: number | null;
    conversationType: string | null;
    agentName: string | null;
    nFrames: number;
    framesByRole: Record<string, number>;
    verificationChecks: { total: number; byVerdict: Record<string, number> };
  }[];
  /**
   * Thread turns — COUNTED here, NOT captured. Complete NAMED typing, no catch-all:
   * `userTyped` (your prompts), `assistant`, `toolResults` (data/tool feedback),
   * `systemNotice`, `harnessInjected`; `unclassified` is a tripwire (should be 0).
   * total = userTyped+assistant+toolResults+systemNotice+harnessInjected+unclassified.
   */
  messages: {
    total: number;
    userTyped: number;
    assistant: number;
    toolResults: number;
    systemNotice: number;
    harnessInjected: number;
    unclassified: number;
  };
  missingFiles: string[];
  remoteCompute: boolean;
  credentialsScope: "deferred-to-capture";
  warnings: string[];
}

/** Resolve `csRoot` (+ optional orgId) to the org dir holding operon-cli.db. */
export function resolveOrgDir(
  csRoot: string,
  orgId?: string,
): { orgDir: string; org: string } {
  const orgsBase = `${csRoot}/orgs`;
  if (orgId) return { orgDir: `${orgsBase}/${orgId}`, org: orgId };
  const entries: string[] = [];
  for (const e of Deno.readDirSync(orgsBase)) {
    if (e.isDirectory) entries.push(e.name);
  }
  if (entries.length === 1) {
    return { orgDir: `${orgsBase}/${entries[0]}`, org: entries[0] };
  }
  throw new Error(
    `found ${entries.length} orgs under ${orgsBase}; pass orgId to disambiguate: ${
      entries.join(", ")
    }`,
  );
}

/**
 * True iff any frame ran on remote compute (SSH/Modal/NIM). Single source of truth for the
 * honesty stamp — reused by `buildManifest` (inspect) and `captureCorpus` (replayable vs
 * witnessed) so the two records of a session never disagree.
 */
export function remoteCompute(
  frames: { compute_enabled?: unknown }[],
): boolean {
  return frames.some((f) => {
    const c = f.compute_enabled;
    return c != null && c !== "" && c !== 0 && c !== "0" && c !== "false";
  });
}

/** The base dir holding a session's artifact files (artifact_versions.storage_path is relative to it). */
export function artifactsBaseDir(orgDir: string): string {
  return `${orgDir}/artifacts`;
}

/** Resolve a project by name or proj_id, matching in TypeScript (no user input in SQL). */
export async function resolveProject(
  dbPath: string,
  arg: string,
): Promise<{ id: string; name: string | null } | null> {
  const rows = await query(dbPath, "projects_all");
  const projects = rows.map((r) => ProjectRow.parse(r));
  const hit = projects.find((p) => p.id === arg || p.name === arg);
  return hit ? { id: hit.id, name: hit.name ?? null } : null;
}

/**
 * List ALL live CS sessions (id + name) for a `status` overview, and report
 * whether the DB is currently quiescent. Unlike capture, a listing does NOT need
 * a consistent snapshot, so it NEVER refuses on a changing `-wal` — it reads
 * read-only and just flags `dbQuiescent`. Reads via `sqlite3 -readonly` (non-mutating).
 */
export async function listLiveSessions(
  csRoot: string,
  orgId?: string,
): Promise<
  { dbQuiescent: boolean; sessions: { id: string; name: string | null }[] }
> {
  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  if (!(await statMaybe(dbPath))) {
    throw new Error(`operon-cli.db not found at ${dbPath}`);
  }
  let dbQuiescent = true;
  try {
    await assertQuiescent(dbPath);
  } catch {
    dbQuiescent = false; // actively written (a live session) — fine for a listing
  }
  const rows = await query(dbPath, "projects_all");
  const sessions = rows
    .map((r) => ProjectRow.parse(r))
    .map((p) => ({ id: p.id, name: p.name ?? null }));
  return { dbQuiescent, sessions };
}

/** Build the read-only inspect manifest for a quiescent DB. */
export async function buildManifest(
  csRoot: string,
  projectArg: string,
  orgId?: string,
): Promise<Manifest> {
  const warnings: string[] = [];
  const warn = (m: string) => warnings.push(m);

  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);

  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  if (!(await statMaybe(dbPath))) {
    throw new Error(`operon-cli.db not found at ${dbPath}`);
  }
  await assertQuiescent(dbPath);

  const project = await resolveProject(dbPath, projectArg);
  if (!project) {
    throw new Error(`no project matched '${projectArg}' (by name or proj_id)`);
  }
  const pid = project.id;

  // frames
  let frames: z.infer<typeof FrameRow>[] = [];
  try {
    frames = (await query(dbPath, "frames_by_project", pid, warn)).map((r) =>
      FrameRow.parse(r)
    );
  } catch (e) {
    warn(
      `frames query degraded: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  // role breakdown — generic, so any added specialist role is captured, not just REVIEWER
  const framesByRole: Record<string, number> = {};
  for (const f of frames) {
    const role = (f.agent_name ?? "unknown").toUpperCase();
    framesByRole[role] = (framesByRole[role] ?? 0) + 1;
  }
  const remoteComputeUsed = remoteCompute(frames);
  // A project can hold SEVERAL top-level sessions. A session = a parentless frame
  // that is an agent conversation (conversation_type='agent'); the UPLOADS root
  // (conversation_type='uploads') is not a session. Descendant frames attribute to
  // their session via root_frame_id (self on the root, the root's id on children).
  const roots = frames.filter((f) => !f.parent_frame_id);
  const sessionRoots = roots
    .filter((f) =>
      !!f.id &&
      ((f.conversation_type ?? "").toLowerCase() === "agent" ||
        (f.agent_name ?? "").toUpperCase() === "OPERON")
    )
    .sort((a, b) =>
      (a.created_at ?? 0) - (b.created_at ?? 0) ||
      (a.id ?? "").localeCompare(b.id ?? "")
    );
  // `||` (not `??`) so an empty-string root_frame_id falls back to the frame's own
  // id — matches the falsy `!f.parent_frame_id` roots filter and avoids attributing a
  // frame to a phantom "" session (which would drop it from every session's counts).
  const sessionIdOf = (f: z.infer<typeof FrameRow>) => f.root_frame_id || f.id;

  // artifact counts by language
  const byLanguage: Record<string, number> = {};
  try {
    for (
      const r of (await query(dbPath, "artifact_counts", pid, warn)).map((x) =>
        LangCountRow.parse(x)
      )
    ) {
      byLanguage[r.language ?? "unknown"] = r.n ?? 0;
    }
  } catch (e) {
    warn(
      `artifact_counts degraded: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // saved vs intermediate vs distinct vs versions (the count that reconciles with CS's UI)
  const artifacts = {
    saved: 0,
    intermediate: 0,
    distinct: 0,
    versions: 0,
    byLanguage,
  };
  try {
    for (const r of await query(dbPath, "artifact_agg", pid, warn)) {
      const inter = Number(r.is_intermediate) === 1;
      const versions = Number(r.versions) || 0;
      const distinct = Number(r.distinct_artifacts) || 0;
      artifacts.versions += versions;
      artifacts.distinct += distinct;
      if (inter) artifacts.intermediate += distinct;
      else artifacts.saved += distinct;
    }
  } catch (e) {
    warn(
      `artifact_agg degraded: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // distinct envs
  let nDistinctEnvs = 0;
  try {
    const r = (await query(dbPath, "distinct_envs", pid, warn)).map((x) =>
      CountRow.parse(x)
    );
    nDistinctEnvs = r[0]?.n ?? 0;
  } catch (e) {
    warn(
      `distinct_envs degraded: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // missing artifact files (storage_path is RELATIVE to the artifacts base)
  const artifactsBase = artifactsBaseDir(orgDir);
  const missingFiles: string[] = [];
  try {
    const paths = await query(dbPath, "artifact_paths", pid, warn);
    for (const row of paths) {
      const sp = row.storage_path;
      if (typeof sp !== "string" || !sp) continue;
      if (!(await statMaybe(`${artifactsBase}/${sp}`))) missingFiles.push(sp);
    }
  } catch (e) {
    warn(
      `artifact_paths degraded: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // verification checks (verdicts) per root frame — matches CS reviewer "N checks".
  // Fetched once per parentless root, then attached to each session AND summed for the
  // project roll-up, so a multi-session project never drops the other sessions' checks.
  const checksByRoot = new Map<
    string,
    { total: number; byVerdict: Record<string, number> }
  >();
  for (const r of roots) {
    if (!r.id || !FRAME_ID_RE.test(r.id)) continue;
    const acc = { total: 0, byVerdict: {} as Record<string, number> };
    try {
      for (const row of await query(dbPath, "checks_by_root", r.id, warn)) {
        const v = String(row.verdict ?? "unknown");
        const n = Number(row.n) || 0;
        acc.byVerdict[v] = (acc.byVerdict[v] ?? 0) + n;
        acc.total += n;
      }
    } catch (e) {
      warn(
        `checks_by_root degraded: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
    checksByRoot.set(r.id, acc);
  }
  // project-level roll-up = sum across ALL roots (never silently drops a session)
  const verificationChecks = {
    total: 0,
    byVerdict: {} as Record<string, number>,
  };
  for (const acc of checksByRoot.values()) {
    verificationChecks.total += acc.total;
    for (const [v, n] of Object.entries(acc.byVerdict)) {
      verificationChecks.byVerdict[v] = (verificationChecks.byVerdict[v] ?? 0) +
        n;
    }
  }
  // per-session breakdown: headline, when it started, its own frames + checks
  const sessions = sessionRoots.map((s) => {
    const sid = s.id as string;
    const mine = frames.filter((f) => sessionIdOf(f) === sid);
    const roleBreakdown: Record<string, number> = {};
    for (const f of mine) {
      const role = (f.agent_name ?? "unknown").toUpperCase();
      roleBreakdown[role] = (roleBreakdown[role] ?? 0) + 1;
    }
    return {
      rootFrameId: sid,
      headline: s.name ?? null,
      createdAt: s.created_at ?? null,
      conversationType: s.conversation_type ?? null,
      agentName: s.agent_name ?? null,
      nFrames: mine.length,
      framesByRole: roleBreakdown,
      verificationChecks: checksByRoot.get(sid) ??
        { total: 0, byVerdict: {} as Record<string, number> },
    };
  });

  // thread turns — counted, NOT captured. Complete named typing; unclassified = tripwire.
  const messages = {
    total: 0,
    userTyped: 0,
    assistant: 0,
    toolResults: 0,
    systemNotice: 0,
    harnessInjected: 0,
    unclassified: 0,
  };
  const KNOWN = [
    "userTyped",
    "assistant",
    "toolResults",
    "systemNotice",
    "harnessInjected",
  ];
  try {
    const tot = (await query(dbPath, "messages_total", pid, warn)).map((x) =>
      CountRow.parse(x)
    );
    messages.total = tot[0]?.n ?? 0;
    let classified = 0;
    for (const r of await query(dbPath, "messages_typed", pid, warn)) {
      const kind = String(r.kind ?? "unclassified");
      const n = Number(r.n) || 0;
      if (KNOWN.includes(kind)) (messages as Record<string, number>)[kind] += n;
      else messages.unclassified += n;
      classified += n;
    }
    // rows excluded by json_valid (malformed) are a tripwire too, never silently dropped
    messages.unclassified += messages.total - classified;
  } catch (e) {
    warn(`messages degraded: ${e instanceof Error ? e.message : String(e)}`);
  }

  return {
    origin: {
      tool: "claude-science",
      org,
      project: { id: pid, name: project.name },
    },
    artifacts,
    nDistinctEnvs,
    nFrames: frames.length,
    framesByRole,
    verificationChecks,
    sessions,
    messages,
    missingFiles,
    remoteCompute: remoteComputeUsed,
    credentialsScope: "deferred-to-capture",
    warnings,
  };
}
