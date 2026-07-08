/**
 * @vcjdeboer/session-ingest — credentials.ts
 *
 * `capture_credentials` (#23): a PRESENCE-ONLY inventory of the credential PROVIDERS a
 * session REQUESTED at runtime — so a replay can re-provision them via a swamp VAULT
 * without any secret ever entering the bundle.
 *
 * STRUCTURAL secret exclusion (Vincent-chosen: requested-at-runtime): sourced entirely
 * from host_call_log.credentials_request on the SCRUBBED CLONE. The secret tables
 * (user_secrets / oauth_tokens / cloud_credentials / anthropic_api_keys) are DROPPED from
 * the clone (makeScrubbedClone) and NEVER read. The provider is extracted via
 * json_extract(args_json,'$[0]') under a json_valid guard (the shipped capture_external
 * pattern), NEVER reading args_json[1+] / data_inline / data_ref or any encrypted value.
 * get_user_email is DELIBERATELY out of scope (identity/PII — its result must never be
 * captured).
 *
 * Per provider: {provider, requestCount, firstAt, lastAt}. vaultRefs + provisioningManifest
 * are emitted ONLY for REAL providers (passing PROVIDER_RE + the tripwire); sentinel buckets
 * (malformed / unrecognized / secret-shaped) stay in credentials[]/totals as DIAGNOSTICS
 * only, never in the provisioning surface, and no warning ever interpolates the raw value.
 * The vault key is ORG-NAMESPACED (<org>/<provider>) to avoid cross-account collision. The
 * bundle REFERENCES secrets by vault (vault.get CEL) — it never embeds them.
 *
 * SENSITIVE resource; deterministic; read-only; source never mutated.
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
import { secretTripwire } from "./store.ts";

/** A well-formed credential provider id (openalex, github, google_cloud, nvidia_api, …). */
const PROVIDER_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
/**
 * Safe charset for the org id + vault name that get interpolated into the emitted CEL ref
 * (`vault.get(...)`) and the `swamp vault put` manifest — the ONLY generated executable/CEL
 * strings this module produces. Gate them like every other interpolated value (PROJ_ID_RE
 * et al.) so an odd org/vault (quote, space, `;`) can never inject into a ref the user runs.
 * A real org (ULID/UUID/dir-name) and the default vault both match.
 */
const SAFE_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/* ============================ schema ============================ */
export const CredentialEntry = z.object({
  provider: z.string(),
  requestCount: z.number(),
  firstAt: z.number(),
  lastAt: z.number(),
});
export const CredentialsSchema = z.object({
  sensitive: z.literal(true),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  /** Per provider (real + sentinel diagnostic buckets), sorted by provider key. */
  credentials: z.array(CredentialEntry),
  /** REAL providers only -> the vault.get CEL reference a replay wires. Org-namespaced key. */
  vaultRefs: z.record(z.string(), z.string()),
  /** REAL providers only -> the one-time `swamp vault put` commands (SECRET is a placeholder). */
  provisioningManifest: z.array(z.string()),
  totals: z.object({
    requests: z.number(),
    providers: z.number(),
    realProviders: z.number(),
    secretShapedCount: z.number(),
  }),
  warnings: z.array(z.string()),
});
export type Credentials = z.infer<typeof CredentialsSchema>;

/** What capture_credentials needs from the model's execute context (DB-only). */
export interface CredentialsSink {
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (msg: string, props?: Record<string, unknown>) => void };
}

export interface CredentialsOpts {
  /** The vault name the vault.get refs + provisioning manifest target. */
  vault?: string;
}

type Row = Record<string, unknown>;
type Warn = (m: string) => void;
const errName = (e: unknown): string => (e instanceof Error ? e.name : "error");

/* ============================ the capture ============================ */
export async function captureCredentials(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: CredentialsSink,
  opts: CredentialsOpts = {},
): Promise<{ credentials: Credentials; dataHandles: unknown[] }> {
  const warnings: string[] = [];
  const warn: Warn = (m) => warnings.push(m);
  const vault = opts.vault ?? "session-ingest-creds";
  // vault is a user-supplied arg that lands in a generated CEL ref + a `swamp vault put`
  // command — fail fast on an unsafe name rather than emit an injectable string.
  if (!SAFE_KEY_RE.test(vault)) {
    throw new Error(
      "invalid vault name: must be [A-Za-z0-9][A-Za-z0-9_-]{0,127}",
    );
  }

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
  sink.logger.info("capture_credentials start", { project: projectArg, org });

  const { path: clone, cleanup } = await cloneDb(dbPath); // static scrubbed copy; secret tables dropped
  try {
    const projects = (await readClone(clone, QUERIES.projects_all())) as Row[];
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);
    const projName = (proj.name ?? null) as string | null;

    let rows: Row[] = [];
    try {
      rows = (await readClone(
        clone,
        QUERIES.credential_requests_by_project(pid),
      )) as Row[];
    } catch (e) {
      warn(`credential_requests degraded: ${errName(e)}`);
    }

    type Agg = { requestCount: number; firstAt: number; lastAt: number };
    const byProvider = new Map<string, Agg>();
    const realProviders = new Set<string>();
    let secretShapedCount = 0;

    for (const r of rows) {
      const raw = r.provider;
      let key: string;
      let real = false;
      if (raw === null || raw === undefined) {
        key = "malformed"; // json_valid=0 or non-array args_json → provider is NULL
        warn(
          "a credentials_request has a malformed/missing provider — bucketed 'malformed'",
        );
      } else if (typeof raw === "string" && PROVIDER_RE.test(raw)) {
        // defense-in-depth: a provider-shaped-BUT-secret-shaped value is bucketed, never emitted
        // as a key and never interpolated into a warning.
        const before = warnings.length;
        secretTripwire(raw, warn, "a credential provider key");
        if (warnings.length > before) {
          secretShapedCount++;
          key = "secret-shaped";
        } else {
          key = raw;
          real = true;
        }
      } else {
        key = "unrecognized"; // non-provider-shaped value — never emit the raw value
        warn(
          "a credentials_request has a non-provider-shaped value — bucketed 'unrecognized'",
        );
      }
      if (real) realProviders.add(key);
      const a = byProvider.get(key) ??
        { requestCount: 0, firstAt: Infinity, lastAt: -Infinity };
      a.requestCount++;
      const at = Number(r.created_at) || 0;
      a.firstAt = Math.min(a.firstAt, at);
      a.lastAt = Math.max(a.lastAt, at);
      byProvider.set(key, a);
    }

    const credentials = [...byProvider.keys()].sort().map(
      (key): z.infer<typeof CredentialEntry> => {
        const a = byProvider.get(key)!;
        return {
          provider: key,
          requestCount: a.requestCount,
          firstAt: a.firstAt,
          lastAt: a.lastAt,
        };
      },
    );

    // vaultRefs + provisioning manifest: REAL providers only, ORG-NAMESPACED key. If org has
    // unexpected characters (would break/inject the generated CEL ref + manifest command), omit
    // the provisioning surface + warn — the credential INVENTORY is still emitted.
    const vaultRefs: Record<string, string> = {};
    const provisioningManifest: string[] = [];
    if (!SAFE_KEY_RE.test(org)) {
      warn(
        "org id has unexpected characters — vault refs + provisioning manifest omitted",
      );
    } else {
      for (const p of [...realProviders].sort()) {
        const nsKey = `${org}/${p}`;
        vaultRefs[p] = `vault.get("${vault}", "${nsKey}")`;
        provisioningManifest.push(`swamp vault put ${vault} ${nsKey} <SECRET>`);
      }
    }

    const credentialsRecord: Credentials = {
      sensitive: true,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: projName },
      },
      credentials,
      vaultRefs,
      provisioningManifest,
      totals: {
        requests: rows.length,
        providers: credentials.length,
        realProviders: realProviders.size,
        secretShapedCount,
      },
      warnings,
    };
    CredentialsSchema.parse(credentialsRecord); // validate before write
    const handle = await sink.writeResource(
      "credentials",
      pid,
      credentialsRecord,
    );
    sink.logger.info(`credentials for ${projName ?? pid}`, {
      project: pid,
      requests: rows.length,
      providers: credentials.length,
      realProviders: realProviders.size,
      secretShaped: secretShapedCount,
      warnings: warnings.length,
    });
    return { credentials: credentialsRecord, dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
