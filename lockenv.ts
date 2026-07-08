/**
 * @vcjdeboer/session-ingest — lockenv.ts
 *
 * `lock_env` (#27, spec §9): a PURE TRANSFORM of a session's captured conda env snapshot
 * into portable reproducibility LOCK FILES — anti-lock-in (getting OUT of conda's format).
 * It EMITS files; it does NOT build or run anything — that is #28 replay, which validates
 * and upgrades the type-stamp. Reads the RAW content_snapshots.content (dodging provenance's
 * >2000-char packagesFileRef offload) via the shared `parseEnvSnapshot`.
 *
 * Two targets:
 *  - DOCKER (version-PINNED best-effort — re-solved, NOT build-locked): a reconstructed
 *    environment.yml (exact `name=version` per conda package + a `pip:` block for pip packages
 *    + `channels:` from conda_history.channels IN RECORDED ORDER) and a Dockerfile
 *    (FROM mambaorg/micromamba, micromamba install -f). Honest: `micromamba install name=version`
 *    re-solves the graph (no build strings / transitive lock), so it is version-pinned, not a
 *    faithful lock — stamped `witnessed` until #28 proves it.
 *  - NIX SCAFFOLD (honestly NOT reproducing): a flake.nix pinning a nixpkgs ref + the package
 *    list as best-effort attrs, with a scaffold header (verify attrs; scientific python lives
 *    under python3Packages.*; many bioconda tools have no nixpkgs equivalent).
 *
 * SENSITIVE record + files (the env fingerprint is re-identifying; a tokenized channel URL must
 * not land in a shareable artifact). Content-sha FILE keying (per-env env.yml/flake unique; the
 * env-independent Dockerfile dedupes to one). Deterministic (sort PACKAGES only; preserve channel
 * order). Read-only over a scrubbed clone; source never mutated.
 * @module
 */
import { z } from "npm:zod@4";
import { stringify as stringifyYaml } from "jsr:@std/yaml@1.0.5";
import {
  assertQuiescent,
  cloneDb,
  type EnvPackage,
  HASH_RE,
  parseEnvSnapshot,
  preflightSqlite,
  PROJ_ID_RE,
  QUERIES,
  readClone,
  resolveOrgDir,
} from "./db.ts";
import { secretTripwire, sha256hex } from "./store.ts";

/**
 * A token (package name/version, env name) safe to place into a generated file. Uses a
 * NEGATED-class test, not `^…$` — JS `$` (no `m`) matches before a trailing "\n", which would
 * let a name ending in a newline slip through and split a flake comment into invalid nix.
 */
const safeToken = (s: string): boolean =>
  s.length > 0 && !/[^A-Za-z0-9._+-]/.test(s);
/** A user-supplied nixpkgs commit rev — full 40-hex only (else the default channel ref is used). */
const NIXREV_RE = /^[0-9a-f]{40}$/;
/** A user-supplied micromamba image digest — 64-hex (else a version tag + a not-digest-pinned warn). */
const DIGEST_RE = /^[0-9a-f]{64}$/;

const DEFAULT_MICROMAMBA_TAG = "mambaorg/micromamba:1.5.10";
const DEFAULT_NIXPKGS_REF = "nixos-24.05"; // a readable channel ref for the SCAFFOLD (pin a full rev for real use)
const PIP_CHANNELS = new Set(["pip", "pypi"]); // conda records pip-installed pkgs here (real data: 'pip')

/* ============================ schema ============================ */
export const DockerLock = z.object({
  status: z.literal("generated"),
  envYamlRef: z.string(),
  dockerfileRef: z.string(),
  digestPinned: z.boolean(),
});
export const NixLock = z.object({
  status: z.literal("scaffold"),
  flakeRef: z.string(),
  nixpkgsRef: z.string(),
  caveat: z.string(),
});
export const LockEntry = z.object({
  envHash: z.string(),
  environmentName: z.string().nullable(),
  pythonVersion: z.string().nullable(),
  channels: z.array(z.string()),
  packageCount: z.number(),
  docker: DockerLock,
  nix: NixLock,
});
export const LockEnvSchema = z.object({
  sensitive: z.literal(true),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
  /** One lock per distinct env snapshot the project referenced, sorted by env hash. */
  locks: z.array(LockEntry),
  totals: z.object({
    envCount: z.number(),
    dockerGenerated: z.number(),
    nixScaffolded: z.number(),
  }),
  /** Lock-time stamp is always 'witnessed' (unvalidated); #28 replay upgrades per target. */
  typeStamp: z.enum(["witnessed", "replayable-docker", "replayable-nix"]),
  /** Distinct content shas of the lock files written this invocation. */
  writeManifest: z.array(z.string()),
  warnings: z.array(z.string()),
});
export type LockEnv = z.infer<typeof LockEnvSchema>;

/** What lock_env needs from the model's execute context (writes lock FILES + a record). */
export interface LockEnvSink {
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<{ version: number }>;
  createFileWriter: (
    spec: string,
    instance: string,
    overrides?: { contentType?: string },
  ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
  logger: { info: (msg: string, props?: Record<string, unknown>) => void };
}

export interface LockEnvOpts {
  /** A nixpkgs commit rev (40-hex) for the flake scaffold; else a readable channel ref is used. */
  nixpkgsRev?: string;
  /** A mambaorg/micromamba image digest (64-hex) → digest-pinned FROM; else a version tag + warn. */
  micromambaDigest?: string;
}

type Row = Record<string, unknown>;
type Warn = (m: string) => void;
const errName = (e: unknown): string => (e instanceof Error ? e.name : "error");
const enc = new TextEncoder();

/* ============================ generators (pure) ============================ */
/** Reconstruct a conda environment.yml (exact name=version + pip block + source channels). */
export function generateEnvYaml(
  name: string | null,
  channels: string[],
  packages: EnvPackage[],
  warn: Warn,
): string {
  const conda: string[] = [];
  const pip: string[] = [];
  const seen = new Set<string>();
  for (const p of packages) {
    if (!safeToken(p.name)) {
      warn(`env package with an unexpected name skipped`);
      continue;
    }
    let version = p.version;
    if (version !== null && !safeToken(version)) {
      warn(`package ${p.name} has an unexpected version — pinned unversioned`);
      version = null;
    }
    const isPip = p.channel !== null &&
      PIP_CHANNELS.has(p.channel.toLowerCase());
    const key = `${isPip ? "pip:" : "conda:"}${p.name}`;
    if (seen.has(key)) {
      warn(`duplicate package ${p.name} deduped`);
      continue;
    }
    seen.add(key);
    if (isPip) {
      pip.push(version ? `${p.name}==${version}` : p.name);
    } else {
      conda.push(version ? `${p.name}=${version}` : p.name);
    }
  }
  conda.sort();
  pip.sort();
  const dependencies: unknown[] = [...conda];
  if (pip.length) {
    if (!seen.has("conda:pip")) dependencies.push("pip"); // conda needs `pip` present to run the pip: block
    dependencies.push({ pip });
  }
  const chans = channels.length ? channels : ["conda-forge"];
  if (!channels.length) {
    warn(
      "env has no conda_history.channels — defaulted to conda-forge (may not resolve)",
    );
  }
  return stringifyYaml({
    name: name ?? "captured-env",
    channels: chans,
    dependencies,
  });
}

/** An env-INDEPENDENT Dockerfile that installs the accompanying environment.yml via micromamba. */
export function generateDockerfile(from: string): string {
  return [
    `# Generated by @vcjdeboer/session-ingest lock_env — version-pinned (re-solved, NOT build-locked).`,
    `FROM ${from}`,
    `COPY environment.yml /tmp/environment.yml`,
    `RUN micromamba install -y -n base -f /tmp/environment.yml && micromamba clean -a -y`,
    ``,
  ].join("\n");
}

/** A flake.nix SCAFFOLD (NOT a reproducing lock) — best-effort attrs + honest caveats. */
export function generateFlakeScaffold(
  name: string | null,
  nixpkgsRef: string,
  packages: EnvPackage[],
): string {
  const attrs = [...packages]
    .map((p) => p.name)
    .filter((n) => safeToken(n))
    .sort()
    .map((n) =>
      `        # ${n} — verify: top-level? python3Packages.${n}? bioconda (no nix eq)?`
    );
  // the env name is interpolated RAW into the nix `description` string — sanitize it (a `"`/`${`
  // would break out and inject nix into the scaffold #28 replay evaluates).
  const safeName = name && safeToken(name) ? name : "captured-env";
  return [
    `# AUTO-GENERATED SCAFFOLD by @vcjdeboer/session-ingest lock_env — NOT a reproducing lock.`,
    `# Best-effort only: each package below is a NAME to map by hand. Scientific PYTHON packages`,
    `# usually live under python3Packages.* (NOT top-level); many bioconda tools have no nixpkgs`,
    `# equivalent and need a pinned build or another source. Pin a full nixpkgs REV for real use.`,
    `{`,
    `  description = "session-ingest scaffold for env '${safeName}'";`,
    `  inputs.nixpkgs.url = "github:NixOS/nixpkgs/${nixpkgsRef}";`,
    `  outputs = { self, nixpkgs }:`,
    `    let pkgs = import nixpkgs { system = "x86_64-linux"; };`,
    `    in {`,
    `      devShells.x86_64-linux.default = pkgs.mkShell {`,
    `        packages = with pkgs; [`,
    ...attrs,
    `        ];`,
    `      };`,
    `    };`,
    `}`,
    ``,
  ].join("\n");
}

/* ============================ the transform ============================ */
export async function lockEnv(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: LockEnvSink,
  opts: LockEnvOpts = {},
): Promise<{ lockenv: LockEnv; dataHandles: unknown[] }> {
  const warnings: string[] = [];
  const warn: Warn = (m) => warnings.push(m);

  // gate the user args that get interpolated into emitted files
  let dockerFrom = DEFAULT_MICROMAMBA_TAG;
  let digestPinned = false;
  if (opts.micromambaDigest !== undefined) {
    if (!DIGEST_RE.test(opts.micromambaDigest)) {
      throw new Error("invalid micromambaDigest: must be 64 hex");
    }
    dockerFrom = `mambaorg/micromamba@sha256:${opts.micromambaDigest}`;
    digestPinned = true;
  } else {
    warn(
      "no micromambaDigest — Dockerfile FROM uses a version tag (not digest-pinned)",
    );
  }
  let nixpkgsRef = DEFAULT_NIXPKGS_REF;
  if (opts.nixpkgsRev !== undefined) {
    if (!NIXREV_RE.test(opts.nixpkgsRev)) {
      throw new Error("invalid nixpkgsRev: must be a 40-hex commit");
    }
    nixpkgsRef = opts.nixpkgsRev;
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
  sink.logger.info("lock_env start", { project: projectArg, org });

  const { path: clone, cleanup } = await cloneDb(dbPath);
  const written = new Set<string>();
  const writeFile = async (spec: string, text: string): Promise<string> => {
    const sha = await sha256hex(text);
    if (!written.has(sha)) {
      await sink.createFileWriter(spec, sha, { contentType: "text/plain" })
        .writeAll(enc.encode(text));
      written.add(sha);
    }
    return sha;
  };
  try {
    const projects = (await readClone(clone, QUERIES.projects_all())) as Row[];
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);
    const projName = (proj.name ?? null) as string | null;

    let hashRows: Row[] = [];
    try {
      hashRows =
        (await readClone(clone, QUERIES.project_env_hashes(pid))) as Row[];
    } catch (e) {
      warn(`env hashes degraded: ${errName(e)}`);
    }

    const dockerfileText = generateDockerfile(dockerFrom); // env-independent → written once
    const locks: z.infer<typeof LockEntry>[] = [];
    for (const r of hashRows) {
      const hash = String(r.env_snapshot_hash ?? "");
      if (!HASH_RE.test(hash)) { // gate before interpolating into env_content(hash)
        warn("an env_snapshot_hash is not a 64-hex content address — skipped");
        continue;
      }
      let content: string | null = null;
      try {
        const rows =
          (await readClone(clone, QUERIES.env_content(hash))) as Row[];
        content = rows.length
          ? (rows[0].content == null ? null : String(rows[0].content))
          : null;
      } catch (e) {
        warn(`env ${hash.slice(0, 12)} content degraded: ${errName(e)}`);
        continue;
      }
      if (content === null) {
        warn(`env ${hash.slice(0, 12)} has no content_snapshots row — skipped`);
        continue;
      }
      secretTripwire(content, warn, "env.content");
      const snap = parseEnvSnapshot(content);
      if (snap === null) {
        warn(`env ${hash.slice(0, 12)} content is not JSON — skipped`);
        continue;
      }
      const envYaml = generateEnvYaml(
        snap.environmentName,
        snap.channels,
        snap.packages,
        warn,
      );
      const flake = generateFlakeScaffold(
        snap.environmentName,
        nixpkgsRef,
        snap.packages,
      );
      const envYamlRef = await writeFile("environment.yml", envYaml);
      const dockerfileRef = await writeFile("dockerfile", dockerfileText);
      const flakeRef = await writeFile("flake.nix", flake);
      locks.push({
        envHash: hash,
        environmentName: snap.environmentName,
        pythonVersion: snap.pythonVersion,
        channels: snap.channels,
        packageCount: snap.packages.length,
        docker: {
          status: "generated",
          envYamlRef,
          dockerfileRef,
          digestPinned,
        },
        nix: {
          status: "scaffold",
          flakeRef,
          nixpkgsRef,
          caveat:
            "best-effort attrs only — verify each (python3Packages.*, bioconda has no nix eq); not a reproducing lock",
        },
      });
    }
    if (locks.length === 0) {
      warn("no env snapshots referenced by this project — nothing to lock");
    }

    const lockenv: LockEnv = {
      sensitive: true,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: projName },
      },
      locks,
      totals: {
        envCount: locks.length,
        dockerGenerated: locks.filter((l) =>
          l.docker.status === "generated"
        ).length,
        nixScaffolded: locks.filter((l) => l.nix.status === "scaffold").length,
      },
      typeStamp: "witnessed", // unvalidated at lock time; #28 replay upgrades
      writeManifest: [...written].sort(),
      warnings,
    };
    LockEnvSchema.parse(lockenv);
    const handle = await sink.writeResource("lockenv", pid, lockenv);
    sink.logger.info(`lockenv for ${projName ?? pid}`, {
      project: pid,
      envs: locks.length,
      files: written.size,
      digestPinned,
      warnings: warnings.length,
    });
    return { lockenv, dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
