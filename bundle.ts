/**
 * @vcjdeboer/session-ingest — bundle.ts
 *
 * The `seal` method (#29): assemble a captured CS session's resources into a
 * logical, order-stable bundle-manifest, stamped with its reproducibility
 * honesty. Pure helpers (canonical ordering, stamp resolution, manifest
 * assembly) are extracted so they unit-test without a runtime; the `seal` method
 * takes injected readers (queryData/readResource) so it too unit-tests via stubs.
 * The witness digest is produced by @vcjdeboer/session-witness `seal_manifest`,
 * wired downstream by the `seal-bundle` workflow — seal writes only its own
 * bundle-manifest resource.
 *
 * @module
 */
import { z } from "npm:zod@4";

/**
 * Canonical order of the sealable capture resources. The digest chains items in
 * THIS order, so it is fixed and reproducible. `matchspec` is listed for when the
 * baseline method registers it; until then it is simply never present.
 */
export const CANONICAL_ORDER = [
  "corpus",
  "provenance",
  "matchspec",
  "lockenv",
  "transcript",
  "inputs",
  "external",
  "credentials",
  // Appended (.11.8) so the pre-existing digest order above is preserved: the
  // replay-critical resources produced by capture_cells/capture_skills/
  // capture_host_calls. Before this they were silently dropped from the seal.
  "cells",
  "skills",
  "host_calls",
] as const;

/** One sealable resource: its spec name, swamp content checksum, and content-ref. */
export interface BundleItem {
  name: string;
  checksum: string;
  ref: string;
}

export type BundleStamp = "witnessed" | "replayable-nix" | "replayable-docker";

/** The `bundle-manifest` resource schema: the logical, order-stable bundle index. */
export const BundleManifestSchema = z.object({
  session: z.string(),
  items: z.array(
    z.object({ name: z.string(), checksum: z.string(), ref: z.string() }),
  ).default([]),
  stamp: z.enum(["witnessed", "replayable-nix", "replayable-docker"]),
  origin: z.object({
    tool: z.string(),
    build: z.string().default(""),
    org: z.string().default(""),
    proj: z.string(),
  }),
});
export type BundleManifest = z.infer<typeof BundleManifestSchema>;

/** Order the present items by CANONICAL_ORDER, dropping any not in the set. */
export function orderItems(present: BundleItem[]): BundleItem[] {
  const idx = new Map<string, number>(
    CANONICAL_ORDER.map((n, i) => [n, i]),
  );
  return present
    .filter((p) => idx.has(p.name))
    .slice()
    .sort((a, b) => idx.get(a.name)! - idx.get(b.name)!);
}

/**
 * Resolve the honesty stamp from a replay verdict: `replayable-nix`/`-docker`
 * only when a run actually reproduced in that env; otherwise `witnessed`.
 */
export function resolveStamp(
  verdict: { reproduced?: boolean; envUsed?: string } | null,
): BundleStamp {
  if (verdict?.reproduced && verdict.envUsed === "nix") return "replayable-nix";
  if (verdict?.reproduced && verdict.envUsed === "docker") {
    return "replayable-docker";
  }
  return "witnessed";
}

/** Assemble the bundle-manifest: ordered items + stamp + origin. */
export function buildBundleManifest(
  session: string,
  present: BundleItem[],
  verdict: { reproduced?: boolean; envUsed?: string } | null,
  origin: { tool: string; build: string; org: string; proj: string },
): BundleManifest {
  return {
    session,
    items: orderItems(present),
    stamp: resolveStamp(verdict),
    origin,
  };
}

/** Sanitize a session id into a swamp instance name. */
function safeName(s: string): string {
  return (s || "session").replace(/[^A-Za-z0-9_-]/g, "_");
}

export const SealArgsSchema = z.object({
  /** The session's proj_id — the instance key every capture resource is keyed by. */
  session: z.string().min(1),
  /** Org the session belongs to (origin stamp). */
  org: z.string().default(""),
  /** Ingesting tool build id (origin stamp). */
  build: z.string().default(""),
});

/** Enumerates a session's captured resources as {specName, checksum, ref}. */
type Enumerator = (instance: string) => Promise<BundleItem[]>;

interface SealContext {
  modelId: string;
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** Shell out to the swamp CLI and parse its JSON, or null (witness's pattern). */
async function swampJson(args: string[]): Promise<unknown> {
  try {
    const out = await new Deno.Command("swamp", {
      args,
      stdout: "piped",
      stderr: "piped",
    }).output();
    return JSON.parse(new TextDecoder().decode(out.stdout));
  } catch {
    return null;
  }
}

/**
 * Default enumerator: a session's captured resources all share one dataName
 * (the proj_id) as accumulating VERSIONS — v1 manifest, v2 provenance, v3 corpus,
 * … — and swamp's content checksum lives in `data versions`, while the spec
 * identity lives in each version's `tags.specName` (neither is in queryData). So
 * we shell out (witness's proven pattern): list the versions for their checksums,
 * then read each version's `tags.specName`, keeping the LATEST version per spec.
 */
function defaultEnumerate(ctx: SealContext): Enumerator {
  return async (instance) => {
    // `data versions`/`data get` resolve by model NAME, not id — resolve it once.
    const mres = (await swampJson(["model", "get", ctx.modelId, "--json"])) as
      | { name?: string }
      | null;
    const model = mres?.name ?? ctx.modelId;
    const vres = (await swampJson(
      ["data", "versions", model, instance, "--json"],
    )) as { versions?: Array<{ version: number; checksum?: string }> } | null;
    const versions = (vres?.versions ?? []).slice().sort((a, b) =>
      b.version - a.version
    );
    const items: BundleItem[] = [];
    const seen = new Set<string>();
    for (const v of versions) {
      const got = (await swampJson([
        "data",
        "get",
        model,
        instance,
        "--version",
        String(v.version),
        "--json",
      ])) as { tags?: { specName?: string }; checksum?: string } | null;
      const spec = got?.tags?.specName;
      const checksum = v.checksum ?? got?.checksum;
      if (spec && checksum && !seen.has(spec)) {
        seen.add(spec);
        items.push({
          name: spec,
          checksum,
          ref: `${spec}/${instance}@${v.version}`,
        });
      }
    }
    return items;
  };
}

/**
 * The `seal` method: enumerate the session's captured resources (their swamp
 * content checksums), assemble the order-stable, canonically-ordered
 * bundle-manifest, and write it. The witness DIGEST over these items is produced
 * downstream by `session-witness.seal_manifest` (the `seal-bundle` workflow) —
 * seal writes only its own `bundle-manifest`. Injected `_enumerate`/`_verdict`
 * seams keep it unit-testable without a runtime.
 */
export async function runSeal(
  args: z.input<typeof SealArgsSchema> & {
    _enumerate?: Enumerator;
    _verdict?: { reproduced?: boolean; envUsed?: string } | null;
  },
  context: SealContext,
): Promise<{ dataHandles: unknown[] }> {
  const enumerate = args._enumerate ?? defaultEnumerate(context);
  const present = await enumerate(args.session);
  const verdict = args._verdict ?? null;
  const origin = {
    tool: "session-ingest",
    build: args.build ?? "",
    org: args.org ?? "",
    proj: args.session,
  };
  const manifest = buildBundleManifest(args.session, present, verdict, origin);
  const handle = await context.writeResource(
    "bundle-manifest",
    safeName(args.session),
    manifest,
  );
  context.logger.info(
    "Sealed bundle {session}: {n} items, stamp {stamp}",
    { session: args.session, n: manifest.items.length, stamp: manifest.stamp },
  );
  return { dataHandles: [handle] };
}
