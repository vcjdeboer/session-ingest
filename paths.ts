/**
 * @vcjdeboer/session-ingest — paths.ts
 *
 * Shared filesystem path safety + deterministic walk, used by both `corpus.ts`
 * (org-tree byte capture) and `inputs.ts` (Tier-1 /tmp freeze). Centralised so the
 * security-critical containment/walk logic never diverges between callers.
 * @module
 */
import { relative, resolve, SEPARATOR } from "jsr:@std/path@1.1.5";

/** Small text-like files get a sampled secret tripwire (warn-only); >= this are not sampled. */
export const TRIPWIRE_MAX = 256 * 1024;
/** Extensions treated as text-like for the tripwire — incl. credential-bearing formats. */
export const TEXT_EXT = new Set([
  ".txt",
  ".md",
  ".json",
  ".csv",
  ".tsv",
  ".py",
  ".r",
  ".sh",
  ".yaml",
  ".yml",
  ".env",
  ".cfg",
  ".ini",
  ".nwk",
  ".toml",
  ".xml",
  ".log",
  // credential-bearing formats — sample these so a copied secret is flagged
  ".pem",
  ".key",
  ".crt",
  ".cer",
  ".der",
  ".pfx",
  ".p12",
  ".keystore",
  ".pkcs12",
]);

/**
 * Containment check against a set of prefixes (each caller passes BOTH the resolved
 * and realpath'd root, since on macOS /tmp→/private/tmp and /var→/private/var).
 * Returns the prefix-relative path if `p` is contained, else null (outside → skip).
 */
export function containedRel(prefixes: string[], p: string): string | null {
  for (const pre of prefixes) {
    if (p === pre || p.startsWith(pre + SEPARATOR)) {
      return relative(pre, p) || p;
    }
  }
  return null;
}

/** A deterministic, symlink-skipping recursive walk (files only), sorted by name at each level. */
export async function walkSorted(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries: Deno.DirEntry[] = [];
  try {
    for await (const e of Deno.readDir(dir)) entries.push(e);
  } catch {
    return out;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const e of entries) {
    const p = `${dir}/${e.name}`;
    if (e.isSymlink) continue; // never follow a symlink (escape / non-verifiable)
    if (e.isDirectory) out.push(...await walkSorted(p));
    else if (e.isFile) out.push(p);
  }
  return out;
}

/** True if a path's extension is text-like (or it has no extension / is a dotfile). */
export function textLike(path: string): boolean {
  const base = path.slice(path.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return true; // no extension (or dotfile) → treat as text-like
  return TEXT_EXT.has(base.slice(dot).toLowerCase());
}

/** The containment prefix set for a (realpath'd) root: unique [resolve, realRoot]. */
export function rootPrefixes(realRoot: string): string[] {
  return [...new Set([resolve(realRoot), realRoot])];
}

export type ValidateRootResult =
  | { ok: true; resolved: string }
  | { ok: false; reason: string };

/**
 * Validate a user-supplied external root before it is ever walked. ALLOWLIST model:
 *  - realPath MUST succeed (ENOENT / uncanonicalizable → reject; NO lexical fallback,
 *    so `<base>/../<sensitive>` can't sneak through unresolved).
 *  - the realpath'd TARGET must be a DIRECTORY (a symlink root is resolved first, so a
 *    symlink → ~/.ssh is checked as ~/.ssh, not the link).
 *  - the realpath'd TARGET must resolve UNDER an allowed base (default /private/tmp,
 *    /tmp), UNLESS allowSensitiveRoot AND the ORIGINAL root string is opted-in.
 */
export async function validateRoot(
  root: string,
  opts: {
    allowedBases?: string[];
    allowSensitiveRoot?: boolean;
    sensitiveRootOptIn?: string[];
  } = {},
): Promise<ValidateRootResult> {
  let real: string;
  try {
    real = await Deno.realPath(root);
  } catch {
    return {
      ok: false,
      reason: "root does not exist / cannot be canonicalized",
    };
  }
  let info: Deno.FileInfo;
  try {
    info = await Deno.stat(real);
  } catch {
    return { ok: false, reason: "root cannot be stat'd" };
  }
  if (!info.isDirectory) {
    return { ok: false, reason: "root is not a directory" };
  }

  const bases = opts.allowedBases ?? ["/private/tmp", "/tmp"];
  const baseReals = (await Promise.all(
    bases.map((b) => Deno.realPath(b).catch(() => resolve(b))),
  )).flatMap((b) => rootPrefixes(b));
  const underBase = containedRel(baseReals, real) !== null;

  const optedIn = !!opts.allowSensitiveRoot &&
    (opts.sensitiveRootOptIn ?? []).includes(root);

  if (underBase || optedIn) return { ok: true, resolved: real };
  return {
    ok: false,
    reason:
      "root outside the allowed base(s) and not an opted-in sensitive root",
  };
}
