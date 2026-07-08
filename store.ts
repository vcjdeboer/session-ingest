/**
 * @vcjdeboer/session-ingest — store.ts
 *
 * The per-invocation, content-addressed (sha256) OFFLOAD STORE shared by
 * `capture.ts` (message bodies / inline images) and `provenance.ts` (cell
 * source / stdout / stderr / env snapshots). Large text is written to
 * deduplicated `body` files keyed by the sha of its bytes; the caller keeps
 * only the sha (a `bodyFileRef`) in the index resource.
 *
 * DECISIONS:
 *  - PER-INVOCATION factory (`makeStore()`), never a module-level singleton, so
 *    concurrent captures never share a dedup Map — each call is hermetic and its
 *    manifest is reproducible from its own inputs alone.
 *  - `offload` dedups by content sha and preserves first-seen INSERTION ORDER;
 *    `flush` writes bodies FIRST (content-addressed, idempotent) in that order
 *    and returns the ordered sha manifest, so the same inputs always yield the
 *    same shas AND the same manifest (witness-sealable). This is the exact
 *    contract capture_test pins byte-identically.
 *  - The offload-or-inline DECISION and the size cap stay in the CALLERS; this
 *    module only stores what it is handed.
 *  - `secretTripwire` is WARN-ONLY: it flags secret-shaped content without ever
 *    mutating it (content is stored VERBATIM; the resource is marked sensitive).
 * @module
 */

import { crypto as stdCrypto } from "jsr:@std/crypto@1.1.0";

const hex = (h: ArrayBuffer): string =>
  [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");

/** sha256 of a string's UTF-8 bytes, as 64 lowercase hex chars. */
export async function sha256hex(s: string): Promise<string> {
  return hex(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)),
  );
}

/** sha256 of RAW bytes (binary-safe), as 64 lowercase hex chars. */
export async function sha256hexBytes(bytes: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/** Streaming sha256 of a file — hashes chunk-by-chunk without loading the whole file. */
async function sha256hexFileStream(path: string): Promise<string> {
  const f = await Deno.open(path, { read: true });
  // @std/crypto's digest accepts an (async) iterable of chunks (Deno's file .readable is one),
  // hashing without ever materializing the full file in memory. Consuming the stream closes
  // the fd on success; on any error cancel it so the fd never leaks (fd-exhaustion guard).
  try {
    return hex(await stdCrypto.subtle.digest("SHA-256", f.readable));
  } catch (e) {
    await f.readable.cancel().catch(() => {});
    throw e;
  }
}

/** Streaming sha256 of an ALREADY-OPEN fd (consumes + closes it on success). */
async function sha256hexFd(f: Deno.FsFile): Promise<string> {
  try {
    return hex(await stdCrypto.subtle.digest("SHA-256", f.readable));
  } catch (e) {
    await f.readable.cancel().catch(() => {});
    throw e;
  }
}

/**
 * Open a file for reading, REFUSING to follow a symlink at the final path component.
 * Deno has no `O_NOFOLLOW`, so we `lstat` immediately before `open` — the residual
 * window is sub-millisecond, and once the fd is open a later swap cannot redirect it.
 * Used by `noFollow` captures over a world-writable tree (TOCTOU hardening).
 */
async function guardedOpen(path: string): Promise<Deno.FsFile> {
  const li = await Deno.lstat(path);
  if (li.isSymlink) {
    throw new Deno.errors.NotFound(
      "refusing to read through a symlink at a capture path",
    );
  }
  return await Deno.open(path, { read: true });
}

/** WARN-only tripwire: flags secret-shaped content. NEVER mutates (verbatim preserved). */
export const CONTENT_SECRET_RE =
  /sk-[A-Za-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}|(?:bearer|api[_-]?key|secret|token|password)["'\s:=]+[A-Za-z0-9._-]{16,}/i;

/** Flag secret-shaped text without mutating it. Pushes one warning; never throws. */
export function secretTripwire(
  text: string,
  warn: (m: string) => void,
  where: string,
): void {
  if (text && CONTENT_SECRET_RE.test(text)) {
    warn(
      `secret-shaped content in ${where} — captured VERBATIM (not mutated); bundle is sensitive/private`,
    );
  }
}

/** The slice of a model execute context the store needs to persist bodies. */
export interface FileSink {
  createFileWriter: (
    spec: string,
    instance: string,
    overrides?: { contentType?: string },
  ) => { writeAll: (content: Uint8Array) => Promise<unknown> };
}

/** A per-invocation content-addressed offload store. */
export interface Store {
  /** Register `text` as a `body` file; returns its content sha (deduped). */
  offload: (text: string) => Promise<string>;
  /** Write every registered body (files-first, insertion order); returns the ordered sha manifest. */
  flush: (sink: FileSink) => Promise<string[]>;
}

/* ============================ binary blob store ============================ */

/** The slice of a model execute context the blob store needs (streaming-capable). */
export interface BlobSink {
  createFileWriter: (
    spec: string,
    instance: string,
    overrides?: { contentType?: string },
  ) => {
    writeAll: (content: Uint8Array) => Promise<unknown>;
    writeStream?: (stream: ReadableStream<Uint8Array>) => Promise<unknown>;
  };
}

/** Default size above which a file is streamed (writeStream) rather than read whole. */
export const BLOB_STREAM_THRESHOLD = 64 * 1024 * 1024; // 64 MiB

export interface BlobResult {
  sha: string; // content sha256 (64 hex)
  size: number; // bytes on disk
  deduped: boolean; // sha already stored this invocation -> not re-written
  skipped: boolean; // over maxFileBytes -> hashed but NOT copied (by-reference)
  /**
   * The exact bytes read — populated ONLY on the `noFollow` SMALL-file path. Lets a caller
   * harvest/scan the content it just froze WITHOUT re-opening the path (which would reintroduce
   * a TOCTOU window and a redundant read). Undefined for streamed/over-cap/legacy copies.
   */
  bytes?: Uint8Array;
}

export interface BlobCopyOpts {
  /** Above this, hash + copy the file by-reference only (record path+sha+size, don't store bytes). */
  maxFileBytes?: number;
  /** Above this, stream the copy (writeStream) instead of reading the whole file. */
  streamThreshold?: number;
  /**
   * Refuse to read through a symlink at `srcPath` (TOCTOU hardening for capture over a
   * world-writable tree). Each open is preceded by an `lstat`-not-symlink assert as close
   * to the syscall as Deno allows (Deno has no `O_NOFOLLOW`); small files are read from a
   * single fd so no post-open re-resolution can redirect them.
   */
  noFollow?: boolean;
}

export interface BlobStore {
  /** Content-address a file into the `blob` spec (streaming for large files); dedup by sha SET. */
  copyFileToBlob: (
    srcPath: string,
    sink: BlobSink,
    opts?: BlobCopyOpts,
  ) => Promise<BlobResult>;
  /** Distinct blob shas written this invocation, in first-seen order. */
  manifest: () => string[];
}

/**
 * A per-invocation, content-addressed BINARY store for the artifact/workspace byte
 * corpus. MEMORY-SAFE: processes one file at a time and NEVER retains a Map of bytes
 * (only a sha SET) — small files are read once (single read, no TOCTOU), large files
 * are hashed + written by streaming, so peak RSS is bounded by a single file (or a
 * chunk), never the whole 2.5GB corpus.
 */
export function makeBlobStore(): BlobStore {
  const seen = new Set<string>();
  const order: string[] = [];
  return {
    manifest: () => [...order],
    copyFileToBlob: async (srcPath, sink, opts = {}) => {
      const threshold = opts.streamThreshold ?? BLOB_STREAM_THRESHOLD;

      if (opts.noFollow) {
        // TOCTOU-hardened path: open once under a symlink guard; small files (the
        // credential-risk ones) are read from a SINGLE fd so no post-open re-resolution
        // can redirect them. Large files still need two passes (hash then copy) — each
        // open is re-guarded.
        const f = await guardedOpen(srcPath);
        let consumed = false;
        try {
          const size = (await f.stat()).size;
          if (opts.maxFileBytes !== undefined && size > opts.maxFileBytes) {
            const sha = await sha256hexFd(f); // over-cap: content-address only, no bytes stored
            consumed = true;
            return { sha, size, deduped: seen.has(sha), skipped: true };
          }
          if (size <= threshold) {
            const bytes = new Uint8Array(
              await new Response(f.readable).arrayBuffer(),
            );
            consumed = true; // f.readable was consumed → fd closed
            const sha = await sha256hexBytes(bytes);
            if (seen.has(sha)) {
              return { sha, size, deduped: true, skipped: false, bytes };
            }
            await sink.createFileWriter("blob", sha, {
              contentType: "application/octet-stream",
            }).writeAll(bytes);
            seen.add(sha);
            order.push(sha);
            return { sha, size, deduped: false, skipped: false, bytes };
          }
          // large: hash this fd, then re-open (guarded) to stream-copy — RSS bounded
          const sha = await sha256hexFd(f);
          consumed = true;
          if (seen.has(sha)) {
            return { sha, size, deduped: true, skipped: false };
          }
          const w = sink.createFileWriter("blob", sha, {
            contentType: "application/octet-stream",
          });
          const f2 = await guardedOpen(srcPath);
          if (w.writeStream) {
            try {
              await w.writeStream(f2.readable);
            } catch (e) {
              await f2.readable.cancel().catch(() => {});
              throw e;
            }
          } else {
            try {
              await w.writeAll(
                new Uint8Array(await new Response(f2.readable).arrayBuffer()),
              );
            } catch (e) {
              await f2.readable.cancel().catch(() => {});
              throw e;
            }
          }
          seen.add(sha);
          order.push(sha);
          return { sha, size, deduped: false, skipped: false };
        } finally {
          if (!consumed) {
            try {
              f.close();
            } catch { /* already closed by a consumed stream */ }
          }
        }
      }

      const { size } = await Deno.stat(srcPath);

      // over the policy cap: hash for content-address, but do NOT copy the bytes
      if (opts.maxFileBytes !== undefined && size > opts.maxFileBytes) {
        const sha = size <= threshold
          ? await sha256hexBytes(await Deno.readFile(srcPath))
          : await sha256hexFileStream(srcPath);
        return { sha, size, deduped: seen.has(sha), skipped: true };
      }

      if (size <= threshold) {
        // small: single read — hash the exact buffer we write (no TOCTOU, no double read)
        const bytes = await Deno.readFile(srcPath);
        const sha = await sha256hexBytes(bytes);
        if (seen.has(sha)) return { sha, size, deduped: true, skipped: false };
        await sink.createFileWriter("blob", sha, {
          contentType: "application/octet-stream",
        }).writeAll(bytes);
        seen.add(sha);
        order.push(sha);
        return { sha, size, deduped: false, skipped: false };
      }

      // large: stream-hash (pass 1) then stream-copy (pass 2) — bounded RSS
      const sha = await sha256hexFileStream(srcPath);
      if (seen.has(sha)) return { sha, size, deduped: true, skipped: false };
      const w = sink.createFileWriter("blob", sha, {
        contentType: "application/octet-stream",
      });
      if (w.writeStream) {
        // open the fd ONLY on this branch; consuming the stream closes it on success,
        // and cancel() releases it if writeStream rejects before consuming (no fd leak).
        const f = await Deno.open(srcPath, { read: true });
        try {
          await w.writeStream(f.readable);
        } catch (e) {
          await f.readable.cancel().catch(() => {});
          throw e;
        }
      } else {
        await w.writeAll(await Deno.readFile(srcPath));
      }
      seen.add(sha);
      order.push(sha);
      return { sha, size, deduped: false, skipped: false };
    },
  };
}

/** Build a fresh, isolated offload store. One per capture/provenance invocation. */
export function makeStore(): Store {
  const files = new Map<string, Uint8Array>();
  return {
    offload: async (text: string): Promise<string> => {
      const sha = await sha256hex(text);
      if (!files.has(sha)) files.set(sha, new TextEncoder().encode(text));
      return sha;
    },
    flush: async (sink: FileSink): Promise<string[]> => {
      const manifest: string[] = [];
      for (const [sha, bytes] of files) {
        await sink.createFileWriter("body", sha, { contentType: "text/plain" })
          .writeAll(bytes);
        manifest.push(sha);
      }
      return manifest;
    },
  };
}
