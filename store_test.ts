/**
 * Tests for @vcjdeboer/session-ingest store.ts — the per-invocation, content-
 * addressed offload store shared by capture.ts and provenance.ts. Proves the
 * sha/dedup/flush-order contract that capture_test relies on staying byte-identical.
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  type BlobSink,
  CONTENT_SECRET_RE,
  type FileSink,
  makeBlobStore,
  makeStore,
  secretTripwire,
  sha256hex,
  sha256hexBytes,
} from "./store.ts";

function fakeFileSink() {
  const files: { spec: string; inst: string; contentType?: string; bytes: Uint8Array }[] = [];
  const sink: FileSink = {
    createFileWriter: (spec, inst, overrides) => ({
      writeAll: (c: Uint8Array) => {
        files.push({ spec, inst, contentType: overrides?.contentType, bytes: c });
        return Promise.resolve({});
      },
    }),
  };
  return { sink, files };
}

Deno.test("sha256hex is 64 lowercase hex and stable for the same input", async () => {
  const a = await sha256hex("hello");
  const b = await sha256hex("hello");
  assertEquals(a, b);
  assert(/^[0-9a-f]{64}$/.test(a), "64 lowercase hex");
});

Deno.test("makeStore.offload returns the content-addressed sha and dedups identical text", async () => {
  const store = makeStore();
  const s1 = await store.offload("same");
  const s2 = await store.offload("same");
  const s3 = await store.offload("different");
  assertEquals(s1, s2);
  assertEquals(s1, await sha256hex("same"));
  assert(s1 !== s3);
});

Deno.test("makeStore.flush writes body files in insertion order and returns their shas as the manifest", async () => {
  const store = makeStore();
  const shaA = await store.offload("aaa");
  const shaB = await store.offload("bbb");
  await store.offload("aaa"); // dedup: no new entry
  const { sink, files } = fakeFileSink();
  const manifest = await store.flush(sink);
  assertEquals(manifest, [shaA, shaB]); // insertion order, deduped
  assertEquals(files.map((f) => f.inst), [shaA, shaB]);
  assertEquals(files.map((f) => f.spec), ["body", "body"]);
  assertEquals(files.map((f) => f.contentType), ["text/plain", "text/plain"]); // body stays text/plain
  assertEquals(new TextDecoder().decode(files[0].bytes), "aaa");
  assertEquals(new TextDecoder().decode(files[1].bytes), "bbb");
});

Deno.test("makeStore is per-invocation: two stores keep independent dedup maps", async () => {
  const a = makeStore();
  const b = makeStore();
  await a.offload("x");
  const { sink: sinkB, files: filesB } = fakeFileSink();
  const manifestB = await b.flush(sinkB); // b never saw "x"
  assertEquals(manifestB, []);
  assertEquals(filesB.length, 0);
});

function fakeBlobSink() {
  const files: { spec: string; inst: string; contentType?: string; bytes: Uint8Array; via: string }[] = [];
  const sink: BlobSink = {
    createFileWriter: (spec, inst, overrides) => ({
      writeAll: (c: Uint8Array) => {
        files.push({ spec, inst, contentType: overrides?.contentType, bytes: c, via: "writeAll" });
        return Promise.resolve({});
      },
      writeStream: async (s: ReadableStream<Uint8Array>) => {
        const chunks: Uint8Array[] = [];
        for await (const ch of s) chunks.push(ch);
        const total = chunks.reduce((n, c) => n + c.length, 0);
        const buf = new Uint8Array(total);
        let o = 0;
        for (const c of chunks) { buf.set(c, o); o += c.length; }
        files.push({ spec, inst, contentType: overrides?.contentType, bytes: buf, via: "writeStream" });
        return {};
      },
    }),
  };
  return { sink, files };
}

async function tmpFile(bytes: Uint8Array): Promise<string> {
  const dir = await Deno.makeTempDir({ prefix: "blob-test-" });
  const p = `${dir}/f.bin`;
  await Deno.writeFile(p, bytes);
  return p;
}

Deno.test("sha256hexBytes hashes RAW bytes (binary-safe), matching sha256 of the bytes", async () => {
  const bytes = new Uint8Array([0, 1, 2, 255, 128, 0]);
  const got = await sha256hexBytes(bytes);
  const want = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  assertEquals(got, want);
  assert(/^[0-9a-f]{64}$/.test(got));
});

Deno.test("makeBlobStore.copyFileToBlob (small path): copies bytes to a sha-named blob with octet-stream contentType", async () => {
  const bytes = new Uint8Array([10, 20, 30, 40]);
  const src = await tmpFile(bytes);
  try {
    const store = makeBlobStore();
    const { sink, files } = fakeBlobSink();
    const r = await store.copyFileToBlob(src, sink, { streamThreshold: 1024 });
    assertEquals(r.sha, await sha256hexBytes(bytes));
    assertEquals(r.size, 4);
    assertEquals(r.deduped, false);
    assertEquals(r.skipped, false);
    assertEquals(files.length, 1);
    assertEquals(files[0].spec, "blob");
    assertEquals(files[0].inst, r.sha);
    assertEquals(files[0].contentType, "application/octet-stream");
    assertEquals(files[0].bytes, bytes);
    assertEquals(store.manifest(), [r.sha]);
  } finally {
    await Deno.remove(src.replace(/\/f\.bin$/, ""), { recursive: true });
  }
});

Deno.test("makeBlobStore dedups identical bytes by sha SET (one blob, deduped=true on repeat)", async () => {
  const bytes = new Uint8Array([1, 1, 1, 1, 1]);
  const src1 = await tmpFile(bytes);
  const src2 = await tmpFile(bytes); // same content, different path
  try {
    const store = makeBlobStore();
    const { sink, files } = fakeBlobSink();
    const r1 = await store.copyFileToBlob(src1, sink, { streamThreshold: 1024 });
    const r2 = await store.copyFileToBlob(src2, sink, { streamThreshold: 1024 });
    assertEquals(r1.sha, r2.sha);
    assertEquals(r1.deduped, false);
    assertEquals(r2.deduped, true);
    assertEquals(files.length, 1); // written once
    assertEquals(store.manifest(), [r1.sha]);
  } finally {
    await Deno.remove(src1.replace(/\/f\.bin$/, ""), { recursive: true });
    await Deno.remove(src2.replace(/\/f\.bin$/, ""), { recursive: true });
  }
});

Deno.test("makeBlobStore (large path): streams via writeStream, sha + bytes correct, never over-buffers the corpus", async () => {
  const bytes = new Uint8Array(5000).map((_, i) => i % 256);
  const src = await tmpFile(bytes);
  try {
    const store = makeBlobStore();
    const { sink, files } = fakeBlobSink();
    const r = await store.copyFileToBlob(src, sink, { streamThreshold: 1024 }); // 5000 > 1024 -> stream
    assertEquals(r.sha, await sha256hexBytes(bytes));
    assertEquals(r.size, 5000);
    assertEquals(files.length, 1);
    assertEquals(files[0].via, "writeStream");
    assertEquals(files[0].contentType, "application/octet-stream");
    assertEquals(files[0].bytes, bytes);
  } finally {
    await Deno.remove(src.replace(/\/f\.bin$/, ""), { recursive: true });
  }
});

Deno.test("makeBlobStore honors maxFileBytes: over-cap file is skipped (not written) but still hashed", async () => {
  const bytes = new Uint8Array(4096);
  const src = await tmpFile(bytes);
  try {
    const store = makeBlobStore();
    const { sink, files } = fakeBlobSink();
    const r = await store.copyFileToBlob(src, sink, { maxFileBytes: 100 });
    assertEquals(r.skipped, true);
    assertEquals(r.sha, await sha256hexBytes(bytes)); // still content-addressed
    assertEquals(files.length, 0); // NOT written
    assertEquals(store.manifest(), []);
  } finally {
    await Deno.remove(src.replace(/\/f\.bin$/, ""), { recursive: true });
  }
});

Deno.test("makeBlobStore noFollow refuses to read through a symlink at the capture path (TOCTOU guard)", async () => {
  const dir = await Deno.makeTempDir({ prefix: "blob-nofollow-" });
  const target = `${dir}/secret.txt`;
  await Deno.writeTextFile(target, "SENSITIVE-OUT-OF-TREE");
  const link = `${dir}/swapped.txt`;
  await Deno.symlink(target, link); // a file that got swapped for a symlink after canonicalization
  try {
    const store = makeBlobStore();
    const { sink, files } = fakeBlobSink();
    // legacy (no noFollow) follows the link — this is exactly the gap the guard closes
    await store.copyFileToBlob(link, sink, { streamThreshold: 1024 });
    assertEquals(new TextDecoder().decode(files[0].bytes), "SENSITIVE-OUT-OF-TREE");
    // noFollow: refuse to open through the symlink (no bytes read from the target)
    await assertRejects(
      () => store.copyFileToBlob(link, sink, { noFollow: true, streamThreshold: 1024 }),
      Error,
    );
    assertEquals(files.length, 1, "guarded call wrote nothing");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("secretTripwire warns (never throws) on secret-shaped content and is silent otherwise", () => {
  const warnings: string[] = [];
  const warn = (m: string) => warnings.push(m);
  secretTripwire("here is sk-ABCDEFGHIJKLMNOPQRSTUVWX token", warn, "source");
  secretTripwire("just ordinary output", warn, "stdout");
  assertEquals(warnings.length, 1);
  assert(/secret-shaped/.test(warnings[0]));
  assert(/source/.test(warnings[0]));
  assert(CONTENT_SECRET_RE.test("sk-ABCDEFGHIJKLMNOPQRSTUVWX"));
});
