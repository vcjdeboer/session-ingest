/**
 * Tests for @vcjdeboer/session-ingest inputs.ts (capture_inputs).
 * Skip-guarded on sqlite3. Builds its own org db + external-root trees under
 * makeTempDir (which is /var/folders → /private/var, exercising the realpath
 * containment path); never touches real CS data or real /tmp.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  captureInputs,
  deriveTmpRoots,
  type Inputs,
  type InputsSink,
} from "./inputs.ts";
import { preflightSqlite } from "./db.ts";

Deno.test("deriveTmpRoots: distinct top-level /tmp roots from files_read/written trace", () => {
  const rows = [
    {
      files_written: JSON.stringify([
        { path: "/tmp/quant/ref/seal.fna.gz", sha256: "a" },
        { path: "/private/tmp/cds/panel.json", sha256: "b" },
      ]),
      files_read: JSON.stringify([{ path: "/tmp/quant/idx/x.bin" }]),
    },
    {
      files_written: JSON.stringify([{ path: "/tmp/sel/keep.json" }]),
      // paths OUTSIDE /tmp must be ignored (handled by capture_corpus, not here)
      files_read: JSON.stringify([
        "/Users/x/.claude-science/orgs/o/workspaces/w/handoff/meta.json",
      ]),
    },
  ];
  assertEquals(deriveTmpRoots(rows), [
    "/private/tmp/cds",
    "/tmp/quant",
    "/tmp/sel",
  ]);
});

Deno.test("deriveTmpRoots: tolerant of null/malformed/empty trace", () => {
  assertEquals(deriveTmpRoots([]), []);
  assertEquals(
    deriveTmpRoots([
      { files_written: null, files_read: undefined },
      { files_written: "not json", files_read: "{}" },
      { files_written: JSON.stringify([{ nope: 1 }]) },
    ]),
    [],
  );
});

const HAVE = (await preflightSqlite()).ok;
const enc = (s: string) => new TextEncoder().encode(s);

async function sqlite(db: string, sql: string): Promise<void> {
  const out = await new Deno.Command("sqlite3", { args: [db, sql] }).output();
  if (!out.success) throw new Error(new TextDecoder().decode(out.stderr));
}

function fakeSink() {
  const resources: Record<string, unknown> = {};
  const files: Record<string, Uint8Array> = {};
  const sink: InputsSink = {
    writeResource: (spec, inst, data) => {
      resources[`${spec}/${inst}`] = data;
      return Promise.resolve({ version: 1 });
    },
    createFileWriter: (spec, inst) => ({
      writeAll: (c: Uint8Array) => {
        files[`${spec}/${inst}`] = c;
        return Promise.resolve({});
      },
      writeStream: async (s: ReadableStream<Uint8Array>) => {
        const chunks: Uint8Array[] = [];
        for await (const ch of s) chunks.push(ch);
        const total = chunks.reduce((n, c) => n + c.length, 0);
        const buf = new Uint8Array(total);
        let o = 0;
        for (const c of chunks) { buf.set(c, o); o += c.length; }
        files[`${spec}/${inst}`] = buf;
        return {};
      },
    }),
    logger: { info: () => {} },
  };
  return { sink, resources, files };
}

const MANIFEST = "run species common group\nSRR11884684 Mirounga elephant diver\nSRR9201556 Leptonychotes weddell diver\njunkline\n";
const ASSEMBLIES = '{"Mirounga":{"sci":"M. angustirostris","assembly":"GCF_029215605.1"}}';
const SECRET_ENV = "API_TOKEN=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n";

/** Build an org db (projects only) + return csRoot + the external base (an allowedBases entry). */
async function makeOrg(): Promise<{ csRoot: string; extBase: string; extReal: string }> {
  const csRoot = await Deno.makeTempDir({ prefix: "inp-org-" });
  const orgDir = `${csRoot}/orgs/org1`;
  await Deno.mkdir(orgDir, { recursive: true });
  await sqlite(
    `${orgDir}/operon-cli.db`,
    `PRAGMA journal_mode=WAL;
     CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
     INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL);`,
  );
  const extBase = await Deno.makeTempDir({ prefix: "inp-ext-" });
  const extReal = await Deno.realPath(extBase);
  return { csRoot, extBase, extReal };
}

async function mk(path: string, bytes: Uint8Array): Promise<void> {
  await Deno.mkdir(path.slice(0, path.lastIndexOf("/")), { recursive: true });
  await Deno.writeFile(path, bytes);
}

Deno.test({
  name: "inputs: copy + accession harvest + tripwire + over-cap by-reference + symlink skip",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    const copyroot = `${extBase}/copyroot`;
    await mk(`${copyroot}/small.txt`, enc("hello"));
    await mk(`${copyroot}/manifest.tsv`, enc(MANIFEST));
    await mk(`${copyroot}/assemblies.json`, enc(ASSEMBLIES));
    await mk(`${copyroot}/secret.env`, enc(SECRET_ENV));
    await mk(`${copyroot}/big.bin`, new Uint8Array(4096)); // > maxFileBytes=1024 → by-reference
    const outside = await Deno.makeTempDir({ prefix: "inp-out-" });
    await Deno.writeTextFile(`${outside}/leak.txt`, "SECRET");
    await Deno.symlink(`${outside}/leak.txt`, `${copyroot}/link.txt`); // must be skipped
    try {
      const { sink, resources, files } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/copyroot`],
        maxFileBytes: 1024,
        allowedBases: [extReal],
      });
      assertEquals(resources["inputs/proj_abc123"], c);
      const root = c.roots[0];
      const copied = root.copied.map((x) => x.relPath);
      assert(copied.includes("small.txt"), "small.txt copied");
      assert(copied.includes("manifest.tsv"), "manifest copied");
      assert(copied.includes("assemblies.json"), "assemblies copied");
      // over-cap big.bin → by-reference even in a copy root
      assert(root.referenced.some((x) => x.relPath === "big.bin"), "big.bin by-reference");
      assert(!files["blob/" + (root.copied.find((x) => x.relPath === "big.bin")?.sha ?? "")], "big not blobbed");
      // accessions harvested (space-delimited manifest; a TAB split would yield 0)
      assertEquals(c.accessions.sra, ["SRR11884684", "SRR9201556"]);
      assertEquals(c.accessions.refseq, ["GCF_029215605.1"]);
      // tripwire on the .env token
      assert(c.totals.secretShapedCount >= 1, "secret .env tripped");
      assert(copied.includes("secret.env"), "secret still copied (sensitive bundle)");
      // symlink escape NOT captured, and no absolute path leaked into the record
      assert(!copied.includes("link.txt") && !root.referenced.some((x) => x.relPath === "link.txt"), "symlink skipped");
      assert(!JSON.stringify(c).includes(outside), "no outside absolute path in the record");
      // no absolute filesystem path (the ext base or the outside dir) leaks into warnings
      assert(!JSON.stringify(c.warnings).includes(extReal), "warnings carry no ext-base abs path");
      assert(!JSON.stringify(c.warnings).includes(outside), "warnings carry no outside abs path");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: referenceRoot records path+size only (no blob); accession still copied",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/refroot/refbig.bin`, new Uint8Array(2048));
    await mk(`${extBase}/refroot/manifest.tsv`, enc(MANIFEST));
    try {
      const { sink, files } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/refroot`],
        referenceRoots: [`${extReal}/refroot`],
        allowedBases: [extReal],
      });
      const root = c.roots[0];
      assert(root.referenced.some((x) => x.relPath === "refbig.bin"), "refbig referenced");
      const refEntry = root.referenced.find((x) => x.relPath === "refbig.bin")!;
      assertEquals(refEntry.sha, undefined, "no sha when hashReferenced=false");
      // no blob written for the referenced file
      assertEquals(Object.keys(files).length, root.copied.length, "only copied files blobbed");
      // accession file still copied + parsed even inside a referenceRoot
      assert(root.copied.some((x) => x.relPath === "manifest.tsv"), "manifest copied in refRoot");
      assert(c.accessions.sra.length === 2, "accessions harvested from refRoot manifest");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: most-specific-root-wins + canonical dedup across overlapping walk roots",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/parent/sub/f.txt`, enc("dup"));
    await mk(`${extBase}/parent/top.txt`, enc("top"));
    try {
      const { sink } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/parent`, `${extReal}/parent/sub`], // overlapping
        allowedBases: [extReal],
      });
      // f.txt appears ONCE, owned by the most-specific root (parent/sub → relPath "f.txt")
      const allCopied = c.roots.flatMap((r) => r.copied.map((x) => `${r.resolvedRoot}|${x.relPath}`));
      const fEntries = c.roots.flatMap((r) => r.copied).filter((x) => x.relPath.endsWith("f.txt"));
      assertEquals(fEntries.length, 1, "f.txt deduped to one entry");
      assert(allCopied.some((s) => s.endsWith("/parent/sub|f.txt")), "owned by most-specific root");
      assertEquals(c.totals.files, 2, "two distinct files total");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: out-of-base root is rejected (warn, nothing captured)",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    const other = await Deno.makeTempDir({ prefix: "inp-other-" });
    await Deno.writeTextFile(`${other}/x.txt`, "x");
    try {
      const { sink } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [other], // NOT under extReal
        allowedBases: [extReal],
      });
      assertEquals(c.capturedRoots.length, 0, "no roots accepted");
      assertEquals(c.totals.files, 0);
      assert(c.warnings.some((w) => /root rejected/.test(w)), "rejection warned");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
      await Deno.remove(other, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: a per-file IO failure is warned WITHOUT leaking an absolute path, and does not overcount totals (H1/M2)",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/r/ok.txt`, enc("ok"));
    const noperm = `${extBase}/r/noperm.txt`;
    await mk(noperm, enc("blocked"));
    await Deno.chmod(noperm, 0o000); // unreadable → copy fails on the per-file error path
    try {
      const { sink } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/r`],
        allowedBases: [extReal],
      });
      // the failure is surfaced (root-relative), not silent …
      assert(c.warnings.some((w) => /noperm\.txt/.test(w)), "the failing file is warned");
      // … but the per-file error text carries NO absolute path (the H1 contract). Note:
      // roots[].resolvedRoot / capturedRoots legitimately echo the DECLARED roots, so the
      // guarantee is specifically about warning text, not the whole record.
      assert(!JSON.stringify(c.warnings).includes(extReal), "no abs path in any warning (H1)");
      assert(!JSON.stringify(c).includes(`${extReal}/r/noperm.txt`), "the failing file's abs path never leaks");
      // totals.files counts only files actually frozen, not the failed one (M2)
      const frozen = c.roots.reduce((n, r) => n + r.copied.length + r.referenced.length, 0);
      assertEquals(c.totals.files, frozen, "totals.files == frozen count (no overcount)");
    } finally {
      await Deno.chmod(noperm, 0o600).catch(() => {});
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: a referenceRoot outside the walk roots is TRULY ignored — files stay frozen, not silently by-referenced (H3)",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/proj/a.txt`, enc("freeze me"));
    try {
      const { sink } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/proj`],
        referenceRoots: [extReal], // PARENT of the walk root → under no accepted root
        allowedBases: [extReal],
      });
      assert(c.warnings.some((w) => /under no accepted walk root/.test(w)), "over-broad refRoot warned");
      const root = c.roots[0];
      assert(root.copied.some((x) => x.relPath === "a.txt"), "a.txt COPIED (frozen), not silently by-referenced");
      assert(!root.referenced.some((x) => x.relPath === "a.txt"), "a.txt NOT by-referenced");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: a non-manifest .tsv honors referenceOver instead of being force-copied (M1)",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/q/abundance.tsv`, new Uint8Array(4096)); // a big DATA .tsv (not a recipe)
    await mk(`${extBase}/q/manifest.tsv`, enc(MANIFEST)); // the recipe: still always-copied
    try {
      const { sink } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/q`],
        referenceOver: 1024,
        allowedBases: [extReal],
      });
      const root = c.roots[0];
      assert(root.referenced.some((x) => x.relPath === "abundance.tsv"), "big data .tsv by-reference (not hoarded)");
      assert(!root.copied.some((x) => x.relPath === "abundance.tsv"), "big data .tsv NOT copied");
      assert(root.copied.some((x) => x.relPath === "manifest.tsv"), "manifest.tsv still copied (recipe)");
      assertEquals(c.accessions.sra.length, 2, "manifest still harvested");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: a root listed twice yields ONE root entry, no double count (M5)",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/d/one.txt`, enc("x"));
    try {
      const { sink } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/d`, `${extReal}/d`], // same root twice (or two aliases of one realpath)
        allowedBases: [extReal],
      });
      assertEquals(c.roots.length, 1, "deduped to one root entry");
      assertEquals(c.totals.files, 1, "one file counted once");
      assertEquals(c.roots.reduce((n, r) => n + r.copied.length, 0), 1, "file not double-listed");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: hashReferenced records a sha on referenced entries without writing a blob (M6)",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/ref/big.bin`, new Uint8Array(2048));
    try {
      const { sink, files } = fakeSink();
      const { inputs: c } = await captureInputs(csRoot, "gdh", undefined, sink, {
        roots: [`${extReal}/ref`],
        referenceRoots: [`${extReal}/ref`],
        hashReferenced: true,
        allowedBases: [extReal],
      });
      const e = c.roots[0].referenced.find((x) => x.relPath === "big.bin")!;
      assert(typeof e.sha === "string" && /^[0-9a-f]{64}$/.test(e.sha!), "referenced entry carries a sha");
      assertEquals(Object.keys(files).length, 0, "no blob bytes written for a referenced file");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});

Deno.test({
  name: "inputs: self-describing, NO drift field, deterministic two-run, source unmutated",
  ignore: !HAVE,
  fn: async () => {
    const { csRoot, extBase, extReal } = await makeOrg();
    await mk(`${extBase}/r/a.txt`, enc("a"));
    await mk(`${extBase}/r/manifest.tsv`, enc(MANIFEST));
    const srcSha = async (p: string) =>
      [...new Uint8Array(await crypto.subtle.digest("SHA-256", await Deno.readFile(p)))]
        .map((b) => b.toString(16).padStart(2, "0")).join("");
    const before = await srcSha(`${extBase}/r/a.txt`);
    try {
      const a = fakeSink();
      const r1 = await captureInputs(csRoot, "gdh", undefined, a.sink, { roots: [`${extReal}/r`], allowedBases: [extReal] });
      const b = fakeSink();
      const r2 = await captureInputs(csRoot, "gdh", undefined, b.sink, { roots: [`${extReal}/r`], allowedBases: [extReal] });
      assertEquals(JSON.stringify(r1.inputs), JSON.stringify(r2.inputs), "two runs byte-identical");
      const c: Inputs = r1.inputs;
      assert(c.capturedRoots.length === 1, "self-describing capturedRoots");
      assert(!JSON.stringify(c).includes('"drift"'), "no drift field (/tmp untracked)");
      assertEquals(await srcSha(`${extBase}/r/a.txt`), before, "source file unmutated");
    } finally {
      await Deno.remove(csRoot, { recursive: true });
      await Deno.remove(extBase, { recursive: true });
    }
  },
});
