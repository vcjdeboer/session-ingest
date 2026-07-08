/**
 * Tests for @vcjdeboer/session-ingest paths.ts — the shared path-safety helpers.
 * validateRoot is the security floor for capture_inputs' external-root allowlist.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  containedRel,
  rootPrefixes,
  textLike,
  validateRoot,
  walkSorted,
} from "./paths.ts";

Deno.test("containedRel returns the relative path when contained, null otherwise", () => {
  assertEquals(containedRel(["/a/b"], "/a/b/c/d"), "c/d");
  assertEquals(containedRel(["/a/b"], "/a/b"), "/a/b"); // p===pre → absolute (callers pass dirs)
  assertEquals(containedRel(["/a/b"], "/a/bx/y"), null); // not a path-segment prefix
  assertEquals(containedRel(["/a/b"], "/other"), null);
});

Deno.test("textLike: extensions + no-extension → true; unknown binary ext → false", () => {
  assert(textLike("x/y.tsv"));
  assert(textLike("x/id_rsa.pem"));
  assert(textLike("x/README")); // no extension
  assert(!textLike("x/blob.bin"));
  assert(!textLike("x/img.png"));
});

Deno.test("validateRoot ACCEPTS a real directory under an allowed base", async () => {
  const base = await Deno.makeTempDir({ prefix: "vr-base-" });
  const baseReal = await Deno.realPath(base);
  const root = `${baseReal}/sub`;
  await Deno.mkdir(root);
  try {
    const r = await validateRoot(root, { allowedBases: [baseReal] });
    assert(r.ok, "should accept a dir under the base");
    if (r.ok) assertEquals(r.resolved, await Deno.realPath(root));
  } finally {
    await Deno.remove(base, { recursive: true });
  }
});

Deno.test("validateRoot REJECTS a non-existent root (no lexical fallback)", async () => {
  const r = await validateRoot("/private/tmp/does-not-exist-xyz-123", {});
  assert(!r.ok);
});

Deno.test("validateRoot REJECTS a file root (not a directory)", async () => {
  const base = await Deno.makeTempDir({ prefix: "vr-file-" });
  const baseReal = await Deno.realPath(base);
  const f = `${baseReal}/a.txt`;
  await Deno.writeTextFile(f, "x");
  try {
    const r = await validateRoot(f, { allowedBases: [baseReal] });
    assert(!r.ok, "a file is not a valid root");
  } finally {
    await Deno.remove(base, { recursive: true });
  }
});

Deno.test("validateRoot REJECTS a directory OUTSIDE the allowed bases", async () => {
  const base = await Deno.makeTempDir({ prefix: "vr-out-" });
  const baseReal = await Deno.realPath(base);
  try {
    // real dir, but base is a different (nonexistent-under) path
    const r = await validateRoot(baseReal, { allowedBases: ["/private/tmp"] });
    assert(!r.ok, "outside the base must be rejected");
  } finally {
    await Deno.remove(base, { recursive: true });
  }
});

Deno.test("validateRoot REJECTS a symlink whose TARGET is outside the bases", async () => {
  const base = await Deno.makeTempDir({ prefix: "vr-link-" });
  const baseReal = await Deno.realPath(base);
  const outside = await Deno.makeTempDir({ prefix: "vr-secret-" });
  const outsideReal = await Deno.realPath(outside);
  const link = `${baseReal}/link`;
  await Deno.symlink(outsideReal, link);
  try {
    // base allows baseReal, but the symlink resolves to outsideReal → reject
    const r = await validateRoot(link, { allowedBases: [baseReal] });
    assert(!r.ok, "symlink resolving outside the base must be rejected");
  } finally {
    await Deno.remove(base, { recursive: true });
    await Deno.remove(outside, { recursive: true });
  }
});

Deno.test("validateRoot ACCEPTS a sensitive (out-of-base) root ONLY with allowSensitiveRoot + opt-in", async () => {
  const dir = await Deno.makeTempDir({ prefix: "vr-sens-" });
  const dirReal = await Deno.realPath(dir);
  try {
    const denied = await validateRoot(dirReal, { allowedBases: ["/private/tmp"] });
    assert(!denied.ok, "denied without opt-in");
    const allowed = await validateRoot(dirReal, {
      allowedBases: ["/private/tmp"],
      allowSensitiveRoot: true,
      sensitiveRootOptIn: [dirReal],
    });
    assert(allowed.ok, "allowed with allowSensitiveRoot + exact opt-in");
    // opt-in must be the EXACT root string
    const wrongOptIn = await validateRoot(dirReal, {
      allowedBases: ["/private/tmp"],
      allowSensitiveRoot: true,
      sensitiveRootOptIn: ["/some/other/path"],
    });
    assert(!wrongOptIn.ok, "opt-in must name the exact root");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("rootPrefixes returns unique resolve+real prefixes", () => {
  const p = rootPrefixes("/private/tmp/x");
  assert(p.includes("/private/tmp/x"));
});

Deno.test("walkSorted returns files in deterministic sorted order, skipping symlinks", async () => {
  const d = await Deno.makeTempDir({ prefix: "walk-" });
  try {
    await Deno.mkdir(`${d}/sub`);
    await Deno.writeTextFile(`${d}/b.txt`, "b");
    await Deno.writeTextFile(`${d}/a.txt`, "a");
    await Deno.writeTextFile(`${d}/sub/c.txt`, "c");
    await Deno.symlink("/etc", `${d}/link`); // must be skipped
    const files = await walkSorted(d);
    assertEquals(files, [`${d}/a.txt`, `${d}/b.txt`, `${d}/sub/c.txt`]);
  } finally {
    await Deno.remove(d, { recursive: true });
  }
});
