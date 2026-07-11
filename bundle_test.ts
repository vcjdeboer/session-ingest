import { assertEquals } from "jsr:@std/assert@1";
import {
  buildBundleManifest,
  type BundleItem,
  orderItems,
  resolveStamp,
  runSeal,
} from "./bundle.ts";

function fakeIngestCtx() {
  const written: { s: string; i: string; d: Record<string, unknown> }[] = [];
  return {
    written,
    ctx: {
      modelId: "m1",
      writeResource: (s: string, i: string, d: unknown) => {
        written.push({ s, i, d: d as Record<string, unknown> });
        return Promise.resolve({ version: 1 });
      },
      logger: { info: () => {} },
    },
  };
}

Deno.test("orderItems sorts into canonical order regardless of input order", () => {
  const present: BundleItem[] = [
    { name: "credentials", checksum: "c8", ref: "r8" },
    { name: "corpus", checksum: "c1", ref: "r1" },
    { name: "lockenv", checksum: "c4", ref: "r4" },
  ];
  const ordered = orderItems(present).map((i) => i.name);
  assertEquals(ordered, ["corpus", "lockenv", "credentials"]);
});

Deno.test("orderItems drops resources not in the canonical set", () => {
  const present: BundleItem[] = [
    { name: "corpus", checksum: "c1", ref: "r1" },
    { name: "manifest", checksum: "cx", ref: "rx" }, // summary, not a bundle item
  ];
  assertEquals(orderItems(present).map((i) => i.name), ["corpus"]);
});

Deno.test("orderItems seals the replay-critical cells/skills/host_calls resources", () => {
  // Regression: these three (added in .11.x) were silently DROPPED from the seal,
  // so the witness digest never covered the cell script / injected skills / host
  // calls that make a session replayable. They must be retained, in canonical order.
  const present: BundleItem[] = [
    { name: "host_calls", checksum: "h", ref: "rh" },
    { name: "cells", checksum: "c", ref: "rc" },
    { name: "corpus", checksum: "co", ref: "rco" },
    { name: "skills", checksum: "s", ref: "rs" },
  ];
  assertEquals(
    orderItems(present).map((i) => i.name),
    ["corpus", "cells", "skills", "host_calls"],
  );
});

Deno.test("resolveStamp maps a reproduced nix verdict to replayable-nix", () => {
  assertEquals(
    resolveStamp({ reproduced: true, envUsed: "nix" }),
    "replayable-nix",
  );
});

Deno.test("resolveStamp maps a reproduced docker verdict to replayable-docker", () => {
  assertEquals(
    resolveStamp({ reproduced: true, envUsed: "docker" }),
    "replayable-docker",
  );
});

Deno.test("resolveStamp falls back to witnessed when no reproducing verdict", () => {
  assertEquals(resolveStamp(null), "witnessed");
  assertEquals(
    resolveStamp({ reproduced: false, envUsed: "nix" }),
    "witnessed",
  );
});

Deno.test("buildBundleManifest composes ordered items + stamp + origin", () => {
  const m = buildBundleManifest(
    "gdh/p1",
    [
      { name: "provenance", checksum: "c2", ref: "r2" },
      { name: "corpus", checksum: "c1", ref: "r1" },
    ],
    { reproduced: true, envUsed: "nix" },
    { tool: "session-ingest", build: "aa553de7", org: "gdh", proj: "p1" },
  );
  assertEquals(m.session, "gdh/p1");
  assertEquals(m.items.map((i) => i.name), ["corpus", "provenance"]);
  assertEquals(m.stamp, "replayable-nix");
  assertEquals(m.origin.build, "aa553de7");
});

Deno.test("runSeal assembles present resources into a canonical bundle-manifest", async () => {
  const { ctx, written } = fakeIngestCtx();
  // The enumerator returns captured resources in arbitrary order (as the data
  // store yields them); seal must canonicalize.
  const r = await runSeal({
    session: "p1",
    org: "gdh",
    build: "aa553de7",
    _enumerate: () =>
      Promise.resolve([
        { name: "lockenv", checksum: "h4", ref: "lockenv/p1@5" },
        { name: "corpus", checksum: "h1", ref: "corpus/p1@3" },
        { name: "provenance", checksum: "h2", ref: "provenance/p1@2" },
        {
          name: "bundle-manifest",
          checksum: "hx",
          ref: "bundle-manifest/p1@6",
        },
      ]),
    _verdict: null,
  }, ctx);

  assertEquals(written[0].s, "bundle-manifest");
  const m = written[0].d as {
    items: BundleItem[];
    stamp: string;
    origin: { proj: string };
  };
  // canonical order: corpus, provenance, lockenv; bundle-manifest is dropped
  // (not a sealable item), matchspec/others absent.
  assertEquals(m.items.map((i) => i.name), ["corpus", "provenance", "lockenv"]);
  assertEquals(m.stamp, "witnessed");
  assertEquals(m.origin.proj, "p1");
  assertEquals(r.dataHandles.length, 1);
});

Deno.test("runSeal stamps replayable-nix when the verdict reproduced in nix", async () => {
  const { ctx, written } = fakeIngestCtx();
  await runSeal({
    session: "p1",
    _enumerate: () =>
      Promise.resolve([{ name: "corpus", checksum: "h1", ref: "corpus/p1@3" }]),
    _verdict: { reproduced: true, envUsed: "nix" },
  }, ctx);
  assertEquals((written[0].d as { stamp: string }).stamp, "replayable-nix");
});
