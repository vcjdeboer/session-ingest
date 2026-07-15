/** Tests for status.ts — the local-vs-live reconciliation. Pure functions plus
 * the method wired through injected seams; no real DB or swamp CLI. */
import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  deriveState,
  type LocalSession,
  reconcile,
  runStatus,
  StatusSchema,
} from "./status.ts";

Deno.test("deriveState: sealed > partial > inspected", () => {
  assertEquals(
    deriveState(["manifest", "bundle-manifest", "transcript"]),
    "sealed",
  );
  assertEquals(deriveState(["manifest", "transcript", "cells"]), "partial");
  assertEquals(deriveState(["manifest"]), "inspected");
  assertEquals(deriveState([]), "inspected");
});

Deno.test("reconcile: intersects live/local, counts states, schema-valid", () => {
  const live = [
    { projectId: "proj_a", name: "A" },
    { projectId: "proj_b", name: "B" }, // live, not captured
  ];
  const local: LocalSession[] = [
    {
      projectId: "proj_a",
      name: "A",
      state: "sealed",
      facets: ["bundle-manifest"],
    },
    { projectId: "proj_c", name: null, state: "inspected", facets: ["manifest"] }, // captured, not live
  ];
  const parsed = StatusSchema.parse(reconcile(true, live, local));
  assertEquals(parsed.reconciliation.liveAndCaptured, ["proj_a"]);
  assertEquals(parsed.reconciliation.liveNotCaptured, ["proj_b"]);
  assertEquals(parsed.reconciliation.capturedNotLive, ["proj_c"]);
  assertEquals(parsed.counts, {
    live: 2,
    local: 2,
    sealed: 1,
    inspected: 1,
    partial: 0,
  });
  assertEquals(parsed.dbQuiescent, true);
});

Deno.test("runStatus: wires injected seams and writes one status resource", async () => {
  const writes: Array<{ spec: string; inst: string; data: unknown }> = [];
  const res = await runStatus(
    {
      csRoot: "",
      orgId: "",
      _live: () =>
        Promise.resolve({
          dbQuiescent: false,
          sessions: [{ projectId: "proj_x", name: "X" }],
        }),
      _local: () =>
        Promise.resolve([
          {
            projectId: "proj_x",
            name: "X",
            state: "partial",
            facets: ["manifest", "cells"],
          },
        ]),
    },
    {
      modelId: "m",
      globalArgs: {},
      writeResource: (spec, inst, data) => {
        writes.push({ spec, inst, data });
        return Promise.resolve({ version: 1 });
      },
      logger: { info: () => {} },
    },
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "status");
  assertEquals(writes[0].inst, "status");
  const data = writes[0].data as {
    dbQuiescent: boolean;
    reconciliation: { liveAndCaptured: string[] };
  };
  assertEquals(data.dbQuiescent, false);
  assertEquals(data.reconciliation.liveAndCaptured, ["proj_x"]);
  assert(res.dataHandles.length === 1);
});
