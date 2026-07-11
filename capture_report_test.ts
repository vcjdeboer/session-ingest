/** Tests for capture_report.ts — the swamp-native capture report. Uses an
 * in-memory dataRepository mock; no real CS data or files. */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { type RepoLike, report } from "./capture_report.ts";

const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

/** Build a mock dataRepository over a {name: {version: json}} store + specName tags. */
function mockRepo(
  store: Record<string, Record<number, unknown>>,
  specs: Array<{ name: string; version: number; specName: string }>,
): RepoLike {
  return {
    getContent(_t, _m, dataName, version) {
      const vs = store[dataName];
      if (!vs) return Promise.resolve(null);
      const v = version ?? Math.max(...Object.keys(vs).map(Number));
      return Promise.resolve(vs[v] ? enc(vs[v]) : null);
    },
    findAllForModel() {
      return Promise.resolve(
        specs.map((s) => ({
          name: s.name,
          version: s.version,
          tags: { specName: s.specName },
        })),
      );
    },
  };
}

Deno.test("capture-report: empty model → no-session message", async () => {
  const res = await report.execute({
    modelType: "@vcjdeboer/session-ingest",
    modelId: "m",
    dataRepository: mockRepo({}, []),
  });
  assert(res.markdown.includes("No captured session"));
  assertEquals(res.json.error, "no captured session");
});

Deno.test("capture-report: mines tools, skills, reviewer tally, prompts from sealed facets", async () => {
  const rn = "proj_x";
  const store = {
    [rn]: {
      1: {
        origin: { project: { id: rn, name: "Demo session" } },
        verificationChecks: {
          total: 3,
          byVerdict: { fail: 1, warn: 1, pass: 1 },
        },
        messages: { total: 10, userTyped: 1 },
        artifacts: { distinct: 2 },
        nFrames: 4,
        nDistinctEnvs: 1,
      },
      2: {
        items: [{ name: "cells", ref: `cells/${rn}@3`, checksum: "abc123" }],
        stamp: "witnessed",
      },
      3: {
        cells: [
          { language: "bash", source: "hyphy absrel --alignment x.fa" },
          { language: "python", source: "import numpy\nimport pandas" },
          { language: "r", source: "library(RERconverge)" },
        ],
      },
      4: { skills: [{ name: "figure-style", symbols: ["a", "b", "c"] }] },
      5: {
        locks: [{
          environmentName: "python",
          pythonVersion: "3.11",
          packageCount: 95,
        }],
      },
      6: {
        turns: [{
          type: "userTyped",
          blocks: [{ type: "text", text: "how does gdh evolve" }],
        }],
      },
      7: {
        total: 2,
        byVerdict: { fail: 1, warn: 1 },
        checks: [
          {
            verdict: "fail",
            severity: "low",
            claim: "L128V value mismatch",
            evidence: "0.00003 vs computed 0.0000167",
            reviewerModel: "claude-sonnet-5",
          },
          { verdict: "warn", claim: "unverified assumption", evidence: "" },
        ],
      },
    },
  };
  const specs = [
    { name: rn, version: 1, specName: "manifest" },
    { name: rn, version: 2, specName: "bundle-manifest" },
    { name: rn, version: 3, specName: "cells" },
    { name: rn, version: 4, specName: "skills" },
    { name: rn, version: 5, specName: "lockenv" },
    { name: rn, version: 6, specName: "transcript" },
    { name: rn, version: 7, specName: "review" },
  ];
  const res = await report.execute({
    modelType: "@vcjdeboer/session-ingest",
    modelId: "m",
    dataRepository: mockRepo(store, specs),
    methodArgs: { project: "Demo session" },
  });
  // resolved the right session
  assert(res.markdown.includes("Demo session"));
  // tools + packages + skills mined from the sealed facets
  assert(res.markdown.includes("hyphy"), "CLI tool");
  assert(res.markdown.includes("RERconverge"), "R package");
  assert(res.markdown.includes("figure-style"), "CS skill");
  assert(res.markdown.includes("numpy"), "python package");
  // reviewer detail from the sealed review facet (claim + evidence, not just tally)
  assert(res.markdown.includes("1 fail"));
  assert(res.markdown.includes("L128V value mismatch"), "sealed claim");
  assert(res.markdown.includes("0.0000167"), "sealed evidence");
  // prompt captured
  assert(res.markdown.includes("how does gdh evolve"));
  // structured json mirrors it
  const j = res.json as Record<string, unknown>;
  // prefers the sealed review facet (total 2) over the manifest tally (3)
  assertEquals((j.reviewer as { total: number }).total, 2);
  assertEquals((j.reviewer as { detailSealed: boolean }).detailSealed, true);
  assertEquals((j.prompts as string[]).length, 1);
});
