/** Tests for review.ts (capture_review). buildReview is pure over rows. */
import { assertEquals } from "jsr:@std/assert@1";
import { buildReview, ReviewSchema } from "./review.ts";

Deno.test("buildReview shapes rows into checks + a verdict tally", () => {
  const { checks, byVerdict } = buildReview([
    {
      verdict: "fail",
      severity: "low",
      claim: "value mismatch",
      evidence: "0.00003 vs 0.0000167",
      reviewer_model: "claude-sonnet-5",
      reviewer_kind: "adversarial",
      status: "resolved",
    },
    { verdict: "warn", claim: "unverified assumption" },
    { verdict: "pass" },
    { verdict: "warn" },
  ]);
  assertEquals(checks.length, 4);
  assertEquals(byVerdict, { fail: 1, warn: 2, pass: 1 });
  assertEquals(checks[0].reviewerModel, "claude-sonnet-5");
  assertEquals(checks[0].evidence, "0.00003 vs 0.0000167");
  // defaults fill missing fields (no undefineds leak into the sealed record)
  assertEquals(checks[1].evidence, "");
  assertEquals(checks[2].claim, "");
});

Deno.test("buildReview output validates against ReviewSchema", () => {
  const { checks, byVerdict } = buildReview([{ verdict: "pass" }]);
  const rec = {
    sensitive: true as const,
    session: "proj_x",
    total: checks.length,
    byVerdict,
    checks,
    origin: {
      tool: "claude-science" as const,
      org: "o",
      project: { id: "proj_x", name: "Demo" },
    },
  };
  // throws on mismatch
  ReviewSchema.parse(rec);
});
