/** Tests for settings.ts (capture_settings). buildSettings is pure over rows. */
import { assertEquals } from "jsr:@std/assert@1";
import { buildSettings, SettingsSchema } from "./settings.ts";

Deno.test("buildSettings aggregates model/effort, delegation, timeline", () => {
  const s = buildSettings(
    [
      { model: "claude-opus-4-8", effort: "high", created_at: 1000 },
      { model: "claude-sonnet-5", delegate_name: "reviewer", created_at: 2000 },
      { model: "claude-sonnet-5", delegate_name: "reviewer", created_at: 3000 },
      { model: null, created_at: 1500 }, // no model → skipped in models tally
    ],
    [{ kind: "capability", key: "memory", enabled: 1 }, {
      kind: "capability",
      key: "auto_review",
      enabled: 0,
    }],
    [{ agent_name: "biostatistician", enabled: 1 }],
  );
  assertEquals(s.timeline.startedAt, 1000);
  assertEquals(s.timeline.endedAt, 3000);
  assertEquals(s.timeline.durationMs, 2000);
  assertEquals(s.timeline.nFrames, 4);
  // model×effort pairs, sorted by count desc
  assertEquals(s.models[0], {
    model: "claude-sonnet-5",
    effort: "",
    count: 2,
  });
  assertEquals(s.delegation, [{ delegate: "reviewer", count: 2 }]);
  assertEquals(s.toggles, [
    { kind: "capability", key: "memory", enabled: true },
    { kind: "capability", key: "auto_review", enabled: false },
  ]);
  assertEquals(s.specialists, [{ agent: "biostatistician", enabled: true }]);
});

Deno.test("buildSettings output validates against SettingsSchema", () => {
  const body = buildSettings([{ model: "m", created_at: 1 }], [], []);
  SettingsSchema.parse({
    session: "proj_x",
    ...body,
    origin: {
      tool: "claude-science" as const,
      org: "o",
      project: { id: "proj_x", name: null },
    },
  });
});
