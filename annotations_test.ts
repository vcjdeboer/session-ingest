/** Tests for annotations.ts (capture_annotations). buildAnnotations is pure. */
import { assertEquals } from "jsr:@std/assert@1";
import { AnnotationsSchema, buildAnnotations } from "./annotations.ts";

Deno.test("buildAnnotations shapes rows + a kind tally; nulls stay null", () => {
  const { annotations, byKind } = buildAnnotations([
    {
      kind: "bookmark",
      source: "assistant",
      anchor_text: "altitude",
      note: "a thread bookmark",
      origin: "user",
      created_at: 1783,
      message_index: 12,
    },
    {
      kind: "comment",
      source: "tool",
      tool_name: "cpt1c_report.md",
      anchor_text: "p=0.74",
      note: "check this",
      origin: "user",
    },
    { kind: "bookmark" },
  ]);
  assertEquals(annotations.length, 3);
  assertEquals(byKind, { bookmark: 2, comment: 1 });
  assertEquals(annotations[0].note, "a thread bookmark");
  assertEquals(annotations[0].messageIndex, 12);
  assertEquals(annotations[1].toolName, "cpt1c_report.md");
  // missing offsets/uuid → null, not undefined
  assertEquals(annotations[2].startOffset, null);
  assertEquals(annotations[2].note, "");
});

Deno.test("buildAnnotations output validates against AnnotationsSchema", () => {
  const { annotations, byKind } = buildAnnotations([{ kind: "bookmark" }]);
  AnnotationsSchema.parse({
    sensitive: true as const,
    session: "proj_x",
    total: annotations.length,
    byKind,
    annotations,
    origin: {
      tool: "claude-science" as const,
      org: "o",
      project: { id: "proj_x", name: "Demo" },
    },
  });
});
