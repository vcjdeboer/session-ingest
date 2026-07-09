import { assert, assertEquals } from "jsr:@std/assert@1";
import { extractSymbols, usedSkills } from "./skills.ts";

Deno.test("extractSymbols pulls top-level defs and assignments only", () => {
  const syms = extractSymbols(
    [
      "import x",
      "def apply_figure_style(a):",
      "    def inner(): pass",
      "GC = {}",
      "  indented = 1",
      "META_GREY = '#888'",
    ].join("\n"),
  );
  assert(syms.includes("apply_figure_style"));
  assert(syms.includes("GC"));
  assert(syms.includes("META_GREY"));
  assert(!syms.includes("inner")); // nested def excluded
  assert(!syms.includes("indented")); // indented assignment excluded
});

Deno.test("usedSkills selects skills whose symbol appears in cell source", () => {
  const used = usedSkills(
    {
      "figure-style": ["apply_figure_style", "set_frame"],
      "unused": ["never_called"],
    },
    ["import x", "apply_figure_style(frame='open')"],
  );
  assertEquals(used, ["figure-style"]);
});

Deno.test("usedSkills uses word boundaries (no substring false positives)", () => {
  assertEquals(usedSkills({ "s": ["fig"] }, ["prefig_thing = 1"]), []);
});
