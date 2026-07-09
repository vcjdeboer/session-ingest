import { assertEquals } from "jsr:@std/assert@1";
import { readCells } from "./cells.ts";

Deno.test("readCells preserves order, keeps small source inline, offloads large source", async () => {
  const big = "x".repeat(3000);
  const offloaded: string[] = [];
  const offload = (t: string) => {
    offloaded.push(t);
    return Promise.resolve("sha_" + t.length);
  };
  const { cells } = await readCells([
    { cell_index: 1, language: "python", source: "small" },
    { cell_index: 2, language: "python", source: big },
    { cell_index: 3, language: "bash", source: "ls" },
  ], offload);

  assertEquals(cells.map((c) => c.cellIndex), [1, 2, 3]);
  assertEquals(cells[0].source, "small"); // small inline
  assertEquals(cells[0].bodyRef, "");
  assertEquals(cells[1].source, ""); // large offloaded
  assertEquals(cells[1].bodyRef, "sha_3000");
  assertEquals(cells[2].language, "bash");
  assertEquals(offloaded.length, 1);
});
