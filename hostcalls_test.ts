import { assertEquals } from "jsr:@std/assert@1";
import { buildHostCalls } from "./hostcalls.ts";

Deno.test("buildHostCalls parses args, inlines/resolves responses, scrubs credentials, flags errors", async () => {
  const resolveRef = (p: string) =>
    Promise.resolve({ tape: p, domains: [1, 2] });
  const calls = await buildHostCalls([
    {
      method: "mcp",
      args_json: '["s","query",{"x":1}]',
      data_inline: '{"hits":[1]}',
      data_ref: null,
      error: null,
    },
    {
      method: "mcp",
      args_json: '["s","big",{}]',
      data_inline: null,
      data_ref: "tapes/a.json",
      error: null,
    },
    {
      method: "credentials_request",
      args_json: '["openalex"]',
      data_inline: null,
      data_ref: null,
      error: null,
    },
    {
      method: "mcp",
      args_json: '["s","boom",{}]',
      data_inline: null,
      data_ref: null,
      error: "upstream 500",
    },
  ], resolveRef);

  assertEquals(calls.length, 4);
  assertEquals(calls[0].args, ["s", "query", { x: 1 }]);
  assertEquals(calls[0].response, { hits: [1] }); // inline parsed
  assertEquals(calls[1].response, { tape: "tapes/a.json", domains: [1, 2] }); // ref resolved
  assertEquals(calls[2].hasSecret, true); // credentials scrubbed
  assertEquals(calls[2].response, null);
  assertEquals(calls[3].isError, true);
  assertEquals(calls[3].error, "upstream 500");
});
