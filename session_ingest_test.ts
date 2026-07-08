/** Model-wiring smoke test for @vcjdeboer/session-ingest: the model loads and every
 * read/capture/lock method + sensitive resource + lock file spec is registered. */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { model } from "./session_ingest.ts";

const m = model as unknown as {
  type: string;
  version: string;
  methods: Record<string, { execute: unknown }>;
  resources: Record<string, { sensitive?: boolean }>;
  files: Record<string, unknown>;
};

Deno.test("session_ingest: identity + CalVer version", () => {
  assertEquals(m.type, "@vcjdeboer/session-ingest");
  assert(/^\d{4}\.\d{2}\.\d{2}\.\d+$/.test(m.version), `CalVer version, got ${m.version}`);
});

Deno.test("session_ingest: all 8 read/capture/lock methods are wired", () => {
  for (const name of [
    "inspect", "capture_messages", "capture_provenance", "capture_corpus",
    "capture_inputs", "capture_external", "capture_credentials", "lock_env",
  ]) {
    assert(name in m.methods, `method ${name} registered`);
    assertEquals(typeof m.methods[name].execute, "function", `${name} has an execute fn`);
  }
});

Deno.test("session_ingest: capture resources are unconditionally sensitive", () => {
  for (const r of ["transcript", "provenance", "corpus", "inputs", "external", "credentials", "lockenv"]) {
    assert(r in m.resources, `resource ${r} present`);
    assertEquals(m.resources[r].sensitive, true, `${r} marked sensitive`);
  }
});

Deno.test("session_ingest: lock_env + offload file specs registered", () => {
  for (const f of ["body", "blob", "environment.yml", "dockerfile", "flake.nix"]) {
    assert(f in m.files, `file spec ${f} present`);
  }
});
