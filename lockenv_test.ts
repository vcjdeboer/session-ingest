/**
 * Tests for @vcjdeboer/session-ingest lockenv.ts (lock_env).
 * Skip-guarded on sqlite3. Fixtures MIRROR THE REAL SCHEMA: per-package channel:'conda',
 * a real pip package (channel:'pip'), source channels in conda_history.channels.
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { generateEnvYaml, type LockEnv, type LockEnvSink, lockEnv } from "./lockenv.ts";
import { parse as parseYaml } from "jsr:@std/yaml@1.0.5";
import { preflightSqlite } from "./db.ts";

const HAVE = (await preflightSqlite()).ok;

async function sqlite(db: string, sql: string): Promise<void> {
  const out = await new Deno.Command("sqlite3", { args: [db, sql] }).output();
  if (!out.success) throw new Error(new TextDecoder().decode(out.stderr));
}

function fakeSink() {
  const resources: Record<string, unknown> = {};
  const files: Record<string, string> = {};
  const dec = new TextDecoder();
  const sink: LockEnvSink = {
    writeResource: (spec, inst, data) => {
      resources[`${spec}/${inst}`] = data;
      return Promise.resolve({ version: 1 });
    },
    createFileWriter: (spec, inst) => ({
      writeAll: (c: Uint8Array) => {
        files[`${spec}/${inst}`] = dec.decode(c);
        return Promise.resolve({});
      },
    }),
    logger: { info: () => {} },
  };
  return { sink, resources, files };
}

// A quant-like env: per-package channel:'conda' + one real pip package; source channels in conda_history.
const QUANT_ENV = JSON.stringify({
  environment_name: "quant",
  packages: [
    { name: "salmon", version: "2.3.1", channel: "conda" },
    { name: "sra-tools", version: "3.4.1", channel: "conda" },
    { name: "python", version: "3.11.15", channel: "conda" },
    { name: "somepkg", version: "1.0.0", channel: "pip" },
  ],
  python_version: "3.11.15",
  conda_history: { specs: ["python=3.11", "salmon"], channels: ["conda-forge", "bioconda"] },
});

async function fixture(envContent = QUANT_ENV, hash = "a".repeat(64)): Promise<string> {
  const org = await Deno.makeTempDir({ prefix: "lock-fixture-" });
  const orgDir = `${org}/orgs/org1`;
  await Deno.mkdir(orgDir, { recursive: true });
  await sqlite(
    `${orgDir}/operon-cli.db`,
    `PRAGMA journal_mode=WAL;
     CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
     INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL);
     CREATE TABLE artifact_versions (id TEXT,artifact_id TEXT,storage_path TEXT,env_snapshot_hash TEXT);
     INSERT INTO artifact_versions VALUES ('A1','a1','proj_abc123/v1/a.py','${hash}'),('A2','a2','proj_abc123/v2/b.py','${hash}'),('A3','a3','proj_other/v1/x.py','${"b".repeat(64)}');
     CREATE TABLE content_snapshots (hash TEXT PRIMARY KEY,content TEXT,size_bytes INT,created_at INT);
     INSERT INTO content_snapshots VALUES ('${hash}','${envContent.replace(/'/g, "''")}',1,1);`,
  );
  return org;
}

Deno.test({
  name: "lock_env: environment.yml — channels from conda_history (NOT packages[].channel), exact name=version, pip block",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, resources, files } = fakeSink();
      const { lockenv: c } = await lockEnv(org, "gdh", undefined, sink);
      assertEquals(resources["lockenv/proj_abc123"], c);
      assertEquals(c.locks.length, 1); // proj_other's env excluded (scoping)
      const lock = c.locks[0];
      const envYaml = files[`environment.yml/${lock.docker.envYamlRef}`];
      const parsed = parseYaml(envYaml) as { name: string; channels: string[]; dependencies: unknown[] };
      // channels come from conda_history (order preserved) EVEN THOUGH every pkg .channel='conda'
      assertEquals(parsed.channels, ["conda-forge", "bioconda"]);
      // exact name=version conda deps, sorted; pip pkg in the pip block (NOT conda deps)
      assert(parsed.dependencies.includes("salmon=2.3.1"), "salmon pinned");
      assert(parsed.dependencies.includes("sra-tools=3.4.1"), "sra-tools pinned");
      assert(parsed.dependencies.includes("pip"), "bare pip present so the pip: block runs");
      const pipBlock = parsed.dependencies.find((d) => typeof d === "object" && d !== null && "pip" in (d as object)) as { pip: string[] };
      assertEquals(pipBlock.pip, ["somepkg==1.0.0"]);
      assert(!parsed.dependencies.includes("somepkg=1.0.0"), "pip pkg NOT in conda deps");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "lock_env: Dockerfile (env-independent, micromamba) + Nix scaffold + witnessed type-stamp",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, files } = fakeSink();
      const { lockenv: c } = await lockEnv(org, "gdh", undefined, sink, { micromambaDigest: "c".repeat(64) });
      const lock = c.locks[0];
      const dockerfile = files[`dockerfile/${lock.docker.dockerfileRef}`];
      assert(dockerfile.includes("FROM mambaorg/micromamba@sha256:" + "c".repeat(64)), "digest-pinned FROM");
      assert(dockerfile.includes("micromamba install -y -n base -f /tmp/environment.yml"), "micromamba install");
      assertEquals(lock.docker.digestPinned, true);
      const flake = files[`flake.nix/${lock.nix.flakeRef}`];
      assert(/NOT a reproducing lock/.test(flake), "scaffold honestly labeled");
      assert(flake.includes("github:NixOS/nixpkgs/"), "nixpkgs pinned ref");
      assert(/python3Packages/.test(flake), "python namespacing caveat");
      assertEquals(lock.nix.status, "scaffold");
      assertEquals(c.typeStamp, "witnessed"); // unvalidated at lock time
      assertEquals(c.totals, { envCount: 1, dockerGenerated: 1, nixScaffolded: 1 });
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "lock_env: default FROM is a version tag + a not-digest-pinned warning (no fabricated digest)",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink, files } = fakeSink();
      const { lockenv: c } = await lockEnv(org, "gdh", undefined, sink); // no digest
      const dockerfile = files[`dockerfile/${c.locks[0].docker.dockerfileRef}`];
      assert(dockerfile.includes("FROM mambaorg/micromamba:"), "version tag default");
      assert(!dockerfile.includes("@sha256:undefined"), "never a fabricated/undefined digest");
      assertEquals(c.locks[0].docker.digestPinned, false);
      assert(c.warnings.some((w) => /not digest-pinned/.test(w)), "warned it's not digest-pinned");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "lock_env: no env snapshots → empty record + warning, does not throw",
  ignore: !HAVE,
  fn: async () => {
    const org = await Deno.makeTempDir({ prefix: "lock-empty-" });
    const orgDir = `${org}/orgs/org1`;
    await Deno.mkdir(orgDir, { recursive: true });
    await sqlite(
      `${orgDir}/operon-cli.db`,
      `PRAGMA journal_mode=WAL;
       CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
       INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL);
       CREATE TABLE artifact_versions (id TEXT,artifact_id TEXT,storage_path TEXT,env_snapshot_hash TEXT);
       INSERT INTO artifact_versions VALUES ('A1','a1','proj_abc123/v1/a.py',NULL);
       CREATE TABLE content_snapshots (hash TEXT PRIMARY KEY,content TEXT,size_bytes INT,created_at INT);`,
    );
    try {
      const { sink } = fakeSink();
      const { lockenv: c } = await lockEnv(org, "gdh", undefined, sink);
      assertEquals(c.locks, []);
      assertEquals(c.totals, { envCount: 0, dockerGenerated: 0, nixScaffolded: 0 });
      assert(c.warnings.some((w) => /nothing to lock/.test(w)), "warned nothing to lock");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "lock_env: deterministic two-run byte-identical; malformed env content degrades; source unmutated",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture("{bad json", "d".repeat(64));
    const dbPath = `${org}/orgs/org1/operon-cli.db`;
    const before = await Deno.readFile(dbPath);
    try {
      const a = fakeSink();
      const r1 = await lockEnv(org, "gdh", undefined, a.sink);
      const b = fakeSink();
      const r2 = await lockEnv(org, "gdh", undefined, b.sink);
      // malformed env content → skipped + warned, no throw, empty locks
      assertEquals(r1.lockenv.locks, []);
      assert(r1.lockenv.warnings.some((w) => /not JSON/.test(w)), "malformed env warned");
      assertEquals(JSON.stringify(r1.lockenv), JSON.stringify(r2.lockenv), "two runs byte-identical");
      assertEquals(await Deno.readFile(dbPath), before, "source db unmutated");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test({
  name: "lock_env: arg gates throw on a bad digest / rev; multi-env shares one Dockerfile sha",
  ignore: !HAVE,
  fn: async () => {
    const org = await fixture();
    try {
      const { sink } = fakeSink();
      let d = false, r = false;
      try { await lockEnv(org, "gdh", undefined, sink, { micromambaDigest: "nothex" }); } catch { d = true; }
      try { await lockEnv(org, "gdh", undefined, sink, { nixpkgsRev: "abc" }); } catch { r = true; }
      assert(d && r, "invalid digest and rev both throw");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
    // two distinct envs → 2 env.yml + 2 flake refs but ONE shared (env-independent) Dockerfile sha
    const org2 = await Deno.makeTempDir({ prefix: "lock-multi-" });
    const orgDir = `${org2}/orgs/org1`;
    await Deno.mkdir(orgDir, { recursive: true });
    const h1 = "a".repeat(64), h2 = "e".repeat(64);
    const env2 = QUANT_ENV.replace('"quant"', '"cobra"');
    await sqlite(
      `${orgDir}/operon-cli.db`,
      `PRAGMA journal_mode=WAL;
       CREATE TABLE projects (id TEXT,name TEXT,description TEXT,created_at INT,updated_at INT,uploads_frame_id TEXT);
       INSERT INTO projects VALUES ('proj_abc123','gdh',NULL,1,2,NULL);
       CREATE TABLE artifact_versions (id TEXT,artifact_id TEXT,storage_path TEXT,env_snapshot_hash TEXT);
       INSERT INTO artifact_versions VALUES ('A1','a1','proj_abc123/v1/a.py','${h1}'),('A2','a2','proj_abc123/v2/b.py','${h2}');
       CREATE TABLE content_snapshots (hash TEXT PRIMARY KEY,content TEXT,size_bytes INT,created_at INT);
       INSERT INTO content_snapshots VALUES ('${h1}','${QUANT_ENV.replace(/'/g, "''")}',1,1),('${h2}','${env2.replace(/'/g, "''")}',1,1);`,
    );
    try {
      const { sink } = fakeSink();
      const { lockenv: c } = await lockEnv(org2, "gdh", undefined, sink);
      assertEquals(c.locks.length, 2);
      const dockerRefs = new Set(c.locks.map((l) => l.docker.dockerfileRef));
      assertEquals(dockerRefs.size, 1, "one shared Dockerfile across envs");
      const envRefs = new Set(c.locks.map((l) => l.docker.envYamlRef));
      assertEquals(envRefs.size, 2, "distinct env.yml per env");
      // writeManifest = 2 env.yml + 2 flake + 1 dockerfile = 5 distinct shas
      assertEquals(c.writeManifest.length, 5);
    } finally {
      await Deno.remove(org2, { recursive: true });
    }
  },
});

Deno.test({
  name: "lock_env: a hostile env name is sanitized in the flake (no nix break-out)",
  ignore: !HAVE,
  fn: async () => {
    const hostile = JSON.stringify({
      environment_name: 'evil"; injected = builtins.exec [',
      packages: [{ name: "salmon", version: "2.3.1", channel: "conda" }],
      python_version: "3.11",
      conda_history: { channels: ["conda-forge"] },
    });
    const org = await fixture(hostile, "f".repeat(64));
    try {
      const { sink, files } = fakeSink();
      const { lockenv: c } = await lockEnv(org, "gdh", undefined, sink);
      const flake = files[`flake.nix/${c.locks[0].nix.flakeRef}`];
      assert(!flake.includes("builtins.exec"), "hostile env name not interpolated into the flake");
      assert(flake.includes("'captured-env'"), "fell back to a safe name");
    } finally {
      await Deno.remove(org, { recursive: true });
    }
  },
});

Deno.test("lock_env generateEnvYaml: null version → bare name; duplicate deduped; unsafe name skipped", () => {
  const warns: string[] = [];
  const yaml = generateEnvYaml("e", ["conda-forge"], [
    { name: "a", version: null, channel: "conda" },
    { name: "a", version: "1", channel: "conda" }, // duplicate name → deduped
    { name: "bad name", version: "1", channel: "conda" }, // unsafe → skipped
    { name: "b", version: "2", channel: "conda" },
  ], (m) => warns.push(m));
  assert(yaml.includes("- a\n") || /- a$/m.test(yaml), "null-version pkg emitted as bare name");
  assert(yaml.includes("- b=2"), "b pinned");
  assert(!yaml.includes("bad name"), "unsafe name skipped");
  assert(warns.some((w) => /deduped/.test(w)) && warns.some((w) => /unexpected name/.test(w)), "warned dedup + skip");
});
