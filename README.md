# @vcjdeboer/session-ingest

**Lift your own Claude Science (operon) sessions out of the box — into open,
inspectable, sealable [swamp](https://github.com/swamp-club/swamp) records.**

Claude Science stores each session locally in an `operon-cli.db` SQLite
database: your prompts, the agent's code cells, the artifacts it produced, the
external databases it queried, and the conda environments it ran in. That is a
lot of valuable, hard-won provenance — locked inside one proprietary schema.
This extension reads **your own** local session and re-expresses it as portable,
governed swamp resources you fully own: a typed transcript, a
turn→execution→artifact→env provenance graph, an immutable byte corpus, a frozen
copy of your Tier‑1 inputs, an external-data inventory, a credential-presence
manifest, and reproducible environment locks.

It is an **anti-lock-in** tool. Its purpose is data portability over data you
already have a right to.

> **Not affiliated with, or endorsed by, Anthropic.** "Claude Science" and
> "operon" are used descriptively to name the local data this tool reads. It
> runs entirely on your machine, reads only your own session database, and is
> designed so a hosted future of the tool doesn't strand your existing work.

## What it captures

| Method                | Produces                                                                                                                                                                            |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inspect`             | a fast, read-only summary of a session (counts only)                                                                                                                                |
| `capture_messages`    | the verbatim, typed conversation transcript                                                                                                                                         |
| `capture_provenance`  | the turn → execution → artifact → env provenance **graph**                                                                                                                          |
| `capture_corpus`      | an immutable, content-addressed **byte copy** of every artifact + project-scoped workspace file (sha-verified for drift)                                                            |
| `capture_cells`       | the **full ordered execution script** — _every_ cell's source + language + cellIndex (the graph keeps only artifact-linked nodes; this keeps the setup/helper cells too)            |
| `capture_inputs`      | a freeze of your Tier‑1 `/private/tmp` inputs (the "days-from-deletion" working data the corpus deliberately skips), by allow-listed root                                           |
| `capture_external`    | a per-source inventory of the external databases the session called (counts + access dates + a release-pin gap slot)                                                                |
| `capture_credentials` | a **presence-only** list of which credential providers the session used, with `vault.get` references for replay                                                                     |
| `capture_host_calls`  | the session's **replayable** `host.*` calls (`mcp`/`query_db`/…) — request + response, with `credentials_request` tokens scrubbed                                                   |
| `capture_skills`      | the CS **skills** the session used — each skill's injected `kernel.py` (e.g. `figure-style` → `apply_figure_style()`), content-addressed                                            |
| `lock_env`            | portable environment locks from the captured conda snapshot — a version-pinned Docker `environment.yml`+`Dockerfile`, plus a Nix scaffold                                           |
| `seal`                | an order-stable `bundle-manifest` over the captured resources, stamped `witnessed`/`replayable-*`; its independent digest comes from `@vcjdeboer/session-witness`'s `seal_manifest` |

Every record is a typed, schema-validated swamp resource, deterministic and
witness-sealable. And because the cells, env, host-calls, skills, and artifacts
are _complete_, a captured session **re-runs outside the app** via
[`@vcjdeboer/session-execute`](https://github.com/vcjdeboer/session-execute)'s
`run-notebook` — papermill in the locked Docker env, with a host-replay shim
that serves recorded `host.*` calls offline (or falls through to the live API in
hybrid mode). Inspect, diff, replay, seal, and archive a session long after the
app changes.

## Security & privacy by design

- **Never decrypts secrets.** The read runs against a disposable, scrubbed clone
  with the secret tables (`user_secrets`, `oauth_tokens`, `cloud_credentials`,
  `anthropic_api_keys`) **dropped and VACUUMed out** before any query. Your
  `encryption.key` is never touched.
- **Structural exclusion, not discipline.** SQL reads use an explicit column
  allow-list — no `SELECT *`, no secret column ever named. Credentials are
  captured by _provider name only_; external-DB call content
  (`args_json[1+]`/`data_inline`/`data_ref`) is never selected.
- **No absolute paths in a portable record**; warnings are root-relative; copies
  are path-safety-canonicalized and TOCTOU-hardened.
- **Read-only.** The source database and files are never mutated
  (byte-verified).
- Records that can carry your data are marked **sensitive**.

## Requirements

- A local Claude Science install with a session database at
  `~/.claude-science/orgs/<org>/operon-cli.db`.
- `sqlite3` (≥ 3.38, for JSON1) on `PATH`.
- Because Claude Science's background server keeps the database open, take a
  consistent snapshot first (or quit the app):
  `sqlite3 'file:<db>?mode=ro' "VACUUM INTO snapshot.db"`.

> **Scope:** this reads a **local** Claude Science / operon session. It does not
> reach hosted agent products (e.g. browser-based tools that keep your data
> server-side) — those expose their own exports.

## Install

```sh
swamp extension pull @vcjdeboer/session-ingest
swamp model create @vcjdeboer/session-ingest ingest
```

## Usage

```sh
# summarize a session (read-only)
swamp model method run ingest inspect --input project=<proj_id-or-name>

# capture the provenance graph + a sealable corpus
swamp model method run ingest capture_provenance --input project=<proj>
swamp model method run ingest capture_corpus     --input project=<proj>

# freeze the external-data inventory, credential presence, and env locks
swamp model method run ingest capture_external    --input project=<proj>
swamp model method run ingest capture_credentials --input project=<proj>
swamp model method run ingest lock_env            --input project=<proj>
```

Each method writes typed swamp resources you can then query, seal with
`@vcjdeboer/session-witness`, or bundle.

## License

See [LICENSE.md](./LICENSE.md).
