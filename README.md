# baoist-monk

Resolve `bao:` references from OpenBao, cached on disk so a sealed Bao does not
stop a running deployment.

```
bao:kv/adx/elephant/nodes/imaging#POSTGRES_PASSWORD
bao:kv/adx/s3/prickly-pear/accounts/elephant#elephant.secret
    └─────────── kv path ───────────┘ └── selector ──┘
```

**A reference names everything needed to resolve it.** Nothing else has to be
configured anywhere — no template, no per-path env var, no list of paths to keep
in sync with a policy.

The selector is dot-separated and walks the decoded JSON, so a flat scope and a
nested record use the *same syntax*. There is no branch between them.

## Use

```bash
bm get 'bao:kv/adx/elephant/nodes/imaging#POSTGRES_PASSWORD'

# KEY=VALUE lines, for `eval` or a 0600 file. Values never reach a command line.
eval "$(bm env \
    POSTGRES_PASSWORD='bao:kv/adx/elephant/nodes/imaging#POSTGRES_PASSWORD' \
    S3_SECRET_KEY='bao:kv/adx/s3/prickly-pear/accounts/elephant#elephant.secret' \
    BACKUP_DEST='literal values pass through unchanged')"

# poll kv METADATA for version changes; refresh what moved; fire a trigger
bm watch --interval 3m --on-change '/usr/local/bin/reload.sh'

bm list      # cached paths, versions, ages — never values
```

| variable | default |
|---|---|
| `BAO_ADDR` | `https://openbao.internal.astradx.com` |
| `BAO_TOKEN` | — (use this instead of AppRole login) |
| `BAO_ROLE_ID_FILE` | `/etc/bao/role_id` |
| `BAO_SECRET_ID_FILE` | `/etc/bao/secret_id` |
| `BAOIST_CACHE` | `/var/cache/baoist-monk` |

## ★ The property this exists for

**OpenBao does not auto-unseal.** Once sealed it stays sealed until a human
pastes the key. An application that must reach Bao to start is an application
that cannot start after a power event.

The usual answer is to render every secret into a file ahead of time, with a Bao
Agent template. That file persists, so it survives a sealed Bao — but it requires
knowing **every kv path before the process starts**, which is wrong for any
application whose credential set is *data* (rows in a database, entries in a
config repo) rather than deployment configuration.

The tool gets the same durability from a **disk cache** instead:

- a cache hit **does not contact Bao** — cheap enough to resolve per-operation
- with Bao unreachable, cached references still resolve
- an **uncached** reference fails **loudly, naming the path** — never an empty
  string

> ⚠️ A Bao Agent's own cache does **not** do this. It is a token/lease cache, not
> a KV response cache: with the server stopped, a read through an agent in
> `api_proxy` mode returns `HTTP 000`. Measured, not assumed — it is why this
> tool exists rather than a wrapper around the agent.

## What `watch` does, and what it refuses to do

It compares each cached path's `current_version` against Bao and re-fetches only
what moved.

**Metadata first, deliberately.** A version check does not transfer the secret,
so the steady state — nothing has rotated — costs one small request per path and
never puts a credential on the wire.

**A path that cannot be read is logged and skipped, never evicted.** A sealed
Bao, a revoked grant or a network blip leaves every other value serving from
cache *and* the failing one serving its last known value. Losing a credential
because Bao was briefly unreachable would be strictly worse than serving a stale
one.

The `--on-change` command receives `BAOIST_CHANGED` (`path v1->v2, …`) so it can
act narrowly.

## Deliberate choices

- **No dependencies.** Three HTTP endpoints. A static binary with no module graph
  is easier to ship inside an image and to reason about when it holds
  credentials.
- **The token is never written to disk.** The cache holds *values*, which the
  deployment needs in order to run while Bao is unreachable. A cached token would
  be a credential outliving the process for no benefit.
- **Values never reach a command line.** `env` prints; callers `eval` or redirect.
  `ps` never shows a secret.
- **A selector resolving to an object is an error**, never stringified. A
  credential that silently becomes `map[...]` is the empty-credential failure
  wearing a different costume — it reaches S3 as a 403 inside a job, hours later.
- **Non-reference values pass through unchanged**, so a value can be pinned
  without inventing a scheme for it.

## kv v2

Paths are given **logically** — `kv/adx/…`, as they appear in a policy's
`kv/data/…` line minus the `data`. The tool inserts `data` or `metadata` as
needed. Getting that rewrite wrong reads as a permissions mystery, so it happens
in exactly one place.

A read needs `read` on `kv/data/<path>`; `watch` also needs `read` on
`kv/metadata/<path>`.

## Install

Binaries are published per tag on the
[releases page](https://github.com/astradxma/baoist-monk/releases) — `bm-<os>-<arch>`
plus `checksums.txt`. The binary is **`bm`**; the repo keeps the long name, the
thing you type in a script does not.

```bash
curl -fsSLO https://github.com/astradxma/baoist-monk/releases/download/v0.1.0/bm-linux-amd64
install -m 0755 bm-linux-amd64 /usr/local/bin/bm
```

## Build

```bash
CGO_ENABLED=0 go build -o bm .
```

Static, so one `linux/amd64` build runs on glibc and musl alike — the same reason
OpenBao's own release has no separate musl target.

## Exit codes

A caller should not have to parse prose to decide what to do:

| code | meaning | retry? |
|---|---|---|
| `0` | resolved | — |
| `2` | usage — a malformed reference | no |
| `3` | configuration — wrong path, field, or permission | **no** |
| `4` | unavailable — Bao unreachable and nothing cached | **maybe** |

3 and 4 are the distinction that matters. A supervisor treating them alike will
either retry a typo forever or give up on a network blip.

## Errors

Every failure names the fix, not just the symptom.

★ **403 is the one that wastes time.** OpenBao returns 403 for *both* "your
policy does not grant this" *and* "this path does not exist" — deliberately, so a
token cannot probe for paths it cannot read. So the message says both are
possible and gives the check order, with the real path strings filled in:

```
baoist-monk: cannot read kv/adx/forbidden: permission denied

  OpenBao answers 403 for BOTH of these, and does not distinguish them:
    - the policy does not grant read on this path
    - the path does not exist

  Check, in this order:
    1. does the path exist?      bao kv get kv/adx/forbidden
    2. does the policy grant it? it needs BOTH lines, because kv v2 splits them:
         path "kv/data/adx/forbidden" { capabilities = ["read"] }
         path "kv/metadata/adx/forbidden" { capabilities = ["read"] }
    3. is the AppRole bound to that policy?
```

A missing field lists what *is* present. A selector landing on an object lists
its fields and suggests the deeper selector. A missing credential file says which
file and what it is for — it is a **configuration** error, not an availability
one, even though it surfaces before any HTTP request happens.
