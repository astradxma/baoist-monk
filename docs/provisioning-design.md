# Should `bm` Learn to Provision? A Design Exploration

*Status: design only. Nothing here is built. Written 2026-09-11 after reading
the three `bao/provision.sh` scripts in adx-servers and the one that didn't
hurt (versity's).*

## Chapter 1: The Scoreboard

We have written four Bao provisioning scripts. Let's be honest about how they
went.

| script | what it moves into Bao | typed a secret? | pain |
|---|---|---|---|
| `versity-gw-*/access-control/setup-bao.sh` + `seed-bao.sh` | IAM accounts, from `/iam/users.json` | no | none worth mentioning |
| `elephant-events/bao/provision.sh` | four NATS passwords, from `../.env` | no | low |
| `elephant-db/bao/provision.sh` | one *generated* password | no | medium — 5 commits in a day |
| `elephant-imaging-prod/bao/provision.sh` | one PAT, plus policy for six paths | **yes** | high — 12 commits, 600 lines |

Two things jump out before we even look at code. First, the one that worked
great **never asked a human to type a secret**. Second, it is the only one that
sources `openbao/bao-cli.sh` — the shared library with the `/dev/tty` token
prompt, the fingerprint receipts, and the `--audit` mode. The three elephant
scripts each re-implemented `log`/`ok`/`warn`/`die`/`confirm`, the seal check,
and the token prompt from scratch. Three copies of a 25-line "LAN name, not
tailnet name" comment. Three copies of a 20-line "log() writes to stderr, and
that is load-bearing" post-mortem.

So the first, cheap, slightly embarrassing answer to "what should bm absorb?"
is: **nothing that `bao-cli.sh` already does.** Let's get that out of the way
and then look at what's actually left.

## Chapter 2: The Bugs, Sorted by What They Actually Were

The 15-minute taxes, in the order they landed:

1. **`jq '.sealed // "unknown"'` treats `false` as empty**, so an unsealed Bao
   aborted the script. *Category: bash/jq footgun.* Versity avoided it by
   just calling `bao status` and trusting the exit code.
2. **`patch || put` silently replaces an entry on any patch failure.**
   *Category: shell logic.* Fixed by checking existence first.
3. **`log()` wrote to stdout inside `v="$(ask_secret …)"`**, so a 93-char
   token was stored as 157 chars with its own log line prepended. *Category:
   command substitution + secrets = corruption.* This is the big one. It
   cost the length-capture, the length-verify-after-write, and three copies
   of the explanation.
4. **The policy's path list is hand-maintained in `provision.sh` and must
   agree with `refs.env` by eye.** The comment literally says "cross-check
   against refs.env". *Category: two sources of truth.*
5. **The versity record's shape check** — 40 lines of jq asserting that
   `.data.data.<acct>` is an object with `.access` and `.secret`. *Category:
   re-implementing bm's selector walk in jq.*
6. **The self-test** logs in as the role, reads each path, and re-reads with
   the operator token to tell 403-from-policy apart from 404-from-absent.
   *Category: re-implementing `bm`'s `explain()` in bash.*

And a bonus one that is sitting in the tree **right now**, un-noticed, because
nothing checks it:

```
# elephant-imaging-prod/bao/refs.env, line 71
NATS_PASSWORD=bao:kv/adx/elephant/nodes/imaging#NATS_PASSWORD
```

`provision.sh` stopped prompting for `NATS_PASSWORD` in the node scope and now
grants `kv/adx/nats` expecting `#NATS_PUB_PW`. The ref file and the policy
disagree. A fresh provision + preflight will fail with "no field
NATS_PASSWORD" — which is exactly bug #4 doing what bug #4 does.

Now sort those by what would have prevented them:

- **#1, #2, #3** → sourcing `bao-cli.sh` and *not inventing a new secret-capture
  pattern*. `bao_require_token` already reads with `IFS= read -rs … < /dev/tty`
  in the main shell — no subshell, nothing to corrupt. The elephant scripts
  needed one more prompt of that shape (for the PAT) and instead built
  `ask_secret` around `$( )`. Bash fix. Ten minutes.
- **#4, #5, #6, bonus** → these are all the same disease: **the script
  re-derives, in bash, things `bm` already knows how to do in Go.** `ParseRef`
  knows which paths a ref file touches. `insertSeg` knows the `kv/data/` +
  `kv/metadata/` rewrite. `apply()` walks `#elephant.secret` and says "no field
  X — present: a, b, c" when it fails. `explain()` already distinguishes
  403-denied from 403-absent from sealed. The bash reimplementations are worse
  *and* they drift.

**My leaning:** the second group is worth building. The first group is not —
it's a "use the library" fix, and I'll push back on putting it in Go below.

## Chapter 3: Two Verbs, Not a Framework

Here is the whole proposal. Two subcommands, both of which are *derived from a
ref file*, which makes `refs.env` the single source of truth it was always
supposed to be.

### `bm policy`

```
bm policy --from bao/refs.env [--allow kv/adx/s3/…/accounts/foo]…
```

Parses every `bao:` reference in the file (and any extra `--allow` paths for
refs that live in *data* — ObjectStores rows — and can't be seen statically),
dedupes the kv paths, and prints HCL:

```hcl
path "kv/data/adx/elephant-db"     { capabilities = ["read"] }
path "kv/metadata/adx/elephant-db" { capabilities = ["read"] }
path "kv/data/adx/nats"            { capabilities = ["read"] }
…
```

That's it. It writes nothing to Bao. You pipe it where versity pipes its
hand-written file:

```
bm policy --from bao/refs.env | bao policy write elephant-imaging -
```

or — better, and this is the versity pattern — you commit the output as
`openbao/policies/elephant-imaging.hcl` and let a CI check assert
`bm policy --from … | diff - openbao/policies/elephant-imaging.hcl`. Now
bug #4 and the bonus bug are impossible: the policy *is* the ref file, and if
someone edits `refs.env` without regenerating, the diff fails.

Why it's cheap: `ParseRef` + `insertSeg` + a sort + `fmt.Printf`. Maybe 40
lines. No new dependencies, no token needed, no network.

### `bm check`

```
bm check --from bao/refs.env [--role-dir ./bao]
```

Logs in with the role (or `BAO_TOKEN`), and for every ref in the file:
fetches metadata (proving the `kv/metadata/` grant that `watch` needs),
fetches data, walks the selector, and reports **by name only**:

```
✓ POSTGRES_PASSWORD        kv/adx/elephant-db#elephant_password        v3, 40 chars
✓ HDDPOOL_ACCESS_KEY       kv/adx/s3/…/accounts/elephant-imaging-poc#elephant-imaging-poc.access
✗ NATS_PASSWORD            kv/adx/elephant/nodes/imaging#NATS_PASSWORD
      no field "NATS_PASSWORD" — present: ELEPHANT_CONFIG_GIT_TOKEN
✗ SOMETHING_ELSE           kv/adx/other#X
      403 — and the path exists (checked with the operator token),
      so this is the POLICY, not a missing secret
```

Exit non-zero if anything is ✗. It does not write the cache (this is a
provisioning-time check, not a warm-up — the container's cache is elsewhere).

What it replaces, line for line:

- the self-test loop (#6) — `explain()` already produces these messages
- the versity shape check (#5) — a selector of `#elephant.secret` *is* the
  shape check; if the record is a string, `apply()` says "is a value, so it has
  no fields under it"
- the "typed length == stored length" check (#3's band-aid) — `check` reports
  the stored length, so you eyeball it once and move on
- the `preflight` container's job, from the operator's laptop, before the
  stack is touched

Why it's cheap: it's `cmdEnv` with a nicer report and the 403-vs-404
disambiguation `explain()` already does. Maybe 80 lines.

### What each provision.sh becomes

```bash
source ../../openbao/bao-cli.sh          # token from /dev/tty, receipts, fp
bao_require_token

# the one secret this deployment OWNS (typed, in the main shell, no $( ))
IFS= read -rs -p 'ELEPHANT_CONFIG_GIT_TOKEN: ' PAT < /dev/tty; echo
jq -n --arg v "$PAT" '{ELEPHANT_CONFIG_GIT_TOKEN: $v}' | bao kv patch kv/adx/elephant/nodes/imaging -
unset PAT

bm policy --from refs.env | bao policy write elephant-imaging -
bao write auth/approle/role/elephant-imaging token_policies=elephant-imaging …   # 4 lines, unchanged
bm check --from refs.env --role-dir .
```

Thirty lines, of which the ownership prose ("why elephant-db owns the password,
and the rotation order") stays as comments because *that* is the part a human
needs to read. The 600-line version's comments are mostly post-mortems of
bugs that this shape can't have.

## Chapter 4: The Things I'm Pushing Back On

You asked me to push back if it's not worth it. Here is where I'd say no, or
not yet.

**`bm put` / a Go secret-entry prompt.** Tempting — Go has no command
substitution, so bug #3 is structurally impossible there. But count the
typed secrets across four scripts: **one.** The PAT. Versity reads a file,
events reads a file, db generates. Building a hidden-prompt + JSON-merge +
CAS-write + length-verify command in Go for one field is a framework for a
problem we have once. Use `bao-cli.sh`'s prompt shape and move on. Revisit
if a fourth deployment needs to type three things.

**`bm approle`.** The `bao` CLI does it in four lines and versity's version
of those four lines is fine. The keep-or-reissue dance is a `grep` on
`../.env`. Nothing here needs `ParseRef`.

**`bm gen` (generate-and-store).** It's `head -c 64 /dev/urandom | base64 |
tr -dc A-Za-z0-9 | head -c 40` piped into `jq` into `bao kv patch`. Three
lines; the value never touches a variable if you pipe it. Not a Go feature.

**Moving the LAN-vs-tailnet default into bm.** The three-way copy of that
comment is annoying, but the right home is one paragraph in
`openbao/README.md` and `BAO_ADDR=` in each `refs.env` (which imaging already
has). bm's default stays the tailnet name because bm is also run from
laptops.

**A general `bm admin` surface.** No. bm's ★ property is "resolve a ref, cached,
without touching Bao on a hit." Both verbs above are *read-only* and
*ref-driven*; they extend that identity rather than bolt an admin CLI onto it.
The moment a `bm` subcommand *writes* to kv, it needs an operator token,
different failure modes, and a different threat model. Keep the binary that
lives in every container small and boring.

## Chapter 5: Is Even This Worth It?

The honest cost-benefit: two subcommands, ~120 lines of Go, reusing code that
exists. In exchange we delete roughly 250 lines of bash across three scripts
(the policy loop, the self-test, the shape check, the length check) and we
turn the "cross-check refs.env against provision.sh" instruction into a diff
that CI can run.

The alternative — just sourcing `bao-cli.sh` and being disciplined about `$( )`
— fixes bugs #1–#3 and costs nothing. Do that regardless. It does **not** fix
#4–#6 and the bonus bug, because those are about two files that have to agree
and no amount of bash discipline makes a hand-maintained list agree with a
ref file forever. That's the one thing that genuinely wants a program that
understands the ref syntax, and we already have that program.

**So: yes to `bm policy` and `bm check`, no to everything else, and fix the
`NATS_PASSWORD` ref in imaging's `refs.env` today regardless — it's the
bonus bug already in the tree, and `bm check` would have been the thing that
told you.**
