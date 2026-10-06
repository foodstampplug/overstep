# overstep

[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](pyproject.toml)
[![tests](https://img.shields.io/badge/tests-32%20passing-brightgreen.svg)](tests/)
[![status](https://img.shields.io/badge/status-active-success.svg)](https://github.com/foodstampplug/overstep)

**Authorization / BOLA differential tester.** Replay captured HTTP requests under multiple
identities — owner, a peer user, a low-privilege user, unauthenticated — diff every response
against the owner's baseline, and flag where an identity reached something it shouldn't:
**BOLA/IDOR**, **missing authentication**, or **privilege escalation (BFLA)**.

Zero third-party dependencies. Scope-gated. Safe (read) methods only unless you opt in. For
**authorized** bug-bounty / pentest work on assets in your program's scope.

```
  _____   _____ _ __ ___| |_ ___ _ __
 / _ \ \ / / _ \ '__/ __| __/ _ \ '_ \
| (_) \ V /  __/ |  \__ \ ||  __/ |_) |
 \___/ \_/ \___|_|  |___/\__\___| .__/
                                |_|
  authorization / BOLA differential tester · v0.1.0

GET /orders/1001
    bob           peer      BYPASSED      owner=200 cand=200 sim=1.00 len=1.00  → BOLA / IDOR (cross-user object access)
    low           lowpriv   BYPASSED      owner=200 cand=200 sim=1.00 len=1.00  → Privilege escalation / BFLA
    anon          unauth    ENFORCED      owner=200 cand=403

summary: 2 BYPASSED, 0 UNCLEAR, 1 ENFORCED, 0 OWNER_FAILED, 0 ERROR
⚠  2 likely authorization bug(s) — review and verify before reporting.
```

## Why this exists

Broken access control / BOLA is the #1 paid and fastest-growing bug class, yet most hunters
skip it because it needs *two accounts and methodical replay-and-diff* — friction the lazy
majority won't do, which is exactly why those bugs stay un-duplicated. The common tools
(Burp's Autorize / AuthMatrix) are GUI-bound and manual. overstep makes the whole matrix a
scriptable, repeatable CLI so the un-duped surface becomes routine.

## Install

No dependencies. Python 3.10+.

```bash
git clone https://github.com/foodstampplug/overstep && cd overstep
python3 -m overstep --version
# optional: pip install -e .   (gives you the `overstep` command)
```

## Quickstart

1. **Capture traffic as your owner account.** Browse the target logged in as user A, then
   export: browser DevTools → Network → *Save all as HAR*, or Burp → right-click a request →
   *Copy to file* (raw HTTP). Point `-r` at the `.har`, the raw file, or a directory of them.

2. **Describe your identities** (`identities.json`) — see `examples/identities.example.json`.
   Exactly one `owner` (the account you captured as); add `peer`, `lowpriv`, and/or `unauth`.
   Each carries its own auth headers (cookie / bearer / api-key).

   ```bash
   overstep identities template > identities.json   # then paste your cookies/tokens
   ```

3. **Set your scope** (`scope.txt`) — only hosts the program authorizes. See `examples/scope.txt`.

4. **Run:**
   ```bash
   overstep run -r traffic.har -i identities.json -s scope.txt --md report.md -o findings.json
   ```

`run` exits **0** when nothing was bypassed, **3** when at least one `BYPASSED` was found (so
CI / a wrapper can gate on it), **2** on a usage/IO error.

## How it decides (the verdict model)

For every (request, identity) pair it compares the identity's response to a **fresh owner
replay** (re-sent live, so a stale HAR response never misleads it) on three deterministic
signals — status code, body length, body similarity:

| Verdict | Meaning |
|---|---|
| `BYPASSED` | Identity got a success closely matching the owner's → **the finding** |
| `ENFORCED` | Blocked (401/403, login redirect) or clearly different / non-success → authz works |
| `UNCLEAR` | A success, only partly similar — could be the identity's *own* data or a partial leak → **review by hand** |
| `OWNER_FAILED` | The owner baseline itself wasn't a success — refresh the owner session/capture and re-run |
| `ERROR` | Transport error reaching the candidate |

The bug label is assigned from the candidate's role (`peer` → BOLA, `lowpriv` → BFLA/privesc,
`unauth` → missing auth). It's a hint — you assign the final class. (A low-priv user reading a
*peer's object* is really BOLA even though it's labeled privesc; the point is it's a bypass.)

## Safety

- **Scope gate, no override.** Every request is authorized against `scope.txt` before it is
  sent; out-of-scope URLs inside a capture (third-party hosts in a HAR) are skipped, never sent.
- **Reads only by default.** GET/HEAD/OPTIONS. Replaying POST/PUT/PATCH/DELETE as another user
  can *mutate their data*, so writes require `--include-writes` and print a warning. Use
  `--methods` to control the set exactly.
- **Gentle.** A `--delay` (default 0.5s) between requests respects rate rules.
- TLS verification is off by default (staging targets); `--verify` to enable.

## Output

- **Console**: the matrix above (hits only; `--all` shows ENFORCED/ERROR too).
- **JSON** (`-o`): machine-readable findings (BYPASSED + UNCLEAR).
- **Markdown** (`--md`): a per-finding report draft with evidence and repro steps, shaped to
  drop into Trapline's report generator (fill in severity + impact).

## Commands

```
overstep run        -r <requests> -i <identities> -s <scope> [--md f] [-o f] [--all]
                    [--delay 0.5] [--methods GET,POST] [--include-writes]
                    [--verify] [--timeout 15] [--scheme https|http]
overstep identities template        # print a starter identities.json
overstep identities list -i file    # validate + show identities
overstep requests   list -r file    # parse + list captured requests (sanity check)
```

## Tests

Stdlib `unittest` — no install, runs anywhere:

```bash
python3 -m unittest discover -s tests -t .
```

32 tests cover the scope gate, the classifier, HAR/raw parsing, identity loading, and a full
end-to-end authorization matrix against an in-process mock target (BOLA, privesc, missing-auth,
properly-enforced, write-skip, out-of-scope-skip).

## Roadmap

- Sequential-ID / UUID enumeration mode (walk `id=1001..` under one identity).
- GraphQL operation matrix (pair with introspection).
- Response field-level diffing (BOPLA — suppressed fields present in the raw body).
- Auto-detect which captured requests are object-scoped (have an ID) to prioritize.

## Author

Built and maintained by **Dev** ([@foodstampplug](https://github.com/foodstampplug)). Issues and ideas welcome.

Licensed MIT. Built for authorized testing only — in scope, non-destructive, your own targets.
