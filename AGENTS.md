# AGENTS.md — orientation for any agent doing implementation work in this repo

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

## Agent definitions live in TWO places — edit the right one

The six registered agents (`bughunter`, `recon`, `pentest`, `validator`, `chain-builder`,
`cloud-offensive`) exist both at `~/.claude/agents/` and at `skills/moraa-ai-offsec-agent/agents/`.

- **`~/.claude/agents/` is canonical.** Claude Code loads agents from there; that is the copy with
  the full `mcp__burp__*` tool grants.
- `skills/moraa-ai-offsec-agent/agents/` holds **mirrors**, kept in the repo so the methodology travels
  with its agents. Never edit these directly — edit the canonical copy and re-mirror, or the two
  silently drift (they did: `chain-builder`, `recon`, `validator` had lost their Burp grants).
- `knowledge/bug-bounty/agents/` is a **third, vendored set** of 10 upstream files that duplicates
  names like `chain-builder` and `validator`. It is NOT in an agent directory so nothing loads it —
  but it is in the corpus a model may read. Do not treat those as the live definitions.

## What this repo is

`moraa-ai-offsec-agent` is a working offensive-security methodology: per-vuln-class playbooks
(`ssrf.md`, `idor-access-control.md`, `cors.md`, `graphql.md`, `xs-leaks.md`, `web-cache.md`, …),
a router in `SKILL.md`, and `scripts/` — automation that turns recurring, expensive manual
checks into single deterministic commands. It is used on live authorised bug-bounty
engagements. `SKILL.md` is the entry point; `scripts/README.md` documents every script.

**The one rule the whole methodology is built on**: a finding must be something an attacker
could do *right now* for real harm. "Could theoretically…" is not a finding. Tooling here
exists to produce evidence, not to produce output.

## Hard safety rules — these are not style preferences

1. **Never make live requests to a real third-party host from a test.** Tests are offline:
   mock at the script's single network seam, or use a local fixture / throwaway
   `127.0.0.1` server you start and stop yourself. A test suite that hits the internet is
   broken, and on this repo it could also mean unauthorised traffic to someone's production.
2. **Never print a secret.** These scripts handle live session cookies, JWTs, API keys and
   AWS STS credentials. Print header *names*, lengths, and hash prefixes — never values.
   Script output routinely gets pasted into a bug report. `xsleak_probe.py` leaked full
   session JWTs to stdout until this was fixed; don't reintroduce it.
3. **A probe must not damage or alter the thing it measures.** The clearest example is
   `cache_probe.sh`: its whole safety argument is that a unique cache-buster keeps a
   poisoned entry off any key a real user is served. That argument has a precondition — the
   query string must be *in* the cache key — and on real CDNs it sometimes isn't, so the
   script pre-flights every host and refuses the unsafe ones. **Do not weaken or remove a
   safety pre-flight to make a host testable.** If a check blocks something, that is the
   check working.
4. **State the precondition, don't promise unconditional safety.** A header comment that
   over-promises is worse than one that's honest about limits, because someone will rely
   on it. This repo has already shipped one false guarantee; don't add another.

## Conventions

- **Shell**: POSIX-ish bash, `set -euo pipefail`. Paths may contain spaces (real engagement
  dirs do) — use NUL-delimited `find -print0 | xargs -0`, quote every expansion.
- **Python**: 3, **standard library only**. No third-party deps — these run in sandboxed
  engagement environments where `pip install` fails (no sudo, PEP-668 externally-managed
  interpreters). `favicon_hash.py` contains a hand-rolled MurmurHash3 for exactly this reason.
- **Every script starts with a header comment explaining WHY it exists** — the recurring
  problem it removes — then usage, then code. Match the tone of `build_known_hosts.sh` and
  `jwt_expiry.py`.
- **Line endings**: `.gitattributes` forces LF on `scripts/**` and `tests/**`. CRLF breaks
  `#!/usr/bin/env` shebangs under WSL, which is the standing execution environment.
- **Portability note**: some greps (MSYS/Git-Bash) SIGABRT on `-i` combined with `-F`.
  Don't combine them.

## Tests

`tests/` uses **stdlib `unittest` + `unittest.mock` only**, no pytest, no runner config.
Network is mocked at each script's single seam (see `test_cors_check.py`, `test_cms_detect.py`
for the pattern). Fixtures live in `tests/fixtures/<area>/`.

```bash
python3 -m unittest discover -s tests -v                      # whole suite
python3 -m unittest discover -s tests -p "test_foo.py" -v     # one file
```

For shell scripts, drive the script as a subprocess against a local fixture server or
recorded header files and assert on its stdout/exit code; `bash -n` for syntax is a floor,
not a test.

## Working agreement

- Do **not** commit or push. Leave changes in the working tree; the orchestrator reviews the
  diff and lands it.
- Don't modify a script's behaviour while writing tests for it. If a test reveals a bug,
  report it — don't silently "fix" the script so the test passes.
- Report honestly what you did *not* do or could not verify. An unverified claim in a
  report here becomes an unverified claim in a security finding.
