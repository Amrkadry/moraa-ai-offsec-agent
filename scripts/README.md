# moraa scripts — token-saving automation

## `doctor.sh [--json]`
Recon-environment diagnostic — run this first on a new box/WSL distro. Reports every tool
`recon.md`/`scripts/` assume might exist (OK/path+version, WARN if optional and missing,
MISSING if required and missing — exits non-zero only on a required-tool miss), API-key
presence (never values) for `lib/config.sh`'s known keys, DNS/internet reachability, and
output-dir writability. `--json` emits the same data as a normalized object for an agent to
branch on instead of parsing the human table.

```bash
scripts/doctor.sh              # human-readable
scripts/doctor.sh --json | jq .missing_required_tools
```

## `lib/tools.sh` / `lib/config.sh` (sourced, not run directly)
`lib/tools.sh` provides `tool_path <name>` / `tool_exists <name>` / `tool_version <name>
[flag]` — searches PATH plus the common extra install dirs a non-login shell or a
go-installed tool won't have on PATH (`~/go/bin`, `~/.local/bin`, `/opt/*/bin`, ...). Use
this instead of a bare `command -v` in any new script so it works the same whether it's
run from an interactive shell or spawned by an agent. `lib/config.sh` provides
`moraa_config_get <ENV_VAR_NAME>` / `moraa_config_has <ENV_VAR_NAME>` — checks the
environment first, then `~/.moraa/config.json` (gitignored, never committed) as a fallback
so you don't have to `export` every API key in every shell. See both files' headers for
full usage; every new script that shells out to an optional tool or needs an API key
should `source` these rather than reinventing the check.

These exist because long engagements hit the same expensive pattern repeatedly: an agent
re-reads a multi-thousand-line `coverage.md`/`HUNT-QUEUE.md` (or re-pulls the same CT-log
data a prior pass already triaged) just to answer "is this host already known?" or "is
this token still fresh?" — burning tokens on re-derivation instead of hunting. Each script
below turns one of those recurring questions into a single deterministic command.

All scripts are POSIX shell or stdlib-only Python 3 (no pip — engagement boxes can't install),
and are safe to re-run any time — they regenerate their outputs from source, never hand-edit
their own state.

## `build_known_hosts.sh <engagement-dir> [tld ...]`
Greps every `.md`/`.txt`/`.json` file under the engagement dir for hostnames matching each
given TLD, dedupes, writes `recon/known_hosts_<tld>.txt`. Run this once at the start of a
session (or after a big batch of findings/coverage updates) to get a flat, grep-able
registry instead of re-reading prose files to check "was this host already tested."

```bash
./build_known_hosts.sh "/path/to/engagements/acme.example" acme.example acme-legacy.example acme-nms.example
grep -vFxf recon/known_hosts_<tld>.txt fresh_candidates.txt   # isolate genuinely NEW hosts
```

## `enum_diff.sh <domain> <engagement-dir> [subfinder|full]`
Runs subfinder + crt.sh + certspotter (+ assetfinder/chaos in `full` mode) against a
domain, folds the union into `recon/known_hosts_<domain>.txt`, and outputs ONLY the hosts
that weren't already in that registry to `recon/new_candidates_<domain>_<date>.txt`. This
is the fix for the recurring "three separate triage passes on the same day all rediscover
the same 300+ hosts" problem — run `build_known_hosts.sh` first so there's something to
diff against.

```bash
./enum_diff.sh acme.example "/path/to/engagements/acme.example" full
```

## `classify_hosts.sh <candidates-file>`
Fingerprints a candidate list with `httpx` and auto-clusters by (status, content-length).
The largest cluster gets tagged `CATCHALL?` — this is the automated version of the lesson
learned the hard way on `*.acme-nms.example` (wildcard DNS + Host-header L7 routing means any
label resolves and falls back to an identical generic redirect that looks "live" in a
shallow scan). Everything outside that cluster is tagged `LIVE-DISTINCT` and worth
looking at first. **Always eyeball a few of the `CATCHALL?` bucket once per engagement**
— the heuristic can be wrong on a small candidate set.

```bash
./classify_hosts.sh recon/new_candidates_example.com_2026-09-18.txt
awk -F'\t' '$5=="LIVE-DISTINCT"' recon/new_candidates_example.com_2026-09-18.txt.classified.tsv
```

## `jwt_expiry.py <auth.json>`
Recursively scans an `auth.json` for JWT-shaped strings, decodes the payload (no signature
verification — this is a freshness check, not a security check), and reports exp/iat vs
now, sorted soonest-to-expire first, flagging anything already expired or expiring within
an hour. Non-JWT opaque tokens/cookies are listed separately with a reminder to verify
liveness directly or pull a fresher one from Burp history. Replaces "reason about whether
this token is probably still good" with an actual answer.

```bash
python3 jwt_expiry.py "/path/to/engagements/acme.example/auth.json"
```

## `dns_brute.sh <wordlist|assetnote> <output-dir> <domain1> [domain2 ...]`
Full-wordlist DNS brute-force across one or more (sub)domains in a single `dnsx` pass, with an
automatic per-zone wildcard pre-flight check (queries a random never-seen label against EVERY
target zone before brute-forcing, not just the apex — see the acme.example r23 lesson below) and an
`httpx` + `classify_hosts.sh` filter pass on any zone that comes back wildcarded. Pass `assetnote`
as the wordlist arg to auto-download Assetnote's `2m-subdomains.txt` (2.1M words).

```bash
./dns_brute.sh assetnote recon/brute acme.example acme-legacy.example svc.acme.example dev.svc.acme.example stg.svc.acme.example
```

**Lesson learned (acme.example r23, 2026-09-18)**: wildcard DNS is NOT limited to the zone apex or to one
company's whole estate. `*.acme.example` wildcards to a generic CloudFront catch-all, but so do several of
its OWN sub-zones (`stg.acme.example`, `tw.acme.example`, `store.acme.example`, `corp.acme.example`, and even the
already-known `cell0.acme.example`/`cell2.acme.example` app subdomains — each wildcarding to a DIFFERENT generic
body), while sibling zones at the same visual depth (`dev.acme.example`, `svc.acme.example`) are clean NXDOMAIN
zones. Never assume wildcard behavior is uniform across sibling subdomains, and never trust
`dnsx -auto-wildcard` alone in multi-domain mode — it did not reliably suppress any of these. Always
verify with a manual `dig`/`curl` probe per zone before trusting bulk resolution as a signal.

## `gotator_perm.sh <seed-hosts-file> <output-dir> [perm-wordlist]`
Permutation/alteration scan (gotator, depth 1) seeded from every known-live host you feed it,
mutated with `infra_perms.txt` (dev/stg/qa/uat/v2/new/old/internal/api/backup/... ~290 words),
resolved, and auto-classified. Same wildcard-noise caveat as `dns_brute.sh` applies — always review
the `classify_hosts.sh` output before trusting anything as new. On a later recon pass this found a
live dev sibling of an already-partially-exploited production lead purely because the mutation
happened to hit a real internal naming convention (`dev-<prod-hostname>`) — that's the whole point
of this technique: CT logs and subfinder only find names that got a public cert; permutation scans
find names that follow an internal naming *pattern*.

```bash
./gotator_perm.sh recon/known_hosts_<tld>.txt recon/perm
```

## `favicon_hash.py <url> [<url> ...]`
Shodan/FOFA-format favicon mmh3 hashing with **zero external dependencies** — a pure-Python
MurmurHash3-x86-32 implementation, verified byte-for-byte against the real `mmh3` package. Exists
because `pip install mmh3` routinely fails in sandboxed engagement environments (no sudo, PEP-668
"externally managed" Kali/Debian pythons, no `ensurepip`). Prints the hash plus ready-to-paste
`http.favicon.hash:` (Shodan) / `icon_hash=` (FOFA) query lines. The actual Shodan/FOFA *query* still
needs an API key or a logged-in web session — this script only gets you to the hash.

```bash
python3 favicon_hash.py https://app.acme.example/favicon.ico
```

## `find_asn_netblocks.sh "<org name search term>"`
Finds a company's own dedicated ASN/netblock via ARIN's public REST API (no key needed) —
distinguishes real, dedicated IP space from the shared AWS/CloudFront/Shopify/Cloudflare ranges
that dominate a cloud-hosted company's discoverable footprint. **Always check scope before acting on
the result**: on a later recon pass this found the vendor's real ASN (`AS27625`) and netblock
(`192.76.255.0/24`), which turned out to be their San Jose corporate office network — explicitly
OUTSIDE a domain-scoped (`*.acme.example`/`*.acme-legacy.example`/`*.acme-nms.example`) bug bounty. Finding a dedicated
netblock is not itself permission to scan it.

```bash
./find_asn_netblocks.sh "the vendor*"
```

## `subdomain_takeover.py <host>`  (or: -l recon/subs.txt)
Dangling-DNS / subdomain-takeover candidate detector — CNAME + NS (best-effort) resolution, and a
candidate only flags when fingerprint + DNS-state + HTTP evidence all agree. Backed by
`scripts/data/takeover_fingerprints.json` (50 service fingerprints merged from DNSReaper
upstream). Replaces eyeballing `httpx -cname` output against a takeover list from memory — the
recall problem is why the takeover checklist item keeps getting skipped.

```bash
python3 scripts/subdomain_takeover.py sub.target.com --verbose
python3 scripts/subdomain_takeover.py -l recon/subs.txt --json --output takeovers.json --threads 20
```

## `cms_detect.py <url>`  (or: -l recon/live.txt)
Adaptive CMS/web-technology fingerprinter — weighted-signal identification (not a single
`X-Powered-By` grep), version extraction, and CMS-specific follow-up checks per host. Detection
itself is recon/info; an *exposure* it turns up gets its own low finding. The `--json` output is
also the exact input `nuclei_wrap.py --from-cms-detect` consumes (see below) — run this before
the quick-win sweep and keep the file.

```bash
python3 scripts/cms_detect.py https://target.example --verbose
python3 scripts/cms_detect.py -l recon/hosts.txt --json --output cms.json --threads 20
```

## `cors_check.py <url>`  (or: -l recon/live.txt)
Credentialed-CORS misconfiguration checker implementing the `cors.md` pipeline: baseline + Origin
bypass-payload sweep, the adaptive unescaped-dot allowlist sweep, preflight consistency, and
SameSite discipline. Verdicts cap at LIKELY by design — a credentialed-CORS reflection is a
precondition, never a standalone finding (SKILL.md) — so LIKELY means "go prove the exploit by
hand", not "file it".

```bash
python3 scripts/cors_check.py https://target.example/api/account --cookie "SESSION=<value>"
python3 scripts/cors_check.py -l recon/live.txt --json --output cors.json --threads 20
```

## `github_recon.py --org ORG [--domain DOMAIN] [--local-repo PATH]`
GitHub/code-recon orchestrator (`recon.md` §4): wraps trufflehog (org-wide secret scan, live
verification ON), gitleaks against an ALREADY-cloned local repo (`--local-repo` — it never
clones), github-subdomains (domain hosts in GitHub code), and the authenticated GitHub code-search
dork sweep (10 req/min, spaced; 403/422 recorded, not retried). Not a secret-scanning engine — it
normalizes whatever sources actually ran into the repo JSON contract and says exactly which were
skipped and why. Secret VALUES never appear in output (detector/repo/file/line/verified only).
Token: `--token`, `$GH_TOKEN`, or the `GH_TOKEN` key in `~/.moraa/config.json`.

```bash
python3 scripts/github_recon.py --org targetorg --domain target.com --json --output gh.json
python3 scripts/github_recon.py --domain target.com --local-repo ~/clones/target-api --verbose
```

## `exposure_sweep.py <url>`  (or: -l recon/live.txt)
Source/config disclosure sweeper (`recon.md` §4d): tier-1 triage sweep (14 paths) + tier-2
env/config-by-stack (5 paths) across a host list, with genuine-file format checks, the §4d
severity ladder applied (200=info, real file=low, +secret pattern=high, never critical), git
origin-remote extraction (a credentialed remote is its own distinct high finding), and best-effort
`.DS_Store` filename extraction. A detector, not a git-dumper — reconstruction of confirmed hits
stays with the manual §4d techniques.

```bash
python3 scripts/exposure_sweep.py -l recon/live.txt --json --output exposure.json
python3 scripts/exposure_sweep.py https://host.example --threads 20 --verbose
```

## `js_recon.py <bundle-url>`  (or: -l recon/js.txt)
JS bundle miner (`js-analysis.md` pipeline): range-parallel download with a hard size assertion,
secret/key regex sweep, backend hosts + API paths + SPA routes, and parse-confirmed `.map`
exposure checks — across many bundles in one pass instead of one curl+grep per file. Secrets are
regex matches only (capped at medium pending live validation); source-map exposure is
low/CWE-540; the aggregate summary is info. Bundles at least `--chunk-threshold-mb` (default 2)
that advertise `Accept-Ranges` take the range-parallel path (`--range-chunks`, default 12).

```bash
python3 scripts/js_recon.py https://host/app.min.js
python3 scripts/js_recon.py -l recon/js.txt --json --output js_recon.json
python3 scripts/js_recon.py -l recon/js.txt --range-chunks 16 --chunk-threshold-mb 5 --verbose
```

## `graphql_recon.py <url>`  (or: -l recon/live.txt)
GraphQL recon (the automated half of `graphql.md`): endpoint discovery, introspection dump with
aliased-bypass retry, bounded field-suggestion fallback (`--all-paths` enumerates every confirmed
endpoint, not just the first). Mapping only — discovery and schema dumps are info; exploitation
(IDOR, mass-assignment, batching) stays manual per `graphql.md`.

```bash
python3 scripts/graphql_recon.py https://target.example --all-paths --verbose
python3 scripts/graphql_recon.py -l recon/live.txt --json --output graphql.json
```

## `nuclei_wrap.py -u URL | -l FILE [--from-cms-detect cms.json] [--local-templates]
Thin wrapper around ProjectDiscovery's nuclei (`recon.md` §7 quick-wins), NOT a template engine:
builds the default tag set (`exposure,config,git,backup,takeover` @ `critical,high,medium`) or an
ADAPTIVE one from a `cms_detect.py --json` file (`--from-cms-detect`: identified CMS → `+<cms>`
tag for that target, one nuclei run per tag-set group), runs nuclei with `-jsonl`, and maps its
template-id/severity/matched-at into the repo finding contract — severities pass through
unchanged, nothing re-derived. nuclei missing → clean skip (exit 0). Intended combo: run
`cms_detect.py --json` first, feed the file here. `--local-templates [DIR]` (default:
`<repo>/templates`) additionally loads the library's own high-signal template set via `-t` on
every run, tagging each run `+moraa` so the `-tags` filter still loads them — validate first
per `nuclei-templates.md` (`nuclei -validate -t templates/`, plus the positive/negative
control runs) and treat every hit as a 0.85-confidence lead, never proof.

```bash
python3 scripts/nuclei_wrap.py -u https://target.example
python3 scripts/nuclei_wrap.py -l recon/live.txt --from-cms-detect cms.json --json --output nuclei.json
python3 scripts/nuclei_wrap.py -l recon/live.txt --local-templates --json --output nuclei.json
```

The library's own templates live in `templates/` (one file per class the public sets handle
weakly — credentialed-CORS, genuine source maps, SvelteKit `__data.json`, Next.js middleware
bypass probe, Spring actuator, edge-block gaps, healthz metadata) with their gates documented
in `nuclei-templates.md` §5. Every template carries the `moraa` tag.

## `race_harness.py (-r req.txt | URL [curl-style opts])`
Fires N (default 20) copies of one HTTP request with maximum synchronization — a thread barrier
plus last-byte sync (every worker opens its connection and sends all but the FINAL byte of the
request, blocks, then all workers release the last byte together) so all N land inside one server
tick. That sync is what separates a real race test from an unsynced loop, where requests land
milliseconds apart and every run "passes" — the reason race conditions (double-redeem, transfer,
vote/rate-limit, 2FA bypass) currently get skipped. Responses are grouped by (status,
content-length, body sha256 prefix) and only group counts print; one response outside the modal
group IS the bug, and `--diff` flags it loudly and exits non-zero. Input is a Burp "Copy to file"
request (`-r`; Host header picks the target) or curl-style args; `{{i}}` templates a per-request
value (unique one-time codes) without breaking sync. Stdlib-only HTTP/1.1 — on H2 targets where
this "fails", re-test with Turbo Intruder's single-packet attack before calling it unexploitable.

```bash
python3 scripts/race_harness.py -r req.txt -n 30 --diff
python3 scripts/race_harness.py -X POST https://target/api/redeem -H "Cookie: s=..." -d '{"code":"X"}' -n 20 --diff
```

## `cache_probe.sh <url1> [url2 ...]`  (or: cat urls.txt | scripts/cache_probe.sh)
Non-destructive web cache poisoning/deception sweep. For each URL it probes the standard
unkeyed-input candidates (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`,
`X-Rewrite-URL`, `X-Host`, plus one fat-GET) as warm+verify request pairs, reads cache-hit
signals (`X-Cache`, `CF-Cache-Status`, `Age`), and reports ONLY URLs where the injected canary is
reflected AND the verify response came from cache — reflection alone is noise; cached reflection
is the finding. Hard non-destructive guarantee (stated in the header): every single probe carries
a unique random canary AND a unique cache-buster query param, so even a "successful" poisoning
is stored under a cache key no real user will ever request.

```bash
scripts/cache_probe.sh "https://target.com/" "https://target.com/account/menu"
```

## `xsleak_probe.py -e <url> [-e ...] -H "<authed cookie/header>"`
XS-Leak oracle detector: for each endpoint it samples N times (default 30) with and without the
authed leg's headers, computes median ± MAD for timing plus ≥90%-consistency checks for the
error-vs-success distinguishers (status class, redirect behaviour, content length), and flags an
endpoint ONLY when the separation between conditions exceeds the measured noise floor (default
3σ combined MAD + 25ms). Naive single-sample timing scripts are all false positives — which is
exactly why this class gets skipped — so the statistical rigour is the point, not a nicety.
Stdlib-only; sequential sampling on purpose (concurrency would distort the timing signal).

```bash
python3 scripts/xsleak_probe.py -e "https://target.com/api/notifications" -H "Cookie: session=..." -n 30
python3 scripts/xsleak_probe.py -E endpoints.txt -H "Cookie: session=..." --insecure
```

## `check_docs.py`
Structural lint over the library's own .md corpus — the repo checking itself the way tests check
code. Exists because a doc gave wrong advice for months (recon.md's DNS-resolve-to-verify CT
names, which wildcard DNS invalidates) and nothing caught it. Checks: zero-fence root docs
(technique doc with no commands), unbalanced ``` fences, `[[wiki-links]]` that resolve to no
file, ROUTER rows pointing at missing files, root docs no ROUTER row references (orphans, minus
the meta allowlist and the deliberately-unrouted MANUAL-ONLY docs), the MANUAL-ONLY invariant
(captcha-bypass.md/web-cache.md only ever inside SKILL.md's MANUAL-ONLY section, zero mentions
in web-hunt.md), web-hunt class-table coverage (a class wired into SKILL.md's ROUTER but absent
from web-hunt.md is invisible to bughunter STEP 3 — FAIL), the validate.md pointer rule (agent
files must resolve the gate to the ROOT doc, not the knowledge/ copy — FAIL), gate-substance
presence (INFO only — substance phrasing or an impact-gate heading; deliberately not a
heading lint), and agent mirror drift against `~/.claude/agents/` (WARN — these mirrors once
silently lost their Burp grants; AGENTS.md records it). knowledge/, docs/ process notes and
`*.bak*` (now collected in `bak/`) are excluded by design (scope documented in the script
header). Exit non-zero on any FAIL; WARN/INFO inform without gating.

```bash
python3 scripts/check_docs.py           # after any doc change; run from the repo root
python3 scripts/check_docs.py --quiet   # output only on failure
```

## Requirements
`subfinder`, `httpx`, `dnsx`, `curl`, `python3` on PATH. `assetfinder`/`chaos`/`gotator` are
optional (only used in `enum_diff.sh full` mode / `gotator_perm.sh`, silently skipped or need
`go install github.com/Josue87/gotator@latest` if missing). No API keys required for the
crt.sh/certspotter fallback path, the ARIN ASN lookup, or the favicon-hash computation itself
(only the actual Shodan/FOFA *query* needs a key). The vuln-class harnesses (`race_harness.py`,
`cache_probe.sh`, `xsleak_probe.py`) and the eight detector/recon scripts (`cms_detect.py`, `cors_check.py`, `exposure_sweep.py`, `github_recon.py`,
`graphql_recon.py`, `js_recon.py`, `nuclei_wrap.py`, `subdomain_takeover.py`) need nothing beyond
the already-required `python3` and `curl` — stdlib-only, no pip, by design. `github_recon.py` and
`nuclei_wrap.py` additionally *wrap* external tools (`trufflehog`/`gitleaks`/`github-subdomains`
and `nuclei` respectively) — optional wrapped tools, not deps, same category as
`assetfinder`/`chaos`/`gotator` (cleanly skipped/flagged when missing).

## SPA bundle mining + authz sweep (subscription-billing SaaS case)
Stdlib-only, born on the SaaS platform app (Vite/rolldown SPA), reusable on any JS-heavy SaaS dashboard:
- **`rc_mine_routes.py <all.js> <outdir>`** — cat all chunks into one file first. Extracts
  API route strings (`/v1/...`, `/internal/v1/...`, template-literal forms), SPA page routes, and
  keyword-bearing literals (webhook/api_key/saml/capital/collaborator/impersonat) →
  `routes.txt`, `pages.txt`, `keywords.txt`.
- **`rc_extract_mutations.py <all.js> <outfile>`** — for every `` method:`VERB` `` marker grabs the
  nearest preceding `url:` (handles RTK-query `url:$(...)`) plus a body-shape hint → mutation
  inventory (`VERB url BODY:...`). Pair-regexes that demand url+method adjacent miss RTK code —
  this nearest-marker approach doesn't.
- **`rc_ctx.py <all.js> <kw>`** — URL-ish literals within ±400 chars of a keyword (endpoint
  discovery around `sensitive`, `api_keys`, `webhook`, ...).
- **`rc_authz_sweep.py <auth.json> <out.json>`** — the routes × {unauth, A, B} status matrix with a
  bogus-id control; reads cookie strings straight from the engagement `auth.json`; flags any 200 on
  the B/unauth column (mind: `/me`-routes legitimately 200 for B — self-scoped ≠ IDOR).
- **`rc_probe1.py` / `rc_webhook_probe.py` / `rc_collab_lane.py`** — the lane probes for that
  engagement (step-up unlock, webhook verb+test surface, invite→accept→privesc chain);
  template them per target. **`rc_webhook_probe.py` lesson: never blind-probe DELETE in a verb
  surface on a pre-existing resource — the API executed it and killed the tenant's webhook. Only
  DELETE objects your own lane created this session.**
