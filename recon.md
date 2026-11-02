# Moraa — Recon (external + internal)

> External = attack-surface mapping for web/bug-bounty. Internal = host/AD discovery once you
> have a foothold (pivot first). Deep ref: `knowledge/bug-bounty/SKILL.md`,
> `knowledge/offensive/offensive-osint.md`, `knowledge/offensive/offensive-active-directory.md`.
>
> Recon compounds: more assets → more surface → the one forgotten host is the bug. Run the passive
> sweep in full, THEN brute/permute, THEN fuzz content on the ranked live hosts.

---

## Target scoring — go/no-go (decide before you sink hours in)

| Criterion | Points |
|---|---|
| Max bounty ≥ $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Known tech stack | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

`<4` skip · `4-5` only if nothing better · `6-8` good, 1-3 days · `≥9` excellent, up to a week.

Kill signals (don't dive): max bounty <$500 · all recent reports N/A/dupe (hunters saturated it) ·
scope is a static marketing page only · company <5 employees/no revenue · program explicitly
excludes your planned bug class.

---

## 0. Wordlists (set these once)

```bash
# Assetnote — best real-world lists (download fresh, they update ~monthly)
SUBS_BIG=httparchive_subdomains_2026_02_27.txt   # https://wordlists-cdn.assetnote.io/data/automated/<name>
# grab: curl -sO https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2026_02_27.txt
#       (also: best-dns-wordlist.txt, httparchive_directories_*.txt, httparchive_parameters_*.txt)
# Local curated content/dir+SvelteKit/API list (86k lines, project-tuned)
FUZZ_ALL="D:/wordlists/Fuzz_all.txt"
# SecLists fallbacks: Discovery/DNS/*, Discovery/Web-Content/*, raft-*-directories.txt
```

---

## 0b. Scripts — reach for these FIRST on a long-running/multi-session engagement

`scripts/` (this skill repo) automates the recurring, token-expensive parts of a long
engagement — repeated CT-log re-pulls that just rediscover the same hosts a prior pass
already triaged, manually re-reading a multi-thousand-line `coverage.md`/`HUNT-QUEUE.md`
to check "is this host already known," the wildcard-DNS/generic-fallback-redirect trap
(see `*.acme-nms.example` lesson below), and reasoning about whether a stored `auth.json` token is
still fresh instead of just checking. Full usage in `scripts/README.md`; short version:

```bash
# once per session (or after a big coverage/findings update): build the known-hosts registry
scripts/build_known_hosts.sh <engagement-dir> TARGET ...

# enumerate a domain, get ONLY hosts not already in the registry
scripts/enum_diff.sh TARGET <engagement-dir> full

# classify a candidate list, auto-flag the wildcard-catchall cluster
scripts/classify_hosts.sh recon/new_candidates_TARGET_<date>.txt

# is this auth.json token still good, or stale and due a Burp-history refresh?
python3 scripts/jwt_expiry.py <engagement-dir>/auth.json

# full-wordlist DNS brute across one or more (sub)domains, with automatic per-zone
# wildcard pre-flight + filtering (pass "assetnote" to auto-download the 2.1M-word list)
scripts/dns_brute.sh assetnote recon/brute TARGET sub.TARGET dev.sub.TARGET

# permutation/alteration scan (gotator) seeded from every known-live host, resolved + classified
scripts/gotator_perm.sh recon/known_hosts_TARGET.txt recon/perm

# favicon mmh3 hash, zero deps (pip mmh3 routinely fails in sandboxed envs) — prints
# ready-to-paste Shodan/FOFA query lines
python3 scripts/favicon_hash.py https://TARGET/favicon.ico

# find a company's own dedicated ASN/netblock (vs shared cloud IP space) via ARIN, no API key
scripts/find_asn_netblocks.sh "Company Name*"

# dangling-DNS / takeover candidates across the whole sub list (a hit needs fingerprint + DNS
# state + HTTP evidence together; 50 service fingerprints) — detector, not proof
python3 scripts/subdomain_takeover.py -l recon/subs.txt --json --output takeovers.json

# adaptive CMS/web-tech fingerprint per live host (weighted signals + version + follow-ups) —
# keep the --json file, the §7 sweep chains it
python3 scripts/cms_detect.py -l recon/live.txt --json --output cms.json
```

GitHub dorking: `scripts/github_recon.py` runs the authenticated path automatically when a token
is configured (`$GH_TOKEN`, or the `GH_TOKEN` key in `~/.moraa/config.json`) — trufflehog +
gitleaks + github-subdomains + the code-search dork sweep (10 req/min, spaced; 403/422 recorded,
not retried). Official GitHub code search still returns **zero results when unauthenticated**
(confirmed on a later recon pass), so with NO token fall back to manual
`site:github.com "known.internal.hostname"`-style search-engine dorking, which has independently
turned up real leaked recon artifacts before.

---

## 1. Subdomain enumeration — many sources, then merge

No single source is complete. Union them, then resolve.

```bash
# passive (fast, run all → anew dedups)
subfinder -d TARGET -all -recursive -silent | anew recon/subs.txt
assetfinder --subs-only TARGET           | anew recon/subs.txt
amass enum -passive -d TARGET            | anew recon/subs.txt      # optional, slower
chaos -d TARGET -silent                  | anew recon/subs.txt      # ProjectDiscovery dataset (key)
github-subdomains -d TARGET -t $GH_TOKEN | anew recon/subs.txt      # subs mentioned in code
```

### 1a. Certificate Transparency (crt.sh + fallbacks)

```bash
# crt.sh JSON — the %25 is a URL-encoded % wildcard.
# PARSE IT AS JSON. Do NOT grep the raw response — see THE TRAP below.
curl -sk "https://crt.sh/?q=%25.TARGET&output=json" > /tmp/crt.json
python3 - <<'PY' | anew recon/subs.txt
import json
names = set()
for row in json.load(open('/tmp/crt.json')):
    for field in ('name_value', 'common_name'):
        for n in (row.get(field) or '').split('\n'):    # <-- THE FIX: split FIRST
            n = n.strip().lower()
            if n.startswith('*.'): n = n[2:]
            if n.endswith('.TARGET'): names.add(n)
print('\n'.join(sorted(names)))
PY
# THE TRAP (it has fabricated a whole delta on a real pass): crt.sh returns `name_value` as a
#   NEWLINE-separated list inside ONE JSON string. A hostname regex matches ACROSS that separator,
#   so "acme.example\nwww.acme.example\naccount.acme.example" invents the hosts "nwww.acme.example" and "naccount.acme.example".
#   2026-09-29, acme.example: a naive grep reported "478 new hosts". Parsed correctly: the true count
#   was 1. Every 'n'-prefixed name was an artifact.
# DO NOT use "DNS-resolve it to check" as the mitigation on a WILDCARD domain. With `*.TARGET`
#   wildcard DNS, every invented name resolves AND returns the same redirect/app as a real one,
#   which makes the artifacts look completely legitimate. Resolution proves nothing.
#   Verify a host by WHAT IT SERVES — response size + <title> compared against the target's known
#   default-app shell — not by whether it resolves.
# crt.sh often 502s under load → fallbacks:
curl -sk "https://api.certspotter.com/v1/issuances?domain=TARGET&include_subdomains=true&expand=dns_names" \
  | grep -oiE '[a-zA-Z0-9_*.-]+\.TARGET' | sort -u | anew recon/subs.txt
# also: censys/shodan ssl.cert.subject; tls.certificate.parsed via httpx -tls-grab
```
> CT is the single richest source but noisy: per-tenant hosts (`{uuid}.app.TARGET`) flood it —
> filter those (`grep -vE '^[0-9a-f]{8}-'`) unless the tenant instances are in scope & yours.
> **crt.sh outages are multi-day** (acme.example engagement: 502 for 2026-10-02 AND 10-03). A
> certspotter+subfinder run while it's down proves nothing about CT freshness — certspotter's
> anon endpoint returns only a thin recent window. Record "last full CT pull: <date> (<source>)"
> per zone in coverage.md so a "NEW=0" delta is never silently stale; re-pull CT when crt.sh
> returns, before trusting any negative result.

### 1b. DNS brute-force + permutations (find what CT/passive missed)

```bash
# brute with a big list (puredns handles wildcards + fast massdns resolvers)
puredns bruteforce $SUBS_BIG TARGET -r resolvers.txt | anew recon/subs.txt
# or ffuf/dnsx if no puredns:
ffuf -w $SUBS_BIG -u https://FUZZ.TARGET -mc all -t 100 -o recon/ffuf-dns.json     # host-header FUZZ
dnsx -d TARGET -w $SUBS_BIG -silent | anew recon/subs.txt
# permutations from what you already found (dev/stg/uat/api/-v2/region prefixes)
gotator -sub recon/subs.txt -perm permutations.txt -depth 1 -numbers 5 | dnsx -silent | anew recon/subs.txt
# (alt: dnsgen recon/subs.txt | dnsx -silent ; or altdns)
# virtual-host fuzz (subs sharing one IP that DNS won't reveal)
ffuf -w $SUBS_BIG -u https://KNOWN_HOST/ -H "Host: FUZZ.TARGET" -fs <baseline-size>
```

## 2. Resolve → live → fingerprint

```bash
cat recon/subs.txt | dnsx -silent -a -resp | anew recon/resolved.txt
cat recon/subs.txt | httpx -silent -sc -title -td -ip -cname -server -location \
  -favicon -jarm -o recon/live.txt        # -favicon prints the mmh3 hash inline (see §3)
```

## 2b. Alt-port web scan (often skipped — don't skip)

```bash
cat recon/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee recon/alt-ports.txt
```
Admin panels, debug services, internal APIs run on alt ports. Named wins: `:8080/actuator/env`
(Spring Boot), `:9200/_cat/indices` (Elasticsearch open), `:6379` (Redis unauth).

## 2c. NTLM info-disclosure (IIS/SharePoint/Exchange — anonymous, no auth attempt)

`WWW-Authenticate: NTLM`/`Negotiate` on an anonymous response leaks internal AD topology via the
Type-2 challenge's AV_PAIRS — no credential needed, no lockout risk. Send a canned Type-1, read the
Type-2 back over a **keep-alive connection** (one-shot curl usually drops it before the reply):
```bash
curl -sk -I -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  "https://T/_api/web/CurrentUser" 2>&1 | grep -i WWW-Authenticate   # SharePoint REST
# also try: /EWS/Exchange.asmx  /owa/  /Autodiscover/Autodiscover.xml  /_vti_bin/*.asmx
```
Use Burp `send_http1_request` (keep-alive native) or a raw Python `ssl.wrap_socket` to capture the
full Type-2 header, then base64-decode and walk the `AV_PAIRS` (offsets per MS-NLMP): AvId
`2`=NetBIOS domain, `4`=DNS domain (the AD domain), `5`=DNS tree (AD forest root), `7`=timestamp.
A default `WIN-XXXXXXXXXXX` hostname signals never-renamed/lazy provisioning → likely default
service-account creds downstream. A DNS tree like `customer.parent-corp.example` reveals the
target is a child domain inside a larger corporate forest — cross-trust escalation path. Severity:
Medium if internet-exposed + default hostname or forest disclosure, chained with an auth-bypass
finding on the same host it upgrades that finding's severity (attacker now has UPN format ready);
Informational if intranet-only. Feeds `credential-access.md` §0 (UPN format for spray) and
`m365-entra-attack.md` (resolve the disclosed AD domain to an Entra tenant via
`https://login.microsoftonline.com/<domain>/.well-known/openid-configuration`).

## 3. Favicon hashing (find origin-behind-CDN + related/hidden assets by tech)

A favicon's murmur3 hash is a fingerprint: same hash = same app/stack/company. Pivot from it in
Shodan/FOFA to find sibling hosts, the origin IP behind a CDN, and instances of a known product.

```python
# compute the hash (Shodan format: base64-encode the raw bytes first, then mmh3)
import mmh3, requests, codecs
r = requests.get("https://TARGET/favicon.ico")
b64 = codecs.encode(r.content, "base64")
print(mmh3.hash(b64))            # e.g. -1234567890
```
```bash
# httpx already prints it:  httpx -favicon  → "https://host  [-1234567890]"
```
Search the hash across engines:
```
Shodan:  http.favicon.hash:-1234567890
FOFA:    icon_hash="-1234567890"
ZoomEye: iconhash:"-1234567890"
Censys:  services.http.response.favicons.md5_hash:<md5>   (Censys uses md5, not mmh3)
```
Uses: (1) leak the **real origin IP** of a WAF'd site (find a box serving the same favicon on a
raw IP). (2) enumerate an org's estate by a **custom/product favicon**. (3) spot admin panels/
appliances (Jenkins, GitLab, Grafana, VPNs) by their default favicon hash.

## 4. GitHub / code recon (leaked secrets & internal hosts)

`scripts/github_recon.py` orchestrates this section when a GH token is configured (`$GH_TOKEN` or
`~/.moraa/config.json`) — trufflehog + gitleaks (`--local-repo`, it never clones) +
github-subdomains + the authenticated dork sweep, normalized to one JSON contract. Raw commands
below = the no-token fallback and deep-dive reference.

```bash
# clone the org's public repos + members' repos, then scan history (secrets live in old commits)
trufflehog github --org=TARGETORG --only-verified            # verified live creds
gitleaks detect --source ./repo -v                           # local clone deep scan
github-subdomains -d TARGET -t $GH_TOKEN                      # hosts referenced in code
gitdorker -tf tokens.txt -q TARGET -d dorks.txt              # automated dork sweep
```
High-signal GitHub search dorks (web UI or `gh search code`):
```
org:TARGETORG  "password"|"secret"|"api_key"|"apikey"|"token"|"BEGIN RSA PRIVATE KEY"
"TARGET.com" AKIA        "TARGET.com" password
"TARGET.com" filename:.env       "TARGET" filename:config extension:json
"TARGET.com" "authorization: bearer"     "internal" "TARGET.com" filename:.npmrc
org:TARGETORG language:yaml "aws_secret_access_key"
```
Also mine: commit history (`git log -p` / GitHub commit search), Gists of employees, issues/PRs,
dependency manifests (internal package registries → hosts), CI config (`.github/workflows` → cloud
OIDC, secret names). Feed found hosts back into §1, found creds into `initial-access.md`.

## 4b. Google dorking (site indexing leaks what recon tools can't reach)

Google indexes pages that never show up in a crawl (removed but cached, misconfigured directory
listings, exposed docs a robots.txt hides from *your* crawler but not from Google's history).

```
site:TARGET.com inurl:admin | inurl:login | inurl:dashboard | inurl:internal
site:TARGET.com filetype:env | filetype:log | filetype:sql | filetype:bak | filetype:swp
site:TARGET.com filetype:json inurl:config | inurl:swagger | inurl:api-docs
site:TARGET.com "index of /" (backup|db|dump|old|admin)
site:TARGET.com intitle:"index of" "parent directory"
site:pastebin.com | site:trello.com | site:notion.site "TARGET.com" password
site:TARGET.com ext:php intitle:phpinfo "published by the PHP Group"
site:TARGET.com inurl:wp-content | inurl:wp-json          (WordPress instance)
"TARGET.com" site:s3.amazonaws.com | site:storage.googleapis.com | site:blob.core.windows.net
"TARGET.com" (site:jira.* | site:confluence.* | site:*.atlassian.net) — internal ticket leakage
```
Cache tricks: `cache:URL` for a page since taken down; Wayback Machine (`web.archive.org/web/*/TARGET.com/*`)
and `waybackurls`/`gau` for URLs Google itself missed — cross-feed both into §5's `urls.txt`.

## 4c. GitLab recon (self-hosted instances are a different attack surface than GitHub)

Many orgs run **self-hosted GitLab** (`gitlab.TARGET.com`) in addition to/instead of GitHub —
treat it as its own target, not a GitHub substitute:
```bash
# gitlab.com-hosted public groups/projects — same secret-hunting logic as GitHub
gitleaks detect --source ./repo -v                            # after cloning a public project
trufflehog gitlab --org=TARGETORG --only-verified              # if trufflehog gitlab module available

# self-hosted GitLab instance recon (once gitlab.TARGET.com is found via §1)
curl -s https://gitlab.TARGET.com/api/v4/version                       # unauth version disclosure → CVE match
curl -s https://gitlab.TARGET.com/api/v4/projects?visibility=public    # public/internal project listing
curl -s https://gitlab.TARGET.com/explore                              # explore page, no auth needed if misconfigured
curl -s https://gitlab.TARGET.com/api/v4/users                          # user enum if not locked down
```
GitLab-flavored search dorks (gitlab.com web search or self-hosted `/search`):
```
"TARGET.com" AKIA                    "TARGET.com" filename:.env
"TARGET.com" extension:yml "password"     "TARGET.com" "BEGIN OPENSSH PRIVATE KEY"
```
Self-hosted GitLab is also a direct **RCE target in its own right** — check version against known
CVEs (CVE-2021-22205 unauth RCE via ExifTool, CVE-2023-7028 password-reset-to-arbitrary-email,
CVE-2024-6385/6678 unauth pipeline-as-arbitrary-user) before treating it as recon-only. Exposed
`.git/` on any web host (not just GitHub/GitLab-hosted) is its own finding — `git-dumper`/
`GitTools` to reconstruct history from a `.git` directory left in a webroot.

## 4d. Source disclosure & extraction (turns black-box into white-box)

Run the detector first: `python3 scripts/exposure_sweep.py -l recon/live.txt --json` fires the
tier-1/tier-2 path sweep across every live host with the severity ladder and git-remote
extraction already applied. Everything below is the *reconstruction* half — manual
git-dumper/SVN/DVCS work on confirmed hits only.

A bare directory-listing or exposed file is Low/Info alone — it's High/Critical the moment the
recovered source yields a hardcoded secret, a confirmed injectable sink, or auth logic you can now
bypass with certainty. **Severity ladder** — submit at the top you can *prove*, never the bottom:
`path returns 200` → Info · `full source recovered` → Low · `+ verified secret OR confirmed
exploitable sink (SQLi/RCE/auth bypass)` → High/Critical.

**Triage sweep — fire against every live host first:**
```bash
for host in $(awk '{print $1}' recon/live.txt); do
  for p in /.git/HEAD /.git/config /.svn/wc.db /.svn/entries /.hg/requires /.bzr/branch-format \
           /.DS_Store /.env /web.config /WEB-INF/web.xml /application.properties /config.php.bak \
           /backup.zip /.git/logs/HEAD; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$host$p")
    [ "$code" = "200" ] && echo "[HIT] $code  $host$p"
  done
done | tee recon/disclosure-hits.txt
nuclei -l recon/live.txt -tags exposure,config,git,backup -severity info,low,medium,high -o recon/exposure.txt
```
**Same sweep via `meg`** (tomnomnom — "request many paths for many hosts") — replaces the serial
nested curl loop above with a concurrent host×path sweep that saves every raw response (headers +
full body) to disk, one file per request, so a later grep catches a body-content signal even on a
non-200 status, not just a status code:
```bash
printf '%s\n' /.git/HEAD /.git/config /.svn/wc.db /.svn/entries /.hg/requires /.bzr/branch-format \
  /.DS_Store /.env /web.config /WEB-INF/web.xml /application.properties /config.php.bak \
  /backup.zip /.git/logs/HEAD > recon/disclosure-paths.txt
meg -d 1000 -c 20 recon/disclosure-paths.txt recon/live.txt recon/meg-out   # -d: ms delay per host
# recon/meg-out/index: one line per request — "<saved-file-path> <url> (<status>)"
grep " (200" recon/meg-out/index                                # every 200 hit, url + saved-file path
grep -l "BEGIN.*PRIVATE KEY\|password" recon/meg-out/*/*         # grep the actual saved bodies for content
```
General use — `meg` is also the fast path any time you have ONE interesting path (a newly-found
admin panel, an actuator endpoint) and want it checked across the WHOLE resolved host list at once,
or vice versa (one host, a big path wordlist) — it's `ffuf`'s host×path sibling, tuned for saving
full raw responses rather than just a status/size summary. `-d <ms>` rate-limits per host (not
global), so it's safe to run wide without hammering any single origin.

**VCS dump beyond git — reconstruct the whole repo + history, not just the 200:**
```bash
# git (most common) — git-dumper rebuilds the tree even with directory listing OFF
git-dumper "https://HOST/.git/" /tmp/dump-target
cd /tmp/dump-target && git log --all --oneline && git log -p --all | grep -iE "password|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY"
# alt when the index is broken: GitTools gitdumper.sh + extractor.sh

# SVN 1.7+ — everything lives in one SQLite DB
curl -s "https://HOST/.svn/wc.db" -o /tmp/wc.db
sqlite3 /tmp/wc.db "SELECT local_relpath, checksum FROM NODES;"   # file list + blob hashes
# pristine objects at /.svn/pristine/<2-char>/<sha1>.svn-base ; SVN <=1.6 -> /.svn/entries + /.svn/text-base/*.svn-base

# Mercurial / Bazaar — confirm fingerprint then dump with dvcs-ripper
curl -s "https://HOST/.hg/requires"; curl -s "https://HOST/.bzr/branch-format"
rip-hg.pl -v -u https://HOST/.hg/ ; rip-bzr.pl -v -u https://HOST/.bzr/
```
Vendored framework code with no secrets/app-logic = Info at best — chain it to a real secret/sink
or drop it, don't pad your N/A ratio.

**`.DS_Store` — recursive directory map, no brute force needed:**
```bash
pip install ds-store                                 # parser dependency
python3 ds_store_exp.py "https://HOST/.DS_Store"      # recurses into every leaked filename it finds
grep -rilE "backup|admin|config|\.sql|\.zip|\.bak|internal|test" ./HOST/
# single file only: curl -s "https://HOST/.DS_Store" -o /tmp/ds && strings /tmp/ds | sort -u
```

**Backup/temp/swap fuzz — shadow copies serve raw source instead of executing it:**
```bash
ffuf -u "https://HOST/configFUZZ" \
  -w <(printf '%s\n' .bak .old .orig .save .swp .swo .tmp .txt '~' .1 .copy .inc .dist .sample) \
  -mc 200 -ac -t 20
ffuf -u "https://HOST/FUZZ" -w ~/wordlists/SecLists/Discovery/Web-Content/BackupFiles.fuzz.txt \
  -mc 200 -ac -fs 0 -t 30
curl -s "https://HOST/.index.php.swp" -o /tmp/i.swp && vim -r /tmp/i.swp    # vim swap recovery
```

**PHP source read (no RCE needed) — `php://filter` on any LFI-style include sink:**
```bash
curl -s "https://HOST/?page=php://filter/convert.base64-encode/resource=index.php" \
  | grep -oE '[A-Za-z0-9+/=]{40,}' | base64 -d        # raw source, not executed output
# config.php this way = DB creds/API keys, the real escalation
for f in index config admin login db; do              # some servers serve .phps highlighted, no LFI needed
  curl -s -o /dev/null -w "%{http_code} $f.phps\n" "https://HOST/$f.phps"
done
```

**Env/config leak by stack — pull + grep for live-looking secrets:**

| File | Stack | Escalation |
|---|---|---|
| `/.env` `/.env.production` | Laravel/Node/Rails | `DB_PASSWORD`, `APP_KEY`, `AWS_*`, `STRIPE_*` |
| `/web.config` `/connectionStrings.config` | ASP.NET/IIS | DB conn strings, `machineKey` → ViewState RCE |
| `/WEB-INF/web.xml` `*.properties` | Java/Spring | datasource creds — reachable only via traversal → that's the real bug |
| `/application.properties` `.yml` | Spring Boot | DB creds, actuator exposure |
| `/config.php` `/wp-config.php` | PHP/WP/Joomla | DB creds, auth salts |
| `/appsettings.json` `/secrets.json` | .NET Core | conn strings, JWT signing keys |

```bash
for p in /.env /web.config /WEB-INF/web.xml /application.properties /appsettings.json /config.php /wp-config.php; do
  body=$(curl -s "https://HOST$p")
  echo "$body" | grep -iqE "password|secret|api[_-]?key|aws|jdbc|connectionstring|begin .*private key" && echo "[SECRET?] https://HOST$p"
done
```

## 5. URLs, JS, parameters

```bash
# historical + crawled URLs
echo TARGET | gau --subs | anew recon/urls.txt
cat recon/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew recon/urls.txt
# JS → secrets, endpoints, backend hosts (see framework-misconfig.md §3 for the deep mine)
cat recon/urls.txt | grep -iE '\.js($|\?)' | sort -u > recon/js.txt
cat recon/js.txt | while read u; do curl -sk "$u"; done | grep -oiE \
  '(AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9A-Za-z-]+|-----BEGIN)'
# parameter discovery for fuzzing later
cat recon/urls.txt | unfurl -u keys | sort -u > recon/params-seen.txt
# gf pattern classification (tomnomnom/gf) — fast triage over the URL list
for p in xss ssrf idor sqli redirect lfi rce; do cat recon/urls.txt | gf $p > recon/gf-$p.txt; done
```

For the mechanical parts across many bundles at once (secret regex sweep, source-map exposure
check, backend-host/route extraction) run `python3 scripts/js_recon.py -l recon/js.txt --json`;
`js-analysis.md` is still the reference for the manual deep-dive technique.

GraphQL surface: `python3 scripts/graphql_recon.py -l recon/live.txt --json` discovers endpoints
and dumps the schema (introspection w/ aliased-bypass retry) — exploitation stays manual per
`graphql.md`.

## 6. Content / directory fuzzing (per ranked live host)

```bash
# curated project list (fast, high-signal: SvelteKit __data.json, admin panels, API paths)
ffuf -w "$FUZZ_ALL" -u "https://HOST/FUZZ" -ac -t 80 -mc 200,201,204,301,302,307,401,403 -o recon/ffuf-HOST.json
# big recursive dir sweep
feroxbuster -u https://HOST -w $SUBS_BIG --scan-limit 4 -x json,txt,bak,zip,old
# API/params
ffuf -w httparchive_parameters.txt -u "https://HOST/api/endpoint?FUZZ=test" -ac -mc 200
```
> Match filters to the app: note the SPA/API "catch-all" size (everything returns index.html/200) —
> filter it (`-fs <size>`) so a real route stands out. 403 from a WAF ≠ 403 from the app; test
> path/case/header tricks (`bypass-403`).

**ffuf's default User-Agent gets silently rate-limited by some edges (acme-legacy.example lesson) — always set
a real one.** Symptom: ffuf "matches everything" with `Size: 0` (every request 429), or the opposite
— zero results even with a size filter — while an identical `curl` from the same box returns 200.
The edge is keying off the `ffuf` UA string, not IP/rate. Fix: `-H "User-Agent: Mozilla/5.0 (Windows
NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"` on every
run, AND run fuzzers against one edge **serially** (`-t` concurrency alone re-triggers it even with a
good UA on some WAFs). This silently invalidated two runs before it was caught — always eyeball a
handful of raw response bodies/sizes early in a big fuzz job, don't trust the summary line alone.

## 7. Vulns / quick wins

```bash
nuclei -l recon/live.txt -severity critical,high,medium -o recon/nuclei.txt
```
`python3 scripts/nuclei_wrap.py -l recon/live.txt --json` runs this sweep and maps results into
the repo finding contract — intended combo: `cms_detect.py --json` (§0b) → `nuclei_wrap.py
--from-cms-detect cms.json` for an adaptive per-CMS tag set. For the CORS quick-win,
`python3 scripts/cors_check.py <url> --cookie "SESSION=..."` runs the `cors.md` pipeline;
verdicts cap at LIKELY (a credentialed reflection is a precondition, never a standalone finding)
— a hit is a lead to exploit by hand, not a submittable report.

Quick-wins checklist: subdomain takeover · exposed `.git`/`.env`/`.svn` · default creds on admin
panels · JS secrets · open redirects · CORS (`Origin: evil.com`+creds) · S3/cloud buckets ·
GraphQL introspection · Spring actuators · Firebase open `.json` · `__data.json` (SvelteKit) ·
source maps (`*.js.map`) · `_next/data` (Next.js).

Tech fingerprint → stack priority (hunt first before spreading thin):

| Stack | Hunt first | Hunt second | Quick-win paths |
|---|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) | |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (`mark_safe`) | |
| Flask | SSTI (`render_template_string`) | SSRF (`requests` lib) | |
| Laravel | Mass assignment (`$fillable`) | IDOR (Eloquent, no ownership) | `/telescope` `/.env` |
| Express (Node) | Prototype pollution | Path traversal / debug surface | `/.env` `/graphql` |
| Spring Boot | Actuator endpoints | SSTI (Thymeleaf) | |
| ASP.NET | ViewState deserialization (→ padding-oracle if encrypted) | Open redirect (`ReturnUrl`) | |
| GraphQL | Introspection → auth bypass on mutations | IDOR via `node(id:)` | |
| WordPress | Plugin SQLi | REST API auth bypass | `/wp-json/wp/v2/users` `/xmlrpc.php` |

Next.js/SvelteKit → `framework-misconfig.md`.

Map everything into `coverage.md`; feed leaked creds straight to `initial-access.md`.

## Find origin IP behind CDN/WAF
Favicon hash pivot (§3) · historical DNS (SecurityTrails/DNSDumpster) · SAN analysis
(crt.sh/censys) · dev/staging subs on raw IPs · `curl --resolve host:443:ORIGIN_IP https://host/`
to confirm the origin serves the app directly (bypassing the WAF).

---

## Internal (post-foothold — pivot first via `pivoting.md`)

```bash
# Host discovery on the internal subnet
nxc smb 10.10.10.0/24                      # live hosts + signing + OS + domain
fping -agq 10.10.10.0/24                   # or: nmap -sn 10.10.10.0/24
# Service scan key targets
nmap -sC -sV -p 21,22,80,88,135,139,389,443,445,1433,3306,3389,5985,5432 -oA recon/int 10.10.10.10

# What can I touch unauthenticated?
nxc smb 10.10.10.0/24 -u '' -p '' --shares
nxc ldap DC_IP -u '' -p ''
snmpwalk -v2c -c public TARGET
showmount -e TARGET                        # NFS exports
```

Internal recon priorities: DC IP + domain name, SMB signing (relay targets), readable shares,
unauth services, anything with stored creds. Then → `active-directory.md`.

## Recon discipline
- 5-minute rule: if a host shows only 401/403/404 after 5 min, move on.
- Log everything to `recon/`; update `coverage.md` with what's mapped vs untested.
- Impact-first: rank targets by crown-jewel value × easiest entry, not by count.
- Re-run passive recon periodically — new subdomains/repos appear; new == unreviewed == bugs.

## Firmware unpack with no root / no preinstalled binwalk (Kali WSL sandbox)
When a target ships firmware images off a public CDN (fw-update/fw-download style) and you need to
unpack them but `binwalk`/`squashfs-tools`/`binutils` aren't installed and there's no `sudo`:

```bash
# apt-get download does NOT need root — it just fetches the .deb to cwd
mkdir -p /tmp/tools && cd /tmp/tools
apt-get download squashfs-tools liblzo2-2      # add binutils here too if you need objdump/readelf

# dpkg-deb -x extracts a .deb's payload without installing it (no root needed)
dpkg-deb -x squashfs-tools_*.deb extracted
dpkg-deb -x liblzo2-2_*.deb extracted          # only if `ldd` on unsquashfs shows it missing

ldd extracted/usr/bin/unsquashfs               # check for any other "not found" libs, grab those too
export LD_LIBRARY_PATH=/tmp/tools/extracted/usr/lib/x86_64-linux-gnu
/tmp/tools/extracted/usr/bin/unsquashfs -stat  rootfs.squashfs   # confirm superblock first
/tmp/tools/extracted/usr/bin/unsquashfs -d out rootfs.squashfs   # extract (chardev create warnings if non-root — harmless)
```

the vendor's `fwup`-format images (`<VENDORMAGIC><version>\x00<sha1>\x00...` 256-byte header) are a flat
concatenation of `PART <name>\x00...` segments (`u-boot`, `kernel`, `rootfs`) — `grep -a -o` for the
literal `PART` magic to find each segment's offset, then slice the rootfs segment out in Python and
feed it straight to `unsquashfs` (squashfs magic `hsqs` immediately follows the `PART rootfs` header,
offset ~0x38 later). No `binwalk` needed once you know this layout.

Once unpacked: `grep -rla` (not `-rl`, binaries need `-a` to be treated as text) across the rootfs for
credential/key material, and `python3 -c "import re; re.findall(rb'[ -~]{4,}', data)"` as a `strings`
substitute when the `strings` binary itself isn't installed either. This is enough to find hardcoded
hostnames, format strings (protocol/wire-format reverse engineering), and crypto API usage
(`EVP_VerifyFinal`, `d2i_PUBKEY` etc. = the device verifies a firmware signature — check for this
before treating a plaintext-download-transport finding as more than defence-in-depth).

---

## CT-mine the SERVICE name, not just the domain — siblings carry the weak surface

When you land on an interesting service host, immediately run certificate transparency for its
*parent* zone and read the results for **siblings of that service**, not for new domains. A hardened
front door usually has a less-hardened sibling doing the unglamorous work: webhook receipt, internal
service-to-service calls, staging.

Worked example (`blobstore.svc.acme.example`, 2026-09-29). The host itself is a well-gated Go API — every
authz boundary held. One CT query changed the picture:

```bash
curl -s 'https://crt.sh/?q=%25.svc.acme.example&output=json' \
 | python3 -c 'import sys,json;n=sorted({x["name_value"] for x in json.load(sys.stdin)});[print(x) for x in n if "storage" in x]'
```

```
blobstore.svc.acme.example                          <- the host you already had
blobstore.stg.svc.acme.example                      <- staging tier
blobstore.dev.svc.acme.example                      <- dev tier
webhooks.blobstore.svc.acme.example                 <- NEW: separate AWS API Gateway, different IP range
*.acme-blobstore-service.svc.acme.example          <- internal service name, does NOT resolve publicly
*.acme-blobstore-service.{stg,dev}.svc.acme.example
```

Three distinct leads from one request, and none of them were reachable from the app's JS bundle.

### What each pattern is worth

- **`webhooks.<service>.<zone>`** — the highest-value sibling. Webhook receivers take input from a
  *third party* (Stripe, S3, SNS), so the app's normal session auth does not apply; they authenticate
  with a shared secret or a signature instead. A missing or unverified signature check turns into
  forged state — "subscription created", "payment succeeded" — which is direct financial impact.
  Always check whether it is even the same stack: here the main host is CloudFront->ALB->Go, while
  `webhooks.` resolves to a different IP range entirely and is **AWS API Gateway**:

  ```bash
  curl -si https://webhooks.blobstore.svc.acme.example/ | grep -i 'x-amzn-errortype\|x-amz-apigw-id'
  # x-amzn-errortype: ForbiddenException     <- API Gateway, not the app
  ```

- **Internal `<product>-<service>-service` names in the cert but with no public DNS.** These are the
  origin/service-mesh names. They are not directly reachable, but they are the exact `Host:` values
  to try when you are testing routing confusion, and they confirm the internal service naming
  convention for the whole estate — useful for guessing siblings of *other* products.

- **`.stg` / `.dev` tiers** — worth one request each. Often the same code with the edge rules
  relaxed. (Here both returned a CloudFront HTML 403 for every path: edge-restricted, dead end. One
  request each to establish that is still worth it.)

### The trap: API Gateway 403 is not an enumeration oracle

On an API Gateway HTTP API, **"no such route" and "route exists but wrong method" both return the
identical `403 {"message":"Forbidden"}`**. A GET sweep across a webhook host therefore tells you
almost nothing — the real routes are `POST`-only and invisible to it. Confirm you can reach the
backend at all with the one route that does answer, then stop:

```bash
curl -s https://webhooks.blobstore.svc.acme.example/ping     # 200 "healthy"  -> backend reachable
curl -s https://webhooks.blobstore.svc.acme.example/stripe   # 403 Forbidden  -> proves nothing either way
```

**Do not brute-force POST against a production webhook receiver to find routes.** Every request is a
state-changing write to a billing/provisioning path, and the blast radius is other people's
accounts. Recover the path from the vendor side instead — the webhook URL is configured in the
provider's dashboard, appears in provider-side delivery logs, and is frequently hardcoded in
IaC (`terraform`/`serverless.yml`) or in a leaked config on GitHub. That is a recon problem, not a
fuzzing problem.

---

## "Edge-403 on `/`" does NOT mean "health endpoint only" — test the prefix, not the path
*(Added 2026-10-01, from `tenant-cloud.svc.acme.example`.)*

A very common estate shape is: `GET /` → CDN 403, `GET /health` → 200, and the host gets triaged as
"health-only, nothing reachable". That triage is frequently wrong, because CDN path allowlists are
usually written as **prefix patterns**, and a prefix that is open exposes an entire origin.

The tell is *which component answers the 404*:

```
GET /            -> 403, ~919-byte CloudFront error page          (edge)
GET /api/v1      -> 404 page not found                            (Go net/http — the ORIGIN)
```

The moment a path returns an **application-shaped** 404 (Go's `404 page not found`, Express's
`{"message":"Not Found"}`, a framework JSON envelope) instead of the CDN's branded error page, the
whole prefix is forwarded and must be swept. Conversely if every probe returns the identical
919-byte CDN body, the allowlist is exact-match and no amount of wordlist will help.

Minimum triage per host — five requests, before deciding anything:

```bash
for p in / /health /api /api/v1 /zzqqnope; do
  printf "%-14s " "$p"
  curl -s -o /tmp/r -w "%{http_code}/%{size_download} " "https://$H$p"
  head -c 60 /tmp/r | tr -d '\n'; echo
done
# identical size on every 403  => exact-match allowlist, host is genuinely closed
# an app-shaped 404 anywhere   => that prefix is OPEN, sweep it (with a canary, see below)
```

**Why this matters more than it sounds:** an estate-wide sweep that probes a fixed path list
(`health healthz status version ping api api/v1 metrics`) and then reports "nothing beyond health
was reachable" can be a *triage* miss rather than a *probe* miss — the right path was requested, but
the app-404 was bucketed as "not 200, therefore nothing". Re-grade such sweeps on response **shape**
(who answered), not on status code alone.

**Always canary the sweep** ([[controls-and-oracles]] Case 1): fire one known-bad path immediately
before and immediately after. If the post-canary no longer matches the pre-canary, an edge rate rule
tripped mid-run and the entire result set is noise — discard it rather than cherry-picking rows.

### Exhausting the "no caller exists" question before calling a host closed
When a service has no reachable routes and no route names, the blocker is the *caller*, not the
edge. Mark the host closed only after all of these come back empty, and record which ones you ran:
JS/source-map mining of every SPA that plausibly talks to it; the **route-map object** in sibling
app bundles (one SPA often carries a literal `{serviceName:{base:…, paths:{…}}}` map for 20+
backend hosts — grep for the service name *inside that object*, not just in the file); the mobile
APK corpus; Burp proxy history; Wayback CDX; GitHub dorking. A device/service-to-service-only
backend is a legitimate, well-evidenced clean negative — but only with that list attached, and with
any source you could not run (no `gh` token, code-search behind a bot checkpoint) written down as
an acknowledged blind spot rather than quietly counted as clean.

---

## CT gives you the ORIGIN tier, not just the edge: the `internal-X` SAN convention

When an estate fronts ALBs with CloudFront/WAF, the ALB hostname is normally issued on the **same
ACM certificate** as the public name — so Certificate Transparency hands you the origin tier for
free. That matters because **if the authz is enforced at the edge, the origin is the bypass.**

```bash
curl -s 'https://crt.sh/?q=%25.svc.example.com&output=json' \
  | grep -o '"name_value":"[^"]*"' | sed 's/.*:"//;s/"$//' | sed 's/\\n/\n/g' \
  | tr 'A-Z' 'a-z' | sort -u > names.txt
wc -l names.txt
grep -E '^internal[-.]' names.txt          # the origin tier
grep -E '^\*\.'          names.txt         # per-tenant / per-version wildcards
```

Measured on `*.svc.acme.example` (600 unique names, 2026-10-14): a near-perfect 1:1 convention —
**every public `X.svc.acme.example` has a private SAN `internal-X.svc.acme.example` on the same certificate**,
sometimes with an extra `internal-apigateway-X.svc.*` tier in front of it. Examples harvested in one
request: `internal-protect.{,dev.,stg.}svc.acme.example`, `internal-relay.*`,
`internal-nca-uapi-device-pxy.*`, `internal-apigateway-msp-mgmt.*`,
`internal-cap-iot-{eu-central-1,us-west-2}.*`.

### How to use it

1. **Resolve them all.** A public A record on an `internal-*` name is a direct-to-origin path that
   skips the edge WAF, the signed-URL gate, and any Lambda@Edge authz. That is a finding shape in
   its own right, not just a recon note.
2. **Keep a known-resolving host in the same loop** so a `curl` `000` means NXDOMAIN and not a dead
   resolver — otherwise you will record "origin is private" when your DNS was simply broken
   (`controls-and-oracles.md`).
3. **The wildcards are the other half of the prize.** `*.relay.svc.acme.example`,
   `*.net-cloud.svc.acme.example`, `*.acme-surveil-ui.pkg.svc.acme.example` mean per-tenant or
   per-version labels exist. You cannot guess the label, but any API response or package manifest
   that discloses one turns the wildcard into a reachable host.
4. **The `internal-` list doubles as a service catalogue.** It names backends that have no public
   DNS and are therefore invisible to subdomain enumeration — exactly the hosts a leaked config,
   SSRF primitive, or CI secret would let you reach.

---

## Vendor firmware / package index — a listable software source, and a product inventory

Two uses, one request. For appliance and IoT vendors, check for a **public firmware distribution
API** early in recon — it is both an offline-source-review entry point *and* a complete product
inventory you did not have to enumerate.

```bash
# the vendor (verified 2026-10-14) - anonymous, no referer check, HAL+JSON, filter is eq~~<field>~~<value>
curl -sS 'https://fw-update.acme-legacy.example/api/firmware-latest?limit=50'                       # every product
curl -sS 'https://fw-update.acme-legacy.example/api/firmware?filter=eq~~product~~acme-protect&limit=500'
#  per build: version / platform / channel (release|beta-public) / created / file_size / md5 / sha256
#             _links.data.href -> fw-download.acme-legacy.example/data/<product>/<...>.deb|.bin
#             _links.changelog.href
```

Why it is recon and not just exploitation prep:

- **Product inventory.** The set of `product` values is the vendor's real internal component list,
  including components with no marketing presence (`ds`, `msf`, `msr`, `msp`, `mst`,
  `ai-feature-controller`, `protect-verify`, `acme-user-assets`). Each is a candidate attack surface
  name and a candidate subdomain/package-prefix word.
- **Channel disclosure.** `channel: beta-public` builds date pre-release features; diffing a beta
  against the current release is a cheap way to find a surface that is live in the cloud but not yet
  documented.
- **Version pinning for honest reporting.** Anti-false-positive rule: vendor source proves the code
  path, not production. The index's `version` + `sha256_checksum` are how you pin and state exactly
  which build you read.

Try the generic shapes on any appliance vendor: `fw-update.*`, `fw-download.*`, `dl.*`, `static.*`,
`download.*`, `packages.*`, `apt.*`, an `/api/firmware*` route, and the vendor's apt/yum repo paths.
An empty result for a *guessed* product name is not an absent index — confirm with a product name you
know exists before concluding anything.

Full extraction-and-reading workflow (including the `Depends:`-line trick that finds the component
you actually want, and the untrusted-archive handling rules):
`framework-misconfig.md` § "Vendor package index". Reading the resulting one-line megabundle:
`js-analysis.md` § "Reading a one-line multi-megabyte webpack bundle".

---

## TRAP — a 4-byte `200` on `/` means "API with no index route", NOT "dead host"

Discovered on `linkapp-be.acme.example` (the vendor r4, lane L2-ssrf, 2026-10-15). The host had been closed
**twice** in `coverage.md` as *"only /health, Flask, routes locked. dead."* — a conclusion reached by
requesting `/` and `/health`, seeing a 4-byte body, and guessing route names from the product name.

It was not dead. It was a live **unauthenticated** Flask API whose entire route table was sitting in
the Wayback CDX index the whole time: a terrain-elevation data plane
(`/api/v1/usgshgt/{path,extendedpath}/<lat,lng>/<lat,lng>/<int>`, 200 with 73–76 KB of USGS
elevations), public store pricing (`/api/v1/store/{listPrices,inventory}`), two multi-MB reference
datasets, plus an SSO-gated `links2/*` data plane and a user-bootstrap route.

**Why the mistake is structural, not careless:** an API-only backend has *no reason* to serve
anything at `/`. A tiny 200 at the root is the expected shape of a healthy API, so it reads as
"nothing here" to a probe that only looks at `/`. Route *guessing* then fails because real API
prefixes (`usgshgt`, `bwdistribute`, `towerleasing`, `links2`) are product-internal vocabulary no
wordlist contains.

**Rule: before recording any API host as dead/empty/locked, CDX it.** One request, no load on the
target, and it returns paths that no wordlist will ever produce:

```bash
# the single command that would have prevented two wrong closures
curl -s "http://web.archive.org/cdx/search/cdx?url=<HOST>/*&output=text&fl=original&collapse=urlkey&limit=3000"

# batch it across a shard, then mine the result for real prefixes and fetch-shaped params
for h in $(cat hosts.txt); do
  curl -s -m 45 "http://web.archive.org/cdx/search/cdx?url=${h}/*&output=text&fl=original&collapse=urlkey&limit=3000"
done | sort -u | tee way.txt
# real route prefixes (what a wordlist cannot give you)
sed -E 's#https?://[^/]+##' way.txt | awk -F/ '{print $2}' | sort | uniq -c | sort -rn | head -25
# fetch-shaped params for the SSRF pass
grep -oiE '[?&](url|uri|src|image|callback|webhook|redirect|target|host|domain|endpoint|feed|import|template|source|tile|proxy)=[^&]*' way.txt | sort -u
```

Corollary, same engagement: CDX on `link.acme.example` also surfaced
`/dynamic/media/radioIcon.svg?type=&color=&backgroundOpacity=` — an unauthenticated **server-side
SVG renderer on the app origin** that no crawl of the live SPA had found, because nothing in the
current bundle links it. Historical URLs are how you find *retired-but-still-routed* render and
fetch sinks, which are exactly the under-maintained ones.

**Pair it with the right control, though.** On that SVG renderer the params turned out to be
ignored entirely (`color=ZZPROBE1234` returned a response byte-identical to the real colour), so
CDX gives you *candidate* sinks, not confirmed ones. Always fire the reflection control before
building an injection matrix on a param you only know from history — and a positive control that
proves some *other* param on the same route does change the output, or you cannot tell "not
reflected" from "never arrived".


## Vhost fuzzing: it works on ALB, NOT on CloudFront (measured, the vendor r4 L25, 2026-10-17)

Sending a candidate hostname in the `Host` header to a known edge IP is the standard way to find
backends with **no public DNS record**. On an AWS estate the result depends entirely on which edge
type you hit, and getting it wrong wastes a whole lane.

| Target | Request shape | Result |
|---|---|---|
| CloudFront **IP** | `-H 'Host: zzz-random.acme.example'` to `https://<cf-ip>/` | **`status=000`** — TLS handshake fails outright; CloudFront requires SNI to match the distribution |
| CloudFront **hostname** | `-H 'Host: zzz-random.acme.example'` to `https://account.acme.example/` | **`421 Misdirected Request`** (1003 B) — connection succeeds, CloudFront rejects the host/SNI mismatch |
| **ALB**-fronted host | `-H 'Host: junk.svc.acme.example'` to `https://analytics-api.svc.acme.example/` | **`404`, 22 B** — arbitrary Host accepted and routed |

**Rules that follow:**

- **Do not vhost-fuzz CloudFront.** `000` and `421` are the edge refusing the mismatch, not a signal
  about the candidate hostname. Every row is noise.
- **Do vhost-fuzz the ALB tier.** It accepts an arbitrary Host header and answers, so a response
  differing from the 404 baseline is a real hit — and on an estate like this the ALB tier is exactly
  where the internal backends live (the `*.svc.*` and `internal-*` families).
- **Pick the edge type before building the wordlist.** `httpx -cdn`, or the response headers
  (`X-Amz-Cf-Id` / `Via: ... CloudFront` versus `Server: awselb`), tell you which you have.
- `421` is itself a useful fingerprint: it proves the host is CloudFront-fronted and strictly
  SNI-bound.

Related trap, same engagement: a 4-byte `200` on `/` is the normal shape of an API with no index
route, **not** a dead host. Check Wayback CDX before declaring absence — `linkapp-be.acme.example` was
wrongly closed as dead twice on exactly that basis, while its full route table sat in the CDX index.

### Authoring note (why this section exists twice over)
This lesson was first written with a shell heredoc whose quoting broke, so the markdown's backticked
values were **executed as commands** and their output — including a live CloudFront error page — was
appended into the doc. When adding a section containing backticks, code fences or `$`, write it with
a file-writing tool or a Python script, never an interpolating shell heredoc.

## Wildcard-DNS phantom hosts: canary at the SAME LABEL DEPTH before trusting a host list

A resolving name is not a host. If the apex is wildcarded, **every** label resolves, and a
subdomain list built from DNS (or from passive sources then "confirmed" by resolution) fills up
with phantoms that serve the edge's default behaviour.

Measured on `*.acme.example` (2026-10-28): `zzznope-orch-4471.acme.example`, `totally-made-up-9931.acme.example` and
`cdn.zzznope-orch-4471.acme.example` all returned HTTP 200 with the **byte-identical** 1634-byte SPA that
`account.acme.example` serves — same sha256. Two consequences bit real lanes:

- An orchestrator claim that three "forgotten" hostnames exposed the identity app was **retracted**:
  the wildcard serves that SPA for any name.
- A lane's 110-stem `cdn.<x>.acme.example` sweep produced ~40 "live" hits that were **all phantoms**.

**Always do this before trusting a DNS-derived list:**

```bash
# canary at EVERY label depth you intend to probe
for d in "zzznope-$RANDOM.$APEX" "cdn.zzznope-$RANDOM.$APEX" "zzznope-$RANDOM.svc.$APEX"; do
  printf '%-44s %s
' "$d" "$(getent hosts "$d" | head -1 || echo NXDOMAIN)"
done
# then fetch the canary and hash it; any "host" matching that hash is the wildcard default
curl -s "https://zzznope-$RANDOM.$APEX/" | sha256sum
```

Depth matters and is not uniform: on this estate `*.acme.example` **is** wildcarded while
`*.svc.acme.example` is **not** (`cdn.zzznope.svc.acme.example` -> NXDOMAIN), so only the deeper
`<x>.svc.acme.example` shape could be trusted from resolution alone.

Corollary for takeover hunting: a wildcard that points at the target's **own** live edge is not a
takeover condition — do not file it as a dangling CNAME.

