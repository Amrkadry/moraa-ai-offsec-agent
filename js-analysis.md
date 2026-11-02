# Moraa — Deep JavaScript Analysis (recon phase, high-yield)

> Load during recon on any JS-heavy app. **The frontend host is usually static; the real backend,
> full route list, secrets, feature flags, and client-side sinks all live in the bundle.** Mining JS
> is step 1 on every SPA. Feeds `framework-misconfig.md`, `ssrf.md`, `sqli.md`, `auth-oauth.md`.

## 1. Collect every script
```bash
# from live hosts
cat recon/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | grep -iE '\.js($|\?)' | anew recon/js.txt
echo T | gau --subs | grep -iE '\.js($|\?)' | anew recon/js.txt
# pull them all + any webpack chunks referenced inside
mkdir -p recon/jsdump; cd recon/jsdump
while read u; do curl -sk "$u" -o "$(echo "$u"|md5sum|cut -c1-12).js"; done < ../js.txt
# follow chunk maps: grep bundle for more chunk names (e.g. "static/chunks/xxxx.js", index-*.js)
grep -rhoE '[A-Za-z0-9_]+[-.][A-Za-z0-9_]{6,}\.js' . | sort -u   # fetch these too
```

**Huge single bundles (10 MB+): never pull them in one stream.** Origins behind nginx/CDN throttle
or RST a long-lived GET — you get a silently truncated file and then "grep found nothing" on routes
that really are there (seen on `connect.acme-nms.example`, 35.5 MB `index-*.js`: single stream stalled at
~11 MB and `--retry` restarted it at byte 0, leaving a truncated partial). Check
`accept-ranges: bytes` and pull it in parallel chunks instead:
```bash
U=https://host/assets/index-XXXX.js
TOT=$(curl -sI "$U" | tr -d '\r' | awk '/[Cc]ontent-[Ll]ength/{print $2}')
N=12; CH=$((TOT/N+1))
for i in $(seq 0 $((N-1))); do S=$((i*CH)); E=$((S+CH-1)); [ $E -ge $TOT ] && E=$((TOT-1))
  curl -s --retry 4 --retry-all-errors -r $S-$E -o p$(printf %02d $i) "$U" & done; wait
cat p?? > bundle.js; ls -l bundle.js   # size MUST equal $TOT before you trust any grep
```
Always assert the assembled size equals Content-Length — a short bundle is a false-negative factory.
On the 35.5 MB the NMS appliance bundle the partial yielded 74 routes; the complete file yielded **293**, and the
SSRF candidate (`v2.1/sites/nominatim/proxy?apiurl=`) only appeared in the full copy.

## 2. Secrets & keys (verify before reporting — many are public-by-design)
```bash
grep -rhoiE '(AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]+|sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{36}|glpat-[0-9A-Za-z_-]{20}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY|firebase[A-Za-z]*|mongodb(\+srv)?://|postgres://|mysql://)' recon/jsdump
# tools
trufflehog filesystem recon/jsdump --only-verified
# tell apart: pk_live/AIza(often restricted) = maybe low; sk_/private key/DB URI/session token = high.
```
Runtime config (the API base + client_id + Stripe/Maps keys):
```bash
grep -rhoiE '(REACT_APP_[A-Z_]+|VITE_[A-Z_]+|NG_[A-Z_]+|NEXT_PUBLIC_[A-Z_]+|__ENV__|window\.__CONFIG__)[^,}]{0,90}' recon/jsdump | sort -u
```

## 3. Endpoints, hosts, routes (the map)
```bash
# backend hosts + full API paths (feed to authz/IDOR/SSRF hunting)
grep -rhoiE 'https?://[a-z0-9.-]+\.[a-z]{2,}(:[0-9]+)?' recon/jsdump | sort -u > recon/js-hosts.txt
grep -rhoiE '"/(api|v[0-9]|rest|graphql|internal|admin|oauth|sso|auth|user|account)[A-Za-z0-9/_.$%{}:-]{1,70}' recon/jsdump | sort -u > recon/js-endpoints.txt
# SPA client-side routes (hidden admin views)
grep -rhoiE '(path|route):\s*["\x27][/A-Za-z0-9:_-]{2,50}' recon/jsdump | sort -u
# source maps → full original source (biggest win)
while read u; do curl -sko /dev/null -w "%{http_code} $u.map\n" "$u.map"; done < recon/js.txt   # 200 = jackpot
# reconstruct with:  npx source-map-explorer / shuffle: cat x.js.map | jq -r '.sourcesContent[]'
```
> Source-map exposure alone is a reportable info-disclosure (CWE-540) — and it hands you internal
> endpoint lists & auth logic (Fetch lesson: 163–253 internal endpoints from `*.js.map`).

**Axios/fetch-wrapper interceptors silently rewrite the path — grepped route strings under-count.**
Many SPAs create one axios instance with a request interceptor that auto-prepends a segment
(`config.url = '/ent/api' + config.url` unless a per-call flag opts out). A literal-string grep only
finds the *suffix* passed at the call site, not the effective URL the browser actually sends. Trace
the interceptor/base-config (`axios.create({baseURL: ...})`, `interceptors.request.use(...)`) before
concluding a route 404s — a route that looks dead under one prefix can be live under the interceptor's
real prefix (the vendor lesson: `/gw/ent/api/*` 404'd for weeks; the real, live prefix was `/ent/api/*`
with no `/gw`, only found by reading the interceptor, not the literal fetch-call strings).

## 4. Client-side sinks (DOM XSS, open redirect, prototype pollution)
```bash
# DOM XSS sinks — trace back to a source (location/hash/search/postMessage/name/referrer)
grep -rhnoiE '\.(innerHTML|outerHTML|insertAdjacentHTML)\s*=|document\.write|eval\(|setTimeout\(["\x27]|new Function\(|\$\(.*\)\.html\(|dangerouslySetInnerHTML|v-html|Element\.setAttribute\(["\x27]?(href|src)' recon/jsdump | head -50
# sources feeding them
grep -rhnoiE 'location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name|postMessage|URLSearchParams|params\.get\(' recon/jsdump | head -50
# open redirect sinks
grep -rhnoiE '(location\.(href|replace|assign)|window\.open)\s*[=(]' recon/jsdump | head
# postMessage handlers without origin check → cross-origin msg injection
grep -rhnoiE 'addEventListener\(["\x27]message["\x27]' recon/jsdump
```
Prototype pollution (client-side → DOM XSS / gadget):
```bash
# vulnerable merge/clone/set patterns + __proto__ handling
grep -rhnoiE '(merge|extend|deepmerge|deepClone|setValue|_\.set|assignIn|defaultsDeep)\(|__proto__|constructor\[|prototype\[' recon/jsdump | head
# test in URL/JSON:  ?__proto__[test]=1  ?constructor[prototype][test]=1  {"__proto__":{"polluted":1}}
# then look for a gadget (a lib reading an undefined config prop) → escalate to DOM XSS/RCE
```
Tools: `npx @dwisiswant0/linkfinder` / `SecretFinder` / `getjs` / `js-beautify` (deobfuscate first),
`DOM Invader` (Burp) for live sink tracing.

## 5. What to do with the loot
```
new host/route      → recon.md §2 (resolve/live) + authz/IDOR hunt (framework-misconfig §7)
API base + client_id→ auth-oauth.md (OAuth flow, redirect_uri) / JWT
secret/DB URI       → verify live → findings/ (or initial-access.md if it grants access)
DOM sink+source     → craft XSS PoC → validate.md
proto-pollution     → find gadget → DOM XSS/RCE PoC
```
Update `coverage.md` with every endpoint/host discovered so nothing gets lost.

---

## Grep EVERY chunk for the service constant — the first hit is usually the boring one

Cost of getting this wrong, measured: on `blobstore.svc.acme.example` (2026-09-29) the first bundle chunk
that matched the host string produced **two** routes and made the service look like a subscription
stub not worth a second hour. The complete route map — including a Protect **camera-archive
download** plane — sat in a different chunk of the same app that the first grep never opened.

Webpack/Next splits an app across dozens of `main~N.<hash>.js` chunks. The chunk that *calls* an API
and the chunk that *declares its route table* are frequently different files: route tables get
hoisted into a shared constants chunk, while the call sites land in the feature chunk. A single
`grep -l` stops at the first match and hands you the call site.

```bash
# WRONG - stops at one file, gives you the call site and nothing else
grep -rl 'storage\.svc\.ui\.com' js/

# RIGHT - every matching chunk, then pull the route table out of each
grep -rlI 'storage\.svc\.ui\.com' js/ | while read -r f; do
  echo "### $f"
  grep -oE '.{0,120}(https://[a-z0-9.-]+\.svc\.[a-z.]+)?/v[0-9]/[A-Za-z0-9:_/-]{4,}.{0,120}' "$f" | sort -u
done
```

Better: find the **minified variable** the base URL was assigned to, then chase that symbol. Route
tables are written as one object literal and fall out whole:

```bash
# 1. what symbol holds the base URL?
grep -oE '[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*"https://storage\.svc\.ui\.com"' js/*.js
#    -> rf="https://blobstore.svc.acme.example"

# 2. pull the object literal that uses it (route maps are long - take a wide window)
grep -roE '.{0,80}\{[a-zA-Z]+:\{hosts:.{0,1200}' js/
```

That second command is what recovered:

```
storage:{
  org:  {hosts:`${S}/v1/organizations/:orgScope/hosts`, …,
         protectArchiveDownload:`${S}/v1/organizations/:orgScope/hosts/:ncaHostId/protect/archive/download`},
  noorg:{hosts:`${S}/v1/users/self/hosts`, …,
         protectArchiveDownload:`${S}/v1/users/self/hosts/:ncaHostId/protect/archive/download`}
}
```

Two things to take from the shape of that object, both generalisable:

- **`:param` placeholders name the id type for you.** `:ncaHostId` told us the segment is a console
  id, not a UUID — worth knowing before you waste a sweep guessing formats.
- **Parallel scope trees (`org` vs `noorg`) are a standing authz question.** The same nine routes
  exist twice, under different scope prefixes, almost certainly behind different middleware. Always
  test both: the older/less-used tree is where the weaker check lives. Here a literal `self` was a
  valid scope under `/v1/users/` while `/v1/organizations/` demanded a real UUID — that asymmetry is
  exactly the kind of thing that hides a "current org" alias on a less careful service.

### Corollary — a route table beats a wordlist, every time

Bundle-derived routes cost one grep and zero requests. On this host, hand-picked route-name sweeps
plus a 4000-word ffuf run found **nine** routes and tripped the WAF; the bundle chunk gave
**eighteen**, including the only one that mattered, with no traffic at all. Mine the JS to
exhaustion before you fuzz — and treat a route your wordlist "discovered" that is absent from every
bundle as suspect until a cold single request confirms it.

---

## Reading a one-line multi-megabyte webpack bundle: extract modules by numeric id

**When:** you have a server-side or device-side bundle — no source map, no `sourceMappingURL`,
sometimes 9+ MB on a single line — and `grep -n` is useless because everything is line 1. This is the
normal shape of a bundled Node service shipped inside an appliance package (see
`framework-misconfig.md` § "Vendor package index").

Webpack emits numeric-id modules as `NNNNNN(e,t,r){...}`, and inside each module every
`require()` is a call to `r(NNNNNN)`. That makes the bundle a **navigable call graph by integer**,
which is almost as good as a source map:

1. Grep for the route/host/string you care about to find the *entry* module.
2. Read its `const o=r(248543), i=r(995663), ...` header — those integers are its imports.
3. Pull each import by id. Two or three hops reach the thing you actually want.

In the vendor evidence-registry case the chain was four hops and ended on the answer:
`uploadEvidenceManifestV2` -> `retryRegistryRequestWithAuth` (`741576`) -> `resolveRegistryAuth`
(`9395`) -> `HeaderNames` (`816116` -> `49621`), where `49621` is a flat enum of **every custom
header the product uses** — the device-plane auth scheme, plus six more header names worth sweeping
the rest of the estate for.

### The two scripts (keep them OUTSIDE the extracted tree; run with `python3 -I`)

`ctx.py` — regex hit with byte context, for finding entry points:

```python
import sys, re
path, pat = sys.argv[1], sys.argv[2]
before, after = int(sys.argv[3]), int(sys.argv[4])
limit = int(sys.argv[5]) if len(sys.argv) > 5 else 10
s = open(path, encoding="utf-8", errors="replace").read()
hits = [m.start() for m in re.finditer(pat, s)]
print("HITS:", len(hits), file=sys.stderr)
for i, h in enumerate(hits[:limit]):
    print("\n########## HIT %d @ %d ##########" % (i, h))
    print(s[max(0, h - before):h + after])
```

`mod.py` — extract one module whole, by brace matching that is **quote-aware** (naive brace counting
breaks on `{` inside strings and template literals, which these bundles are full of):

```python
import sys, re
path = sys.argv[1]
s = open(path, encoding="utf-8", errors="replace").read()
for mid in sys.argv[2:]:
    m = re.search(r"(?:^|[,{])" + re.escape(mid) + r"(?:e\d+)?\(e,t,r\)\{", s) \
        or re.search(r"(?:^|[,{])" + re.escape(mid) + r"\(e,t\)\{", s)
    if not m:
        print("### MODULE %s NOT FOUND" % mid); continue
    start = i = m.end() - 1
    depth = 0
    while i < len(s):
        c = s[i]
        if c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: break
        elif c in "\"'`":                      # skip string/template bodies entirely
            q = c; i += 1
            while i < len(s):
                if s[i] == "\\": i += 2; continue
                if s[i] == q: break
                i += 1
        i += 1
    print("\n####### MODULE %s (%d bytes) #######" % (mid, i - start))
    print(s[start:i + 1])
```

```bash
python3 -I tools/ctx.py x/usr/share/app/service.js 'api/v2/<route>' 1500 1500 6
python3 -I tools/mod.py x/usr/share/app/service.js 741576 9395 49621
```

### Gotchas that cost time

- **Module-id forms vary:** `NNNNNN(e,t,r){`, `NNNNNN(e,t){` (no `require`), and the webpack
  shorthand `559e3(` / `NNNNe3(` for ids ending in zeros. Handle the `e\d+` form or you will "not
  find" a module that is right there.
- **A module id that will not match is often a node builtin shim:** `e.exports=require("node:events")`.
  Resolve such ids by grepping their *call sites* and reading which functions are destructured off
  them — `randomUUID` + `randomBytes` + `createHash` + `createPrivateKey` identifies `node:crypto`
  with certainty, which is exactly what settles an "is this id guessable?" question.
- **Search for the *generator*, not the field name.** `grep 'exportId'` returns dozens of plumbing
  sites; `grep 'exportId:'` plus reading each hit found the single minting line
  `` const h = `exp_${randomUUID().replaceAll("-","")}` `` — 122 bits, which killed a would-be
  High-severity enumeration lead.
- **Check for a decoy generator in the same bundle.** The same Protect bundle ships a timestamp-
  prefixed `uuidv7` helper (`randomBytes(16)` with the first 6 bytes overwritten by `Date.now()`)
  that *is* partially predictable — used elsewhere, not for the id under test. Assuming either answer
  without reading the actual call site would have been wrong in one direction or the other.
- **Client-side echo checks are not server-side enforcement.** These bundles are full of
  `if (resp.signerId !== mine) throw ...`. That tells you what the *client* expects; it tells you
  nothing about whether the server binds the field. Record it as the question to test, not as a
  negative.

---

## Trap: a bare `curl` gets 403 and you conclude "no source maps" (acme.example pro/customer, 2026-10-15)

Two acme.example SPAs had been bundle-mined by earlier passes and recorded as minified-only. They ship
**genuine 8.6–8.8 MB source maps**. The reason nobody saw them: the CDN 403s a default `curl`
User-Agent.

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://console.acme.example/        # 403 118
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36'
curl -s -A "$UA" https://console.acme.example/ | grep -o '/static/js/main\.[a-f0-9]*\.js'      # 200, real index
curl -s -A "$UA" https://console.acme.example/static/js/main.<hash>.js.map | head -c 80
# {"version":3,"file":"static/js/main.<hash>.js","mappings":";0FAAIA,...
```

**Always send a browser UA before declaring a JS/map surface absent**, and re-check hosts already
recorded as "no source maps" if the recorded evidence was a bare-curl 403 or 404 rather than a body.
A 118-byte 403 is a UA gate, not an absence.

Verification still applies (the SPA-index false positive): require `"version":3`, real `mappings`,
populated `sourcesContent`, and a size wildly larger than the index (8.8 MB vs 920 B here).

Extractor (writes every original file to disk; run it from a directory that is **not** the extract
target, and treat the output as untrusted data — read it, never execute it):

```python
import json, os
m = json.load(open("main.<hash>.js.map"))
for s, c in zip(m["sources"], m.get("sourcesContent") or []):
    if c is None: continue
    p = os.path.join("out", s.replace("webpack://", "").lstrip("./").replace("..", "_"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(c)
```

What it bought on this target, beyond the route list: request DTOs as TypeScript interfaces (which is
what makes a 400 interpretable — see `parameter-deep-dive.md` § NestJS pipes), the role matrix, and
the **socket.io channel naming** that opened an entire previously unmapped surface
(`websocket.md` § socket.io on a REST host).

---

## Lazy-chunk source maps — the admin plane is usually NOT in `main.js.map`

**Proven on `console.acme.example` / `customer.acme.example` (the vendor, 2026-10-15): three prior passes extracted the
main source map and concluded the surface was mapped. The main map held 369 app files and ZERO of the
admin pages.** CRA/webpack (and Vite) split every `React.lazy(() => import(...))` into its own chunk,
and `index.html` references only `main.*.js`. The chunk maps are still on the server — you just have
to derive their names.

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
# 1. main bundle (NOTE: a bare curl gets 403/118 B on CloudFront-fronted hosts — browser UA is mandatory)
curl -s -A "$UA" https://target/static/js/main.<hash>.js -o main.js
# 2. the webpack runtime carries a chunkId -> contenthash table and the filename template
grep -oE 'static/js/"\+e\+"[^;]{0,160}' main.js
grep -oE '\{[0-9]+:"[a-f0-9]{8}"(,[0-9]+:"[a-f0-9]{8}")*\}' main.js
#    -> {352:"48baf45b",438:"4961d3e5",...}   and   static/js/"+e+"."+{...}[e]+".chunk.js"
#    single-hash variant (all chunks share one hash):  static/js/"+e+".ae8a7283.chunk.js"
#    chunk ids actually loaded:  grep -oE '\.e\([0-9]{2,4}\)' main.js | sort -u
# 3. fetch every chunk's map
curl -s -A "$UA" "https://target/static/js/352.48baf45b.chunk.js.map" -o 352.map
```

Then extract as usual, skipping `node_modules` and any `sourcesContent[i] === null`:

```python
import json, os, re
m = json.load(open("352.map"))
for s, c in zip(m["sources"], m.get("sourcesContent") or []):
    if c is None or "node_modules" in s: continue
    p = re.sub(r"^(\.\./)+", "", s)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True); open(p, "w", encoding="utf-8").write(c)
```

**Why it pays:** lazy chunks are exactly the routes the app loads *after* a privilege check, so they
are where the admin plane, the role table and the staff-only tooling live. On the vendor run the 10
recovered chunk maps yielded 174 new files containing `pages/useRoutes.tsx` (the authoritative
role->route table), `app/admin/index.tsx` (four undocumented SysAdmin routes + five whole-platform CSV
exports) and the SysAdmin-only payments plane — none of it in the main map.

**Corollary for triage:** "we already mined the source map for this host" is not coverage unless the
chunk maps were enumerated too. Check `sources` for `/pages/` or `/admin/`; if the app clearly has
routes those files would implement and they are missing, the chunks are unfetched.

## Case — Vite/rolldown `__vite__mapDeps`: the whole SPA in one pull (a subscription-billing SaaS dashboard)

apps that ship a rolldown/Vite build register their **entire chunk map inline** in the entry
bundle as `__vite__mapDeps` (an array of `assets/<name>-<hash>.js`). One grep of `index-*.js`
gave all 239 chunks; one parallel `xargs -P 12 curl` pull = 4.2 MB = the full authenticated-app
source with zero crawling and zero auth. From there `scripts/rc_mine_routes.py` (route/page/keyword
extraction) + `scripts/rc_extract_mutations.py` (nearest-`url:` before each `` method:`VERB` ``
marker — RTK-query style, where the url is `$(...)` not a literal, so pair-extraction regexes that
demand ``url:`...`,method:`` adjacent miss everything) produced 129 API routes + 113 mutations in
minutes: `rc_capital` fintech plane (plaid/airwallex/increase/withdrawal), org SSO plane,
`sensitive_data_access` step-up, webhook config, documents download-by-id — the full backend
surface before a single authenticated request was sent.

```bash
grep -oE "assets/[A-Za-z0-9_.-]+\.js" bundles/index.js | sort -u > chunklist.txt
xargs -a chunklist.txt -P 12 -I{} sh -c 'curl -sf -m 40 -o "chunks/$(basename {})" "https://host/{}"'
cat chunks/*.js > all.js   # then rc_mine_routes.py / rc_extract_mutations.py
```

**Tells worth grepping once you have `all.js`:** `invalidatesTags` right after a mutation names the
cache slice the SPA *assumes* the server re-serves — i.e. the real gated data endpoint to probe
directly (the SaaS platform `sensitiveDataAccessUnlock` → `invalidatesTags:[ProjectApp]` → keys endpoint =
`/internal/v1/developers/me/projects/{id}/api_keys`); `feature_flags` dicts in `/me` responses name
the flag-gated planes (`ORGANIZATIONS_BY_DEVELOPER_ID=false` told us the whole org/SSO plane would
403 before we touched it); `dangerouslySnakeCaseRequest:!0` marks the RTK clients whose error
bodies are Pydantic-shaped. Engagement: `engagements/<target>/`.
