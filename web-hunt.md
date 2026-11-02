# Moraa — Web Vulnerability Hunting (router + high-yield core)

> This is the orchestration layer. For full depth on any class, the encyclopedias are on disk:
> `knowledge/bug-bounty/SKILL.md` (bypass tables, A→B chains, all classes) and the per-class
> `offensive-*.md` (offensive-idor, -ssrf, -ssti, -jwt, -xss, -xxe, -graphql, -oauth,
> -request-smuggling, -business-logic, -race-condition, -open-redirect, -parameter-pollution,
> -waf-bypass). Load the one you're hunting.
>
> **In-skill focused docs (load directly):** `ssrf.md` (cloud-native SSRF), `framework-misconfig.md`
> (Next.js/SvelteKit/SPA/API-gw + authz methodology), `websocket.md` (CSWSH/WS-IDOR),
> `cloud.md` (multi-cloud post-cred). Second per-class deep-dive library (cain-agent, Apache-2.0):
> `knowledge/*/skills/web/{sqli,xss,ssrf,ssti,xxe,csrf,open-redirect,path-traversal,file-inclusion,
> file-upload,command-injection,deserialization,info-disclosure}/` if synced locally.

---

## Mindset (top 1%)

- Crown-jewel first: "if auth broke here, what's the worst an attacker does?" If nothing
  valuable → skip the target.
- Hunt the **feature**, not the endpoint. Test interactions between endpoints.
- New == unreviewed. Mobile/legacy API == lower maturity, different surface.
- Authorization inconsistency is the bug: checked in 9 places, missed in the 10th.
- A→B cluster: find bug A, hunt B and C nearby. Chains pay 3-10x.
- **Parallel runs claim before they hunt.** Two agents or shards on one engagement coordinate
  through `.claims/` lease files per `work-claims.md` — an ACTIVE, unexpired claim on a host means
  it is another run's; pick the next queue entry instead of waiting. Never Edit `coverage.md`
  mid-file while any claim is ACTIVE (append only).
- **Dev mirrors prod — test both, every time.** When a `dev.`/`stg.` host shares a backend with a
  prod host (same GraphQL schema, same API), don't stop at whichever one you found first:
  (1) a schema/field/route leaked via a weaker dev-tier control (introspection on, verbose errors,
  no WAF) is directly reusable against prod — disabling introspection doesn't block *calling* a
  field you already know the name of, it only hides discovery; (2) prod and dev are not always
  the same *data* even on the same code — verify separately, don't assume dev is a data mirror;
  (3) session tokens/cookies from one environment sometimes work on the other (test it, don't
  assume either way). the vendor lesson: `community.dev.svc.acme.example` had introspection on, leaked the
  `searchUsers` field name; that field, called directly (no introspection needed) against
  `community.svc.acme.example` (prod), returned real production users at full-userbase scale, unauth,
  zero rate limit — the prod-side bug was invisible until the dev leak handed over the schema.

## Route by class

| Hunting… | Core test | Deep ref |
|---|---|---|
| **ANY parameter you just found** — do this BY DEFAULT before picking a single class | build a baseline oracle, then run the full 20-class matrix on that one parameter (IDOR · type-confusion · SQLi · NoSQLi · SSTI · CMDi · traversal/LFI · SSRF · XXE · XSS · CRLF · LDAP/XPath · proto-pollution · open-redirect · business-logic · mass-assign · DoS/ReDoS · encoding · HPP); flip every client-supplied boolean flag | **`parameter-deep-dive.md`** |
| **IDOR / access control** | 2 accounts, replay A's reqs with B's session; swap IDs in path/body/GraphQL/batch; GET→PUT/DELETE; v1 vs v2; mass-assign; 400-vs-403 trap; **no 2nd account? check for an auto-provisioned anonymous/temp identity — an unauth `GET /user/me` that returns 200 often IS identity B** | **`idor-access-control.md`** (+offensive-idor) |
| **Multi-tenancy / tenant isolation** | tenant-id positions (path/subdomain/header/JWT claim/body), the 4-cell cross-tenant matrix, shared-resource leakage (search/export/cache/storage/audit), invitation-flow escape, sign-up-your-own-tenant second identity | **`multi-tenancy.md`** |
| **CORS (credentialed)** | reflect attacker `Origin` + `ACAC:true` → read own authed data cross-origin; bypass table; same-site escape; CSRF-token→ATO chain; fleet check | **`cors.md`** |
| **Signed-URL / signed-cookie mints** (`*/cf_cookie`, `*/presign`, `*/signed_url`, `*/sas`, `*/upload_link`) | the MINT is an authz decision and is routinely ungated while its sibling data route is gated: low-priv mint -> decode policy -> caller-scoped or tenant-wide? -> is the scope segment built from a client param with no ACL (`md5(site_id)`)? -> replay with NO session (unbound bearer?) -> does a sibling service gate its mint (proves the control exists); beware the SPA-`index.html` fallback that destroys the signed-vs-unsigned oracle | **`signed-url-mints.md`** |
| **Server-signed response bodies** (response carries `X-*-Sig`/`X-*-Key-Id`, client pins a root key) | the body echoes your path/query param back INSIDE the signed bytes = a chosen-plaintext signing oracle: try duplicate-key injection (`a","status":"found","x":"`) because `JSON.parse` keeps the LAST duplicate key, so a raw interpolation forges a validly SIGNED authoritative verdict; fire the positive control (`a%22b` -> is the quote `\"`-escaped?) FIRST, then check request-binding, client-side expiry enforcement (revocation bypass) and whether verification uses the registry's key or the attacker's own file's key | **`signed-url-mints.md`** |
| **Pre-prod / dev-stg sibling of a production app** (`X.dev.svc.*`, `X.stg.svc.*`, `app.dev.*`) | read the CloudFront SPLIT-distribution fingerprint before investing: 146 B `MissingKey` = fell through to the default `/*` private behaviour (no app route here) / **919 B `Request blocked.` = the app behaviour MATCHED and AWS WAF then blocked it, which PROVES the route exists and is deliberately fenced** / app JSON = origin reached. Then: normalisation+encoding matrix with PRODUCTION as the mandatory decode control (a row only counts if prd shows the edge normalised it and still reached the origin), the 11-header AWS-WAF `ForwardedIPConfig` viewer-IP-spoof battery, method substitution, and going AROUND the edge via the CT-disclosed `internal-X.svc` ALB SAN. Case-shifting the path (`/API/...`) dodges the WAF AND the behaviour — that is not a bypass. **And before any of it: prove a shipped CLIENT can be pointed at the pre-prod backend at all** (`controls-and-oracles.md` Case 12) | **`bypass-4xx.md`** § split-distribution fingerprint |
| **A pinned trust root / env map with a `null` or empty entry** (crypto verifier, signed-response client, cert-pinning SPA) | it reads like "verification disabled in that env" and is almost always the OPPOSITE: the resolver does `if(!root) throw` and the env yields *cannot verify*. Read the CONSUMER, not the table — same discipline as `auth:false` being a lead not a finding. Then prove whether the alternate env is reachable at all: a Vite/webpack build INLINES the env string, so grep for `import.meta`/`searchParams`/`location.search`/`localStorage`/`sessionStorage`/`window.__` — all zero means no query param, cookie or global repoints the production client | **`controls-and-oracles.md`** § Case 12 |
| **S3/CDN origin that refuses listing** (`403 AccessDenied` on `/` and on `?list-type=2`) | it is still a **key-existence oracle**: no `s3:ListBucket` means `403 AccessDenied` for absent keys and `200` (often 0 B folder marker) for present ones. Fire a deliberately absent sibling prefix as the control in the same loop. Grade honestly — enumerating PRODUCT names is Low/Info, enumerating PER-TENANT prefixes is a customer enumerator. Its best use is usually as an UNBLOCKER: a confirmed package prefix + one version string = an anonymously downloadable build to read offline | **`controls-and-oracles.md`** § Case 13 |
| **Device-plane / machine-to-machine API you cannot authenticate to** (`400 missing device ID or device auth`-class gates on `*.svc.*` hosts) | two moves, in this order. (1) **Read the error string as a specification**: an error naming N credentials is an N-ary AND, so probe the *combination*, never the singletons — a 24-name battery sent one header at a time returns the baseline error 24 times and reads as a clean negative (`controls-and-oracles.md` Case 14). (2) **Get the device-side code instead of guessing**: the vendor's firmware/package index is usually anonymous and listable, and the shipped bundle carries a flat `HeaderNames` enum that hands you the entire custom-header vocabulary plus the credential's origin | **`controls-and-oracles.md`** § Case 14 + **`framework-misconfig.md`** § "Vendor package index" |
| **SSRF** | metadata `169.254.169.254`, internal ports, IP-bypass table, `file://gopher://`, blind via interactsh, cert-CN/error oracles | **`ssrf.md`** (+offensive-ssrf) |
| **DNS rebinding** (the filter resolves-then-checks) | two-answer attacker DNS, TOCTOU between validate-resolve and fetch-resolve, pooling/pinning defeats it, prove the re-resolve with controlled records | **`dns-rebinding.md`** |
| **Webhooks** (inbound receiver / outbound sender) | signature missing/weak/alg-confusion/wrong-bytes, replay window, forged provider events → state change; outbound URL → SSRF/secret-leak/redirect; no-route-oracle ceiling → recover path provider-side | **`webhooks-security.md`** |
| **Modern SPA / API-gw misconfig** | source maps, Next.js `x-middleware-subrequest` auth bypass + `_next/data`, SvelteKit `__data.json`, actuator/heapdump, CORS, identity-header spoof, authz status-code methodology, **SPA custom header as a credential component (`X-App-Build`-class false 401s)**, error-message-dialect gate mapping | **`framework-misconfig.md`** |
| **XSS** | context detection, DOM sinks, filter/CSP bypass, blind XSS in admin views, chain into CORS-trusted origin | **`xss.md`** (+offensive-xss) |
| **CSRF** | SameSite interplay, token-validation flaws (removal/empty/method-swap/content-type), auto-submit PoC, CORS-leaks-token→ATO | **`csrf.md`** |
| **Clickjacking / postMessage** | X-Frame-Options/CSP frame-ancestors check + overlay PoC; `addEventListener('message')` missing/weak origin check | **`clickjacking.md`**, **`postmessage.md`** |
| **Password-reset flow** | token entropy/predictability, host-header poisoning, race on verify, IDOR via user-id in reset body | **`auth-oauth.md`** § Password reset |
| **Host header injection** | reset-link poisoning, `X-Forwarded-Host`/absolute-URI override, cache poisoning, virtual-host confusion → SSRF | **`host-header.md`** |
| **HTML injection / dangling markup** | unclosed tag exfil when `<script>`/`on*` stripped but raw HTML isn't; steal CSRF token/next content | **`xss.md`** § HTML injection |
| **gRPC** | reflection enum (grpcurl), proto-file mining, per-RPC authz gap (REST pattern in a new transport), metadata-header auth bypass | **`graphql.md`** § gRPC |
| **Shadow / zombie API** | mobile-app-only endpoints, deprecated-but-live v1, staging routes reachable from prod DNS, JS-bundle-referenced-but-unlinked routes | **`shadow-api.md`** |
| **Edge route-allowlist mapping** | host 403s on `/` but an app-shaped 404 leaks from some prefix; the `awselb/2.0` 403-vs-app-404 oracle reads the edge's own listener rules; exact-match vs wildcard rule shapes; decode control is per-distribution | **`shadow-api.md`** (ALB oracle) + `recon.md` (prefix triage) + `bypass-4xx.md` (decode control) |
| **CI/CD pipeline** | exposed Jenkins/GitLab-CI/Actions runners, `.git`/`.env`/Terraform-state leak, self-hosted-runner → cloud OIDC pivot | **`cicd-attack.md`** |
| **Kubernetes** | exposed kubelet (10250)/etcd (2379)/dashboard/API-server, anonymous-auth, SA-token theft → cloud IAM pivot | **`k8s.md`** |
| **SSTI** | `{{7*7}}`/`${7*7}`/`<%=7*7%>` in name/bio/email/PDF/error → engine RCE | **`ssti.md`** |
| **2FA/MFA bypass** | skip-step, OTP reuse/brute, race on verify, backup-code IDOR, per-field step-up gaps | **`2fa-bypass.md`** |
| **SAML SSO** | XML signature wrapping (XSW), signature stripping, self-signed cert swap, NameID comment injection, federation confusion | **`auth-oauth.md`** § SAML SSO attacks |
| **Rate-limit bypass** | IP-spoof headers, param jitter, race, resend-resets-counter, endpoint/version switch | **`rate-limit-bypass.md`** |
| **Network egress filter in the way** | target unreachable from your vantage point, or the client claims "we block X" — characterise the block layer (DNS/IP/TLS-SNI/Host/explicit-proxy) before tunnelling; blocklist-edge siblings (API/CDN/`m.`/IPv6/port-80) usually pass; also the C2/exfil channel-selection pivot | **`egress-filter-bypass.md`** |
| **Identity handle reuse** | does the IdP release a handle on rename/delete; does the downstream app key the local account on handle/email rather than the immutable `sub` (rename your own handle and re-login — new empty account = vulnerable shape); two-account canary proof | **`identity-handle-reuse.md`** |
| **User enumeration** | body/status/redirect/timing-distribution/rate-limit oracles across login/reset/signup/OAuth-linking/SSO-discovery; controls that prove the oracle is real; chained to lockout/reset flaws = the real finding | **`user-enumeration.md`** |
| **ReDoS** | catastrophic backtracking regex, blind timing probe, header/input parsers | **`redos.md`** |
| **JWT** | `alg:none`, RS256→HS256 confusion, weak secret, `kid` injection, `jku/jwk`, exp/claim tamper, per-service inconsistency, logout non-revoke | **`jwt.md`** (+offensive-jwt) |
| **Session management** | fixation (id rotates on login/step-up?), logout non-invalidation, **sessions surviving password/email/2FA change**, puzzling/overloading, concurrency, timeouts, cookie scoping, entropy | **`session-management.md`** |
| **Auth / OAuth / ATO** | reset poisoning, OAuth redirect_uri/state, JWT, MFA/2FA bypass, signup/login flows, step-up gaps | **`auth-oauth.md`** |
| **GraphQL** | introspection → node() authz bypass, batching brute, mutation IDOR | **`graphql.md`** |
| **Business logic** | negative qty, price tamper, currency confusion, workflow skip, coupon stack/reuse, race; client-check-not-a-control | **`business-logic.md`** (+offensive-business-logic) |
| **Race condition** | single-packet / Turbo Intruder on coupon/transfer/OTP/limits | **`race-condition.md`** |
| **SQLi** | error/union/boolean/time; sqlmap; WAF bypass; ORM sinks | **`sqli.md`** |
| **NoSQLi / LDAP / XPath injection** | operator injection (`$ne`/`$regex`), LDAP filter break (`*)(uid=*`), XPath `' or '1'='1` | **`nosql-ldap-xpath-injection.md`** |
| **XXE** | file-read, blind OOB via external DTD, error-based (local-DTD trick), SVG/DOCX upload, SOAP, XXE→SSRF/RCE | **`xxe.md`** (+offensive-xxe) |
| **Prototype pollution** | `__proto__`/`constructor.prototype` injection → template-engine RCE, authz-check bypass, DOM-XSS gadget | **`prototype-pollution.md`** |
| **CSS injection** | attribute-selector token exfil (no JS, survives CSP), opacity clickjacking PoC, `@import` takeover, font char-oracle | **`xss.md`** § CSS injection |
| **Padding oracle / crypto misuse** | CBC 1-byte-flip triangulation, PadBuster decrypt/forge, `__VIEWSTATE`→ysoserial.net RCE, ECB/static-IV, base64-as-encryption | **`crypto-padding-oracle.md`** |
| **LFI / path traversal** | traversal+encoding bypass, PHP wrappers (`php://filter`,`data://`,`expect://`), log/session poisoning→RCE | **`lfi.md`** |
| **Command injection** | separators, blind time/OOB confirm, WAF bypass (`${IFS}`,brace-expand,base64), argument injection | **`command-injection.md`** |
| **File upload** | web shell, double ext, magic bytes, .htaccess, SVG XSS, parser SSRF/XXE, zip-slip | **`file-upload.md`** |
| **Request smuggling** | CL.TE / TE.CL / H2.* desync (Burp smuggler) | **`request-smuggling.md`** |
| **Open redirect** | as OAuth/token-theft/SSRF chain | **`open-redirect.md`** |
| **Deserialization** | Java/PHP/.NET/pickle/Ruby/Node/YAML → RCE | **`deserialization.md`** |
| **Parameter pollution / mass-assign** | dup params, autobind privileged fields, type confusion | **`parameter-deep-dive.md`** § HPP |
| **Mass assignment / auto-binding** (BOPLA write half) | find the hidden fields (GET-vs-PUT key diff, JS bundle/source map, OpenAPI `readOnly`, GraphQL input types, Arjun/x8), inject role/ownerId/price/status, then PROVE it: read back via a separate GET in a second session with a negative-control canary — every major stack silently drops unknown fields and still returns 200 | **`mass-assignment.md`** |
| **RCE (any route)** | cmd inj, SSTI, deser, upload, SQLi, SSRF, n-day, LFI | **`rce-scenarios.md`** |
| **RCE → foothold** (the web finding becomes a shell) | primitive→shell routes (cmdi/upload/deser/SSRF), webshell placement+cleanup, reverse vs bind vs forward, first-10-minutes recon, credential reuse into the internal estate | **`initial-access.md`** |
| **Shell one-liners / TTY upgrade / payload encoding** | reverse shell per language/platform, pty upgrade (`stty raw -echo`), listeners (nc/rlwrap/socat/pwncat), base64/URL/-enc past filters, firewall-aware port choice | **`payloads/reverse-shells.md`** |
| **CMS (WordPress/Joomla/Drupal)** | vuln plugins/components, user enum, config leak, xmlrpc | **`cms-wordpress-joomla.md`** |
| **Moodle / LMS** (`MoodleSession`, `M.cfg`) | unauth config dump, exact-version hash-pinning vs git tags, free plugin inventory, enrolment gate, **`auth_oauth2` identity-mapping ATO** | **`cms-moodle.md`** |
| **403/401/400 or WAF in the way** | path/header/method normalization, edge-vs-app | **`bypass-4xx.md`** |
| **Deep JS recon** | secrets, endpoints, source maps, DOM sinks, prototype pollution | **`js-analysis.md`** |
| **One-line multi-MB bundle, no source map** (bundled Node service inside an appliance package) | webpack numeric-id modules make it a call graph by integer: grep for the route to find the entry module, read its `r(NNNNNN)` imports, hop two or three times. Extract modules with a **quote-aware** brace matcher (naive counting dies on `{` inside template literals). Search for the **generator**, not the field name — and check for a decoy generator (a `uuidv7` helper next to the `randomUUID` you assumed) before rating an id guessable | **`js-analysis.md`** § "one-line multi-megabyte bundle" |
| **Fuzzing behind a CDN/WAF** | rate-rule trips mid-run and every path returns the edge 403 -> ffuf scores it as a hit; canary control + `-fs` the edge body | **`bypass-4xx.md`** § canary control |
| **ANY oracle you're about to trust** (fuzz result, S3 403, OOB poll negative, CT name, `-o` output file) | fire the control that MUST read the opposite way FIRST — WAF-poisoned fuzz, stale `curl -o` files, S3 AccessDenied-on-missing, unpollable OOB payloads, CT `n`-prefix artifacts + wildcard-DNS fake confirmation, **a 429 whose body is a few bytes off your `-fs` baseline reporting as thousands of hits** | **`controls-and-oracles.md`** |
| **"We already mined the source map"** (CRA/Vite SPA, admin plane missing from the map) | `main.js.map` is only the EAGER bundle; every `React.lazy` route is a separate chunk whose `.map` is still on the server. Derive the names from the chunkId->hash table in `main.js`, fetch each `.chunk.js.map` with a browser UA. This is where the role table and the staff/admin routes live | **`js-analysis.md`** § lazy-chunk source maps |
| **SPA route table hiding in a second chunk** | the chunk that CALLS an API and the one DECLARING its route map are different files; `:param` names, parallel org-vs-user scope trees | **`js-analysis.md`** § grep every chunk |
| **Sibling service hosts** (`webhooks.<svc>`, `.stg/.dev`, internal `*-service` names) | CT-mine the service name; webhook receivers auth by signature not session -> forged billing state | **`recon.md`** § CT-mine the SERVICE name |
| **WebSocket** (chat/live/agent/GraphQL-subs) | CSWSH (foreign Origin + cookie), per-message IDOR, message-field injection, graphql-ws authz | **`websocket.md`** |
| **Cloud creds / cloud infra** | metadata→creds, IAM/RAM privesc, public buckets, secrets | **`cloud.md`** |
| **AWS deep-dive** | full shadow-admin table, Lambda/EKS/ECS/Cognito/API-Gateway/SNS/SQS chains, IMDSv2 IPv6 bypass | **`cloud-aws.md`** |
| **Supply-chain / artifact integrity** | firmware plaintext-HTTP/no-HSTS/no-sig, redirect downgrade, package-repo/Artifactory, dependency confusion, CI token theft | **`supply-chain.md`** |
| **LLM/AI feature** | prompt injection, chat IDOR, indirect injection, tool-misuse (ASI01-10) | offensive-ai-security |
| **AI red teaming** | indirect injection, Unicode-Tags invisible payloads, markdown-image/invisible-char exfil, memory implants, agent tool abuse | **`ai-redteam.md`** |
| **Signed/anti-bot request blocks replay** | `sign`/`nonce`/`X-Sensor-Data`, 401/403 on Repeater replay of a client-computed field | **`request-signing.md`** |
| **Mobile app target** | Android/iOS runtime-first proxy/replay, static secrets/endpoints, SSL-pinning bypass, deeplink/WebView-bridge injection, signer recovery | **`mobile-pentest.md`** |
| **Subdomain takeover** | dangling CNAME/NS, fingerprint DB, confirm-before-claim | **`subdomain-takeover.md`** |
| **Supabase / PostgREST / BaaS** | anon/service_role JWT, RLS read/write bypass, record forgery | **`supabase-baas.md`** |
| **Okta IdP** (red-team/internal) | tenant discovery, factor enum, ROPC spray discipline, OIDC redirect_uri, SAML SP check | **`okta-attack.md`** |
| **M365 / Entra ID** (red-team/internal) | AADSTS reference, Smart Lockout math, OneDrive enum, CA bypass options | **`m365-entra-attack.md`** |
| **VMware vCenter/Workspace ONE** (external-exposed) | version fingerprint, pre-auth RCE CVE matrix, MOB/vmdir enum | **`vmware-vcenter-attack.md`** |
| **Enterprise SSL VPN appliance** | vendor fingerprint (Cisco/Fortinet/Citrix/PAN/Pulse/F5), pre-auth CVE matrix, SAML SP check | **`enterprise-vpn-attack.md`** |
| **RAG / vector-store** | corpus poisoning, cross-tenant vector IDOR, metadata leak, retrieval hijack | **`rag-vector-attacks.md`** |
| **XS-Leaks** (cross-site login-state/membership oracle, no XSS/CORS needed) | ETag-length leak chains, connection-pool-prioritization timing oracle | **`xs-leaks.md`** |
| **Tooling setup / smoke test** (Kali/WSL kit) | Go tooling installs (subfinder/httpx/dnsx/ffuf/gau/waybackurls/nuclei/anew), wordlists + locations, Burp↔WSL proxy/CA config, WSL/Windows node+python gotchas, offline smoke test | **`loadout.md`** |
| **Custom nuclei templates** | high-signal checks for classes public sets handle weakly (credentialed-CORS reflection, genuine `*.js.map`, SvelteKit `__data.json`, Next `x-middleware-subrequest` probe, actuator/heapdump, edge-block gaps, healthz metadata); `-validate` + known-vulnerable AND known-clean controls before trusting — a template is an oracle | **`nuclei-templates.md`** |
| **Delegating a hunt to a shell-only agent** (pi/GLM/aider/codex — no MCP client) | fill-in brief template: scope confirmation, do-not-redo pre-flight, live-vs-dead sessions (dead 2nd account = IDOR BLOCKED, never faked), Burp via `scripts/burp_bridge.py` not MCP, estate traps, controls required before any negative, the closing output contract | **`delegation-hunt-brief.md`** |

## The two highest-paying habits

1. **IDOR with two sessions** (from `auth.json` creds A+B) — #1 paid class. Replay every
   endpoint with the other identity. Don't forget PUT/PATCH/DELETE and batch/GraphQL.
2. **A→B chaining** — e.g. SSRF→metadata→IAM keys→cloud; open-redirect→OAuth code theft→ATO;
   S3 listing→JS bundle→client_secret→OAuth; XSS→cookie/CSRF-token→ATO.

## Per-finding flow

```
confirm A with a real request → map sibling endpoints → test siblings with same pattern
   → try to chain to B/C → quantify impact (N users / $ / PII) → validate.md → findings/
```

A web foothold (RCE/creds) → switch to `initial-access.md` and keep going internal.

## OWASP Top 10 (2021) coverage map — use this to sanity-check a target isn't missing a category

| OWASP category | Moraa doc(s) |
|---|---|
| A01 Broken Access Control | `idor-access-control.md`, `parameter-deep-dive.md` § HPP, `framework-misconfig.md §7` |
| A02 Cryptographic Failures | `jwt.md`, `crypto-padding-oracle.md` (CBC padding oracle, ECB, weak hash), `host-header.md` (transport), `supply-chain.md` (plaintext/no-HSTS) |
| A03 Injection | `sqli.md`, `nosql-ldap-xpath-injection.md`, `ssti.md`, `command-injection.md`, `xss.md` |
| A04 Insecure Design | `business-logic.md`, `rate-limit-bypass.md` |
| A05 Security Misconfiguration | `framework-misconfig.md`, `cors.md`, `k8s.md`, `cicd-attack.md`, `host-header.md` |
| A06 Vulnerable & Outdated Components | `supply-chain.md`, `cms-wordpress-joomla.md`, `cms-moodle.md`, `shadow-api.md` (dead-but-live old versions) |
| A07 Identification & Auth Failures | `auth-oauth.md` (incl. § SAML, § password-reset battery), `2fa-bypass.md`, `jwt.md`, `cms-moodle.md §5` (federated identity keyed on a *mutable* handle → ATO) |
| A08 Software & Data Integrity Failures | `deserialization.md`, `supply-chain.md`, `prototype-pollution.md` |
| A09 Logging & Monitoring Failures | no dedicated doc — low bug-bounty yield (rarely externally provable); note in `reporting.md` if observed (no rate-limit on auth failures, no alert on impossible-travel) |
| A10 SSRF | `ssrf.md`, `cloud.md` |

## CWE Top 25 (2023, web-relevant subset) — quick lookup

| CWE | Class | Moraa doc |
|---|---|---|
| CWE-79 | XSS | `xss.md` (incl. § HTML injection / § CSS injection) |
| CWE-89 | SQL injection | `sqli.md` |
| CWE-78 / CWE-77 | OS command injection | `command-injection.md` |
| CWE-20 | Improper input validation | `parameter-deep-dive.md` § HPP, `business-logic.md` |
| CWE-22 | Path traversal | `lfi.md` |
| CWE-352 | CSRF | `csrf.md` |
| CWE-434 | Unrestricted upload | `file-upload.md` |
| CWE-862 / CWE-863 | Missing/incorrect authorization | `idor-access-control.md`, `framework-misconfig.md §7` |
| CWE-287 / CWE-306 | Improper/missing authentication | `auth-oauth.md`, `jwt.md` |
| CWE-502 | Insecure deserialization | `deserialization.md` |
| CWE-798 | Hard-coded credentials | `recon.md §4/4b/4c` (GitHub/Google/GitLab dorking), `js-analysis.md` |
| CWE-918 | SSRF | `ssrf.md` |
| CWE-362 | Race condition | `race-condition.md` |
| CWE-269 | Improper privilege management | `idor-access-control.md`, `business-logic.md` |
| CWE-94 | Code injection (incl. SSTI/prototype pollution) | `ssti.md`, `prototype-pollution.md` |
| CWE-276 | Incorrect default permissions | `cloud.md` (buckets/IAM), `k8s.md` |

Binary/memory-safety CWEs in the raw Top 25 (CWE-787/416/125/476/119/190) are out of scope for
black-box web hunting — see `knowledge/offensive/offensive-exploit-development.md` and
`offensive-crash-analysis.md` if a target ships a native client/binary component.


## Product-family API references: when one vendor ships several products on one gateway (2026-10-12)

When hunting `*.acme.example` the enterprise-identity product tenants, these public artifacts of the access-control product
family sharpen credential findings (used to harden the nfc/manager IDOR report):

- `github.com/YuDefine/acme-access-api-openapi` — OpenAPI 3.1 of the on-prem Access controller
  (converted from the vendor's official PDF, MIT). Card model: `nfc_id` = the card's **printed
  identifier**, `token` = the controller handle the assignment endpoints take, `display_id` =
  human-readable; lifecycle `pending → assigned`; assign/unassign are guarded by
  `x-permission-key: edit:user` + 401/403. Use it to show the cloud gateway omits a check the
  family's own reference design enforces.
- `hjdhjd/acme-access` (npm, live-verified types) + `tuckert/acme_access` (PyPI) — NFC tokens can
  only be minted via a reader enrollment session (`POST /credentials/nfc_cards/sessions`, needs a
  physical reader `device_id`) or a local admin file import. No API-only card minting without
  hardware — so in cloud labs with zero doors/cards there is NO real card id to test with; prove
  binding-gate absence by error ordering (roleless byte-identical to Owner on hex-format
  nonexistent ids 8/16/32 chars) instead.
- GitHub code search for the cloud route string (`"nfc/manager/workers"`) → 0 hits: no public
  integration leaks real tenant-cloud card ids.

---

## Class-table additions (r4 L1, 2026-10-15)

| Class | When to run it | Doc |
|---|---|---|
| **socket.io / engine.io on a REST host** | Any SPA backend whose bundle imports `socket.io-client`, or whose host answers `GET /socket.io/?EIO=4&transport=polling`. Route-census tooling never finds this — grep the bundle for `io(`, `.emit(`, `SOCKET_EVENTS`. Highest-value tell: **id-keyed event names subscribed with no room join** (`order_create:{quoteId}`) = possible namespace-wide broadcast of per-tenant events. | `websocket.md` § socket.io on a REST host |
| **NestJS pipe census (run BEFORE the injection matrix)** | Any NestJS/class-validator API. The empty-body `{}` probe is a free pre-auth DTO contract disclosure; `ParseUUIDPipe` is a hard fence whose two error strings give you the "never arrived vs arrived and matched nothing" oracle; the unknown-property probe is your mass-assignment precondition. Doing this first turns five of six parameters from "untested" into "control-backed fenced" and tells you which one is actually worth the matrix. | `parameter-deep-dive.md` § NestJS / class-validator |
| **Source-map re-check behind a UA gate** | Any host previously recorded as "no source maps" where the evidence was a bare-`curl` 403/404 rather than a body. A 118-byte 403 is a User-Agent gate, not an absence. | `js-analysis.md` § Trap: a bare curl gets 403 |
