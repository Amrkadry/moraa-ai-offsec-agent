# Moraa — Microsoft 365 / Entra ID attack chain

> Trigger: `autodiscover.*` records, `login.microsoftonline.com` redirects, `*.onmicrosoft.com`,
> `*-my.sharepoint.com`, `enterpriseregistration.*`/`enterpriseenrollment.*` in recon, client
> mentions "Conditional Access"/"compliant device". Red-team/internal engagements only — this is
> credential-attack territory, confirm authorization scope before any spray.

## Tenant discovery
```bash
msftrecon -d client.example    # tenant ID, Federation Namespace (Managed=ROPC works / Federated=ADFS),
                                # SharePoint Detected (OneDrive enum vector), Admin Consent Endpoint
```
Sister domains can be **separate tenants** — each has its own user list, lockout policy, CA config.
Don't assume one spray covers all owned domains.

## AADSTS code reference (memorize — these decide whether a password is correct)
| Code | Meaning | Password status |
|---|---|---|
| 50034 | User does not exist | — (no lockout impact, drop from list) |
| 50126 | Invalid username/password | wrong (+1 attempt) |
| 50053 | Smart Lockout | already locked — don't retry |
| **53003** | CA blocked token issuance | **VALID — CA wall** |
| **50076/50079** | MFA / strong-auth required | **VALID — MFA wall** |
| **50158** | External auth required | **VALID — federated MFA** |
| **530003** | Device-state required | **VALID — needs compliant device** |
| 700016 | App not in tenant | user is in a different tenant |

Any of {53003, 50076, 50079, 50158, 530003} = **the password is correct** — Entra only returns
these after successful credential validation. Document as confirmed-valid even with no token.

## Smart Lockout math (the cap discipline)
10 failed sign-ins/10min → lockout, counter shared across ROPC+SAML+IMAP+EWS+SMTP+device-code.
- Hard cap: **≤2 attempts per user, lifetime, per engagement** (some engagements: 1).
- Atomic state file (`json.dump` to `.tmp` + `os.replace`) — never race the counter.
- With 1 attempt/user you mathematically cannot cause lockout (1<10) — any 50053 you see is
  **pre-existing** → active-attacker detection signal (see `reporting.md` IR-observation section).

## User enumeration — hardening status (re-verify each engagement, don't trust stale notes)
**Hardened (2024+):** `/getuserrealm.srf` (tenant-level only), `/common/GetCredentialType`
(needs flowToken), `/autodiscover/autodiscover.json/v1.0/<email>` (identical body for any address).

**Still works:** OneDrive personal-site differential —
```
GET /personal/<user>_<domain>_com/_layouts/15/onedrive.aspx
Host: <tenant>-my.sharepoint.com
```
302 = user exists, 404 = doesn't. **Zero auth attempts, zero lockout impact.** Requires SharePoint
provisioned. Cross-reference with ROPC to classify account type:

| OneDrive | ROPC | Class |
|---|---|---|
| 200 | 50076/50126 | licensed regular user, MFA enforced |
| 404 | 50126 | **shared mailbox / service account** — has a password, historically MFA-exempt, prime target |
| 404 | 50034 | doesn't exist |

The OneDrive-404 + ROPC-50126 combo finds functional accounts (`noreply@`, `accounts@`,
`postmaster@`, `transport@`) that admins often exempt from Conditional Access.

## ROPC password validation
```python
import urllib.request, urllib.parse, ssl, json, os
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
HARD_CAP = 1  # never higher without explicit sign-off

def attempt(email, password, state_file="engagement_log/o365_attempts.json"):
    state = json.load(open(state_file)) if os.path.exists(state_file) else {}
    if state.get(email.lower(), 0) >= HARD_CAP: return {"status": "SKIPPED_CAP"}
    body = urllib.parse.urlencode({
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Graph PowerShell
        "grant_type": "password", "username": email, "password": password, "scope": "openid",
    }).encode()
    state[email.lower()] = state.get(email.lower(), 0) + 1
    json.dump(state, open(state_file+".tmp","w")); os.replace(state_file+".tmp", state_file)  # atomic
    req = urllib.request.Request("https://login.microsoftonline.com/common/oauth2/token",
                                  data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = json.loads(urllib.request.urlopen(req, context=ctx, timeout=15).read())
        return {"status": "VALID"} if "access_token" in r else {"status": "STATUS_200_NO_TOKEN"}
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="ignore")
        for code in ["AADSTS50034","AADSTS50126","AADSTS50053","AADSTS53003","AADSTS50076","AADSTS50079"]:
            if code in msg: return {"status": code}
        return {"status": "OTHER", "msg": msg[:200]}
```

**⚠ CRITICAL TRAP:** an MFA-blocked (50076) error body contains a `claims` field whose JSON
literally includes the substring `"access_token"` (CA policy step-up challenge, not a real token).
**Never substring-match `"access_token" in raw_body`** — parse JSON, check `"access_token" in dict`.
A loose substring check produces false-positive "CA bypasses" on every MFA-enforced account.

**Pace — hard rule, not a tuning knob: NEVER use concurrency.** Serial, 1.5–5s jitter only. Entra's
IP-reputation anti-spray layer is separate from per-user Smart Lockout — concurrency trips it, not
attempts-per-user. 12 threads produced ~183 false `AADSTS50053` in 15s vs. 1 across 454 paced
serial attempts on a real engagement. Kill-switch: >5 unexpected 50053 in a 1-attempt/user run →
STOP, you tripped IP anti-spray or you're seeing a real external spray — either way, diagnose first.

## Conditional Access bypass options (mostly blocked, document anyway)
| Vector | Status | Notes |
|---|---|---|
| Alt client_id (Graph PS `1b730954-...`, Azure CLI `04b07795-...`, Office `d3590ed6-...`) | sometimes | CA can be per-app |
| Alt resource (graph.microsoft.com / outlook.office.com / management.azure.com) | sometimes | CA can be per-resource |
| Legacy Basic Auth (EWS/IMAP/POP3/SMTP) | mostly dead | MS deprecated Oct 2022 |
| FOCI refresh-token reuse across Family-of-Client-IDs | post-auth | needs a token already |
| AiTM session-cookie steal | works, needs phishing | primary real-world technique — OOS for non-phishing engagements |
| Geo-bypass via VPN to trusted-location IP | sometimes | if CA trusts corp-HQ IP ranges |

If every path returns 53003 with universal CA (device+MFA), the cred is valid but unusable
externally — **phishing-completed cookie theft is the only realistic adversary path.** Say so
plainly in the deliverable.

## SAML SSO validation (when ROPC is CA-blocked, still prove the cred both ways)
Drive the real login via Playwright; Microsoft's `ConvergedConditionalAccess` page in the response
body is definitive evidence of CA-block (see `auth-oauth.md` § SAML for the XSW/signature side once
federated to a 3rd-party IdP).

## Active-attacker detection (the highest-value byproduct of any spray)
If 50053 appears on multiple users despite your 1-attempt cap: you didn't cause it (math).
Cluster locked users alphabetically (sorted-list spray signature); diff lockout count
before/after your session (new locks = attacker active *right now*). This is frequently the most
valuable finding in the engagement — see `reporting.md` IR-observation template.

## Anti-patterns
Don't retry after 50053. Don't parallelize ROPC at all. Don't skip sister-tenant domains. Don't
retract a CA-block (53003) finding — that IS the confirmed-valid signal.

## Bridge
`okta-attack.md` (sibling IdP, identical mental model — check federation first via `getuserrealm`
`NameSpaceType: Federated`), `hunt-mfa-bypass`/`2fa-bypass.md` (factor-downgrade once MFA wall
hit), `auth-oauth.md` § SAML (XSW on the federated IdP), `hunt-ntlm-info` fold in `recon.md` (on-prem
NTLM leak → Entra tenant resolution via `.well-known/openid-configuration`).
