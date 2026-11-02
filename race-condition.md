# Moraa — Race conditions (TOCTOU / limit-overrun)

> Load when an action has a per-user limit, a one-time property, or a check-then-act gap. High-value
> in money/credits/coupons/withdrawals/invites/votes. Tool: Burp Repeater **group → send in parallel /
> single-packet attack**, or Turbo Intruder.

## Where they live
```
coupon/gift-card redeem (use once → use N times)     balance/withdrawal (double-spend)
credits/points transfer                              invite/seat limits (exceed org seat cap)
OTP / password-reset token attempts (bypass rate limit / lockout)
vote/like/rating (inflate)                           account signup (bypass "one per email")
file/quota limits                                    2FA enable/disable toggles (state confusion)
"apply once" promotions, referral bonuses            approve/approve (double-approve a workflow)
```

## Technique
```
# Burp: select the request → "Send group in parallel" (single-packet attack for HTTP/2 — sub-ms window)
# Turbo Intruder (classic):
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30, engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req)          # same request 30x
    engine.openGate('1'); engine.completeGate('1')   # release simultaneously
```
```bash
# quick CLI parallel fire (no Burp):
seq 30 | xargs -P30 -I_ curl -sk -X POST https://T/redeem -H "Cookie: $A" -d 'code=ONCE' -o /dev/null -w "%{http_code}\n" | sort | uniq -c
```
- **Single-packet attack** (HTTP/2) removes network jitter → the reliable modern method. Use it first.
- Confirm by state, not status: did you redeem the coupon twice / go negative balance / exceed the cap?

## TOCTOU beyond limit-overrun (state-confusion races)
```
Upload+scan+serve: race the swap between AV/validation scan and the final write (upload safe.png,
  race a rename/overwrite to evil.svg before the scanner reads the final file).
"Is admin?" check then a long-running privileged task: race a logout/role-change between the
  check and the use — the task still runs with the OLD privilege.
Symlink race on any file-write tool that writes through a user-supplied path (check, then act,
  on a path an attacker can re-point between the two).
Order-before-payment: race order creation against a payment-webhook/cancel to get a fulfilled
  order with no successful charge, or a double-fulfillment from one payment.
```

## Mitigation patterns (so you know when you're beaten — stop chasing a dead race)
If you see any of these guarding the target operation, the race is probably not winnable —
confirm quickly (one clean vs one raced attempt) then refocus on a different endpoint:
```
SELECT ... FOR UPDATE / explicit row lock around the check-then-act.
Optimistic concurrency: every update carries a `version`/`etag` field that's compare-and-swapped.
Idempotency keys: the request carries a client-generated key; server stores key+result and
  replays the stored result on a duplicate instead of re-executing.
UNIQUE (user_id, resource_id) constraint + `ON CONFLICT DO NOTHING` — the DB itself rejects the
  second concurrent insert, no app-level race window to exploit.
```

## Method
1. Do the action once legitimately → note the "used/limit reached" response.
2. Fire N in parallel from a fresh state → count how many *succeeded* beyond the limit.
3. Prove impact in state (balance, redemptions, seats). → `validate.md` → `findings/`.
> Test on your own resources only; don't drain a shared/prod balance. Prove the overrun with the
> minimum count that shows the limit broke.
