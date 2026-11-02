# Moraa — User Enumeration (small class, unlocks the expensive ones)

> Enumeration alone is Low. Its value is what it UNLOCKS: credential stuffing, password spray,
> targeted 2FA and reset attacks against confirmed-live accounts ([[rate-limit-bypass]],
> [[auth-oauth]] § password-reset, [[2fa-bypass]]). Report it as the chain-opener it is — or don't report it.
> This is a CONTROLS problem: every oracle below needs a calibration before you trust it —
> [[controls-and-oracles]] is the parent discipline. Cross-ref [[auth-oauth]] (login/OAuth flows),
> [[rate-limit-bypass]] (the chain it feeds).

**The one rule:** a difference between "user exists" and "user doesn't" must survive a CONTROL —
the same test run against a KNOWN-existing address (your own account) and a KNOWN-absent one —
repeated enough times to separate signal from noise. One pair of requests is a hunch, not an
oracle.

```bash
H="https://TARGET"
REAL="you@your-account.test"          # your own account on the target — the KNOWN-YES control
FAKE="no-such-$(date +%s)@dead.test"  # verifiably absent — the KNOWN-NO control
```

## 1. The oracles — and the test that proves each one real

### 1a. Response-body difference
```bash
for U in "$REAL" "$FAKE"; do
  curl -s -X POST "$H/api/login" -H 'Content-Type: application/json' \
       -d "{\"email\":\"$U\",\"password\":\"DefinitelyWrong123!\"}" -o "/tmp/body-$U.json"
  md5sum "/tmp/body-$U.json"; done
```
Diff the bodies (messages: "user not found" vs "wrong password"; JSON keys present only in one).
Watch for case-normalization (§1f) — run the control at the same case as the target.

### 1b. Status-code difference
```bash
curl -s -o /dev/null -w "$REAL %{http_code}\n" -X POST "$H/api/login" -H 'Content-Type: application/json' \
     -d "{\"email\":\"$REAL\",\"password\":\"x\"}"
curl -s -o /dev/null -w "$FAKE %{http_code}\n" -X POST "$H/api/login" -H 'Content-Type: application/json' \
     -d "{\"email\":\"$FAKE\",\"password\":\"x\"}"
```

### 1c. Redirect-target difference
Login/reset forms that redirect: exists → `/reset-sent`, absent → `/login?error=...` (or the
reset flow redirects to `/login` vs `/check-your-email`). Read the `Location` header, not the
status alone:
```bash
curl -s -o /dev/null -w '%{redirect_url}\n' -X POST "$H/api/password-reset" \
     -H 'Content-Type: application/json' -d "{\"email\":\"$REAL\"}"
curl -s -o /dev/null -w '%{redirect_url}\n' -X POST "$H/api/password-reset" \
     -H 'Content-Type: application/json' -d "{\"email\":\"$FAKE\"}"
```

### 1d. TIMING difference — measure a DISTRIBUTION, never a single pair

Single-request timing is noise: a GC pause, a cold cache, a network hiccup. The classic timing
oracle (user-exists → password hash computed → ~100ms slower) is real, but you must compare
distributions:

```bash
python3 - "$H" "$REAL" "$FAKE" <<'PY'
import json, statistics, sys, time, urllib.request
H, REAL, FAKE = sys.argv[1], sys.argv[2], sys.argv[3]
def probe(u, n=40):
    ts = []
    for _ in range(n):
        req = urllib.request.Request(H + "/api/login",
              data=json.dumps({"email": u, "password": "x"}).encode(),
              headers={"Content-Type": "application/json"})
        t = time.perf_counter(); urllib.request.urlopen(req); ts.append(time.perf_counter() - t)
        time.sleep(0.2)                      # gentle; stay under any rate rule
    return ts
a, b = probe(REAL), probe(FAKE)
for name, ts in (("REAL", a), ("FAKE", b)):
    print(f"{name}: median={statistics.median(ts)*1000:.1f}ms p10={sorted(ts)[4]*1000:.1f} "
          f"p90={sorted(ts)[35]*1000:.1f}")
med_a, med_b = statistics.median(a), statistics.median(b)
mad = statistics.median([abs(x - med_a) for x in a] + [abs(x - med_b) for x in b])
print(f"median gap={abs(med_a-med_b)*1000:.1f}ms  pooled-MAD={mad*1000:.1f}ms  "
      f"ratio={(max(med_a,med_b)/max(min(med_a,med_b),1e-9)):.2f}")
PY
```
**A real oracle:** the medians separate by clearly MORE than the pooled MAD (rough guide:
gap ≥ 3× MAD, stable across re-runs, and the direction is explainable — the slower side is the
existing user because it does more work). A gap smaller than the noise band, or one that
flips sign between runs, is noise — say so and stop.

### 1e. Rate-limit-behaviour difference
Some limiters key on the ACCOUNT: the existing user's attempts get throttled/locked while the
absent user sails through (or the lockout email/notification fires only for real accounts).
```bash
# fire 6 failed logins each (own REAL account vs FAKE), compare when 429/lockout kicks in:
for i in $(seq 1 6); do
  for U in "$REAL" "$FAKE"; do
    curl -s -o /dev/null -w "$U %{http_code}\n" -X POST "$H/api/login" -H 'Content-Type: application/json' \
         -d "{\"email\":\"$U\",\"password\":\"wrong$i\"}"; done; sleep 2; done
```
A different trip point/countdown per account class is the oracle — and its DARK SIDE is the
finding: an attacker sprays and reads lockouts as a live-account detector. Chain:
[[rate-limit-bypass]].

### 1f. Case / normalization side channels
`Real@Target.com` vs a canonicalized store: one casing 200s on reset and another 404s → the store
is case-sensitive where the UI isn't, which both confirms an address AND gives password-spray
variants ([[rate-limit-bypass]] technique 9).

## 2. Where the side channels live (test each flow, each with both controls)

| Flow | Classic oracle |
|---|---|
| **Registration** | "email already registered" on signup; the SIGNUP version often leaks when login is hardened — always test both |
| **Password reset** | §1a-§1e applied to the reset request (full battery: [[auth-oauth]] § password-reset #1) |
| **Login** | §1a-§1f; also response-size diffs and `Set-Cookie` presence (pre-auth session issued only for... nothing — but verify) |
| **OAuth account linking** | connect-your-account flow: an error that distinguishes "email already linked to another account" from generic failure — leaks which providers/emails exist |
| **SSO discovery** | "enter your email → we route you to your IdP": IdP name/domain reflected back for REAL corporate addresses, generic error for unknowns — corporate address book for free |
| **MFA / 2FA step** | password accepted → "enter code" prompt only for valid passwords+users; an invalid-password user short-circuits (that's REQUIRED behavior — the oracle is a DIFFERENCE IN TIMING/response at the PASSWORD step, see §1d) |

## 3. Confirming the oracle is REAL (the controls checklist)

1. **Both controls first:** KNOWN-YES (your account) and KNOWN-NO must read opposite — if your
   own account and the fake read the SAME, the endpoint doesn't leak; done, note it, move on.
2. **Repeat:** a difference that appears once and vanishes on re-run is noise (rate-limiter
   warm-up, cache, deploy in flight).
3. **Hold everything constant:** same case, same client, same IP, minutes apart — then flip ONLY
   the existence bit. Any other changing variable voids the reading ([[controls-and-oracles]]
   Case 5's discipline: verify by content, not by a single artifact).
4. **State the mechanism:** "exists-side computes a bcrypt hash" or "exists-side sends the mail
   before responding" — an oracle you can EXPLAIN is one you can trust; an unexplained difference
   is one retry scheduled, not one finding written.

## 4. Impact gate

- **Standalone:** Low / informational at almost every program. A clean timing-only oracle is
  often not worth submitting on its own.
- **Chained → real finding:** enumeration + weak/no lockout = workable credential stuffing at
  scale (quantify: spray feasibility per [[rate-limit-bypass]]); enumeration on the RESET flow +
  predictable tokens = targeted ATO ([[auth-oauth]] § password-reset); SSO-discovery leak + factor
  enumeration = targeted phishing list ([[2fa-bypass]]). Report the CHAIN with the enumeration as
  step 1, evidence for each step, and run the whole thing through [[validate]].
