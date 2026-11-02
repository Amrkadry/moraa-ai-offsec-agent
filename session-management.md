# Moraa — Session Management (the doc between jwt.md and auth-oauth.md)

> `[[jwt]]` covers tokens and `[[auth-oauth]]` covers flows — classic cookie/session handling was
> uncovered, and it still pays: a session that survives a password reset defeats the entire
> recovery flow, and logout-that-doesn't-invalidate turns every stolen-cookie into a permanent
> ATO. Cross-ref [[2fa-bypass]] (post-auth session issuance), [[auth-oauth]] § password-reset (the recovery
> flow this doc breaks), [[csrf]] (SameSite interplay), [[auth-oauth]] (where sessions are born).

**Universal discipline:** test with TWO accounts you own (A=attacker, B=victim — same pattern as
[[idor-access-control]]). Store sessions in separate cookie jars. Never replay against a real
victim's session. All tests below assume your own accounts.

```bash
H="https://TARGET"
# login each account into its own jar once, and keep the jars — every test reuses them:
curl -s -c jarA.txt -X POST "$H/api/login" -H 'Content-Type: application/json' \
     -d '{"email":"A@you.test","password":"<A-pass>"}' >/dev/null
curl -s -c jarB.txt -X POST "$H/api/login" -H 'Content-Type: application/json' \
     -d '{"email":"B@you.test","password":"<B-pass>"}' >/dev/null
```

## 1. THE high-impact test — session survives password change / email change / 2FA enrolment

An attacker who has stolen a session (XSS, log theft, shared machine) keeps it after the victim
"fixes" the compromise by rotating their password — unless every session is invalidated on
credential change. This is the test that turns "medium cookie theft" into a persistent-ATO story:

```bash
# 1. capture B's CURRENT session id
SESS_B=$(awk '/session/ {print $NF}' jarB.txt)          # adjust the cookie name
# 2. B changes password (and email, and enrols 2FA — test each lifecycle event separately)
curl -s -b jarB.txt -X POST "$H/api/user/password" -H 'Content-Type: application/json' \
     -d '{"current":"<B-old-pass>","new":"<B-new-pass>"}' -o /dev/null -w 'pwd-change: %{http_code}\n'
# 3. replay the OLD pre-change session
curl -s -H "Cookie: session=$SESS_B" "$H/api/user/me" -o /dev/null -w 'old-session: %{http_code}\n'
```
**A 200 with real account data on step 3 = the finding.** The old session must be dead after a
password change, an email change, and a 2FA enrolment — test all three; often only one
invalidates. Why it's severe: password reset is what a victim does when they suspect theft; if
the attacker's session survives it, the recovery flow is decorative. Pairs with
[[auth-oauth]] § password-reset: a reset-token flow that doesn't invalidate sessions has the same hole at the
other end.

## 2. Session fixation — does the id rotate on privilege change?

The session id must be REISSUED at every privilege boundary: anonymous → logged-in, and especially
login → 2FA-verified and user → elevated role. If it isn't, anything that can plant a value in
the victim's cookie jar (subdomain XSS, a sibling app on the same parent domain — see cookie
scoping below) rides their login into an authenticated session.

```bash
# 1. grab the PRE-auth cookie (GET / unauthenticated) and note the session value
curl -s -c jarPre.txt "$H/" -o /dev/null; PRE=$(awk '/session/ {print $NF}' jarPre.txt)
# 2. log in — does the server SET-COOKIE a NEW value, or keep yours?
curl -s -D - -o /dev/null -b jarPre.txt -X POST "$H/api/login" \
     -H 'Content-Type: application/json' -d '{"email":"A@you.test","password":"<A-pass>"}' | grep -i 'set-cookie'
# 3. fixation check: FORCE the pre-auth value post-login and see if it's accepted as authenticated
curl -s -H "Cookie: session=$PRE" "$H/api/user/me" -o /dev/null -w 'fixed-session: %{http_code}\n'
```
**Proves the bug:** the pre-auth value you supplied is the authenticated session afterwards (200
+ your account data on step 3), i.e. the server adopts attacker-chosen ids instead of minting
fresh ones. If login returns a brand-new value AND step 3 is 401, rotation is done — move on.

## 3. Session puzzling / variable overloading

Multi-param apps accept several session-ish inputs — `session`, `auth`, `token`, `sid`, `user`,
legacy cookies from an old stack. "Puzzling" = combining values from two different sessions into
one request that the backend validates piecewise (signature checked on part A, identity read from
part B) and accepts. Also the reverse trap: an app that checks `auth=` but ignores a leftover
`user=` cookie.

```bash
# enumerate what the app honors: strip ONE at a time and watch for auth breakage
for c in "session" "auth" "token" "sid" "user" "remember"; do
  grep -v "$c" jarA.txt > jarA_no_$c.txt
  curl -s -b jarA_no_$c.txt "$H/api/user/me" -o /dev/null -w "without-$c: %{http_code}\n"
done
# puzzling probe: A's auth value + B's identity value (and vice versa) in one request
curl -s -H "Cookie: auth=<A-auth-value>; user=<B-user-value>" "$H/api/user/me"
```
**Proves the bug:** a hybrid request is accepted and resolves to the WRONG identity or elevated
privileges — the response data shows whose session won. If every subset behaves sanely (401s or
correct identity only), the parts are bound properly; note it and move on.

## 4. Logout that doesn't invalidate server-side

```bash
# 1. capture B's live session value
SESS_B=$(awk '/session/ {print $NF}' jarB.txt)
# 2. log out
curl -s -b jarB.txt -X POST "$H/api/logout" -o /dev/null -w 'logout: %{http_code}\n'
# 3. replay the same value straight back
curl -s -H "Cookie: session=$SESS_B" "$H/api/user/me" -w '\nreplay-after-logout: %{http_code}\n'
```
**A 200 after step 3 = the session is only client-side discarded.** Same check after
"terminate all other sessions" buttons and after admin-forced-logout (if your roles include
admin). Impact: logged-out ≠ safe; stolen session persists through the victim's logout. (JWT
variant of the same hole: token valid until exp after logout — [[jwt]] § logout non-revoke.)

## 5. Concurrent sessions + session list

```bash
# 1. log B in on a "second device" (fresh jar)
curl -s -c jarB2.txt -X POST "$H/api/login" -H 'Content-Type: application/json' \
     -d '{"email":"B@you.test","password":"<B-pass>"}' >/dev/null
# 2. is there a session manager? does it list both? does "revoke other sessions" actually revoke?
curl -s -b jarB.txt "$H/api/user/sessions"
# 3. revoke jarB2's session via the manager, then replay it:
curl -s -H "Cookie: session=$(awk '/session/ {print $NF}' jarB2.txt)" "$H/api/user/me" -o /dev/null -w '%{http_code}\n'
```
**Finding shapes:** revoke-all leaves old sessions live (same proof shape as §4); the session
manager lists sessions from OTHER identities (session list IDOR — cross-check with A's jar); no
limit on concurrent sessions combined with no idle timeout = indefinitely farmable stolen
sessions. Zero concurrency allowed with no option to approve a second device is a UX note, not a
finding — don't report it.

## 6. Absolute vs idle timeout

```bash
# idle timeout: park the jar, replay every N minutes until it dies
while :; do sleep 300; CODE=$(curl -s -b jarA.txt "$H/api/user/me" -o /dev/null -w '%{http_code}'); \
  echo "$(date +%H:%M) $CODE"; [ "$CODE" != "200" ] && break; done
# absolute timeout: keep the session WARM (a light authenticated call every few minutes)
#   and check whether it dies at the absolute cap anyway — it should.
```
**What counts:** idle timeout of days, or no expiry attribute at all (`Expires`/`Max-Age` absent
on a persistent cookie), or a session that outlives its absolute cap while kept warm. Honest
gate: "no idle timeout after 2h of observation" is a weak claim — observe long enough to state a
real window, or drop it. Rolling refresh extending indefinitely with no absolute cap is the
stronger, provable version.

## 7. Cookie scoping — read every Set-Cookie like an attacker

```bash
curl -s -D - -o /dev/null -b jarA.txt "$H/api/user/me" | grep -i set-cookie
```
| What you see | Why it matters | The test that proves harm |
|---|---|---|
| `Domain=.target.com` from `app.target.com` | cookie rides to EVERY sibling subdomain — one vulnerable subdomain steals it (subdomain XSS/takeover) | confirm a sibling host you control/reported can receive it: `curl -s -H "Cookie: session=..." https://ANY.target.com/` reflects acceptance |
| missing `Secure` | leaks over plain HTTP on any network MITM | `curl -s http://TARGET/ -D -` shows the app links/redirects via http at all |
| missing `HttpOnly` | XSS reads it — chain closes: XSS→cookie→ATO | note it with the XSS finding ([[xss]]); alone it's a precondition, not a finding |
| missing/no `SameSite` (or `None` without `Secure`) | cross-site requests carry it → CSRF exposure | [[csrf]] test battery |
| no `__Host-` prefix on the main session cookie | host/prefix-scoping not enforced; combined with a broad Domain it's downgradeable | worth one line in the report as hardening, not standalone |

Scoping findings obey the chain rule: a broad `Domain` is real when a second, attackable host
under that Domain exists in scope (your subdomain-takeover or XSS lead) — otherwise it's
hardening advice. Same-site attacks: [[csrf]], [[cors]].

## 8. Session id entropy / predictability

```bash
# collect 30 ids from 30 fresh anonymous sessions (gentle — minutes apart, your own traffic):
for i in $(seq 1 30); do curl -s -D - -o /dev/null "$H/" | grep -i 'set-cookie' | grep -o 'session=[^;]*'; sleep 2; done > ids.txt
# eyeball first — the classic fails show up without math:
sort ids.txt | uniq -c | sort -rn | head        # duplicates = recycled counter = game over
awk -F= '{print length($2)}' ids.txt | sort -u  # short (<16 chars) or fixed-length-and-sparse?
for v in $(cut -d= -f2 ids.txt); do echo "$v" | base64 -d 2>/dev/null | xxd | head -2; done
#   decodable ids leak structure: embedded timestamp, username, sequence — decode two and diff
```
**Proves the bug:** a decoded/recoverable structure that lets you PREDICT another live session
(then confirm by predicting your own next session id before the server issues it — a clean
self-proof, no victim needed). Random-looking 128-bit+ values with no visible structure: log the
sample as "no structural weakness found" and stop — do not run entropy suites on a hunch.

## Impact gate

Write the finding in terms of what an attacker holds afterward: "attacker's session survives the
victim's password reset → stolen access persists through recovery" (High/Critical), "logout
doesn't invalidate → stolen cookie = permanent ATO" (High), "session id adopts attacker-chosen
values + sibling-host cookie injection → ATO" (High when the injection host exists), scoping
flags and timeout oddities alone are Low/hardening — report them as such or chain them. Run the
result through [[validate]] before it lands in `findings/`.
