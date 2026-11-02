# Moraa — XS-Leaks (cross-site information leak side-channels)

> Distinct from `xss.md` § CSS injection (needs a CSS-injection primitive) and `clickjacking.md`/
> `postmessage.md` (need frame embedding / a message listener). XS-Leaks need **neither** — they
> exploit observable, cross-origin-visible side effects of a normal browser request (response
> timing, connection reuse, error events, resource-loading behavior, pre-set script/global state) to
> infer information about a victim's authenticated state on another origin — or, with prototype
> override (Technique 3), read a victim-scoped value outright — without ever reading the response
> body directly (same-origin policy still blocks that). Load when hunting for ways to infer "is this
> victim logged in / a member of X / has data matching Y" cross-origin, with no XSS/CORS primitive
> needed.

## Technique 1 — ETag-length leak chains (Takeshi Kaneko, 2025)
HTTP `ETag` headers are sometimes derived from response properties (length, content hash) in a way
that's observable cross-origin even when the response body itself isn't. Chaining a resource whose
ETag value/format correlates with response *length* lets an attacker binary-search the victim's
cross-origin response size purely from ETag comparisons across repeated cross-origin requests
(cacheable resource, `If-None-Match` probing) — no body read needed. Useful when a target endpoint's
response size varies meaningfully by account state (e.g. a longer JSON body when a search matches
vs. an empty-result short body), turning that size difference into a boolean oracle. Reference:
https://blog.arkark.dev/2025/12/26/etag-length-leak

## Technique 2 — connection-pool-prioritization timing oracle (Salvatore Abello, 2025)
Chrome (and similarly-architected browsers) prioritizes/reuses connections from a shared pool in a
way that's measurably different depending on prior cross-origin activity — specifically usable to
infer where a cross-origin redirect chain ultimately lands, by timing how connection reuse behaves
around the redirect versus a control request with a known destination. Lets an attacker infer a
victim's redirect destination (e.g. does `/dashboard` redirect a logged-in user to `/app` vs an
anonymous user to `/login` — a login-state oracle) without ever seeing the `Location` header or
final response. Reference: https://blog.babelo.xyz/posts/cross-site-subdomain-leak/

## Technique 3 — prototype-override interception (direct value read, not an oracle) (ysamm.com, 2026)
An attacker page defines a method on a built-in prototype — `Function.prototype.default = (e) => {...}` —
BEFORE a legitimate third-party script loads and runs. When that script later calls
`someObject.default(userObject)` on a method name it expects to be undefined (or to be its own), the
attacker's override intercepts the call and reads `userObject.userID` straight out of the argument: a
DIRECT value read, not a timing/side-channel inference like Techniques 1-2. Distinct from
`prototype-pollution.md`'s gadget-chain focus — pollution poisons `Object.prototype` values to reach an
exploitable sink downstream, while this pre-defines a method NAME on a prototype so a third-party script
hands its argument to attacker code. Cross-reference that doc, but test for this separately: grep the
target's JS bundles for calls like `x.default(...)` / `x.something(...)` where `something` looks like an
unclaimed/expected-undefined property name on a built-in prototype, then check whether an attacker page
can define that property on the relevant prototype BEFORE the target's own script runs — script load
order decides it (only works if the override runs first: the attacker's page embeds the third-party
script itself, or the override lives in a shared/earlier-loading context). Reference: https://ysamm.com/
— "cross-site-leaks" (Jan 2026), bug #3

## Technique 4 — Content-Type/CORB onload-vs-onerror oracle (ysamm.com, 2026)
An endpoint that returns `Content-Type: text/html` for a valid/matching ID and `application/json` for an
invalid one (direction doesn't matter — the DIFFERENCE is the oracle) can be probed by loading the URL
as `<script src="...">` cross-origin: an HTML content-type "loads successfully" as far as the browser's
script-tag machinery is concerned (fires `onload`, even though the body isn't valid JS and does
nothing), while a JSON content-type gets blocked by CORB/ORB (Cross-Origin/Opaque Response Blocking —
the browser protection that blocks cross-origin no-cors responses that look like JSON/HTML from being
read as script) and fires `onerror` instead. Clean two-outcome boolean oracle from a Content-Type
header the app already sets for an unrelated reason — no timing measurement, just listen for which
event fires. General pattern: ANY endpoint whose Content-Type differs based on a boolean/enum condition
(valid-vs-invalid ID, matched-vs-unmatched search, authorized-vs-not) is a candidate regardless of the
endpoint's actual purpose — load it as a `<script src>` cross-origin and compare onload/onerror across
both states. Reference: https://ysamm.com/ — "cross-site-leaks" (Jan 2026), bug #1

## Technique 5 — X-Frame-Options presence/absence oracle (ysamm.com, 2026)
An endpoint that sets `X-Frame-Options: deny` (or doesn't) depending on a boolean condition leaks that
condition through framing: valid ID → no XFO header → the page loads successfully inside a cross-origin
iframe (its `onload` fires, or it postMessages the attacker); invalid ID → `X-Frame-Options: deny`
present → the browser refuses to render it in the iframe → no `onload` / no postMessage ever arrives →
attacker infers state from the absence/timeout of the expected signal. Same shape as Technique 4, keyed
on the XFO header instead of Content-Type — both instances of one broader rule worth stating
explicitly: any response header that gets conditionally set/omitted based on a fact about the victim's
session state is a candidate XS-leak oracle. Check `Content-Type`, `X-Frame-Options`, CSP
`frame-ancestors`, and `Cross-Origin-Resource-Policy` for conditional presence across the states you're
trying to distinguish. Reference: https://ysamm.com/ — "cross-site-leaks" (Jan 2026), bug #2

## Technique 6 — AppCache NETWORK allowlist prefix oracle (Lucas Herrera, Google VRP — deprecated API, legacy browsers only)
The HTML5 AppCache manifest's `NETWORK` section supports glob-style allowlist entries, and whether a
given cross-origin URL succeeds or fails to fetch under a manifest depends on whether it matches one of
those patterns. An attacker crafts a manifest with a candidate URL prefix and reads fetch success/failure
to BINARY-SEARCH an unknown cross-origin URL one character at a time (e.g. a redirect destination
carrying a CSRF token or session identifier in a query param) — a textbook oracle, same shape as
Techniques 1/2/4/5 but via a completely different browser subsystem. CAVEAT, stated up front and not to
be buried: AppCache is deprecated and REMOVED from modern Chrome (~2020-2021) and most other modern
browsers — real-world applicability today is narrow (legacy browsers, some embedded/older
WebView-based apps, environments that haven't updated in years). Keep it on file for the generalizable
PATTERN (prefix-allowlist-as-oracle), not as a live, broadly-applicable technique — don't assume it
works on a modern Chrome/Firefox/Safari without qualification. Reference: https://blog.lbherrera.me/ —
"AppCache's forgotten tales" (Google VRP writeup)

## Runnable harness (confirm the oracle server-side FIRST, then PoC it cross-origin)

Every technique here reduces to: **some response property differs by victim state**. Confirm the
server-side difference with curl on your own two accounts before building any browser PoC:

```bash
H="https://TARGET"
# Technique 4 — does Content-Type differ by ID validity / match state? (THE oracle)
curl -sI "$H/api/profile?id=<VALID-own-id>"   | grep -iE 'content-type|x-frame-options'
curl -sI "$H/api/profile?id=999999999"        | grep -iE 'content-type|x-frame-options'
# Technique 1 — does ETag correlate with response size across your two accounts?
curl -si "$H/api/search?q=<matches-my-data>"   | grep -i etag; curl -s "$H/api/search?q=<match>" | wc -c
curl -si "$H/api/search?q=<no-match-gibberish>" | grep -i etag; curl -s "$H/api/search?q=<nomatch>" | wc -c
# Technique 5 — XFO/CORP present on one state and absent on the other?
for id in <VALID-own-id> 999999999; do
  echo "id=$id"; curl -sI "$H/api/profile?id=$id" | grep -iE 'x-frame-options|cross-origin-resource-policy'
done
```

Then the two PoC skeletons an attacker page would serve (host on YOUR origin; the victim's
cookies ride along because these are no-cors/top-level requests):

```html
<!-- Technique 4 — Content-Type onload-vs-onerror boolean oracle -->
<script>
function probe(id) {
  return new Promise(res => {
    const s = document.createElement('script');
    s.src = 'https://TARGET/api/profile?id=' + id;
    s.onload  = () => res('HTML-content-type (loaded)');
    s.onerror = () => res('JSON-content-type (CORB/ORB-blocked)');
    document.head.appendChild(s);
  });
}
// diff(probe(VICTIM_ID_or_MATCHING_QUERY), probe(KNOWN_INVALID)) = the extracted fact
</script>

<!-- Technique 5 — XFO presence/absence oracle (iframe onload vs silence/timeout) -->
<iframe id="f" src="https://TARGET/api/profile?id=VICTIM_ID" style="display:none"></iframe>
<script>
  document.getElementById('f').onload = () => alert('no XFO on this state -> loads cross-origin');
  setTimeout(() => alert('no onload in 5s -> XFO blocked this state'), 5000);
</script>
```

```bash
# Technique 2 timing harness — median-of-N, known-destination control, >=30 runs per state
for i in $(seq 1 30); do curl -s -o /dev/null -w '%{time_total}\n' \
  "https://TARGET/redirect?to=<known-destination>"; done | sort -n | sed -n '15p'   # median
# run the same N against the victim-context URL and compare medians — one run proves nothing
```

**Impact gate (the proof bar below, operationalized):** the oracle must separate the two states
reliably across repeated runs (noise ≠ finding), and the write-up must name the extractable fact
("an attacker can learn whether the victim is logged into TARGET"), not just "timing differs".

## General XS-leak proof bar
1. The signal (timing delta, ETag value, connection behavior) must reliably and repeatably
   distinguish the two states you're claiming to infer (logged-in vs anonymous, member vs
   non-member, match vs no-match) — run each state multiple times and confirm the delta isn't
   noise. A one-off timing difference is not a finding.
2. State explicitly WHAT boolean/enum fact the leak proves an attacker can extract about a victim
   (not "there's a timing difference" — "an attacker can determine whether the victim is logged
   into TARGET" or "...is a member of organization X"). A leak with no articulable extractable
   fact is Informational.
3. Confirm it's genuinely cross-origin (attacker page, victim's real cookies riding along) — same
   discipline as the CORS/CSRF docs' credentialed-request requirement.

## Severity
| Finding | Severity |
|---|---|
| Prototype-override direct value read (Technique 3) proven — attacker code reads an actual victim-scoped value (ID/token), not just a boolean | High |
| Reliable cross-origin login-state / membership oracle (any boolean-oracle technique — 1/2/4/5, proven) | Medium |
| Oracle proven but only leaks a low-sensitivity boolean (e.g. "site uses this framework") | Low |
| Oracle technique that only works on deprecated/removed browser subsystems (Technique 6 AppCache — legacy/WebView browsers only) | Low |
| Signal present but not reliably reproducible / no articulable extractable fact | Informational |

## Bridge
`cors.md` and `csrf.md` (the credentialed cross-origin-request discipline this class shares),
`xss.md` § CSS injection (a different no-JS side-channel exfil primitive, useful comparison for framing
severity — CSS injection typically proves more per-bit than a boolean XS-leak), `prototype-pollution.md`
(related but distinct — pollution poisons `Object.prototype` values to reach an exploitable sink
downstream; Technique 3 pre-defines a method NAME on a prototype so a trusted third-party script hands
its argument to attacker code — different mechanisms, grep/test for both separately).
