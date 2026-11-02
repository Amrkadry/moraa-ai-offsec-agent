# Moraa — postMessage vulnerabilities (cross-window/iframe messaging)

> HackTricks `postmessage-vulnerabilities`. Cross-ref [[xss]] (missing origin check = DOM XSS sink),
> [[cors]] (same trust-boundary failure mode, different API).

## Find it
```js
// in target's bundle/console:
window.addEventListener('message', ...)   // grep bundles for this
```
Bugs to check on BOTH sides of the channel — then the failure modes that survive a correct-looking check:

## Bug 1 — sender doesn't restrict the target origin
`window.postMessage(sensitiveData, '*')` (wildcard target) sent from an iframe/popup lets **any**
page that can get itself into that window relationship (opened via `window.open`, or embedded as an
iframe by another site first) receive the message. Confirm: load the vulnerable page in your own
iframe and listen — do you receive sensitive data (tokens, user info, internal state)?

The "sensitive data" is very often the sender's OWN URL: payloads built from `window.location.href` /
`document.referrer` carry their query params along. Real case (Facebook, ysamm.com Jan 2026): a
redirect endpoint sent `postMessage(data, '*')` to its `window.opener` with `data` containing the
full current page URL — including `token`/`blob` query params. Easy to miss in review because the
leaking field isn't named `token` — the URL itself is the leak vector.

## Bug 2 — receiver doesn't validate `event.origin` (the common, higher-impact one)
```js
window.addEventListener('message', function(e) {
  // NO check on e.origin  <-- the bug
  eval(e.data)                          // → RCE-in-browser / full XSS
  document.getElementById('x').innerHTML = e.data   // → DOM XSS
  someAction(e.data.command, e.data.params)         // → arbitrary privileged action from ANY origin
})
```
If the origin check is present but weak, these all fail to actually restrict:
```js
if (e.origin.indexOf('target.com') > -1)      // passes for evil-target.com.attacker.com
if (e.origin.endsWith('target.com'))          // passes for eviltarget.com  (no dot!)
if (/target\.com/.test(e.origin))             // passes for target.com.attacker.com
// correct: e.origin === 'https://target.com'  (exact match, or an explicit allow-list)
```

## Bug 2b — origin used to construct a script-src URL (not just trusted as data)
Worse than the usual missing check: when the handler builds a resource URL from `event.origin`
itself (not just consumes `event.data`), the attacker doesn't need to control the payload at all —
being the postMessage SENDER is enough, because their own origin string becomes the source of the
script that gets loaded and executed. Real case (Facebook Conversions API Gateway, ysamm.com Jan
2026): `pixel_id` was allow-listed correctly, `event.origin` was never checked, and the handler
loaded `<origin>/sdk/<pixel_id>/iwl.js`:
```js
window.addEventListener('message', function(e) {
  if (!ALLOWED_PIXEL_IDS.includes(e.data.pixel_id)) return       // payload param: checked
  loadScript(e.origin + '/sdk/' + e.data.pixel_id + '/iwl.js')   // sender origin: NOT checked
})
```
Attacker page iframes the target and posts `{pixel_id: <valid-id>}` — `e.origin` is the attacker's
own origin, so the target fetches `/sdk/<id>/iwl.js` from the attacker's server and executes it on
the target origin = XSS.

## Bug 2c — trusted origin, but is the origin itself trustworthy? (exact-match check ≠ safe)
A CORRECT exact-match origin check does not make the message safe — it makes the message as safe as
the trusted origin. If the trusted origin has its own XSS/injection bug, you inherit that origin's
trust for free: inject there first, and the injected script's `postMessage` passes the receiver's
check legitimately, delivering the payload as if the real partner sent it. Real case (Facebook
Payments, ysamm.com Jan 2026): receiver checked `e.origin ===
'https://ThirdPartyPaymentProvider.com'` exactly, then rendered the payload as unsanitized HTML —
exploitable directly only as self-XSS (you'd have to message yourself), until the third party's own
URL-parameter reflected XSS was found and chained. When auditing a postMessage receiver, ALSO
enumerate and test every origin it trusts for their own independent XSS bugs, not just the
receiver's origin-check logic (see [[xss]]).

## Exploit (host on any origin, lure the victim to it)
```html
<iframe src="https://victim/vulnerable-page" id="f"></iframe>
<script>
onload = () => {
  document.getElementById('f').contentWindow.postMessage(
    {command:'setAdmin', params:{isAdmin:true}}, '*'   // or the exact expected shape
  );
}
</script>
```
Or, if the victim page performs `window.opener.postMessage(...)` back to whatever opened it — open it
yourself via `window.open` and listen, no iframe embedding needed (works even against
`X-Frame-Options: DENY` pages, since you're not framing them).

## Escalate
- Reflected `data` into `innerHTML`/`eval`/`document.write` = XSS on the RECEIVING origin → chain into
  whatever that origin is trusted for (cookies, and — if it's a CORS-trusted origin, see [[cors]] —
  credential theft on a THIRD service too).
- A message that triggers a privileged action (grant admin, change setting, submit a form) with no
  origin check = a cross-origin CSRF-equivalent, often WORSE than CSRF because it needs no cookie/session
  requirement — just getting the victim to load a page that talks to the target's window.

## Weak PRNG for a callback/nonce identifier — forge it, don't guess it
If a postMessage protocol accepts a reply solely because its ID matches one the receiver generated
and is waiting on, the ID generator IS the entire authenticity check. `Math.random()` (or any
generator not documented as a CSPRNG) doesn't qualify: its internal PRNG state is reconstructable
from a handful of observed outputs, so the next value is PREDICTED, not guessed. Real case (Facebook
JS SDK, ysamm.com Jan 2026): plugin-message "guid"s came from `Math.random()` and the guid match was
the only gate on treating an incoming postMessage as a legitimate callback response. The side
channel that made it practical: the same guids were used as plugin IFRAME `name` attributes —
readable same-origin from the DOM. Attacker page forces the SDK to reinit several plugin iframes →
reads the raw PRNG outputs off the `name` attrs → feeds them to Z3 → reconstructs V8's PRNG state →
predicts/forges the NEXT guid → injects a fake postMessage response the SDK accepts as authentic.

Test for it:
```
grep -Hn "Math.random" bundle.js     # near anything message/callback/nonce/guid-shaped
- is the generated value the SOLE gate on accepting an incoming postMessage as legitimate?
- is it exposed same-origin? (DOM attrs like iframe name/id, URL params, echoed in observable traffic)
- yes + yes → collect samples → solve PRNG state (Z3) → predict + forge the reply
```

## Impact gate — fire it from a foreign origin, catch the effect yourself

The falsifier is directional: your sender page lives on an origin the target does NOT trust, and
the effect lands where YOU can observe it.

- Host the sender on your own domain (or `window.open` the target and listen — no framing needed,
  works against `X-Frame-Options: DENY`), post the message, then show the EFFECT: script executing
  on the target origin, a privileged action completing, or sensitive data arriving in YOUR
  listener.
- A weak origin check that accepts your message but does nothing with it is a hardening note —
  the claim is the effect, not the missing `===`.
- Receiving your own message back on the origin it came from proves transport, not vulnerability.

## Report
Show `addEventListener('message', ...)` has no (or a broken) origin check, the exact payload sent from
an untrusted origin, and the concrete effect (XSS fired / privileged action executed / data exfiltrated).
