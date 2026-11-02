# Moraa — Clickjacking & tab-nabbing

> HackTricks `clickjacking`, `iframe-traps`, `reverse-tab-nabbing`. Cross-ref [[csrf]] (often chained), [[xss]].

## Detect
```bash
curl -sI https://target/sensitive-page | grep -iE 'x-frame-options|content-security-policy'
```
No `X-Frame-Options: DENY/SAMEORIGIN` AND no CSP `frame-ancestors` directive → framable.

## PoC (drag the victim's real UI under an invisible/decoy overlay)
```html
<style>
  iframe{opacity:0.0001;position:absolute;top:0;left:0;width:800px;height:600px;z-index:2;}
  .decoy{position:absolute;top:250px;left:100px;z-index:1;}
</style>
<div class="decoy"><button>Click here to win a prize</button></div>
<iframe src="https://target/delete-account?confirm=1"></iframe>
```
Align the decoy button exactly under the real target's action button (delete/confirm/pay/grant) using
DevTools ruler on a local copy first. **Multi-step clickjacking:** chain several precisely-positioned
clicks across an iframe to walk a multi-page confirm flow (drag-and-drop can carry data too — "drag &
drop" clickjacking can exfiltrate text a user drags across frames).

## Bypass attempts if a defense exists
- `X-Frame-Options: ALLOW-FROM` is obsolete/ignored by modern browsers → often still framable if that's the ONLY defense (no CSP).
- CSP `frame-ancestors 'self'` bypassed via **XSS on a same-origin page** that can be framed with the target inside it, or via a sandboxed iframe (`sandbox="allow-scripts allow-top-navigation"`) if it isn't `allow-same-origin`-restricted.
- **Framebusting-script bypass** (legacy JS-based defense, not headers): `<iframe sandbox="allow-forms allow-scripts">` — some framebuster scripts break without `allow-top-navigation`, become inert.

## SVG-filter clickjacking (cross-origin pixel read) — Dec 2025
This is why clickjacking is no longer automatically a Low. CSS `filter: url(#id)` applies an SVG
filter graph to a CROSS-ORIGIN iframe, and the iframe's rasterized pixels enter that graph as
`SourceGraphic` with no CORS check — so the attacker can READ the framed page's pixels, not just
overlay it.
```html
<iframe src="https://target.com/account" style="filter:url(#f)"></iframe>
<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0">
  <filter id="f">
    <!-- feTile crops one region; feColorMatrix isolates a channel;
         feComposite arithmetic thresholds it into a detectable value -->
    <feTile/><feColorMatrix type="matrix" values="..."/><feComposite operator="arithmetic"/>
  </filter>
</svg>
```
Primitives that matter: `feDisplacementMap` (move pixels), `feComposite` (arithmetic on channel
values), `feColorMatrix` (channel isolation / format conversion), `feTile` (crop+tile a region),
`feBlend`, `feFlood`, `feMorphology`, `feGaussianBlur`, `feImage`. Chaining `feBlend`/`feComposite`
builds AND/OR/NOT/XOR logic gates inside the rendering engine, which makes the overlay *reactive*:
it can detect that a dialog opened, a button turned green, or text appeared, and adapt — so
multi-step clickjacking flows that used to be impractical now work. Exfil without any script on the
target: encode the read pixels into a QR code rendered on the attacker page and get the victim to
scan it.

Browser state: Chromium and Firefox affected (Firefox `feTile` unreliable); Safari patched the
underlying issue back in 2017 and renders these unreliably. Mozilla bug 2004487; W3C
filter-effects PR 13846 proposes forbidding reference filters on cross-origin iframes.

What it changes for us: on a framable page, the severity question is no longer only "what single
privileged action can I trick a click into" but "what can I READ off this page while framed" —
account name, balance, partial token, MFA state. Still requires the page to be framable, so
`X-Frame-Options: DENY` / CSP `frame-ancestors 'none'` remains the fix, and an unframable page is
still not a finding.
Reference: https://lyra.horse/blog/2025/12/svg-clickjacking/

## Reverse tab-nabbing (a target you LINK to, not frame)
Any `<a href="https://evil" target="_blank">` you control (or that a stored-content field lets you
inject) without `rel="noopener noreferrer"` lets the new tab's JS do `window.opener.location =
'https://phishing-login-page'` — silently rewrites the ORIGINAL tab (the one the user still trusts)
to a phishing page while they interact with the new tab. Check: user-generated content with
attacker-controlled outbound links (profile "website" field, markdown renderer, chat links).

## Impact gate — one click, real state change, victim's session

- The PoC must drive a **one-click (or precisely-aligned multi-click) state change on the
  victim's real session** — delete account, transfer, permission grant, OAuth consent. Name the
  click and the state it changes; "the page can be framed" is the precondition, not the finding.
- A framable page with no sensitive action (marketing, docs, already-public data) is
  clickjacking-on-non-sensitive-pages = the always-rejected list. Drop it.
- SVG-filter pixel reads are graded by what is actually READABLE off the framed page (balance,
  token, MFA state) — if the sensitive region renders empty for a logged-in victim, there is
  nothing to read and the claim dies.

## Report
For clickjacking: show the working overlay HTML and the concrete privileged action it triggers
(1-click account deletion / fund transfer / permission grant beats a demo that "just" reframes a page).
For reverse tab-nabbing: show `window.opener` is reachable and redirects the origin tab.
