# Moraa — CSRF (state-changing action forged from another origin)

> HackTricks `csrf-cross-site-request-forgery`. Cross-ref [[cors]] (CORS can LEAK the CSRF token
> itself → ATO chain), [[open-redirect]], [[xss]] (XSS defeats any CSRF defense trivially).

## Is it exploitable? (check before building the PoC)
1. **A valuable state-changing action** (email/password change, fund transfer, privilege grant, add-SSH-key).
2. **Ambient credentials** — cookie sent automatically (not a header-only bearer token an attacker page can't attach).
3. **SameSite on the session cookie** — the gate that decides whether the forgery can fire at all;
   canonical mechanics in `[[cors]] §4` (None rides everywhere · Lax still rides top-level GET
   navigations · Strict blocks cross-site). Determine the actual value before building any PoC.
4. **No unpredictable, session-bound parameter validated server-side** — that's the actual CSRF token; test its validation, don't assume it works (below).

## Token-validation flaws (this is where most "protected" endpoints fail)
| Test | Bypass |
|---|---|
| Remove the token param entirely | accepted if the check is "if present, validate" not "must be present" |
| Send `csrf=` (empty) | some implementations treat empty as valid/skip |
| Send **any other valid token** (even your OWN, reused, or from a different user's session) | token not bound to the current session — proves it's checked for well-formedness, not ownership |
| Change request method: POST→GET (or add `_method=PUT/DELETE`, `X-HTTP-Method-Override`) | CSRF check often only wired to one verb |
| `Content-Type: application/json` → `text/plain` or `multipart/form-data` | dodges preflight (simple request) while many backends still parse JSON body loosely — try urlencoded/multipart too |
| Double-submit cookie pattern | if the token is ALSO sent as a cookie, an attacker who can set cookies on the domain (e.g. via a subdomain) can satisfy the check themselves |
| Referer/Origin check | strip via `<meta name="referrer" content="never">` or navigate via `rel=noreferrer`; bypass a substring/regex check with `https://attacker.com/?victim.com` or `victim.com.attacker.com` |

## PoC template (adapt to method/content-type discovered above)
```html
<html><body>
<form id=f method="POST" action="https://victim/change-email" enctype="text/plain">
  <input type=hidden name='email' value='attacker@evil.com'>
</form>
<script>f.submit()</script>
</body></html>
<!-- GET variant, needs no script, survives stricter contexts: -->
<img src="https://victim/api/delete?id=42">
<!-- iframe delivery to avoid navigating the victim away: -->
<form target=x method=POST action=...>...</form><iframe name=x hidden></iframe><script>document.forms[0].submit()</script>
```

## The chain that actually pays: CORS leaks the token → CSRF → ATO
A CORS misconfig on a GET-only, "no direct impact" endpoint that happens to return the page's CSRF
token turns into full account takeover: read the token cross-origin ([[cors]]), then fire the CSRF POC
above with the stolen token attached. This is a very common H1 chain — always check whether a leaky
CORS endpoint's response body contains a CSRF token before writing off the CORS bug as low-impact.

## Report
State the exact SameSite value, the token-validation flaw exploited (or the fact the endpoint has
NO token check at all), and the concrete action forced — with a working PoC HTML the triager can click.

## THE GATE: curl doesn't enforce SameSite — a curl proof is not a browser proof

This cost real findings on a live engagement. `curl -H "Origin: https://attacker.com" -b
"SESSION=..."` sends the cookie with a spoofed Origin; **a real browser will not.** Before calling
anything CSRF: read the ACTUAL `Set-Cookie` line (`curl -sI ... | grep -i set-cookie`), then apply
the SameSite gate — same-site vs cross-site is the registrable domain (eTLD+1), same-company
domains can still be cross-site, and `Lax` rides only top-level GET navigations. The canonical
reasoning, the `.acme.example`-vs-`.acme-legacy.example` lesson, and the same-site escape live in `[[cors]] §4` —
gate on it, don't re-derive it here. One corollary stays ours: a CORS finding from a same-site
origin is a DIFFERENT bug class that SameSite does not defeat (`[[cors]] §4` "same-site escape")
— don't let a SameSite-driven CSRF retraction sweep it up.

---

## The handler that ignores `Content-Type` — turning a JSON API into a form-CSRF target

A JSON API is usually CSRF-safe by accident: `Content-Type: application/json` is **not** a
CORS-simple type, so the browser preflights, and a cross-origin `OPTIONS` that is not approved
stops the write before it happens. An HTML form can only ever send three types —
`application/x-www-form-urlencoded`, `text/plain`, `multipart/form-data` — none of which produce
valid JSON, so the handler rejects the body.

**Unless the handler ignores `Content-Type` and just parses the body as JSON.** Then a form POST
with a JSON string as the field name delivers a valid request with **no preflight at all**, and the
CORS configuration never enters the picture — the attacker does not need to read the response,
because the write has already landed.

**Test it on every state-changing JSON route, in one batch.** Send the identical body four times:

```
Content-Type: application/x-www-form-urlencoded   <- simple
Content-Type: text/plain                          <- simple
Content-Type: multipart/form-data                 <- simple
Content-Type: application/json                    <- control (preflighted)
```

If any of the first three succeeds, the route is form-reachable. Confirmed live on the enterprise-identity product
2026-10-24: `POST /gw/ent/api/user/org_manager/add_member` created a real workspace member on
**all four**, so member creation needs no preflight.

**A tell to look for before you even test:** the app's own frontend sending a JSON body under
`Content-Type: application/x-www-form-urlencoded`. If the client does that and the server accepts
it, the server is definitionally not checking the type. (On that estate this appeared on
`POST /gw/ent/api/user/org/plan/quota`.)

**Then measure the real gate, which is `SameSite` — do not assume it.** Read it off an actual
`Set-Cookie` rather than guessing:

* `SameSite=None` → cross-site form POST works from **anywhere**. Full CSRF.
* `SameSite=Lax` → a cross-**site** POST is blocked, but `SameSite` is evaluated per site
  (eTLD+1). **Any subdomain of the same registrable domain is same-site**, so attacker-controlled
  content on *any* sibling host still carries the cookie. Pair this with the cookie's `Domain`
  attribute: host-scoped (`Domain=tenant.example.com`) still receives the cookie from a sibling
  origin's POST — host-scoping limits *where the cookie is sent*, not *who can cause the send*.
* `SameSite=Strict` → dead for this vector.

So a `Lax` cookie plus a content-type-blind handler is not "safe", it is **a CSRF gated on one
same-site HTML injection** — the same precondition a credentialed-CORS finding needs, which means
the two share a delivery vector and should be hunted together. Check `base-uri` and `form-action`
in the CSP too: `script-src` says nothing about whether a form may post, and their absence means
the CSP will not restrain it.

**Severity gate:** without a proven same-site delivery vector this is a precondition, not a
finding. With one, it is strictly stronger than a CORS write of the same route, because it drops
the preflight and the origin-reflection dependency entirely.
