# Moraa — Shadow / zombie API discovery

> Sourced from elementalsouls/Claude-BugHunter `hunt-shadow-api`. Cross-ref [[idor-access-control]]
> (v1-vs-v2 authz gap is the same pattern), [[recon]], [[js-analysis]] (mobile-app APIs referenced in bundles).

## The core insight
Old API versions rarely get security fixes backported. Find one still alive → it's usually the
weakest door into the same data the current, hardened version protects.

## 1. Discover live versions
```bash
# path-based
for v in v1 v2 v3 beta alpha internal legacy 2022-01-01 2023-01-01; do
  curl -s -o /dev/null -w "%{http_code} $v\n" "https://$TARGET/api/$v/"
done
# header-based
curl -s -H "X-API-Version: 1" https://$TARGET/api/users
curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/users
# subdomain-based
for sub in api api-v1 api-v2 legacy-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
```

## 2. Pull specs and diff them
```bash
for path in openapi.json swagger.json v1/swagger.json api-docs.json; do
  curl -s "https://$TARGET/$path" -o "$path"
done
# Wayback for specs that existed and were pulled
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*swagger*&output=json"
# diff the route inventory
jq -r '.paths|keys[]' v1-swagger.json | sort > v1.txt
jq -r '.paths|keys[]' v2-swagger.json | sort > v2.txt
comm -23 v1.txt v2.txt   # routes that ONLY exist in v1 — your candidate list
```

## 2b. The spec is a MISSING-AUTH oracle, not just a route list

A spec carries each route’s **security requirement** alongside its path. That turns
one benign GET into “which routes have no auth” — answered **without touching any
of them**. FastAPI (and most Spring/NestJS generators) serve the spec
unauthenticated by default.

```bash
curl -s "https://$TARGET/openapi.json" -o spec.json

# routes with NO security requirement at all -> candidate unauth surface
jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[]
       | select(.value.security == null and .value.operationId != null)
       | "\(.key|ascii_upcase)\t\($p)"' spec.json | sort -k2

# the differential that MAKES it a finding: same resource family, split verdict
jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[]
       | "\(if .value.security == null then "NONE" else "AUTH" end)\t\(.key|ascii_upcase)\t\($p)"' \
  spec.json | sort -k3
```

**Read the split, not the count.** A spec where *everything* is `NONE` usually
means the generator was never told about the auth dependency — no signal. The
finding is when **sibling routes on the same resource disagree**: five management
routes carry a scheme and four omit it. That asymmetry is an *omission*, which is
a bug; uniform absence is a *design*, which is not.

Corroborate before claiming it, because a spec can lie in both directions:

- auth applied as **middleware or a path-prefix mount** never appears in the spec
  at all — so `NONE` can still be gated (this is exactly the MCPHub false
  positive: *read the mount point, not the route list*)
- a declared scheme can be **unenforced** — so `AUTH` can still be open

So the spec **ranks** the candidates; one request per candidate settles it. Pair
each hit with a sibling that *does* require auth and fire both in the same run —
a **401 control beside a 200 attack** is the whole proof, and it is what survives
triage.

> Cheap passive oracles of the same shape, worth trying before anything
> intrusive: Ray `GET /api/authentication_mode` (`"disabled"` ⇒ unauth job
> submission = RCE), Spring `/actuator/mappings`, and any
> `/swagger-resources`/`/v3/api-docs` sibling.

## 3. Prove a behavioral regression (not cosmetic difference)
Test the SAME probe on old vs. new version and compare:
- **Auth strength:** does the old version accept an expired/low-priv token the new one rejects?
- **Rate limiting:** identical burst — does the old version skip the 429 the new one enforces?
- **Input validation:** identical injection/oversized/malformed payload — old version processes it, new one blocks it?
- **Field exposure:** does the old version's response body leak internal IDs/PII the new one redacts?

## 4. Find the routes nobody documented
- Grep JS bundles for API calls the current UI never triggers (`/internal/`, `/admin/`, `/debug/`) — [[js-analysis]]
- `robots.txt` / `sitemap.xml` disallow lists
- **Mobile APK/IPA teardown** — the mobile app frequently talks to an OLDER backend version than the web app does; decompile and grep for base URLs/endpoints

## 5. Fuzz the VERB, not just the path
Route discovery is almost always GET-only, so routes that exist only under POST/PUT/PATCH/DELETE
are invisible to a standard content scan — and those are exactly the state-changing ones. Two sweeps:
```bash
# A) one known path, every method — find write verbs the UI never issues
ffuf -u https://T/api/v1/users/1 -X FUZZ -w methods.txt -mc all \
     -H "Authorization: Bearer $TOKEN"
# methods.txt: GET POST PUT PATCH DELETE HEAD OPTIONS TRACE COPY MOVE LOCK PROPFIND SEARCH REPORT
# B) OPTIONS sweep across discovered paths — Allow: header hands you the route's real verb set
while read p; do
  printf '%-45s ' "$p"; curl -sk -X OPTIONS -D- -o /dev/null "https://T$p" | grep -i '^allow:'
done < paths.txt
```
Read a `405` as "path exists, wrong verb" — a route-existence oracle even when GET 404s — and a
401/403 on one verb but 200 on another as a per-verb authz gap. Then apply the existing §3
regression test: does the undocumented verb skip the validation/authz the documented one enforces?
(GET→PUT/DELETE swap → `idor-access-control.md`.)
Reference: https://www.intigriti.com/blog/business-insights/31-bite-sized-tips-techniques-and-bug-bounty-resources-to-kick-off-2026

## Severity
| Finding | Level |
|---|---|
| Old version bypasses auth the new one requires | Critical |
| Old version skips rate-limiting the new one has | Med-High |
| Old version leaks PII/internal fields the new one redacts | Med-High |
| Old version accepts payloads the new one validates against | High |
| No behavioral difference | Info — not a finding |

**Gate:** confirm with a payload that behaves DIFFERENTLY old-vs-new, not just a cosmetic response diff.

## Impact gate — the old version must BEHAVE differently, not just differ

The falsifier is a differential: the SAME probe against old and new, where old processes what new
rejects — an expired/low-priv token accepted, the 429 skipped, a payload new validates away but
old executes, a PII field present on old and redacted on new.

- Version-only signals (older banner, a 404-vs-410 route, a spec diff with no tested delta) are
  inventory, not findings — without the behavioral delta the severity table above collapses to
  "Info — not a finding".
- No behavioral difference on the probes you ran = write the CLEAN negative naming the probes, so
  the next run doesn't re-fuzz v1 from scratch.

---

## The ALB 403-vs-404 oracle — enumerate the EDGE's rule set, not the app
*(Added 2026-10-01, from `endpointsvc.svc.acme.example` / `support.endpointsvc.svc.acme.example` on the vendor estate.)*

When a host answers `server: awselb/2.0` with **no CDN in front**, the ALB listener rules usually
*are* the route allowlist, and they leak themselves through a two-value status split:

| Response | Meaning |
|---|---|
| `403` + ~118-byte nginx-style `<html>…403 Forbidden…` body | path matched NO listener rule — the ALB's default action. Never reached the app. |
| the application's own 404 (e.g. `{"message":"Not Found"}`, or Go's `404 page not found`) | path WAS forwarded — it is inside an allowlisted rule, just not routed by the app |

So a path sweep stops being "guess the app's routes" and becomes "read the edge's rule list". You
learn the allowed **prefixes** even when every path under them 404s, which tells you where the real
routes live and lets you aim a much smaller, politer wordlist.

```bash
# oracle: 403 => not in ALB rules; anything else => reached the app
for p in /api/v1/foo /api/v1/bar; do
  printf "%-40s " "$p"
  curl -s -o /tmp/r -w "%{http_code} " "https://$H$p" -H "Cookie: $SESS"
  head -c 80 /tmp/r | tr -d '\n'; echo
done
```

Probe `/<prefix>`, `/<prefix>/`, and `/<prefix>/zzz` for each candidate: a rule written as
`/api/v1/msps/*` gives app-404 on all three, while an exact rule like `/api/v1/products/plans`
gives ALB-403 on `/api/v1/products` and `/api/v1/products/zzz`. That difference maps wildcard rules
versus exact rules for free.

**Pair it with the v1-vs-v2 check.** On the host above only `/api/v2/products/plans` existed — every
other `/api/v2/*` was ALB-403. One request per version per route tells you in seconds whether a
weaker older/newer twin is even deployed, before you spend an hour hunting an authz gap in it.

### The trap: do NOT mistake the ALB default action for a rate ban
Mid-sweep the unknown-path responses can appear to flip from app-404 to 403 and read exactly like an
edge rate-limit kicking in — which would mean discarding the whole result set as noise.

Before declaring a ban, **re-fire a path you have already seen return the application's own 404.**
- A rate ban hits *every* path, including that one.
- A listener-rule 403 does not — the known-good path still reaches the app.

On the engagement that produced this note the "ban" was an illusion created by a `tail -40` hiding
the earlier 403s; the real ban-check took three requests and saved a valid result set from being
thrown away. Record which it was in the tracker, because "I discarded the sweep" and "the sweep was
clean" are very different entries for the next pass.
