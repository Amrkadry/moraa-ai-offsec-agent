# Signed-URL / signed-cookie mints as an authz surface

> Written 2026-10-11 from the enterprise-identity product engagement, where this class produced a confirmed A01
> after the broad role matrix produced nothing. Cross-ref [[cloud]] (CloudFront/S3 mechanics),
> [[idor-access-control]], [[controls-and-oracles]].

## The class, in one line

**A route that mints a signed URL or signed cookie is an authorization decision, and it is routinely
left ungated because "it only returns a cookie".** The sibling route that returns the object *ids* is
gated; the mint next to it is not.

Look for: `*/cf_cookie`, `*/signed_url`, `*/presign`, `*/upload_link`, `*/download_url`, `*/sas`
(Azure), `*/signed-cookie`, `*/token` on a media path. Any endpoint whose whole job is handing out a
credential for a CDN or bucket.

## Why it pays

The mint hands over a capability whose scope is set server-side. Three things go wrong, and they
compound:

1. **No permission check on the mint** while the data route enforces one. Proof shape: the same
   session is denied by permission name on `.../list` but gets `200` + a cookie on `.../cf_cookie`.
2. **Policy scoped to the tenant/workspace, not the caller.** Decode it — if the member's policy is
   byte-identical to the admin's, the scope is not caller-derived at all.
3. **Scope segment derived from a client-supplied parameter with no ACL check.** On that estate the
   access-control mint built its path segment from `md5(site_id)[8:24]`, so the caller named the site:
   `?site_id=aaaaaaaaaaaaaaaa` -> segment `02f49b3ea5592b14`. Always diff the segment while moving
   each parameter; a param that moves the segment but is never authorized is the bug.

## Decode recipe

CloudFront policies are base64url with `~` padding:

```bash
node -e 'console.log(Buffer.from(process.argv[1].replace(/-/g,"+").replace(/_/g,"/").replace(/~/g,"="),"base64").toString())' "$POLICY"
```

Read `Resource` and `DateLessThan`. A `Resource` of `https://*/prefix/<tenant>/*` is tenant-wide: every
object under the prefix, not the caller's. Some mints return the cookie in the JSON body, others only
in `Set-Cookie` — capture both (`curl -D hdrs.txt -c jar.txt`), or you will wrongly conclude the mint
returns nothing useful.

## The tests, in order

```bash
# 1. is the mint gated at all? (low-priv session)
./probe.sh member GET /gw/<svc>/api/v1/.../cf_cookie
# 2. is the caller denied the DATA route? -> this is what makes the mint a privilege gap
./probe.sh member POST /gw/<svc>/api/v1/.../list
# 3. is the policy caller-scoped? decode member vs admin and compare
# 4. is the scope segment client-controlled? move each param, re-decode, diff the segment
# 5. is the capability bound to anything? replay with NO session cookie at all
# 6. does a sibling mint enforce a permission? -> proves the gate exists and is just missing
```

Step 6 is the one that makes a report land: "`report`, `risk` and `systemlog` gate their mint;
`announcement` does not" is far stronger than "this endpoint is ungated", because the fix is applying
an existing control rather than building one.

## The trap that costs you the finding

**An SPA distribution that maps missing objects to `index.html` destroys the signed-vs-unsigned
oracle.** On that estate, the tenant host and `portal.*` returned `200` + 2066-byte `index.html` for *every*
media path, signed or not — identical responses, which reads exactly like "the signature is not
honoured". The real distribution (`cf1/cf2.tenant-cdn.acme.example`) returned `403` unsigned and `200` + the actual
`image/png` signed. A subagent burned a whole run concluding the host was unfindable because it tested
the wrong hosts and, on the right ones, paired them with a policy for a different path prefix.

Rules that follow:
- **Pair the policy with the prefix it was minted for.** A access-control cookie on an announcement path
  is a guaranteed 403 and tells you nothing about the host.
- **Find the distribution via DNS, not guessing**: CloudFront ranges (`108.159.*`, `3.175.*`, `13.*`)
  and `cf1`/`cf2`-style names in the CSP `media-src` or in the `signed_cookie.domain`/`path` fields.
- **You need one REAL object key** to get a usable oracle, because a nonexistent key may fall through
  to the SPA. Keys are usually `<date>/<uuid>` and unguessable — get one by uploading through a role
  that is allowed to, then read it back as the low-priv role.

## Grading the severity honestly

Unguessable object keys are a **secret, not an access control**, so an ungated tenant-wide mint is a
real finding — but exploitation needs a key. Medium alone; High the moment any route reachable by the
low-priv role emits a key (`cf_url`, `unique_id`, capture id, attachment id). Hunt that key oracle
before writing the report, and say plainly in the report which half you proved.

Two negatives worth firing so you do not overclaim:
- **Cross-tenant**: swap the tenant hash in the path. If the segment is session-derived you get 403,
  and the finding is workspace-scoped — say so.
- **Validation-before-authz**: a malformed body may return a *validation* error from a route that would
  have denied you on permissions. Re-send with VALID params before calling it a bypass. On that estate the
  announcement upload_link looked reachable (`E_C_PARAMS_INVALID`) and was correctly gated
  (`announcement.notice.add`) once the body was valid. See [[framework-misconfig]] for the
  400-vs-403 trap generally.

## Hunting the key oracle (do this before you grade the severity)

An ungated tenant-wide mint is capped at Medium while object keys stay unguessable, so the severity
question is entirely "can the low-priv role learn a key?". Hunt it in this order, and write the result
down either way — a documented negative is what stops the next session re-inflating the finding:

1. **The notification / activity / feed service.** Most under-probed surface on an enterprise app and
   usually readable by the lowest role, because it is "just your own messages". On that estate,
   `/gw/notification/api/v1/message/list` was member-ALLOW with 39KB of payload that no other sweep had
   touched. Grep it for `\.(png|jpg|pdf)`, `rich_text_img`, `avatar`, `url`, `key`, `path`, and for any
   id field (`site_id`, `unique_id`, `ticket_id`).
2. **The `/me/` or self-service tree, which is often a SEPARATE route family from the admin tree.**
   `/workspace/anns/*` was permission-gated; `/me/anns/<uuid>` existed, was undocumented, and was
   member-reachable. Always try `me`, `my`, `mine`, `self`, `user`, `end_user` as a sibling of the
   admin path — a gated admin tree does not mean the data is gated.
3. **Then test that tree for IDOR properly**: you need an object the low-priv role is NOT a recipient of.
   Get its id from the privileged list route, not by guessing. Beware the 404-ownership pattern — if the
   ADMIN also gets `NOT_EXIST` for that id, the route is ownership-scoped rather than role-scoped and
   there is no bug. (That is exactly how that estate's `/me/` tree came back clean.)
4. **Error strings leak the internal route prefix.** `url not found /api/v1/authorized/me/anns` revealed
   the gateway's internal rewrite namespace, which is worth collecting for later route discovery.
5. **A partial oracle still matters.** The feed leaked a real `site_id`, and minting with it reproduced
   the `md5(site_id)[8:24]` segment exactly — which proves the derivation on real data and closes one of
   two unknowns. Report partial oracles as such: "attacker can obtain X, still needs Y".

## The SECOND trap: an expired policy is byte-identical to an unsigned one

Sibling of the SPA-fallback trap above, and it survives doing everything else right. Some mints carry
a `DateGreaterThan` as well as a `DateLessThan` — on that estate the announcement mint was valid for exactly
**300 seconds** while the identity/access-control/support mints ran ~1746 s. Save that cookie to a file, do
five minutes of host-hunting, replay it, and CloudFront serves its custom error page — **the same
bytes as the unsigned request**. That reads exactly like "the distribution does not honour the
signature", and it is how a run concludes "host unfindable" while holding a working primitive.

```bash
# decode the window BEFORE you trust any fetch result
node -e 'const p=JSON.parse(Buffer.from(process.argv[1].replace(/-/g,"+").replace(/_/g,"/").replace(/~/g,"="),"base64"));
  const c=p.Statement[0].Condition, now=Math.floor(Date.now()/1e3);
  console.log("valid_for",c.DateLessThan["AWS:EpochTime"]-now,"s; not_before",c.DateGreaterThan?.["AWS:EpochTime"]??"-")' "$POLICY"
```

Rules:
- **Re-mint immediately before every fetch. Never replay a cookie from a saved header file** — one
  mint, one fetch, in the same command.
- When signed and unsigned responses are byte-identical (`cmp -s` SAME), **check the clock before you
  blame the host.** Expired policy and wrong host look identical; only one is cheap to rule out.
- A custom S3/CloudFront error page is what makes this silent. `AccessDenied` XML, `MissingKey` XML and
  a themed 403 HTML page are three different signals — a distribution with a custom error response
  collapses them all into one, so you cannot distinguish missing-object from missing-signature.

## Enumerating mints: grade on Set-Cookie, not on the body

A path sweep that greps response **bodies** for `cloudfront_policy` will under-count the mint
inventory, because some mints return only `{"code":"SUCCESS","data":{"expired_at":...}}` (52 bytes) and
deliver the policy in `Set-Cookie`. On that estate a 189-path sweep missed the single broadest mint on the
target for exactly this reason. Grade on the header:

```bash
# a mint is anything that sets a CloudFront-* cookie, whatever its body says
curl -s -D - -o /dev/null -k -x http://127.0.0.1:8080 -H "Cookie: $CK" "https://$H$P" \
  | grep -qi '^set-cookie: *CloudFront-' && echo "MINT $P"
```

And do not enumerate blind — **mine the bundles for the route literal next to its prefix**. That is how
that estate's `workflow-form` mint surfaced after the path sweep had already "finished":

```bash
grep -ohE '"/[a-z0-9_/.-]*cf_cookie"' bundles/*.js | sort -u          # relative literals
grep -ohE 'prefix:"/[a-z0-9-]+/api/v?[0-9]*"' bundles/*.js | sort -u  # the prefixes to join them to
```
Fire the per-service existence oracle before enumerating a new prefix: a subtree whose absent routes
answer `E_C_INVALID_REQUEST` (or any single catch-all) gives you **no** existence signal, so path
enumeration there is 100% noise and the only way in is a literal from the bundle.

## Severity ladder: count the segments the policy PINS

Compare the mints on one target and grade by how much of the key space is wildcarded, not by the
endpoint's name. The five mints on that estate, worst last:

| mint | Resource | pinned |
|---|---|---|
| identity avatar | `/cdn/*/avatar/<tenant>/*` | category `avatar` |
| announcement | `/announcement/u/{avatar,rich_text_img}/<tenant>/*` | tier + category |
| helpdesk | `/feedback/*/ticket/<org>/*` | category `ticket` |
| access-control | `/access-control/thumbnail*/<tenant>/<site>/*` | category glob + site (site is caller-named) |
| **workflow-form** | **`/workflow-form/*/<tenant>/*`** | **nothing but the tenant** |

An `/admin/`-looking path is not the tell — `admin/thumbnail/cf_cookie` was ungated and
`admin/visitor/avatar/cf_cookie` enforced `visitor.edit`. The tell is the **unpinned category
segment**: it collapses every object class of that service into one cookie, which on a workflow
service means every attachment on every HR/approval/expense form in the tenant. Rank the mint with
the fewest pinned segments first and hunt its key oracle first.

## THE CACHE TRAP — read this before you believe any signed-vs-unsigned result

A CDN that caches the **negative** response will destroy this oracle in both directions. Measured on
CloudFront (the enterprise-identity product, 2026-10-11), on two freshly-created objects:

| Object | 1st request | 2nd request |
|---|---|---|
| A | unsigned -> 403, `X-Cache: Error from cloudfront` | signed -> **403** (the cached error, a FALSE NEGATIVE) |
| B | signed -> **200**, `X-Cache: Miss from cloudfront` | unsigned -> 403 |

Once any unsigned or invalid request touches a URL, the 403 is cached (observed `Age` up to ~150s) and
is then served **even to a request carrying a perfectly valid signed cookie**. Both failure directions
are real and both have cost real engagement time:

- **False negative:** you probe unsigned first "to establish the baseline", poisoning the cache, then
  conclude the signature is not honoured and abandon the correct host. This is exactly how a run
  reported `cf1/cf2` as returning "byte-identical 403 signed and unsigned" and wrote off the right
  distribution.
- **False positive:** a `200` can be a cached hit populated by someone else's *authorised* fetch, so a
  200 does **not** prove your credential was accepted.

Rules:
1. **Fire the SIGNED request FIRST, on a virgin object**, before anything unsigned touches that URL.
2. **Require `X-Cache: Miss from cloudfront`** on the success. A Miss means the edge went to origin and
   the ORIGIN validated your signature. `Hit` proves nothing about your credential.
3. Create your own virgin object through a privileged identity when you can — it guarantees a clean
   cache key and gives you known-good bytes to `cmp` against.
4. Log `X-Cache`, `Age` and `X-Amz-Cf-Pop` on every probe. Without them this class is unfalsifiable.
5. Watch for `DateGreaterThan = mint time` in the policy: a fetch racing the edge clock is rejected as
   not-yet-valid, which looks identical to a rejected signature.

**The upload-link route often volunteers the CDN host.** On that estate, the admin-only
`anns/img/upload_link` response contained `img_full_url: https://cf1.tenant-cdn.acme.example/...` alongside the S3
presigned `url` — the server naming its own distribution. If you are hunting for the serving host, read
the *write* path's response before resorting to DNS or CSP mining.

## Closing the key-oracle question properly: enumerate the EMITTERS, then grade

"I could not find a key" and "the keys are structurally gated" are different reports and only the
second one is defensible. Turn the first into the second like this:

1. **Enumerate every route in the service that emits a key**, from the route table, not from guesses.
   On that estate's access-control service that was exactly three: `resource/resource_cf_url`, `resource/cf_cookie`,
   `resource/archived/list` (plus `resource/archived/{uuid}` which returns
   `capture_image_id`/`capture_video_id`).
2. **Recover each one's parameter shape from the bundle call site**, because an
   `E_C_PARAMS_INVALID`/`400` is validation-before-authz and will hide the real verdict. Reading the
   call site gave `{page_num,page_size,start_at,end_at,user_id,door_id}` — guessing never would.
3. **Re-test each with VALID params.** If they all deny the low-priv role with the *same* permission
   while the mint denies nothing, you have an evidenced ceiling: name the missing primitive, name what
   would unblock it, and name which findings it caps (see [[engagement-ceiling]]).
4. **Check whether the data even exists.** `admin -> archived/list` returned `total:0` — an empty test
   workspace. State that in the submission instead of implying the data was there; it is an
   evidence-availability limit, not a control, and a triager who spots the gap will discount the rest.

A mint whose key-emitters are *all* gated by one permission is the strongest version of the finding,
because the single missing decorator is obvious and the fix is unarguable.

### Reading minified bundles without hanging the shell

`grep -ohE '.{0,200}needle.{0,200}'` over a 5-13 MB webpack bundle routinely exceeds a two-minute
tool timeout — it backtracks. Use `indexOf` instead; it is instant:

```bash
node -e 'const s=require("fs").readFileSync(process.argv[2],"latin1");let i=-1,n=0;
 while((i=s.indexOf(process.argv[3],i+1))!==-1&&n++<3) console.log(s.slice(Math.max(0,i-300),i+300))' bundle.js "resource/archived"
```
Build the route table the same way — `prefix:"..."` offsets and quoted-path offsets collected in one
pass, each path joined to its nearest prefix by byte distance, keeping the distance as a confidence
column (under ~4000 bytes was reliable on that estate; 493 routes across 19 services from 15 bundles).

## The tenant/scope segment is usually a HASH of a disclosed identifier — compute it, don't assume

The opaque hex blob in the middle of a signed-cookie `Resource` looks like an internal id. It usually
is not. On that estate every tenant segment across five services was a slice of `md5(org_uuid)`, and the
site segment was `md5(site_uuid)[8:24]` — with the company and site UUIDs both handed to the
LOWEST-privileged role by a member-ALLOW route (`GET /gw/access-control/api/v2/admin/access/sites/`).

```bash
# you have the policy segment and a tenant/site UUID from any API response — test the derivation
ID=ddb2d08f-1add-4fc4-a319-135710aba95b
printf '%s' "$ID" | md5sum                    # full 32 → /cdn/*/avatar/<32hex>/*
printf '%s' "$ID" | md5sum | cut -c1-16       # [0:16]  → /feedback/*/ticket/<16hex>/*
printf '%s' "$ID" | md5sum | cut -c9-24       # [8:24]  → /access-control/*/<16hex>/<site>/*
```

Try the full hash and both 16-char slices against every segment you have collected; one will match,
and then the whole key namespace is computable. Two consequences for the write-up:

- **Kill the "paths are unguessable" mitigation before the vendor raises it.** If every directory
  level is a hash of a disclosed id, the only secret left is the per-object filename, and path
  obscurity contributes nothing. Say so explicitly in the report.
- **Do not overclaim it as cross-tenant.** Computing a foreign tenant's prefix is worthless without a
  signature scoped to it, and a correctly-built mint pins the tenant from the session. Verify that
  (`?company_id=`, `?workspace_id=`, `?tenant=` tampering → segment unchanged) and report the
  derivation as *defence-in-depth collapse*, not as tenant isolation failure. Getting this distinction
  wrong is how a solid Medium turns into a rejected "Critical".

### And hunt the scope-id ENUMERATION route, not just one leaked id
A single leaked scope id makes the caller-named-scope bug opportunistic; an enumeration route makes it
systematic. Look for `*/sites`, `*/locations`, `*/buildings`, `*/groups`, `*/tenants`, `*/count` —
and check them with the LOW-PRIV session, including under an `/admin/` prefix, because on this estate
the `/admin/`-named routes were repeatedly the ungated ones. See [[controls-and-oracles]] Case 11 on
why an `/admin/` path segment is not a security signal.

## Prove the pattern in a SECOND service before you write the report

One ungated mint reads as an oversight and invites "working as intended". The *same* omission in two
services, each with a correctly-gated sibling enforcing a *named* permission, is a systemic wiring
defect — and that reframing is worth more than any extra payload. On that estate:

| service | gated data route | permission it enforces | ungated mint for the same data |
|---|---|---|---|
| access-control | `/resource/{resource_cf_url,cf_cookie,archived/list}` | `access.captures_list.view` | `/admin/thumbnail/cf_cookie` |
| workflow-form | `/approvals/{id}` | `workflow.approval_list.view` | `/resource/cf_cookie` |

So after you confirm the first one, **go find the sibling pair in every other service that has a
mint.** For each mint, identify the data route that serves the same objects and record the permission
it enforces. The deliverable is that two-column table; the remediation then writes itself — "apply
the permission the sibling already enforces" — and the vendor cannot argue design intent when their
own code enforces it one route over.

Check the denial is route-level, not id-dependent, before claiming the data route is gated: fire the
same route with several `{id}` values (`me`, `todo`, `mine`, `all`, `1`) and confirm an identical
byte-for-byte denial. If one value slips through, the gate is on the id, not the route, and you have
a different (often better) bug.

---

## Server-SIGNED RESPONSE bodies: the duplicate-key forgery test

A newer pattern (seen on the vendor's the camera/NVR product evidence registry, `surveil.svc.acme.example`, r4 2026-10-14):
instead of minting a signed **URL**, the service **ECDSA-signs its own JSON response body** and ships
the signature in a header, with the verifying public key chained to a root pinned inside the client
bundle:

```
X-Registry-Sig:        <base64 ES256-P1363 over the exact response bytes>
X-Registry-Key-Id:     protect-api-evidence-registry-v1
X-Registry-Sig-Alg:    ES256-P1363
```

The client refuses to trust anything whose signature does not verify, so the usual "tamper with the
response" attacks are dead. **But the response body almost always echoes caller-supplied path or
query parameters back** (`{"status":"not_found","signerId":"<yours>","keyId":"<yours>",...}`). That
makes the endpoint a **chosen-plaintext signing oracle**, and it opens one specific, high-value test:

> If the echoed parameter is interpolated into the JSON **without proper escaping**, inject a
> duplicate key that flips the verdict. `JSON.parse` keeps the **last** occurrence of a duplicate
> key, so a body of
> `{"status":"not_found","signerId":"a","status":"found","x":"",...}`
> parses as `status === "found"` — **and the server signed it.** You have forged a validly signed
> authoritative answer without ever touching the private key.

### Test it like this (one request, always worth firing)

```bash
# 1. POSITIVE CONTROL first — prove the parameter really reaches the signed body
curl -s -D - 'https://host/api/v2/thing/a%22b/k1'      # expect "signerId":"a\"b"  (quote arrives, escaped)

# 2. the forgery attempt
curl -s -D - 'https://host/api/v2/thing/a%22%2C%22status%22%3A%22found%22%2C%22x%22%3A%22/k1'
#            = a","status":"found","x":"
```

- Reflected **and** `\"`-escaped (Go `encoding/json`, `json.dumps`, `JSON.stringify`) -> CLEAN, and
  the oracle only ever signs `not_found` bodies. Record it as a clean negative **with the positive
  control**, because "no change in the response" alone does not distinguish "escaped properly" from
  "parameter never reached the body".
- Reflected **raw** -> stop and write it up. Also try the same injection in every other echoed field,
  and try injecting the fields the client cross-checks (`attestationId`, `sourceSha256`, `exportId`)
  so the forged body survives the client's own consistency checks.

### The three other things to check on a signed-response design

1. **Is the signature computed over anything that binds the request?** If the body omits the
   parameter that was asked for, a signed answer for object X can be replayed as the answer for
   object Y. (Protect binds it: the client compares every echoed field against the file it holds.)
2. **Is `responseValidUntilMs` / `expiresAt` actually enforced by the client?** If the field is only
   type-checked and never compared to `Date.now()`, a captured signed response is valid forever —
   which defeats **revocation** (a revoked key can still be "proven active" by replaying the old
   signed response). Only exploitable with a response-injection position, so rate it accordingly.
3. **Which key does the client verify with — the registry's, or the one the file/attacker supplied?**
   Grep for the verify call and check its first argument. `verifySig(registryResponse.publicKey, ...)`
   is correct; `verifySig(fileEnvelope.publicKey, ...)` is a total break. Also check whether a
   trust-origin field inside the attacker's own file (`registry_base`, `issuer`, `jku`-style) is ever
   used to build the fetch URL — if it is, a malicious file points verification at an
   attacker-controlled registry and self-certifies.

---

## Cross-distribution key-group reuse: replay a HARVESTED `Key-Pair-Id` before you go hunting a mint

The expensive blocker on every private-distribution lead is "I hold no legitimate signature". There
is a question you can answer **without** one, for five requests, and it is worth asking first
because a yes is a cross-service break:

**Does distribution B trust the key pair that distribution A signs with?**

CloudFront validates in order: is the `Key-Pair-Id` in **this distribution's** trusted key group ->
does the signature verify -> is the policy still in date. So the *first* stage answers the trust
question on its own, and an **expired** signature is perfectly adequate for it — you never reach the
date check.

```bash
# any well-formed triple; the Policy/Signature values are deliberately junk
POL='eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly90YXJnZXQuZXhhbXBsZS5jb20vKiIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6OTk5OTk5OTk5OX19fV19'
for K in $(cat harvested-key-pair-ids.txt); do
  printf '%-22s %s\n' "$K" "$(curl -s "https://target.example.com/media/x.mp4?Key-Pair-Id=$K&Signature=AAAA&Policy=$POL" | grep -o '<Code>[^<]*')"
done
```

| Response | Meaning |
|---|---|
| `<Code>MissingKey</Code>` | you sent no/incomplete triple — fix the request, this is not a result |
| `<Code>InvalidKey</Code>` *Unknown Key* | **not trusted here.** Key groups are isolated between these distributions |
| anything else (`AccessDenied`, `InvalidSignature`, `200`) | **the key pair IS trusted here** — escalate hard: a signature minted by service A is replayable against service B, so find A's mint (which may be ungated, see above) and sign for B's media |

### Harvest the ids from your own engagement directory first — they are already there

```bash
grep -rIoh 'Key-Pair-Id=[A-Za-z0-9]\{8,\}'        . | sort -u
grep -rIoh 'CloudFront-Key-Pair-Id[=:][^&";, ]*'  . | sort -u
```

Any avatar/thumbnail/attachment CDN you have already browsed as an authenticated user has set one of
these cookies. On the vendor estate this yielded four real ids from the community avatar mint
(`recon/parsed.json`, policy resource `.../avatar/<md5frag>/*/*`) at zero marginal cost.

### Grade the negative honestly

`InvalidKey` across the board proves *not trusted at this distribution*. If the harvested policies
had already expired you cannot also claim *proven trusted elsewhere* — so write
"cross-service signature replay is closed" and state the limit. The `MissingKey` -> `InvalidKey`
transition is itself the control that the distribution really parses and checks the triple rather
than serving a canned page; record it.

### And test the environment siblings while you are there

prd/stg/dev of the same service are usually separate distributions with separate key groups. Running
the same five ids across all three costs nothing and closes "could I sign for prd using the dev key
pair" with evidence. Measured on `protect.{,dev.,stg.}svc.acme.example`: all `InvalidKey`, no sharing in
either direction.
