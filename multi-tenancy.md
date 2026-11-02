# Moraa — Multi-Tenancy / Tenant Isolation (SaaS #1 question)

> "Can tenant A read tenant B's data?" is THE question on SaaS targets, and [[idor-access-control]]
> only half-covers it: object-level IDOR is per-object, tenant isolation is per-BOUNDARY — every
> object you can touch carries a tenant, and the bug is anywhere that boundary is derived from
> client input instead of the session. Cross-ref [[idor-access-control]] (the two-account
> discipline this doc extends), [[jwt]] (claim-forged tenant), [[mass-assignment]] (tenantId as a
> bindable field), [[business-logic]] (invitation/role-mapping flows).

**Standing rule (same as IDOR): a single-account "fake tenant id" test proves NOTHING.** A 404 or
`NOT_FOUND` on an invented tenant is the correct answer for both "not yours" and "doesn't exist" —
the [[idor-access-control]] fake-id trap, one level up. You need TWO REAL TENANTS, or valid data
on a foreign object. Good news: you can usually mint the second tenant yourself (§5).

## 1. Where the tenant id lives — test EACH position

```bash
# A two-tenant setup of your own: T1 (yours) and T2 (your second tenant — §5).
# For each position, capture T1's real request, then swap in T2's identifier — with T1's session.
H="https://app.target.com"
T1="acme-8f3a"            # your tenant slug/id as the app really writes it
T2="globex-9d21"          # your second tenant's real id
```

| Position | What you capture | The swap |
|---|---|---|
| **Path** | `/t/acme-8f3a/projects` | `GET /t/globex-9d21/projects` with T1 session |
| **Subdomain** | `acme.app.target.com` | same request against `globex.app.target.com`, T1 cookie jar |
| **Header** | `X-Tenant-Id: acme-8f3a` / `X-Org-Id` | replay with `X-Tenant-Id: globex-9d21` |
| **JWT claim** | decode your token: `{"tid":"acme-8f3a",...}` | see §3 — forging is a different test |
| **Body param** | `"tenantId":"acme-8f3a"` / nested `"org":{"id":...}` | create/update calls with the foreign value injected (that's also the [[mass-assignment]] play) |
| **Query param** | `?org=acme-8f3a` | same swap, often forgotten server-side when the SPA always sends it |

**Proves the bug:** T1's session returns T2's data, or a write under T2's identifier succeeds and
is visible from T2. Accept-but-ignore (the value is read then discarded, identity resolved from
the session) is the inert case — the response must REFLECT the foreign tenant, per the
[[idor-access-control]] discipline.

## 2. The cross-tenant matrix — four cells, four meanings

Run every read AND write endpoint against all four cells; the interesting column is what each
result means:

| Cell | Own object? | Own tenant? | Meaning when it SUCCEEDS for T1's session |
|---|---|---|---|
| 1 | yes | yes | baseline — nothing to report |
| 2 | yes | **no** (your object re-parented / id used in T2 context) | **tenant-boundary bypass** — the object-level check passed but the tenant scoping didn't; strongest single finding |
| 3 | **no** | yes | plain IDOR inside your tenant — [[idor-access-control]] class, report as such |
| 4 | **no** | **no** | **full cross-tenant read/write** — the SaaS-killer; prove with T2's REAL object ids and T2-visible effects |

Cell 4 is the money cell; cell 2 is the subtle one people skip (it appears when ownership checks
are object-scoped but list/search/export routes are tenant-scoped by a client-supplied value).
Build the matrix per endpoint family — read, write, delete, export, search — one family at a
time, and record coverage in `coverage.md`.

## 3. Tenant from JWT claim vs resolved server-side

```bash
# decode your token and see WHERE tenant lives:
python3 - "$TOKEN" <<'PY'
import base64, json, sys
p = sys.argv[1].split('.')[1]; p += '=' * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
PY
```
- **Claim-carried tenant (`tid`, `org_id`, custom claim):** the client TELLS the backend who it
  is. If the claim is trusted without re-resolution, forging is the test — alg confusion / weak
  secret / `jku`-style claim injection per [[jwt]], swap `tid` to T2's value, replay. Accepted +
  T2 data returned = the whole tenancy model rides on a forgeable token. That's Critical on its own.
- **Server-resolved tenant (session → DB lookup → tenant):** claim-forgery is dead on arrival —
  your only road is the positions in §1 (header/body/path where a client value overrides the
  resolved one). Don't burn time attacking the JWT if the tenant is session-resolved; DO test
  whether any endpoint accepts a tenant override header that short-circuits the resolution.

## 4. Shared-resource leakage — the boundary is broken where the tenant ISN'T the unit

Isolation usually dies on the resources that are scoped by query, not by ownership:

```bash
# SEARCH: does the index filter by tenant? (T1 session, T2 object's known-unique string)
curl -s -b jarT1.txt "$H/api/search?q=<unique-string-from-T2-data>" | jq '.results|length'
# EXPORTS: report/CSV generation often queries by id only:
curl -s -b jarT1.txt "$H/api/exports" | jq '.[].id'    # then fetch T2's export id if any leak
# FILE STORAGE: predictable per-tenant paths (T2 filename patterns from your own T2 uploads):
curl -s -o /dev/null -w '%{http_code}\n' -b jarT1.txt "https://cdn.target.com/uploads/$T2/<known-file>"
# AUDIT LOGS / USAGE COUNTERS: admin-ish endpoints that aggregate ACROSS tenants but authorize weakly:
curl -s -b jarT1.txt "$H/api/usage" | jq 'keys'        # does YOUR usage endpoint see other orgs' rows?
```
Same root cause as the [[idor-access-control]] search-index bypass: the direct GET is hardened,
the aggregated/indexed path forgot the `WHERE tenant_id =` clause. A search result row from T2 is
proof — no need to mass-harvest (data-minimization rule; a 5-record sample suffices, redacted).

## 5. Sign up your own tenant — the clean second identity

When the program gives you one account and no second tenant: **create the second tenant
yourself.** SaaS sign-up is usually self-serve by design — a fresh email (or a `+tag` alias) gets
you T2 with real ids, real objects, real data, zero rules-lawyering:

```bash
# sign up → create org "globex-9d21" → upload/create a few objects with KNOWN unique strings →
# capture T2's ids. You now have the full matrix (§2) against real foreign objects.
# Bonus: the INVITATION flow is itself a test surface (§6) — invite your T1 user into T2.
```
Honest limits: some programs restrict account creation volume — respect the program policy on
multi-account testing before you do this. Where self-serve tenant creation is closed, the
invitation flow (§6) is usually still open because it's a user-facing feature.

## 6. Invitation & role-mapping flows as a tenant-escape vector

The invitation path crosses the boundary BY DESIGN — that's why it breaks:

- **Invite with a foreign tenant hint:** intercept the invite POST; if it carries
  `tenantId`/`orgId` in the body, invite YOUR T1 user into T2's context — or craft an invitation
  that claims T2 while signed by T1.
- **Accept-flow confusion:** invitation links that accept you into a tenant derived from the LINK
  rather than the invite record — mutate the accept request's org/project references.
- **Role mapping across tenants:** join T2 as a member, then test whether T1-granted roles
  (admin in T1) leak privileges into T2 contexts — role checks cached per-user rather than
  per-membership are the classic root cause.
- **Leaving/being-removed edge:** after leaving T2 (or being removed), can you still call T2
  endpoints with stale membership? The membership-revocation analogue of §4 logout tests.

**Proves the bug:** your T1 identity reads/writes in T2 with a membership or role it shouldn't
hold — evidenced from BOTH sides (T2 admin view shows you as member/role you granted yourself).

## Impact gate

State the boundary in business terms: "T1 user reads T2's <customer/invoice/PII records>" —
tenant-to-tenant leakage on a SaaS is Critical when it crosses to OTHER CUSTOMERS' data (not
merely your own two test tenants — say explicitly that T2 is yours, and that the same boundary
separates every real customer). Full-tenant read via search/export = mass-exposure framing per
[[business-logic]]. Claim-scoped JWT forging → any tenant = Critical standalone. Cell-3-only
results are ordinary IDOR — don't inflate them to "tenant isolation failure". Route through
[[validate]]; sample redacted; `coverage.md` records which endpoints ran the full matrix vs
partial.
