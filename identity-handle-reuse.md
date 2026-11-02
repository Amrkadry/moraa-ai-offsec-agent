# Identity handle reuse — claim a released username, land in someone else's account

> Why this doc exists: SSO moved authentication to the IdP, but a surprising number of downstream
> apps still key the local account on a **mutable** string — username, handle, or email local-part —
> instead of the IdP's immutable subject identifier. When the IdP lets a handle be released and
> re-registered (after a rename, a deletion, or an organisation leaving), whoever claims it next
> logs into the previous owner's account at every app that matched on the string. No password, no
> token theft, no phishing. We have demonstrated this end-to-end at CVSS 8.8.
> Cross-ref [[auth-oauth]] (the SSO/OIDC flow this abuses), [[user-enumeration]] (finding which
> handles exist and which are free), [[multi-tenancy]] (the same confusion across tenants),
> [[validate]] (the gate this class must clear), [[subdomain-takeover]] (same "released resource,
> re-registered by attacker" shape, different resource).

---

## 0. The mechanism, in four steps

```text
1. Victim signs in to App X via the IdP.  App X creates a local account keyed on "alice".
2. Victim renames their handle, deletes the account, or leaves the org.
   The IdP RELEASES "alice" back to the pool.
3. Attacker registers "alice" at the IdP. New subject id, same handle.
4. Attacker signs in to App X via the IdP. App X matches on "alice" ->
   attacker is inside the victim's existing account, with the victim's data and role.
```

The bug is at step 4 and it is a single line of logic: the app looked up the user by handle rather
than by the `sub` claim. Everything before step 4 is normal product behaviour.

---

## 1. Does the IdP release handles at all?

This is the precondition. Test it on **your own two accounts** — never on anyone else's handle.

```bash
# A. does a rename free the old handle immediately, or is it reserved?
#    rename account A from a1 to a1-moved, then try to claim a1 from account B
curl -s -X PATCH https://sso.acme.example/api/v1/user/self \
  -H "Cookie: $A_SESSION" -H 'Content-Type: application/json' \
  -d '{"username":"a1-moved"}' -o /dev/null -w '%{http_code}\n'

curl -s -X POST https://sso.acme.example/api/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"a1","email":"b+claim@yourdomain.example","password":"..."}' \
  -o /dev/null -w '%{http_code}\n'
```

| Result | Reading |
|---|---|
| `200/201` — claim succeeds right away | **release is immediate.** Precondition met; go to §2. |
| `409 already exists` | handle is reserved (tombstoned). Check whether the reservation expires. |
| `400` with a reserved-name error | explicit tombstone list. Good design; class is closed here. |

Check the tombstone window if there is one — a 30-day reservation is a delay, not a fix:

```bash
# re-try the claim on a schedule; a handle that frees at T+30d is still exploitable, just slower
for d in 1 7 30 31 60; do echo "day $d: (re-run the register call above and record the code)"; done
```

> **Deletion is the stronger path.** Renames are often tombstoned while *deletions* are not,
> because deletion is modelled as "the user is gone, reclaim their resources". Test both.

---

## 2. Find which downstream apps key on the handle

Any app that accepts the IdP is a candidate. You are looking for the identifier the app stores
locally. Three ways to read it without touching another user:

```bash
# a. the app's own profile/API response — which field is the stable key?
curl -s https://app.acme.example/api/me -H "Cookie: $APP_SESSION" | jq '.'
#    id numeric and unrelated to the IdP  -> local account exists, keyed on SOMETHING
#    "username":"a1" echoed back          -> candidate
#    "sub":"8f3c-..." or "external_id"    -> likely keyed on the immutable id (good)

# b. the SSO assertion the app actually receives (decode your own)
#    OIDC id_token: is `sub` stable across your rename? If sub changes on rename, the app
#    CANNOT key on it safely and almost certainly keys on something mutable.
echo "$ID_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '.sub,.preferred_username,.email'

# c. rename your own handle, then sign in to the app again — the decisive test
#    same local account, new handle  -> app keyed on the immutable id (safe)
#    NEW empty account               -> app keyed on the handle  (VULNERABLE SHAPE)
```

That third test is the one that matters, and it is entirely self-contained: two of your own
accounts, your own handle, no third party involved.

```text
rename a1 -> a1-moved, re-login to App X:
  lands in the SAME account, data intact   => keyed on sub. Move on.
  lands in a NEW empty account             => keyed on the handle. The released "a1" now
                                              owns that abandoned account. Go to §3.
```

---

## 3. Prove it with two accounts you control

Never test by claiming a real user's handle. The clean proof uses only your own identities:

```text
Account A  handle "a1"  -> sign in to App X -> create a marker: a note titled "CANARY-A-7731"
Account A  rename a1 -> a1-moved            (A's App X account is now orphaned, keyed on "a1")
Account B  claim handle "a1" at the IdP
Account B  sign in to App X via SSO
  => B sees "CANARY-A-7731"  ==  B is inside A's account.  THAT is the finding.
```

```bash
# the evidence to capture, in this order
curl -s https://app.acme.example/api/notes -H "Cookie: $B_SESSION_AFTER_CLAIM" | jq '.[].title'
# expect: "CANARY-A-7731"  <- data created by a DIFFERENT identity, read by B
```

What the write-up must contain (see [[reporting]]):

- the IdP request that released `a1` and the one that re-claimed it, with status codes;
- the two distinct IdP subject identifiers, proving these are different principals;
- the canary object created by A and read by B, in full request/response;
- the app's own `/api/me` for B showing the account id it landed in **equals** A's.

---

## 4. Variants worth checking on the same engagement

| Variant | Where the mutable key hides | Test |
|---|---|---|
| **Email local-part match** | app normalises `a1+tag@` or `a1@` to a user | claim an email that normalises to the victim's; see [[auth-oauth]] |
| **Unverified-email match** | app trusts `email` from the assertion without `email_verified` | set an unverified email on B equal to A's and sign in |
| **Org/tenant slug reuse** | tenant keyed on slug; a deleted org frees its slug | re-register the slug, check for inherited members or data ([[multi-tenancy]]) |
| **Display-name match** | approvals/mentions resolve by display name | set B's display name to A's and look for mis-routed approvals |
| **Group/role by name** | authz grants attached to a group *name*, not id | recreate a deleted group with the same name; check inherited grants |
| **Invite keyed on handle** | a pending invite to `a1` is claimed by whoever holds it | accept an old invite after claiming the handle |

---

## 5. Impact gate

| You have | Verdict |
|---|---|
| IdP releases handles, no downstream app keyed on the handle | **not a finding.** Handle reuse alone is intended behaviour at most IdPs. |
| An app creates a *new empty* account after rename | **Informational/Low.** Shows the key is mutable, but nothing was accessed. |
| You land in an account you previously owned, as a new principal | **Medium at best, and argue it carefully** — self-to-self is a weak demonstration on its own |
| A second principal reads or controls data created by the first | **the finding — High/Critical.** Rate on what the account can do: data read, actions taken, role inherited. |
| The inherited account is an admin, or the app is the SSO for others | **Critical, and chain it** ([[chain-builder]] territory) |

Kill signals — stop here:

- **Handle is tombstoned permanently** and no expiry exists. Closed.
- **Every downstream app keys on `sub`** and `sub` is stable across rename/delete. Closed; this is
  the correct design and worth stating as a clean negative ([[validate]]).
- **You only ever reached a fresh empty account.** That is the *absence* of the bug, not a weak
  version of it. Do not write it up as one.
- **The app is hosted by a third party**, not the programme owner. Many programmes accept the
  report but treat third-party-hosted assets as out of scope for reward — check the scope rules
  before investing a day in it.

> **The one rule applies.** "An attacker could claim a handle if a user ever deletes their
> account" is not a finding. "Here is principal B reading principal A's data, with both subject
> ids shown" is.
