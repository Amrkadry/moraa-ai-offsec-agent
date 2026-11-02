# Moodle LMS — version pinning, plugin inventory, and the classes that actually pay

Companion to `cms-wordpress-joomla.md`. Same flow (**identify version → n-day → plugin surface →
generic classes**) but Moodle's recon primitives are completely different from WP's, and much
better: Moodle leaks its whole plugin list and half its config to an unauthenticated client.

Use when: `Set-Cookie: MoodleSession`, `M.cfg = {...}` in the page, `/theme/styles.php/<theme>/<rev>/all`,
`/lib/requirejs.php/`, or a `YUI_config` blob.

Proven on `learn.acme.example` (the vendor training portal exams portal, Moodle 4.3.12, ~126k users, 2026-09).

---

## 0. First three requests (do these before anything else)

```bash
H=https://target

# (a) Unauthenticated full config dump — no session needed.
curl -sk -X POST "$H/lib/ajax/service-nologin.php?info=tool_mobile_get_public_config" \
  -H 'Content-Type: application/json' \
  -d '[{"index":0,"methodname":"tool_mobile_get_public_config","args":{}}]'

# (b) M.cfg — sesskey, theme, jsrev, wwwroot, contextid, courseId
curl -sk "$H/" | grep -o 'M.cfg = {.*};'

# (c) Docs-branch fingerprint: force any error, read moreinfourl
curl -sk -X POST "$H/lib/ajax/service.php?sesskey=x&info=y" -H 'Content-Type: application/json' \
  -d '[{"index":0,"methodname":"core_enrol_get_users_courses","args":{"userid":2}}]'
#   "moreinfourl":"http://docs.moodle.org/403/..."   403 => 4.3   405 => 4.5   500 => 5.0
```

`tool_mobile_get_public_config` is the single highest-value unauth request on any Moodle. It tells
you, with no session, which whole vuln classes are **n/a** before you waste a pass on them:

| Field | Why you care |
|---|---|
| `registerauth` | `""` = self-registration CLOSED. `"email"` = open signup → free account, go get one. |
| `guestlogin` | `1` = guest access, browse courses with no account at all. |
| `enablewebservices` | `0` = `/webservice/rest/server.php` dead, skip the whole token-hunting lane. |
| `identityproviders[]` | The SSO list. **This is usually where the real bug is** — see §5. |
| `forgottenpasswordurl` / `authnoneenabled` | Empty + 0 ⇒ no local auth ⇒ `auth-oauth.md` § password-reset / `2fa-bypass.md` are n/a. |
| `maintenancemessage`, `sitename` | Free recon + sometimes internal hostnames. |
| `agedigitalconsentverification`, `supportavailability` | Version hints. |

---

## 1. Version pinning to an exact point release

`/lib/upgrade.txt`, `/version.php`, `/composer.json`, `/README.txt` are all blocked or empty on a
sane deploy (`version.php` returns **200 with 0 bytes** — `defined('MOODLE_INTERNAL') || die()`).
Do it with **served static assets vs upstream git tags** instead.

### The three-way 404 oracle (memorise this — it drives every Moodle sweep)

| Response | Meaning |
|---|---|
| `404` + ~16 bytes (`File not found.`) or nginx default | Path genuinely absent on disk |
| `404` + ~26 KB themed `<title>Error \| Site</title>` page | **PHP file EXISTS**, threw on missing/invalid params |
| `200` + **0 bytes** | **PHP file EXISTS** and correctly refuses direct access |
| `303` | Exists, requires login |
| `403` + small | Directory exists, listing denied |

### Coarse bracket by feature-file presence

```bash
for p in /lib/editor/tiny/js/tinymce/tinymce.min.js \
         /lib/editor/atto/yui/build/moodle-editor_atto-editor/moodle-editor_atto-editor-min.js \
         /lib/editor/tiny/plugins/premium/version.php \
         /admin/tool/mfa/index.php /communication/configure.php \
         /course/section.php /ai/configure.php /reportbuilder/index.php; do
  echo "$(curl -sk -o /dev/null -w '%{http_code}:%{size_download}' "$H$p")  $p"; done
```

| Marker | Bracket |
|---|---|
| `/reportbuilder/` present | ≥ 4.0 |
| `/lib/editor/tiny/` present | ≥ 4.1 |
| `/lib/editor/tiny/plugins/premium/`, `/admin/tool/mfa/`, `/communication/` present | ≥ 4.3 |
| `/course/section.php` present | ≥ 4.4 |
| `/ai/` present | ≥ 4.5 |
| `/lib/editor/atto/` still present | ≤ 4.4 (removed in 5.0) |

Bundled-library versions cross-check it: TinyMCE `majorVersion:"6",minorVersion:"6.2"` (grep
`/lib/editor/tiny/js/tinymce/tinymce.min.js`) ⇒ 4.3; jQuery 3.7.1 + jQuery UI 1.13.2 ⇒ ≥ 4.3.

### Exact point release — hash-diff against git tags

Moodle **commits its built AMD files**, so served `*.min.js` are byte-identical to the tag.

```bash
# 1. Ask GitHub which assets changed between candidate tags — don't guess.
for pair in v4.3.6...v4.3.7 v4.3.7...v4.3.8 v4.3.10...v4.3.11; do
  echo "== $pair"; curl -s "https://api.github.com/repos/moodle/moodle/compare/$pair" \
    | grep -oE '"filename": "[^"]*\.min\.js"'; done

# 2. Hash the discriminators locally vs each tag.
for f in lib/editor/tiny/amd/build/utils.min.js \
         course/format/amd/build/local/courseindex/section.min.js \
         lib/form/amd/build/collapsesections.min.js; do
  L=$(curl -sk "$H/$f" | md5sum | cut -c1-10); echo "$f LOCAL=$L"
  for t in v4.3.6 v4.3.8 v4.3.11 v4.3.12; do
    echo "  $t $(curl -sfL "https://raw.githubusercontent.com/moodle/moodle/$t/$f" | md5sum | cut -c1-10)"
  done; done
```

Pins to an exact release in ~3 requests. Then check the branch's **EOL date** — Moodle gives each
non-LTS branch ~12 months general + ~6 months security support. A branch past its security EOL means
*every* MSA since that date is live; enumerate them at `moodle.org/security/index.php`.

---

## 2. Plugin inventory (free, no fuzzing)

**`YUI_config.groups.moodle.modules`** is rendered into every Moodle page and names every installed
plugin that ships a YUI module. One request, zero noise:

```bash
curl -sk "$H/" | grep -oE 'moodle-(mod|block|filter|local|enrol|auth|theme|qbank|tool|report|atto|assignfeedback|availability|gradereport|message)_[a-z0-9]+' | sort -u
curl -sk "$H/" | grep -oE "require\(\['[a-z0-9_]+/[a-z0-9_]+'" | sort -u   # catches filter_oembed etc.
```

Then confirm/extend with the `version.php` oracle (`200:0` = installed):

```bash
probe(){ c=$(curl -sk -o /dev/null -w '%{http_code}:%{size_download}' "$H$1/version.php"); [ "$c" = "200:0" ] && echo "EXISTS $1"; }
for m in assign quiz scorm lti forum certificate customcert turnitintooltwo h5pactivity attendance hvp; do probe /mod/$m; done
for b in configurable_reports workflow grade_me xp completion_progress; do probe /blocks/$b; done
for f in oembed filtercodes generico; do probe /filter/$f; done
for e in self manual guest paypal stripe wallet lti cohort database flatfile; do probe /enrol/$e; done
for a in oauth2 saml2 ldap cas lti shibboleth; do probe /auth/$a; done
```

**Anything not in Moodle core is the weak link.** High-value third-party names to flag on sight:

| Plugin | Why |
|---|---|
| `block_configurable_reports` | **Top prize.** Lets a report author run raw SQL; has student-reachable unparameterised SQL sinks in `reports/sql/report.class.php` + filter plugins, and an editingteacher→`managesqlreports` self-grant path via per-instance permission override → full DB read (admin hashes) → RCE via plugin upload. Enumerate `viewreport.php?id=1..200`. |
| `filter_oembed` | Server-side URL fetch on rendered content → SSRF. Needs a course text context. |
| `mod_turnitintooltwo` | Historic unauth SQLi in `ajax.php`; enumerate `?action=`. |
| `mod_certificate` (legacy) / `mod_customcert` | Certificate forgery + `verify_certificate.php` code entropy. |
| `enrol_paypal` / `enrol_stripe` / payment plugins | IPN/webhook spoofing → free paid enrolment. |
| `block_xp`, `local_*` vendor plugins | Unreviewed custom code. |

---

## 3. Enrolment — the gate that everything else sits behind

On a Moodle worth testing, ~all value (quiz answers, grades, certificates, plugin SQL/SSRF sinks,
file upload, stored XSS) is behind **course enrolment**. Map it first or you will waste the pass.

```bash
for id in $(seq 1 120); do
  curl -sk -b jar.txt -L "$H/course/view.php?id=$id" -o c.html -w "$id %{url_effective}\n"
  grep -oE '<title>[^<]*</title>' c.html | head -1; done
```

Read the enrol page HTML, not the rendered text:

| Signal in `/enrol/index.php?id=N` | Meaning |
|---|---|
| `_qf__enrol_self_empty_form` | Self-enrol instance exists but is **disabled/inactive** — dead end |
| `_qf__<instanceid>_enrol_self_enrol_form` + `<input name="enrolpassword">` | **Live**, key-gated |
| Same form, **no** `enrolpassword` input | **Live and keyless — enrol yourself right now** |
| `"You cannot enroll yourself in this course."` | No self-enrol instance at all |
| Course renders directly without redirect | Guest access on → browse without enrolling |

Notes:
- Moodle's `enrol_self` has **no rate limit / lockout** on the enrolment key. Worth reporting as Low
  on its own; do **not** run a key brute-force against production — that is credential guessing.
- If `customint1` is set on the instance, **any group enrolment key** in the course also works.
- `enrol_page_hook()` only performs the enrolment when `can_self_enrol()` returns `true`, so there is
  no "submit the form anyway" bypass. Don't burn time on it.
- Look for an *administrative* course (e.g. a trainer/instructor portal) with a live self-enrol
  instance — enrolling there is role escalation, not just content access.

---

## 4. What is reachable **without** enrolment (run this battery first)

```bash
for u in /blog/index.php /tag/search.php "/search/index.php?q=a" /calendar/view.php \
         /user/files.php "/badges/view.php?type=1" "/mod/forum/index.php?id=1" \
         "/course/info.php?id=N" /admin/tool/dataprivacy/mydatarequests.php \
         /admin/tool/policy/user.php /message/index.php /cohort/index.php; do
  curl -sk -b jar.txt -L "$H$u" -o p.html -w "%{http_code} $u "
  sed -n '/region-main/,$p' p.html | sed 's/<[^>]*>/ /g' | tr -s ' \n' ' \n' | grep -v '^\s*$' | head -2
done
```

- **Site-wide blogs** (`bloglevel=site`) and **tags** leak other users' content across courses when enabled.
- **`tool_dataprivacy`** — GDPR export IDOR (`download.php?requestid=`) is a huge PII win when a DPO is configured.
- **Private files** (`/user/files.php`) are writable by *any* provisioned user with no enrolment → a
  real file-upload surface. But check the serve headers before getting excited (§6).
- `/user/profile.php?id=<foreign>` should say *"The details of this user are not available to you"*.
- **`/mod/quiz/attempt.php?attempt=N` is an existence + course-mapping oracle** (`require_login`
  ordering): nonexistent → "Invalid quiz attempt ID"; existing → redirect reveals the owning course,
  including hidden courses. Info-leak only — record it, don't over-rate it.

---

## 5. SSO / `auth_oauth2` — the highest-value class on a corporate Moodle

When `identityproviders[]` is non-empty and there is no local login, **the integration is the attack
surface**, not Moodle core. This is where `learn.acme.example`'s High came from.

```bash
# Capture the authorize redirect to get client_id / redirect_uri / scope / state:
curl -sk -c j -b j "$H/login/index.php" -o l.html
S=$(grep -oE '"sesskey":"[^"]*"' l.html | head -1 | cut -d'"' -f4)
curl -sk -c j -b j -o /dev/null -w '%{redirect_url}\n' \
  "$H/auth/oauth2/login.php?id=1&wantsurl=%2F&sesskey=$S"
```

### 5a. The identity-mapping audit (generalises to ANY federated login)

Moodle resolves a returning SSO user with
`api::match_username_to_user($userinfo['username'], $issuer)` → a lookup on
`auth_oauth2_linked_login` by **`(issuerid, username)` ONLY**. The stored `useridentifier`/`sub` is
never consulted at login. So: **whatever the admin mapped to `username` is the account's identity.**

```bash
# 1. What Moodle actually matches on — renders as "<email>, (<username>)":
curl -sk -b jar.txt "$H/auth/oauth2/linkedlogins.php" | sed 's/<[^>]*>/ /g' | grep -A2 'External account'

# 2. What the IdP offers (is there a stable id it could have used?):
curl -sk -H "Cookie: <idp session>" https://idp/api/.../user/self

# 3. Where the stable id actually went — often uselessly into idnumber:
curl -sk -b jar.txt "$H/user/edit.php?id=<uid>&course=1" | tr '\n' ' ' | grep -o 'name="idnumber"[^>]*'
```

**Red flag:** `linked_login.username` holds a *mutable* handle while the IdP's immutable `uuid`/`sub`
sits in `idnumber`. Then:
- The handle is user-changeable at the IdP → the old handle is released.
- `api::link_login()` **INSERTs only** — it never deletes/updates prior rows for that user. So the
  victim's abandoned handle stays permanently bound to their Moodle account.
- Anyone who claims that handle logs in **as the victim**. Full ATO, no victim interaction.

Confirm handle mutability at the IdP *without changing anything* — see §5c.
Remaining precondition to check: **does the IdP allow re-registration of a released handle?**

### 5b. `requireconfirmation` OFF → silent email linking

If accounts are auto-provisioned with **no** email confirmation, `requireconfirmation` is off, and
`auth/oauth2/classes/auth.php` takes this branch:

```php
$moodleuser = \core_user::get_user_by_email($userinfo['email']);
if (!empty($moodleuser)) {
    if ($issuer->get('requireconfirmation')) { /* send confirm mail */ }
    else { \auth_oauth2\api::link_login($userinfo, $issuer, $moodleuser->id, true); }  // SILENT
}
```

⇒ **any** IdP identity whose email matches an existing Moodle account (staff created by
`tool_uploaduser`/manual auth with corporate addresses) is silently bound and logged in as it.
Exploitable iff the IdP lets you register/change to an unverified email — always test that.

### 5c. Per-field step-up (L2) allowlist as a *read* oracle

On IdPs with per-field step-up, you can prove a field is writable **without writing it**:

```bash
curl -sk -X OPTIONS -H "Cookie: $S" https://idp/api/.../user/self -i | grep -i allow
curl -sk -X PUT -H "Cookie: $S" -H 'Content-Type: application/json' -d '{}'                     ... # 204 baseline
curl -sk -X PUT -H "Cookie: $S" -H 'Content-Type: application/json' -d '{"zzz_bogus":1}'        ... # 204 => no field validation
curl -sk -X PUT -H "Cookie: $S" -H 'Content-Type: application/json' -d '{"username":"<current>"}' ... # 499 L2_REQUIRED
```

A field that returns `L2_REQUIRED` while bogus fields return `204` is **recognised, writable, and
explicitly on the sensitive list**. You have enumerated the IdP's sensitive-field set and proven
mutability with zero side effects. (Pairs with the L2 field-gate notes in `auth-oauth.md`.)

### 5d. Things that are usually already closed — timebox them
- `redirect_uri` at the IdP: test traversal, bare origin, suffix domain (`target.com.evil.com`),
  sibling subdomain, `@` userinfo, appended query, `http://` downgrade. Exact-match ⇒ move on.
- Moodle packs `wantsurl`+`sesskey` into the OAuth2 `state`; `admin/oauth2callback.php` validates
  that sesskey ⇒ login-CSRF closed. `wantsurl` is `PARAM_LOCALURL` ⇒ no open redirect.
- `mod/lti/auth.php` validates `redirect_uri` against the registered list (fixed in current 4.x) and
  needs a prior `$SESSION->$launchid`. Its unauth `repost_crosssite_page` reflects `REQUEST_URI` and
  all `$_POST` — but Mustache-escaped. Verify with a **raw** (un-encoded) quote, then drop it.

---

## 6. File upload / serving

Private files are writable by any provisioned user, **no enrolment required**:

```bash
# /user/files.php gives contextid + draft itemid + client_id; repo_id 3 = "Upload a file"
curl -sk -b jar.txt "$H/user/files.php" | grep -oE '"itemid":[0-9]+|"contextid":[0-9]+|"client_id":"[^"]*"'
curl -sk -b jar.txt -X POST "$H/repository/repository_ajax.php?action=upload" \
  -F "sesskey=$S" -F "client_id=$CID" -F "itemid=$ITEM" -F "repo_id=3" -F "ctx_id=$CTX" \
  -F "author=t" -F "license=allrightsreserved" -F "repo_upload_file=@x.svg;type=image/svg+xml"
```

**Check the serve headers before rating it.** Current Moodle returns
`Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` for `text/html` and
`image/svg+xml` on `draftfile.php`/`pluginfile.php` ⇒ no inline execution. And the draft/private
area is per-user, so even inline would be **self-XSS only**. To get cross-user XSS you need a shared
area (forum attachment, course files, assignment feedback) ⇒ back to §3, you need enrolment.

**Clean up** — delete drafts you created, then re-fetch to confirm 404:

```bash
curl -sk -b jar.txt -X POST "$H/repository/draftfiles_ajax.php?action=delete" \
  -d "sesskey=$S&client_id=$CID&filepath=%2F&filename=x.svg&itemid=$ITEM&ctx_id=$CTX"
```

---

## 7. Classes that are usually n/a — confirm from §0 and skip

`enablewebservices:0` ⇒ no `/webservice/rest/server.php`, no `core_webservice_get_site_info` token
hunting. Messaging/blogs/tags/global-search disabled ⇒ those leak paths are dead. No local auth ⇒
`auth-oauth.md` § password-reset, `2fa-bypass.md`, `host-header.md` (no reset mail to poison) are n/a. Moodle
core reflected XSS is hardened — one sweep across `search`/`errorcode`/`tag`/`q`/`component` params
is enough; if everything comes back entity-escaped, move to the plugins.

Content fuzz that is worth exactly one pass (and usually finds nothing on a sane deploy):
`/config.php{,.bak,~}`, `/moodledata/`, `/backup(s)/`, `.git`, `.env`, `/vendor/`, `/node_modules/`,
`/cache/ /temp/ /filedir/ /muc/ /sessions/`, `phpinfo|info|test|adminer`. CLI scripts
(`/admin/cli/*.php`) return `200`/0 bytes — they refuse web execution, not a finding.

---

## 8. Reporting notes

- "Runs EOL Moodle" is **Medium at best** on its own (A06). Don't inflate it — pin the exact version,
  name the EOL date and the count of missed MSAs, and say plainly whether you demonstrated an n-day.
- The quiz-attempt existence oracle, missing enrolment-key rate limiting, and JWKS at
  `/mod/lti/certs.php` (public by design) are **Low/info**. Record them in `coverage.md` so they are
  not rediscovered and re-escalated; don't write them up.
- The SSO identity-mapping flaw (§5a/5b) is the one that pays. It is an **authentication design**
  bug, so it survives a Moodle upgrade — say so in the report.
