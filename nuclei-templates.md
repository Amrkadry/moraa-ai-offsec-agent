# Moraa — Custom Nuclei Templates (high-signal checks for the classes public sets miss)

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> nuclei's ~10k community templates are excellent for known CVEs and generic exposures — and
> weak exactly where this library hunts: credentialed-CORS reflection, genuine `*.js.map`
> exposure, SvelteKit `__data.json`, the Next.js middleware-bypass probe, actuator/heapdump,
> path-scoped edge-block gaps, healthz metadata. On wildcard-shadowed estates public templates
> also false-positive constantly: a catch-all host answers **200 for everything**, so any
> template matching status codes alone "finds" every nonexistent path. This doc covers writing
> templates that survive that estate — and the control discipline to trust them
> ([[controls-and-oracles]] applied to your own tooling).
> The local set lives in `templates/`; `scripts/nuclei_wrap.py --local-templates` runs it.
> Cross-refs: [[framework-misconfig]] (the estate patterns these detect), [[cors]],
> [[js-analysis]], [[bypass-4xx]] (canary controls), [[validate]] (the gate every hit passes).

## 0. The 60-second workflow

```bash
# write/edit a template, then ALWAYS validate before trusting it:
nuclei -validate -t templates/                       # syntax + field checks (exit 0 = loadable)
nuclei -t templates/credentialed-cors-reflection.yaml -u https://target/api/me -H "Cookie: <session>"
# the trust loop (see §4): known-VULNERABLE control must hit, known-CLEAN control must NOT:
nuclei -t templates/<name>.yaml -u https://vulnerable-control.example   # expect a match
nuclei -t templates/<name>.yaml -u https://normal-clean-site.example    # expect NO match
# sweep with the wrapper (adds -t templates/ + the moraa tag so the -tags filter loads them):
python3 scripts/nuclei_wrap.py -l recon/live.txt --local-templates --json --output nuclei.json
```

## 1. Template anatomy — the fields that matter

```yaml
id: moraa-credentialed-cors-reflection     # unique, NO spaces (it's the output identifier)

info:
  name: Credentialed CORS - Arbitrary Attacker Origin Reflected with Allow-Credentials
  author: moraa-ai-offsec-agent
  severity: high            # info|low|medium|high|critical — pass through to the wrapper contract
  description: |
    WHAT it detects AND the honest impact gate (what makes it a finding vs a lead).
  reference:                # links that survive into the finding's next_action
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
  classification:           # for CVE-backed templates: cvss-metrics, cvss-score, cve-id, cwe-id
    cve-id: CVE-2025-29927
  metadata:                 # free-form key:value — we pin moraa-doc + moraa-gate for the report
    moraa-doc: nuclei-templates.md
    moraa-gate: reflection + delivery vector + victim data in hand, or it stays a lead
  tags: cors,exposure,moraa # moraa = the local-set marker the wrapper filters on
```

Field discipline:
- **severity is the wrapper contract's severity passthrough** (`nuclei_wrap.py` maps it
  unchanged) — set it to what the CLASS earns, not what the hit proves. A reflection detector
  is `high` (its class is); a metadata leak is `info`. The confirmation step (validate.md)
  owns the final call.
- **tags double as routing**: `exposure` etc. ride the default sweep; `moraa` marks the local
  set; `cve2025`-style year tags match nuclei's convention for CVE templates.
- **description carries the gate** — a template you can't state the false-positive condition
  for isn't finished.

## 2. Matchers — match CONTENT, never status alone

Seven matcher types: `status`, `size`, `word`, `regex`, `binary`, `dsl`, `xpath`. The wildcard
estate rule: **a catch-all host returns 200 with the same HTML for every path — only body
content (and headers) can separate a real hit from the shadow.**

```yaml
# word matchers, condition AND — every word must be present:
matchers-condition: and            # request-level: how MULTIPLE matchers combine (and|or)
matchers:
  - type: word
    part: body
    condition: and
    words:
      - '"version"'                # quoted JSON keys — real source-map fields (v3 spec)
      - '"sources"'
      - '"mappings"'

# dsl matcher — full expressions with helper functions; the escape hatch for precision:
matchers:
  - type: dsl
    dsl:
      - "status_code == 200 && contains(body, '\"type\":\"data\"') && contains(body, '\"data\":[')"
      - "contains(to_lower(header), 'access-control-allow-credentials: true')"
```

DSL attributes worth knowing: `status_code`, `body`, `header`, `content_type`, `contains()`,
`to_lower()`, `len()`, `starts_with()`; multi-step suffixes below. Case-sensitivity: wrap the
part in `to_lower()` yourself rather than trusting matcher defaults.

**Stable-anchor rule:** when you must match on HTML, anchor to content the shadow page can't
have — a real app's `<title>` and app-specific strings, never favicon/meta defaults. Test
against the estate's OWN catch-all before shipping the template (that's the §4 clean control).

## 3. Requests — raw HTTP, extractors, multi-step req-condition, OAST

**Raw requests** give full control (and are required for dynamic extractors):

```yaml
http:
  - raw:
      - |
        GET HTTP/1.1
        Host: {{Hostname}}
        Origin: https://attacker.example
```
Blank request-URI = the input URL verbatim; `{{Hostname}}` stays as-is per the docs.

**Extractors** capture values (`regex`/`kval`/`json`/`xpath`/`dsl`); with `internal: true` +
`name:` the value becomes a variable usable in SUBSEQUENT requests — the two-step source-map
pattern (`templates/exposed-source-map.yaml`):

```yaml
    extractors:
      - type: regex
        name: js_path
        part: body
        internal: true          # required for dynamic use; also keeps values out of output
        group: 1
        regex: '(?i)(?:src|href)\s*=\s*["''](/[^"'']+\.js)["'']'
  - raw:
      - |
        GET {{js_path}}.map HTTP/1.1
        Host: {{Hostname}}
```

**Multi-step req-condition** — DSL attributes numbered by request (`status_code_1` = first
request's status, `body_2` = second request's body) let one template express a CONTROLLED
DIFFERENCE: baseline vs probe. The middleware-bypass and edge-block-gap templates are built on
this — `status_code_2 == 200 && status_code_1 == 403` is a comparison, and a comparison is a
control ([[controls-and-oracles]]):

```yaml
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 >= 400 && status_code_2 == 200 && contains(to_lower(content_type_2), 'json')"
```

**OAST / blind checks** — `{{interactsh-url}}` in the request, then match on the interaction:

```yaml
      - |
        GET /fetch?url=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        part: interactsh_protocol   # dns | http | smtp — dns is the least intrusive
        words:
          - "dns"
```
The [[controls-and-oracles]] OOB rule applies: only payloads YOUR client minted poll as hits —
which interactsh satisfies automatically, but a pasted Burp Collaborator payload does NOT
(matcher polls nothing; the hit dies silently).

## 4. TEST before trusting — a template is an oracle, so calibrate it

Every template is an instrument, and every instrument needs the two-point calibration from
[[controls-and-oracles]]: a reading you know must be YES and one you know must be NO.

```bash
# 1. syntax: loadable and field-valid
nuclei -validate -t templates/          # exit 0 required
# 2. POSITIVE control — a target you KNOW is vulnerable (your own lab host; never a third party):
#    for source maps: serve a real .map on a scratch nginx; for CORS: a two-line echo server.
#    The template MUST fire here. If it doesn't, the matcher is broken — no exceptions.
# 3. NEGATIVE control — a normal, clean host (an RFC-2606 example domain page, or any boring site):
#    The template MUST stay silent. Every wildcard-shadow catch-all you hunt against is ALSO a
#    negative control — run the template on one before the sweep.
```

Positive-control rigs you can stand up in minutes:

```bash
# clean CORS echo control (vulnerable on purpose): reflects Origin + ACAC:true
python3 -c "
import http.server,socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin','*'))
        self.send_header('Access-Control-Allow-Credentials','true'); self.end_headers(); self.wfile.write(b'{\"user\":\"victim\"}')
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
socketserver.TCPServer(('127.0.0.1',8443),H).serve_forever()"
nuclei -t templates/credentialed-cors-reflection.yaml -u http://127.0.0.1:8443   # MUST hit
```

**Anti-patterns that false-positive on wildcard-shadowed estates** (each one has burned this
estate — [[controls-and-oracles]] Case 1 is the same failure in ffuf):

| Anti-pattern | Why it fails | Fix |
|---|---|---|
| `- type: status / status: [200]` (status alone) | wildcard host 200s EVERYTHING | always pair with body-content matchers |
| matching reflected input without a baseline | the edge reflects too / cache echoes | controlled-difference design (§3) |
| grepping generic words (`error`, `login`, `version`) in body | present in the catch-all page too | quoted JSON keys, app-specific strings, `to_lower()` anchors |
| interactsh template with no `interactsh_protocol` matcher part | template "runs" but nothing proves the callback | match the interaction, dns part |
| trusting a hit without the §4 controls | your own tool is an uncalibrated oracle | positive+negative control BEFORE the sweep |
| regex without `group:` on multi-capture extractors | wrong value feeds the next request | pin `group: 1`, assert with the positive control |

## 5. The local set (`templates/`) — what each template proves and its gate

| Template | Detects | Severity | Gate (what makes it a finding) |
|---|---|---|---|
| `credentialed-cors-reflection.yaml` | exact attacker-Origin echo + `ACAC: true` (DSL, header) | high | precondition only ([[cors]]): needs XSS/takeover delivery + victim data, or it stays a lead |
| `exposed-source-map.yaml` | 2-step: bundle extraction → `.map` with the v3 spec fields | low | map content is CWE-540; escalate only on a working secret ([[js-analysis]]) |
| `sveltekit-data-json.yaml` | `{"type":"data","data":[` envelope on `/__data.json` | medium | read the leaked objects — severity follows what `load()` exposed ([[framework-misconfig]] CONFIRMED-HIGH precedent) |
| `nextjs-middleware-subrequest-bypass.yaml` | baseline-gated vs header'd-200 controlled difference, CVE-2025-29927 | high | confirm the 200 body is the protected content by hand; NVD: fixed in 12.3.5/13.5.9/14.2.25/15.2.3 |
| `spring-actuator-exposure.yaml` | `/actuator/env` propertySources + `/actuator/heapdump` download | high | pull the heapdump and extract secrets — the extracted secret is the report |
| `edge-api-block-gap.yaml` | `/` 4xx (edge block) while `/api/` or `/api/v1/` returns 200 JSON (req-condition) | medium | re-test blocked class with canary controls ([[bypass-4xx]]), then chase what the API leaks unauth |
| `healthz-build-metadata.yaml` | health endpoints whose body carries commit/revision/buildTime fields | info | info-severity: build-SHA pinning feeds n-day matching ([[rce-scenarios]] §13) |

Every template is `moraa`-tagged; every template's `metadata.moraa-gate` field (see YAML)
restates its gate. All validated: `nuclei -validate -t templates/` (exit 0, "All templates
validated successfully" on nuclei v3.11.1).

## 6. Wrapper workflow (`nuclei_wrap.py --local-templates`)

```bash
# default quick-wins sweep + the local set on every target (one nuclei run per tag-set group,
# unchanged; -t templates/ is appended, and each run's tags gain +moraa so the filter loads them):
python3 scripts/nuclei_wrap.py -l recon/live.txt --local-templates --json --output nuclei.json
# explicit dir:
python3 scripts/nuclei_wrap.py -u https://target.example --local-templates /path/to/templates
```
Evidence lines record the local-templates dir and tag; findings keep the same contract
(template-id/severity passthrough, confidence 0.85 — **never 1.0, templates do false-positive**).
Confirmation stays manual: `nuclei -id <template-id> -u <target>` for the evidence chain, then
`validate.md` before anything reaches `findings/`.

## 7. Contributing a new template (the checklist)

1. Name it `moraa-<class>-<what>`, tag it `moraa` + a default-sweep tag.
2. Match CONTENT (or a controlled difference) — status code alone is disqualified by §4.
3. State the gate in `description` + `metadata.moraa-gate` (the key the rest of the set uses).
4. `nuclei -validate -t templates/` → exit 0.
5. Positive control (lab host) hits; negative control (clean host + the estate's catch-all)
   stays silent — record both in the PR/commit note.
6. Add the row to §5's table, then run `python3 scripts/check_docs.py`.
