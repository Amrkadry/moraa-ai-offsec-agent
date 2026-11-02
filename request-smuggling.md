# Moraa — HTTP Request Smuggling / desync

> Load when there's a front-end proxy/CDN + back-end (almost always). Front and back disagree on where
> a request ends → smuggle a prefix onto the next user's request. High impact: auth bypass, cache
> poisoning, credential capture. Tool: **Burp "HTTP Request Smuggler" extension** (Turbo Intruder).

## Classes
```
CL.TE   front uses Content-Length, back uses Transfer-Encoding
TE.CL   front uses Transfer-Encoding, back uses Content-Length
TE.TE   both support TE but one is tricked by an obfuscated header
H2.CL / H2.TE   HTTP/2 downgrade: h2 frames → h1 back-end mis-parses (the modern goldmine)
CL.0    back-end ignores CL on some paths (e.g. static/redirect) → prefix next request
0.CL / client-side desync   browser-powered desync (single connection)
```

## Detect (safe timing method first — don't poison shared infra blindly)
```
# Burp Smuggler → "launch scan" ; or manual TE obfuscation:
Transfer-Encoding: chunked
Transfer-Encoding : chunked        (space before colon)
Transfer-Encoding:\tchunked        Transfer-Encoding\n : chunked
X: X\nTransfer-Encoding: chunked   (header folding)
Content-Length: 6 + Transfer-Encoding: chunked  → timeout delta reveals desync
```
```
# CL.TE timing probe (back-end waits for more body → delay)
POST / HTTP/1.1
Host: T
Content-Length: 4
Transfer-Encoding: chunked

1
A
0
```

## Exploit (once desync confirmed)
```
- bypass front-end auth/controls: smuggle a request to an internal-only path (/admin) past the proxy.
- capture other users' requests: smuggle a prefix that stores the victim's next request (with their
  cookies/token) into a response you can read (e.g. into a comment/search that echoes).
- web cache poisoning: smuggle to poison a cached response with attacker content → mass XSS/redirect.
- request-line/header injection into the victim's request → forced browsing / CSRF-token theft.
```

## Browser-powered desync & modern parsing-discrepancy primitives ("HTTP/1.1 must die" —
PortSwigger/James Kettle, 2025-26) — beyond the classic CL.TE/TE.CL table above
1. **Browser-powered desync attacks.** The `0.CL`/client-side desync row above is the entry point;
   the escalation is turning the VICTIM'S OWN BROWSER into the delivery mechanism instead of your
   own connection. A malicious page makes a cross-domain request that the victim's browser sends
   over a connection the attacker has primed to desync — the victim's browser effectively smuggles
   its own follow-up requests (with its own cookies) into the response the attacker's page reads.
   This needs no server-side connection reuse quirk beyond what the browser itself does (HTTP
   keep-alive/connection pooling) — the "attacker connection" IS the victim's browser session. Can
   chain into a **desync worm**: the poisoned response itself contains another copy of the
   malicious cross-domain request, so each new victim who loads the poisoned cached page continues
   the attack against the next visitor without further attacker action.
2. **Chunk-extension parsing discrepancies.** RFC 7230 allows chunk-size lines to carry optional
   `;extension=value` metadata after the hex length (`4;ext=1\r\nbody`) that compliant parsers
   should ignore for framing purposes. Some real-world parsers mishandle extensions differently —
   one treats the line as ending at the extension, another keeps reading past it looking for CRLF —
   producing a length-interpretation desync distinct from classic CL/TE disagreement. Probe:
   append chunk extensions to a normally-well-formed chunked body and diff the framing behavior
   against a plain chunked request of identical byte length.
3. **Pause-based desync (Apache/Varnish).** Send a request with an intentional pause mid-header (a
   slow/incomplete header line held open) — some front-end/back-end pairs (notably Apache and
   Varnish in certain configurations) disagree on how long to wait before deciding the request is
   complete, creating a timing-dependent desync window distinct from the length-mismatch classes
   above. This is a TIMING primitive, not a byte-content trick — test with a deliberately slow-drip
   header write (character-by-character with a delay) and watch for the same "next request gets
   prefixed" signature as classic smuggling.

These three are refinements of the SAME desync root cause the CL.TE/TE.CL table already covers —
don't treat them as a separate class needing a separate proof bar, just a wider set of ways to
reach the same disagreement. Reference: https://portswigger.net/research/http1-must-die

## HTTP Terminator — new desync triggers (PortSwigger / James Kettle, Aug 2026)
An AI-assisted research harness generated ~30,000 candidate desync vectors, found ~700 vulnerable
live targets, and produced an Apache Traffic Server 0-day (CVE-2026-63078). Practical takeaway for
us: the CL.TE/TE.CL trigger table above is no longer the whole list — these four new triggers hit
servers that PASS a classic Smuggler scan, so re-scan anything previously ruled clean.

**Trigger A — `Transfer-Encoding: gzip` on an HTTP/1.0 request → CL.0 desync.** Several server
implementations produce a CL.0 desync from an unrecognised TE value here. Confirmed in the wild
against a US government site and F5 BIG-IP deployments.
```
GET / HTTP/1.0
Transfer-Encoding: gzip
Content-Length: N

X
```

**Trigger B — `Content-Type: multipart/byteranges` as a CL.0 trigger.** The RFC only discusses
byteranges in a RESPONSE context; servers that reuse one parser for both directions apply the
response-side rule to your request (exactly the shared-parser confusion idea below). Hit 200+ sites
including a US bank.
```
POST / HTTP/1.1
Content-Type: multipart/byteranges; boundary=BOUND
Content-Length: 123

<smuggled prefix>
```

**Trigger C — duplicate but IDENTICAL `Content-Length`.** Classic lore says duplicate-and-DIFFERING
CL is the bug; here two MATCHING values make some servers treat the request as zero-length →
cross-request contamination. Used against SSO servers and a misconfigured Citrix NetScaler that
exposed bank API keys.
```
GET / HTTP/1.1
Host: target
Content-Length: 28
Content-Length: 28

GET /x HTTP/5.1
X: X
```

**Trigger D — the "dangling byte" technique (response-queue poisoning reliability fix).** Send the
smuggled request one byte SHORT of complete: the back end cannot generate the response until the
victim's request supplies that final byte, which removes the race window entirely on method-agnostic
back ends ("completely eliminated the race condition"). This is the reliability fix for RQP, not a
new desync class.

**Shared-parser confusion — the pattern behind Trigger B.** Servers that reuse one parsing routine
for both requests and responses will apply RESPONSE-only rules to a REQUEST. Trigger B is one
instance. Others: `Set-Cookie` processing on a request, Range/cache handling on a request, and
**status-line injection** — the server copies the request's protocol token verbatim into the
response status line:
```
GET / COW<
Host: target

→  COW< 200 OK
```
When hunting, ask: "what response-side feature might this server accidentally run on my request?"

**Tooling.** The Burp **HTTP Request Smuggler** extension was updated with these vectors plus
request-contamination detection; **Param Miner** gained the protocol-ruler header technique;
**Turbo Intruder** gained an MCP interface; HTTP Terminator itself is open source. Install the
first three from the BApp store and re-scan targets that were previously clean.

Impact statement: same ceiling as the rest of this doc — auth bypass, cache poisoning, credential
capture on desyncable front/back pairs; Triggers A-C are the ones that turn a previously "clean"
scan into a finding. The safety caution in the Method section stays in force: these poison shared
infrastructure — prove with self-targeted requests, get explicit go-ahead before anything touching
a shared cache.
Reference: https://portswigger.net/research/http-terminator

## Method
1. Fingerprint front-end (CDN/proxy) + confirm a back-end exists.
2. Burp Smuggler scan → confirm CL.TE/TE.CL/H2.* with the **timing** technique (least collateral).
3. Prove a concrete impact (auth bypass to /admin, or capture your OWN second request) — **avoid
   poisoning shared caches / other real users on prod**; demonstrate with self-targeted requests.
→ `validate.md` → `findings/` with the exact smuggle payload + the desync evidence.
> This class can disrupt other users — keep PoCs self-contained and get explicit ok before anything
> that touches a shared cache or another user's traffic.
