# Moraa — DNS Rebinding (when the SSRF filter is the obstacle)

> The complement to [[ssrf]]: where that doc's IP-encoding tricks beat a STRING filter,
> rebinding beats a RESOLUTION check. Any defense of the shape "resolve the hostname, check the
> IP against an allowlist/denylist, then fetch the URL" has a gap between the two lookups —
> rebinding is the exploit for that gap. Cross-ref [[ssrf]] (the rest of the bypass table),
> [[controls-and-oracles]] (the gate in §5 is mandatory — an unproven re-resolve is a shrug,
> and an unproven immunity is equally worthless).

## 1. The mechanism — TOCTOU between two resolutions

```
validation:  attacker.test  ──resolve──▶  1.2.3.4   (YOUR ip → passes the allowlist/denylist)
                 …gap…                 (TTL expired; resolver cache expired)
fetch:       attacker.test  ──resolve──▶  169.254.169.254 / 10.0.0.5   (internal → the fetch)
```
The check resolves ONCE, the HTTP client resolves AGAIN (or the connection re-resolves after the
first is dropped). The attacker controls both answers via their own authoritative DNS with a
tiny TTL. If the target resolves once and CONNECTS TO THAT IP directly, there is no second
lookup and rebinding cannot work — which is exactly what §5 makes you prove.

## 2. Setting up attacker-controlled two-answer DNS

```bash
# PUBLIC rebinding services (fastest, fine for authorized testing):
#   rbndr.us  — two hex-encoded IPv4 addresses as labels, alternating answers:
#     <hex-of-your-ip>.<hex-of-target-ip>.rbndr.us     e.g. 7f000001.c0a80001.rbndr.us
#   1u.ms      — make-A-record syntax with an initial-then-rebind answer pair (read its docs for the exact RR grammar)
python3 -c 'import socket,struct;print(".".join("%02x"%b for b in socket.inet_aton("10.10.14.2")))'
#   → your IP as hex for the rbndr label

# YOUR OWN (deterministic, no third party): delegate a subdomain to a tiny authoritative server
#   you control, answer alternately with TTL 0:
#   - any nameserver you run (even a 30-line UDP responder) answering:
#       attacker.test.  0  IN  A  <your-ip>        # first query
#       attacker.test.  0  IN  A  <internal-ip>    # every subsequent query
#   delegate: NS record attacker.test → your NS host, glue A record set. Full control = you can
#   script EXACT sequences (§5's proof needs a deterministic two-answer record, not random alternation).
```
Honest caveat: caches fight you. Public recursive resolvers and the target's own resolver may
enforce a minimum TTL or ignore TTL 0 for a few seconds — that's why alternating/first-N answers
patterns exist, and why §5's proof uses MANY requests rather than one lucky flip.

## 3. Why it defeats resolution-time validation

Any validator that converts hostname → IP once and judges the IP is beaten, because the judgment
is about a DIFFERENT connection than the one actually made. This includes: denylists checking
against RFC1918/link-local ranges, allowlists expecting your registered domain, and "SSRF
protection" middleware that resolves-then-checks then hands the ORIGINAL hostname to the HTTP
client. What it does NOT beat:
- **connect-by-IP validators** — resolve once, then connect to the validated IP (no name survives
  to the fetch);
- **pinned connections** — the fetch reuses an already-established connection (see §4);
- **response-side checks** — nothing here is invisible: if the fetch is followed by a body/redirect
  inspection, rebinding only got you the request, not the data (blind vs non-blind, same split
  as [[ssrf]]).

## 4. Which stacks are actually vulnerable — ask "does it re-resolve?"

| Client behaviour | Rebinding outcome |
|---|---|
| New connection per request, name passed to the resolver each time (naive `requests`/`curl` per-call, most HTTP libs' default) | **vulnerable** — second lookup happens, answer two lands |
| Connection pooling / keep-alive reused across validate→fetch | **defeated** — one resolution, one connection; the rebind never gets asked |
| OS/runtime DNS cache with honored TTL > your window | **defeated for that window** — retry over a longer horizon; still prove it (§5) |
| Client resolves once then dials the IP (`--resolve`-style, explicit-IP constructors) | **structurally immune** — no name in the fetch path |

Test the actual runtime, not the framework's reputation: a Go service with the default transport
pools connections (immune per-connection), while per-job HTTP clients that build a fresh client
per request re-resolve. The `Connection: close` header on the target's responses (forcing new
connections) is a hint the pooling defense is absent.

```bash
# the rebinding SSRF probe — validate-time and fetch-time see different answers:
#   (target endpoint: "fetch this URL for you" feature with hostname validation)
curl -s "https://TARGET/fetch?url=http://<hex-yours>.<hex-internal>.rbndr.us:PORT/path" \
     -H "Cookie: $AUTH" -o /tmp/rebind.out -w '%{http_code} %{size_download}\n'
# repeat N times — each request is a fresh coin-flip between the two answers; internal-content
# responses are the wins. This is a probe loop, not a single shot:
for i in $(seq 1 20); do
  curl -s -m 8 "https://TARGET/fetch?url=http://<hex-yours>.<hex-internal>.rbndr.us:PORT/path" \
       -H "Cookie: $AUTH" -o /tmp/rb-$i.out -w '%{http_code} %{size_download}\n'; sleep 1; done
```

## 5. Browser-side rebinding — the victim's own network

Classic browser rebinding: victim visits YOUR page; `attacker.test` first resolves to your server
(serving the malicious JS), then rebinds to an INTERNAL service on the victim's network — the
browser then reads internal responses (same-origin after the rebind, since the origin is your
hostname). Modern browsers partially mitigate with DNS pinning, and `Host:` header routing on the
internal service may reject your hostname — state both when assessing, and note the modern
variants (host-header stays yours; services that ignore Host — many internal admin panels,
dev servers, metrics endpoints — don't care). Severity logic = a logged-out victim's internal
surface, which on a corporate network is a pivot-grade finding; it's a DELIVERY question, so
weigh it like any self-XSS/drive-by chain: real only with a plausible delivery vector.

## 6. Defences that actually work (what to recommend — and what NOT to)

Works:
1. **Resolve once, connect by IP** — do the lookup, validate the IP, dial the IP (with SNI/Host
   set deliberately); the name never survives to the fetch.
2. **Validate POST-resolution** — check the CONNECTED peer address (socket-level), not just the
   pre-flight lookup.
3. **Host/domain allowlisting** at the URL-feature level (only `api.provider.com` may be fetched),
   which kills rebinding AND redirect games in one move.
4. Redirect handling that re-validates each hop (same as [[ssrf]]'s redirect section).
Do NOT recommend (the folklore that doesn't hold): "block TTL 0" (attacker uses TTL 1; caches lie
anyway), "double-resolve and compare" (the attacker's server can answer sequentially by design),
"strip private IPs from responses" (blind intranet reach is still a finding).

## 7. Impact gate — prove the re-resolve or drop the claim

**Rebinding is only a finding if the target ACTUALLY re-resolves — prove it with a controlled
two-answer record, never by asserting the TOCTOU.** The minimum proof:

```bash
# 1. control A — your answer FIRST, internal SECOND (deterministic own-server, not alternating):
#    validation sees your IP → passes. Fetch hits internal → response DIFFERS from all baselines.
# 2. control B — SAME request against a hostname that resolves ONLY to your IP for both answers:
#    response must equal the "external content" baseline.
# 3. control C — a hostname that resolves ONLY to the internal IP, which the validator must REJECT:
#    this is the reading that proves a validation layer EXISTS.
# A passing rebinding claim = (A shows internal content) + (B external baseline) + (C rejected).
```
Without control C you cannot even claim there's a check to bypass ([[controls-and-oracles]]:
fire the control that must read the opposite way); without control B an odd response could be
the app's generic error. Then the usual chain rule applies: internal reach → metadata → creds is
the [[ssrf]] payoff path; a re-resolve that reaches only a harmless host is a Hardening note.
Route through [[validate]] before `findings/`.

---

## Gate: count the resolves BEFORE reaching for rebinding

Rebinding is a TOCTOU on **resolve-validate -> resolve-fetch**. It needs the target to resolve the
hostname **at least twice**. So the first question is never "which rebinding tool" — it is **how
many times does this server resolve my name at all?**

Measure it with a collaborator hostname and count DNS interactions:

- **2+ resolves** -> rebinding is the right attack. Proceed with two-answer attacker DNS.
- **1 resolve** -> there is a fetch but no separate validation resolve. Rebinding is pointless
  (nothing is being validated); you want plain SSRF with a literal, or a redirect.
- **0 resolves** -> **there is no request to race.** Rebinding cannot manufacture a fetch the
  server never performs. Stop; the parameter is stored config, not an outbound-request sink.

The 0-resolve case is the common one on "feels like SSRF" parameters that are really **client-side
config** being stored and handed back to a client — VPN endpoints, WireGuard `dns`, NTP servers,
syslog targets, STUN/TURN hosts, proxy settings in a device profile. The field accepts a hostname,
accepts `169.254.169.254`, returns 200, and never touches the network. Accepting a metadata literal
with **no filter at all** is itself the tell: rebinding exists to defeat a filter, so a surface with
nothing to defeat is a surface with no fetch.

### Corollary: a 0-resolve negative is only valid with a proven-live channel AND a dwell window

Two ways that negative goes wrong:

1. **Dead OOB channel.** Always fire a positive control from your own host
   (`nslookup <payload>` + `curl http://<payload>/control`) and confirm both land, *in the same
   session*. An unproven channel turns every blind test into an ungraded one.
2. **Create-then-delete too fast.** Probing a write endpoint by creating an object and deleting it
   seconds later only tests **synchronous** resolution on the create path. It misses a background
   validator, a reachability health-check, or a **config-push worker that resolves at send time** —
   and a push-time resolve is exactly the second resolve rebinding needs.

So for any stored-config parameter, **plant a persistent canary and leave it**: one object per
candidate field, carrying a collaborator hostname, named so it is obviously yours, and left in place
across a long poll window. Record the ids in the finding so nobody deletes them early. Then the
verdict is honest in both directions — a late DNS hit overturns the negative and promotes the lane
to rebinding; a silent window closes the whole SSRF family for that parameter.

Worked example, `vpnmgr.svc.acme.example` VPN profiles (2026-10-28): `wg_server_endpoint`/`wg_dns` accepted
hostnames, loopback and both metadata addresses with a 200, while `wg_address`/`wg_allowed_ips` were
strictly `netip.ParsePrefix`-parsed. Zero resolutions with a proven-live channel => no SSRF, and
rebinding inapplicable rather than merely unsuccessful. Three canaries left planted for the
async path. Residual caveat worth copying: the push path needed an adopted device, and binding was
`403` even for the owner, so a push-time resolve can exist yet stay unobservable — say so in the
finding instead of over-claiming the negative.
