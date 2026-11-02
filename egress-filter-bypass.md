# Egress Filter / DPI Bypass — network censorship & egress-control assessment

**Use when:** you are on a network (client office, guest WiFi, hotel, ISP, country-level) that blocks
destinations, and you need to (a) characterise *how* it blocks, and (b) get traffic through.
Also the methodology for an **egress-filtering control test** on a pentest — proving a client's
"we block social media / C2 / exfil" control is bypassable is a legitimate finding.

**Authorization:** only on networks you own or are authorized to test. On a client engagement this
belongs in scope as an egress-control test; the write-up is the deliverable, not the YouTube access.

---

## 0. The rule: characterise before you tunnel

Everyone reaches for a VPN first. Don't. **Identify the layer the block lives at** — it dictates
which bypass is a one-liner and which needs infrastructure, and the *characterisation itself* is
what you put in the report.

Seven layers a block can live at. Walk them in order; the first one that fails is your answer.

| # | Layer | Test | Signature of a block at this layer |
|---|---|---|---|
| 1 | **DNS** (NXDOMAIN / sinkhole / RPZ) | `dig +short A target @local-resolver` vs `@1.1.1.1` | Differs from public resolver; returns `0.0.0.0`, `127.0.0.1`, RFC1918, or the filter's portal IP |
| 2 | **IP / route** (null route, ACL) | `timeout 5 bash -c 'exec 3<>/dev/tcp/<ip>/443'` | TCP never completes to the real IP |
| 3 | **TLS SNI** (DPI ClientHello parse) | TCP OK to the IP, but TLS fails with real SNI and **succeeds with a benign SNI to the same IP** | The discriminator — see §1 |
| 4 | **HTTP Host** (plaintext :80) | `curl -I http://target/` | 403 / block page while HTTPS behaves differently |
| 5 | **TLS cert / SAN inspection** | Block survives SNI tricks but dies after ServerHello | Filter reads the server cert, not the ClientHello |
| 6 | **Explicit proxy / PAC** | `env | grep -i proxy`, Windows PAC, `netsh winhttp show proxy` | Policy-based categorisation, block page with a vendor banner |
| 7 | **Protocol / port** (QUIC, WireGuard, OpenVPN, Tor) | UDP/443, 2408, 1194, 51820, 9001 reachability | Specific L4 ports dead while TCP/443 is fine |

### The decisive SNI test (layer-3 discriminator)

This single test separates "they blocked the IP" from "they're reading your ClientHello":

```bash
IP=$(dig +short www.youtube.com | head -1)

# a) does TCP reach the real server at all?
timeout 5 bash -c "exec 3<>/dev/tcp/$IP/443" && echo "TCP OK"

# b) real SNI
timeout 8 openssl s_client -connect $IP:443 -servername www.youtube.com </dev/null 2>&1 | head -5

# c) benign SNI, SAME IP, SAME port
timeout 8 openssl s_client -connect $IP:443 -servername www.google.com </dev/null 2>&1 | head -5
```

**TCP OK + (b) silently dropped + (c) returns a cert ⇒ SNI-based DPI, nothing else.**
Nothing about the IP, the route, or the port is blocked — the string in your ClientHello is.

### Fingerprint the filter's behaviour (goes straight in the report)

```bash
# drop vs RST — drop = inline tap/IPS; RST = inline injector. Drop means timeouts, RST means instant fail.
timeout 10 curl -sv https://target/ 2>&1 | grep -iE "reset|timed out|Empty reply"

# normalisation quality: does it lowercase and strip the trailing dot?
for s in target.com TARGET.COM Target.Com target.com. ; do
  printf "%-20s " "$s"
  timeout 8 openssl s_client -connect $IP:443 -servername "$s" </dev/null 2>&1 \
    | grep -qE "subject=" && echo PASS || echo BLOCKED
done

# blocklist granularity: exact host, or whole domain + CDN + API?
for h in target.com www.target.com m.target.com api.target.com cdn.target.com; do
  printf "%-26s " "$h"; curl -s -o /dev/null -w "%{http_code}\n" --max-time 8 "https://$h/"
done
```

A filter that normalises case **and** trailing dots is a commercial DPI (Fortinet / Palo Alto /
Netskope / Zscaler class), not an iptables string match. Skip §2 entirely and go to §3/§4.

---

## 1. Tier 1 — the block is narrower than it looks (free wins, no tooling)

Blocklists are **curated host lists**, and curation is always incomplete. Before any tunnel, map
the *edges* of the list. This is the highest-yield step and costs three minutes.

- **Sibling hosts of the same service.** The web frontend is on the list; the **API backend, mobile
  API, CDN, and media origin usually are not** — different hostnames, added by whoever wrote the list
  only if they thought of them.
  - YouTube: `www.youtube.com` blocked, but check `youtubei.googleapis.com` (InnerTube — the API the
    real client uses), `redirector.googlevideo.com` / `*.googlevideo.com` (the actual video bytes),
    `i.ytimg.com`, `yt3.ggpht.com`.
  - Meta: `www.facebook.com` vs `graph.facebook.com`, `mbasic.facebook.com`, `*.cdninstagram.com`,
    `www.messenger.com`, `*.whatsapp.com`.
  - Generic: `api.`, `m.`, `mbasic.`, `cdn.`, `static.`, `*-api.`, regional TLDs, the raw apex.
- **Plaintext HTTP.** Many SNI-only filters never touch port 80. `curl -I http://target/` returning
  301/200 means the Host header is not inspected — useful for API work even when browsing isn't.
- **IPv6.** Blocklists are routinely v4-only. `curl -6 https://target/` — if the network has v6
  egress this is often a complete, zero-effort bypass.
- **Alternative frontends** (read + media, in-browser, nothing to install):
  - YouTube → Invidious (`yewtu.be`, `invidious.nerdvpn.de`, `inv.nadeko.net`), Piped (`piped.video`),
    `www.youtube-nocookie.com` (embed host — check separately, sometimes off the list).
  - Twitter/X → Nitter instances. Reddit → `old.reddit.com`, Libreddit/Redlib. Instagram → Imginn/Bibliogram.
  - These work because the SNI on the wire is the frontend's domain. Instance uptime is the limiting
    factor, not the filter — keep 3+ in your pocket.
- **Server-side fetch proxies** (read-only, zero install, instant):
  - `https://r.jina.ai/https://<blocked-url>` — renders the page server-side and hands you Markdown.
  - Google cache / Wayback (`web.archive.org`), `allorigins.win`, `corsproxy.io`, text-mode proxies.
  - Great for recon and reading; no auth, no video, no interactivity.

> **Report framing:** if a sibling API host reaches the same service the policy forbids, the control
> is bypassed *by the vendor's own blocklist being hostname-based*. That is the finding — write it as
> "policy intent not enforced: blocklist covers frontends only, service fully reachable via `<host>`."

---

## 2. Tier 2 — defeat the DPI parser itself (no third party, no infra)

Works against naive / stateless SNI matchers. **Fails against anything that does TCP reassembly** —
test it, don't assume. If §0's normalisation test showed case+dot handling, these will fail too.

| Technique | Mechanism | Tool |
|---|---|---|
| **ClientHello fragmentation** | Split the TLS record across several small TCP segments so the SNI string never appears in one packet | GoodbyeDPI `-f 2`, zapret, SpoofDPI, Green Tunnel, ByeDPI |
| **TCP segmentation + desync** | Send a decoy ClientHello with a low TTL / bad checksum that dies before the server but is what the DPI sees | zapret `--dpi-desync=fake`, GoodbyeDPI `--fake` |
| **TLS record splitting** | Two TLS records, SNI straddling the boundary | SpoofDPI, ByeDPI |
| **SNI case / trailing dot** | Naive exact-match lists | `-servername TARGET.COM`, `target.com.` |
| **Out-of-order segments** | DPI reassembles wrongly, real stack reassembles right | zapret `--dpi-desync=disorder2` |
| **No SNI + IP-direct** | Omit SNI entirely | Only works on single-tenant origins — shared frontends return `invalid2.invalid` |
| **ECH (Encrypted ClientHello)** | SNI is encrypted; DPI sees only the public outer name | Needs an `ech=` param in the target's HTTPS/SVCB RR + DoH. Check: `dig +short HTTPS target @1.1.1.1` |

**Quick fragmentation test** (no root, proves reassembly behaviour before you install anything):
stand up a local forwarder that dribbles the first client write out in 2-byte segments, point curl
at it with `--resolve`, and compare against an unfragmented control to the same upstream IP. If both
fail identically, the DPI reassembles — stop here and go to §3.

**ECH reality check:** ECH only helps if the target publishes it. Cloudflare-fronted sites largely
do; Google properties (YouTube) **do not** — `dig +short HTTPS www.youtube.com @1.1.1.1` with no
`ech=` param means ECH is not an option, regardless of browser support.

---

## 3. Tier 3 — tunnel out through an SNI the filter allows

Once §0 proves the block is hostname-based and TCP/443 to arbitrary hosts is open, **every one of
these works**, because the only thing on the wire is a TLS session to an unlisted domain.

Precondition to verify first:
```bash
curl -s -o /dev/null -w "%{http_code}\n" --max-time 8 https://<any-unlisted-host>/   # expect 200/3xx
curl -s -o /dev/null -w "%{http_code}\n" --max-time 8 \
  "https://1.1.1.1/dns-query?name=example.com&type=A" -H "accept: application/dns-json"  # DoH open?
```

| Option | Needs | Notes |
|---|---|---|
| **SSH dynamic SOCKS over 443** | A VPS | `ssh -D 1080 -p 443 user@vps -N` → set browser SOCKS5 to `127.0.0.1:1080`. Simplest full tunnel. Add `-o ServerAliveInterval=30`. |
| **sslh / stunnel-wrapped SSH** | A VPS | Makes the SSH look like TLS on 443 if plain SSH on 443 is fingerprinted |
| **Cloudflare WARP** | Nothing | Free. Prefers UDP 2408 — if UDP is blocked, force its TCP/MASQUE-over-443 mode. Registration API `engage.cloudflareclient.com:443` reachable is a good sign. |
| **WireGuard over TCP/443** | VPS | Native WG is UDP (usually blocked); wrap with `udp2raw`, `wstunnel`, or `phantun` |
| **OpenVPN `--proto tcp --port 443`** | VPS | Classic; TLS-looking on the right port |
| **V2Ray / Xray (VLESS+TLS / Trojan / ShadowTLS)** | VPS + domain | Purpose-built for exactly this filter class; indistinguishable from HTTPS to the fronting domain |
| **Tor + obfs4 / snowflake / meek** | Nothing | `snowflake.torproject.org` reachable ⇒ snowflake viable even when `bridges.torproject.org` is listed. Slow but needs zero infrastructure. |
| **Cloudflare Worker / Vercel / Netlify reverse proxy** | Free account | Deploy a tiny proxy; your SNI becomes `*.workers.dev` / `*.vercel.app`. Verify the platform's apex isn't itself listed. |
| **wstunnel** | VPS | Tunnels anything inside a WebSocket over 443 — survives most L7 proxies too |

**Pick-one heuristic:** no VPS and need it now → WARP, then Tor+snowflake. Have a VPS → `ssh -D` on
443 first, Xray/VLESS if that gets fingerprinted. Need it for a whole subnet → WireGuard-over-TCP on
a jump host.

---

## 4. Tier 4 — the filter is an explicit proxy, not inline DPI

Different beast: the network forces traffic through a proxy that categorises destinations, often
with TLS interception (its own CA in your trust store).

- Find it: `env | grep -i proxy`, `netsh winhttp show proxy`, the PAC file URL, `cat /etc/environment`,
  browser settings, WPAD (`http://wpad/wpad.dat` — **read the PAC**: it usually enumerates the
  whole bypass list and the internal networks in plaintext).
- **PAC bypass list** — hosts in `DIRECT` branches skip the proxy entirely. Often includes wildcard
  internal domains and CDNs you can abuse as a tunnel endpoint.
- **CONNECT to a non-standard port** — many proxies only categorise 80/443 and allow blind CONNECT
  elsewhere: `curl -x http://proxy:8080 -p https://your-vps:8443/`.
- **Host header vs CONNECT authority mismatch** — the proxy categorises on one, routes on the other.
  Classic smuggling-adjacent bug; see `request-smuggling.md`.
- **TLS interception check** — if the served cert chains to a corporate CA, everything is readable.
  That's its own finding: `openssl s_client -connect site:443 | openssl x509 -noout -issuer`.
- Cert-pinned apps break under interception → the proxy keeps a **pinning bypass list** of hosts it
  passes through untouched. Those hosts are your uninspected tunnel.

---

## 5. Worked example — 2026-10-13, local network

Characterisation, in the order above:

| Layer | Result |
|---|---|
| DNS | **Clean.** `youtube.com`, `facebook.com`, `instagram.com` all resolve to real public IPs. No sinkhole. |
| IP/route | **Clean.** Raw TCP to `142.251.153.4:443` (a YouTube frontend IP) completes. |
| **TLS SNI** | **THE BLOCK.** Same IP, same port: `-servername www.youtube.com` → silently dropped; `-servername www.google.com` → valid `CN=www.google.com` cert. |
| HTTP :80 | **Not filtered.** `http://www.youtube.com/` → 301. Host header not inspected. |
| QUIC / UDP | Blocked — `--http3-only` to YouTube fails; WireGuard (51820) and OpenVPN (1194) ports closed. |
| Normalisation | **Competent DPI.** Uppercase, mixed case, and trailing-dot SNI all blocked ⇒ commercial-grade, not a string match. |
| Reassembly | **Full TCP reassembly.** 2-byte-segment ClientHello fragmentation failed identically to the unfragmented control ⇒ Tier 2 is dead on this network. |
| ECH | **Unavailable.** `dig HTTPS www.youtube.com` publishes no `ech=` param. |

**Blocklist scope — narrow and frontend-only:**

- Blocked: `youtube.com`, `www.`/`m.`/`music.youtube.com`, `www.youtube-nocookie.com`, `i.ytimg.com`,
  `yt3.ggpht.com`, `facebook.com` (+`www`/`m`/`mbasic`/`graph`), `instagram.com`,
  `scontent.cdninstagram.com`, `www.messenger.com`.
- **Not blocked:** `youtubei.googleapis.com` (YouTube's InnerTube API — returned a real API error, so
  the connection completed), `redirector.googlevideo.com` → **404, i.e. the video CDN is reachable**,
  all of `*.whatsapp.com`, and every other social platform tested — Twitter/X, TikTok, Reddit,
  Telegram Web, Discord, LinkedIn, Snapchat.
- Frontends reachable: `yewtu.be`, `piped.video`, `invidious.nerdvpn.de`, `r.jina.ai`,
  `snowflake.torproject.org`, `vercel.app`.

**Proven working bypass:** `https://r.jina.ai/https://www.youtube.com/watch?v=jNQXAC9IVRw` returned
the genuine page (`Title: Me at the zoo - YouTube`) — a server-side fetch proxy defeats a
hostname-based filter completely, because the wire SNI is `r.jina.ai`.

**Conclusion / what this network's control is actually worth:** the policy intent ("block YouTube and
Meta") is enforced *only* against web frontend hostnames over TLS. The media CDN, the mobile API,
plain HTTP, every alternative frontend, and all other social platforms pass. Tier 1 and Tier 3 both
work; Tier 2 does not. A single `ssh -D 1080 -p 443` or Cloudflare WARP session nullifies it entirely.

**If this were a client engagement, the finding is:**
> *Egress content-filtering control is hostname-scoped and trivially bypassable (Medium).* The DPI
> enforces a curated SNI blocklist with no coverage of sibling API/CDN hostnames, no port-80
> enforcement, no QUIC-era equivalence, and no outbound-tunnel detection on TCP/443. Any user can
> reach the forbidden service via the vendor's own media CDN, via a third-party frontend, or via a
> commodity TLS tunnel. *The same gap means the control provides no defence against C2 or data
> exfiltration over TLS/443* — which is the part that actually matters.

---

## 6. Pivot: what an egress gap means offensively

Characterising egress is not just about reaching blocked sites — it is **C2 and exfil channel
selection** (see `initial-access.md`, `pivoting.md`).

- Which ports leave? 443 only, or 22/53/123 too? → picks your C2 transport.
- Is TLS intercepted? → pinning / certificate-pinned C2 dies, but the **pinning bypass list** is a
  free uninspected channel.
- Is DoH open? (`1.1.1.1/dns-query` reachable) → DNS-over-HTTPS C2 and exfil, invisible to any
  DNS-log-based detection.
- Is plain DNS to external resolvers allowed? → DNS tunnelling (iodine, dnscat2).
- Does the blocklist cover *categories* or *hostnames*? Hostname-based means any fresh domain or
  cloud frontend (`*.workers.dev`, `*.vercel.app`, `*.blob.core.windows.net`) is an open channel.
- Does the filter log? Drop-without-RST plus no block page usually means an inline tap with
  logging — assume your probes are recorded, and say so in the engagement notes.

---

## 7. Quick reference — one-liner ladder

```bash
T=www.youtube.com; IP=$(dig +short $T | head -1)

dig +short A $T @1.1.1.1                                     # 1. DNS sinkholed?
timeout 5 bash -c "exec 3<>/dev/tcp/$IP/443" && echo TCP-OK  # 2. IP routable?
openssl s_client -connect $IP:443 -servername $T </dev/null  # 3. real SNI
openssl s_client -connect $IP:443 -servername www.google.com </dev/null  # 3b. benign SNI = SNI filter
curl -I --max-time 8 http://$T/                              # 4. port 80 open?
curl -6 -s -o /dev/null -w "%{http_code}\n" https://$T/      # 1b. IPv6 bypass?
dig +short HTTPS $T @1.1.1.1                                 # ECH available?
curl -s "https://r.jina.ai/https://$T/" | head -5            # server-side proxy
ssh -D 1080 -p 443 user@vps -N                               # full tunnel
```

**Cross-refs:** `recon.md` (surface mapping), `initial-access.md` + `pivoting.md` (C2 channel
choice), `request-smuggling.md` (proxy authority/Host mismatch), `enterprise-vpn-attack.md`
(the appliance itself as a target), `reporting.md` (writing the control-failure finding).
