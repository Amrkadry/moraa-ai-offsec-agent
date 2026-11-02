# Moraa — Burp Suite MCP workflow

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> When the Burp MCP server is connected (registers as e.g. `burp` — confirm the tool prefix in the
> session's tool list), prefer it for anything request-related over hand-rolled curl. Burp holds the
> **live authenticated state** (proxy history, sitemap, cookies, the user's active session) — that's
> the ground truth. Commands-first still applies: read what's there, then act.

## Connect Burp to Claude Code (one-time setup) — CONFIRMED WORKING
```
1. Burp desktop: Extensions → BApp Store → "MCP Server" (PortSwigger) → Install.  (Burp 2025.x+;
   Pro recommended — Community works but no Scanner tools. Native extension, no Jython.)
2. Burp → MCP tab → Enable. Note the host/port (default 127.0.0.1:9876).
3. Download PortSwigger's stdio bridge `mcp-proxy.jar` (from the MCP tab) and register it as a
   STDIO server (needs Java 17+):
     claude mcp add --scope user burp -- java -jar "C:\path\to\mcp-proxy.jar" --sse-url http://127.0.0.1:9876
4. Verify:  claude mcp list   → burp ✔ Connected   (or /mcp inside a session; approve the tools).
```

### Connect Burp to ZCode (same bridge — CONFIRMED WORKING 2026-10-23)
ZCode reads MCP servers from `~/.zcode/cli/config.json` under the **nested `mcp.servers`** key
(strict schema — unknown keys silently drop the server; `command` is a string, `args` an array;
no `${...}` template expansion — absolute paths only). Same jar, same base-URL rule (no `/sse`):

```json
"mcp": { "servers": { "burp": {
  "type": "stdio",
  "command": "java",
  "args": ["-jar", "C:\\Users\\<you>\\Documents\\mcp-proxy.jar", "--sse-url", "http://127.0.0.1:9876"]
} } }
```

Tools register as `mcp__burp__<tool>` at the **next session start** (all scopes auto-connect).
Check status in **Settings → MCP**; if `failed`, run the jar command by hand and read its stderr.
Pre-flight check before relying on it: `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9876/`
(200 = Burp MCP BApp enabled and listening). Validate the bridge standalone any time:

```bash
(printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}\n'; sleep 5) \
  | java -jar "C:\Users\<you>\Documents\mcp-proxy.jar" --sse-url http://127.0.0.1:9876
# expect: "Successfully connected to SSE server" + an initialize result with capabilities
```
> **Use the jar proxy, NOT a direct SSE registration.** Burp's MCP server does not speak plain
> MCP-over-SSE to Claude's native SSE client — `claude mcp add --transport sse burp http://127.0.0.1:9876/sse`
> fails with **HTTP 404**. The `mcp-proxy.jar` stdio bridge (`--sse-url http://127.0.0.1:9876`, no
> `/sse` suffix — the proxy handles the path/protocol) is the working method. Pass the base URL only.
> If you get a "conflicting scopes" warning, you registered burp twice — keep the jar-proxy entry and
> `claude mcp remove burp -s <other-scope>`.
> Credentials: prefer env vars (`MCP_SSE_URL`, `MCP_AUTH_TOKEN`) over CLI args (proxy warns on this).
> WSL↔Windows: if Claude runs in WSL and Burp on Windows, use `/mnt/c/...` jar path + a WSL Java, and
> point `--sse-url` at the Windows host IP (`grep nameserver /etc/resolv.conf`); simplest is same side.
> Keep Burp running with the MCP server enabled. Only replay against in-scope hosts.

## When to reach for Burp MCP vs curl/httpx
- **Burp MCP:** replaying/tampering a captured request, reading the real sitemap/proxy history,
  Repeater-style iteration on one request, Intruder-style fuzzing of a param with the user's session,
  decoding, scanning a specific request. The session cookies/headers are already correct.
- **curl/httpx/ffuf (WSL):** broad host sweeps, subdomain/content discovery, unauthenticated probes,
  anything scripted across many hosts. Then pull the interesting request into Burp for depth.

## Standard flow (adapt to the actual tool names the MCP exposes)
```
1. LIST/READ sitemap + proxy history   → inventory endpoints the user already browsed (authed).
   - grep the history for: /api, /graphql, /admin, params with ids, file ops, redirects, tokens.
2. PULL a target request                → get method, URL, headers, cookies, body verbatim.
3. REPEATER replay                      → reproduce baseline, then mutate ONE variable at a time:
   - authz: swap the id / resend with account B's session (two-account IDOR).
   - injection: SSRF collaborator, SQLi probe, SSTI {{7*7}}, path traversal, per web-hunt.md.
   - method/verb swap (GET→PUT/DELETE), content-type swap, remove auth header.
4. INTRUDER/fuzz a single param         → id enumeration, wordlist a param, boolean/time oracle.
5. DECODER/encoder                      → base64/url/jwt as needed.
6. SCAN one request (if available)      → triage, then MANUALLY verify every hit (no raw scanner reports).
```

## Rules of engagement with Burp MCP
- **Always keep `auth.json` tokens fresh from live Burp traffic — don't wait for the user to paste
  a capture.** Whenever Burp MCP is connected, check the proxy history for newer session
  cookies/JWTs/Bearer tokens for accounts already tracked in `auth.json` before assuming a stored
  token is current — session tokens rotate/refresh constantly (see the `VENDOR_SSO_AUTH` server-side
  re-issue pattern elsewhere in this skill set) and a stale one produces false "dead session"
  negatives. `get_proxy_http_history_regex` paginates **oldest-first from offset 0** on a live
  target with a large history — don't page from the start hunting for the newest entry; query a
  narrow regex scoped to the exact host/cookie-name you need, or (cheaper) just try the credential
  you have first and only fall back to a Burp history pull if it's dead. Update `auth.json` in
  place the moment a fresher token is found — note the capture timestamp so staleness is obvious
  next time.
- **Read before write.** Inventory the sitemap/history first; don't re-crawl what Burp already has.
- **One variable per replay** so the signal is clean (the authz status-code methodology in
  `framework-misconfig.md §7` reads best when only the id/session/verb changed).
- **Two-account IDOR via Burp:** keep account A's request, swap only the session cookie to B (or use
  Burp's session-handling / a second browser profile), resend, diff. Both accounts must be the user's.
- **Collaborator/OAST:** use Burp Collaborator for blind SSRF/XXE/OOB (unique token per test); a
  DNS-only hit still proves the fetch — scope it (see `ssrf.md §4`).
- **Scope guard:** only replay against in-scope hosts (per `auth.json`/the program). Burp makes it
  easy to fire at anything in history — check the host before sending.
- **Evidence:** capture the exact request+response from Repeater into `findings/` (real proof, not a
  200). Redact secrets before saving.
- **Don't auto-run destructive requests** (DELETE, password reset on real accounts, mass Intruder on
  prod) without the user's ok — same as any outward-facing action.

## Typical Burp-MCP-driven hunt on a fresh target
```
sitemap/history → rank endpoints by crown-jewel value → for the top one:
  Repeater: baseline → authz probe (B session + id swap) → injection probes → verb swap
  → if signal: Intruder to enumerate/confirm → validate.md → findings/  → update coverage.md
```
> If the MCP exposes a "send to sqlmap"/export-request capability, export the raw request and run
> `sqlmap -r req.txt` (see `sqli.md`) — Burp captures the auth, sqlmap does the grind.

## The Collaborator polling trap — mint the payload, and ALWAYS fire a control

**Proven the hard way, 2026-09-29.** `mcp__burp__get_collaborator_interactions` only returns
interactions for payloads minted by **this Burp instance's own Collaborator client**. A payload you
paste in by hand — from the Burp UI, a teammate, a previous session — polls as
`No interactions detected` **forever, no matter what actually happened.**

That is a silent false negative on the exact class of bug you use OOB testing to find. A blind SSRF
that fires perfectly looks identical to one that never fired.

### The rule

1. **Mint the payload from the MCP**, never paste one in:
   ```
   mcp__burp__generate_collaborator_payload  (customData: "<what you are testing>")
   ```
   `customData` comes back on every interaction — use it to label the campaign.
2. **Fire a control BEFORE trusting any negative.** One request you *know* must land:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" "http://control.<payload>.oastify.com/canary"
   ```
   Then poll. **If the control does not appear, your negative is worthless** — the detection chain is
   broken, not the target.
3. **Label each vector with its own subdomain** so a hit is attributable:
   `p1.<payload>`, `p2.<payload>` … for params; `h101.<payload>` … for headers. Otherwise a hit tells
   you something fetched, but not *what you sent*.

### Reading the interaction

Check `clientIp` before celebrating. Your **own** egress IP means it was your control or your own
resolver, not the target. A real server-side fetch shows the target's infrastructure — for an
AWS-hosted service, an AWS egress IP. Google (`172.253.x`) / Cloudflare (`172.68.x`, `172.69.x`)
client IPs on a DNS interaction are just recursive resolvers servicing *your* lookup.

`https://` to a Collaborator **subdomain** fails the cert check (`curl` exit 60) — the wildcard cert
does not cover it. Use `http://` for controls, or expect DNS-only.

### If you must use a payload you did not mint

You cannot verify it through the MCP. Say so explicitly rather than reporting a clean negative, and
have the operator read the Collaborator tab in the Burp UI directly. Leave a labelled canary
(`control-probe.<payload>`) so they can confirm they are looking at the right session.

---

## Driving Burp from a shell-only agent (pi/GLM, aider, codex)

Claude Code speaks MCP natively (`mcp__burp__*`). The delegated CLIs — pi/GLM, aider, codex, and
anything else the delegate skills drive — have **no MCP client at all, only a shell.** Without a
bridge, a hunt delegated to one of them loses Repeater, Collaborator and the authenticated proxy
history — which is most of the value of having Burp attached in the first place.

`scripts/burp_bridge.py` closes that gap: a one-file, **stdlib-only MCP client exposed as a CLI**.
It connects straight to the same HTTP+SSE endpoint the jar proxy uses (`127.0.0.1:9876`), so the
Burp-side setup is exactly the one at the top of this doc — no extra BApp config. `python3
scripts/burp_bridge.py` (or `-h`) prints the full usage.

### Pre-flight: `ping` FIRST — every session, before any other call

```bash
python3 scripts/burp_bridge.py ping
# OK — Burp MCP reachable, 27 tools, session <sid>
```

**Exit 3 means Burp is not running or the "MCP Server" BApp is not enabled. Stop and say so** —
do NOT run the hunt and report clean negatives from a dead tool. Everything the bridge would have
given you (history, Repeater, Collaborator) silently polls empty, and a negative produced with no
Burp attached is worthless, not clean.

Exit codes: `0` ok · `2` usage error (unknown subcommand / args not valid JSON) · `3` Burp
unreachable · `4` tool error returned by Burp (a timeout is surfaced as 4 with a
"narrow the regex" hint).

### The five subcommands

```bash
# 1. ping — is Burp reachable? Run this before anything else.
python3 scripts/burp_bridge.py ping

# 2. list — every tool the server exposes, one line each
python3 scripts/burp_bridge.py list

# 3. schema <tool> — the exact JSON args the tool accepts
python3 scripts/burp_bridge.py schema generate_collaborator_payload

# 4. call <tool> '<json>' — replay a request off the live authenticated session
python3 scripts/burp_bridge.py call send_http1_request '{
  "targetHostname":"example.acme.example","targetPort":443,"usesHttps":true,
  "content":"GET /api/v1/health HTTP/1.1\\r\\nHost: example.acme.example\\r\\n\\r\\n"}'

# 5. call <tool> @args.json — same, with args from a file (useful for long request bodies)
echo '{"customData":"ssrf-p1"}' > /tmp/args.json
python3 scripts/burp_bridge.py call generate_collaborator_payload @/tmp/args.json
```

### Collaborator discipline through the bridge — same trap, same rule

This is [[controls-and-oracles]] Case 4 applied to the bridge — the bridge does not remove the
trap, it is the same Collaborator client behind both:

1. **Mint the payload THROUGH the bridge**, never paste one in:
   ```bash
   python3 scripts/burp_bridge.py call generate_collaborator_payload '{"customData":"ssrf-p1"}'
   python3 scripts/burp_bridge.py call get_collaborator_interactions '{"payloadId":"<id>"}'
   ```
2. **Fire a control at the payload and confirm the control appears BEFORE trusting any negative.**
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" "http://control.<payload>.oastify.com/canary"
   ```
   `http://`, not `https://` (the wildcard cert does not cover Collaborator subdomains). If the
   control interaction does not appear, every negative you collected is worthless.
3. **Check `clientIp` is not your own egress IP** — your own IP means you saw your control or your
   resolver, not the target's fetch.

**`customData` is capped at 16 alphanumeric characters** — Burp rejects longer values with a tool
error (found by testing; recorded here so nobody re-discovers it). Keep labels short: `ssrf-p1`,
`hdr-h101`.

### The proxy-history trap

A broad `get_proxy_http_history_regex` times out **server-side at 30s** — the bridge surfaces it
as exit 4 with a hint. Narrow the regex to the exact host (or host + cookie name) and keep `count`
small (**≤5**); page forward with `offset`. Same pagination note as above: oldest-first from
offset 0, so don't page from the start hunting for the newest entry.

```bash
python3 scripts/burp_bridge.py call get_proxy_http_history_regex '{"regex":"example\\.ui\\.com","count":5,"offset":0}'
```

> Environment note: the bridge targets `127.0.0.1:9876`. If the agent runs in WSL2 against Burp on
> the Windows side without mirrored networking, loopback does not cross the VM boundary — run the
> bridge on the same side as Burp, or fix the networking mode. `ping` failing with connection
> refused is this, not a dead BApp — check which before blaming Burp.

---

### BLOCKER: the bridge does NOT work from inside WSL (loopback-only bind)

Found the hard way on 2026-10-01, and it matters because **WSL is exactly where a delegated
shell-only agent runs on this machine.**

```
# inside WSL
python3 scripts/burp_bridge.py ping
ERROR: Burp MCP not reachable at http://127.0.0.1:9876 — ... (Connection refused)   # exit 3
```

Burp was running the whole time. From **Windows**, the same port answers:

```
curl -o /dev/null -w "%{http_code}" http://127.0.0.1:9876/      # -> 200
```

**Cause.** The MCP BApp binds **loopback-only**. WSL2 is a separate network namespace, so its
`127.0.0.1` is its own loopback, not the Windows host's. Reaching the host by IP also fails,
because nothing is listening on an externally-bound interface:

```
# inside WSL
ip route | awk '/^default/{print $3}'    # -> 172.23.96.1  (the Windows host)
curl http://172.23.96.1:9876/            # -> refused
curl http://10.255.255.254:9876/          # -> refused  (the resolv.conf nameserver)
```

**This undercuts the delegation design in [[delegation-hunt-brief]].** The whole point of the
bridge is that pi/GLM has a shell but no MCP client — but if that agent runs in WSL while Burp
binds loopback on Windows, the shell does not help. Exit code 3 is doing its job here: it refuses
to let the agent mistake a dead tool for a clean negative. Respect it.

#### What to do about it

1. **Tell the delegated agent up front that Burp is unavailable**, rather than letting it discover
   exit 3 and improvise. Put `burp=UNAVAILABLE (WSL cannot reach a loopback-only bind)` on the
   SOURCES line, and mark any class that genuinely needs Burp (Collaborator OOB especially) as
   **BLOCKED**, never as clean. A negative that depended on a tool that never ran is worthless —
   this is [[controls-and-oracles]] Case 4 arriving by a different road.
2. **Run the bridge from Windows instead.** Windows python reaches the loopback fine; pass a
   Windows-style path. This is the zero-setup option when the orchestrator (not the delegate) needs
   Burp.
3. **Or stand up a userland forwarder on Windows** so WSL can reach it — a plain process, no system
   or firewall settings touched, and it dies with the shell:

   ```powershell
   # Windows, listens on all interfaces and forwards to Burp's loopback bind
   python -c "import socket,threading
   def pipe(a,b):
       try:
           while True:
               d=a.recv(65536)
               if not d: break
               b.sendall(d)
       except Exception: pass
       finally:
           for s in (a,b):
               try: s.close()
               except Exception: pass
   srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   srv.bind(('0.0.0.0',9877)); srv.listen(16)
   print('forwarding 0.0.0.0:9877 -> 127.0.0.1:9876')
   while True:
       c,_=srv.accept(); u=socket.create_connection(('127.0.0.1',9876))
       threading.Thread(target=pipe,args=(c,u),daemon=True).start()
       threading.Thread(target=pipe,args=(u,c),daemon=True).start()"
   ```

   Then from WSL point the bridge at the Windows host on that port:

   ```bash
   GW=$(ip route | awk '/^default/{print $3}')
   BURP_MCP_BASE="http://$GW:9877" python3 scripts/burp_bridge.py ping
   ```

   Note `burp_bridge.py` currently hardcodes `BASE = "http://127.0.0.1:9876"`, so either edit that
   constant or add the env-var override before this path works. **Verify with `ping` and only then
   trust a negative.**
4. Prefer a **Windows-side orchestrator + WSL-side curl** split: the orchestrator (Claude Code,
   which has `mcp__burp__*` natively) handles Repeater/Collaborator work, and the delegated agent
   does curl/httpx sweeps in WSL. That requires no forwarder and is what was actually done on the
   2026-10-01 billing-webhook pass.

#### The general lesson

`ping` returning exit 3 is not "the bridge is broken" — it is "this process cannot see Burp from
where it is standing." Before concluding Burp is down, check the port **from the OS that Burp runs
on**. A tool that is reachable for the operator and unreachable for the delegate is the kind of
asymmetry that silently manufactures false negatives in a delegated hunt.
