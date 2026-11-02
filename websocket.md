# Moraa — WebSocket testing methodology (bug hunting)

> Load when a target uses WebSockets (chat, live dashboards, notifications, collaborative editing,
> LLM/agent streaming, trading, GraphQL subscriptions). WS surfaces are **under-tested** — auth is
> often only at the handshake, and per-message authz is frequently missing. Commands first.

---

## 0. Discover the WS endpoint

```bash
# from the page/app
curl -sk https://T/ -D- | grep -i 'content-security-policy'      # connect-src wss://host = the WS host
cat *.js | grep -oiE 'new WebSocket\([^)]{0,80}|wss?://[a-z0-9./{}$_-]{0,60}|io\(|socket\.io|graphql-(transport-)?ws|/ws\b|/socket|/cable|/subscriptions|/live|/hub' | sort -u
# probe common paths — a real WS replies 101 Switching Protocols (or 426 Upgrade Required over plain GET)
for p in / /ws /socket.io/?EIO=4&transport=websocket /graphql /subscriptions /cable /live /api/ws /chat; do
  curl -sk -m6 "https://T$p" -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZQ==' -o /dev/null -w "%{http_code} $p\n"; done
```
> **101** = real WS. **426 Upgrade Required** = WS service, wrong path/headers. **200** to an upgrade
> attempt = the path is an HTTP/SPA catch-all, NOT the WS (acme.example agents lesson — "Handshake status
> 200" meant the SPA answered, not the socket). Keep hunting the exact path from the JS.

Tools: `wscat -c wss://host/path`, `websocat wss://host/path`, Burp (WebSockets history + repeater),
python `websocket-client`. Send Origin/cookies explicitly to control the test.

## 1. Handshake auth model — the first question

How is the socket authenticated? Determines the top bug:
```bash
# A) cookie-authenticated handshake  → test CSWSH (§2)
wscat -c wss://T/ws -H "Cookie: $SESSION"
# B) token in URL  ?token=…  → leaks in logs/referrer/history (report if sensitive); also try expired/none
# C) token in subprotocol   Sec-WebSocket-Protocol: bearer,<jwt>   (common for browsers that can't set headers)
websocat -H='Origin: https://T' --protocol 'graphql-transport-ws' wss://T/graphql
# D) first-message auth   {"type":"connection_init","payload":{"authToken":"…"}}  (graphql-ws / custom)
# E) NONE → unauth access to the stream (test what data/actions it exposes)
```
Test the negatives: **no auth**, **expired token**, **another user's token** — does the socket still open?

## 2. CSWSH — Cross-Site WebSocket Hijacking (the #1 WS bug)

If the handshake authenticates by **cookie** and does **not validate `Origin`**, any attacker page can
open the socket in the victim's browser with the victim's cookies → full read/write of the WS API.

```bash
# does the server accept a foreign / missing Origin while still authenticating the cookie?
wscat -c wss://T/ws -H "Cookie: $SESSION" -H "Origin: https://evil.com"    # opens + works? → CSWSH
wscat -c wss://T/ws -H "Cookie: $SESSION" -H "Origin: null"
wscat -c wss://T/ws -H "Cookie: $SESSION"     # no Origin
```
- Accepts foreign/absent Origin **and** the session cookie rides along → **CSWSH confirmed**.
- PoC: a page that `new WebSocket('wss://T/ws')`, then on `onmessage` exfil to attacker (browser sends
  cookies automatically for same-site; `SameSite=None`/no-SameSite cookies make it work cross-site).
- Impact = whatever the socket does: read chat/PII, send messages as victim, trigger actions → ATO-ish.
- Rate it honestly with the cookie's `SameSite` (Lax/Strict shrinks cross-site reach — note the precondition).

## 3. Per-message authorization (IDOR over WS)

Handshake auth ≠ message auth. After connecting as user A, try to act on B's objects:
```json
{"type":"subscribe","channel":"user:<OTHER_ID>"}          // subscribe to another user's stream
{"action":"join","room":"<OTHER_ROOM>"}                    // join a room you don't own
{"type":"message","chatId":"<OTHER_CHAT>","text":"x"}      // post into another chat
{"op":"get","resource":"order","id":"<OTHER_ORDER>"}       // fetch another's object
```
> Servers often check ownership on the REST side but forget it on the socket. Enumerate topic/channel/
> room/id formats from legit traffic, then swap IDs — same discipline as HTTP IDOR (two accounts).

## 4. Message-content injection (often less-filtered than HTTP)

Fuzz each field of the message schema — WS inputs frequently skip the HTTP WAF/validation:
```
SQLi:  {"search":"' OR 1=1-- -"}          NoSQLi: {"q":{"$ne":null}}
XSS (stored → rendered in another user's live view): {"msg":"<img src=x onerror=alert(1)>"}
SSTI:  {"name":"{{7*7}}"}     cmd inj: {"host":"127.0.0.1;id"}     path trav: {"file":"../../etc/passwd"}
type confusion: send number where string expected, arrays/objects, null, huge ints
oversized frame / deep JSON → DoS ; missing required field → verbose error / stack leak
```
Blind variants → collaborator/interactsh callback in a field (SSRF/XXE over WS).

## 5. GraphQL over WebSocket (subscriptions)

Subprotocols: `graphql-transport-ws` (new) / `graphql-ws` (legacy). Auth is usually in `connection_init`.
```json
→ {"type":"connection_init","payload":{"Authorization":"Bearer …"}}
← {"type":"connection_ack"}
→ {"id":"1","type":"subscribe","payload":{"query":"subscription{__typename}"}}
```
- **Introspection over WS** may be open even when the HTTP endpoint blocks it → map the schema, then hunt
  subscription/mutation authz + field-level IDOR (`node(id:)`), batching abuse.
- Apollo CSRF-prevention & the precompiled-AST-in-bundle notes apply (acme.example RMA lesson) — pull the AST
  from the JS to learn real ops. Missing auth on `connection_init` → unauth subscription to live data.

## 6. Framework specifics

```
Socket.IO:  handshake GET /socket.io/?EIO=4&transport=polling  → sid → upgrade to websocket.
            Test namespaces ("40/admin,"), unauth namespace access, ack-callback injection.
Rails ActionCable /cable:  {"command":"subscribe","identifier":"{\"channel\":\"XChannel\",\"id\":<other>}"}
STOMP/MQTT-over-WS:  SUBSCRIBE to topics you shouldn't (topic-level authz bypass); wildcard topics (#, +).
SignalR (/hub):  negotiate → connectionToken; test hub method authz.
```

## 7. Other checks

- **No message rate limit / unbounded subscriptions** → resource-exhaustion DoS (note, don't weaponize on prod).
- **Token/secret in the WS URL** → logged by proxies/CDN → disclosure.
- **wss not enforced** (plain `ws://`) → MITM of a "signed"/authed stream; client-forgeable signatures
  (secret in browser bundle) → telemetry/log injection (OTLP-collector class).
- **Session not re-validated** after login/logout on a long-lived socket → stale-auth actions.

## Methodology recap
1. Find the exact WS path (JS/CSP; 101 not 200). 2. Determine handshake auth (cookie→CSWSH; token→leak/none).
3. Test CSWSH (foreign Origin + cookie). 4. Test per-message IDOR (two accounts). 5. Inject in message fields.
6. For GraphQL-WS, retry introspection + subscription authz. → `validate.md` → `findings/` with a real frame log.

---

## socket.io on a REST host: the namespace-accept probe, and the "id-keyed event with no room join" tell

An SPA backend that also mounts socket.io is a surface nobody maps, because route-census tooling only
reads `http.*` call sites. Grep the bundle (or better, the source map) for `socket.io-client`,
`io(`, `.emit(`, `.on(` and any `SOCKET_EVENTS`-style constants table. Found on acme.example `console.svc`
2026-10-15 with zero prior coverage after ~150 REST routes had been mapped twice.

### Step 1 — is the transport mounted, and is the handshake open?

```bash
curl -s "https://host/socket.io/?EIO=4&transport=polling"
# 0{"sid":"...","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}
```

**Control, do not skip it** — prove it is a real mount and not a catch-all that echoes
`SUCCESS`-shaped bodies for invented paths:

```bash
curl -s -o /dev/null -w '%{http_code}\n' "https://host/engine.io/?EIO=4&transport=polling"   # 404 => real mount
```

### Step 2 — is the *namespace* connect authorised? (the handshake is not the auth boundary)

The engine.io handshake almost always answers; the security question is the socket.io CONNECT. Over
the WS transport (`wss://host/socket.io/?EIO=4&transport=websocket`), send `40` with **no cookie**:

- `44{"message":...}` = CONNECT_ERROR -> an `io.use()` middleware rejected you. Secure, move on.
- `40{"sid":"..."}`   = **ACCEPTED**. No auth middleware. Keep going.

Minimal client, no npm needed (python3 + `websockets`): connect, `send("40")`, log every frame,
reply `3` to every `2` ping. Reference implementation kept at
`engagements/acme.example` lane L1 (`ws_sio.py`).

### Step 3 — the tell that makes it worth chasing: id-keyed event names with no room join

```ts
export const SOCKET_EVENTS = {
  order:   { create: (quoteId: string) => `order_create:${quoteId}` },
  payment: { update: (quoteId: string) => `payment_update:${quoteId}` },
}
socket.subscribe(SOCKET_EVENTS.order.create(quoteId), handler)   // and NO 'join room' anywhere
```

A client that does `socket.on('order_create:<uuid>')` **without first joining a room** can only ever
receive that event if the server broadcasts namespace-wide (`io.emit`) instead of
`io.to(room).emit`. If so, every connected socket — including an unauthenticated one — receives every
tenant's order/payment/payout events. That is cross-tenant real-time data leakage, and it is invisible
to every REST-only authz test.

Compare the two clients in a fleet: acme.example's **pro** bundle defines `JOIN_ROOM`/`LEAVE_ROOM` while
the **customer** bundle subscribes to id-keyed names and never joins. That asymmetry is the signal.

### Step 4 — accept-then-drop is AMBIGUOUS. Say so; do not pick the flattering reading

Common outcome: the namespace ACKs, then the socket dies 1-2 s later with **no close frame and no
`44`**. Two readings, and the frames do not discriminate:

1. the server accepted then called `socket.disconnect()` because there is no session — **secure**;
2. the ALB/target group cut the upgraded connection — **says nothing about authz**.

(Reading 2 gains weight if the *polling* transport also 502s on the first poll — that is multiple
socket.io instances without sticky routing for the transport.)

**The discriminating control is one authenticated socket.** Connect authed and anonymous side by
side: only the anonymous one dropped => reading 1, kill the lead. Anonymous survives => attach an
`onAny` logger and wait for a frame carrying an id you do not own. Without that control, write it up
as an explicit LEAD with the missing primitive named — not as a finding, and not as a clean negative.

### Rate warning

Un-upgraded sids and repeated connects are disproportionately expensive for these servers. Two
separate bursts of a handful of connects each preceded two multi-minute estate-wide 503 windows on
the same host (`controls-and-oracles.md` Case 20). Probe once, log, stop.

---

## MANDATORY ORACLE — your WS client probably forges the header you are testing

Before reading a single Origin result, prove the **known-good** Origin returns `101` with frames
flowing. If it does not, every row in your matrix is a client artifact and the table is worthless.

The specific trap, which cost a whole discarded matrix: Python's **`websocket-client` emits its own
`Origin` header**. Pass one via `header=[...]` and the request carries **two** `Origin` headers, and
a strict server 403s **everything — including the origin that actually works**. Written up
uncritically that reads as "CSWSH fully blocked"; cherry-picked the other way it manufactures a
finding. Either way it is not a measurement of server policy.

**Fix: hand-build the handshake on a raw TLS socket** for any Origin-sensitive work, so exactly the
bytes you intend go on the wire. Reusable raw handshake + frame parser from this engagement:
scratchpad `g2_raw.py`, `g2_idor.py`. Same caution applies to any library that injects
`Sec-WebSocket-Protocol`, `User-Agent` or cookies on your behalf.

Distinguish the bad states too, so a silent socket is never ambiguous. A well-built server gives
you three different closes:

```
garbage cookie   -> CLOSE 1008 "invalid auth: unauthorized"
no auth at all   -> CLOSE 1008 "invalid uri"
garbage ticket   -> CLOSE 1008 "invalid auth: websocket ticket not found or expired"
bad Origin       -> HTTP 403 BEFORE the upgrade (never reaches a close frame)
```

## No subscribe frame? Then you need an event generator, or your clean is false

Many modern buses have **no client-side subscribe at all**: the server fans out by authenticated
principal and the client merely filters locally (`messageFilter: e => e.app === appId`). Signs you
are looking at one: the only frame the real client ever sends is a heartbeat; topics arrive
unsolicited; there is no `{"action":"subscribe"}` anywhere in the bundle.

Two consequences that decide whether your per-message authz test means anything:

1. **No backlog replay.** A socket that connects *after* an event never sees it. So "I connected as
   B and saw nothing" proves nothing — you must hold sockets open and **generate a live event on the
   other principal** while they are connected. Without a generator, every WS authz test on such a
   bus reads as a false clean.
2. **Nothing client-side to tamper with.** The IDOR surface moves off the socket and onto the
   **ticket mint** (`POST /ws-tickets`) and the handshake: try mass-assigning `user_id` into the
   ticket body, spoofing identity headers on the mint, and query-string params on `/ws`. In this
   engagement all were inert — the body was never read — but that is where the bug would be.

A good event generator is a reversible own-account write whose notification you can predict
(e.g. `POST /roles` on your own workspace, deleted afterwards). Hold five sockets at once — plain A,
plain B, a tampered-ticket A, cookie-only, and a bogus-id variant — fire one event per principal,
and tabulate which socket saw which frame. Zero crossings with **both** plain sockets receiving
their own event is a real negative; anything less is an untested lane.

## Ticket auth that adds no defence in depth

A 30-second single-use ticket in `Sec-WebSocket-Protocol` is the standard anti-CSWSH pattern, and it
works *only if the cookie path is closed*. Check explicitly whether the socket **still accepts the
session cookie alone with no ticket**. Where it does (observed on a real estate), the ticket is
cosmetic: cookies ride a cross-site WebSocket handshake, so **`CheckOrigin` becomes the single
control** between an attacker page and the victim's live event stream.

That is Informational on its own — an attacker page cannot read a ticket if the mint is CORS-locked,
and cannot forge an allowlisted Origin. But record it, because it is a **one-change-from-critical**
condition: the moment that allowlist is widened to a suffix or wildcard match, it is direct CSWSH
with no second gate. On an estate that already has confirmed wildcard `*.acme.example` credentialed CORS
elsewhere, that is a realistic regression, not a hypothetical. Keep the Origin matrix scripted and
re-run it after any edge change.
