#!/usr/bin/env python3
"""
burp_bridge.py — use the Burp Suite MCP server from any CLI agent that has only a shell.

WHY THIS EXISTS
    The PortSwigger "MCP Server" BApp speaks MCP over HTTP+SSE on 127.0.0.1:9876.
    Claude Code talks to it natively as mcp__burp__*. Other coding CLIs (pi/GLM,
    aider, codex, …) have no MCP client at all — they only have a shell. Without a
    bridge, delegating a hunt to one of those means losing Repeater, Collaborator
    and the authenticated proxy history, which is most of the value of having Burp
    connected in the first place.

    This is a one-file, stdlib-only MCP client exposed as a CLI. Any agent that can
    run a command can now drive Burp.

USAGE
    python3 burp_bridge.py list
    python3 burp_bridge.py schema <tool>
    python3 burp_bridge.py call <tool> '<json-args>'
    python3 burp_bridge.py call <tool> @args.json      # args from a file
    python3 burp_bridge.py ping                        # is Burp reachable?

EXAMPLES
    # Replay a request off the live authenticated session
    python3 burp_bridge.py call send_http1_request '{
      "targetHostname":"example.acme.example","targetPort":443,"usesHttps":true,
      "content":"GET /api/v1/health HTTP/1.1\\r\\nHost: example.acme.example\\r\\n\\r\\n"}'

    # Mint an OOB payload, then poll it (ALWAYS fire a control first — see
    # controls-and-oracles.md Case 4: a payload you did not mint polls empty forever)
    python3 burp_bridge.py call generate_collaborator_payload '{"customData":"ssrf-test"}'
    python3 burp_bridge.py call get_collaborator_interactions '{"payloadId":"<id>"}'

    # Mine the authenticated proxy history — NARROW regex, small count; a broad
    # query times out server-side at 30s
    python3 burp_bridge.py call get_proxy_http_history_regex '{"regex":"example\\\\.ui\\\\.com","count":5,"offset":0}'

EXIT CODES
    0 ok · 2 usage error · 3 Burp unreachable · 4 tool error returned by Burp
"""
import json
import queue
import sys
import threading
import time
import urllib.error
import urllib.request

import os

BASE = os.environ.get("BURP_MCP_BASE", "http://127.0.0.1:9876")
TIMEOUT = 60


class Bridge:
    def __init__(self, base=BASE):
        self.base = base
        self.sid = None
        self.q = queue.Queue()
        self._err = None
        self._next_id = 0

    # --- transport ----------------------------------------------------------
    def _reader(self):
        """Hold the SSE stream open. The session id arrives first, then every
        JSON-RPC response — responses do NOT come back on the POST."""
        try:
            r = urllib.request.urlopen(self.base + "/", timeout=TIMEOUT)
        except Exception as e:                      # Burp closed, BApp not loaded
            self._err = e
            return
        for raw in r:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload.startswith("?sessionId="):
                self.sid = payload.split("=", 1)[1]
            else:
                try:
                    self.q.put(json.loads(payload))
                except ValueError:
                    pass

    def connect(self):
        threading.Thread(target=self._reader, daemon=True).start()
        for _ in range(200):                        # ~10s for the handshake
            if self.sid or self._err:
                break
            time.sleep(0.05)
        if self._err or not self.sid:
            raise ConnectionError(
                "Burp MCP not reachable at %s — is Burp running with the "
                "PortSwigger 'MCP Server' BApp enabled? (%s)"
                % (self.base, self._err or "no sessionId in the SSE handshake")
            )
        self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "moraa-burp-bridge", "version": "1"},
        })
        self._notify("notifications/initialized")
        return self

    def _post(self, obj):
        req = urllib.request.Request(
            "%s/?sessionId=%s" % (self.base, self.sid),
            data=json.dumps(obj).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=TIMEOUT).read()

    def _notify(self, method, params=None):
        self._post({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _rpc(self, method, params=None):
        self._next_id += 1
        mid = self._next_id
        self._post({"jsonrpc": "2.0", "id": mid, "method": method,
                    "params": params or {}})
        deadline = time.time() + TIMEOUT
        while time.time() < deadline:
            try:
                msg = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(json.dumps(msg["error"]))
                return msg.get("result", {})
        raise TimeoutError("no response to %s within %ss" % (method, TIMEOUT))

    # --- api ----------------------------------------------------------------
    def tools(self):
        return self._rpc("tools/list").get("tools", [])

    def call(self, name, args):
        return self._rpc("tools/call", {"name": name, "arguments": args})


def _flatten(result):
    """Burp returns MCP content blocks; print the text rather than the envelope."""
    parts = []
    for block in result.get("content", []) or []:
        if block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(parts) if parts else json.dumps(result, indent=2)


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2

    cmd = argv[0]
    try:
        b = Bridge().connect()
    except ConnectionError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 3

    if cmd == "ping":
        print("OK — Burp MCP reachable, %d tools, session %s"
              % (len(b.tools()), b.sid))
        return 0

    if cmd == "list":
        for t in b.tools():
            desc = (t.get("description") or "").split("\n")[0][:88]
            print("%-38s %s" % (t["name"], desc))
        return 0

    if cmd == "schema":
        if len(argv) < 2:
            print("usage: burp_bridge.py schema <tool>", file=sys.stderr)
            return 2
        for t in b.tools():
            if t["name"] == argv[1]:
                print(json.dumps(t.get("inputSchema", {}), indent=2))
                return 0
        print("no such tool: %s" % argv[1], file=sys.stderr)
        return 2

    if cmd == "call":
        if len(argv) < 2:
            print("usage: burp_bridge.py call <tool> '<json>'", file=sys.stderr)
            return 2
        name = argv[1]
        raw = argv[2] if len(argv) > 2 else "{}"
        if raw.startswith("@"):                     # args from a file
            with open(raw[1:], encoding="utf-8") as fh:
                raw = fh.read()
        try:
            args = json.loads(raw) if raw.strip() else {}
        except ValueError as e:
            print("ERROR: arguments are not valid JSON: %s" % e, file=sys.stderr)
            return 2
        try:
            print(_flatten(b.call(name, args)))
        except RuntimeError as e:
            print("TOOL ERROR: %s" % e, file=sys.stderr)
            return 4
        except TimeoutError as e:
            # The usual cause is a too-broad proxy-history regex.
            print("TIMEOUT: %s\nHint: narrow the regex and lower `count`."
                  % e, file=sys.stderr)
            return 4
        return 0

    print("unknown command: %s (try list | schema | call | ping)" % cmd,
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
