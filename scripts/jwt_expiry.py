#!/usr/bin/env python3
"""
jwt_expiry.py -- scan an auth.json for every JWT-shaped string (recursively, any nesting)
and report its exp/iat vs now, sorted soonest-to-expire first.

WHY: "is this stored token still fresh?" currently gets answered by re-deriving it from
context/memory or re-pulling Burp history speculatively. This makes it a 2-second, zero-
ambiguity check before trusting (or replacing) anything in auth.json.

Usage:
    python3 jwt_expiry.py <path-to-auth.json>

Non-JWT tokens (opaque session cookies, API keys) can't be decoded this way -- they're
listed separately as "opaque, can't check expiry: try it or check Burp history."
"""
import sys
import json
import base64
import time
import re
from datetime import datetime, timezone

JWT_RE = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$')


def b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def try_decode_jwt(tok: str):
    parts = tok.split('.')
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(b64url_decode(parts[1]))
        return payload
    except Exception:
        return None


def walk(obj, path=""):
    """yield (path, string_value) for every string leaf in a nested dict/list"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def human_delta(seconds: float) -> str:
    sign = "in " if seconds >= 0 else ""
    suffix = "" if seconds >= 0 else " ago"
    seconds = abs(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{int(days)}d")
    if hours:
        parts.append(f"{int(hours)}h")
    if not days and minutes:
        parts.append(f"{int(minutes)}m")
    return f"{sign}{' '.join(parts) or '0m'}{suffix}"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    with open(sys.argv[1], encoding='utf-8') as f:
        data = json.load(f)

    now = time.time()
    jwt_rows = []
    opaque_rows = []
    seen = set()

    for path, val in walk(data):
        if len(val) < 20 or val in seen:
            continue
        seen.add(val)
        if JWT_RE.match(val):
            payload = try_decode_jwt(val)
            if payload and ('exp' in payload or 'iat' in payload):
                exp = payload.get('exp')
                iat = payload.get('iat')
                jwt_rows.append((path, exp, iat, payload))
            else:
                opaque_rows.append((path, val[:24] + "..."))
        elif re.match(r'^[A-Za-z0-9_.=%\-+/]{25,}$', val) and any(
            key in path.lower() for key in ('token', 'auth', 'cookie', 'sid', 'session', 'bearer')
        ):
            opaque_rows.append((path, val[:24] + "..."))

    jwt_rows.sort(key=lambda r: (r[1] is None, r[1] or 0))

    print(f"=== JWT-decodable tokens in {sys.argv[1]} ({len(jwt_rows)} found) ===\n")
    for path, exp, iat, payload in jwt_rows:
        status = ""
        if exp is not None:
            delta = exp - now
            status = "EXPIRED " + human_delta(delta) if delta < 0 else "expires " + human_delta(delta)
        else:
            status = "no exp claim"
        iat_str = datetime.fromtimestamp(iat, tz=timezone.utc).isoformat() if iat else "?"
        flag = " <-- STALE, re-mint from Burp history" if (exp is not None and exp - now < 0) else ""
        flag = flag or (" <-- expiring soon" if exp is not None and 0 <= exp - now < 3600 else "")
        print(f"  {path}\n      issued: {iat_str}   status: {status}{flag}")

    print(f"\n=== Opaque tokens/cookies (can't decode expiry -- {len(opaque_rows)} found) ===")
    for path, preview in opaque_rows:
        print(f"  {path}: {preview}  (verify liveness directly, or check Burp proxy history for a fresher capture)")


if __name__ == "__main__":
    main()
