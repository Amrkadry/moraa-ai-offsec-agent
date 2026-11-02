#!/usr/bin/env python3
"""favicon_hash.py — Shodan/FOFA-format favicon mmh3 hashing, zero external deps.

Why this exists: `pip install mmh3` routinely fails in sandboxed engagement environments
(no sudo, PEP-668 "externally managed" Kali/Debian pythons, no ensurepip). This is a
pure-Python MurmurHash3-x86-32 implementation, verified byte-for-byte against the real
`mmh3` package (acme.example r23 pass, 2026-09-18):
    mmh3_hash32(b"")               == 0
    mmh3_hash32(b"test")           == -1167338989
    mmh3_hash32(b"Hello, world!")  == -1070186941

Usage:
    python3 favicon_hash.py <url> [<url> ...]
    python3 favicon_hash.py https://example.com/favicon.ico

Prints: <mmh3_hash>\t<size>B\t<final_url>\t<url>
And a ready-to-paste Shodan/FOFA query line for each successful hash.
"""
import sys, base64, urllib.request, ssl


def mmh3_hash32(key: bytes, seed: int = 0) -> int:
    length = len(key)
    nblocks = length // 4
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    def fmix(h):
        h &= 0xffffffff
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xffffffff
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xffffffff
        h ^= h >> 16
        return h

    for block_start in range(0, nblocks * 4, 4):
        k1 = int.from_bytes(key[block_start:block_start + 4], byteorder='little')
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    tail = key[nblocks * 4:]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 = fmix(h1)

    if h1 & 0x80000000:
        h1 = -((h1 ^ 0xffffffff) + 1)
    return h1


def favicon_shodan_hash(data: bytes) -> int:
    # Shodan's algorithm: base64-encode raw bytes with 76-char line wrapping
    # (Python's base64.encodebytes / the old Python2 base64.encodestring
    # behavior), then mmh3.hash() the base64 TEXT (not the raw bytes).
    b64 = base64.encodebytes(data)
    return mmh3_hash32(b64)


def fetch(url: str) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
        return r.read()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for url in sys.argv[1:]:
        try:
            data = fetch(url)
            h = favicon_shodan_hash(data)
            print(f"{h}\t{len(data)}B\t{url}")
            print(f"  shodan: http.favicon.hash:{h}")
            print(f"  fofa:   icon_hash=\"{h}\"")
        except Exception as e:
            print(f"ERROR\t{e}\t{url}")
