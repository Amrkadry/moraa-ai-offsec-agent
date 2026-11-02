#!/usr/bin/env python3
"""Offline tests for scripts/cache_probe.sh.

stdlib unittest only, zero third-party deps. cache_probe.sh is shell, so per AGENTS.md it
is driven as a SUBPROCESS against a throwaway http.server on 127.0.0.1 started/stopped by
each test — never a real host. The fixture server is an in-memory cache: a request path
never seen before is served as a MISS (X-Cache: Miss, Age: 0), the same path again as a
HIT (X-Cache: Hit, Age: 500) — which is exactly the observable the script's logic keys on.

The tests centre on the safety pre-flight, because that is the property whose failure
caused a live incident (see the script header): if the query string is NOT part of the
cache key, the cache-buster is inert and every probe would land on the cache entry real
users are served. A host like that must be SKIPPED — and the assertions here check the
REQUESTS THE SERVER ACTUALLY RECEIVED (probe count == 0), not just the text the script
printed, because a stdout-only grep would pass even if the script probed anyway.

SAFETY REGRESSION (found while writing these tests, FIXED in the script on review):
cache_hit()'s Age arm was case-sensitive (`grep -qE '^age:...'`) while the X-Cache /
CF-Cache-Status arms used -qi, so a canonical-case `Age: 500` — how CloudFront/Fastly/
Varnish/Cloudflare put it on the wire over HTTP/1.1 — was NOT recognised as a hit and the
pre-flight did NOT refuse such a host, landing every probe on the live cache key. Now
`grep -qiE`. The tests below exercise the Age signal in BOTH lowercase (h2 wire form) and
canonical (h1.1) case; both must stay detected or the safety hole reopens.

Run:  python3 -m unittest discover -s tests -p "test_cache_probe.py" -v
"""

import http.server
import subprocess
import threading
import unittest
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "cache_probe.sh"

# headers whose presence marks a request as one of the script's injected-header probes
PROBE_HEADERS = {"x-forwarded-host", "x-forwarded-scheme", "x-original-url",
                 "x-rewrite-url", "x-host"}


class _FixtureCacheHandler(http.server.BaseHTTPRequestHandler):
    """Behavior is driven by the .fixture object on the server; see _FixtureCache."""

    protocol_version = "HTTP/1.1"
    server_version = "FixtureCache/1.0"

    def log_message(self, fmt, *args):  # keep test output clean
        pass

    def do_GET(self):
        cfg = self.server.fixture.cfg
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)  # drain the fat-GET body
        lower = {k.lower(): v for k, v in self.headers.items()}
        cfg["requests"].append({"path": self.path, "headers": lower,
                                "had_body": length > 0})

        if cfg["always_hit"]:
            # unkeyed-cache stand-in: even a never-before-seen random query is a HIT
            status, extra, body = 200, dict(cfg["hit_headers"]), "fixture cached body"
        elif cfg["fatget_403"] and length > 0:
            # CDN-style rejection of a GET that carries a body
            status, extra, body = 403, dict(cfg["miss_headers"]), "fixture forbidden"
        elif self.path in cfg["seen"]:
            status, extra = 200, dict(cfg["hit_headers"])
            body = cfg["hit_body"] if cfg["hit_body"] is not None else self._reflected(lower)
        else:
            cfg["seen"][self.path] = True
            status, extra = 200, dict(cfg["miss_headers"])
            body = self._reflected(lower)

        payload = body.encode("utf-8")
        self.send_response(status)
        for k, v in extra.items():
            self.send_header(k, v)
        if cfg["vary"]:
            self.send_header("Vary", cfg["vary"])
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _reflected(self, lower):
        cfg = self.server.fixture.cfg
        if not cfg["reflect_hdr"]:
            return "fixture plain body"
        return "fixture body [" + lower.get(cfg["reflect_hdr"], "") + "]"


class _FixtureCache:
    """Throwaway in-memory cache on 127.0.0.1.

    Default behavior: first request for a path+query is a MISS (X-Cache: Miss, Age: 0),
    the same path again is a HIT (X-Cache: Hit, Age: 500) — a keyed cache. Overrides:
      always_hit     every request is a HIT (the unkeyed-cache danger case)
      hit_headers    the exact hit markers sent (for testing cache_hit()'s inputs)
      miss_headers   the exact miss markers sent
      reflect_hdr    header whose value is echoed into the response body (reflection)
      hit_body       fixed body for HITs (simulates a clean pre-existing entry overwriting
                     the poisoned variant — the warm-leg-only reflection case)
      vary           value of a Vary response header (cache keyed on the injected input)
      fatget_403     answer any request carrying a body with 403
      requests       list every received request: {"path", "headers" (lowercased),
                     "had_body"} — the ground truth the assertions count
    """

    def __init__(self, **overrides):
        self.cfg = {
            "always_hit": False,
            "hit_headers": {"X-Cache": "Hit", "Age": "500"},
            "miss_headers": {"X-Cache": "Miss", "Age": "0"},
            "reflect_hdr": None,
            "hit_body": None,
            "vary": None,
            "fatget_403": False,
            "requests": [],
            "seen": {},
        }
        self.cfg.update(overrides)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                                     _FixtureCacheHandler)
        self.httpd.fixture = self
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def url(self):
        return "http://127.0.0.1:%d/" % self.port


def run_probe(urls):
    """Run cache_probe.sh as a subprocess against the fixture; return the CompletedProcess."""
    return subprocess.run(
        ["bash", "scripts/cache_probe.sh", *urls],
        cwd=str(REPO_ROOT), capture_output=True, timeout=180,
        encoding="utf-8", errors="replace",  # script emits UTF-8; never trust the locale
    )


def probe_requests(fx):
    """Requests the script sent as part of a probe: an injected-header probe, or a
    fat-GET (which carries a body instead of a header). Excludes the 2 pre-flight GETs."""
    return [r for r in fx.cfg["requests"]
            if (PROBE_HEADERS & set(r["headers"])) or r["had_body"]]


def cb_values(fx):
    """Cache-buster values carried by probe requests, in arrival order."""
    out = []
    for r in fx.cfg["requests"]:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(r["path"]).query)
        if "cb" in q:
            out.append(q["cb"][0])
    return out


# --------------------------------------------------------------------------
# (1) THE safety pre-flight — an unkeyed query string must mean ZERO probes
# --------------------------------------------------------------------------

class TestSafetyPreflight(unittest.TestCase):

    def test_unkeyed_query_host_is_skipped_and_probed_zero_times(self):
        # every response is a HIT even for a never-before-seen random query string:
        # the query is not in the cache key, the buster is inert -> the host is unsafe
        with _FixtureCache(always_hit=True) as fx:
            proc = run_probe([fx.url()])
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr)

        # the safety property, asserted on TRAFFIC not stdout: the only requests that
        # arrived are the two pre-flight ones — zero probes were ever sent
        reqs = fx.cfg["requests"]
        self.assertEqual(len(reqs), 2)
        self.assertEqual(probe_requests(fx), [])
        for r in reqs:
            self.assertNotIn("cb=", r["path"])          # no cache-bustered probe URL
        # the two pre-flight requests carried two DIFFERENT random query strings
        self.assertNotEqual(reqs[0]["path"], reqs[1]["path"])

        # ...and the human-visible warnings are there too
        self.assertIn("[!] SKIP", out)
        self.assertIn("query string is NOT in the cache key", out)
        self.assertIn("SKIPPED 1 host(s) as unsafe to probe", out)
        self.assertIn(fx.url(), out.split("SKIPPED 1 host(s)")[-1])  # listed in the summary
        self.assertIn("across 0 probes", out)           # TOTAL never advanced

    def test_keyed_query_host_proceeds_through_all_probes(self):
        # fresh query => MISS: the buster works, so the full sweep is allowed
        with _FixtureCache() as fx:
            proc = run_probe([fx.url()])
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("[!] SKIP", out)
        self.assertNotIn("SKIPPED", out)
        # 2 pre-flight + 6 probes x warm+verify = 14 requests, and all 6 probes ran
        self.assertEqual(len(fx.cfg["requests"]), 14)
        self.assertEqual(len(probe_requests(fx)), 12)
        for probe in ("xfh", "xfs", "xou", "xru", "xhost", "fatget"):
            self.assertIn(f"[{probe}]", out)
        self.assertIn("no cached reflection across 6 probes", out)


# --------------------------------------------------------------------------
# (2) cache-hit detection: what cache_hit() accepts / rejects
# --------------------------------------------------------------------------

class TestCacheHitSignals(unittest.TestCase):
    """Each single marker must alone convince the pre-flight the host is unkeyed.

    The Age arm is exercised in BOTH cases on purpose. Lowercase `age:` is what an
    HTTP/2 CDN puts on the wire; canonical `Age:` is what an HTTP/1.1 CDN sends. The
    script's Age grep used to be case-sensitive and missed the canonical form on exactly
    the h1.1 hosts the pre-flight most needs to refuse — a real safety hole (now fixed
    with `grep -qiE`). This test is the regression guard: if either case stops being
    detected, a probe run could land on a live cache key.
    """

    def test_each_hit_marker_triggers_the_preflight_refusal(self):
        for marker in ({"X-Cache": "Hit"},
                       {"CF-Cache-Status": "HIT"},
                       {"age": "500"},      # h2 wire form (lowercase header name)
                       {"Age": "500"}):     # h1.1 canonical form — the arm that was buggy
            with self.subTest(marker=marker), _FixtureCache(always_hit=True,
                                                            hit_headers=marker) as fx:
                proc = run_probe([fx.url()])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(fx.cfg["requests"]), 2)     # refused after pre-flight only
            self.assertEqual(probe_requests(fx), [])
            self.assertIn("[!] SKIP", proc.stdout)

    def test_age_zero_with_x_cache_miss_is_not_a_hit(self):
        # the default keyed fixture answers fresh queries with X-Cache: Miss + Age: 0 —
        # neither marker may count as a hit, or every keyed host would be refused
        with _FixtureCache() as fx:
            proc = run_probe([fx.url()])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("[!] SKIP", proc.stdout)
        self.assertEqual(len(probe_requests(fx)), 12)        # the sweep went ahead


# --------------------------------------------------------------------------
# (3) findings: cached reflection, Vary suppression, warm-leg reflection
# --------------------------------------------------------------------------

class TestFindings(unittest.TestCase):

    def test_cached_canary_reflection_is_reported_with_exact_canary_and_buster(self):
        with _FixtureCache(reflect_hdr="x-forwarded-host") as fx:
            proc = run_probe([fx.url()])
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # exactly one finding: the xfh probe (nothing else is reflected by the fixture)
        self.assertIn("=== FINDINGS: canary reflected AND served from cache (1)", out)
        self.assertEqual(out.count("injected: X-Forwarded-Host: "), 1)
        self.assertEqual(out.count("reflected=yes"), 1)
        self.assertEqual(out.count("reflected=no"), 5)

        # the printed reproduce line must carry the EXACT canary and cache-buster that
        # went over the wire — pull both off the recorded probe request and require them
        xfh = [r for r in probe_requests(fx) if "x-forwarded-host" in r["headers"]]
        self.assertEqual(len(xfh), 2)                        # warm + verify, same canary
        canary = xfh[0]["headers"]["x-forwarded-host"]
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(xfh[0]["path"]).query)
        cb = q["cb"][0]                                      # THIS probe's buster
        base = fx.url() + "?cb=" + cb
        self.assertIn(f"injected: X-Forwarded-Host: {canary}", out)
        self.assertIn(f"reproduce: curl -sk -D- -H 'X-Forwarded-Host: {canary}' "
                      f"'{base}'   # while TTL lives", out)

    def test_vary_on_the_injected_header_is_not_a_finding(self):
        # cache HIT + canary reflected, but Vary: X-Forwarded-Host means the cache is
        # correctly KEYED on the injected input — reporting it would be a false positive
        with _FixtureCache(reflect_hdr="x-forwarded-host",
                           vary="X-Forwarded-Host") as fx:
            proc = run_probe([fx.url()])
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("=== FINDINGS", out)
        self.assertIn("Vary: x-forwarded-host present", out)
        self.assertIn("not poisonable", out)
        self.assertIn("no cached reflection across 6 probes", out)
        self.assertEqual(out.count("reflected=yes"), 1)      # reflection seen, then suppressed

    def test_reflection_on_the_warm_leg_only_is_still_detected(self):
        # verify served from a clean pre-existing entry: the canary only ever appeared
        # in the warm response — the script must check BOTH legs
        with _FixtureCache(reflect_hdr="x-forwarded-host",
                           hit_body="fixture clean pre-existing body") as fx:
            proc = run_probe([fx.url()])
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("=== FINDINGS: canary reflected AND served from cache (1)", out)
        self.assertEqual(out.count("injected: X-Forwarded-Host: "), 1)


# --------------------------------------------------------------------------
# (4) fat-GET: a CDN 403 is INCONCLUSIVE, not a clean negative
# --------------------------------------------------------------------------

class TestFatGet(unittest.TestCase):

    def test_fatget_403_is_labelled_inconclusive_and_not_a_finding(self):
        with _FixtureCache(fatget_403=True) as fx:
            proc = run_probe([fx.url()])
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("fat-GET rejected by CDN", out)
        self.assertIn("INCONCLUSIVE", out)
        self.assertIn("[fatget]  status=403  cache=miss  reflected=no", out)
        self.assertNotIn("=== FINDINGS", out)
        self.assertIn("no cached reflection across 6 probes", out)
        # the two fat-GET legs really did carry a body; the other probes did not
        bodied = [r for r in fx.cfg["requests"] if r["had_body"]]
        self.assertEqual(len(bodied), 2)
        self.assertEqual(len(fx.cfg["requests"]) - len(bodied), 12)


# --------------------------------------------------------------------------
# (5) the invariant the whole safety argument rests on: unique buster PER PROBE
# --------------------------------------------------------------------------

class TestCacheBusterUniqueness(unittest.TestCase):
    """An earlier version generated one buster per URL instead of per probe, which would
    let probe N be served the entry probe N-1 cached. Every probe must carry its own."""

    def test_every_probe_carries_a_distinct_cache_buster(self):
        with _FixtureCache() as fx:
            proc = run_probe([fx.url()])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cbs = cb_values(fx)
        self.assertEqual(len(cbs), 12)                       # every probe request has one
        self.assertEqual(len(set(cbs)), 6)                   # ...and only 6 distinct values
        for cb in set(cbs):
            self.assertEqual(cbs.count(cb), 2)               # warm+verify SHARE their probe's

    def test_preflight_uses_two_different_random_query_strings(self):
        with _FixtureCache() as fx:
            run_probe([fx.url()])
        preflight = [r["path"] for r in fx.cfg["requests"] if "cb=" not in r["path"]]
        self.assertEqual(len(preflight), 2)
        self.assertNotEqual(preflight[0], preflight[1])


if __name__ == "__main__":
    unittest.main()
