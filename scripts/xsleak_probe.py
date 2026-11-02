#!/usr/bin/env python3
"""
xsleak_probe.py -- XS-Leak oracle detector: does an endpoint behave measurably
differently for an authenticated vs an unauthenticated request, in a way a
cross-origin attacker can observe?

WHY: XS-Leaks (login-state detection, search/notice oracles, group-membership
probing) live in the gap between "the response differs" and "the difference is
cross-origin observable AND statistically real". Naive single-sample timing scripts
are nothing but false positives -- one slow request is not an oracle -- so the class
gets written off. This harness samples each condition N times (default 30), reports
median +- MAD, and flags an endpoint ONLY when the separation between conditions
exceeds the measured noise floor. The statistical rigour is the point, not a nicety.

Signals per sample:
  timing (ms)       cross-origin observable (ResourceTiming / error events)
  status class      2xx/3xx/4xx/5xx -- observable via error events / no-cors fetch
  redirect target   observable via navigation behaviour
  content length    same-origin ground truth -- validates that the observable signals
                    really track the state difference (not itself cross-origin readable)

Oracle flagged when ANY of:
  * status class differs between legs (>=90% consistent within each leg)
  * redirect target differs between legs (>=90% consistent)
  * content length differs between legs (>=90% consistent)
  * |median_authed - median_unauth| > --sigma (3.0) x combined noise floor
    (1.4826*MAD, quadrature-combined) AND > --min-ms (25ms)

Usage:
  python3 xsleak_probe.py -e "https://target/api/notifications" -H "Cookie: session=..." -n 30
  python3 xsleak_probe.py -E endpoints.txt -H "Cookie: session=..." --insecure

Exit: 0 = no oracle above the noise floor; 2 = at least one oracle flagged;
1 = usage/IO error. Sampling is sequential on purpose: concurrency would distort
the timing signal.
"""
import argparse
import hashlib
import math
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.request
from collections import Counter


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block redirect following so redirect behaviour stays an observable signal."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(insecure: bool):
    handlers = [NoRedirect()]
    if insecure:
        ctx = ssl._create_unverified_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def sample_once(opener, url, method, headers, timeout):
    """One timed request. -> (sample dict, None) or (None, error string)."""
    t0 = time.perf_counter()
    req = urllib.request.Request(url, method=method, headers=dict(headers))
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read()
        code, final = resp.status, resp.geturl()
        loc = resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:  # includes blocked 3xx -- exactly what we want
        body = e.read()
        code, final = e.code, e.geturl()
        loc = e.headers.get("Location", "")
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return {
        "ms": (time.perf_counter() - t0) * 1000.0,
        "code": code,
        "class": f"{code // 100}xx",
        "final": final,
        "loc": loc,
        "len": len(body),
    }, None


def median_mad(vals):
    med = statistics.median(vals)
    mad = statistics.median([abs(v - med) for v in vals])
    return med, mad


def modal(values):
    """-> (modal value, count, total)"""
    val, count = Counter(values).most_common(1)[0]
    return val, count, len(values)


def analyze(unauth, auth, args):
    """-> (verdict string or None, printed detail lines)"""
    lines = []
    verdicts = []

    # -- status class (error-vs-success distinguisher)
    u_cls, u_cnt, u_tot = modal([s["class"] for s in unauth])
    a_cls, a_cnt, a_tot = modal([s["class"] for s in auth])
    if u_cls != a_cls and u_cnt / u_tot >= 0.9 and a_cnt / a_tot >= 0.9:
        verdicts.append(f"error-vs-success oracle ({u_cls} vs {a_cls})")
    lines.append(f"    status class  unauth: {u_cls} ({u_cnt}/{u_tot})   "
                 f"authed: {a_cls} ({a_cnt}/{a_tot})")

    # -- redirect behaviour
    u_red, u_cnt, u_tot = modal([s["loc"] or s["final"] for s in unauth])
    a_red, a_cnt, a_tot = modal([s["loc"] or s["final"] for s in auth])
    if u_red != a_red and u_cnt / u_tot >= 0.9 and a_cnt / a_tot >= 0.9:
        verdicts.append(f"redirect oracle ({u_red!r} vs {a_red!r})")
    lines.append(f"    redirect      unauth: {u_red!r} ({u_cnt}/{u_tot})   "
                 f"authed: {a_red!r} ({a_cnt}/{a_tot})")

    # -- content length (same-origin ground truth for the state difference)
    u_len, u_cnt, u_tot = modal([s["len"] for s in unauth])
    a_len, a_cnt, a_tot = modal([s["len"] for s in auth])
    if u_len != a_len and u_cnt / u_tot >= 0.9 and a_cnt / a_tot >= 0.9:
        verdicts.append(f"content-length oracle ({u_len} vs {a_len} bytes)")
    lines.append(f"    content-len   unauth: {u_len} ({u_cnt}/{u_tot})   "
                 f"authed: {a_len} ({a_cnt}/{a_tot})")

    # -- timing vs measured noise floor (median +- MAD)
    u_med, u_mad = median_mad([s["ms"] for s in unauth])
    a_med, a_mad = median_mad([s["ms"] for s in auth])
    delta = abs(a_med - u_med)
    combined = math.hypot(1.4826 * u_mad, 1.4826 * a_mad)
    mult = delta / combined if combined > 1e-9 else float("inf")
    if delta > args.sigma * combined and delta >= args.min_ms:
        verdicts.append(f"timing oracle (delta {delta:.1f}ms = {mult:.1f} sigma)")
    lines.append(
        f"    timing (ms)   unauth: median {u_med:.1f} MAD {u_mad:.1f}   "
        f"authed: median {a_med:.1f} MAD {a_mad:.1f}   "
        f"delta {delta:.1f}ms = {mult:.1f} sigma "
        f"(floor: {args.sigma:g} sigma AND {args.min_ms:g}ms)"
    )

    return ("; ".join(verdicts) if verdicts else None), lines


def main():
    ap = argparse.ArgumentParser(
        prog="xsleak_probe.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-e", "--endpoint", action="append", default=[],
                    help="endpoint URL to probe (repeatable)")
    ap.add_argument("-E", "--endpoints-file",
                    help="file with one URL per line (# comments ok)")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help="header applied ONLY to the authed leg, 'Name: value' "
                         "(repeatable, e.g. -H 'Cookie: session=...')")
    ap.add_argument("-X", "--method", default="GET", help="HTTP method (default GET)")
    ap.add_argument("-n", "--samples", type=int, default=30,
                    help="samples per condition (default 30)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="per-request timeout seconds (default 10)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--sigma", type=float, default=3.0,
                    help="timing flag threshold in combined sigma (default 3.0)")
    ap.add_argument("--min-ms", type=float, default=25.0,
                    help="minimum timing delta in ms to flag (default 25)")
    args = ap.parse_args()

    endpoints = list(args.endpoint)
    if args.endpoints_file:
        with open(args.endpoints_file, encoding="utf-8") as f:
            endpoints += [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    if not endpoints:
        ap.error("need -e URL (repeatable) or -E endpoints.txt")

    auth_headers = {}
    for h in args.header:
        if ":" not in h:
            ap.error(f"--header expects 'Name: value', got: {h}")
        name, _, value = h.partition(":")
        auth_headers[name.strip()] = value.strip()

    opener = make_opener(args.insecure)
    print(f"=== xsleak_probe: {len(endpoints)} endpoint(s) x {args.samples} samples "
          f"x 2 conditions (authed vs unauthed) ===")
    # Print header NAMES and a short value fingerprint only. Never the values:
    # these are live session cookies/JWTs, and this output routinely gets pasted
    # into a findings file or a bug report.
    def _redact(hdrs):
        if not hdrs:
            return "(none -- both legs identical; add -H 'Cookie: ...')"
        out = []
        for k, v in hdrs.items():
            out.append(f"{k}: <redacted {len(v)} chars, sha256:"
                       f"{hashlib.sha256(v.encode()).hexdigest()[:8]}>")
        return "; ".join(out)

    print(f"authed leg headers: {_redact(auth_headers)}\n")

    any_oracle = False
    for url in endpoints:
        # warmup per leg: DNS/TLS/connection artefacts would otherwise skew sample #1
        sample_once(opener, url, args.method, {}, args.timeout)
        sample_once(opener, url, args.method, auth_headers, args.timeout)

        unauth, auth = [], []
        errors = 0
        for _ in range(args.samples):
            for bucket, hdrs in ((unauth, {}), (auth, auth_headers)):
                s, err = sample_once(opener, url, args.method, hdrs, args.timeout)
                if s is None:
                    errors += 1
                else:
                    bucket.append(s)

        if len(unauth) < 5 or len(auth) < 5:
            print(f"[ ERROR ] {url}: insufficient samples "
                  f"(unauth={len(unauth)}, authed={len(auth)}, errors={errors})\n")
            continue

        verdict, lines = analyze(unauth, auth, args)
        print(f"[{'ORACLE' if verdict else '  clean'}] {url}")
        for ln in lines:
            print(ln)
        if verdict:
            any_oracle = True
            print(f"    verdict: {verdict}")
        else:
            print("    verdict: no oracle (all signals within noise)")
        if errors:
            print(f"    ({errors} request errors dropped from the sample set)")
        print()

    if any_oracle:
        print("At least one endpoint separates authed vs unauthed beyond its noise floor --")
        print("confirm cross-origin exploitability (attacker-controllable request state) per")
        print("the XS-Leak methodology doc before reporting.")
        sys.exit(2)
    print("No oracle above the noise floor on any endpoint.")


if __name__ == "__main__":
    main()
