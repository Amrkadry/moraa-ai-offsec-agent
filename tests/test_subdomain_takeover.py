#!/usr/bin/env python3
"""Offline tests for scripts/subdomain_takeover.py (TASK-002; first slice of TASK-005).

stdlib unittest + unittest.mock only. No real network/DNS: subprocess dig is mocked at
run_dig (the module's single subprocess seam) and HTTP at probe_http — the pipeline logic,
verdict ladder, and output contract are tested without touching the wire.

Run:  python3 -m unittest discover -s tests -p "test_subdomain_takeover.py" -v
"""

import contextlib
import io
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import subdomain_takeover as st  # noqa: E402


class FakeDig:
    """Standalone-in for run_dig. Builds dig outputs from small lookup tables.

    cname/a/ns: qname -> list of record values (rendered one-per-line, trailing dot,
    exactly like `dig +short`). status: qname -> header status for +noall +comments.
    soa: nameserver host -> SOA output ("" == server unresponsive, dig prints nothing).
    timeout_names / rc_fail_names: qnames that raise TimeoutExpired / return rc=1.
    """

    RTYPES = ("CNAME", "A", "NS", "SOA")

    def __init__(self, cname=None, a=None, ns=None, status=None, default_status="NXDOMAIN",
                 soa=None, timeout_names=(), rc_fail_names=(), resolver_error_names=()):
        def norm(d):
            return {k.lower(): v for k, v in (d or {}).items()}
        self.cname, self.a, self.ns = norm(cname), norm(a), norm(ns)
        self.status = norm(status)
        self.default_status = default_status
        self.soa = {k.lower(): v for k, v in (soa or {}).items()}
        self.timeout_names = {n.lower() for n in timeout_names}
        self.rc_fail_names = {n.lower() for n in rc_fail_names}
        # rc != 0 but STDOUT non-empty — a real dig failure mode (e.g. rc=9 "no servers could
        # be reached" prints its ";; ..." diagnostic to stdout under +short, not stderr). Must
        # be treated as an error, never as record data. Regression coverage for that bug.
        self.resolver_error_names = {n.lower() for n in resolver_error_names}
        self.calls: list[list[str]] = []

    def run_dig(self, dig_path, args, timeout):
        self.calls.append(list(args))
        args = [str(a) for a in args]
        if any(x.startswith("@") for x in args):  # NS SOA probe
            ns_host = next(x for x in args if x.startswith("@"))[1:]
            out = self.soa.get(ns_host, "")
            return 0, out, ""
        if "+noall" in args:  # status query: qname is the last arg
            qname = args[-1].lower()
            hdr = f";; ->>HEADER<<- opcode: QUERY, status: {self._status(qname)}, id: 1234"
            return 0, hdr + "\n;; ANSWER: 0\n", ""
        rtype = next((x for x in args if x in self.RTYPES), "A")
        idx = args.index(rtype)
        qname = (args[idx + 1] if idx + 1 < len(args) and not args[idx + 1].startswith("+")
                 else args[-1]).lower()
        if qname in self.timeout_names:
            raise subprocess.TimeoutExpired(cmd=["dig"] + args, timeout=timeout)
        if qname in self.rc_fail_names:
            return 1, "", "dig: simulate hard failure"
        if qname in self.resolver_error_names:
            return 9, (";; communications error to 10.255.255.254#53: timed out\n"
                       ";; no servers could be reached"), ""
        table = {"CNAME": self.cname, "A": self.a, "NS": self.ns}.get(rtype, {})
        return 0, "".join(v + ".\n" for v in table.get(qname, [])), ""

    def _status(self, qname):
        return self.status.get(qname, self.default_status)


def make_probe(status=404, body="", error=None, calls=None):
    """Standalone-in for probe_http."""
    def probe(url, timeout):
        if calls is not None:
            calls.append(url)
        return {"url": url, "status": status, "body": body, "error": error}
    return probe


def scan(fake_dig, domain, probe=None, timeout=5.0):
    """Run scan_domain with dig + http fully mocked."""
    with mock.patch.object(st, "run_dig", fake_dig.run_dig), \
         mock.patch.object(st, "probe_http", probe or make_probe(error="unreachable")):
        return st.scan_domain(domain, st.load_fingerprints(), timeout=timeout, dig_path="dig")


class TestPipelineVerdicts(unittest.TestCase):
    """The core verdict ladder — every task-mandated scenario."""

    def test_no_cname_is_not_vulnerable(self):
        res = scan(FakeDig(a={"sub.test": ["1.2.3.4"]}, default_status="NOERROR"), "sub.test")
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "NOT_VULNERABLE")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["confidence"], 0.95)
        self.assertTrue(any("no CNAME" in e for e in res["evidence"]))

    def test_input_nxdomain_is_handled_not_crash(self):
        # NXDOMAIN on the input itself: a valid, handled case — strong negative, exit-clean.
        res = scan(FakeDig(default_status="NXDOMAIN"), "does-not-exist.test")
        f = res["findings"][0]
        self.assertEqual(res["status"], "success")
        self.assertEqual(f["verdict"], "NOT_VULNERABLE")
        self.assertTrue(any("NXDOMAIN" in e for e in res["evidence"]))

    def test_confirmed_pattern_plus_nxdomain_style_resolving_plus_http(self):
        # CNAME -> github.io (resolving-style service), HTTP body carries the unclaimed
        # fingerprint: two independent signals agree -> CONFIRMED / high / 0.9.
        fake = FakeDig(
            cname={"sub.test": ["lost.github.io"]},
            a={"lost.github.io": ["185.199.108.153"]},
            default_status="NOERROR",
        )
        probe = make_probe(status=404, body="<h1>There isn't a GitHub Pages site here.</h1>")
        res = scan(fake, "sub.test", probe=probe)
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "CONFIRMED")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["confidence"], 0.90)
        self.assertIn("claim", f["next_action"].lower())
        # evidence must show the ordered stage-by-stage reasoning, not just the number
        self.assertTrue(any("CNAME chain" in e for e in res["evidence"]))
        self.assertTrue(any("matched 'GitHub Pages'" in e for e in res["evidence"]))
        self.assertTrue(any("fingerprint MATCHED" in e for e in res["evidence"]))

    def test_nxdomain_target_is_likely_without_http(self):
        # herokudns-style: pattern matches, target NXDOMAIN (dangling), domain unreachable.
        fake = FakeDig(cname={"sub.test": ["lost.herokudns.com"]}, default_status="NXDOMAIN")
        probe = make_probe(error="NameResolutionError: sub.test does not resolve")
        res = scan(fake, "sub.test", probe=probe)
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "LIKELY")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["confidence"], 0.70)
        self.assertTrue(any("NXDOMAIN" in e for e in res["evidence"]))

    def test_claimed_service_is_not_vulnerable(self):
        # Pattern matches but the target resolves AND the body has no unclaimed signature.
        fake = FakeDig(
            cname={"sub.test": ["live.github.io"]},
            a={"live.github.io": ["185.199.108.153"]},
            default_status="NOERROR",
        )
        probe = make_probe(status=200, body="<html>Welcome to our live documentation</html>")
        res = scan(fake, "sub.test", probe=probe)
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "NOT_VULNERABLE")
        self.assertEqual(f["severity"], "info")
        self.assertTrue(f["confidence"] < 0.95)  # claimed-verdict is a softer negative
        self.assertTrue(any("no unclaimed-fingerprint" in e for e in res["evidence"]))

    def test_unknown_cname_target_is_inconclusive_not_safe(self):
        fake = FakeDig(cname={"sub.test": ["cdn.unknown-provider.example"]},
                       a={"cdn.unknown-provider.example": ["203.0.113.7"]},
                       default_status="NOERROR")
        res = scan(fake, "sub.test")
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "INCONCLUSIVE")
        self.assertEqual(f["severity"], "info")
        self.assertTrue(any("does not match any known takeover-vulnerable service" in e
                            for e in res["evidence"]))

    def test_wildcard_parent_does_not_false_positive(self):
        # Parent wildcards (random control label resolves) — the "dangling" CNAME may be
        # synthetic, so DNS-only escalation must be suppressed.
        fake = FakeDig(
            cname={"sub.test": ["lost.github.io"],
                   "live.github.io": []},
            a={"live.github.io": ["185.199.108.153"]},
            default_status="NOERROR",
        )
        # any CNAME/A lookup not in the tables (i.e. the random control label) must resolve
        original_run = fake.run_dig

        def wildcard_run(dig_path, args, timeout):
            rc, out, err = original_run(dig_path, args, timeout)
            if "moraadns-wildcard-" in " ".join(args) and "+noall" not in args:
                return 0, "wildcard-catchall.test.\n", ""
            return rc, out, err
        fake.run_dig = wildcard_run

        probe = make_probe(status=200, body="<html>generic hosting landing page</html>")
        res = scan(fake, "sub.test", probe=probe)
        f = res["findings"][0]
        self.assertIn(f["verdict"], ("NOT_VULNERABLE", "INCONCLUSIVE"))
        self.assertEqual(f["severity"], "info")
        self.assertNotIn(f["verdict"], ("CONFIRMED", "LIKELY"))
        self.assertTrue(any("wildcard" in e for e in res["evidence"]))

    def test_ns_delegation_unresponsive_is_potential(self):
        fake = FakeDig(ns={"sub.test": ["ns1.example-dns.test", "ns2.example-dns.test"]},
                       soa={"ns1.example-dns.test": "", "ns2.example-dns.test": ""})
        res = scan(fake, "sub.test")
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "POTENTIAL")
        self.assertEqual(f["severity"], "low")
        self.assertIn("NS-takeover", f["next_action"])

    def test_ns_delegation_answering_is_not_vulnerable(self):
        fake = FakeDig(ns={"sub.test": ["ns1.example-dns.test"]},
                       soa={"ns1.example-dns.test": "ns1.example-dns.test. hostmaster. 1 2 3 4 5"})
        res = scan(fake, "sub.test")
        self.assertEqual(res["findings"][0]["verdict"], "NOT_VULNERABLE")


class TestErrorHandling(unittest.TestCase):
    """dig failures degrade to INCONCLUSIVE with captured errors — never a crash."""

    def test_dig_timeout_is_inconclusive_with_error(self):
        fake = FakeDig(timeout_names=["sub.test"])
        res = scan(fake, "sub.test")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["findings"][0]["verdict"], "INCONCLUSIVE")
        self.assertTrue(res["errors"])
        self.assertIn("timed out", res["errors"][0])

    def test_dig_hard_failure_is_inconclusive_with_error(self):
        fake = FakeDig(rc_fail_names=["sub.test"])
        res = scan(fake, "sub.test")
        self.assertEqual(res["findings"][0]["verdict"], "INCONCLUSIVE")
        self.assertTrue(res["errors"])

    def test_resolver_error_with_stdout_diagnostic_is_inconclusive_not_potential(self):
        # Regression: a resolver-communication failure (rc=9) prints its ";; ..." diagnostic
        # to STDOUT under +short, not stderr. That text must never be parsed as an NS record —
        # it previously slipped through a `rc != 0 and not out.strip()` check (stdout was
        # non-empty) and got treated as a single fabricated nameserver, producing a false
        # POTENTIAL takeover verdict from the CNAME-absent/NS-delegation branch.
        fake = FakeDig(resolver_error_names=["sub.test"])
        res = scan(fake, "sub.test")
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "INCONCLUSIVE")
        self.assertNotEqual(f["verdict"], "POTENTIAL")
        self.assertTrue(res["errors"])
        self.assertTrue(any("dig rc=9" in e for e in res["errors"]))
        # the diagnostic text itself must never appear as if it were a discovered NS hostname
        self.assertFalse(any("communications error" in e and "NS delegation found" in e
                             for e in res["evidence"]))

    def test_http_connection_failure_is_evidence_not_signal(self):
        # pattern + dangling DNS, HTTP totally down -> stays at LIKELY, error is evidence only
        fake = FakeDig(cname={"sub.test": ["lost.herokudns.com"]}, default_status="NXDOMAIN")
        res = scan(fake, "sub.test", probe=make_probe(error="ConnectionRefusedError: [Errno 111]"))
        f = res["findings"][0]
        self.assertEqual(f["verdict"], "LIKELY")
        self.assertTrue(any("probe failed" in e for e in res["evidence"]))


class TestFingerprintDB(unittest.TestCase):
    """The data file itself is part of the contract."""

    def setUp(self):
        self.fps = st.load_fingerprints()

    def test_at_least_20_well_documented_entries(self):
        self.assertGreaterEqual(len(self.fps), 20)
        well = [f for f in self.fps if f.get("confidence_basis") == "well-documented"]
        self.assertGreaterEqual(len(well), 20)

    def test_every_entry_has_required_fields(self):
        required = {"service", "cname_patterns", "http_fingerprint",
                    "nxdomain_expected", "documentation", "confidence_basis"}
        seen_services = set()
        for fp in self.fps:
            missing = required - set(fp)
            self.assertFalse(missing, f"{fp.get('service')}: missing {missing}")
            self.assertIsInstance(fp["cname_patterns"], list)
            self.assertTrue(fp["cname_patterns"], f"{fp.get('service')}: empty cname_patterns")
            self.assertIsInstance(fp["http_fingerprint"], list)
            self.assertIsInstance(fp["nxdomain_expected"], bool)
            self.assertIn(fp["confidence_basis"], ("well-documented", "community-report"))
            self.assertNotIn(fp["service"], seen_services)
            seen_services.add(fp["service"])

    def test_all_patterns_are_valid_regexes(self):
        for fp in self.fps:
            for pat in fp["cname_patterns"]:
                try:
                    re.compile(pat)
                except re.error as e:
                    self.fail(f"{fp['service']}: bad pattern {pat!r}: {e}")

    def test_canonical_services_present(self):
        names = {fp["service"].lower() for fp in self.fps}
        for svc in ("github pages", "heroku", "aws s3", "azure app service", "shopify",
                    "fastly", "netlify", "vercel", "surge.sh", "pantheon", "zendesk"):
            self.assertTrue(any(svc in n for n in names), f"missing {svc}")


class TestCLIContract(unittest.TestCase):
    def test_json_output_shape_and_exit_code(self):
        fake = FakeDig(a={"sub.test": ["1.2.3.4"]}, default_status="NOERROR")
        stdout = io.StringIO()
        with mock.patch.object(st, "run_dig", fake.run_dig), \
             mock.patch.object(st, "probe_http", make_probe(error="x")), \
             contextlib.redirect_stdout(stdout):
            rc = st.main(["--json", "--quiet", "sub.test"])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "subdomain_takeover")
        self.assertEqual(payload["status"], "success")
        f = payload["findings"][0]
        for key in ("type", "severity", "confidence", "target", "evidence", "source",
                    "next_action"):
            self.assertIn(key, f)
        self.assertEqual(f["type"], "subdomain_takeover")
        self.assertEqual(f["source"], "subdomain_takeover.py")

    def test_hard_errors_exit_nonzero(self):
        with self.assertRaises(SystemExit) as cm:  # no domains at all -> usage error
            st.main([])
        self.assertEqual(cm.exception.code, 2)
        rc = st.main(["-l", str(REPO_ROOT / "tests" / "definitely-missing-file.txt")])
        self.assertEqual(rc, 2)

    def test_list_file_domains_processed(self):
        listfile = REPO_ROOT / "tests" / "fixtures" / "dns" / "list_smoke.txt"
        listfile.parent.mkdir(parents=True, exist_ok=True)  # a test that needs a fixture dir creates it
        listfile.parent.mkdir(parents=True, exist_ok=True)
        listfile.write_text("a.test\n# comment\nb.test\n", encoding="utf-8")
        self.addCleanup(listfile.unlink)  # self-cleaning (TASK-013 lesson)
        fake = FakeDig(a={"a.test": ["1.2.3.4"], "b.test": ["5.6.7.8"]},
                       default_status="NOERROR")
        stdout = io.StringIO()
        with mock.patch.object(st, "run_dig", fake.run_dig), \
             mock.patch.object(st, "probe_http", make_probe(error="x")), \
             contextlib.redirect_stdout(stdout):
            rc = st.main(["--json", "--quiet", "-l", str(listfile)])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, list)
        self.assertEqual([r["target"] for r in payload], ["a.test", "b.test"])


if __name__ == "__main__":
    unittest.main()
