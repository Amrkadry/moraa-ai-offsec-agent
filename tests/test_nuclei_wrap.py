#!/usr/bin/env python3
"""Offline tests for scripts/nuclei_wrap.py (TASK-012).

stdlib unittest + unittest.mock only. NO real nuclei invocation, NO real network calls —
the single external seam (subprocess.run inside run_tool, reached via find_tool + the
nuclei handler) is mocked exactly like test_github_recon.py mocks its wrapped tools.
Every call's argv is recorded so tests can assert the exact nuclei CLI syntax,
including the ADAPTIVE per-tag-set grouping (--from-cms-detect -> one invocation per
distinct tag set, asserted on the real subprocess argv).

The JSONL fixtures are synthetic: RFC 2606 .invalid hosts, generic public template ids
(git-config / env-file / backup-detect), obviously-fake extracted values — nothing
pointing at any real target.

Run:  python3 -m unittest discover -s tests -p "test_nuclei_wrap.py" -v
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import nuclei_wrap as nw  # noqa: E402

FIXTURE_JSONL = REPO_ROOT / "tests" / "fixtures" / "nuclei" / "sample_results.jsonl"

WP_TARGET = "https://wp-test.invalid"
PLAIN_TARGET = "https://plain-test.invalid"
JOOMLA_TARGETS = ["https://j1-test.invalid", "https://j2-test.invalid"]
NUCLEI = "/fake/go/bin/nuclei"

DEFAULT_TAGS = nw.DEFAULT_TAGS            # exposure,config,git,backup,takeover
DEFAULT_SEV = nw.DEFAULT_SEVERITY         # critical,high,medium


def nuclei_jsonl(*objs) -> str:
    return "".join(json.dumps(o) + "\n" for o in objs)


def nuclei_hit(template_id="git-config", name="Git Config Exposure", severity="high",
               host="scan-target.invalid", matched=None, extracted=None,
               reference=None, matcher_status=None):
    obj = {
        "template-id": template_id,
        "info": {"name": name, "severity": severity,
                 "tags": ["exposure"], "description": "synthetic"},
        "type": "http",
        "host": host,
        "matched-at": matched or ("https://%s/synthetic" % host),
        "matcher-status": True,
    }
    if extracted is not None:
        obj["extracted-results"] = extracted
    if reference is not None:
        obj["info"]["reference"] = reference
    if matcher_status is not None:
        obj["matcher-status"] = matcher_status
    return obj


def cms_result(target, cms):
    """One cms_detect.py-shaped result object (the 'cms' key lives on the
    cms_detection finding; unidentified hosts carry cms=None)."""
    return {"tool": "cms_detect", "target": target, "timestamp": "2026-09-24T00:00:00Z",
            "status": "success",
            "findings": [{"type": "cms_detection", "severity": "info",
                          "confidence": 0.9, "target": target, "evidence": [],
                          "source": "cms_detect.py", "cms": cms,
                          "next_action": "synthetic"}],
            "evidence": [], "errors": [], "metadata": {}}


class FakeCompleted:
    def __init__(self, rc=0, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class FakeTools:
    """Standalone-in for subprocess.run. Keyed by tool basename; every call's argv is
    recorded, and for -l invocations the target-list file content is captured BEFORE
    run_nuclei_group deletes it."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.list_file_contents: list[str] = []
        self.handlers = {}

    def run(self, argv, capture_output=False, text=False, timeout=None):
        argv = list(argv)
        self.calls.append(argv)
        if "-l" in argv:
            path = argv[argv.index("-l") + 1]
            self.list_file_contents.append(
                Path(path).read_text(encoding="utf-8") if Path(path).is_file() else "")
        handler = self.handlers.get(Path(argv[0]).name)
        if handler is None:
            return FakeCompleted(rc=99, err="FakeTools: no handler for %s" % argv[0])
        return handler(argv)


def run_main(argv, tools=None, handlers=None, version="v0.0.0-test"):
    """Run nw.main under the fully patched world.
      tools:    name -> path for find_tool (absent = not installed)
      handlers: basename -> fn(argv) -> FakeCompleted for subprocess.run
      version:  get_nuclei_version stub (its own seam — separately tested)
    Returns (rc, stdout, stderr, fake_tools)."""
    ft = FakeTools()
    ft.handlers.update(handlers or {})

    def finder(name):
        return (tools or {}).get(name)

    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.object(nw, "find_tool", side_effect=finder), \
         mock.patch.object(nw.subprocess, "run", ft.run), \
         mock.patch.object(nw, "get_nuclei_version", return_value=version), \
         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = nw.main(argv)
    return rc, stdout.getvalue(), stderr.getvalue(), ft


def scan_direct(tools=None, handlers=None, **kwargs):
    """scan_nuclei directly with the subprocess seam patched; returns (result, fake_tools)."""
    ft = FakeTools()
    ft.handlers.update(handlers or {})
    with mock.patch.object(nw, "find_tool",
                           side_effect=lambda n: (tools or {}).get(n)), \
         mock.patch.object(nw.subprocess, "run", ft.run), \
         mock.patch.object(nw, "get_nuclei_version", return_value="v0.0.0-test"):
        res = nw.scan_nuclei(**kwargs)
    return res, ft


def tags_of(argv):
    return argv[argv.index("-tags") + 1]


# --------------------------------------------------------------------------
# (1) nuclei not found -> clean success skip, exit 0
# --------------------------------------------------------------------------

class TestNucleiMissing(unittest.TestCase):

    def test_not_found_clean_skip_exit0(self):
        rc, out, err, ft = run_main(["-u", WP_TARGET, "--json", "--quiet"], tools={})
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["findings"], [])
        # one clear skip line carrying the actual install command, in BOTH evidence
        # and errors so neither a human nor an agent can mistake skip for clean-zero
        joined = " ".join(payload["errors"] + payload["evidence"])
        self.assertIn("not installed", joined)
        self.assertIn(nw.NUCLEI_INSTALL_CMD, joined)
        self.assertIn("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                      joined)
        md = payload["metadata"]
        self.assertIsNone(md["nuclei_path"])
        self.assertEqual(md["targets_scanned"], 0)
        self.assertEqual(md["raw_finding_count"], 0)
        self.assertEqual(ft.calls, [])           # nothing was ever invoked

    def test_not_found_human_mode_skip_and_next(self):
        rc, out, err, _ = run_main([WP_TARGET], tools={})
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "")        # machine output ONLY with --json
        self.assertIn("[skip] nuclei", err)
        self.assertIn(nw.NUCLEI_INSTALL_CMD, err)
        self.assertIn("Next:", err)


# --------------------------------------------------------------------------
# (2) nuclei found -> JSONL parsed + mapped, severity passthrough
# --------------------------------------------------------------------------

class TestParseAndMap(unittest.TestCase):

    def setUp(self):
        self.fixture_text = FIXTURE_JSONL.read_text(encoding="utf-8")
        self.handlers = {"nuclei": lambda a: FakeCompleted(
            rc=0, out=self.fixture_text, err="")}

    def test_fixture_findings_mapped_and_severity_passthrough(self):
        res, ft = scan_direct(tools={"nuclei": NUCLEI}, handlers=self.handlers,
                              targets=[WP_TARGET])
        self.assertEqual(len(res["findings"]), 3)
        severities = [f["severity"] for f in res["findings"]]
        # nuclei's OWN severity strings, unchanged — including that a "critical" from
        # upstream passes through as "critical" (the one sanctioned passthrough)
        self.assertEqual(severities, ["high", "critical", "medium"])
        for f, matched in zip(res["findings"], [
                "https://scan-target.invalid/.git/config",
                "https://scan-target.invalid/.env",
                "https://scan-target.invalid/backup/"]):
            self.assertEqual(f["type"], "nuclei_finding")
            self.assertEqual(f["confidence"], 0.85)
            self.assertEqual(f["target"], matched)
            self.assertEqual(f["source"], "nuclei_wrap.py")
            self.assertTrue(f["evidence"][0].startswith("template-id: "))
            self.assertIn(f["template_id"], f["evidence"][0])
            self.assertTrue(f["next_action"].startswith("confirm manually -- nuclei template "))
        # extracted-results reach evidence when present
        self.assertIn("extracted-results: [core] repositoryformatversion = 0",
                      res["findings"][0]["evidence"][3])
        # reference reaches next_action; no reference -> no ", see"
        self.assertIn(", see https://synthetic-docs.invalid/git-config",
                      res["findings"][0]["next_action"])
        self.assertNotIn(", see ", res["findings"][1]["next_action"])

    def test_reference_list_and_string_forms_both_handled(self):
        f1 = nw.map_finding(nuclei_hit(reference=["https://a.invalid/x"]))
        f2 = nw.map_finding(nuclei_hit(reference="https://b.invalid/y"))
        self.assertIn("see https://a.invalid/x", f1["next_action"])
        self.assertIn("see https://b.invalid/y", f2["next_action"])

    def test_matcher_status_false_is_not_a_finding(self):
        res, _ = scan_direct(tools={"nuclei": NUCLEI},
                             handlers={"nuclei": lambda a: FakeCompleted(
                                 rc=0, out=nuclei_jsonl(
                                     nuclei_hit(matcher_status=False),
                                     nuclei_hit(template_id="env-file")), err="")},
                             targets=[WP_TARGET])
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["metadata"]["non_matching_results"], 1)
        self.assertEqual(res["metadata"]["raw_finding_count"], 1)

    def test_nuclei_version_parsed_for_metadata(self):
        with mock.patch.object(nw, "run_tool",
                               return_value=(0, "", "[INF] Nuclei Engine Version: v3.11.1\n")):
            self.assertEqual(nw.get_nuclei_version("nuclei"), "v3.11.1")
        with mock.patch.object(nw, "run_tool", return_value=(0, "", "")):
            self.assertIsNone(nw.get_nuclei_version("nuclei"))


# --------------------------------------------------------------------------
# (3) default tag set when no --from-cms-detect
# --------------------------------------------------------------------------

class TestDefaultFlags(unittest.TestCase):

    def test_default_tags_severity_and_cli_shape_single_target(self):
        res, ft = scan_direct(tools={"nuclei": NUCLEI},
                              handlers={"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")},
                              targets=[WP_TARGET])
        self.assertEqual(len(ft.calls), 1)
        argv = ft.calls[0]
        self.assertEqual(argv[argv.index("-tags") + 1], DEFAULT_TAGS)
        self.assertEqual(argv[argv.index("-severity") + 1], DEFAULT_SEV)
        self.assertIn("-jsonl", argv)
        self.assertEqual(argv[argv.index("-timeout") + 1], "10")
        self.assertNotIn("-rl", argv)            # omitted -> nuclei's own default (150)
        self.assertEqual(argv[argv.index("-u") + 1], WP_TARGET)
        self.assertNotIn("-l", argv)
        self.assertEqual(res["metadata"]["tags_used"],
                         [{"tags": DEFAULT_TAGS, "targets": [WP_TARGET]}])

    def test_tags_and_severity_overrides_reach_nuclei(self):
        _, ft = scan_direct(tools={"nuclei": NUCLEI},
                            handlers={"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")},
                            targets=[WP_TARGET], base_tags="cve",
                            severity="high,critical")
        argv = ft.calls[0]
        self.assertEqual(tags_of(argv), "cve")
        self.assertEqual(argv[argv.index("-severity") + 1], "high,critical")

    def test_rate_limit_passthrough_only_when_given(self):
        _, ft = scan_direct(tools={"nuclei": NUCLEI},
                            handlers={"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")},
                            targets=[WP_TARGET], rate_limit=75)
        self.assertEqual(ft.calls[0][ft.calls[0].index("-rl") + 1], "75")
        _, ft2 = scan_direct(tools={"nuclei": NUCLEI},
                             handlers={"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")},
                             targets=[WP_TARGET], rate_limit=None)
        self.assertNotIn("-rl", ft2.calls[0])

    def test_multi_target_group_uses_l_flag_with_file_contents(self):
        targets = ["https://a-test.invalid", "https://b-test.invalid"]
        _, ft = scan_direct(tools={"nuclei": NUCLEI},
                            handlers={"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")},
                            targets=targets)
        self.assertEqual(len(ft.calls), 1)
        self.assertIn("-l", ft.calls[0])
        self.assertEqual(ft.list_file_contents[0],
                         "https://a-test.invalid\nhttps://b-test.invalid\n")


# --------------------------------------------------------------------------
# (4) adaptive --from-cms-detect grouping
# --------------------------------------------------------------------------

class TestAdaptiveCmsTags(unittest.TestCase):

    def _scan(self, tmpdir, cms_payload, targets):
        cms_file = Path(tmpdir) / "cms.json"
        cms_file.write_text(json.dumps(cms_payload), encoding="utf-8")
        argv = ["--from-cms-detect", str(cms_file), "--json", "--quiet"]
        for t in targets:
            argv += ["-u", t]
        rc, out, err, ft = run_main(argv, tools={"nuclei": NUCLEI},
                                    handlers={"nuclei": lambda a: FakeCompleted(
                                        rc=0, out="", err="")})
        return rc, json.loads(out), ft

    def test_two_targets_two_tag_sets_two_invocations(self):
        """WordPress host gets +wordpress; unidentified host gets the plain defaults —
        asserted on the ACTUAL subprocess argv (task contract requirement 4)."""
        cms_payload = [cms_result(WP_TARGET, "WordPress"),
                       cms_result(PLAIN_TARGET, None)]
        with tempfile.TemporaryDirectory() as td:
            rc, payload, ft = self._scan(td, cms_payload, [WP_TARGET, PLAIN_TARGET])
        self.assertEqual(rc, 0)
        self.assertEqual(len(ft.calls), 2)       # once per distinct tag set
        argvs = ft.calls
        wp_call = next(a for a in argvs if "wordpress" in tags_of(a))
        plain_call = next(a for a in argvs if "wordpress" not in tags_of(a))
        self.assertEqual(tags_of(wp_call), DEFAULT_TAGS + ",wordpress")
        self.assertEqual(tags_of(plain_call), DEFAULT_TAGS)
        self.assertEqual(wp_call[wp_call.index("-u") + 1], WP_TARGET)
        self.assertEqual(plain_call[plain_call.index("-u") + 1], PLAIN_TARGET)
        # per-tag-set metadata
        self.assertEqual(len(payload["metadata"]["tags_used"]), 2)
        self.assertEqual({g["tags"] for g in payload["metadata"]["tags_used"]},
                         {DEFAULT_TAGS + ",wordpress", DEFAULT_TAGS})
        self.assertTrue(payload["metadata"]["adaptive_cms_tags"])
        self.assertEqual(payload["metadata"]["targets_scanned"], 2)
        # adaptive evidence names which host got which treatment
        self.assertIn("adaptive: %s -> cms_detect identified WordPress" % WP_TARGET,
                      " ".join(payload["evidence"]))
        self.assertIn("no CMS identified (default tags)",
                      " ".join(payload["evidence"]))

    def test_single_object_form_adds_tag(self):
        """cms_detect's OTHER output form (a single result object) also parses; only the
        target it names gets the CMS tag."""
        cms_payload = cms_result(JOOMLA_TARGETS[0], "Joomla")
        with tempfile.TemporaryDirectory() as td:
            cms_file = Path(td) / "cms.json"
            cms_file.write_text(json.dumps(cms_payload), encoding="utf-8")
            rc, out, _, ft = run_main(
                ["--from-cms-detect", str(cms_file), "--json", "--quiet",
                 JOOMLA_TARGETS[0], PLAIN_TARGET],
                tools={"nuclei": NUCLEI},
                handlers={"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")})
        payload = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(len(ft.calls), 2)
        joomla_call = next(a for a in ft.calls if "joomla" in tags_of(a))
        self.assertEqual(joomla_call[joomla_call.index("-u") + 1], JOOMLA_TARGETS[0])
        self.assertEqual(payload["metadata"]["targets_scanned"], 2)

    def test_same_cms_targets_share_one_l_invocation(self):
        """Same-CMS targets share ONE -l invocation while the plain host gets its own
        run — grouped per tag set, never a unioned sweep."""
        cms_payload = [cms_result(JOOMLA_TARGETS[0], "Joomla"),
                       cms_result(JOOMLA_TARGETS[1], "Joomla"),
                       cms_result(PLAIN_TARGET, None)]
        with tempfile.TemporaryDirectory() as td:
            cms_file = Path(td) / "cms.json"
            cms_file.write_text(json.dumps(cms_payload), encoding="utf-8")
            rc, out, _, ft = run_main(
                ["--from-cms-detect", str(cms_file), "--json", "--quiet",
                 JOOMLA_TARGETS[0], JOOMLA_TARGETS[1], PLAIN_TARGET],
                tools={"nuclei": NUCLEI},
                handlers={"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")})
        payload = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(len(ft.calls), 2)
        joomla_call = next(a for a in ft.calls if "joomla" in tags_of(a))
        plain_call = next(a for a in ft.calls if "joomla" not in tags_of(a))
        self.assertEqual(tags_of(joomla_call), DEFAULT_TAGS + ",joomla")
        self.assertIn("-l", joomla_call)
        self.assertEqual(ft.list_file_contents[0],
                         "%s\n%s\n" % (JOOMLA_TARGETS[0], JOOMLA_TARGETS[1]))
        self.assertEqual(plain_call[plain_call.index("-u") + 1], PLAIN_TARGET)
        groups = payload["metadata"]["tags_used"]
        self.assertEqual(len(groups), 2)
        joomla_group = next(g for g in groups if "joomla" in g["tags"])
        self.assertEqual(len(joomla_group["targets"]), 2)

    def test_cms_detect_output_not_scan_target_is_harmless(self):
        """A CMS entry for a host the user is not scanning is simply unused — the scan
        list always comes from the CLI."""
        cms_payload = [cms_result("https://elsewhere-test.invalid", "Drupal")]
        with tempfile.TemporaryDirectory() as td:
            rc, payload, ft = self._scan(td, cms_payload, [WP_TARGET])
        self.assertEqual(rc, 0)
        self.assertEqual(len(ft.calls), 1)
        self.assertEqual(tags_of(ft.calls[0]), DEFAULT_TAGS)   # drupal tag unused
        self.assertEqual(payload["metadata"]["targets_scanned"], 1)

    def test_cms_file_missing_is_hard_error_rc2(self):
        rc, _, _, _ = run_main([WP_TARGET, "--from-cms-detect",
                                "/no/such/cms.json", "--json", "--quiet"])
        self.assertEqual(rc, 2)

    def test_cms_file_unparseable_is_hard_error_rc2(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "cms.json"
            bad.write_text("{not json at all", encoding="utf-8")
            rc, _, _, _ = run_main([WP_TARGET, "--from-cms-detect", str(bad),
                                    "--json", "--quiet"])
            self.assertEqual(rc, 2)

    def test_effective_tags_dedupe_and_lowercase(self):
        self.assertEqual(nw._effective_tags(DEFAULT_TAGS, "WordPress"),
                         DEFAULT_TAGS + ",wordpress")
        self.assertEqual(nw._effective_tags(DEFAULT_TAGS + ",wordpress", "WordPress"),
                         DEFAULT_TAGS + ",wordpress")   # no duplicate tag


# --------------------------------------------------------------------------
# (5) malformed JSONL lines are skipped, counted, never fatal
# --------------------------------------------------------------------------

class TestMalformedLines(unittest.TestCase):

    def test_malformed_lines_skipped_and_counted(self):
        good1 = json.dumps(nuclei_hit(template_id="git-config"))
        good2 = json.dumps(nuclei_hit(template_id="env-file", severity="critical"))
        noisy = "\n".join(["not-json-at-all{{",
                           "",                      # blank: ignored silently
                           '"bare json string"',    # valid JSON, wrong type -> counted bad
                           good1,
                           "{\"truncated\": ",
                           good2]) + "\n"
        res, _ = scan_direct(tools={"nuclei": NUCLEI},
                             handlers={"nuclei": lambda a: FakeCompleted(
                                 rc=0, out=noisy, err="")},
                             targets=[WP_TARGET])
        self.assertEqual(len(res["findings"]), 2)
        self.assertEqual(res["metadata"]["unparseable_lines"], 3)
        self.assertEqual(res["status"], "success")

    def test_entirely_garbage_stdout_yields_zero_findings_with_note(self):
        res, _ = scan_direct(tools={"nuclei": NUCLEI},
                             handlers={"nuclei": lambda a: FakeCompleted(
                                 rc=0, out="banner\ngarbage\n", err="")},
                             targets=[WP_TARGET])
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["metadata"]["unparseable_lines"], 2)


# --------------------------------------------------------------------------
# (6) nuclei failure (nonzero rc / timeout) -> captured error, not a crash
# --------------------------------------------------------------------------

class TestFailureHandling(unittest.TestCase):

    def test_nonzero_rc_captured_partial_results_kept(self):
        """Template compile error (rc=1) after one result already streamed: the error is
        recorded AND the streamed finding is kept (nuclei emits progressively)."""
        handlers = {"nuclei": lambda a: FakeCompleted(
            rc=1, out=nuclei_jsonl(nuclei_hit(template_id="git-config", severity="high")),
            err="[ERR] could not compile template: t/some-template.yaml (synthetic)")}
        res, _ = scan_direct(tools={"nuclei": NUCLEI}, handlers=handlers,
                             targets=[WP_TARGET])
        self.assertEqual(res["status"], "success")
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["severity"], "high")
        self.assertTrue(any("rc=1" in e for e in res["errors"]))
        self.assertTrue(any("could not compile template" in e for e in res["errors"]))
        self.assertTrue(any("streamed before the failure" in e
                            for e in res["evidence"]))

    def test_tool_timeout_captured_not_crash(self):
        def boom(argv, capture_output=False, text=False, timeout=None):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)
        with mock.patch.object(nw, "find_tool", return_value=NUCLEI), \
             mock.patch.object(nw.subprocess, "run", side_effect=boom):
            res = nw.scan_nuclei(targets=[WP_TARGET])
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["findings"], [])
        self.assertTrue(any("TOOL_TIMEOUT" in e for e in res["errors"]))

    def test_spawn_failure_captured_not_crash(self):
        def boom(argv, capture_output=False, text=False, timeout=None):
            raise OSError(8, "Exec format error")
        with mock.patch.object(nw, "find_tool", return_value=NUCLEI), \
             mock.patch.object(nw.subprocess, "run", side_effect=boom):
            res = nw.scan_nuclei(targets=[WP_TARGET])
        self.assertEqual(res["status"], "success")
        self.assertTrue(any("Exec format error" in e for e in res["errors"]))

    def test_one_group_failure_does_not_stop_the_next_group(self):
        """Two tag-set groups: the first invocation fails, the second still runs."""
        calls = {"n": 0}

        def handler(argv, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeCompleted(rc=1, out="", err="[ERR] boom (synthetic)")
            return FakeCompleted(rc=0, out=nuclei_jsonl(
                nuclei_hit(template_id="env-file", severity="critical")), err="")

        cms_map = {nw._norm_target(WP_TARGET): "WordPress"}
        with mock.patch.object(nw, "find_tool", return_value=NUCLEI), \
             mock.patch.object(nw.subprocess, "run", side_effect=handler), \
             mock.patch.object(nw, "get_nuclei_version", return_value="v0.0.0-test"):
            res = nw.scan_nuclei(targets=[WP_TARGET, PLAIN_TARGET], cms_map=cms_map)
        self.assertEqual(len(res["metadata"]["runs"]), 2)
        self.assertEqual(res["metadata"]["runs"][0]["rc"], 1)
        self.assertEqual(res["metadata"]["runs"][1]["rc"], 0)
        self.assertEqual(len(res["findings"]), 1)   # second group's finding survived
        self.assertEqual(res["status"], "success")


# --------------------------------------------------------------------------
# (7) CLI / JSON output contract
# --------------------------------------------------------------------------

class TestCLIContract(unittest.TestCase):

    def test_json_output_shape_and_exit_code(self):
        rc, out, _, _ = run_main(["-u", WP_TARGET, "--json", "--quiet"], tools={})
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertIsInstance(payload, dict)
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "nuclei_wrap")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["target"], WP_TARGET)
        for f in payload["findings"]:
            for key in ("type", "severity", "confidence", "target", "evidence",
                        "source", "next_action"):
                self.assertIn(key, f)
            self.assertEqual(f["source"], "nuclei_wrap.py")
            self.assertIsInstance(f["evidence"], list)
        md = payload["metadata"]
        for key in ("nuclei_path", "nuclei_version", "tags_used", "severity_filter",
                    "targets_scanned", "raw_finding_count"):
            self.assertIn(key, md)

    def test_full_shape_with_findings_and_version(self):
        handlers = {"nuclei": lambda a: FakeCompleted(
            rc=0, out=FIXTURE_JSONL.read_text(encoding="utf-8"), err="")}
        rc, out, _, _ = run_main(["-u", WP_TARGET, "--json", "--quiet"],
                                 tools={"nuclei": NUCLEI}, handlers=handlers,
                                 version="v3.11.1")
        payload = json.loads(out)
        md = payload["metadata"]
        self.assertEqual(md["nuclei_path"], NUCLEI)
        self.assertEqual(md["nuclei_version"], "v3.11.1")
        self.assertEqual(md["severity_filter"], DEFAULT_SEV)
        self.assertEqual(md["targets_scanned"], 1)
        self.assertEqual(md["raw_finding_count"], 3)
        self.assertIsNone(md["rate_limit"])      # omitted -> nuclei default
        self.assertEqual(md["totals"]["findings_by_severity"],
                         {"high": 1, "critical": 1, "medium": 1})

    def test_output_file_written(self):
        with tempfile.TemporaryDirectory() as td:
            out_path = str(Path(td) / "nuclei.json")
            rc, _, _, _ = run_main(["-u", WP_TARGET, "--json", "--output", out_path],
                                   tools={})
            self.assertEqual(rc, 0)
            payload = json.loads(Path(out_path).read_text(encoding="utf-8"))
            self.assertEqual(payload["tool"], "nuclei_wrap")

    def test_no_targets_is_hard_error(self):
        with self.assertRaises(SystemExit) as cm:
            run_main(["--json", "--quiet"])
        self.assertEqual(cm.exception.code, 2)

    def test_missing_list_file_is_hard_error_rc2(self):
        rc, _, _, _ = run_main(["-l", "/no/such/list.txt", "--json", "--quiet"])
        self.assertEqual(rc, 2)

    def test_bad_timeout_is_hard_error(self):
        with self.assertRaises(SystemExit) as cm:
            run_main(["-u", WP_TARGET, "--timeout", "0", "--json", "--quiet"])
        self.assertEqual(cm.exception.code, 2)

    def test_bad_rate_limit_is_hard_error(self):
        with self.assertRaises(SystemExit) as cm:
            run_main(["-u", WP_TARGET, "--rate-limit", "0", "--json", "--quiet"])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_tags_override(self):
        handlers = {"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")}
        rc, out, _, ft = run_main(["-u", WP_TARGET, "--tags", "cve", "--json",
                                   "--quiet"], tools={"nuclei": NUCLEI},
                                  handlers=handlers)
        self.assertEqual(rc, 0)
        self.assertEqual(tags_of(ft.calls[0]), "cve")

    def test_list_file_targets_read_and_deduped(self):
        with tempfile.TemporaryDirectory() as td:
            lst = Path(td) / "targets.txt"
            lst.write_text("# comment line\n%s\n\n%s\n%s\n"
                           % (WP_TARGET, PLAIN_TARGET, WP_TARGET), encoding="utf-8")
            handlers = {"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")}
            rc, out, _, ft = run_main(["-l", str(lst), "--json", "--quiet"],
                                      tools={"nuclei": NUCLEI}, handlers=handlers)
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["metadata"]["targets_scanned"], 2)
            self.assertIn("-l", ft.calls[0])
            self.assertEqual(ft.list_file_contents[0],
                             "%s\n%s\n" % (WP_TARGET, PLAIN_TARGET))

    def test_human_mode_progress_and_next_hint(self):
        handlers = {"nuclei": lambda a: FakeCompleted(
            rc=0, out=nuclei_jsonl(nuclei_hit(template_id="git-config", severity="high")),
            err="")}
        rc, out, err, _ = run_main(["-u", WP_TARGET], tools={"nuclei": NUCLEI},
                                   handlers=handlers)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "")        # stdout reserved for --json
        self.assertIn("[*] run:", err)
        self.assertIn("[HIGH]", err)
        self.assertIn("Next:", err)
        self.assertIn("coverage.md", err)

    def test_verbose_progress_on_stderr(self):
        handlers = {"nuclei": lambda a: FakeCompleted(rc=0, out="", err="")}
        rc, out, err, _ = run_main(["-u", WP_TARGET, "--verbose", "--json", "--quiet"],
                                   tools={"nuclei": NUCLEI}, handlers=handlers)
        self.assertEqual(rc, 0)
        self.assertIn("nuclei run 1/1", err)

    def test_no_shell_true_argument_string(self):
        """House subprocess rule: argv list only. Assert the wrapper never builds a
        command string (guards against a future regression to shell=True)."""
        seen = []
        handlers = {"nuclei": lambda a: (seen.append(a), FakeCompleted(rc=0, out="",
                                                                      err=""))[1]}
        run_main(["-u", WP_TARGET, "--json", "--quiet"], tools={"nuclei": NUCLEI},
                 handlers=handlers)
        self.assertEqual(len(seen), 1)
        self.assertIsInstance(seen[0], list)
        self.assertTrue(all(isinstance(x, str) for x in seen[0]))


if __name__ == "__main__":
    unittest.main()
