"""Regression coverage for the pinned Grype SARIF summary and its CLI."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "security-scan-summary.py"
SPEC = importlib.util.spec_from_file_location("security_scan_summary", SCRIPT)
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


def report(versions=("1.0",), severity="high", fixed="2.0", package="libexample"):
    vulnerability = "CVE-2026-12345"
    rule_id = f"{vulnerability}-{package}"
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "grype", "rules": [{
                "id": rule_id,
                "properties": {"security-severity": "4.0"},
                "help": {"text": (
                    f"Vulnerability {vulnerability}\nSeverity: {severity}\n"
                    f"Package: {package}\nVersion: {versions[0]}\nFix Version: {fixed}\n"
                    "Type: deb\nLocation: private/location\nData Namespace: example\n"
                    "Link: https://example.invalid/private"
                )},
            }]}},
            "results": [{
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": (
                    f"A {severity} vulnerability in deb package: {package}, version {version} "
                    "was found from SBOM file private/location"
                )},
            } for version in versions],
        }],
    }


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / "report.sarif"

    def write(self, document):
        self.path.write_text(json.dumps(document), encoding="utf-8")

    def test_versions_are_per_result_and_severity_uses_grype_not_cvss(self):
        self.write(report(("1.0", "1.1", "1.0")))
        text, status = SUMMARY.summarize(self.path, "Image scan", 100)
        self.assertEqual(status, 0)
        self.assertIn("3 vulnerability matches; 2 distinct rows", text)
        self.assertIn("| CVE-2026-12345 | libexample | 1.0 | high | 2.0 |", text)
        self.assertIn("| CVE-2026-12345 | libexample | 1.1 | high | 2.0 |", text)
        self.assertNotIn("private", text)

    def test_no_fix_is_explicit_and_output_is_bounded(self):
        self.write(report(("1.0", "1.1", "1.2"), fixed=""))
        text, status = SUMMARY.summarize(self.path, "Image scan", 1)
        self.assertEqual(status, 0)
        self.assertIn("| high | not reported |", text)
        self.assertIn("2 additional rows omitted", text)
        self.assertNotIn("| 1.1 |", text)

    def test_table_cells_escape_markdown_html_and_controls(self):
        self.write(report(package="lib|[example]<img>", fixed="x" * 500))
        text, status = SUMMARY.summarize(self.path, "Scan\n::error::bad\x1b", 100)
        self.assertEqual(status, 0)
        self.assertIn(r"lib\|\[example\]&lt;img&gt;", text)
        self.assertNotIn("<img>", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\n::error", text)
        self.assertNotIn("x" * 160, text)

    def test_missing_and_malformed_reports_are_not_reported_as_clean(self):
        for raw in (None, "{private secret", '{"version":"2.1.0","runs":[]}'):
            with self.subTest(raw=raw):
                if raw is not None:
                    self.path.write_text(raw, encoding="utf-8")
                text, status = SUMMARY.summarize(self.path, "Scan", 100)
                self.assertEqual(status, 1)
                self.assertIn("Summary unavailable", text)
                self.assertIn("No clean-scan conclusion", text)
                self.assertNotIn("0 vulnerability matches", text)
                self.assertNotIn("private secret", text)

    def test_unknown_schema_or_missing_fields_fail_explicitly(self):
        original = report()
        cases = []
        for field in ("tool", "results"):
            altered = copy.deepcopy(original)
            del altered["runs"][0][field]
            cases.append(altered)
        altered = copy.deepcopy(original)
        altered["runs"][0]["results"][0]["ruleId"] = "missing"
        cases.append(altered)
        altered = copy.deepcopy(original)
        altered["runs"][0]["results"][0]["message"]["text"] = "private payload"
        cases.append(altered)
        altered = copy.deepcopy(original)
        altered["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"] = "private payload"
        cases.append(altered)
        altered = copy.deepcopy(original)
        altered["runs"][0]["tool"]["driver"]["rules"] = [None]
        cases.append(altered)
        for document in cases:
            with self.subTest(document=document):
                self.write(document)
                text, status = SUMMARY.summarize(self.path, "Scan", 100)
                self.assertEqual(status, 1)
                self.assertNotIn("private payload", text)
                self.assertNotIn("0 vulnerability matches", text)

    def test_valid_empty_report_does_not_claim_scanner_success(self):
        document = report()
        document["runs"][0]["results"] = []
        document["runs"][0]["tool"]["driver"].pop("rules")
        self.write(document)
        text, status = SUMMARY.summarize(self.path, "Dependencies", 100)
        self.assertEqual(status, 0)
        self.assertIn("0 vulnerability matches", text)
        self.assertIn("scanner step determines pass/fail", text)
        self.assertNotIn("passed", text)

    def test_report_size_limit(self):
        self.write(report())
        with patch.object(SUMMARY, "MAX_REPORT_BYTES", 16):
            text, status = SUMMARY.summarize(self.path, "Scan", 100)
        self.assertEqual(status, 1)
        self.assertIn("summary limit", text)

    def test_cli_writes_stdout_and_appends_github_summary_on_failure(self):
        summary_path = self.directory / "summary.md"
        summary_path.write_text("Existing summary\n", encoding="utf-8")
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary_path))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.path), "--title", "Image scan"],
            env=env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertIn("Summary unavailable", result.stdout)
        self.assertEqual(summary_path.read_text(encoding="utf-8"),
                         "Existing summary\n" + result.stdout + "\n")

    def test_cli_rejects_unbounded_row_limit(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.path), "--title", "Scan", "--max-rows", "1000000"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("between 1 and 500", result.stderr)


if __name__ == "__main__":
    unittest.main()
