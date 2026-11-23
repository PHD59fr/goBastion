"""Regression coverage for the Gosec inventory baseline gate."""

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "gosec-baseline.py"
SPEC = importlib.util.spec_from_file_location("gosec_baseline", SCRIPT)
BASELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASELINE)


def finding(rule="G115", path="internal/example.go", text="integer overflow conversion int -> uint32", line=10):
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": text},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": line, "snippet": {"text": "private source payload"}},
            },
        }],
    }


def report(*findings):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gosec"}},
            "results": list(findings),
        }],
    }


def inventory_row(rule="G115", path="internal/example.go",
                  text="integer overflow conversion int -> uint32", line=10):
    return f"| {rule} | HIGH | MEDIUM | [{path}:{line}](../../{path}#L{line}) | {text} | Pending individual review |"


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.report = self.directory / "gosec.sarif"
        self.inventory = self.directory / "inventory.md"
        self.scan_report = self.directory / "gosec.json"
        self.exit_code = 1
        self.inventory.write_text(
            "# Findings\n\n| Rule | Severity | Confidence | Source | Description | Status |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            + inventory_row() + "\n",
            encoding="utf-8",
        )

    def write_report(self, document):
        self.report.write_text(json.dumps(document), encoding="utf-8")
        count = sum(len(run.get("results", [])) for run in document.get("runs", []))
        self.exit_code = int(count > 0)
        self.scan_report.write_text(json.dumps({
            "GosecVersion": "2.30.0", "Golang errors": {},
            "Stats": {"files": 2, "lines": 100, "found": count},
            "Issues": [{} for _ in range(count)],
        }), encoding="utf-8")

    def summarize(self):
        return BASELINE.summarize(self.report, self.inventory, 50,
                                  self.scan_report, self.exit_code)

    def test_matching_inventory_passes(self):
        self.write_report(report(finding()))
        text, status = self.summarize()
        self.assertEqual(status, 0)
        self.assertIn("1 Gosec findings; 1 in the inventory; 0 new", text)
        self.assertIn("report-only", text)

    def test_new_finding_fails_without_printing_source_snippet(self):
        self.write_report(report(finding(), finding(rule="G304", path="internal/other.go",
                                                    text="Potential file inclusion via variable", line=20)))
        text, status = self.summarize()
        self.assertEqual(status, 1)
        self.assertIn("| G304 | internal/other.go:20 | Potential file inclusion via variable | 1 |", text)
        self.assertNotIn("private source payload", text)

    def test_duplicate_occurrence_is_a_regression(self):
        self.write_report(report(finding(), finding(line=20)))
        text, status = self.summarize()
        self.assertEqual(status, 1)
        self.assertIn("2 Gosec findings; 1 in the inventory; 1 new", text)

    def test_missing_inventory_entry_is_reported_but_not_a_regression(self):
        self.inventory.write_text(
            "# Findings\n\n| Rule | Severity | Confidence | Source | Description | Status |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            + inventory_row() + "\n"
            + inventory_row(rule="G101", path="internal/old.go",
                            text="Potential hardcoded credentials") + "\n",
            encoding="utf-8",
        )
        self.write_report(report(finding()))
        text, status = self.summarize()
        self.assertEqual(status, 0)
        self.assertIn("1 not reproduced", text)

    def test_missing_or_malformed_report_fails_closed(self):
        for raw in (None, "{private secret", '{"version":"2.1.0","runs":[]}'):
            with self.subTest(raw=raw):
                if raw is None:
                    self.report.unlink(missing_ok=True)
                else:
                    self.report.write_text(raw, encoding="utf-8")
                text, status = self.summarize()
                self.assertEqual(status, 1)
                self.assertIn("Baseline unavailable", text)
                self.assertIn("No clean-scan or regression conclusion", text)
                self.assertNotIn("private secret", text)

    def test_malformed_inventory_fails_closed(self):
        self.inventory.write_text("| G115 | not-a-table-row |\n", encoding="utf-8")
        self.write_report(report(finding()))
        text, status = self.summarize()
        self.assertEqual(status, 1)
        self.assertIn("inventory contains a malformed", text)

    def test_unknown_rule_or_missing_location_fails_closed(self):
        broken = copy.deepcopy(report(finding()))
        broken["runs"][0]["results"][0].pop("locations")
        self.write_report(broken)
        text, status = self.summarize()
        self.assertEqual(status, 1)
        self.assertIn("missing its message or location", text)

    def test_unsuccessful_sarif_invocation_fails_even_with_no_findings(self):
        for invocations in (
            [{"executionSuccessful": False}], [], None,
            [{"executionSuccessful": True}, {"executionSuccessful": False}],
            [{"executionSuccessful": True, "toolExecutionNotifications": [
                {"level": "error", "message": {"text": "private diagnostic"}},
            ]}],
            [{"executionSuccessful": True, "toolConfigurationNotifications": [
                {"level": "error"},
            ]}],
        ):
            with self.subTest(invocations=invocations):
                document = report()
                document["runs"][0]["invocations"] = invocations
                self.write_report(document)
                text, status = self.summarize()
                self.assertEqual(status, 1)
                self.assertNotIn("private diagnostic", text)

    def test_native_scan_errors_and_incomplete_reports_fail_closed(self):
        self.write_report(report(finding()))
        valid = json.loads(self.scan_report.read_text())
        invalid = [
            None, "not json", [], {},
            {**valid, "Golang errors": {"private/path": [{"error": "private diagnostic"}]}},
            {**valid, "Golang errors": None},
            {**valid, "GosecVersion": "2.29.0"},
            {**valid, "Stats": {"files": 0, "lines": 0, "found": 1}},
            {**valid, "Stats": {"files": True, "lines": 100, "found": 1}},
            {**valid, "Stats": {"files": 2, "lines": 100, "found": 0}},
            {**valid, "Issues": []},
            {**valid, "Issues": [None]},
        ]
        for document in invalid:
            with self.subTest(document=document):
                if document is None:
                    self.scan_report.unlink(missing_ok=True)
                else:
                    self.scan_report.write_text(json.dumps(document))
                text, status = self.summarize()
                self.assertEqual(status, 1)
                self.assertIn("Baseline unavailable", text)
                self.assertNotIn("private diagnostic", text)
                self.assertNotIn("private/path", text)

    def test_scanner_exit_status_must_match_findings(self):
        for findings, exit_code in (((), 1), ((), 2), ((), 137), ((finding(),), 0), ((finding(),), 2)):
            with self.subTest(findings=findings, exit_code=exit_code):
                self.write_report(report(*findings))
                self.exit_code = exit_code
                self.assertEqual(self.summarize()[1], 1)

    def test_successful_empty_scan_can_report_resolved_findings(self):
        self.write_report(report())
        document = json.loads(self.report.read_text())
        document["runs"][0]["invocations"] = [{"executionSuccessful": True}]
        self.report.write_text(json.dumps(document))
        text, status = self.summarize()
        self.assertEqual(status, 0)
        self.assertIn("1 not reproduced", text)

    def test_cli_requires_native_report_and_scanner_status(self):
        self.write_report(report(finding()))
        base = [sys.executable, str(SCRIPT), str(self.report), "--inventory", str(self.inventory)]
        for extra in ([], ["--scan-report", str(self.scan_report)], ["--scanner-exit-code", "1"]):
            with self.subTest(extra=extra):
                result = subprocess.run(base + extra, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
        for exit_code, expected in ((1, 0), (2, 1)):
            result = subprocess.run(base + ["--scan-report", str(self.scan_report),
                                           "--scanner-exit-code", str(exit_code)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
