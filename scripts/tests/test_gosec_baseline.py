"""Regression coverage for the Gosec inventory baseline gate."""

import copy
import importlib.util
import json
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
        self.inventory.write_text(
            "# Findings\n\n| Rule | Severity | Confidence | Source | Description | Status |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            + inventory_row() + "\n",
            encoding="utf-8",
        )

    def write_report(self, document):
        self.report.write_text(json.dumps(document), encoding="utf-8")

    def test_matching_inventory_passes(self):
        self.write_report(report(finding()))
        text, status = BASELINE.summarize(self.report, self.inventory, 50)
        self.assertEqual(status, 0)
        self.assertIn("1 Gosec findings; 1 in the inventory; 0 new", text)
        self.assertIn("report-only", text)

    def test_new_finding_fails_without_printing_source_snippet(self):
        self.write_report(report(finding(), finding(rule="G304", path="internal/other.go",
                                                    text="Potential file inclusion via variable", line=20)))
        text, status = BASELINE.summarize(self.report, self.inventory, 50)
        self.assertEqual(status, 1)
        self.assertIn("| G304 | internal/other.go:20 | Potential file inclusion via variable | 1 |", text)
        self.assertNotIn("private source payload", text)

    def test_duplicate_occurrence_is_a_regression(self):
        self.write_report(report(finding(), finding(line=20)))
        text, status = BASELINE.summarize(self.report, self.inventory, 50)
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
        text, status = BASELINE.summarize(self.report, self.inventory, 50)
        self.assertEqual(status, 0)
        self.assertIn("1 not reproduced", text)

    def test_missing_or_malformed_report_fails_closed(self):
        for raw in (None, "{private secret", '{"version":"2.1.0","runs":[]}'):
            with self.subTest(raw=raw):
                if raw is None:
                    self.report.unlink(missing_ok=True)
                else:
                    self.report.write_text(raw, encoding="utf-8")
                text, status = BASELINE.summarize(self.report, self.inventory, 50)
                self.assertEqual(status, 1)
                self.assertIn("Baseline unavailable", text)
                self.assertIn("No clean-scan or regression conclusion", text)
                self.assertNotIn("private secret", text)

    def test_malformed_inventory_fails_closed(self):
        self.inventory.write_text("| G115 | not-a-table-row |\n", encoding="utf-8")
        self.write_report(report(finding()))
        text, status = BASELINE.summarize(self.report, self.inventory, 50)
        self.assertEqual(status, 1)
        self.assertIn("inventory contains a malformed", text)

    def test_unknown_rule_or_missing_location_fails_closed(self):
        broken = copy.deepcopy(report(finding()))
        broken["runs"][0]["results"][0].pop("locations")
        self.write_report(broken)
        text, status = BASELINE.summarize(self.report, self.inventory, 50)
        self.assertEqual(status, 1)
        self.assertIn("missing its message or location", text)


if __name__ == "__main__":
    unittest.main()
