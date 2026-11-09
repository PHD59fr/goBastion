#!/usr/bin/env python3
"""Summarize the pinned Grype SARIF format without dumping report payloads."""

from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import re
import sys


MAX_REPORT_BYTES = 32 * 1024 * 1024
SEVERITIES = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Grype v0.121.2: grype/presenter/sarif/presenter.go helpText/resultMessage.
# SARIF levels merge high/critical; security-severity may use a different CVSS
# source. The help text preserves the severity used by Grype's finding gate.
HELP_FIELDS = re.compile(
    r"\AVulnerability ([^\n]+)\nSeverity: ([^\n]+)\nPackage: ([^\n]+)"
    r"\nVersion: [^\n]*\nFix Version: ([^\n]*)\nType: "
)


class ReportError(ValueError):
    """A report cannot be summarized reliably."""


def cell(value: str, limit: int = 160) -> str:
    """Bound and escape a table cell for both logs and GitHub Markdown."""
    value = " ".join("".join(c for c in value if c.isprintable()).split())
    if len(value) > limit:
        value = value[:limit - 1] + "…"
    value = html.escape(value, quote=True)
    return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", value)


def read_findings(path: Path) -> tuple[int, list[tuple[str, ...]]]:
    try:
        with path.open("rb") as report:
            raw = report.read(MAX_REPORT_BYTES + 1)
    except OSError:
        raise ReportError("report is missing or unreadable") from None
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportError("report exceeds the 32 MiB summary limit")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ReportError("report is not valid JSON") from None
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise ReportError("report is not SARIF 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ReportError("report has no scan runs")

    findings = set()
    total = 0
    for run in runs:
        if not isinstance(run, dict):
            raise ReportError("report contains an invalid scan run")
        tool = run.get("tool", {})
        driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
        if not isinstance(driver, dict) or driver.get("name") != "grype":
            raise ReportError("report is not from Grype")
        results, rules = run.get("results"), driver.get("rules", [])
        if not isinstance(results, list) or not isinstance(rules, list):
            raise ReportError("report is missing its results or rules")
        by_id = {}
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                raise ReportError("report contains an invalid rule")
            if rule["id"] in by_id:
                raise ReportError("report contains duplicate rule IDs")
            by_id[rule["id"]] = rule
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
                raise ReportError("report contains an invalid finding")
            rule = by_id.get(result["ruleId"], {})
            help_text = rule.get("help", {})
            text = help_text.get("text") if isinstance(help_text, dict) else None
            fields = HELP_FIELDS.match(text) if isinstance(text, str) else None
            if not fields:
                raise ReportError("finding fields do not match the pinned Grype format")
            vulnerability, severity, package, fixed = fields.groups()
            if (severity not in SEVERITIES or not package.strip()
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,159}", vulnerability)):
                raise ReportError("finding identity or severity is invalid")
            message = result.get("message", {})
            text = message.get("text") if isinstance(message, dict) else None
            # Rules are shared by CVE/package, including across installed versions.
            # Extract only the version from the fixed message prefix, never paths.
            prefix = re.escape(f"A {severity} vulnerability in ")
            package_prefix = re.escape(f" package: {package}, version ")
            version = re.match(
                prefix + r"[A-Za-z0-9_.+-]+" + package_prefix
                + r"([^\n]+?) was found(?: |$)", text
            ) if isinstance(text, str) else None
            if not version:
                raise ReportError("finding version does not match the pinned Grype format")
            findings.add((vulnerability, package, version.group(1), severity, fixed))
            total += 1
    return total, sorted(findings, key=lambda row: (SEVERITIES[row[3]], row))


def summarize(path: Path, title: str, max_rows: int) -> tuple[str, int]:
    heading = f"### {cell(title, 120)}\n\n"
    try:
        total, findings = read_findings(path)
    except ReportError as exc:
        return heading + f"Summary unavailable: {exc}. No clean-scan conclusion is available.\n", 1
    lines = [heading + f"{total} vulnerability matches; {len(findings)} distinct rows.",
             "The scanner step determines pass/fail; this summary only lists report findings.", ""]
    if findings:
        lines.extend(["| Vulnerability | Package | Installed version | Severity | Fixed version (rule) |",
                      "| --- | --- | --- | --- | --- |"])
        for vulnerability, package, version, severity, fixed in findings[:max_rows]:
            lines.append("| " + " | ".join(cell(value) for value in
                         (vulnerability, package, version, severity, fixed or "not reported")) + " |")
        if len(findings) > max_rows:
            lines.extend(["", f"{len(findings) - max_rows} additional rows omitted; see the SARIF artifact."])
    return "\n".join(lines) + "\n", 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--title", required=True)
    parser.add_argument("--max-rows", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.max_rows <= 500:
        parser.error("--max-rows must be between 1 and 500")
    summary, status = summarize(args.report, args.title, args.max_rows)
    print(summary, end="")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as output:
                output.write(summary + "\n")
        except OSError:
            print("Could not write the GitHub step summary.", file=sys.stderr)
            return 1
    return status


if __name__ == "__main__":
    sys.exit(main())
