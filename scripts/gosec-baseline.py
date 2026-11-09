#!/usr/bin/env python3
"""Gate Gosec SARIF findings against the durable reviewed inventory."""

from __future__ import annotations

import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path
import re
import sys


MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
RULE_ID = re.compile(r"G[0-9]{3}")
SOURCE_LINK = re.compile(r"\[([^]\n]+):([0-9]+)\]\([^)]*\)")


class ReportError(ValueError):
    """A Gosec report cannot be compared reliably."""


class InventoryError(ValueError):
    """The reviewed inventory cannot be parsed reliably."""


def cell(value: str, limit: int = 200) -> str:
    """Bound and escape a table cell for logs and GitHub Markdown."""
    value = " ".join("".join(c for c in value if c.isprintable()).split())
    if len(value) > limit:
        value = value[:limit - 1] + "…"
    value = html.escape(value, quote=True)
    return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", value)


def read_report(path: Path) -> tuple[Counter[tuple[str, str, str]], dict[tuple[str, str, str], int]]:
    try:
        with path.open("rb") as report:
            raw = report.read(MAX_REPORT_BYTES + 1)
    except OSError:
        raise ReportError("report is missing or unreadable") from None
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportError("report exceeds the 32 MiB comparison limit")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ReportError("report is not valid JSON") from None
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise ReportError("report is not SARIF 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ReportError("report has no scan runs")

    findings: Counter[tuple[str, str, str]] = Counter()
    first_line: dict[tuple[str, str, str], int] = {}
    for run in runs:
        if not isinstance(run, dict):
            raise ReportError("report contains an invalid scan run")
        tool = run.get("tool", {})
        driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
        if not isinstance(driver, dict) or driver.get("name") != "gosec":
            raise ReportError("report is not from Gosec")
        results = run.get("results")
        if not isinstance(results, list):
            raise ReportError("report is missing its results")
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
                raise ReportError("report contains an invalid finding")
            message = result.get("message", {})
            text = message.get("text") if isinstance(message, dict) else None
            locations = result.get("locations")
            if not isinstance(text, str) or not isinstance(locations, list) or not locations:
                raise ReportError("report finding is missing its message or location")
            physical = locations[0].get("physicalLocation") if isinstance(locations[0], dict) else None
            artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
            region = physical.get("region") if isinstance(physical, dict) else None
            uri = artifact.get("uri") if isinstance(artifact, dict) else None
            if not isinstance(uri, str) or not uri:
                raise ReportError("report finding is missing its source path")
            key = (result["ruleId"], uri, text)
            findings[key] += 1
            line = region.get("startLine") if isinstance(region, dict) else None
            if isinstance(line, int) and line > 0:
                first_line.setdefault(key, line)
    return findings, first_line


def read_inventory(path: Path) -> Counter[tuple[str, str, str]]:
    try:
        with path.open("rb") as inventory:
            raw = inventory.read(MAX_INVENTORY_BYTES + 1)
    except OSError:
        raise InventoryError("inventory is missing or unreadable") from None
    if len(raw) > MAX_INVENTORY_BYTES:
        raise InventoryError("inventory exceeds the 4 MiB comparison limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise InventoryError("inventory is not valid UTF-8") from None

    findings: Counter[tuple[str, str, str]] = Counter()
    for line in text.splitlines():
        if not line.startswith("| G"):
            continue
        fields = [field.strip() for field in line.strip().strip("|").split("|")]
        if len(fields) != 6 or not RULE_ID.fullmatch(fields[0]):
            raise InventoryError("inventory contains a malformed finding row")
        source = SOURCE_LINK.fullmatch(fields[3])
        if not source or not fields[4]:
            raise InventoryError("inventory contains a malformed source or description")
        findings[(fields[0], source.group(1), fields[4])] += 1
    if not findings:
        raise InventoryError("inventory has no findings")
    return findings


def summarize(report: Path, inventory: Path, max_rows: int) -> tuple[str, int]:
    try:
        current, first_line = read_report(report)
        baseline = read_inventory(inventory)
    except (ReportError, InventoryError) as exc:
        return (
            f"### Gosec baseline comparison\n\nBaseline unavailable: {exc}.\n"
            "No clean-scan or regression conclusion is available.\n",
            1,
        )

    new = current - baseline
    missing = baseline - current
    lines = [
        "### Gosec baseline comparison",
        "",
        f"{sum(current.values())} Gosec findings; {sum(baseline.values())} in the inventory; "
        f"{sum(new.values())} new; {sum(missing.values())} not reproduced.",
        "The scanner step is report-only; this comparison fails only on findings absent from the inventory.",
    ]
    if missing:
        lines.extend([
            "",
            "Inventory entries not reproduced were resolved or moved out of the scanned paths. "
            "Update the inventory when those changes are intentional.",
        ])
    if not new:
        return "\n".join(lines) + "\n", 0

    lines.extend([
        "",
        "| Rule | Source | Finding | Count |",
        "| --- | --- | --- | --- |",
    ])
    ordered = sorted(new.items(), key=lambda item: (item[0][0], item[0][1], item[0][2]))
    for (rule, source, text), count in ordered[:max_rows]:
        line = first_line.get((rule, source, text))
        location = f"{source}:{line}" if line else source
        lines.append(f"| {cell(rule, 20)} | {cell(location)} | {cell(text)} | {count} |")
    if len(ordered) > max_rows:
        lines.extend(["", f"{len(ordered) - max_rows} additional rows omitted; see the SARIF artifact."])
    return "\n".join(lines) + "\n", 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--inventory",
        type=Path,
        default=Path("docs/security/GOSEC_2_30_0_FINDINGS.md"),
    )
    parser.add_argument("--max-rows", type=int, default=50)
    args = parser.parse_args()
    if not 1 <= args.max_rows <= 500:
        parser.error("--max-rows must be between 1 and 500")

    summary, status = summarize(args.report, args.inventory, args.max_rows)
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
