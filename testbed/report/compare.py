#!/usr/bin/env python3
"""
compare.py — Parse testbed benchmark results and emit a wiki-ready markdown table.

Usage:
    python3 compare.py /results/bench-*.md  > wiki-bench.md
    python3 compare.py /results/compliance-*.txt  > wiki-compliance.md
"""

import sys
import re
from pathlib import Path
from collections import defaultdict


def parse_bench_table(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        m = re.match(r"\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|", line)
        if m and m.group(1).strip() not in ("Forwarder", "-"):
            rows.append({
                "fwd":     m.group(1).strip(),
                "transport": m.group(2).strip(),
                "metric":  m.group(3).strip(),
                "value":   m.group(4).strip(),
            })
    return rows


def parse_compliance(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        m = re.search(r"\[([\w-]+)\]\s+(PASS|FAIL):\s+(\S+)", line)
        if m:
            rows.append({
                "fwd":    m.group(1),
                "result": m.group(2),
                "test":   m.group(3),
            })
    return rows


def emit_bench_summary(all_rows: list[dict]) -> str:
    # Group by metric → fwd → value
    by_metric: dict[str, dict[str, str]] = defaultdict(dict)
    for r in all_rows:
        key = f"{r['metric']} ({r['transport']})"
        by_metric[key][r["fwd"]] = r["value"]

    fwds = sorted({r["fwd"] for r in all_rows})
    lines = [
        "## Forwarder Benchmarks",
        "",
        "| Metric | " + " | ".join(fwds) + " |",
        "|--------|" + "|".join(["--------"] * len(fwds)) + "|",
    ]
    for metric, fwd_vals in sorted(by_metric.items()):
        row = f"| {metric} |"
        for fwd in fwds:
            row += f" {fwd_vals.get(fwd, 'n/a')} |"
        lines.append(row)
    lines += [
        "",
        "> **Note:** `shm` transport is only available for ndn-fwd (in-process SHM face).",
        "> `udp` numbers reflect socket overhead and are comparable across all forwarders.",
        "",
    ]
    return "\n".join(lines)


def emit_compliance_summary(all_rows: list[dict]) -> str:
    # Group by test → fwd → result
    by_test: dict[str, dict[str, str]] = defaultdict(dict)
    for r in all_rows:
        by_test[r["test"]][r["fwd"]] = "✓" if r["result"] == "PASS" else "✗"

    fwds = sorted({r["fwd"] for r in all_rows})
    lines = [
        "## Protocol Compliance",
        "",
        "| Test | " + " | ".join(fwds) + " |",
        "|------|" + "|".join(["------"] * len(fwds)) + "|",
    ]
    for test, fwd_results in sorted(by_test.items()):
        row = f"| {test} |"
        for fwd in fwds:
            row += f" {fwd_results.get(fwd, '?')} |"
        lines.append(row)
    lines.append("")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    bench_rows = []
    compliance_rows = []

    for path_str in sys.argv[1:]:
        for path in sorted(Path(".").glob(path_str)) or [Path(path_str)]:
            text = path.read_text(errors="replace")
            if "throughput" in path.name or "bench" in path.name:
                bench_rows.extend(parse_bench_table(text))
            elif "compliance" in path.name:
                compliance_rows.extend(parse_compliance(text))

    if compliance_rows:
        print(emit_compliance_summary(compliance_rows))
    if bench_rows:
        print(emit_bench_summary(bench_rows))


if __name__ == "__main__":
    main()
