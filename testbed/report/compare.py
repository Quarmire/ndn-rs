#!/usr/bin/env python3
"""
compare.py — Parse testbed benchmark results and emit a wiki-ready markdown table.

Usage:
    python3 compare.py /results/bench-*.md  > wiki-bench.md
    python3 compare.py /results/compliance-*.txt  > wiki-compliance.md
    python3 compare.py /results/interop-*.txt  > wiki-interop.md
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


def parse_interop(text: str) -> dict:
    """Parse interop-TIMESTAMP.txt produced by run_all.sh."""
    timestamp = ""
    results = []
    section = ""
    for line in text.splitlines():
        m = re.match(r"# NDN Interoperability Test Results — (\S+)", line)
        if m:
            timestamp = m.group(1)
            continue
        m = re.match(r"## (.+)", line)
        if m:
            section = m.group(1).strip()
            continue
        # [scenario] PASS/FAIL/SKIP: description  (optional error context)
        m = re.match(r"\[([^\]]+)\] (PASS|FAIL|SKIP): (.+?)(?:  \((.+)\))?$", line)
        if m:
            results.append({
                "scenario": m.group(1),
                "result":   m.group(2),
                "desc":     m.group(3).strip(),
                "section":  section,
                "error":    (m.group(4) or "").strip(),
            })
    summary_m = re.search(r"Results: (\d+) passed, (\d+) failed, (\d+) skipped", text)
    return {
        "timestamp": timestamp,
        "results":   results,
        "passed":    summary_m.group(1) if summary_m else "?",
        "failed":    summary_m.group(2) if summary_m else "?",
        "skipped":   summary_m.group(3) if summary_m else "?",
    }


def emit_interop_page(data: dict) -> str:
    ts      = data["timestamp"]
    passed  = data["passed"]
    failed  = data["failed"]
    skipped = data["skipped"]

    icon_map = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}

    lines = [
        "# Interoperability Test Results",
        "",
        "This page is automatically updated by the",
        "[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)",
        "on every push to `main` and weekly on Mondays.",
        "",
        "The test matrix exercises ndn-rs against ndn-cxx, NDNts, NFD, and yanfd in both",
        "consumer and producer roles. See [Interoperability Testing](../deep-dive/interop-testing.md)",
        "for the full scenario descriptions and the compatibility challenges resolved along the way.",
        "",
        "<!-- The section below is machine-generated. Do not edit manually. -->",
        "",
        f"*Last run: `{ts}` &nbsp;·&nbsp; "
        f"{passed} passed, {failed} failed, {skipped} skipped*",
        "",
        "| Scenario | Result | Description |",
        "|----------|:------:|-------------|",
    ]

    prev_section = ""
    for r in data["results"]:
        if r["section"] != prev_section:
            # Emit a section separator row.
            lines.append(f"| **{r['section']}** | | |")
            prev_section = r["section"]
        icon = icon_map.get(r["result"], "?")
        error_note = f"<br><small>`{r['error']}`</small>" if r["error"] else ""
        lines.append(
            f"| `{r['scenario']}` | {icon} {r['result']} | {r['desc']}{error_note} |"
        )

    lines.append("")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    bench_rows = []
    compliance_rows = []
    interop_datasets = []

    for path_str in sys.argv[1:]:
        for path in sorted(Path(".").glob(path_str)) or [Path(path_str)]:
            text = path.read_text(errors="replace")
            if "interop" in path.name:
                interop_datasets.append(parse_interop(text))
            elif "throughput" in path.name or "bench" in path.name:
                bench_rows.extend(parse_bench_table(text))
            elif "compliance" in path.name:
                compliance_rows.extend(parse_compliance(text))

    if interop_datasets:
        # Use the most recent run (last by timestamp).
        latest = max(interop_datasets, key=lambda d: d["timestamp"])
        print(emit_interop_page(latest))
    if compliance_rows:
        print(emit_compliance_summary(compliance_rows))
    if bench_rows:
        print(emit_bench_summary(bench_rows))


if __name__ == "__main__":
    main()
