#!/usr/bin/env python3
"""Generate benchmark comparison charts from criterion JSON output.

Usage:
    # After running benchmarks locally:
    cargo bench -p ndn-engine
    cargo bench -p ndn-packet
    cargo bench -p ndn-store
    cargo bench -p ndn-face-local
    cargo bench -p ndn-security

    # Generate charts:
    python3 tools/bench-charts/generate.py

Reads criterion output from target/criterion/ and produces SVG charts
in tools/bench-charts/charts/.
"""

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CRITERION_DIR = REPO_ROOT / "target" / "criterion"
CHARTS_DIR = Path(__file__).resolve().parent / "charts"


def find_estimates(base: Path) -> list[dict]:
    """Walk criterion output and collect benchmark estimates."""
    results = []
    for est_file in base.rglob("new/estimates.json"):
        bench_dir = est_file.parent.parent
        # Read the benchmark ID
        bm_file = bench_dir / "benchmark.json"
        if not bm_file.exists():
            continue
        with open(bm_file) as f:
            bm = json.load(f)
        with open(est_file) as f:
            est = json.load(f)

        group = bm.get("group_id", "")
        func = bm.get("function_id", "")
        value = bm.get("value_str", "")
        full_id = bm.get("full_id", f"{group}/{func}")

        median_ns = est.get("median", {}).get("point_estimate", 0)
        mean_ns = est.get("mean", {}).get("point_estimate", 0)

        results.append({
            "id": full_id,
            "group": group,
            "function": func,
            "value": value,
            "median_ns": median_ns,
            "mean_ns": mean_ns,
        })
    return results


def format_time(ns: float) -> str:
    """Format nanoseconds to human-readable string."""
    if ns < 1_000:
        return f"{ns:.0f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.1f} us"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.1f} ms"
    return f"{ns / 1_000_000_000:.2f} s"


def generate_text_report(results: list[dict]) -> str:
    """Generate a plain-text benchmark summary."""
    lines = ["NDN-RS Benchmark Results", "=" * 60, ""]

    # Group by benchmark group
    groups: dict[str, list] = {}
    for r in sorted(results, key=lambda x: x["id"]):
        g = r["group"] or "ungrouped"
        groups.setdefault(g, []).append(r)

    for group_name, items in sorted(groups.items()):
        lines.append(f"  {group_name}")
        lines.append(f"  {'-' * 50}")
        for item in items:
            label = item["function"] or item["value"] or item["id"]
            median = format_time(item["median_ns"])
            lines.append(f"    {label:<35} {median:>12}")
        lines.append("")

    return "\n".join(lines)


def generate_svg_bar_chart(group_name: str, items: list[dict]) -> str:
    """Generate a simple SVG horizontal bar chart for a benchmark group."""
    if not items:
        return ""

    bar_height = 28
    label_width = 260
    max_bar_width = 400
    padding = 10
    height = len(items) * (bar_height + 6) + 60

    max_ns = max(item["median_ns"] for item in items) or 1
    scale = max_bar_width / max_ns

    bars = []
    for i, item in enumerate(items):
        y = 40 + i * (bar_height + 6)
        label = item["function"] or item["value"] or item["id"]
        w = max(1, item["median_ns"] * scale)
        time_str = format_time(item["median_ns"])

        bars.append(
            f'  <text x="{label_width - 8}" y="{y + bar_height // 2 + 4}" '
            f'text-anchor="end" font-size="12" fill="#c9d1d9">{label}</text>'
        )
        bars.append(
            f'  <rect x="{label_width}" y="{y}" width="{w:.1f}" '
            f'height="{bar_height}" rx="3" fill="#58a6ff" opacity="0.8"/>'
        )
        bars.append(
            f'  <text x="{label_width + w + 6}" y="{y + bar_height // 2 + 4}" '
            f'font-size="11" fill="#8b949e">{time_str}</text>'
        )

    width = label_width + max_bar_width + 120
    bars_str = "\n".join(bars)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"
     viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#0d1117" rx="8"/>
  <text x="{padding}" y="24" font-size="14" font-weight="bold" fill="#e6edf3">
    {group_name}
  </text>
{bars_str}
</svg>"""


def main():
    if not CRITERION_DIR.exists():
        print(f"No criterion output at {CRITERION_DIR}")
        print("Run: cargo bench  (then re-run this script)")
        sys.exit(1)

    results = find_estimates(CRITERION_DIR)
    if not results:
        print("No benchmark results found in criterion output.")
        sys.exit(1)

    # Text report
    report = generate_text_report(results)
    print(report)

    # SVG charts per group
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)

    groups: dict[str, list] = {}
    for r in sorted(results, key=lambda x: x["id"]):
        g = r["group"] or "ungrouped"
        groups.setdefault(g, []).append(r)

    for group_name, items in groups.items():
        svg = generate_svg_bar_chart(group_name, items)
        if svg:
            safe_name = group_name.replace("/", "_").replace(" ", "_")
            path = CHARTS_DIR / f"{safe_name}.svg"
            path.write_text(svg)
            print(f"  Chart: {path}")

    # Save JSON for historical tracking
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = results_dir / f"bench-{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved: {json_path}")


if __name__ == "__main__":
    main()
