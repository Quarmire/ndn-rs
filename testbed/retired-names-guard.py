#!/usr/bin/env python3
"""Retired-names guard for the ndn-rs tree.

The signal API (ndn-surface, `Node::signal_*`, the `32=signal` name keyword, the
`ndn-signal/` signature context) was replaced by the channel and deleted. This
fails if one of those names reappears in a tracked file, so a revert or a
careless merge cannot bring a retired surface back unnoticed.

`docs/specs/history/` is exempt: superseded specs keep their old text on
purpose. This script is exempt because it names the patterns.

    python3 testbed/retired-names-guard.py

Stdlib-only; run from anywhere inside the repo; exits non-zero on any hit.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

RETIRED = re.compile(rb"ndn_surface|signal_scope|ndn-signal/|32=signal")
EXEMPT_PREFIX = "docs/specs/history/"
SELF = "testbed/retired-names-guard.py"


def main() -> int:
    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path(__file__).resolve().parent,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
    ).stdout.split(b"\0")
    hits: list[str] = []
    for raw in tracked:
        if not raw:
            continue
        rel = raw.decode()
        if rel.startswith(EXEMPT_PREFIX) or rel == SELF:
            continue
        path = root / rel
        if not path.is_file():
            continue
        for lineno, line in enumerate(path.read_bytes().splitlines(), 1):
            if RETIRED.search(line):
                hits.append(f"{rel}:{lineno}: {line.decode(errors='replace').strip()[:100]}")
    if hits:
        print("retired-names-guard: a retired signal name is back:")
        for h in hits:
            print(f"  {h}")
        print(
            "The signal API was replaced by the channel (docs/specs/channel.md); "
            "use Heap::get/emit there. Superseded text belongs under docs/specs/history/."
        )
        return 1
    print("retired-names-guard: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
