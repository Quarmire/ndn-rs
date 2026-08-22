#!/usr/bin/env python3
"""CI gate: every `crates/...` path referenced by a docs/wiki page must exist
in this repo. Sibling-repo references are exempt only when written with the
repo prefix (e.g. `ndn-ext/crates/faces/ndn-face-shm`), which the regex skips
via the lookbehind. Run from the repo root: python3 tools/check_wiki_paths.py"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# A bare `crates/...` path: not preceded by a repo-name character or `/`.
PAT = re.compile(r"(?<![\w/-])crates/[A-Za-z0-9_.{},*/-]+")

bad = []
for page in sorted((ROOT / "docs" / "wiki").rglob("*.md")):
    for lineno, line in enumerate(page.read_text().splitlines(), 1):
        for match in PAT.finditer(line):
            path = match.group(0).rstrip(".,;:")
            # `{a,b}` / `*` shorthands: check the literal prefix directory.
            path = re.split(r"[{*]", path)[0]
            # `file.rs:56` line anchors.
            path = re.sub(r":\d+$", "", path).rstrip("/")
            if not (ROOT / path).exists():
                bad.append(f"{page.relative_to(ROOT)}:{lineno}: {match.group(0)}")

if bad:
    print("wiki pages reference crates/ paths that do not exist in this repo:")
    print("\n".join(bad))
    sys.exit(1)
print("check_wiki_paths: all referenced crates/ paths exist")
