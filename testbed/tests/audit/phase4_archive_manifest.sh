#!/usr/bin/env bash
# Witness — Phase 4 §4.1 archive manifest integrity.
#
# Finding:   .claude/wiki-archive-pre-v0.1.0/ARCHIVE_MANIFEST.md
#            must exist and must list every archived .md (no orphan
#            files; no manifest entries pointing at non-existent
#            archive paths).
# Witness:   GREP-PROOF — for each *.md under the archive (except
#            ARCHIVE_MANIFEST.md itself), the manifest contains a
#            row whose path field matches. And for each path
#            field in the manifest, the file exists.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL (orphan archive or orphan manifest row)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

ARCHIVE_DIR=".claude/wiki-archive-pre-v0.1.0"
MANIFEST="$ARCHIVE_DIR/ARCHIVE_MANIFEST.md"

if [ ! -f "$MANIFEST" ]; then
    echo "FAIL: $MANIFEST does not exist" >&2
    exit 1
fi

fail=0

# Each archived md file must appear in a manifest table row.
while IFS= read -r f; do
    rel=${f#$ARCHIVE_DIR/}
    if ! grep -qF "\`$rel\`" "$MANIFEST"; then
        echo "FAIL: archived file not listed in manifest: $rel" >&2
        fail=1
    fi
done < <(find "$ARCHIVE_DIR" -type f -name '*.md' ! -name 'ARCHIVE_MANIFEST.md' | sort)

# Each manifest row path must exist under the archive.
while IFS= read -r path; do
    if [ ! -f "$ARCHIVE_DIR/$path" ]; then
        echo "FAIL: manifest row references missing file: $path" >&2
        fail=1
    fi
done < <(grep -oE '^\| `[^`]+\.md`' "$MANIFEST" | sed -E 's/^\| `//' | sed -E 's/`$//')

if [ "$fail" -eq 0 ]; then
    echo "PASS"
fi
exit "$fail"
