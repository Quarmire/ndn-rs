#!/usr/bin/env python3
"""Dependency-direction guard for the ndn-rs workspace.

Enforces the architectural invariant that the **spec** crate set — the pure
library we tag as `ndn-rs` — is *closed under dependency*: a crate classified
`spec` may only depend (at runtime) on other `spec` crates. Extension / research
/ tooling / draft crates are downstream consumers and may depend on anything.

This is what keeps "ndn-rs is a pure library" true over time: it catches a
`spec` crate reaching "up" into an extension/binding/app crate (or into an
unclassified one) the moment the edge is added — exactly the drift that let
`ndn-engine -> ndn-signal-sources` and `ndn-mgmt -> ndn-config` slip in.

Classification lives in each crate's `[package.metadata.scope] classification`.
Only runtime `[dependencies]` (incl. target-specific) are checked; dev/build deps
are exempt (tests may reach downstream). Stdlib-only, any Python 3; run from
anywhere; exits non-zero on any violation.

    python3 testbed/dep-direction-guard.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SPEC = "spec"

# Known-pending violations: edges that are real and slated for a refactor but not
# yet cut. Reported as PENDING (exit 0) so CI stays usable; a NEW violation not in
# this set fails the build, and an entry here that is no longer a violation also
# fails (keep the list honest — shrink it as refactors land). `"crate -> dep"`.
ALLOWLIST: dict[str, str] = {
    # F-config-split-up RESIDUAL (b2): the NFD management-WIRE codecs moved out of
    # ndn-config into ndn-mgmt-wire (spec), so ndn-ipc / ndn-routing now dep only
    # the wire crate and ndn-mgmt's wire usages do too. The one edge left is
    # ndn-mgmt -> ndn-config for the *forwarder TOML* (`ForwarderConfig`,
    # `parse_cert_sha256_hex`) that the mgmt command handlers read — an extension
    # config tail, not a wire format. Cut by abstracting the config read behind a
    # spec-side trait (or moving those handlers to the forwarder binary) before the
    # split.
    "ndn-mgmt -> ndn-config": "F-config-split-up residual (b2): ForwarderConfig read in mgmt handlers",
}


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for p in (here, *here.parents):
        if (p / "Cargo.toml").exists() and (p / "crates").is_dir():
            return p
    sys.exit("dep-direction-guard: could not locate the workspace root")


def parse_manifest(
    text: str,
) -> tuple[str | None, str | None, list[tuple[str, bool]]]:
    """Return (package name, scope classification, [(dep, optional), ...]).

    A focused parser for the workspace's Cargo.toml dialect — no TOML lib, so it
    runs on any Python. Tracks `[section]` headers; collects keys from any
    `*dependencies` table except dev-/build-; reads `name`/`classification` by key.
    A dep is `optional` if its inline table sets `optional = true` (it then only
    enters the build via a non-default feature, so the default closure stays clean).
    """
    name: str | None = None
    classification: str | None = None
    deps: list[tuple[str, bool]] = []
    in_package = False
    in_runtime_deps = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        header = line.strip()
        if header.startswith("[") and header.endswith("]"):
            sec = header[1:-1].strip()
            in_package = sec == "package"
            last = sec.split(".")[-1]
            in_runtime_deps = (
                last == "dependencies"
                and "dev-dependencies" not in sec
                and "build-dependencies" not in sec
            )
            continue
        if in_package:
            m = re.match(r'name\s*=\s*"([^"]+)"', line.strip())
            if m:
                name = m.group(1)
        m = re.match(r'classification\s*=\s*"([^"]+)"', line.strip())
        if m:
            classification = m.group(1)
        if in_runtime_deps:
            key = line.strip().split("=", 1)[0].strip()
            key = key.split(".", 1)[0].strip()  # `foo.workspace = ...` -> `foo`
            if key:
                optional = bool(re.search(r"\boptional\s*=\s*true\b", line))
                deps.append((key, optional))
    return name, classification, deps


def main() -> int:
    root = repo_root()
    crates: dict[str, tuple[str | None, list[str], str]] = {}
    for toml in root.rglob("Cargo.toml"):
        if any(part in ("target", ".git", "node_modules") for part in toml.parts):
            continue
        name, classification, deps = parse_manifest(toml.read_text())
        if not name:
            continue  # virtual/workspace manifest
        crates[name] = (classification, deps, str(toml.relative_to(root)))

    names = set(crates)
    new_violations: list[str] = []
    pending: list[str] = []
    warnings: list[str] = []
    seen_keys: set[str] = set()
    for name, (classification, deps, path) in sorted(crates.items()):
        if classification != SPEC:
            continue
        for dep, optional in deps:
            if dep not in names:
                continue  # external (crates.io) — not our concern
            dep_class = crates[dep][0] or "UNCLASSIFIED"
            if dep_class == SPEC:
                continue
            key = f"{name} -> {dep}"
            entry = f"  {name} ({path}) [spec]  ->  {dep} [{dep_class}]"
            if optional:
                # Only via a non-default feature → default closure stays clean.
                warnings.append(entry + "  (optional/feature)")
            elif key in ALLOWLIST:
                seen_keys.add(key)
                pending.append(f"{entry}\n      pending: {ALLOWLIST[key]}")
            else:
                new_violations.append(entry)

    spec_count = sum(1 for c, _, _ in crates.values() if c == SPEC)
    stale = sorted(set(ALLOWLIST) - seen_keys)

    if warnings:
        print(
            "dep-direction-guard: WARN — spec crates with optional edges into "
            "downstream (default closure is clean; move to the consumer before "
            "splitting):\n"
        )
        print("\n".join(warnings) + "\n")
    if pending:
        print(
            "dep-direction-guard: PENDING — known allowlisted violations awaiting "
            "a scheduled refactor (not a regression):\n"
        )
        print("\n".join(pending) + "\n")
    if stale:
        print(
            "dep-direction-guard: FAIL — allowlist entries that are no longer "
            "violations (a refactor landed; remove them from ALLOWLIST):\n"
        )
        print("\n".join(f"  {k}" for k in stale) + "\n")
    if new_violations:
        print(
            "dep-direction-guard: FAIL — NEW spec->downstream edges (the library "
            "closure leaked). Cut/feature-gate the edge, split the dep up (spec "
            "half -> a spec crate), or classify a genuinely-spec crate:\n"
        )
        print("\n".join(new_violations) + "\n")

    if new_violations or stale:
        return 1
    status = f" ({len(pending)} known-pending)" if pending else ""
    print(
        f"dep-direction-guard: OK — {spec_count} spec crates form a closed "
        f"library set{status} ({len(crates)} crates checked)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
