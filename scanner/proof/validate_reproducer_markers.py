"""CI gate: validate that every reproducer script carries a PROOF_MODE marker.

This script is invoked by .github/workflows/scanner-ci.yml:
  python scanner/proof/validate_reproducer_markers.py

Every file matching *.sh in the workspace's runtime/reproducers/ directory
(and in any tests/*/fixtures/runtime/reproducers/ directories) MUST have a
`# PROOF_MODE: <mode>` marker within its first 3 lines, where <mode> is one
of the values in VALID_PROOF_MODES.

Rationale (from rm.md):
  Proof tier is *never* inferred by keyword-sniffing a script's contents — a
  CI gate enforces the explicit marker. A changed reproducer without a marker
  is an ambiguous, untrusted artifact.

Exit codes:
  0 — all reproducers have valid markers
  1 — one or more reproducers are missing or have invalid markers
"""
from __future__ import annotations

import sys
from pathlib import Path

from scanner.proof.models import PROOF_MODE_MARKER, VALID_PROOF_MODES

# -----------------------------------------------------------------------
# Directories to scan (relative to workspace root = parent of this file's
# two-level-up ancestor).
# -----------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]

_REPRODUCER_GLOBS = [
    "runtime/reproducers/*.sh",
    "tests/*/fixtures/runtime/reproducers/*.sh",
    "tests/**/runtime/reproducers/*.sh",
]


def _valid_mode_line(line: str) -> bool:
    """Return True if `line` is a syntactically valid PROOF_MODE declaration."""
    stripped = line.strip()
    if not stripped.startswith(PROOF_MODE_MARKER):
        return False
    mode = stripped[len(PROOF_MODE_MARKER):].strip()
    return mode in VALID_PROOF_MODES


def validate_file(path: Path) -> str | None:
    """Return an error message if the file lacks a valid PROOF_MODE marker, else None."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"cannot read: {exc}"

    for line in lines[:3]:
        if _valid_mode_line(line):
            return None

    # Not found in first 3 lines
    first_3 = " | ".join(repr(line) for line in lines[:3])
    return f"missing or invalid {PROOF_MODE_MARKER} in first 3 lines. Found: {first_3}"


def collect_reproducers(root: Path) -> list[Path]:
    """Walk glob patterns relative to root and collect all .sh reproducer paths."""
    found: list[Path] = []
    for pattern in _REPRODUCER_GLOBS:
        found.extend(root.glob(pattern))
    return sorted(set(found))


def run_validation(root: Path | None = None) -> tuple[int, int, list[str]]:
    """Run validation and return (ok_count, fail_count, error_messages)."""
    root = root or _REPO_ROOT
    files = collect_reproducers(root)
    ok = 0
    failures: list[str] = []
    for path in files:
        err = validate_file(path)
        if err is None:
            ok += 1
        else:
            failures.append(f"  {path.relative_to(root)}: {err}")
    return ok, len(failures), failures


def main() -> int:
    ok, fail_count, failures = run_validation()
    total = ok + fail_count

    if total == 0:
        print("validate_reproducer_markers: no reproducer scripts found — nothing to validate")
        return 0

    if fail_count == 0:
        print(f"validate_reproducer_markers: OK — {total} reproducer(s) all have valid {PROOF_MODE_MARKER} markers")
        return 0

    print(f"validate_reproducer_markers: FAIL — {fail_count}/{total} reproducer(s) missing valid markers:")
    for line in failures:
        print(line)
    print(
        f"\nFix: add `{PROOF_MODE_MARKER} direct_call` or `{PROOF_MODE_MARKER} http_rpc` "
        "on line 1 or 2 of each failing script."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
