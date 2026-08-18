"""scanner/suppression.py — Inline suppression comment parser, baseline file manager,
and configuration loader for frapAST.

Public API
----------
- ``load_config(root: Path) -> SuppressionConfig``
    Load frapast.toml or .frapastignore from a project root.

- ``is_suppressed(candidate: Candidate, source_lines: dict[str, list[str]]) -> bool``
    Return True if the candidate is suppressed by an inline ``# frapast: ignore`` comment.

- ``generate_baseline(candidates: list[Candidate], path: Path) -> None``
    Write a baseline file from a list of candidates.

- ``load_baseline(path: Path) -> set[str]``
    Load a baseline file and return a set of finding fingerprints that are already known.

- ``apply_baseline(candidates: list[Candidate], baseline_fingerprints: set[str]) -> list[Candidate]``
    Filter out any candidate whose fingerprint exists in the baseline.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.rules.engine import Candidate  # noqa: F401 — type-checking only

# --------------------------------------------------------------------------- #
# Inline comment suppression
# --------------------------------------------------------------------------- #

# Matches:  # frapast: ignore
#           # frapast: ignore FR-PERM-001
#           # frapast: ignore FR-PERM-001 FR-SQLI-001
_SUPPRESS_RE = re.compile(
    r"#\s*frapast\s*:\s*ignore(?:\s+(?P<rules>[A-Z0-9 ,\-]+))?",
    re.IGNORECASE,
)


def _parse_suppress_comment(line: str) -> set[str] | None:
    """Return the set of rule IDs suppressed by comment(s), or None if not a suppression.

    An empty set means "suppress all rules on this line."
    Supports multiple `# frapast: ignore` directives on the same line as well as
    comma- or space-separated rule lists.
    """
    matches = list(_SUPPRESS_RE.finditer(line))
    if not matches:
        return None
    suppressed: set[str] = set()
    for m in matches:
        raw = m.group("rules")
        if not raw:
            return set()  # wildcard suppress all
        suppressed.update(r.strip() for r in re.split(r"[\s,]+", raw.strip()) if r.strip())
    return suppressed


def is_suppressed(
    candidate: Candidate,
    source_lines: dict[str, list[str]],
) -> bool:
    """Return True if the candidate has an inline ``# frapast: ignore`` suppression.

    Checks the same line as the finding and the immediately preceding line, which is
    the standard convention from Bandit/ESLint/ruff.

    Parameters
    ----------
    candidate:
        The candidate finding to check.
    source_lines:
        A mapping from file path string to a list of source code lines (0-indexed).
    """
    lines = source_lines.get(candidate.file)
    if lines is None:
        return False

    # Line numbers in candidates are 1-indexed.
    check_indices = []
    if candidate.line > 0:
        check_indices.append(candidate.line - 1)  # same line (0-indexed)
    if candidate.line > 1:
        check_indices.append(candidate.line - 2)  # preceding line (0-indexed)

    for idx in check_indices:
        if idx < 0 or idx >= len(lines):
            continue
        suppressed_rules = _parse_suppress_comment(lines[idx])
        if suppressed_rules is None:
            continue
        # Empty set = suppress all rules
        if not suppressed_rules:
            return True
        if candidate.rule_id in suppressed_rules or candidate.taxonomy_id in suppressed_rules:
            return True

    return False


def filter_suppressed(
    candidates: list[Candidate],
    source_lines: dict[str, list[str]],
) -> list[Candidate]:
    """Return candidates that are not suppressed by inline comments."""
    return [c for c in candidates if not is_suppressed(c, source_lines)]


# --------------------------------------------------------------------------- #
# Baseline file management
# --------------------------------------------------------------------------- #

def _fingerprint(candidate: Candidate) -> str:
    """Stable semantic fingerprint for a candidate: rule_id + file + function + code_location_hash.

    Using the enclosing function and AST code fragment hash ensures that the baseline is
    resilient to line-number shifts caused by adding comments or code above the finding,
    while still immediately flagging any change to the vulnerable code itself or any new
    finding introduced in the file.
    """
    func = getattr(candidate, "function", "")
    key = f"{candidate.rule_id}|{candidate.file}|{func}|{candidate.code_location_hash}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def generate_baseline(candidates: list[Candidate], path: Path) -> None:
    """Write a baseline file from the given list of candidates.

    Usage::

        frapast scan /path/to/app --generate-baseline .frapast-baseline.json

    All current findings become "known" — only new findings introduced after
    this baseline was generated will be reported on subsequent scans.
    """
    fingerprints = sorted({_fingerprint(c) for c in candidates})
    payload = {
        "version": 1,
        "generated_by": "frapast",
        "fingerprints": fingerprints,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_baseline(path: Path) -> set[str]:
    """Load a baseline file and return the set of known finding fingerprints.

    Returns an empty set if the file does not exist or is malformed.
    """
    if not path.is_file():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return set(payload.get("fingerprints", []))
    except (json.JSONDecodeError, KeyError, TypeError):
        return set()


def apply_baseline(
    candidates: list[Candidate],
    baseline_fingerprints: set[str],
) -> list[Candidate]:
    """Filter out candidates that are already known in the baseline."""
    if not baseline_fingerprints:
        return candidates
    return [c for c in candidates if _fingerprint(c) not in baseline_fingerprints]


# --------------------------------------------------------------------------- #
# Configuration loader (frapast.toml / .frapastignore)
# --------------------------------------------------------------------------- #

@dataclass
class SuppressionConfig:
    """Project-level scanner configuration loaded from frapast.toml or .frapastignore."""

    # Glob patterns for paths to exclude entirely from scanning.
    exclude_paths: list[str] = field(default_factory=list)

    # Rule IDs to disable globally for this project.
    disabled_rules: list[str] = field(default_factory=list)

    # Minimum severity level to report (critical, high, medium, low).
    min_severity: str = "low"

    # Whether to fail the scan if any findings meet or exceed the severity gate.
    fail_on: str = "critical"

    # Path to the baseline file (if any).
    baseline_path: Path | None = None


def load_config(root: Path) -> SuppressionConfig:
    """Load frapAST configuration from ``frapast.toml`` or ``.frapastignore``.

    Search order:
    1. ``{root}/frapast.toml``
    2. ``{root}/.frapastignore``

    If neither exists, returns a default ``SuppressionConfig``.
    """
    config = SuppressionConfig()

    toml_path = root / "frapast.toml"
    if toml_path.is_file():
        _load_toml(toml_path, config)
        return config

    ignore_path = root / ".frapastignore"
    if ignore_path.is_file():
        _load_ignore(ignore_path, config)

    return config


def _load_toml(path: Path, config: SuppressionConfig) -> None:
    """Parse a frapast.toml file into config."""
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomllib  # type: ignore[no-redef]
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return  # tolerate missing tomli on Python <3.11

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return

    scanner_section = data.get("tool", {}).get("frapast", data.get("frapast", {}))
    if not scanner_section:
        return

    if "exclude" in scanner_section:
        config.exclude_paths = list(scanner_section["exclude"])
    if "disabled_rules" in scanner_section:
        config.disabled_rules = list(scanner_section["disabled_rules"])
    if "min_severity" in scanner_section:
        config.min_severity = str(scanner_section["min_severity"])
    if "fail_on" in scanner_section:
        config.fail_on = str(scanner_section["fail_on"])
    if "baseline" in scanner_section:
        config.baseline_path = path.parent / scanner_section["baseline"]


def _load_ignore(path: Path, config: SuppressionConfig) -> None:
    """Parse a .frapastignore file (one glob pattern per line)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            config.exclude_paths.append(line)


def path_is_excluded(file_path: str | Path, config: SuppressionConfig) -> bool:
    """Return True if the given file path matches any configured exclusion glob."""
    import fnmatch
    p = Path(file_path).as_posix()
    for pattern in config.exclude_paths:
        if fnmatch.fnmatch(p, pattern) or fnmatch.fnmatch(Path(p).name, pattern):
            return True
    return False
