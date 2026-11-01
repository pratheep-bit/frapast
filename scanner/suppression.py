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
    candidate: Candidate | dict,
    source_lines: dict[str, list[str]],
) -> bool:
    """Return True if the candidate has an inline ``# frapast: ignore`` suppression.

    Checks the same line as the finding and the immediately preceding line, which is
    the standard convention from popular linters and static analyzers.

    Parameters
    ----------
    candidate:
        The candidate finding to check (Candidate dataclass or dictionary).
    source_lines:
        A mapping from file path string to a list of source code lines (0-indexed).
    """
    if isinstance(candidate, dict):
        c_file = str(candidate.get("file", "") or "")
        c_line = int(candidate.get("line", 0) or 0)
        c_rule_id = str(candidate.get("rule_id", "") or "")
        c_taxonomy_id = str(candidate.get("taxonomy_id", c_rule_id) or c_rule_id)
    else:
        c_file = str(getattr(candidate, "file", "") or "")
        c_line = int(getattr(candidate, "line", 0) or 0)
        c_rule_id = str(getattr(candidate, "rule_id", "") or "")
        c_taxonomy_id = str(getattr(candidate, "taxonomy_id", c_rule_id) or c_rule_id)

    lines = source_lines.get(c_file)
    if lines is None:
        return False

    # Line numbers in candidates are 1-indexed.
    check_indices = []
    if c_line > 0:
        check_indices.append(c_line - 1)  # same line (0-indexed)
    if c_line > 1:
        check_indices.append(c_line - 2)  # preceding line (0-indexed)

    for idx in check_indices:
        if idx < 0 or idx >= len(lines):
            continue
        suppressed_rules = _parse_suppress_comment(lines[idx])
        if suppressed_rules is None:
            continue
        # Empty set = suppress all rules
        if not suppressed_rules:
            return True
        if c_rule_id in suppressed_rules or c_taxonomy_id in suppressed_rules:
            return True

    return False


def filter_suppressed(
    candidates: list[Candidate | dict],
    source_lines: dict[str, list[str]],
) -> list[Candidate | dict]:
    """Return candidates that are not suppressed by inline comments."""
    return [c for c in candidates if not is_suppressed(c, source_lines)]


# --------------------------------------------------------------------------- #
# Baseline file management
# --------------------------------------------------------------------------- #

def _fingerprint(candidate: Candidate | dict) -> str:
    """Stable semantic fingerprint for a candidate: rule_id + file + function + code_location_hash.

    Using the enclosing function and AST code fragment hash ensures that the baseline is
    resilient to line-number shifts caused by adding comments or code above the finding,
    while still immediately flagging any change to the vulnerable code itself or any new
    finding introduced in the file.
    """
    if isinstance(candidate, dict):
        rule_id = str(candidate.get("rule_id", "") or "")
        file_path = str(candidate.get("file", "") or "")
        func = str(candidate.get("function", "") or "")
        loc_hash = str(candidate.get("code_location_hash", "") or "")
    else:
        rule_id = str(getattr(candidate, "rule_id", "") or "")
        file_path = str(getattr(candidate, "file", "") or "")
        func = str(getattr(candidate, "function", "") or "")
        loc_hash = str(getattr(candidate, "code_location_hash", "") or "")
    key = f"{rule_id}|{file_path}|{func}|{loc_hash}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def generate_baseline(candidates: list[Candidate | dict], path: str | Path) -> None:
    """Write a baseline file from the given list of candidates.

    Usage::

        frapast scan /path/to/app --generate-baseline .frapast-baseline.json

    All current findings become "known" — only new findings introduced after
    this baseline was generated will be reported on subsequent scans.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fingerprints = sorted({_fingerprint(c) for c in candidates})
    payload = {
        "version": 1,
        "generated_by": "frapast",
        "fingerprints": fingerprints,
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_baseline(path: str | Path) -> set[str]:
    """Load a baseline file and return the set of known finding fingerprints.

    Returns an empty set if the file does not exist or is malformed.
    """
    target = Path(path)
    if not target.is_file():
        return set()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        return set(payload.get("fingerprints", []))
    except (json.JSONDecodeError, KeyError, TypeError):
        return set()


def apply_baseline(
    candidates: list[Candidate | dict],
    baseline_fingerprints: set[str],
) -> list[Candidate | dict]:
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


def filter_by_target_version(
    candidates: list[Candidate | dict],
    target_version: str | None,
) -> list[Candidate | dict]:
    """Filter compatibility candidates (FR-COMPAT) to those applicable to the target version.

    Parameters
    ----------
    candidates:
        List of findings (Candidate dataclass or dictionary objects).
    target_version:
        Frappe target framework version, e.g. "v14", "v15", or "v16". If None or empty,
        all candidates are returned without filtering.

    Returns
    -------
    list:
        Candidates applicable when upgrading to `target_version`. Non-FR-COMPAT rules
        are preserved unmodified. For FR-COMPAT rules, findings that only break in a
        future version strictly greater than `target_version` are filtered out.
    """
    if not target_version:
        return candidates

    tv_str = str(target_version).strip().lower().lstrip("v")
    try:
        tv_num = int(tv_str)
    except ValueError:
        return candidates

    filtered = []
    for c in candidates:
        if isinstance(c, dict):
            rule_id = str(c.get("rule_id", "") or "")
            proof = str(c.get("proof_recipe", "") or "")
            evidence = str(c.get("evidence", "") or "")
        else:
            rule_id = str(getattr(c, "rule_id", "") or "")
            proof = str(getattr(c, "proof_recipe", "") or "")
            evidence = str(getattr(c, "evidence", "") or "")

        if not rule_id.startswith("FR-COMPAT"):
            filtered.append(c)
            continue

        combined_text = f"{proof} {evidence}"
        match = re.search(r"(?:upgrading to Frappe|removed in Frappe|Frappe)\s+v?(\d+)", combined_text, re.IGNORECASE)
        if not match:
            match = re.search(r"\bv?(\d+)\b", proof)

        if match:
            break_version = int(match.group(1))
            if break_version <= tv_num:
                filtered.append(c)
        else:
            filtered.append(c)

    return filtered
