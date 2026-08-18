"""test_suppression.py — Unit tests for scanner/suppression.py.

Tests inline comment suppression, baseline generation/loading/application,
frapast.toml parsing, .frapastignore glob exclusions, and path filtering.
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import replace
from pathlib import Path

import pytest

from scanner.suppression import (
    SuppressionConfig,
    apply_baseline,
    filter_suppressed,
    generate_baseline,
    is_suppressed,
    load_baseline,
    load_config,
    path_is_excluded,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_candidate(
    rule_id: str = "FR-PERM-001",
    taxonomy_id: str = "FR-PERM-001",
    file: str = "app/api.py",
    line: int = 10,
    code_location_hash: str = "abc123",
):
    """Construct a minimal Candidate-like namespace object for testing."""
    from types import SimpleNamespace
    return SimpleNamespace(
        rule_id=rule_id,
        taxonomy_id=taxonomy_id,
        file=file,
        line=line,
        code_location_hash=code_location_hash,
    )


# ---------------------------------------------------------------------------
# Inline suppression
# ---------------------------------------------------------------------------

class TestInlineSuppression:
    def _lines(self, code: str) -> dict[str, list[str]]:
        return {"app/api.py": code.splitlines()}

    def test_no_suppression_comment(self):
        candidate = _make_candidate(line=2)
        lines = self._lines("import frappe\nsome_code()")
        assert is_suppressed(candidate, lines) is False

    def test_suppress_all_same_line(self):
        candidate = _make_candidate(line=2)
        lines = self._lines("import frappe\nsome_code()  # frapast: ignore")
        assert is_suppressed(candidate, lines) is True

    def test_suppress_specific_rule_same_line(self):
        candidate = _make_candidate(rule_id="FR-PERM-001", line=2)
        lines = self._lines("import frappe\nsome_code()  # frapast: ignore FR-PERM-001")
        assert is_suppressed(candidate, lines) is True

    def test_suppress_different_rule_not_applied(self):
        candidate = _make_candidate(rule_id="FR-SQLI-001", taxonomy_id="FR-SQLI-001", line=2)
        lines = self._lines("import frappe\nsome_code()  # frapast: ignore FR-PERM-001")
        assert is_suppressed(candidate, lines) is False

    def test_suppress_on_preceding_line(self):
        candidate = _make_candidate(line=3)
        code = "import frappe\n# frapast: ignore FR-PERM-001\nsome_code()"
        lines = self._lines(code)
        assert is_suppressed(candidate, lines) is True

    def test_suppress_multiple_rules_same_line(self):
        candidate = _make_candidate(rule_id="FR-SQLI-001", line=1)
        code = "some_code()  # frapast: ignore FR-PERM-001, FR-SQLI-001"
        lines = self._lines(code)
        assert is_suppressed(candidate, lines) is True

    def test_case_insensitive_comment(self):
        candidate = _make_candidate(line=1)
        code = "some_code()  # FRAPAST: IGNORE"
        lines = self._lines(code)
        assert is_suppressed(candidate, lines) is True

    def test_file_not_in_source_lines(self):
        candidate = _make_candidate(file="other/file.py", line=1)
        lines = {"app/api.py": ["some_code()  # frapast: ignore"]}
        assert is_suppressed(candidate, lines) is False

    def test_filter_suppressed_removes_correct_items(self):
        c1 = _make_candidate(rule_id="FR-PERM-001", taxonomy_id="FR-PERM-001", line=1)
        c2 = _make_candidate(rule_id="FR-SQLI-001", taxonomy_id="FR-SQLI-001", line=2)
        lines = {"app/api.py": [
            "code1()  # frapast: ignore FR-PERM-001",
            "code2()",
        ]}
        result = filter_suppressed([c1, c2], lines)
        assert len(result) == 1
        assert result[0].rule_id == "FR-SQLI-001"


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

class TestBaselineManagement:
    def test_generate_and_load_baseline(self, tmp_path):
        c1 = _make_candidate(rule_id="FR-PERM-001", file="a.py", line=5, code_location_hash="aaa")
        c2 = _make_candidate(rule_id="FR-SQLI-001", file="b.py", line=10, code_location_hash="bbb")
        baseline_file = tmp_path / ".frapast-baseline.json"
        generate_baseline([c1, c2], baseline_file)
        assert baseline_file.exists()

        data = json.loads(baseline_file.read_text())
        assert data["version"] == 1
        assert len(data["fingerprints"]) == 2

    def test_apply_baseline_filters_known(self, tmp_path):
        c1 = _make_candidate(rule_id="FR-PERM-001", file="a.py", line=5, code_location_hash="aaa")
        c2 = _make_candidate(rule_id="FR-SQLI-001", file="b.py", line=10, code_location_hash="bbb")
        baseline_file = tmp_path / ".frapast-baseline.json"
        generate_baseline([c1], baseline_file)  # Only c1 is in the baseline
        fingerprints = load_baseline(baseline_file)

        result = apply_baseline([c1, c2], fingerprints)
        assert len(result) == 1
        assert result[0].rule_id == "FR-SQLI-001"

    def test_load_missing_baseline_returns_empty_set(self, tmp_path):
        result = load_baseline(tmp_path / "nonexistent.json")
        assert result == set()

    def test_load_malformed_baseline_returns_empty_set(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not valid json", encoding="utf-8")
        assert load_baseline(f) == set()

    def test_apply_empty_baseline_returns_all(self):
        c1 = _make_candidate()
        result = apply_baseline([c1], set())
        assert result == [c1]


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

class TestConfigLoading:
    def test_load_config_no_files_returns_defaults(self, tmp_path):
        config = load_config(tmp_path)
        assert config.exclude_paths == []
        assert config.disabled_rules == []
        assert config.min_severity == "low"
        assert config.fail_on == "critical"

    def test_load_frapastignore(self, tmp_path):
        ignore = tmp_path / ".frapastignore"
        ignore.write_text("tests/**\n# comment\npatches/**\n", encoding="utf-8")
        config = load_config(tmp_path)
        assert "tests/**" in config.exclude_paths
        assert "patches/**" in config.exclude_paths
        assert len(config.exclude_paths) == 2  # comment line excluded

    def test_load_frapast_toml(self, tmp_path):
        toml_content = textwrap.dedent("""\
            [frapast]
            exclude = ["tests/**", "patches/**"]
            disabled_rules = ["FR-PERF-001"]
            min_severity = "high"
            fail_on = "critical"
        """)
        (tmp_path / "frapast.toml").write_text(toml_content, encoding="utf-8")
        config = load_config(tmp_path)
        assert "tests/**" in config.exclude_paths
        assert "FR-PERF-001" in config.disabled_rules
        assert config.min_severity == "high"
        assert config.fail_on == "critical"

    def test_path_excluded_by_glob(self, tmp_path):
        config = SuppressionConfig(exclude_paths=["tests/**", "*.generated.py"])
        assert path_is_excluded("tests/fixtures/dummy.py", config) is True
        assert path_is_excluded("app/models.generated.py", config) is True
        assert path_is_excluded("app/api.py", config) is False

    def test_path_excluded_glob_exact(self):
        config = SuppressionConfig(exclude_paths=["app/api.py"])
        assert path_is_excluded("app/api.py", config) is True
        assert path_is_excluded("app/models.py", config) is False
