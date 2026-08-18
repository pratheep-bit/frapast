"""test_suppression_adversarial.py — Adversarial edge-case test suite for scanner/suppression.py.

Tests five specific adversarial scenarios:
1. Multiple/repeated inline suppression comments on the same line.
2. Suppression comments referencing non-existent or misspelled rule IDs.
3. Baseline behavior when code shifts lines.
4. Baseline behavior when underlying code changes on the same line.
5. Malformed frapast.toml and .frapastignore configurations.
"""

from __future__ import annotations

import json
import tempfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.suppression import (
    SuppressionConfig,
    _fingerprint,
    _parse_suppress_comment,
    apply_baseline,
    filter_suppressed,
    generate_baseline,
    is_suppressed,
    load_baseline,
    load_config,
    path_is_excluded,
)


def _candidate(
    rule_id: str = "FR-PERM-001",
    file: str = "app/api.py",
    line: int = 10,
    func: str = "update_record",
    loc_hash: str = "hash_alpha_123",
):
    return SimpleNamespace(
        rule_id=rule_id,
        taxonomy_id=rule_id,
        file=file,
        line=line,
        function=func,
        code_location_hash=loc_hash,
    )


# --------------------------------------------------------------------------- #
# 1. Multiple / Repeated Suppression Comments on the Same Line
# --------------------------------------------------------------------------- #

class TestAdversarialMultipleComments:
    def test_comma_separated_multiple_rules(self):
        line = "db.sql(query)  # frapast: ignore FR-PERM-001, FR-SQLI-001"
        rules = _parse_suppress_comment(line)
        assert rules == {"FR-PERM-001", "FR-SQLI-001"}

    def test_space_separated_multiple_rules(self):
        line = "db.sql(query)  # frapast: ignore FR-PERM-001 FR-SQLI-001"
        rules = _parse_suppress_comment(line)
        assert rules == {"FR-PERM-001", "FR-SQLI-001"}

    def test_repeated_separate_ignore_comments_on_same_line(self):
        """Two separate '# frapast: ignore' comments on the same line must both be parsed."""
        line = "db.sql(query)  # frapast: ignore FR-PERM-001 # frapast: ignore FR-SQLI-001"
        rules = _parse_suppress_comment(line)
        assert rules == {"FR-PERM-001", "FR-SQLI-001"}

    def test_repeated_comments_apply_independently(self):
        line = "db.sql(query)  # frapast: ignore FR-PERM-001 # frapast: ignore FR-SQLI-001"
        lines = {"app/api.py": [line]}

        c_perm = _candidate(rule_id="FR-PERM-001", line=1)
        c_sqli = _candidate(rule_id="FR-SQLI-001", line=1)
        c_csrf = _candidate(rule_id="FR-CSRF-001", line=1)

        assert is_suppressed(c_perm, lines) is True
        assert is_suppressed(c_sqli, lines) is True
        assert is_suppressed(c_csrf, lines) is False  # third rule is NOT suppressed

    def test_wildcard_combined_with_specific_rule(self):
        """A wildcard comment on the same line suppresses all rules."""
        line = "db.sql(query)  # frapast: ignore # frapast: ignore FR-PERM-001"
        rules = _parse_suppress_comment(line)
        assert rules == set()  # empty set = wildcard suppress all


# --------------------------------------------------------------------------- #
# 2. Non-existent / Misspelled Rule IDs
# --------------------------------------------------------------------------- #

class TestAdversarialMisspelledRuleIDs:
    def test_misspelled_rule_does_not_suppress_real_finding(self):
        line = "frappe.db.sql(query)  # frapast: ignore FR-PERMM-001"
        lines = {"app/api.py": [line]}
        c_perm = _candidate(rule_id="FR-PERM-001", line=1)
        # Typo should NOT match FR-PERM-001
        assert is_suppressed(c_perm, lines) is False

    def test_empty_ignore_directive_is_wildcard(self):
        line = "frappe.db.sql(query)  # frapast: ignore"
        lines = {"app/api.py": [line]}
        c_perm = _candidate(rule_id="FR-PERM-001", line=1)
        # Empty directive suppresses everything on that line
        assert is_suppressed(c_perm, lines) is True

    def test_similar_prefix_does_not_overmatch(self):
        line = "frappe.db.sql(query)  # frapast: ignore FR-PERM-001"
        lines = {"app/api.py": [line]}
        c_perm2 = _candidate(rule_id="FR-PERM-0010", line=1)
        c_perm3 = _candidate(rule_id="FR-PERM-00", line=1)
        assert is_suppressed(c_perm2, lines) is False
        assert is_suppressed(c_perm3, lines) is False


# --------------------------------------------------------------------------- #
# 3. Line Number Shifts in Baseline
# --------------------------------------------------------------------------- #

class TestAdversarialBaselineLineShifts:
    def test_fingerprint_includes_file_and_hash(self, tmp_path):
        c1 = _candidate(rule_id="FR-PERM-001", file="app/api.py", line=10, loc_hash="hash_abc")
        fp1 = _fingerprint(c1)
        assert isinstance(fp1, str)
        assert len(fp1) == 32

    def test_line_shift_behavior(self, tmp_path):
        """When line shifts from 10 to 15 (e.g. comments added above), semantic fingerprint remains matched."""
        base_file = tmp_path / "baseline.json"
        c_orig = _candidate(rule_id="FR-PERM-001", file="app/api.py", line=10, func="get_data", loc_hash="hash_abc")
        generate_baseline([c_orig], base_file)
        known = load_baseline(base_file)

        # Same file, function, and code hash, shifted by 5 lines
        c_shifted = _candidate(rule_id="FR-PERM-001", file="app/api.py", line=15, func="get_data", loc_hash="hash_abc")
        remaining = apply_baseline([c_shifted], known)
        # Because baseline binds to the semantic code fragment and function, it remains suppressed
        assert len(remaining) == 0

    def test_new_finding_nearby_is_reported_despite_baseline(self, tmp_path):
        """A new finding introduced in the same file with a different code hash is NOT suppressed."""
        base_file = tmp_path / "baseline.json"
        c_known = _candidate(rule_id="FR-PERM-001", file="app/api.py", line=10, func="get_data", loc_hash="hash_abc")
        generate_baseline([c_known], base_file)
        known = load_baseline(base_file)

        c_new = _candidate(rule_id="FR-SQLI-001", file="app/api.py", line=12, func="get_data", loc_hash="hash_new_sqli")
        remaining = apply_baseline([c_new], known)
        assert len(remaining) == 1
        assert remaining[0].rule_id == "FR-SQLI-001"


# --------------------------------------------------------------------------- #
# 4. Code Change / Reintroduced Vulnerability on the Same Line
# --------------------------------------------------------------------------- #

class TestAdversarialCodeChangeOnSameLine:
    def test_different_code_hash_on_same_line_is_reported(self, tmp_path):
        """If code on line 10 changes (different AST hash), the baseline reports it as new."""
        base_file = tmp_path / "baseline.json"
        # Initial vulnerability on line 10
        c_v1 = _candidate(rule_id="FR-SQLI-001", file="app/api.py", line=10, loc_hash="hash_select_all")
        generate_baseline([c_v1], base_file)
        known = load_baseline(base_file)

        # Code on line 10 was rewritten with a DIFFERENT vulnerable query
        c_v2 = _candidate(rule_id="FR-SQLI-001", file="app/api.py", line=10, loc_hash="hash_update_query")
        remaining = apply_baseline([c_v2], known)
        # Must NOT be suppressed by the old baseline entry
        assert len(remaining) == 1
        assert remaining[0].code_location_hash == "hash_update_query"

    def test_different_rule_on_same_line_is_reported(self, tmp_path):
        """If a different rule triggers on the same line, baseline reports it."""
        base_file = tmp_path / "baseline.json"
        c_sqli = _candidate(rule_id="FR-SQLI-001", file="app/api.py", line=10, loc_hash="hash_x")
        generate_baseline([c_sqli], base_file)
        known = load_baseline(base_file)

        c_perm = _candidate(rule_id="FR-PERM-001", file="app/api.py", line=10, loc_hash="hash_x")
        remaining = apply_baseline([c_perm], known)
        assert len(remaining) == 1
        assert remaining[0].rule_id == "FR-PERM-001"


# --------------------------------------------------------------------------- #
# 5. Malformed Configurations
# --------------------------------------------------------------------------- #

class TestAdversarialMalformedConfig:
    def test_corrupted_toml_syntax_falls_back_safely(self, tmp_path):
        toml = tmp_path / "frapast.toml"
        toml.write_text("this is completely invalid [[[[ toml syntax = {", encoding="utf-8")
        cfg = load_config(tmp_path)
        # Should gracefully return default config without crashing
        assert isinstance(cfg, SuppressionConfig)
        assert cfg.exclude_paths == []
        assert cfg.disabled_rules == []

    def test_unknown_keys_in_toml_are_ignored(self, tmp_path):
        toml = tmp_path / "frapast.toml"
        content = textwrap.dedent("""\
            [frapast]
            completely_unknown_key = true
            another_invalid_setting = "ignored"
            exclude = ["tests/**"]
            min_severity = "high"
        """)
        toml.write_text(content, encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.exclude_paths == ["tests/**"]
        assert cfg.min_severity == "high"

    def test_empty_frapastignore(self, tmp_path):
        ignore = tmp_path / ".frapastignore"
        ignore.write_text("", encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.exclude_paths == []

    def test_frapastignore_with_only_comments_and_whitespace(self, tmp_path):
        ignore = tmp_path / ".frapastignore"
        ignore.write_text("# This is a comment\n\n   # Another comment\n  \n", encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.exclude_paths == []

    def test_path_exclusion_wildcard_adversarial(self):
        cfg = SuppressionConfig(exclude_paths=["**/node_modules/**", "*.min.js", "tests/*"])
        assert path_is_excluded("frontend/node_modules/pkg/index.js", cfg) is True
        assert path_is_excluded("static/bundle.min.js", cfg) is True
        assert path_is_excluded("app/controllers/user.py", cfg) is False
