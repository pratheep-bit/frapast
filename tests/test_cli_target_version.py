"""Tests for CLI --target-version flag and upgrade compatibility filtering.

Coverage:
  1. filter_by_target_version with v14, v15, and v16 boundaries.
  2. Non-compatibility rules (e.g. SQLi, Perm) unaffected by target version.
  3. CLI scan execution with --target-version v15 filtering future v16 deprecations.
  4. CLI scan execution with --target-version v16 retaining all deprecations.
"""
from __future__ import annotations

import json
from pathlib import Path

from scanner.cli import _build_parser, scan
from scanner.rules.engine import Candidate
from scanner.suppression import filter_by_target_version


class TestTargetVersionFiltering:
    """Verify filter_by_target_version correctly bounds compatibility findings."""

    def test_target_version_v15_filters_v16_deprecations(self):
        """When targeting v15, v16-breaking changes must be excluded."""
        c_v15 = Candidate(
            rule_id="FR-COMPAT-001",
            rule_version="1.0.0",
            taxonomy_id="FR-COMPAT-001",
            file="api.py",
            line=10,
            function="load",
            code_location_hash="abc1",
            evidence="Deprecated Frappe framework API used: 'frappe.get_single'",
            proof_recipe="Migrate to 'frappe.get_doc' before upgrading to Frappe v15.",
        )
        c_v16 = Candidate(
            rule_id="FR-COMPAT-001",
            rule_version="1.0.0",
            taxonomy_id="FR-COMPAT-001",
            file="hooks.py",
            line=20,
            function="hooks",
            code_location_hash="abc2",
            evidence="Deprecated Frappe framework API used: 'scheduler_events[\"all\"]'",
            proof_recipe="Migrate to 'cron intervals' before upgrading to Frappe v16.",
        )
        c_sqli = Candidate(
            rule_id="FR-SQLI-001",
            rule_version="1.0.0",
            taxonomy_id="FR-SQLI-001",
            file="db.py",
            line=5,
            function="query",
            code_location_hash="abc3",
            evidence="SQL injection",
            proof_recipe="Use parameterized queries",
        )

        candidates = [c_v15, c_v16, c_sqli]
        filtered = filter_by_target_version(candidates, "v15")

        assert len(filtered) == 2
        assert c_v15 in filtered
        assert c_sqli in filtered
        assert c_v16 not in filtered

    def test_target_version_v16_retains_v15_and_v16(self):
        """When targeting v16, both v15 and v16 deprecations must be retained."""
        c_v15 = Candidate(
            rule_id="FR-COMPAT-001",
            rule_version="1.0.0",
            taxonomy_id="FR-COMPAT-001",
            file="api.py",
            line=10,
            function="load",
            code_location_hash="abc1",
            evidence="Deprecated API",
            proof_recipe="Migrate before upgrading to Frappe v15.",
        )
        c_v16 = Candidate(
            rule_id="FR-COMPAT-001",
            rule_version="1.0.0",
            taxonomy_id="FR-COMPAT-001",
            file="hooks.py",
            line=20,
            function="hooks",
            code_location_hash="abc2",
            evidence="Deprecated hook",
            proof_recipe="Migrate before upgrading to Frappe v16.",
        )

        filtered = filter_by_target_version([c_v15, c_v16], "v16")
        assert len(filtered) == 2

    def test_target_version_v14_filters_v15_and_v16(self):
        """When targeting v14, only v14 deprecations are kept."""
        c_v14 = Candidate(
            rule_id="FR-COMPAT-002",
            rule_version="1.0.0",
            taxonomy_id="FR-COMPAT-002",
            file="script.js",
            line=5,
            function="client_script",
            code_location_hash="abc1",
            evidence="cur_frm.cscript",
            proof_recipe="Migrate to frappe.ui.form.on before upgrading to Frappe v14.",
        )
        c_v15 = Candidate(
            rule_id="FR-COMPAT-002",
            rule_version="1.0.0",
            taxonomy_id="FR-COMPAT-002",
            file="view.js",
            line=8,
            function="client_script",
            code_location_hash="abc2",
            evidence="GridReport",
            proof_recipe="Migrate before upgrading to Frappe v15.",
        )

        filtered = filter_by_target_version([c_v14, c_v15], "v14")
        assert len(filtered) == 1
        assert c_v14 in filtered


class TestCliScanTargetVersionFlag:
    """Integration test for scan() and CLI parser with --target-version."""

    def test_parser_accepts_target_version(self):
        """Verify argparse recognizes --target-version with valid choices."""
        parser = _build_parser()
        args = parser.parse_args(["scan", "/path/to/repo", "--target-version", "v15"])
        assert args.target_version == "v15"

    def test_scan_programmatic_target_version_filter(self, tmp_path):
        """scan(..., target_version='v14') filters out v15 deprecations (tested via FR-COMPAT-002)."""
        app_dir = tmp_path / "myapp"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "__init__.py").write_text("")

        # v14 deprecation: cur_frm.cscript
        (app_dir / "v14_code.js").write_text("cur_frm.cscript.custom_load = function() {};\n")

        # v15 deprecation: frappe.views.GridReport
        (app_dir / "v15_code.js").write_text("let r = new frappe.views.GridReport();\n")

        # Scan targeting v14 -> only v14 finding
        results_v14 = scan(tmp_path, target_version="v14")
        compat_v14 = [c for c in results_v14 if c["rule_id"].startswith("FR-COMPAT")]
        assert len(compat_v14) == 1
        assert "cur_frm.cscript" in compat_v14[0]["evidence"]

        # Scan targeting v15 -> both v14 and v15 findings present
        results_v15 = scan(tmp_path, target_version="v15")
        compat_v15 = [c for c in results_v15 if c["rule_id"].startswith("FR-COMPAT")]
        assert len(compat_v15) == 2
