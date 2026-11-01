"""Unit and integration tests for the CLI --baseline and --generate-baseline flags."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.cli import main


def _create_frappe_app(tmp_path: Path, filename: str = "api.py", vulnerable_code: str | None = None) -> Path:
    app_dir = tmp_path / "custom_app"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (app_dir / "hooks.py").write_text("app_name = 'custom_app'\n", encoding="utf-8")

    code = vulnerable_code or (
        "import frappe\n\n"
        "@frappe.whitelist()\n"
        "def vulnerable_endpoint(data):\n"
        "    frappe.db.sql(f'select * from tabUser where name = \"{data}\"')\n"
    )
    (app_dir / filename).write_text(code, encoding="utf-8")
    return app_dir


class TestCLIBaselineFlags:
    def test_generate_baseline_writes_file_and_exits_zero(self, tmp_path: Path):
        app_dir = _create_frappe_app(tmp_path)
        baseline_file = tmp_path / "baseline.json"

        exit_code = main(["scan", str(app_dir), "--generate-baseline", str(baseline_file)])
        assert exit_code == 0
        assert baseline_file.is_file()

        data = json.loads(baseline_file.read_text(encoding="utf-8"))
        assert data.get("version") == 1
        assert data.get("generated_by") == "frapast"
        assert len(data.get("fingerprints", [])) > 0

    def test_scan_with_baseline_filters_known_and_exits_zero(self, tmp_path: Path):
        app_dir = _create_frappe_app(tmp_path)
        baseline_file = tmp_path / "baseline.json"

        # Generate baseline
        exit_code = main(["scan", str(app_dir), "--generate-baseline", str(baseline_file)])
        assert exit_code == 0

        # Scan with baseline — all findings are known, should exit 0
        exit_code = main(["scan", str(app_dir), "--baseline", str(baseline_file), "--format", "json"])
        assert exit_code == 0

    def test_scan_with_baseline_reports_new_finding_and_exits_one(self, tmp_path: Path, capsys):
        app_dir = _create_frappe_app(tmp_path, filename="first.py")
        baseline_file = tmp_path / "baseline.json"

        # 1. Generate baseline with first vulnerable file
        exit_code = main(["scan", str(app_dir), "--generate-baseline", str(baseline_file)])
        assert exit_code == 0

        # Clear stdout buffer from baseline generation
        capsys.readouterr()

        # 2. Add a second vulnerable file that is not in the baseline
        second_file = app_dir / "second.py"
        second_file.write_text(
            "import frappe\n\n"
            "@frappe.whitelist()\n"
            "def newly_added_vuln(value):\n"
            "    frappe.db.sql(f'select * from tabDoc where id = \"{value}\"')\n",
            encoding="utf-8",
        )

        # 3. Scan with baseline — should catch the new finding and exit 1
        exit_code = main(["scan", str(app_dir), "--baseline", str(baseline_file), "--format", "json"])
        assert exit_code == 1

        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        candidates = payload.get("candidates", [])
        assert len(candidates) >= 1
        # Confirm the reported candidate is the new one, not the baselined one
        reported_files = [c["file"] for c in candidates]
        assert any("second.py" in f for f in reported_files)
        assert not any("first.py" in f for f in reported_files)

    def test_scan_with_nonexistent_baseline_exits_two(self, tmp_path: Path, capsys):
        app_dir = _create_frappe_app(tmp_path)
        nonexistent = tmp_path / "does_not_exist.json"

        exit_code = main(["scan", str(app_dir), "--baseline", str(nonexistent)])
        assert exit_code == 2

        captured = capsys.readouterr()
        assert "does not exist" in captured.err

    def test_scan_auto_discovers_default_baseline_file(self, tmp_path: Path):
        app_dir = _create_frappe_app(tmp_path)
        default_baseline = app_dir / ".frapast-baseline.json"

        # Generate baseline at default location
        exit_code = main(["scan", str(app_dir), "--generate-baseline", str(default_baseline)])
        assert exit_code == 0

        # Scan without --baseline argument — should auto-discover .frapast-baseline.json
        exit_code = main(["scan", str(app_dir), "--format", "json"])
        assert exit_code == 0

    def test_scan_auto_discovers_frapast_toml_baseline(self, tmp_path: Path):
        app_dir = _create_frappe_app(tmp_path)
        custom_baseline = app_dir / "my_custom_baseline.json"

        # Generate baseline
        exit_code = main(["scan", str(app_dir), "--generate-baseline", str(custom_baseline)])
        assert exit_code == 0

        # Configure frapast.toml
        (app_dir / "frapast.toml").write_text(
            '[frapast]\nbaseline = "my_custom_baseline.json"\n',
            encoding="utf-8",
        )

        # Scan without --baseline argument — should load from frapast.toml
        exit_code = main(["scan", str(app_dir), "--format", "json"])
        assert exit_code == 0

    def test_scan_with_baseline_sarif_export_only_includes_new_findings(self, tmp_path: Path):
        app_dir = _create_frappe_app(tmp_path, filename="first.py")
        baseline_file = tmp_path / "baseline.json"
        sarif_file = tmp_path / "results.sarif"

        # Generate baseline
        assert main(["scan", str(app_dir), "--generate-baseline", str(baseline_file)]) == 0

        # Add second file
        (app_dir / "second.py").write_text(
            "import frappe\n\n"
            "@frappe.whitelist()\n"
            "def newly_added_vuln(value):\n"
            "    frappe.db.sql(f'select * from tabDoc where id = \"{value}\"')\n",
            encoding="utf-8",
        )

        # Scan with baseline and export SARIF
        exit_code = main([
            "scan",
            str(app_dir),
            "--baseline",
            str(baseline_file),
            "--sarif",
            str(sarif_file),
            "--format",
            "json",
        ])
        assert exit_code == 1
        assert sarif_file.is_file()

        sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
        results = sarif_data["runs"][0]["results"]
        # Only results from second.py should be in SARIF
        assert len(results) >= 1
        for res in results:
            uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert "second.py" in uri
            assert "first.py" not in uri

    def test_multi_repo_config_generate_and_apply_baseline(self, tmp_path: Path):
        repo1 = _create_frappe_app(tmp_path / "repo1", filename="mod1.py")
        repo2 = _create_frappe_app(tmp_path / "repo2", filename="mod2.py")
        baseline_file = tmp_path / "multi_baseline.json"
        config_file = tmp_path / "scan_config.yaml"

        config_file.write_text(
            f"repos:\n"
            f"  - id: r1\n"
            f"    path: {repo1}\n"
            f"    enabled: true\n"
            f"  - id: r2\n"
            f"    path: {repo2}\n"
            f"    enabled: true\n",
            encoding="utf-8",
        )

        # Generate combined baseline for multi-repo config
        exit_code = main(["scan", "--config", str(config_file), "--generate-baseline", str(baseline_file)])
        assert exit_code == 0
        assert baseline_file.is_file()

        # Scan with baseline — both repos are baselined, so total candidates should be 0 and exit 0
        exit_code = main(["scan", "--config", str(config_file), "--baseline", str(baseline_file), "--format", "json"])
        assert exit_code == 0
