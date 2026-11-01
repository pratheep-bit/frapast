from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import yaml
from scanner.cli import main
from scanner.proof.models import ProofResult, ProofStatus


def test_prove_zero_candidates_with_sarif(tmp_path: Path) -> None:
	sarif_path = tmp_path / "zero.sarif"
	with patch("sys.argv", ["frapast", "prove", str(tmp_path), "--sarif", str(sarif_path)]):
		code = main(["prove", str(tmp_path), "--sarif", str(sarif_path)])
	assert code == 0
	assert sarif_path.exists(), "SARIF report must be exported even when 0 candidates exist"
	data = json.loads(sarif_path.read_text(encoding="utf-8"))
	assert data["version"] == "2.1.0"
	assert isinstance(data["runs"], list)
	assert len(data["runs"]) > 0
	assert data["runs"][0]["results"] == []


def test_prove_batch_with_candidates_with_sarif(tmp_path: Path) -> None:
	app_dir = tmp_path / "app"
	app_dir.mkdir()
	(app_dir / "hooks.py").write_text("app_name = 'test_app'\n", encoding="utf-8")
	(app_dir / "api.py").write_text(
		"import frappe\n\n"
		"@frappe.whitelist(allow_guest=True)\n"
		"def insecure_query(user):\n"
		"    return frappe.db.sql(f'SELECT * FROM tabUser WHERE name = \"{user}\"')\n",
		encoding="utf-8",
	)
	sarif_path = tmp_path / "batch.sarif"
	code = main(["prove", str(app_dir), "--sarif", str(sarif_path), "--dry-run", "--ledger-dir", str(tmp_path / "findings")])
	assert sarif_path.exists(), "SARIF report must be exported for batch prove"
	data = json.loads(sarif_path.read_text(encoding="utf-8"))
	assert data["version"] == "2.1.0"
	assert isinstance(data["runs"], list)
	results = data["runs"][0]["results"]
	assert len(results) > 0
	assert any(r["ruleId"] == "FR-SQLI-001" for r in results)


def test_prove_single_finding_with_sarif(tmp_path: Path) -> None:
	findings_dir = tmp_path / "findings"
	findings_dir.mkdir()
	finding_id = "FR-SQLI-001-mock001"
	finding_data = {
		"id": finding_id,
		"rule_id": "FR-SQLI-001",
		"file": "api.py",
		"line": 5,
		"severity": {"score": 85.0},
		"evidence": "Direct string interpolation in sql",
		"status": "candidate",
	}
	(findings_dir / f"{finding_id}.yaml").write_text(yaml.safe_dump(finding_data), encoding="utf-8")
	sarif_path = tmp_path / "single.sarif"

	code = main([
		"prove",
		str(tmp_path),
		"--finding-id",
		finding_id,
		"--sarif",
		str(sarif_path),
		"--dry-run",
		"--ledger-dir",
		str(findings_dir),
	])
	assert sarif_path.exists(), "SARIF report must be exported when proving a single finding"
	data = json.loads(sarif_path.read_text(encoding="utf-8"))
	assert data["version"] == "2.1.0"
	assert isinstance(data["runs"], list)
	results = data["runs"][0]["results"]
	assert len(results) == 1
	assert results[0]["ruleId"] == "FR-SQLI-001"

