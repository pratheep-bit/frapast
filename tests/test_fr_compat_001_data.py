from __future__ import annotations

import json
from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules.engine import fr_compat_001
from scanner.schema import build_schema_index
from scanner.shared import SourceFile

ROOT = Path(__file__).resolve().parents[1]


def _make_test_data(tmp_path: Path) -> Path:
	data = {
		"schema_version": "1.0.0",
		"generated_at": "2026-01-01T00:00:00Z",
		"branches": {
			"version-14": "sha14",
			"version-15": "sha15",
			"version-16": "sha16",
		},
		"summary": {"total_changes": 2},
		"changes": [
			{
				"name": "frappe.removed_in_v15",
				"kind": "function",
				"status": "removed",
				"last_present_in": "version-14",
				"missing_in": "version-15",
				"moved_to": None,
				"confidence": "high",
				"evidence": "frappe/legacy.py:10",
				"deprecation_message": None,
			},
			{
				"name": "frappe.moved_in_v16",
				"kind": "function",
				"status": "moved",
				"last_present_in": "version-15",
				"missing_in": "version-16",
				"moved_to": ["frappe.new_module.moved_in_v16"],
				"confidence": "medium",
				"evidence": "frappe/old_mod.py:20",
				"deprecation_message": None,
			},
		],
	}
	p = tmp_path / "mock_changes.json"
	p.write_text(json.dumps(data), encoding="utf-8")
	return p


def _scan_code(tmp_path: Path, code: str, *, target_version: str | None = None, data_path: Path | None = None):
	app_dir = tmp_path / "app"
	app_dir.mkdir(parents=True, exist_ok=True)
	(app_dir / "__init__.py").write_text("")
	f = app_dir / "api.py"
	f.write_text(code, encoding="utf-8")

	sources = [SourceFile(app_dir / "__init__.py", tmp_path), SourceFile(f, tmp_path)]
	py_idx = build_python_index(sources)
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	return fr_compat_001(
		schema,
		hooks,
		py_idx,
		cg,
		target_version=target_version,
		data_path=data_path,
	)


def test_removed_name_at_or_after_missing_in_produces_finding(tmp_path: Path) -> None:
	data_path = _make_test_data(tmp_path)
	code = "import frappe\ndef run():\n    return frappe.removed_in_v15()\n"
	findings = _scan_code(tmp_path, code, target_version="v15", data_path=data_path)
	assert len(findings) == 1
	assert findings[0].rule_id == "FR-COMPAT-001"
	assert "frappe.removed_in_v15" in findings[0].evidence
	assert "version-15" in findings[0].evidence


def test_removed_name_with_older_target_version_produces_no_finding(tmp_path: Path) -> None:
	data_path = _make_test_data(tmp_path)
	code = "import frappe\ndef run():\n    return frappe.removed_in_v15()\n"
	findings = _scan_code(tmp_path, code, target_version="v14", data_path=data_path)
	assert len(findings) == 0


def test_call_to_name_present_in_every_branch_produces_no_finding(tmp_path: Path) -> None:
	data_path = _make_test_data(tmp_path)
	code = "import frappe\ndef run():\n    return frappe.get_single('System Settings')\n"
	findings = _scan_code(tmp_path, code, target_version="v16", data_path=data_path)
	assert len(findings) == 0


def test_moved_name_produces_low_severity_finding_mentioning_moved_to(tmp_path: Path) -> None:
	data_path = _make_test_data(tmp_path)
	code = "import frappe\ndef run():\n    return frappe.moved_in_v16()\n"
	findings = _scan_code(tmp_path, code, target_version="v16", data_path=data_path)
	assert len(findings) == 1
	assert "moved" in findings[0].evidence.lower()
	assert "frappe.new_module.moved_in_v16" in findings[0].evidence


def test_without_target_version_no_compat_findings(tmp_path: Path) -> None:
	data_path = _make_test_data(tmp_path)
	code = "import frappe\ndef run():\n    return frappe.removed_in_v15()\n"
	findings = _scan_code(tmp_path, code, target_version=None, data_path=data_path)
	assert len(findings) == 0


def test_aliased_import_resolution_from_frappe(tmp_path: Path) -> None:
	data_path = _make_test_data(tmp_path)
	code = "from frappe import removed_in_v15 as my_alias\ndef run():\n    return my_alias()\n"
	findings = _scan_code(tmp_path, code, target_version="v15", data_path=data_path)
	assert len(findings) == 1
	assert "frappe.removed_in_v15" in findings[0].evidence


def test_end_to_end_with_real_generated_data_file(tmp_path: Path) -> None:
	real_data = ROOT / "scanner" / "data" / "frappe_api_changes.json"
	assert real_data.is_file(), "Generated change data must exist"

	# Five confirmed-existing calls in Frappe core must NOT be flagged
	safe_code = """import frappe
from frappe.desk.form import load

def run():
    frappe.get_single("System Settings")
    frappe.client.get_list("User")
    frappe.db.multisql({"mariadb": "SELECT 1"})
    frappe.db.sql_ddl("CREATE TABLE test (id int)")
    load.getdoc("DocType", "User")
"""
	safe_findings = _scan_code(tmp_path, safe_code, target_version="v16", data_path=real_data)
	assert len(safe_findings) == 0, f"Expected 0 findings on safe calls, got: {[f.evidence for f in safe_findings]}"

	# At least two real removed symbols must be flagged
	# e.g. frappe.app.RequestContext (removed in v15) and frappe.automation.doctype.auto_repeat.auto_repeat.set_auto_repeat_as_completed (removed in v15)
	breaking_code = """import frappe
from frappe.app import RequestContext
from frappe.automation.doctype.auto_repeat.auto_repeat import set_auto_repeat_as_completed

def run():
    rc = RequestContext()
    set_auto_repeat_as_completed()
"""
	breaking_findings = _scan_code(tmp_path, breaking_code, target_version="v15", data_path=real_data)
	assert len(breaking_findings) >= 2
	evidences = [f.evidence for f in breaking_findings]
	assert any("RequestContext" in ev for ev in evidences)
	assert any("set_auto_repeat_as_completed" in ev for ev in evidences)
