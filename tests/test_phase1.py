from pathlib import Path

import yaml

from scanner.cli import scan
from scanner.hooks import build_hook_index, discover_hooks_files
from scanner.callgraph import build_call_graph
from scanner.cli import _write_candidates
from scanner.python import build_python_index, discover_python_files
from scanner.rules import execute_rules
from scanner.schema import SchemaParseError, build_schema_index, discover_doctype_json, load as load_schema


ROOT = Path(__file__).resolve().parents[1]


def test_taxonomy_v1_has_all_26_categories():
	files = sorted((ROOT / "taxonomy").glob("FR-*.yaml"))
	assert len(files) == 26
	for path in files:
		data = yaml.safe_load(path.read_text(encoding="utf-8"))
		assert data["id"] == path.stem
		assert data["runtime_required"] is True
		assert data["detector_status"] in {"none", "partial", "implemented"}


def test_schema_engine_loads_real_attendance_and_employee_fixture():
	fixture_index = build_schema_index(discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "employee"))
	employee = fixture_index.get_doctype("Employee")
	assert employee is not None
	assert employee.table_name == "tabEmployee"
	assert fixture_index.child_table_graph()["Employee"] == ("Attendance",)
	assert employee in fixture_index.owner_scoped_doctypes()


def test_schema_engine_fails_on_malformed_json_and_missing_required_keys():
	broken = discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "broken")
	try:
		build_schema_index(broken, strict=True)
	except SchemaParseError as exc:
		assert "parse_error" in str(exc)
	else:
		raise AssertionError("malformed JSON did not fail")

	missing = discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "missing_required")
	try:
		build_schema_index(missing, strict=True)
	except SchemaParseError as exc:
		assert "missing_required_key" in str(exc)
	else:
		raise AssertionError("missing required keys did not fail")


def test_hooks_engine_parses_handlers_permissions_and_collisions():
	files = discover_hooks_files(ROOT / "tests" / "hooks" / "fixtures")
	index = build_hook_index(files)
	assert len(index.handlers_for("Attendance", "on_submit")) == 2
	assert index.permission_query_conditions["Attendance"] == "app_one.permissions.attendance_query"
	assert index.has_permission["Attendance"] == "app_one.permissions.has_attendance_permission"
	assert index.collisions()[0].doctype == "Attendance"


def test_hooks_engine_handles_missing_hooks_file():
	index = build_hook_index(discover_hooks_files(ROOT / "tests" / "schema" / "fixtures"))
	assert index.handlers == ()


def test_python_index_extracts_phase1_patterns():
	files = discover_python_files(ROOT / "tests" / "python" / "fixtures")
	index = build_python_index(files)
	assert {"ignore_permissions_endpoint", "safe_endpoint", "unsafe_sql"} <= {
		endpoint.function for endpoint in index.whitelisted_endpoints
	}
	assert any(record.value for record in index.ignore_permissions)
	# unsafe_sql uses an f-string: request_controlled=True, dynamic=False (indexer
	# resolves f-strings to a template string with placeholders for the `query`
	# field, so `dynamic` means "could not resolve at all"). The correct flag for
	# "SQL query is fed user-controlled data" is request_controlled.
	assert any(call.request_controlled and not call.parameterized for call in index.sql_calls)
	assert any(call.parameterized for call in index.sql_calls)
	assert any(check.function == "checked" for check in index.permission_checks)
	assert index.functions


def test_phase1_patterns_cover_bounded_reachability_and_core_rules():
	"""Verifies that the rule engine fires the expected set of rules against the fixtures.

	Note: FR-SQLI-001 (dynamic SQL) requires dynamic=True (query string could not be
	resolved to any literal at all). The unsafe_sql fixture uses an f-string, which the
	Python indexer resolves to a template with placeholders (dynamic=False,
	request_controlled=True). FR-SQLI-001 correctly does NOT fire on f-strings; it fires
	only on truly unresolvable query arguments. Use test_all_rules.py for FR-SQLI-001 TP.
	"""
	schema = build_schema_index(
		discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "employee")
		+ discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "expense_claim")
	)
	hooks = build_hook_index(discover_hooks_files(ROOT / "tests" / "hooks" / "fixtures"))
	python = build_python_index(discover_python_files(ROOT / "tests" / "python" / "fixtures"))
	graph = build_call_graph(python)
	candidates = execute_rules(schema, hooks, python, graph)
	by_rule = {candidate.rule_id: candidate for candidate in candidates}
	assert {"FR-SQLI-002", "FR-PERM-002", "FR-HOOK-005", "FR-WKFL-002"} <= set(by_rule)
	assert by_rule["FR-SQLI-002"].function == "raw_submittable_sql"
	assert not any(
		candidate.rule_id == "FR-SQLI-002" and candidate.function == "migration_sql"
		for candidate in candidates
	)
	assert any(
		candidate.rule_id == "FR-PERM-002" and candidate.function == "helper_with_permission_bypass"
		for candidate in candidates
	)
	assert any(
		candidate.rule_id == "FR-PERM-002" and candidate.function == "imported_permission_bypass"
		for candidate in candidates
	)
	assert not any(
		candidate.rule_id == "FR-PERM-002" and candidate.function == "guarded_permission_bypass"
		for candidate in candidates
	)
	assert not any(
		candidate.rule_id == "FR-PERM-002" and candidate.function == "guarded_by_owner_or_role"
		for candidate in candidates
	)
	assert by_rule["FR-HOOK-005"].function in {"on_submit", "ExpenseClaimController.on_submit"}
	assert by_rule["FR-WKFL-002"].function == "direct_workflow_write"
	assert all(
		candidate.rule_version == ("1.1.0" if candidate.rule_id == "FR-PERM-002" else "1.0.0")
		for candidate in candidates
	)
	assert all(candidate.code_location_hash and candidate.proof_recipe for candidate in candidates)


def test_first_phase_rules_emit_candidates_without_filesystem_access():
	schema = build_schema_index(discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "employee"))
	hooks = build_hook_index(discover_hooks_files(ROOT / "tests" / "hooks" / "fixtures"))
	python = build_python_index(discover_python_files(ROOT / "tests" / "python" / "fixtures"))
	candidates = execute_rules(schema, hooks, python)
	ids = {candidate.rule_id for candidate in candidates}
	# FR-SQLI-001 requires dynamic=True (unresolvable SQL) reachable from a
	# whitelisted endpoint. The unsafe_sql fixture uses an f-string which the
	# indexer resolves to a template (dynamic=False, request_controlled=True),
	# so FR-SQLI-001 does not fire — but FR-PERM-001 and FR-PERM-002 do.
	assert "FR-PERM-001" in ids or "FR-PERM-002" in ids
	assert all(candidate.status == "candidate" and candidate.proof_tier == 0 for candidate in candidates)


def test_cli_scan_returns_candidate_dicts():
	candidates = scan(ROOT / "tests" / "python" / "fixtures")
	assert isinstance(candidates, list)


def test_ledger_writer_uses_repository_qualified_source_identity(tmp_path):
	candidates = [
		{
			"rule_id": "FR-SQLI-001",
			"rule_version": "1.0.0",
			"taxonomy_id": "FR-SQLI-001",
			"file": "one.py",
			"line": 10,
			"function": "first",
			"code_location_hash": "same-fragment",
			"evidence": "candidate",
			"proof_recipe": "runtime proof required",
		},
		{
			"rule_id": "FR-SQLI-001",
			"rule_version": "1.0.0",
			"taxonomy_id": "FR-SQLI-001",
			"file": "two.py",
			"line": 10,
			"function": "second",
			"code_location_hash": "same-fragment",
			"evidence": "candidate",
			"proof_recipe": "runtime proof required",
		},
	]
	_write_candidates(candidates, tmp_path, "frappe/example@revision")
	entries = sorted(tmp_path.glob("FR-SQLI-001-*.yaml"))
	assert len(entries) == 2
	assert all(yaml.safe_load(entry.read_text(encoding="utf-8"))["status"] == "candidate" for entry in entries)
