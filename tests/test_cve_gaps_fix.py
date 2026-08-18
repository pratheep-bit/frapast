
from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def test_script_report_sqli_detection(tmp_path):
	"""Verify FR-SQLI-001 flags unescaped dynamic SQL inside Frappe Script Reports."""
	report_dir = tmp_path / "hrms" / "hr" / "report" / "monthly_attendance"
	report_dir.mkdir(parents=True, exist_ok=True)
	report_file = report_dir / "monthly_attendance.py"
	report_file.write_text("""import frappe

def execute(filters=None):
	return get_columns(), get_data(filters)

def get_columns():
	return ["employee", "status"]

def get_data(filters):
	emp_id = filters.get("employee")
	query = "select * from `tabAttendance` where employee = '" + emp_id + "'"
	return frappe.db.sql(query, as_dict=True)
""")

	source = SourceFile(path=report_file, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	sqli_findings = [c for c in candidates if c.rule_id == "FR-SQLI-001"]
	assert len(sqli_findings) == 1
	assert sqli_findings[0].function == "get_data"
	assert "monthly_attendance.py" in sqli_findings[0].file


def test_script_report_parameterized_sql_no_false_positive(tmp_path):
	"""Verify FR-SQLI-001 does NOT fire when script report uses parameterized queries."""
	report_dir = tmp_path / "hrms" / "hr" / "report" / "monthly_attendance"
	report_dir.mkdir(parents=True, exist_ok=True)
	report_file = report_dir / "monthly_attendance.py"
	report_file.write_text("""import frappe

def execute(filters=None):
	return get_columns(), get_data(filters)

def get_columns():
	return ["employee", "status"]

def get_data(filters):
	emp_id = filters.get("employee")
	return frappe.db.sql("select * from `tabAttendance` where employee = %(emp)s", {"emp": emp_id}, as_dict=True)
""")

	source = SourceFile(path=report_file, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	sqli_findings = [c for c in candidates if c.rule_id == "FR-SQLI-001"]
	assert len(sqli_findings) == 0


def test_path_traversal_fr_path_001_vulnerable(tmp_path):
	"""Verify FR-PATH-001 fires on whitelisted endpoint with user-controlled file path."""
	util_dir = tmp_path / "erpnext" / "utilities"
	util_dir.mkdir(parents=True, exist_ok=True)
	util_file = util_dir / "template_viewer.py"
	util_file.write_text("""import frappe
import os

@frappe.whitelist()
def get_template(filename: str):
	path = os.path.join("/var/templates", filename)
	with open(path, "r") as f:
		return f.read()
""")

	source = SourceFile(path=util_file, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	path_findings = [c for c in candidates if c.rule_id == "FR-PATH-001"]
	assert len(path_findings) == 1
	assert path_findings[0].function == "get_template"
	assert "template_viewer.py" in path_findings[0].file


def test_path_traversal_fr_path_001_with_guard_cleared(tmp_path):
	"""Verify FR-PATH-001 does NOT fire when containment check is present."""
	util_dir = tmp_path / "erpnext" / "utilities"
	util_dir.mkdir(parents=True, exist_ok=True)
	util_file = util_dir / "template_viewer.py"
	util_file.write_text("""import frappe
import os

@frappe.whitelist()
def get_template(filename: str):
	base_dir = "/var/templates"
	full_path = os.path.abspath(os.path.join(base_dir, filename))
	if not full_path.startswith(base_dir):
		frappe.throw("Access denied")
	with open(full_path, "r") as f:
		return f.read()
""")

	source = SourceFile(path=util_file, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	path_findings = [c for c in candidates if c.rule_id == "FR-PATH-001"]
	assert len(path_findings) == 0


def test_path_traversal_fr_path_001_with_is_safe_path_guard(tmp_path):
	"""Verify FR-PATH-001 does NOT fire when is_safe_path check is present."""
	util_dir = tmp_path / "erpnext" / "utilities"
	util_dir.mkdir(parents=True, exist_ok=True)
	util_file = util_dir / "template_viewer.py"
	util_file.write_text("""import frappe
import os
from frappe.utils.file_manager import is_safe_path

@frappe.whitelist()
def get_template(filename: str):
	if not is_safe_path(filename):
		frappe.throw("Invalid file path")
	with open(filename, "r") as f:
		return f.read()
""")

	source = SourceFile(path=util_file, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	path_findings = [c for c in candidates if c.rule_id == "FR-PATH-001"]
	assert len(path_findings) == 0


def test_path_traversal_hardcoded_path_no_false_positive(tmp_path):
	"""Verify FR-PATH-001 does NOT fire on hardcoded internal file paths."""
	util_dir = tmp_path / "erpnext" / "utilities"
	util_dir.mkdir(parents=True, exist_ok=True)
	util_file = util_dir / "static_reader.py"
	util_file.write_text("""import frappe
import os

@frappe.whitelist()
def read_system_status():
	with open("/etc/app_version", "r") as f:
		return f.read()
""")

	source = SourceFile(path=util_file, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	path_findings = [c for c in candidates if c.rule_id == "FR-PATH-001"]
	assert len(path_findings) == 0


def test_ghsa_745c_5q8r_vgj2_multihop_script_report_recall(tmp_path):
	"""Verify FR-SQLI-001 detects GHSA-745c-5q8r-vgj2 multi-hop report filter SQL injection."""
	report_dir = tmp_path / "hrms" / "hr" / "report" / "monthly_attendance_sheet"
	report_dir.mkdir(parents=True, exist_ok=True)
	report_file = report_dir / "monthly_attendance_sheet.py"
	report_file.write_text("""import frappe

def execute(filters=None):
	if not filters:
		filters = {}
	return get_columns(filters), get_data(filters)

def get_columns(filters):
	return ["Employee:Link/Employee:120", "Attendance:Data:100"]

def get_data(filters):
	conditions = get_conditions(filters)
	return frappe.db.sql(f"select employee, status from `tabAttendance` where docstatus < 2 {conditions}", as_dict=1)

def get_conditions(filters):
	cond = ""
	if filters.get("company"):
		cond += f" and company = '{filters.get('company')}'"
	return cond
""")

	source = SourceFile(path=report_file, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	sqli_findings = [c for c in candidates if c.rule_id == "FR-SQLI-001"]
	assert len(sqli_findings) == 1
	assert sqli_findings[0].function == "get_data"


def test_talos_2020_1091_synthetic_recall(tmp_path):
	"""Verify FR-PATH-001 detects TALOS-2020-1091 arbitrary file read / deletion."""
	file_dir = tmp_path / "frappe" / "core" / "doctype" / "file"
	file_dir.mkdir(parents=True, exist_ok=True)
	file_py = file_dir / "file.py"
	file_py.write_text("""import frappe
import os

@frappe.whitelist()
def download_file(file_url: str):
	file_path = os.path.join(frappe.get_site_path(), "public", file_url)
	with open(file_path, "rb") as f:
		return f.read()

@frappe.whitelist()
def remove_custom_file(path: str):
	full_path = "/var/uploads/" + path
	os.remove(full_path)
""")

	source = SourceFile(path=file_py, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
	path_findings = [c for c in candidates if c.rule_id == "FR-PATH-001"]
	assert len(path_findings) == 2
	functions = {c.function for c in path_findings}
	assert "download_file" in functions
	assert "remove_custom_file" in functions

