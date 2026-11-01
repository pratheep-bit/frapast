"""Tests for FR-PERM-007: User Permission Filter Bypass / Missing User Permission Guard.

Coverage:
  1. Explicit bypass: ignore_user_permissions=True in whitelisted endpoints (TP)
  2. Implicit bypass: frappe.get_all on multi-tenant DocTypes without strict_user_permissions=True (TP)
  3. Proper user permission enforcement via frappe.get_list (TN)
  4. Proper user permission enforcement via strict_user_permissions=True (TN)
  5. Permission checked prior to get_all (TN)
  6. Non-whitelisted internal queries (TN)
  7. Non-restricted system DocTypes (TN)
"""
from __future__ import annotations

from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def _scan(tmp_path: Path, code: str) -> list:
    """Helper to scan a snippet inside a whitelisted app file."""
    app_dir = tmp_path / "myapp"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("")
    api_file = app_dir / "api.py"
    api_file.write_text(code, encoding="utf-8")

    sources = [
        SourceFile(path=app_dir / "__init__.py", root=tmp_path),
        SourceFile(path=api_file, root=tmp_path),
    ]

    clear_rule_caches()
    py_idx = build_python_index(sources)
    cg = build_call_graph(py_idx)
    schema = build_schema_index([])
    hooks = build_hook_index([])
    candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
    return [c for c in candidates if c.rule_id == "FR-PERM-007"]


class TestUserPermissionTruePositives:
    """FR-PERM-007 must fire on queries bypassing User Permissions in whitelisted paths."""

    def test_explicit_ignore_user_permissions_in_get_list(self, tmp_path):
        """Passing ignore_user_permissions=True in a whitelisted endpoint triggers FR-PERM-007."""
        code = """import frappe

@frappe.whitelist()
def get_invoices():
    return frappe.get_list("Sales Invoice", filters={"docstatus": 1}, ignore_user_permissions=True)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) >= 1
        assert any("ignore_user_permissions=True" in f.evidence for f in findings)

    def test_explicit_ignore_user_permissions_integer(self, tmp_path):
        """Passing ignore_user_permissions=1 in a whitelisted endpoint triggers FR-PERM-007."""
        code = """import frappe

@frappe.whitelist()
def fetch_company_info(name):
    return frappe.db.get_value("Company", name, "tax_id", ignore_user_permissions=1)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) >= 1

    def test_get_all_on_multi_tenant_doctype_without_strict_user_permissions(self, tmp_path):
        """frappe.get_all on multi-tenant DocType without strict_user_permissions triggers FR-PERM-007."""
        code = """import frappe

@frappe.whitelist()
def list_employees():
    return frappe.get_all("Employee", fields=["name", "employee_name", "department"])
"""
        findings = _scan(tmp_path, code)
        assert len(findings) >= 1
        assert any("Employee" in f.evidence for f in findings)

    def test_get_all_sales_invoices(self, tmp_path):
        """frappe.get_all on Sales Invoice in whitelisted endpoint triggers FR-PERM-007."""
        code = """import frappe

@frappe.whitelist()
def get_customer_invoices():
    return frappe.get_all("Sales Invoice", filters={"customer": "CUST-001"})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) >= 1
        assert any("Sales Invoice" in f.evidence for f in findings)


class TestUserPermissionTrueNegatives:
    """FR-PERM-007 must NOT fire on safe or properly guarded queries."""

    def test_standard_get_list_not_flagged(self, tmp_path):
        """Standard frappe.get_list enforces user permissions natively and must not be flagged."""
        code = """import frappe

@frappe.whitelist()
def get_invoices():
    return frappe.get_list("Sales Invoice", filters={"docstatus": 1})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_get_all_with_strict_user_permissions_not_flagged(self, tmp_path):
        """frappe.get_all with strict_user_permissions=True enforces permissions and must not be flagged."""
        code = """import frappe

@frappe.whitelist()
def get_invoices():
    return frappe.get_all("Sales Invoice", strict_user_permissions=True)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_get_all_with_explicit_permission_check_not_flagged(self, tmp_path):
        """Calling frappe.has_permission before get_all guards the operation and must not be flagged."""
        code = """import frappe

@frappe.whitelist()
def get_invoices():
    if not frappe.has_permission("Sales Invoice", "read"):
        frappe.throw("Not permitted", frappe.PermissionError)
    return frappe.get_all("Sales Invoice")
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_non_whitelisted_function_not_flagged(self, tmp_path):
        """Internal background or helper functions not exposed to RPC are not flagged."""
        code = """import frappe

def internal_sync():
    return frappe.get_all("Sales Invoice", ignore_user_permissions=True)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_non_restricted_doctype_not_flagged(self, tmp_path):
        """Querying system/metadata DocTypes not subject to user permissions is not flagged."""
        code = """import frappe

@frappe.whitelist()
def get_system_doctypes():
    return frappe.get_all("DocType", filters={"istable": 0})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_schema_doctype_with_fields_triggers_perm_007(self, tmp_path):
        """DocType with fields must not crash fr_perm_007 and must flag get_all on user-perm doctype."""
        import json
        from scanner.schema.engine import discover_doctype_json, build_schema_index
        app_dir = tmp_path / "myapp"
        dt_dir = app_dir / "doctype" / "custom_project"
        dt_dir.mkdir(parents=True, exist_ok=True)
        (dt_dir / "custom_project.json").write_text(json.dumps({
            "doctype": "DocType",
            "name": "Custom Project",
            "module": "Myapp",
            "fields": [
                {"fieldname": "company", "fieldtype": "Link", "options": "Company"},
                {"fieldname": "project_name", "fieldtype": "Data"},
            ],
        }), encoding="utf-8")

        (app_dir / "__init__.py").write_text("")
        api_file = app_dir / "api.py"
        api_file.write_text("""import frappe

@frappe.whitelist()
def list_projects():
    return frappe.get_all("Custom Project")
""", encoding="utf-8")

        sources = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=api_file, root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(sources)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = build_hook_index([])
        candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
        perm_findings = [c for c in candidates if c.rule_id == "FR-PERM-007"]
        assert len(perm_findings) == 1
        assert "Custom Project" in perm_findings[0].evidence

    def test_schema_doctype_with_fields_get_list_not_flagged(self, tmp_path):
        """DocType with fields queried via get_list must not be flagged."""
        import json
        from scanner.schema.engine import discover_doctype_json, build_schema_index
        app_dir = tmp_path / "myapp"
        dt_dir = app_dir / "doctype" / "custom_project"
        dt_dir.mkdir(parents=True, exist_ok=True)
        (dt_dir / "custom_project.json").write_text(json.dumps({
            "doctype": "DocType",
            "name": "Custom Project",
            "module": "Myapp",
            "fields": [
                {"fieldname": "company", "fieldtype": "Link", "options": "Company"},
                {"fieldname": "project_name", "fieldtype": "Data"},
            ],
        }), encoding="utf-8")

        (app_dir / "__init__.py").write_text("")
        api_file = app_dir / "api.py"
        api_file.write_text("""import frappe

@frappe.whitelist()
def list_projects():
    return frappe.get_list("Custom Project")
""", encoding="utf-8")

        sources = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=api_file, root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(sources)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = build_hook_index([])
        candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
        perm_findings = [c for c in candidates if c.rule_id == "FR-PERM-007"]
        assert len(perm_findings) == 0


