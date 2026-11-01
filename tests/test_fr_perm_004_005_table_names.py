"""Tests for table-name extraction in FR-PERM-004 and FR-PERM-005.

Verifies that multi-word DocTypes with spaces (such as 'Sales Invoice' and
'Salary Structure Assignment') and backticked table names are correctly matched.
"""
from __future__ import annotations

import json
from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.hooks.models import HookIndex
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.rules.engine import fr_perm_004, fr_perm_005
from scanner.schema import build_schema_index
from scanner.schema.engine import discover_doctype_json
from scanner.shared import SourceFile


def _setup_app_and_schema(tmp_path: Path, doctypes: list[str]) -> tuple[Path, list[SourceFile]]:
    app_dir = tmp_path / "testapp"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("", encoding="utf-8")

    for dt_name in doctypes:
        dt_slug = dt_name.lower().replace(" ", "_")
        dt_dir = app_dir / "doctype" / dt_slug
        dt_dir.mkdir(parents=True, exist_ok=True)
        (dt_dir / f"{dt_slug}.json").write_text(json.dumps({
            "doctype": "DocType",
            "name": dt_name,
            "module": "TestApp",
            "fields": [
                {"fieldname": "company", "fieldtype": "Link", "options": "Company"},
            ],
        }), encoding="utf-8")

    return app_dir


class TestFrPerm004TableNames:
    """FR-PERM-004 must match backticked and multi-word DocTypes in script reports."""

    def test_sales_invoice_multi_word_doctype_fires(self, tmp_path):
        """DocType with spaces 'Sales Invoice' must trigger FR-PERM-004 when hook is present."""
        app_dir = _setup_app_and_schema(tmp_path, ["Sales Invoice"])
        rep_dir = app_dir / "report" / "sales_report"
        rep_dir.mkdir(parents=True, exist_ok=True)
        (rep_dir / "sales_report.py").write_text("""import frappe

def execute(filters=None):
    return [], frappe.db.sql("SELECT name FROM `tabSales Invoice`")
""", encoding="utf-8")

        py_files = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=rep_dir / "sales_report.py", root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(py_files)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = HookIndex(
            handlers=(),
            permission_query_conditions={"Sales Invoice": "testapp.hooks.get_conditions"},
            has_permission={},
            unresolved=(),
        )

        candidates = fr_perm_004(schema, hooks, py_idx, cg)
        assert len(candidates) == 1
        assert "Sales Invoice" in candidates[0].evidence

    def test_single_word_customer_fires(self, tmp_path):
        """Single-word DocType 'Customer' must continue to trigger FR-PERM-004."""
        app_dir = _setup_app_and_schema(tmp_path, ["Customer"])
        rep_dir = app_dir / "report" / "customer_report"
        rep_dir.mkdir(parents=True, exist_ok=True)
        (rep_dir / "customer_report.py").write_text("""import frappe

def execute(filters=None):
    return [], frappe.db.sql("SELECT name FROM `tabCustomer`")
""", encoding="utf-8")

        py_files = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=rep_dir / "customer_report.py", root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(py_files)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = HookIndex(
            handlers=(),
            permission_query_conditions={"Customer": "testapp.hooks.get_customer_conditions"},
            has_permission={},
            unresolved=(),
        )

        candidates = fr_perm_004(schema, hooks, py_idx, cg)
        assert len(candidates) == 1
        assert "Customer" in candidates[0].evidence

    def test_negative_report_does_not_touch_protected_table(self, tmp_path):
        """Report querying an unrelated table must not trigger FR-PERM-004."""
        app_dir = _setup_app_and_schema(tmp_path, ["Sales Invoice", "Item"])
        rep_dir = app_dir / "report" / "item_report"
        rep_dir.mkdir(parents=True, exist_ok=True)
        (rep_dir / "item_report.py").write_text("""import frappe

def execute(filters=None):
    return [], frappe.db.sql("SELECT name FROM `tabItem`")
""", encoding="utf-8")

        py_files = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=rep_dir / "item_report.py", root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(py_files)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = HookIndex(
            handlers=(),
            permission_query_conditions={"Sales Invoice": "testapp.hooks.get_conditions"},
            has_permission={},
            unresolved=(),
        )

        candidates = fr_perm_004(schema, hooks, py_idx, cg)
        assert len(candidates) == 0

    def test_three_word_doctype_salary_structure_assignment(self, tmp_path):
        """Three-word DocType 'Salary Structure Assignment' must be matched."""
        app_dir = _setup_app_and_schema(tmp_path, ["Salary Structure Assignment"])
        rep_dir = app_dir / "report" / "salary_report"
        rep_dir.mkdir(parents=True, exist_ok=True)
        (rep_dir / "salary_report.py").write_text("""import frappe

def execute(filters=None):
    return [], frappe.db.sql("SELECT name FROM `tabSalary Structure Assignment`")
""", encoding="utf-8")

        py_files = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=rep_dir / "salary_report.py", root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(py_files)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = HookIndex(
            handlers=(),
            permission_query_conditions={"Salary Structure Assignment": "testapp.hooks.get_ssa_conditions"},
            has_permission={},
            unresolved=(),
        )

        candidates = fr_perm_004(schema, hooks, py_idx, cg)
        assert len(candidates) == 1
        assert "Salary Structure Assignment" in candidates[0].evidence

    def test_backticked_multi_word_does_not_falsely_match_prefix_doctype(self, tmp_path):
        """Query on `tabSales Invoice` must not match `Sales` (table tabSales) via word splitting."""
        app_dir = _setup_app_and_schema(tmp_path, ["Sales", "Sales Invoice"])
        rep_dir = app_dir / "report" / "invoice_report"
        rep_dir.mkdir(parents=True, exist_ok=True)
        (rep_dir / "invoice_report.py").write_text("""import frappe

def execute(filters=None):
    return [], frappe.db.sql("SELECT name FROM `tabSales Invoice`")
""", encoding="utf-8")

        py_files = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=rep_dir / "invoice_report.py", root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(py_files)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = HookIndex(
            handlers=(),
            permission_query_conditions={"Sales": "testapp.hooks.get_sales_conditions"},
            has_permission={},
            unresolved=(),
        )

        candidates = fr_perm_004(schema, hooks, py_idx, cg)
        assert len(candidates) == 0, f"Expected 0 findings for Sales, got: {[c.evidence for c in candidates]}"


class TestFrPerm005TableNames:
    """FR-PERM-005 must match multi-word DocTypes in raw queries bypassing has_permission."""

    def test_multi_word_doctype_has_permission_bypass(self, tmp_path):
        """Internal query on 'Sales Invoice' must trigger FR-PERM-005 when has_permission is registered."""
        app_dir = _setup_app_and_schema(tmp_path, ["Sales Invoice"])
        api_file = app_dir / "api.py"
        api_file.write_text("""import frappe

@frappe.whitelist()
def fetch_invoices():
    return frappe.db.sql("SELECT name FROM `tabSales Invoice`")
""", encoding="utf-8")

        py_files = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=api_file, root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(py_files)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = HookIndex(
            handlers=(),
            permission_query_conditions={},
            has_permission={"Sales Invoice": "testapp.hooks.check_has_perm"},
            unresolved=(),
        )

        candidates = fr_perm_005(schema, hooks, py_idx, cg)
        assert len(candidates) == 1
        assert "Sales Invoice" in candidates[0].evidence

    def test_backticked_multi_word_does_not_falsely_match_prefix_doctype_perm_005(self, tmp_path):
        """Query on `tabSales Invoice` must not match `Sales` (table tabSales) in FR-PERM-005."""
        app_dir = _setup_app_and_schema(tmp_path, ["Sales", "Sales Invoice"])
        api_file = app_dir / "api.py"
        api_file.write_text("""import frappe

@frappe.whitelist()
def fetch_invoices():
    return frappe.db.sql("SELECT name FROM `tabSales Invoice`")
""", encoding="utf-8")

        py_files = [
            SourceFile(path=app_dir / "__init__.py", root=tmp_path),
            SourceFile(path=api_file, root=tmp_path),
        ]
        clear_rule_caches()
        py_idx = build_python_index(py_files)
        cg = build_call_graph(py_idx)
        schema = build_schema_index(discover_doctype_json(app_dir))
        hooks = HookIndex(
            handlers=(),
            permission_query_conditions={},
            has_permission={"Sales": "testapp.hooks.sales_has_permission"},
            unresolved=(),
        )

        candidates = fr_perm_005(schema, hooks, py_idx, cg)
        assert len(candidates) == 0, f"Expected 0 findings for Sales, got: {[c.evidence for c in candidates]}"

