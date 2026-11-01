"""Tests for FR-PERF-002: Unindexed Filter in Query/Report.

Coverage:
  1. Filter on DocType field without index in frappe.get_all / frappe.get_list (TP).
  2. Filter on Link / Check fields with native automatic index (TN).
  3. Filter on fields with search_index, in_standard_filter, or db_index (TN).
  4. Filter on standard framework indexed columns: name, creation, docstatus (TN).
  5. Queries in test files / non-runtime paths (TN).
"""
from __future__ import annotations

from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import SchemaIndex
from scanner.schema.models import DocTypeRecord, FieldRecord
from scanner.shared import SourceFile


def _build_test_schema() -> SchemaIndex:
    dt = DocTypeRecord(
        name="Sales Invoice",
        module="Accounts",
        path=Path("/tmp/sales_invoice.json"),
        table_name="tabSales Invoice",
        fields=(
            FieldRecord(fieldname="customer", fieldtype="Link", options="Customer"),
            FieldRecord(fieldname="is_return", fieldtype="Check"),
            FieldRecord(fieldname="status", fieldtype="Select", in_standard_filter=True),
            FieldRecord(fieldname="remarks", fieldtype="Small Text", search_index=True),
            FieldRecord(fieldname="custom_tracking_code", fieldtype="Data", db_index=True),
            FieldRecord(fieldname="custom_notes", fieldtype="Data"),
            FieldRecord(fieldname="tax_id", fieldtype="Data"),
        ),
        is_submittable=True,
        istable=False,
    )
    return SchemaIndex(doctypes=(dt,))


def _scan(tmp_path: Path, code: str, filename: str = "queries.py") -> list:
    app_dir = tmp_path / "myapp"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("")
    target_file = app_dir / filename
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(code, encoding="utf-8")

    sources = [
        SourceFile(path=app_dir / "__init__.py", root=tmp_path),
        SourceFile(path=target_file, root=tmp_path),
    ]

    clear_rule_caches()
    py_idx = build_python_index(sources)
    cg = build_call_graph(py_idx)
    schema = _build_test_schema()
    hooks = build_hook_index([])
    candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
    return [c for c in candidates if c.rule_id == "FR-PERF-002"]


class TestUnindexedFilterTruePositives:
    """FR-PERF-002 must flag query filters on fields lacking database indexes."""

    def test_filter_dict_on_unindexed_field(self, tmp_path):
        """Filtering by custom_notes without an index triggers full table scan."""
        code = """import frappe

def search_by_note(note):
    return frappe.get_all("Sales Invoice", filters={"custom_notes": note})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 1
        assert "custom_notes" in findings[0].evidence
        assert "Sales Invoice" in findings[0].evidence

    def test_filter_list_on_unindexed_field(self, tmp_path):
        """Filtering by tax_id in list-of-lists format triggers full table scan."""
        code = """import frappe

def search_by_tax(tax_id):
    return frappe.get_list("Sales Invoice", filters=[["tax_id", "=", tax_id]])
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 1
        assert "tax_id" in findings[0].evidence


class TestUnindexedFilterTrueNegatives:
    """FR-PERF-002 must not flag filters on fields with valid database indexes."""

    def test_filter_on_link_field_not_flagged(self, tmp_path):
        """Link fields are indexed by Frappe core schema generator."""
        code = """import frappe

def get_customer_invoices(customer):
    return frappe.get_all("Sales Invoice", filters={"customer": customer})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_filter_on_check_field_not_flagged(self, tmp_path):
        """Check (boolean) fields are automatically indexed."""
        code = """import frappe

def get_returns():
    return frappe.get_all("Sales Invoice", filters={"is_return": 1})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_filter_on_in_standard_filter_not_flagged(self, tmp_path):
        """Fields with in_standard_filter=True are indexed."""
        code = """import frappe

def get_draft_invoices():
    return frappe.get_all("Sales Invoice", filters={"status": "Draft"})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_filter_on_db_index_field_not_flagged(self, tmp_path):
        """Fields with explicit db_index=True are indexed."""
        code = """import frappe

def get_by_tracking(code):
    return frappe.get_all("Sales Invoice", filters={"custom_tracking_code": code})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_filter_on_standard_framework_columns_not_flagged(self, tmp_path):
        """Framework-managed columns (name, docstatus, modified) are indexed."""
        code = """import frappe

def get_active(name):
    return frappe.get_all("Sales Invoice", filters={"name": name, "docstatus": 1})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_non_runtime_file_exempt(self, tmp_path):
        """Test suites are exempt from performance index checks."""
        code = """import frappe

def test_query():
    return frappe.get_all("Sales Invoice", filters={"custom_notes": "test"})
"""
        findings = _scan(tmp_path, code, filename="tests/test_queries.py")
        assert len(findings) == 0
