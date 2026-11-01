"""Tests for FR-PERF-003: Unbounded Transaction Scan in Report.

Coverage:
  1. SQL query on heavy table (tabGL Entry) in Script Report lacking date filters or LIMIT (TP).
  2. frappe.get_all on heavy table (Attendance) in Script Report lacking date filters (TP).
  3. SQL query bounded by posting_date BETWEEN clause (TN).
  4. SQL query bounded by explicit LIMIT clause (TN).
  5. frappe.get_all bounded by attendance_date filter (TN).
  6. Query on heavy table outside report paths (TN).
  7. Query on light non-transactional table in Script Report (TN).
"""
from __future__ import annotations

from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def _scan(tmp_path: Path, code: str, filename: str = "report/financial_analytics/financial_analytics.py") -> list:
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
    schema = build_schema_index([])
    hooks = build_hook_index([])
    candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
    return [c for c in candidates if c.rule_id == "FR-PERF-003"]


class TestUnboundedScanTruePositives:
    """FR-PERF-003 must flag unbounded transactional queries in report files."""

    def test_unbounded_sql_on_gl_entry_in_report(self, tmp_path):
        """Querying tabGL Entry in a Script Report without date bounds or LIMIT must be flagged."""
        code = """import frappe

def execute(filters=None):
    return frappe.db.sql('''
        SELECT name, account, debit, credit
        FROM `tabGL Entry`
        WHERE voucher_type = 'Sales Invoice'
    ''', as_dict=True)
"""
        findings = _scan(tmp_path, code, filename="report/gl_analytics/gl_analytics.py")
        assert len(findings) == 1
        assert "tabGL Entry" in findings[0].evidence

    def test_unbounded_get_all_on_attendance_in_report(self, tmp_path):
        """Scanning Attendance DocType in a report without date bounds must be flagged."""
        code = """import frappe

def execute(filters=None):
    return frappe.get_all("Attendance", filters={"status": "Present"}, fields=["name", "employee"])
"""
        findings = _scan(tmp_path, code, filename="report/attendance_report/attendance_report.py")
        assert len(findings) == 1
        assert "Attendance" in findings[0].evidence


class TestUnboundedScanTrueNegatives:
    """FR-PERF-003 must not flag properly bounded queries or non-transactional lookups."""

    def test_sql_with_date_range_not_flagged(self, tmp_path):
        """SQL queries filtering on posting_date BETWEEN are bounded."""
        code = """import frappe

def execute(filters=None):
    return frappe.db.sql('''
        SELECT name, account, debit, credit
        FROM `tabGL Entry`
        WHERE posting_date BETWEEN %(from_date)s AND %(to_date)s
    ''', filters, as_dict=True)
"""
        findings = _scan(tmp_path, code, filename="report/gl_summary/gl_summary.py")
        assert len(findings) == 0

    def test_sql_with_limit_clause_not_flagged(self, tmp_path):
        """SQL queries with explicit LIMIT are bounded."""
        code = """import frappe

def execute(filters=None):
    return frappe.db.sql('''
        SELECT * FROM `tabStock Ledger Entry`
        WHERE item_code = %s
        ORDER BY creation DESC
        LIMIT 500
    ''', (filters.get('item_code'),), as_dict=True)
"""
        findings = _scan(tmp_path, code, filename="report/sle_trace/sle_trace.py")
        assert len(findings) == 0

    def test_get_all_with_date_filter_not_flagged(self, tmp_path):
        """get_all calls with attendance_date filter are bounded."""
        code = """import frappe

def execute(filters=None):
    return frappe.get_all(
        "Attendance",
        filters={"attendance_date": ["between", ["2026-01-01", "2026-01-31"]]},
        fields=["employee", "status"]
    )
"""
        findings = _scan(tmp_path, code, filename="report/monthly_att/monthly_att.py")
        assert len(findings) == 0

    def test_heavy_table_outside_report_not_flagged(self, tmp_path):
        """Queries on heavy tables in controllers/tasks are evaluated under normal rules, not FR-PERF-003."""
        code = """import frappe

def process_daily_attendance():
    return frappe.get_all("Attendance", filters={"status": "Present"})
"""
        findings = _scan(tmp_path, code, filename="tasks/attendance_task.py")
        assert len(findings) == 0

    def test_light_doctype_query_in_report_not_flagged(self, tmp_path):
        """Queries on non-transactional DocTypes (User, Role, Company) are not flagged."""
        code = """import frappe

def execute(filters=None):
    return frappe.get_all("User", filters={"enabled": 1}, fields=["name", "email"])
"""
        findings = _scan(tmp_path, code, filename="report/active_users/active_users.py")
        assert len(findings) == 0
