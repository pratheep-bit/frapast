"""Tests for FR-DATA-002: Direct Ledger Mutation Guard.

Coverage:
  1. Direct raw SQL mutations on tabGL Entry and tabStock Ledger Entry (TP).
  2. Direct frappe.db.set_value on GL Entry and Stock Ledger Entry (TP).
  3. Legitimate postings in general_ledger.py / stock_ledger.py (TN).
  4. Legitimate postings in make_gl_entries / make_sl_entries functions (TN).
  5. Read-only SQL queries on ledger tables (TN).
  6. Non-ledger DocType mutations (TN).
  7. Patches and test files (TN).
"""
from __future__ import annotations

from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def _scan(tmp_path: Path, code: str, filename: str = "ledger_ops.py") -> list:
    """Helper to scan a snippet inside an app directory."""
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
    return [c for c in candidates if c.rule_id == "FR-DATA-002"]


class TestLedgerMutationTruePositives:
    """FR-DATA-002 must flag direct modifications to GL and Stock Ledger tables."""

    def test_raw_sql_insert_gl_entry(self, tmp_path):
        """Direct SQL INSERT INTO tabGL Entry must be flagged."""
        code = """import frappe

def custom_post_entry(account, debit, credit):
    frappe.db.sql('''
        INSERT INTO `tabGL Entry` (name, account, debit, credit, posting_date)
        VALUES ('GLE-001', %(account)s, %(debit)s, %(credit)s, '2026-01-01')
    ''', {'account': account, 'debit': debit, 'credit': credit})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 1
        assert "tabGL Entry" in findings[0].evidence

    def test_raw_sql_update_stock_ledger(self, tmp_path):
        """Direct SQL UPDATE on tabStock Ledger Entry must be flagged."""
        code = """import frappe

def fix_valuation(item_code, new_rate):
    frappe.db.sql('''
        UPDATE `tabStock Ledger Entry`
        SET valuation_rate = %s
        WHERE item_code = %s
    ''', (new_rate, item_code))
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 1
        assert "tabStock Ledger Entry" in findings[0].evidence

    def test_raw_sql_delete_gl_entry(self, tmp_path):
        """Direct SQL DELETE FROM tabGL Entry must be flagged."""
        code = """import frappe

def purge_gl_record(voucher_no):
    frappe.db.sql('DELETE FROM `tabGL Entry` WHERE voucher_no = %s', (voucher_no,))
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 1
        assert "tabGL Entry" in findings[0].evidence

    def test_set_value_on_gl_entry(self, tmp_path):
        """frappe.db.set_value directly on GL Entry must be flagged."""
        code = """import frappe

def update_voucher_reference(entry_name, ref_no):
    frappe.db.set_value("GL Entry", entry_name, "remarks", ref_no)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 1
        assert "GL Entry" in findings[0].evidence

    def test_set_value_on_stock_ledger_entry(self, tmp_path):
        """frappe.db.set_value directly on Stock Ledger Entry must be flagged."""
        code = """import frappe

def adjust_qty(sle_name, qty):
    frappe.db.set_value("Stock Ledger Entry", sle_name, "qty_after_transaction", qty)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 1
        assert "Stock Ledger Entry" in findings[0].evidence


class TestLedgerMutationTrueNegatives:
    """FR-DATA-002 must not flag official posting pipelines or read operations."""

    def test_official_general_ledger_file_exempt(self, tmp_path):
        """SQL writes in general_ledger.py are part of official posting routines."""
        code = """import frappe

def post_gl():
    frappe.db.sql("INSERT INTO `tabGL Entry` (name) VALUES ('GLE-1')")
"""
        findings = _scan(tmp_path, code, filename="general_ledger.py")
        assert len(findings) == 0

    def test_official_stock_ledger_file_exempt(self, tmp_path):
        """SQL writes in stock_ledger.py are part of official posting routines."""
        code = """import frappe

def update_sle():
    frappe.db.sql("UPDATE `tabStock Ledger Entry` SET stock_value = 100")
"""
        findings = _scan(tmp_path, code, filename="stock_ledger.py")
        assert len(findings) == 0

    def test_official_make_gl_entries_function_exempt(self, tmp_path):
        """make_gl_entries function is the standard ERPNext GL pipeline."""
        code = """import frappe

def make_gl_entries(gl_map):
    frappe.db.sql("INSERT INTO `tabGL Entry` (name) VALUES ('GLE-1')")
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_read_only_sql_query_not_flagged(self, tmp_path):
        """SELECT queries on tabGL Entry do not mutate data and must not be flagged."""
        code = """import frappe

def get_ledger_balance(account):
    return frappe.db.sql(
        'SELECT SUM(debit) - SUM(credit) FROM `tabGL Entry` WHERE account = %s',
        (account,)
    )
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_mutation_on_non_ledger_doctype_not_flagged(self, tmp_path):
        """Mutations on standard non-ledger DocTypes are governed by other rules, not FR-DATA-002."""
        code = """import frappe

def update_customer_name(name, new_name):
    frappe.db.set_value("Customer", name, "customer_name", new_name)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_patch_file_exempt(self, tmp_path):
        """Database migrations / patches are exempt from ledger mutation guard."""
        code = """import frappe

def execute():
    frappe.db.sql("UPDATE `tabGL Entry` SET is_cancelled = 0 WHERE is_cancelled IS NULL")
"""
        findings = _scan(tmp_path, code, filename="patches/v14_fix_gl.py")
        assert len(findings) == 0
