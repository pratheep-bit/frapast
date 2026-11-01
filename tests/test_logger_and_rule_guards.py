"""Regression and guard tests for logger streams, output purity, and rule execution guards."""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.logger import get_logger, logger
from scanner.python import build_python_index
from scanner.rules import ALL_RULES, clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.schema.engine import discover_doctype_json
from scanner.shared import SourceFile


def test_logger_stream_is_stderr():
    """Central scanner logger must write to sys.stderr, not sys.stdout."""
    log = get_logger("scanner")
    assert len(log.handlers) >= 1
    assert isinstance(log.handlers[0], logging.StreamHandler)
    assert log.handlers[0].stream is sys.stderr


def test_scan_format_json_with_rule_exception_leaves_stdout_clean(tmp_path, monkeypatch):
    """When a rule raises an exception during scan, warning goes to stderr and stdout is valid JSON."""
    app_dir = tmp_path / "mock_app"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (app_dir / "api.py").write_text("import frappe\n\n@frappe.whitelist()\ndef ping():\n    return 'pong'\n", encoding="utf-8")

    # Run CLI in subprocess with a rule failure triggered via environment or code
    cmd = [
        sys.executable,
        "-m",
        "scanner.cli",
        "scan",
        str(app_dir),
        "--format",
        "json",
    ]
    # We test with a helper script that forces a broken rule in ALL_RULES
    driver = f"""
import sys
from scanner.rules import engine
orig_rules = engine.ALL_RULES
def broken_rule(schema, hooks, python, graph):
    raise RuntimeError("Intentional test rule failure")
engine.ALL_RULES = (broken_rule,) + orig_rules
from scanner.cli import main
sys.exit(main(['scan', {repr(str(app_dir))}, '--format', 'json']))
"""
    res = subprocess.run([sys.executable, "-c", driver], capture_output=True, text=True)
    assert "Intentional test rule failure" in res.stderr
    assert "WARNING" not in res.stdout
    parsed = json.loads(res.stdout)
    assert "candidates" in parsed


def test_scan_format_sarif_with_rule_exception_leaves_stdout_clean(tmp_path):
    """When a rule raises an exception, --format sarif stdout is valid SARIF JSON."""
    app_dir = tmp_path / "mock_app"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (app_dir / "api.py").write_text("import frappe\n", encoding="utf-8")

    driver = f"""
import sys
from scanner.rules import engine
orig_rules = engine.ALL_RULES
def broken_rule(schema, hooks, python, graph):
    raise RuntimeError("Intentional sarif test failure")
engine.ALL_RULES = (broken_rule,) + orig_rules
from scanner.cli import main
sys.exit(main(['scan', {repr(str(app_dir))}, '--format', 'sarif']))
"""
    res = subprocess.run([sys.executable, "-c", driver], capture_output=True, text=True)
    assert "Intentional sarif test failure" in res.stderr
    assert "WARNING" not in res.stdout
    parsed = json.loads(res.stdout)
    assert parsed.get("version") == "2.1.0"
    assert "runs" in parsed


def test_no_rule_raises_on_rich_fixture(tmp_path, caplog):
    """Guard: ALL_RULES executed against a rich fixture app must produce zero exceptions/warnings."""
    app_dir = tmp_path / "rich_app"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("", encoding="utf-8")

    # 1. DocType with fields
    dt_dir = app_dir / "doctype" / "custom_invoice"
    dt_dir.mkdir(parents=True, exist_ok=True)
    (dt_dir / "custom_invoice.json").write_text(json.dumps({
        "doctype": "DocType",
        "name": "Custom Invoice",
        "module": "RichApp",
        "is_submittable": 1,
        "istable": 0,
        "fields": [
            {"fieldname": "company", "fieldtype": "Link", "options": "Company"},
            {"fieldname": "grand_total", "fieldtype": "Currency"},
            {"fieldname": "status", "fieldtype": "Select"},
        ],
        "permissions": [{"role": "System Manager", "read": 1, "write": 1}],
    }), encoding="utf-8")

    # 2. Child table DocType
    child_dir = app_dir / "doctype" / "custom_invoice_item"
    child_dir.mkdir(parents=True, exist_ok=True)
    (child_dir / "custom_invoice_item.json").write_text(json.dumps({
        "doctype": "DocType",
        "name": "Custom Invoice Item",
        "module": "RichApp",
        "is_submittable": 0,
        "istable": 1,
        "fields": [
            {"fieldname": "item_code", "fieldtype": "Link", "options": "Item"},
            {"fieldname": "amount", "fieldtype": "Currency"},
        ],
    }), encoding="utf-8")

    # 3. Python code with whitelisted endpoints, commit in hook, queries
    api_file = app_dir / "api.py"
    api_file.write_text("""import frappe

@frappe.whitelist()
def mutate_invoice(docname):
    frappe.db.set_value("Custom Invoice", docname, "status", "Paid")

@frappe.whitelist(allow_guest=True)
def guest_read():
    return frappe.get_all("Custom Invoice", fields=["name"])

def lifecycle_hook(doc, method):
    frappe.db.commit()
""", encoding="utf-8")

    # 4. Script report
    rep_dir = app_dir / "report" / "rich_report"
    rep_dir.mkdir(parents=True, exist_ok=True)
    (rep_dir / "rich_report.py").write_text("""import frappe

def execute(filters=None):
    return [], frappe.db.sql("SELECT name FROM `tabCustom Invoice`")
""", encoding="utf-8")

    # 5. Hooks
    (app_dir / "hooks.py").write_text("""
doc_events = {
    "Custom Invoice": {
        "on_submit": "rich_app.api.lifecycle_hook"
    }
}
permission_query_conditions = {
    "Custom Invoice": "rich_app.security.get_conditions"
}
""", encoding="utf-8")

    py_files = [
        SourceFile(path=app_dir / "__init__.py", root=tmp_path),
        SourceFile(path=api_file, root=tmp_path),
        SourceFile(path=rep_dir / "rich_report.py", root=tmp_path),
        SourceFile(path=app_dir / "hooks.py", root=tmp_path),
    ]

    clear_rule_caches()
    py_idx = build_python_index(py_files)
    cg = build_call_graph(py_idx)
    schema = build_schema_index(discover_doctype_json(app_dir))
    hooks = build_hook_index([SourceFile(path=app_dir / "hooks.py", root=tmp_path)])

    with caplog.at_level(logging.WARNING, logger="scanner"):
        candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)

    unexpected_errors = [
        record.message for record in caplog.records
        if "raised an unexpected exception" in record.message
    ]
    assert unexpected_errors == [], f"Rules raised unexpected exceptions: {unexpected_errors}"
    assert len(candidates) > 0


def test_cli_human_output_warns_on_skipped_rules(tmp_path):
    """In CLI human output only, print summary warning to stderr if rules were skipped."""
    app_dir = tmp_path / "mock_app"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (app_dir / "api.py").write_text("import frappe\n", encoding="utf-8")

    driver = f"""
import sys
from scanner.rules import engine
orig_rules = engine.ALL_RULES
def broken_rule1(schema, hooks, python, graph):
    raise RuntimeError("Fail 1")
def broken_rule2(schema, hooks, python, graph):
    raise RuntimeError("Fail 2")
engine.ALL_RULES = (broken_rule1, broken_rule2) + orig_rules
from scanner.cli import main
sys.exit(main(['scan', {repr(str(app_dir))}, '--format', 'human']))
"""
    res = subprocess.run([sys.executable, "-c", driver], capture_output=True, text=True)
    assert "Warning: 2 rule(s) were skipped due to internal errors. Run with --log-level debug for details." in res.stderr

