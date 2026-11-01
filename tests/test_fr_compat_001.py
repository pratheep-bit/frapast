"""Tests for FR-COMPAT-001: Deprecated or Removed Frappe Framework API.

Coverage:
  1. Deprecated call removals: frappe.get_single, frappe.db.multisql, frappe.db.sql_ddl (TP)
  2. Server-side client RPC proxy calls: frappe.client.get_list, frappe.client.get (TP)
  3. Deprecated Redis hash cache calls: frappe.cache().hget, hset, hdel (TP)
  4. Removed/deprecated call keyword arguments: is_path=True, user=... (TP)
  5. Refactored internal imports: frappe.desk.form.load (TP)
  6. Deprecated hooks.py configuration: has_website_permission, scheduler_events['all'] (TP)
  7. Modern recommended replacements (TN)
"""
from __future__ import annotations

from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def _scan(tmp_path: Path, code: str, filename: str = "api.py") -> list:
    """Helper to scan a snippet inside an app directory."""
    app_dir = tmp_path / "myapp"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("")
    target_file = app_dir / filename
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
    from scanner.rules.engine import fr_compat_001
    candidates = fr_compat_001(schema, hooks, py_idx, cg)
    return [c for c in candidates if c.rule_id == "FR-COMPAT-001"]


class TestDeprecatedAPITruePositives:
    """Verifies that APIs previously assumed to be deprecated or removed are not flagged
    unless verified against real Frappe branch API change data.
    """

    def test_frappe_get_single_removal(self, tmp_path):
        """frappe.get_single remains re-exported in frappe/__init__.py across v14-v16 and must not be flagged."""
        code = """import frappe

def load_settings():
    return frappe.get_single("System Settings")
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_frappe_db_multisql_removal(self, tmp_path):
        """frappe.db.multisql exists in Frappe Database classes across v14-v16 and must not be flagged."""
        code = """import frappe

def run_query():
    return frappe.db.multisql({"mariadb": "SELECT 1", "postgres": "SELECT 1"})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_frappe_db_sql_ddl_deprecation(self, tmp_path):
        """frappe.db.sql_ddl is not deprecated in Frappe v14-v16 and must not be flagged."""
        code = """import frappe

def alter_schema():
    frappe.db.sql_ddl("ALTER TABLE `tabCustomer` ADD COLUMN custom_code VARCHAR(255)")
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_frappe_client_get_list_server_side(self, tmp_path):
        """frappe.client.get_list is a valid standard API and must not be flagged."""
        code = """import frappe

def fetch_data():
    return frappe.client.get_list("Customer", limit_page_length=10)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_frappe_cache_redis_hash_methods(self, tmp_path):
        """frappe.cache().hget is not tracked as deprecated in branch API change data and must not be flagged."""
        code = """import frappe

def get_cached_val(user):
    return frappe.cache().hget("user_cache", user)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_render_template_is_path_parameter(self, tmp_path):
        """frappe.render_template is not tracked as removed in branch API change data and must not be flagged."""
        code = """import frappe

def render_invoice(doc):
    return frappe.render_template("templates/invoice.html", {"doc": doc}, is_path=True)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_publish_realtime_user_parameter(self, tmp_path):
        """frappe.publish_realtime is not tracked as removed in branch API change data and must not be flagged."""
        code = """import frappe

def notify(msg, recipient):
    frappe.publish_realtime("custom_notification", msg, user=recipient)
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_desk_form_load_import(self, tmp_path):
        """frappe.desk.form.load exists across v14-v16 and must not be flagged."""
        code = """from frappe.desk.form.load import getdoctype

def inspect():
    return getdoctype("Sales Invoice")
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_hooks_has_website_permission(self, tmp_path):
        """has_website_permission in hooks.py is not tracked by branch Python AST diffs and must not be flagged."""
        code = """app_name = "myapp"
has_website_permission = {
    "Web Form": "myapp.permissions.check_web_form"
}
"""
        findings = _scan(tmp_path, code, filename="hooks.py")
        assert len(findings) == 0

    def test_hooks_scheduler_events_all(self, tmp_path):
        """scheduler_events['all'] in hooks.py is not tracked by branch Python AST diffs and must not be flagged."""
        code = """app_name = "myapp"
scheduler_events = {
    "all": [
        "myapp.tasks.sync_every_minute"
    ]
}
"""
        findings = _scan(tmp_path, code, filename="hooks.py")
        assert len(findings) == 0


class TestDeprecatedAPITrueNegatives:
    """FR-COMPAT-001 must NOT fire when modern, supported framework methods are used."""

    def test_modern_get_doc_single_not_flagged(self, tmp_path):
        """Loading a Single DocType via frappe.get_doc must not be flagged."""
        code = """import frappe

def load_settings():
    return frappe.get_doc("System Settings")
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_modern_cache_get_value_not_flagged(self, tmp_path):
        """Using frappe.cache.get_value must not be flagged."""
        code = """import frappe

def get_cached_val(user):
    return frappe.cache.get_value(f"user_cache:{user}")
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_modern_template_rendering_not_flagged(self, tmp_path):
        """Using frappe.get_template().render() must not be flagged."""
        code = """import frappe

def render_invoice(doc):
    return frappe.get_template("templates/invoice.html").render({"doc": doc})
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_modern_publish_realtime_users_list_not_flagged(self, tmp_path):
        """Using users=[recipient] in publish_realtime must not be flagged."""
        code = """import frappe

def notify(msg, recipient):
    frappe.publish_realtime("custom_notification", msg, users=[recipient])
"""
        findings = _scan(tmp_path, code)
        assert len(findings) == 0

    def test_modern_hooks_configuration_not_flagged(self, tmp_path):
        """Modern hooks configuration with has_permission and cron must not be flagged."""
        code = """app_name = "myapp"
has_permission = {
    "Sales Invoice": "myapp.permissions.check_invoice"
}
scheduler_events = {
    "cron": {
        "*/10 * * * *": [
            "myapp.tasks.sync"
        ]
    }
}
"""
        findings = _scan(tmp_path, code, filename="hooks.py")
        assert len(findings) == 0


def test_fr_compat_001_in_all_rules_and_fixture_not_flagged(tmp_path):
    from scanner.rules.engine import ALL_RULES, fr_compat_001
    assert fr_compat_001 in ALL_RULES
    code = 'import frappe\ndef run():\n    return frappe.get_single("System Settings")\n'
    app_dir = tmp_path / "myapp_compat"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("")
    (app_dir / "api.py").write_text(code, encoding="utf-8")
    sources = [SourceFile(app_dir / "__init__.py", tmp_path), SourceFile(app_dir / "api.py", tmp_path)]
    clear_rule_caches()
    py_idx = build_python_index(sources)
    cg = build_call_graph(py_idx)
    schema = build_schema_index([])
    hooks = build_hook_index([])
    candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
    assert not any(c.rule_id == "FR-COMPAT-001" for c in candidates)


