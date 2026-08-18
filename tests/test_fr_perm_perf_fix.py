"""Tests for FR-PERM-001 and FR-PERF-001 precision fixes.

FR-PERM-001 fixes:
- Recognizes instance method permission checks (self.check_permission, doc.check_permission, *.has_permission)
- Recognizes throw/raise with frappe.PermissionError
- Recognizes session.user scoped functions (frappe.session.user, get_current_employee)
- Excludes functions decorated with @frappe.validate_and_sanitize_search_inputs

FR-PERF-001 fixes:
- Excludes test files, patch files, and setup scripts via _is_non_runtime_path
- Excludes in-memory dict construction (frappe.get_doc(dict(...)) or frappe.get_doc({"doctype": ...}))
"""
import tempfile
import textwrap
from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def _run_rules_on_code(src: str, rel_path: str = "app/api.py") -> list:
    clear_rule_caches()
    content = textwrap.dedent(src)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        sf = SourceFile(path=p, root=Path(td))
        py_idx = build_python_index([sf])
        cg = build_call_graph(py_idx)
        schema = build_schema_index([])
        hooks = build_hook_index([])
        return execute_rules(schema=schema, hooks=hooks, python=py_idx, call_graph=cg)


class TestFRPERM001Fixes:
    def test_tp_missing_permission_check_fires(self):
        """Whitelisted function with no permission checks must fire FR-PERM-001."""
        src = """
        import frappe

        @frappe.whitelist()
        def get_all_secrets():
            return frappe.db.sql("select * from `tabSecret`")
        """
        candidates = _run_rules_on_code(src)
        assert any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_self_check_permission(self):
        """self.check_permission('write') must be recognized as a valid permission check."""
        src = """
        import frappe
        from frappe.model.document import Document

        class TaskController(Document):
            @frappe.whitelist()
            def complete_task(self):
                self.check_permission("write")
                self.status = "Completed"
                self.save()
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_doc_check_permission(self):
        """doc.check_permission('read') must be recognized as a valid permission check."""
        src = """
        import frappe

        @frappe.whitelist()
        def get_private_doc(name: str):
            doc = frappe.get_doc("PrivateDoc", name)
            doc.check_permission("read")
            return doc.as_dict()
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_throw_permission_error(self):
        """frappe.throw(..., frappe.PermissionError) must be recognized as a permission check."""
        src = """
        import frappe

        @frappe.whitelist()
        def update_record(name: str):
            if not frappe.has_role("System Manager"):
                frappe.throw("Not permitted", frappe.PermissionError)
            return True
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_raise_permission_error(self):
        """raise frappe.PermissionError must be recognized as a permission check."""
        src = """
        import frappe

        @frappe.whitelist()
        def delete_item(name: str):
            if frappe.session.user == "Guest":
                raise frappe.PermissionError("Guests cannot delete")
            frappe.delete_doc("Item", name)
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_session_user_scoped_query(self):
        """Filtering by frappe.session.user scopes data to the caller and must not fire."""
        src = """
        import frappe

        @frappe.whitelist()
        def get_my_profile():
            return frappe.get_doc("User", frappe.session.user)
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_current_employee_helper(self):
        """Calling get_current_employee() helper scopes data to the caller and must not fire."""
        src = """
        import frappe

        @frappe.whitelist()
        def get_my_advances():
            emp = get_current_employee()
            return frappe.get_all("Employee Advance", filters={"employee": emp})
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_search_inputs_validator_decorator(self):
        """Functions decorated with @frappe.validate_and_sanitize_search_inputs must not fire."""
        src = """
        import frappe

        @frappe.whitelist()
        @frappe.validate_and_sanitize_search_inputs
        def item_query(doctype, txt, searchfield, start, page_len, filters):
            return frappe.db.sql("select name from `tabItem` where name like %(txt)s", {"txt": "%%%s%%" % txt})
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tn_developer_mode_guard(self):
        """Functions guarded by frappe.conf.developer_mode must not fire."""
        src = """
        import frappe

        @frappe.whitelist()
        def get_debug_context():
            if not frappe.conf.developer_mode:
                frappe.throw("Developer mode only")
            return {"debug": True}
        """
        candidates = _run_rules_on_code(src)
        assert not any(c.rule_id == "FR-PERM-001" for c in candidates)

    def test_tp_mutating_endpoint_has_high_confidence(self):
        """Whitelisted endpoint that performs a write (frappe.db.set_value / doc.save()) has fix_confidence='high'."""
        src = """
        import frappe

        @frappe.whitelist()
        def update_price(item_code: str, price: float):
            frappe.db.set_value("Item", item_code, "standard_rate", price)
        """
        candidates = _run_rules_on_code(src)
        perm_cands = [c for c in candidates if c.rule_id == "FR-PERM-001"]
        assert len(perm_cands) == 1
        assert perm_cands[0].fix_confidence == "high"
        assert "modifies data" in perm_cands[0].evidence

    def test_tp_read_only_endpoint_has_low_confidence(self):
        """Whitelisted endpoint that only reads data has fix_confidence='low' and read-only evidence."""
        src = """
        import frappe

        @frappe.whitelist()
        def get_types():
            return frappe.get_all("Item Type", fields=["name", "description"])
        """
        candidates = _run_rules_on_code(src)
        perm_cands = [c for c in candidates if c.rule_id == "FR-PERM-001"]
        assert len(perm_cands) == 1
        assert perm_cands[0].fix_confidence == "low"
        assert "read-only" in perm_cands[0].evidence


class TestFRPERF001Fixes:
    def test_tp_get_doc_in_loop_fires(self):
        """Real N+1 lookup frappe.get_doc("DocType", x.name) inside loop must fire."""
        src = """
        import frappe

        def process_items():
            items = frappe.get_all("Item")
            for item in items:
                doc = frappe.get_doc("Item", item.name)
                doc.submit()
        """
        candidates = _run_rules_on_code(src, rel_path="app/controllers/item.py")
        assert any(c.rule_id == "FR-PERF-001" for c in candidates)

    def test_tn_get_doc_dict_construction_in_loop(self):
        """frappe.get_doc({"doctype": ...}) or frappe.get_doc(dict(...)) is in-memory construction, not N+1 read."""
        src = """
        import frappe

        def create_notifications():
            logs = frappe.get_all("Activity Log")
            for log in logs:
                frappe.get_doc({
                    "doctype": "Notification Log",
                    "subject": log.name
                }).insert()
        """
        candidates = _run_rules_on_code(src, rel_path="app/notifications.py")
        assert not any(c.rule_id == "FR-PERF-001" for c in candidates)

    def test_tn_get_doc_in_test_file_excluded(self):
        """N+1 in test files (tests/test_*.py) must be excluded via _is_non_runtime_path."""
        src = """
        import frappe

        def test_bulk_cancel():
            items = frappe.get_all("Item")
            for item in items:
                doc = frappe.get_doc("Item", item.name)
                doc.cancel()
        """
        candidates = _run_rules_on_code(src, rel_path="app/tests/test_item.py")
        assert not any(c.rule_id == "FR-PERF-001" for c in candidates)

    def test_tn_get_doc_in_patch_file_excluded(self):
        """N+1 in patch files (patches/*.py) must be excluded via _is_non_runtime_path."""
        src = """
        import frappe

        def execute():
            items = frappe.get_all("Item")
            for item in items:
                doc = frappe.get_doc("Item", item.name)
                doc.db_set("migrated", 1)
        """
        candidates = _run_rules_on_code(src, rel_path="app/patches/v1_0/migrate.py")
        assert not any(c.rule_id == "FR-PERF-001" for c in candidates)
