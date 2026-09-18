"""Regression tests for BUG-01 (Fix B), BUG-02 (Fix C), and BUG-03 (Fix A).

Fix A: FR-PERM-001 session-termination + FR-CSRF-001 token-auth FP suppression.
Fix B: apply failure exit code + per-file error details.
Fix C: tab-consistent indentation in fix_hook_001.
"""
from __future__ import annotations

import ast
import os
import stat
import sys
import tabnanny
import tempfile
import textwrap
import unittest
from io import StringIO
from pathlib import Path

from scanner.autofix.engine import FixEngine, fix_hook_001
from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


# ---------------------------------------------------------------------------
# Shared helper — mirrors the pattern used in test_fr_perm_perf_fix.py
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Fix A: FR-PERM-001 session-termination exemption (BUG-03)
# ---------------------------------------------------------------------------

class TestFrPerm001SessionTerminationExemption(unittest.TestCase):
    """logout and web_logout must not be flagged by FR-PERM-001."""

    def test_logout_not_flagged(self):
        """frappe.handler.logout: session-termination, no DocType mutation."""
        src = """
        import frappe

        @frappe.whitelist()
        def logout():
            frappe.local.login_manager.logout()
            frappe.db.commit()
        """
        candidates = _run_rules_on_code(src, rel_path="frappe/handler.py")
        flagged = [c.function.rsplit(".", 1)[-1] for c in candidates if c.rule_id == "FR-PERM-001"]
        self.assertNotIn("logout", flagged,
                         "logout should NOT be flagged by FR-PERM-001 (session-termination safe)")

    def test_web_logout_not_flagged(self):
        """frappe.www.login.web_logout: session-termination variant."""
        src = """
        import frappe

        @frappe.whitelist()
        def web_logout():
            frappe.local.login_manager.logout()
        """
        candidates = _run_rules_on_code(src, rel_path="frappe/www/login.py")
        flagged = [c.function.rsplit(".", 1)[-1] for c in candidates if c.rule_id == "FR-PERM-001"]
        self.assertNotIn("web_logout", flagged,
                         "web_logout should NOT be flagged by FR-PERM-001 (session-termination safe)")

    def test_unrelated_mutation_still_flagged(self):
        """Genuine unguarded mutating endpoint must still be detected."""
        src = """
        import frappe

        @frappe.whitelist()
        def update_salary(employee, amount):
            frappe.db.set_value("Employee", employee, "salary", amount)
        """
        candidates = _run_rules_on_code(src)
        flagged = [c.function.rsplit(".", 1)[-1] for c in candidates if c.rule_id == "FR-PERM-001"]
        self.assertIn("update_salary", flagged,
                      "update_salary (unguarded mutation) must still be flagged by FR-PERM-001")


# ---------------------------------------------------------------------------
# Fix A: FR-CSRF-001 token-auth exemption (BUG-03)
# ---------------------------------------------------------------------------

class TestFrCsrf001TokenAuthExemption(unittest.TestCase):
    """update_password must not be flagged by FR-CSRF-001."""

    def test_update_password_not_flagged(self):
        """Token-gated password reset: exempt from FR-CSRF-001."""
        src = """
        import frappe

        @frappe.whitelist(allow_guest=True)
        def update_password(new_password, key=None):
            # Validates short-lived cryptographic reset_password_key token.
            user = frappe.db.get_value("User", {"reset_password_key": key})
            frappe.db.set_value("User", user, "reset_password_key", "")
            frappe.db.set_value("User", user, "password", new_password)
        """
        candidates = _run_rules_on_code(
            src, rel_path="frappe/core/doctype/user/user.py"
        )
        flagged = [c.function.rsplit(".", 1)[-1] for c in candidates if c.rule_id == "FR-CSRF-001"]
        self.assertNotIn("update_password", flagged,
                         "update_password uses token-based auth and must NOT be flagged by FR-CSRF-001")

    def test_genuine_guest_mutation_still_flagged(self):
        """A genuinely unprotected guest-accessible write must still be detected."""
        src = """
        import frappe

        @frappe.whitelist(allow_guest=True)
        def subscribe_newsletter(email):
            frappe.db.set_value("Newsletter", email, "subscribed", 1)
        """
        candidates = _run_rules_on_code(src)
        flagged = [c.function.rsplit(".", 1)[-1] for c in candidates if c.rule_id == "FR-CSRF-001"]
        self.assertIn("subscribe_newsletter", flagged,
                      "subscribe_newsletter must still be flagged by FR-CSRF-001")


# ---------------------------------------------------------------------------
# Fix C: Tab-consistent autofix indentation (BUG-02)
# ---------------------------------------------------------------------------

class TestFixHook001TabIndentation(unittest.TestCase):
    """fix_hook_001 must produce indentation consistent with the source file."""

    def _patch(self, source: str, finding_data: dict) -> str:
        patch = fix_hook_001(Path("test.py"), source, finding_data)
        self.assertIsNotNone(patch, "Expected a patch to be generated")
        return patch.modified_source

    def test_tab_file_body_uses_tabs(self):
        """Tab-indented class generates on_cancel body indented with two tabs."""
        source = (
            "class MyDoc(Document):\n"
            "\tdef on_submit(self):\n"
            "\t\tpass\n"
        )
        finding = {"id": "t", "rule_id": "FR-HOOK-001", "function": "MyDoc"}
        modified = self._patch(source, finding)

        # Structural check
        self.assertIn("def on_cancel(self):", modified)
        # Body must use \\t\\t (two tabs) not tab+spaces
        self.assertIn("\t\tpass", modified, "Expected body indented with two tabs")
        # No line must mix a leading tab and space in the generated block
        for line in modified.splitlines():
            if "on_cancel" in line or ("pass" in line and "on_submit" not in line):
                self.assertFalse(
                    "\t " in line or " \t" in line,
                    f"Mixed tab/space indentation detected: {line!r}",
                )

    def test_tab_file_passes_tabnanny(self):
        """Generated file must pass tabnanny (no mixed indentation)."""
        source = (
            "import frappe\n"
            "\n"
            "class MyDoc(Document):\n"
            "\tdef on_submit(self):\n"
            "\t\tfrappe.db.set_value('Ledger', self.ledger, 'status', 'Active')\n"
        )
        finding = {"id": "t", "rule_id": "FR-HOOK-001", "function": "MyDoc"}
        modified = self._patch(source, finding)

        # Must parse cleanly
        try:
            ast.parse(modified)
        except SyntaxError as exc:
            self.fail(f"Generated code has a syntax error: {exc}")

        # tabnanny must report no issues
        with tempfile.NamedTemporaryFile(
            suffix=".py", delete=False, mode="w", encoding="utf-8"
        ) as tf:
            tf.write(modified)
            tmp_path = tf.name
        try:
            out = StringIO()
            saved, sys.stdout = sys.stdout, out
            try:
                tabnanny.check(tmp_path)
            finally:
                sys.stdout = saved
            result = out.getvalue().strip()
            self.assertEqual(
                result, "",
                f"tabnanny reported mixed indentation:\n{result}\n---\n{modified}",
            )
        finally:
            os.unlink(tmp_path)

    def test_space_file_body_uses_spaces(self):
        """4-space-indented class: method def at 4 spaces, body at 8 spaces."""
        source = (
            "class Invoice(Document):\n"
            "    def on_submit(self):\n"
            "        pass\n"
        )
        finding = {"id": "s", "rule_id": "FR-HOOK-001", "function": "Invoice"}
        modified = self._patch(source, finding)
        self.assertIn("    def on_cancel(self):", modified)
        self.assertIn("        pass", modified)
        # No tabs
        for line in modified.splitlines():
            if "on_cancel" in line or ("pass" in line and "on_submit" not in line):
                self.assertNotIn("\t", line, f"Unexpected tab in space-indented output: {line!r}")

    def test_two_space_file_body_uses_two_space_units(self):
        """2-space-indented class generates body at 4 spaces (2 + 2)."""
        source = (
            "class TwoSpace(Document):\n"
            "  def on_submit(self):\n"
            "    pass\n"
        )
        finding = {"id": "2s", "rule_id": "FR-HOOK-001", "function": "TwoSpace"}
        modified = self._patch(source, finding)
        self.assertIn("  def on_cancel(self):", modified)
        self.assertIn("    pass", modified)


# ---------------------------------------------------------------------------
# Fix B: apply-failure exit codes and per-file error details (BUG-01)
# ---------------------------------------------------------------------------

class TestApplyPatchesWithDetail(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)

    def tearDown(self):
        for f in self.repo.rglob("*"):
            try:
                f.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
        self.tmp.cleanup()

    _SOURCE = (
        "class MyDoc(Document):\n"
        "    def on_submit(self):\n"
        "        pass\n"
    )

    def _make_patch(self, filename: str):
        fpath = self.repo / filename
        fpath.write_text(self._SOURCE, encoding="utf-8")
        finding = {"id": f"t-{filename}", "rule_id": "FR-HOOK-001",
                   "file": filename, "function": "MyDoc"}
        patch = fix_hook_001(fpath, self._SOURCE, finding)
        self.assertIsNotNone(patch)
        return patch, fpath

    def test_complete_failure_returns_zero_and_non_empty_errors(self):
        """Read-only file: success_count == 0, failure_details populated."""
        from scanner.cli import _apply_patches_with_detail

        patch, fpath = self._make_patch("readonly.py")
        fpath.chmod(stat.S_IRUSR | stat.S_IRGRP)

        engine = FixEngine(self.repo)
        success_count, failure_details = _apply_patches_with_detail(engine, [patch])

        self.assertEqual(success_count, 0,
                         "Expected 0 successes on read-only file")
        self.assertGreater(len(failure_details), 0,
                           "Expected at least one failure detail entry")
        # First entry: (path_string, error_message)
        err_path, err_msg = failure_details[0]
        self.assertIn(str(fpath), err_path,
                      "Failure detail must reference the problematic file path")
        self.assertTrue(err_msg.strip(),
                        "Error message must be non-empty and descriptive")

    def test_success_returns_correct_count_and_empty_errors(self):
        """Writable file: success_count == 1, no errors."""
        from scanner.cli import _apply_patches_with_detail

        patch, fpath = self._make_patch("writable.py")
        engine = FixEngine(self.repo)
        success_count, failure_details = _apply_patches_with_detail(engine, [patch])

        self.assertEqual(success_count, 1)
        self.assertEqual(failure_details, [])
        # Confirm the file was actually written
        self.assertIn("on_cancel", fpath.read_text(encoding="utf-8"))

    @unittest.skipIf(
        sys.platform == "win32" or (hasattr(os, "getuid") and os.getuid() == 0),
        "File permission restrictions are not enforced for root or on Windows",
    )
    def test_partial_failure_count_is_accurate(self):
        """With one writable and one read-only file, success_count == patches_in_writable_file."""
        from scanner.cli import _apply_patches_with_detail

        patch_ok, fpath_ok = self._make_patch("ok.py")
        patch_ro, fpath_ro = self._make_patch("readonly2.py")
        fpath_ro.chmod(stat.S_IRUSR | stat.S_IRGRP)

        engine = FixEngine(self.repo)
        success_count, failure_details = _apply_patches_with_detail(
            engine, [patch_ok, patch_ro]
        )

        # One file written, one failed
        self.assertEqual(success_count, 1)
        self.assertEqual(len(failure_details), 1)


if __name__ == "__main__":
    unittest.main()
