"""Unit tests for frapAST Autofix Engine."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner.autofix.engine import (
    FixEngine,
    fix_hook_001,
    fix_hook_004,
    fix_hook_006,
    fix_perm_001,
)


class TestAutofixEngine(unittest.TestCase):
    """Test individual rule fixers and FixEngine orchestrator."""

    def test_fix_hook_001_missing_on_cancel(self):
        source = """\
import frappe
from frappe.model.document import Document

class MyDoc(Document):
    def on_submit(self):
        frappe.db.set_value("Ledger", self.ledger, "status", "Active")
"""
        finding_data = {
            "id": "FR-HOOK-001-001",
            "rule_id": "FR-HOOK-001",
            "function": "MyDoc.on_submit",
        }
        patch = fix_hook_001(Path("test.py"), source, finding_data)
        self.assertIsNotNone(patch)
        self.assertIn("def on_cancel(self):", patch.modified_source)
        self.assertIn("MyDoc", patch.modified_source)
        self.assertIn("+", patch.diff)

    def test_fix_hook_004_unhashed_enqueue(self):
        source = """\
import frappe

def queue_salary_slips(employees):
    frappe.enqueue(process_salaries, timeout=3000, employees=employees)
"""
        finding_data = {
            "id": "FR-HOOK-004-001",
            "rule_id": "FR-HOOK-004",
            "line": 4,
            "function": "queue_salary_slips",
        }
        patch = fix_hook_004(Path("test.py"), source, finding_data)
        self.assertIsNotNone(patch)
        self.assertIn("deduplicate=True", patch.modified_source)
        self.assertIn("+", patch.diff)

    def test_fix_hook_006_bare_except(self):
        source = """\
import frappe

def compute_total(values):
    try:
        return sum(values)
    except:
        return 0
"""
        finding_data = {
            "id": "FR-HOOK-006-001",
            "rule_id": "FR-HOOK-006",
            "line": 6,
            "function": "compute_total",
        }
        patch = fix_hook_006(Path("test.py"), source, finding_data)
        self.assertIsNotNone(patch)
        self.assertIn("except Exception:", patch.modified_source)
        self.assertNotIn("except:", patch.modified_source)

    def test_fix_perm_001_whitelisted_guard(self):
        source = """\
import frappe

@frappe.whitelist()
def mark_attendance(employee, status):
    doc = frappe.get_doc("Attendance", {"employee": employee})
    doc.status = status
    doc.save()
"""
        finding_data = {
            "id": "FR-PERM-001-001",
            "rule_id": "FR-PERM-001",
            "function": "mark_attendance",
        }
        patch = fix_perm_001(Path("test.py"), source, finding_data)
        self.assertIsNotNone(patch)
        self.assertIn("frappe.only_for('System Manager')", patch.modified_source)

    def test_fix_engine_orchestration_and_apply(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            file_path = repo / "doctype.py"
            file_path.write_text("""\
import frappe
from frappe.model.document import Document

class Invoice(Document):
    def on_submit(self):
        pass
""", encoding="utf-8")

            finding = {
                "id": "FR-HOOK-001-test",
                "rule_id": "FR-HOOK-001",
                "file": "doctype.py",
                "function": "Invoice.on_submit",
            }

            engine = FixEngine(repo)
            patch = engine.generate_patch(finding)
            self.assertIsNotNone(patch)

            ok = engine.apply_patch(patch)
            self.assertTrue(ok)

            updated_content = file_path.read_text(encoding="utf-8")
            self.assertIn("def on_cancel(self):", updated_content)

    def test_fix_engine_multiple_patches_on_same_file(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            file_path = repo / "doctype.py"
            file_path.write_text("""\
import frappe
from frappe.model.document import Document

class Invoice(Document):
    def on_submit(self):
        try:
            frappe.msgprint("Submitted")
        except:
            pass
""", encoding="utf-8")

            findings = [
                {
                    "id": "FR-HOOK-001-test",
                    "rule_id": "FR-HOOK-001",
                    "file": "doctype.py",
                    "function": "Invoice.on_submit",
                },
                {
                    "id": "FR-HOOK-006-test",
                    "rule_id": "FR-HOOK-006",
                    "file": "doctype.py",
                    "line": 8,
                    "function": "Invoice.on_submit",
                },
            ]

            engine = FixEngine(repo)
            patches = engine.generate_patches(findings)
            self.assertEqual(len(patches), 2)

            applied_count = engine.apply_patches(patches)
            self.assertEqual(applied_count, 2)

            updated_content = file_path.read_text(encoding="utf-8")
            self.assertIn("def on_cancel(self):", updated_content)
            self.assertIn("except Exception:", updated_content)
            self.assertNotIn("except:", updated_content)

    def test_fix_engine_overlapping_same_function_patches(self):
        """Test multiple fixes inside the exact same function with shifting line numbers."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            file_path = repo / "api.py"
            file_path.write_text("""\
import frappe

@frappe.whitelist()
def process_batch(items):
    frappe.enqueue(run_task, items=items)
    try:
        frappe.db.commit()
    except:
        pass
""", encoding="utf-8")

            findings = [
                {
                    "id": "FR-PERM-001-test",
                    "rule_id": "FR-PERM-001",
                    "file": "api.py",
                    "function": "process_batch",
                },
                {
                    "id": "FR-HOOK-004-test",
                    "rule_id": "FR-HOOK-004",
                    "file": "api.py",
                    "line": 5,
                    "function": "process_batch",
                },
                {
                    "id": "FR-HOOK-006-test",
                    "rule_id": "FR-HOOK-006",
                    "file": "api.py",
                    "line": 8,
                    "function": "process_batch",
                },
            ]

            engine = FixEngine(repo)
            patches = engine.generate_patches(findings)
            self.assertEqual(len(patches), 3)

            applied_count = engine.apply_patches(patches)
            self.assertEqual(applied_count, 3)

            updated = file_path.read_text(encoding="utf-8")
            # 1. Permission guard injected
            self.assertIn("frappe.only_for('System Manager')", updated)
            # 2. Enqueue deduplicated
            self.assertIn("deduplicate=True", updated)
            # 3. Bare except replaced
            self.assertIn("except Exception:", updated)
            self.assertNotIn("except:", updated)

            # 4. Syntactically valid Python code check
            import ast
            ast.parse(updated)

    def test_fix_engine_exact_line_overlapping_patches(self):
        """Test behavior when two patches target the exact same line number (collision)."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            file_path = repo / "jobs.py"
            file_path.write_text("""\
import frappe

def trigger_sync(records):
    frappe.enqueue(sync_worker, records=records)
""", encoding="utf-8")

            # Two findings pointing to the EXACT same line (line 4)
            findings = [
                {
                    "id": "FR-HOOK-004-first",
                    "rule_id": "FR-HOOK-004",
                    "file": "jobs.py",
                    "line": 4,
                    "function": "trigger_sync",
                },
                {
                    "id": "FR-HOOK-004-second-duplicate",
                    "rule_id": "FR-HOOK-004",
                    "file": "jobs.py",
                    "line": 4,
                    "function": "trigger_sync",
                },
            ]

            engine = FixEngine(repo)
            patches = engine.generate_patches(findings)

            # First finding synthesizes a patch; second finding detects line is already fixed and yields no duplicate patch
            self.assertEqual(len(patches), 1)

            applied_count = engine.apply_patches(patches)
            self.assertEqual(applied_count, 1)

            updated = file_path.read_text(encoding="utf-8")
            self.assertIn("deduplicate=True", updated)
            # Ensure deduplicate was not injected twice
            self.assertEqual(updated.count("deduplicate=True"), 1)

            import ast
            ast.parse(updated)

    def test_fix_engine_partially_overlapping_line_ranges(self):
        """Test behavior when Patch A targets lines 10-15 and Patch B targets lines 12-20."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            file_path = repo / "workflow.py"
            # Lines 1-9: preamble
            # Line 10: @frappe.whitelist()
            # Line 11: def process_submission(docname, payload):
            # Line 12:     # Start of try block (Patch B's scope starts at line 12 and ends at line 18)
            # Line 13:     try:
            # Line 14:         frappe.db.savepoint("sp1")
            # Line 15:         frappe.enqueue(background_worker, payload=payload)
            # Line 16:     except:
            # Line 17:         frappe.db.rollback(save_point="sp1")
            # Line 18:         raise
            # Lines 19-22: return statement and footer
            source_code = """\
# Line 1: Header
# Line 2: Preamble
# Line 3: Configuration
# Line 4: Constants
# Line 5: Helpers
# Line 6: Utilities
# Line 7: Imports
import frappe
from frappe.model.document import Document

@frappe.whitelist()
def process_submission(docname, payload):
    try:
        frappe.db.savepoint("sp1")
        frappe.enqueue(background_worker, payload=payload)
    except:
        frappe.db.rollback(save_point="sp1")
        raise
    return {"status": "queued"}
"""
            file_path.write_text(source_code, encoding="utf-8")

            # Finding A: FR-PERM-001 targeting process_submission (starts at line 11, modifies lines 11-13 by injecting guard)
            # Finding B: FR-HOOK-006 targeting bare except at line 16 (inside the try/except block spanning lines 13-18)
            # Finding C: FR-HOOK-004 targeting frappe.enqueue at line 15 (inside lines 13-18)
            findings = [
                {
                    "id": "FR-PERM-001-overlap",
                    "rule_id": "FR-PERM-001",
                    "file": "workflow.py",
                    "function": "process_submission",
                },
                {
                    "id": "FR-HOOK-004-overlap",
                    "rule_id": "FR-HOOK-004",
                    "file": "workflow.py",
                    "line": 15,
                    "function": "process_submission",
                },
                {
                    "id": "FR-HOOK-006-overlap",
                    "rule_id": "FR-HOOK-006",
                    "file": "workflow.py",
                    "line": 16,
                    "function": "process_submission",
                },
            ]

            engine = FixEngine(repo)
            patches = engine.generate_patches(findings)

            # Record patch ranges
            ranges = [(p.rule_id, p.start_line, p.end_line) for p in patches]

            # Apply patches atomically to disk
            applied_count = engine.apply_patches(patches)

            updated = file_path.read_text(encoding="utf-8")

            # Verify all 3 modifications applied cleanly without syntax errors
            self.assertEqual(len(patches), 3)
            self.assertEqual(applied_count, 3)
            self.assertIn("frappe.only_for('System Manager')", updated)
            self.assertIn("deduplicate=True", updated)
            self.assertIn("except Exception:", updated)
            self.assertNotIn("except:", updated)

            # Verify syntax validity
            import ast
            ast.parse(updated)

    def test_fix_engine_conflicting_overlapping_range_graceful_rejection(self):
        """Test behavior when Patch A overwrites a region such that Patch B's target no longer exists."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            file_path = repo / "handler.py"
            # Original file
            source_code = """\
import frappe

def handle_data(data):
    try:
        frappe.msgprint(data)
    except:
        pass
"""
            file_path.write_text(source_code, encoding="utf-8")

            # Finding 1 targets bare except at line 6
            # Finding 2 targets an invalid line offset (e.g., line 50) that doesn't exist
            findings = [
                {
                    "id": "FR-HOOK-006-valid",
                    "rule_id": "FR-HOOK-006",
                    "file": "handler.py",
                    "line": 6,
                    "function": "handle_data",
                },
                {
                    "id": "FR-HOOK-006-stale-out-of-range",
                    "rule_id": "FR-HOOK-006",
                    "file": "handler.py",
                    "line": 50,
                    "function": "handle_data",
                },
            ]

            engine = FixEngine(repo)
            patches = engine.generate_patches(findings)

            # Patch 1 succeeds, Patch 2 gracefully returns None (rejected without error)
            self.assertEqual(len(patches), 1)
            applied_count = engine.apply_patches(patches)
            self.assertEqual(applied_count, 1)

            updated = file_path.read_text(encoding="utf-8")
            self.assertIn("except Exception:", updated)
            self.assertNotIn("except:", updated)

            import ast
            ast.parse(updated)

    def test_cli_fix_apply_with_yes_flag_in_git_repo(self):
        """Test frapast fix --apply --yes applies changes cleanly in a git repo without prompting."""
        import argparse
        import subprocess
        from scanner.cli import _run_fix_command

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            # Initialize git repository
            subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
            doc_file = repo / "doc.py"
            doc_file.write_text("""\
import frappe
from frappe.model.document import Document

class SampleDoc(Document):
    def on_submit(self):
        pass
""", encoding="utf-8")

            args = argparse.Namespace(
                repo_path=str(repo),
                apply=True,
                yes=True,
                dry_run=False,
                format="human",
                rule=None,
                finding_id=None,
            )
            exit_code = _run_fix_command(args)
            self.assertEqual(exit_code, 0)
            updated = doc_file.read_text(encoding="utf-8")
            self.assertIn("def on_cancel(self):", updated)

    def test_cli_fix_apply_without_yes_in_non_git_repo_aborts_on_no(self):
        """Test frapast fix --apply without --yes in a non-git repo aborts when user inputs 'n'."""
        import argparse
        import sys
        from unittest.mock import patch
        from scanner.cli import _run_fix_command

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)  # non-git repo
            doc_file = repo / "doc.py"
            doc_file.write_text("""\
import frappe
from frappe.model.document import Document

class SampleDoc(Document):
    def on_submit(self):
        pass
""", encoding="utf-8")

            args = argparse.Namespace(
                repo_path=str(repo),
                apply=True,
                yes=False,
                dry_run=False,
                format="human",
                rule=None,
                finding_id=None,
            )
            with patch.object(sys.stdin, "isatty", return_value=True), patch("builtins.input", return_value="n"):
                exit_code = _run_fix_command(args)
                self.assertEqual(exit_code, 1)

            # Confirm file was NOT modified
            updated = doc_file.read_text(encoding="utf-8")
            self.assertNotIn("def on_cancel(self):", updated)

    def test_cli_fix_apply_non_interactive_without_yes_refuses(self):
        """Test frapast fix --apply without --yes in non-interactive environment refuses to apply."""
        import argparse
        import sys
        from unittest.mock import patch
        from scanner.cli import _run_fix_command

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            doc_file = repo / "doc.py"
            doc_file.write_text("""\
import frappe
from frappe.model.document import Document

class SampleDoc(Document):
    def on_submit(self):
        pass
""", encoding="utf-8")

            args = argparse.Namespace(
                repo_path=str(repo),
                apply=True,
                yes=False,
                dry_run=False,
                format="human",
                rule=None,
                finding_id=None,
            )
            with patch.object(sys.stdin, "isatty", return_value=False):
                exit_code = _run_fix_command(args)
                self.assertEqual(exit_code, 1)

            # Confirm file was NOT modified
            updated = doc_file.read_text(encoding="utf-8")
            self.assertNotIn("def on_cancel(self):", updated)


if __name__ == "__main__":
    unittest.main()






