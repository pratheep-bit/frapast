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


if __name__ == "__main__":
    unittest.main()
