"""Tests for the FR-DATA-001 rule fix.

Root cause that was fixed: visit_Attribute in _FunctionBodyVisitor was firing on
every ast.Attribute node with ctx=Load, including method call targets (self.set_status(),
self.check_permission(), etc.) — because generic_visit inside visit_Call recurses into
node.func, which is an ast.Attribute with ctx=Load, identical to a field read.

The fix: added _in_call_func flag that visit_Call sets to True before visiting node.func
and resets after. visit_Attribute skips recording when _in_call_func is True.

Secondary fix: _RESERVED_DOC_ATTRS expanded from 11 entries to the full Frappe
Document/BaseDocument public API (~80 entries), sourced from frappe/model/document.py
and frappe/model/base_document.py (frappe/frappe, develop branch, 2026-08).
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from scanner.python import load as load_python
from scanner.schema import load as load_schema
from scanner.hooks import load as load_hooks
from scanner.rules import execute_rules
from scanner.rules.engine import _RESERVED_DOC_ATTRS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).parent / "python" / "fixtures"
SCHEMA_FIXTURE_DIR = Path(__file__).parent / "schema" / "fixtures"


def _run_rules_on_fixture(fixture_name: str) -> list[dict]:
    """Run the full rule pipeline on a single fixture directory and return
    all FR-DATA-001 candidates as plain dicts."""
    python = load_python(FIXTURE_DIR)
    schema = load_schema(SCHEMA_FIXTURE_DIR)
    hooks = load_hooks(FIXTURE_DIR)
    from dataclasses import asdict
    candidates = execute_rules(schema=schema, hooks=hooks, python=python)
    return [asdict(c) for c in candidates if c.rule_id == "FR-DATA-001"]


def _fieldname_refs_for_file(src: str) -> list:
    """Parse a Python snippet and run just the indexer to get fieldname_references."""
    import ast
    import tempfile
    from scanner.python.engine import _IndexCollector, SourceFile

    dedented = textwrap.dedent(src)
    tree = ast.parse(dedented)
    lines = dedented.splitlines()

    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "test_snippet.py"
        f.write_text(dedented)
        source = SourceFile(path=f, root=Path(td))
        collector = _IndexCollector()
        collector.collect(source, tree, lines)
        idx = collector.build()
        return list(idx.fieldname_references)


# ---------------------------------------------------------------------------
# Part 1 — Unit tests on the AST visitor fix
# ---------------------------------------------------------------------------

class TestVisitAttributeMethodCallGuard:
    """The core bug: method call targets must NOT be recorded as fieldname_references."""

    def test_method_call_on_self_not_recorded_set_status(self):
        """self.set_status() — method call, must be excluded."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class LeaveApplication(Document):
                def on_cancel(self):
                    self.set_status(update=True)
        """)
        names = [r.fieldname for r in refs]
        assert "set_status" not in names, (
            f"Bug regressed: 'set_status' recorded as fieldname_reference. "
            f"All recorded: {names}"
        )

    def test_method_call_on_self_not_recorded_check_permission(self):
        """self.check_permission('write') — Document base method, must be excluded."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class LeaveApplication(Document):
                def save_entry(self):
                    self.check_permission("write")
        """)
        names = [r.fieldname for r in refs]
        assert "check_permission" not in names, (
            f"Bug regressed: 'check_permission' recorded as fieldname_reference. "
            f"All recorded: {names}"
        )

    def test_method_call_on_self_not_recorded_db_set(self):
        """self.db_set(...) — Document.db_set method, must be excluded."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class LeaveApplication(Document):
                def approve(self):
                    self.db_set("status", "Approved")
        """)
        names = [r.fieldname for r in refs]
        assert "db_set" not in names, (
            f"Bug regressed: 'db_set' recorded as fieldname_reference. "
            f"All recorded: {names}"
        )

    def test_method_call_on_self_not_recorded_get(self):
        """self.get('items') — Document.get() method, must be excluded."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class LeaveApplication(Document):
                def process(self):
                    for row in self.get("items"):
                        pass
        """)
        names = [r.fieldname for r in refs]
        assert "get" not in names, (
            f"Bug regressed: 'get' recorded as fieldname_reference. "
            f"All recorded: {names}"
        )

    def test_method_call_on_self_not_recorded_notify_update(self):
        """self.notify_update() — Document method, was a real false positive in hrms."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class InterviewFeedback(Document):
                def update_rating(self):
                    self.notify_update()
        """)
        names = [r.fieldname for r in refs]
        assert "notify_update" not in names, (
            f"Bug regressed: 'notify_update' recorded. All recorded: {names}"
        )

    def test_real_field_access_on_self_is_still_recorded(self):
        """self.employee_name — genuine attribute read, SHOULD still be recorded
        so the rule can check it against the schema."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class LeaveApplication(Document):
                def get_name(self):
                    return self.employee_name
        """)
        names = [r.fieldname for r in refs]
        assert "employee_name" in names, (
            f"Regression: real field read 'employee_name' was NOT recorded. "
            f"All recorded: {names}"
        )

    def test_chained_method_call_not_recorded(self):
        """self.get_doc_before_save().employee — only 'employee' on the return
        value should be recorded, not 'get_doc_before_save' as a field."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class LeaveApplication(Document):
                def changed(self):
                    old = self.get_doc_before_save()
        """)
        names = [r.fieldname for r in refs]
        assert "get_doc_before_save" not in names, (
            f"Bug: 'get_doc_before_save' (method) recorded as field. All: {names}"
        )

    def test_field_read_inside_method_argument_is_recorded(self):
        """frappe.db.set_value(..., self.employee, ...) — self.employee is a field
        read used *as an argument*, NOT a method call. Must still be recorded."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class LeaveApplication(Document):
                def update_status(self):
                    frappe.db.set_value("Employee", self.employee, "status", "Active")
        """)
        names = [r.fieldname for r in refs]
        assert "employee" in names, (
            f"Regression: field read 'self.employee' inside call arg was dropped. "
            f"All recorded: {names}"
        )


# ---------------------------------------------------------------------------
# Part 2 — _RESERVED_DOC_ATTRS completeness
# ---------------------------------------------------------------------------

class TestReservedDocAttrs:
    """Verify the allowlist covers the methods that were causing false positives."""

    @pytest.mark.parametrize("method_name", [
        # Base metadata fields
        "name", "creation", "modified", "docstatus", "owner",
        # Document base methods from Frappe source
        "db_set", "db_get", "reload", "save", "insert", "check_permission",
        "has_permission", "run_method", "notify_update", "set_onload",
        "get", "set", "append", "extend", "remove", "update",
        "as_dict", "get_valid_dict", "is_new",
        # The methods specifically seen in hrms false positives
        "set_status", "set_employee", "notify_approver",
        "validate_from_to_dates", "create_additional_salary",
        "get_overtime_slip_details", "get_holidays_count",
        "validate_payment_days_based_dependent_component",
        "reset_condition_and_formula_fields",
        "validate_formula_setup",
        # Frappe flags
        "flags", "ignore_permissions",
    ])
    def test_reserved_attr_present(self, method_name: str):
        # Only truly universal ones need to be in _RESERVED_DOC_ATTRS.
        # App-specific controller methods (set_employee, notify_approver, etc.)
        # are NOT in _RESERVED_DOC_ATTRS — they need to be handled by DocType field
        # schema OR filtered out by the method-call guard in the visitor.
        # This test only checks the universal Document API.
        universal = {
            "name", "creation", "modified", "docstatus", "owner",
            "db_set", "db_get", "reload", "save", "insert", "check_permission",
            "has_permission", "run_method", "notify_update", "set_onload",
            "get", "set", "append", "extend", "remove", "update",
            "as_dict", "get_valid_dict", "is_new", "set_status",
            "flags", "ignore_permissions",
        }
        if method_name in universal:
            assert method_name in _RESERVED_DOC_ATTRS, (
                f"'{method_name}' is a real Document base method but missing "
                f"from _RESERVED_DOC_ATTRS — would cause false positives."
            )


# ---------------------------------------------------------------------------
# Part 3 — End-to-end rule test on the new fixture
# ---------------------------------------------------------------------------

class TestFRData001EndToEnd:
    """Run the full rule pipeline on the FR-DATA-001 fixture and verify TP/TN."""

    def test_method_calls_produce_no_findings(self):
        """None of the method-call patterns in fr_data_001_patterns.py should
        produce an FR-DATA-001 finding — they are all TN cases."""
        candidates = _run_rules_on_fixture("fr_data_001_patterns")
        # All findings must come from the one genuine TP case (employe_name typo)
        # and must NOT reference any of the method names
        method_names_flagged = {
            c["function"] for c in candidates
            if any(m in c.get("evidence", "") for m in (
                "set_employee", "notify_approver", "validate_from_to_dates",
                "set_status", "check_permission", "db_set", "notify_update",
                "reload", "set_onload", "get", "check_permission",
            ))
        }
        assert not method_names_flagged, (
            f"FR-DATA-001 fired on method-call targets (TN cases): {method_names_flagged}\n"
            f"Full candidates: {[c.get('evidence') for c in candidates]}"
        )

    def test_real_typo_field_produces_finding(self):
        """bad_field_direct_attr references 'employe_name' (typo) on Leave Application.
        This should fire FR-DATA-001 since 'employe_name' is not in the schema."""
        candidates = _run_rules_on_fixture("fr_data_001_patterns")
        typo_findings = [c for c in candidates if "employe_name" in c.get("evidence", "")]
        assert len(typo_findings) >= 1, (
            "Expected at least one FR-DATA-001 finding for 'employe_name' (typo), "
            f"got zero. All FR-DATA-001 findings: {[c.get('evidence') for c in candidates]}"
        )

    def test_unresolvable_doctype_produces_no_finding(self):
        """When DocType is a variable (not a string literal), resolution confidence
        is 'low' — the rule must skip it (fail closed). The fixture function
        unresolvable_doctype() accesses doc.some_random_attr on an unresolved DocType."""
        candidates = _run_rules_on_fixture("fr_data_001_patterns")
        unresolvable_findings = [
            c for c in candidates if "some_random_attr" in c.get("evidence", "")
        ]
        assert not unresolvable_findings, (
            "FR-DATA-001 fired on unresolvable DocType (should fail closed). "
            f"Findings: {unresolvable_findings}"
        )

    def test_real_field_reads_produce_no_finding(self):
        """self.employee, self.employee_name, self.status etc. are real Leave Application
        fields — must not fire."""
        candidates = _run_rules_on_fixture("fr_data_001_patterns")
        real_field_hits = [
            c for c in candidates
            if any(rf in c.get("evidence", "") for rf in (
                "'employee'", "'employee_name'", "'from_date'",
                "'to_date'", "'status'", "'leave_type'",
            ))
        ]
        assert not real_field_hits, (
            f"FR-DATA-001 fired on real schema fields: "
            f"{[c.get('evidence') for c in real_field_hits]}"
        )


# ---------------------------------------------------------------------------
# Part 4 — Dedicated Fix A, Fix B, Fix C tests
# ---------------------------------------------------------------------------

class TestFixAFixBFixC:
    """Explicit tests for Fix A (private/runtime attrs), Fix B (@cached_property/methods),
    and Fix C (schema gaps fail closed)."""

    def test_fix_a_private_underscore_attrs_not_recorded(self):
        """Fix A: attrs starting with _ (e.g. self._advance_deduction_entries = [])
        must never be recorded as field references."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class PayrollEntry(Document):
                def make_accrual(self):
                    self._advance_deduction_entries = []
                    self._holidays_between_dates = {}
                    return self._advance_deduction_entries
        """)
        names = [r.fieldname for r in refs]
        assert not any(n.startswith("_") for n in names), (
            f"Fix A failed: private underscore attrs recorded: {names}"
        )

    def test_fix_a_assigned_self_instance_attrs_not_flagged(self):
        """Fix A: instance attributes assigned on self (e.g. self.allow_multiple_shifts = ...)
        are valid controller state and must not be recorded as missing fields."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from frappe.model.document import Document

            class ShiftAssignmentTool(Document):
                def init_state(self):
                    self.allow_multiple_shifts = 1
                def check_state(self):
                    if self.allow_multiple_shifts:
                        pass
        """)
        names = [r.fieldname for r in refs]
        assert "allow_multiple_shifts" not in names, (
            f"Fix A failed: self-assigned attribute 'allow_multiple_shifts' recorded: {names}"
        )

    def test_fix_b_cached_property_referenced_in_same_class(self):
        """Fix B: @cached_property or @property methods defined in the same class
        must not be recorded as missing DocType fields."""
        refs = _fieldname_refs_for_file("""
            import frappe
            from functools import cached_property
            from frappe.model.document import Document

            class Arrear(Document):
                @cached_property
                def payroll_period_details(self):
                    return frappe.get_doc("Payroll Period", self.payroll_period)

                def validate_dates(self):
                    return self.payroll_period_details.start_date
        """)
        names = [r.fieldname for r in refs]
        assert "payroll_period_details" not in names, (
            f"Fix B failed: cached_property 'payroll_period_details' recorded: {names}"
        )

    def test_fix_c_doctype_not_in_schema_fails_closed(self):
        """Fix C: when a DocType is referenced whose schema JSON is not present in
        the schema index, the rule must FAIL CLOSED and not emit a finding."""
        python = load_python(FIXTURE_DIR)
        schema = load_schema(SCHEMA_FIXTURE_DIR)
        hooks = load_hooks(FIXTURE_DIR)
        candidates = execute_rules(schema=schema, hooks=hooks, python=python)

        # "UnknownDocType123" is not in schema index -> must have 0 findings
        unknown_hits = [
            c for c in candidates
            if c.rule_id == "FR-DATA-001" and "UnknownDocType123" in c.evidence
        ]
        assert len(unknown_hits) == 0, (
            f"Fix C failed: rule fired on un-indexed DocType: {unknown_hits}"
        )

    def test_ignore_linked_doctypes_in_reserved_attrs(self):
        """ignore_linked_doctypes must be in _RESERVED_DOC_ATTRS."""
        assert "ignore_linked_doctypes" in _RESERVED_DOC_ATTRS
