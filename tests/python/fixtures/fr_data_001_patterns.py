"""Fixture for FR-DATA-001 fix verification.

Each class/function is annotated with what the rule SHOULD and SHOULD NOT produce.
"""
import frappe
from frappe.model.document import Document


# ---------------------------------------------------------------------------
# TRUE NEGATIVE: Method calls on `self` — MUST NOT fire FR-DATA-001
# These were 802/802 false positives before the fix.
# ---------------------------------------------------------------------------

class LeaveApplication(Document):
    def validate(self):
        self.set_employee()                  # TN: method call — not a field access
        self.validate_from_to_dates("from_date", "to_date")  # TN: method call
        self.notify_approver()              # TN: method call (not a field)

    def on_submit(self):
        self.check_permission("submit")     # TN: Document base method
        self.db_set("status", "Approved")   # TN: Document base method

    def after_insert(self):
        self.notify_approver()              # TN: method call
        self.set_onload("employee", self.employee)  # TN: Document.set_onload method

    def set_employee(self):
        if not self.employee:
            pass

    def validate_from_to_dates(self, from_field, to_field):
        pass

    def notify_approver(self):
        pass

    def on_cancel(self):
        self.set_status(update=True)        # TN: Document.set_status method
        self.reload()                       # TN: Document.reload method

    def onload(self):
        self.set_onload("employee", self.employee)  # TN: method call

    def get_summary(self):
        # TN: these are real fields on Leave Application, must not fire
        return {
            "employee": self.employee,           # TN: real field
            "employee_name": self.employee_name, # TN: real field
            "from_date": self.from_date,         # TN: real field
            "status": self.status,               # TN: real field
        }

    def compute_days(self):
        # TN: Document.get() method (called as method, not field access)
        for row in self.get("items"):
            pass

    def make_accrual(self):
        self.check_permission("write")      # TN: Document base method


# ---------------------------------------------------------------------------
# TRUE NEGATIVE: real field access on resolvable DocType — MUST NOT fire
# ---------------------------------------------------------------------------

def check_real_field(name: str):
    doc = frappe.get_doc("Leave Application", name)
    # These are real fields — rule must not flag them
    _ = doc.employee
    _ = doc.employee_name
    _ = doc.status
    _ = doc.leave_type


# ---------------------------------------------------------------------------
# TRUE POSITIVE: genuinely typo'd / missing field — MUST fire FR-DATA-001
# ---------------------------------------------------------------------------

def bad_field_direct_attr(name: str):
    doc = frappe.get_doc("Leave Application", name)
    # "employe_name" is a typo — not in the schema JSON, should fire
    return doc.employe_name   # <-- TP: typo'd field


# ---------------------------------------------------------------------------
# TRUE NEGATIVE: unresolvable DocType (var, not literal) — MUST NOT fire
# ---------------------------------------------------------------------------

def unresolvable_doctype(doctype: str, name: str):
    doc = frappe.get_doc(doctype, name)   # doctype is a variable, not a literal
    # Rule cannot confidently know the DocType, must fail closed and not fire
    return doc.some_random_attr
