import frappe

@frappe.whitelist()
def mass_assign(kwargs):
    # FR-INJ-001
    doc = frappe.get_doc(kwargs)
    doc.save()

@frappe.whitelist()
def dangerous_eval(payload):
    # FR-INJ-002
    return eval(payload)

def enqueue_without_job_id():
    # FR-HOOK-004
    frappe.enqueue("my_method")

@frappe.whitelist()
def query_builder_dynamic(table):
    # FR-SQLI-004
    return frappe.qb.from_(table).select("*").run()

@frappe.whitelist()
def bypass_owner_check(docname):
    # FR-PERM-003
    frappe.db.set_value("Employee", docname, "status", "Active")

@frappe.whitelist()
def bypass_docstatus(docname):
    # FR-WKFL-001
    frappe.db.set_value("Attendance", docname, "status", "Present")

@frappe.whitelist()
def sync_status_without_docstatus(docname):
    # FR-WKFL-003
    frappe.db.set_value("Employee", docname, "status", "Submitted")

class BrokenLifecycle:
    # FR-HOOK-001
    def on_submit(self):
        pass
    # missing on_cancel
