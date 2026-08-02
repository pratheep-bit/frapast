import frappe


@frappe.whitelist()
def safe_endpoint(name):
    frappe.has_permission("Employee", "read")
    return frappe.db.sql("select name from `tabEmployee` where name = %s", name)
