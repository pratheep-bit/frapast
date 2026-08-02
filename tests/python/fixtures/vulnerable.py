import frappe


@frappe.whitelist()
def unsafe_sql(name):
    query = f"select name from `tabEmployee` where name = '{name}'"
    return frappe.db.sql(query)


@frappe.whitelist(allow_guest=True)
def ignore_permissions_endpoint(doc):
    return frappe.get_doc(doc).save(ignore_permissions=True)


def safe_sql(name):
    return frappe.db.sql("select name from `tabEmployee` where name = %s", name)


def checked(doc):
    frappe.has_permission("Employee", "read", doc=doc)
