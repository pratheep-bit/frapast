import frappe


def imported_permission_bypass(name):
	return frappe.get_doc("Employee", name).save(ignore_permissions=True)
