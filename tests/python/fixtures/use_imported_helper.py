import frappe

from imported_helper import imported_permission_bypass


@frappe.whitelist()
def endpoint_using_imported_helper(name):
	return imported_permission_bypass(name)
