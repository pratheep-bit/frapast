import frappe


@frappe.whitelist()
def guarded_permission_bypass(name):
	frappe.only_for("System Manager")
	return frappe.get_doc("Employee", name).save(ignore_permissions=True)


@frappe.whitelist()
def guarded_by_owner_or_role(name):
	doc = frappe.get_doc("Employee", name)
	if frappe.session.user != doc.owner and "System Manager" not in frappe.get_roles():
		frappe.throw("Not permitted")
	doc.save(ignore_permissions=True)
