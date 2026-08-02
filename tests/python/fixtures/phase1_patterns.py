import frappe


@frappe.whitelist()
def endpoint_using_helper(name):
	return helper_with_permission_bypass(name)


def helper_with_permission_bypass(name):
	return frappe.get_doc("Employee", name).save(ignore_permissions=True)


@frappe.whitelist()
def raw_submittable_sql():
	return frappe.db.sql("select name from `tabExpense Claim`")


@frappe.whitelist()
def filtered_submittable_sql():
	return frappe.db.sql("select name from `tabExpense Claim` where docstatus = 1")


@frappe.whitelist()
def direct_workflow_write(name):
	return frappe.db.set_value("Expense Claim", name, "workflow_state", "Approved")


def ordinary_commit():
	frappe.db.commit()


class ExpenseClaimController:
	def on_submit(self):
		frappe.db.commit()
