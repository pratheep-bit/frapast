import frappe


def migration_sql():
	return frappe.db.sql("select name from `tabExpense Claim`")
