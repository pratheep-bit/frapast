import frappe

def assert_safe_identifier(identifier: str, allowed: frozenset[str]) -> str:
    """
    Helper to ensure dynamic SQL identifiers (table/column names) are safe.
    Fails closed if the allow-list is empty or the identifier is not in the allow-list.
    """
    if not allowed:
        frappe.throw(
            frappe._("Dynamic SQL identifier rejected: empty allow-list."),
            frappe.ValidationError
        )
    if identifier not in allowed:
        frappe.throw(
            frappe._("Identifier {0} is not in the allowed set for this query").format(identifier),
            frappe.ValidationError
        )
    return identifier
