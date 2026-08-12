# frapAST Security Engine — Rules Reference Manual

Comprehensive technical reference specification for all 18 static vulnerability detectors implemented in frapAST.

---

## 1. Permission and Authorization Rules (`FR-PERM`)

### `FR-PERM-001`: Missing DocType Permission Check in Whitelisted Endpoint

- **Severity**: High / Critical
- **Impact Class**: `privilege_escalation`
- **Description**: A function exposed via `@frappe.whitelist()` mutates or retrieves database records (`frappe.get_doc`, `frappe.db.set_value`, `frappe.db.delete`) without verifying caller authorization via `frappe.has_permission(doc, ptype)` or `doc.check_permission()`.

#### Non-Compliant Pattern

```python
@frappe.whitelist()
def update_salary(employee_id, amount):
    # Vulnerable: Lacks authorization verification
    doc = frappe.get_doc("Employee", employee_id)
    doc.salary = amount
    doc.save()
```

#### Compliant Pattern

```python
@frappe.whitelist()
def update_salary(employee_id, amount):
    doc = frappe.get_doc("Employee", employee_id)
    doc.check_permission("write")  # Enforces DocType role permission check
    doc.salary = amount
    doc.save()
```

---

### `FR-PERM-002`: Unrestricted `ignore_permissions=True` Execution

- **Severity**: High
- **Impact Class**: `privilege_escalation`
- **Description**: Invokes ORM persistence functions with `ignore_permissions=True` in endpoint contexts accessible by low-privilege roles without explicit role checks.

---

### `FR-PERM-003`: Direct SQL Data Mutation Lacking Permission Controls

- **Severity**: High
- **Impact Class**: `sqli` / `permission_bypass`
- **Description**: Executes raw SQL data definition or data manipulation statements (`UPDATE`, `DELETE`, `DROP`) bypassing Frappe's security layer.

---

## 2. Injection Vulnerabilities (`FR-SQLI` and `FR-INJ`)

### `FR-SQLI-001`: String Format Interpolation in `frappe.db.sql()`

- **Severity**: Critical
- **Impact Class**: `sqli`
- **Description**: Constructs SQL queries using Python f-strings, `%` operators, or `.format()`, exposing the database to SQL injection.

#### Non-Compliant Pattern

```python
@frappe.whitelist()
def search_items(query):
    # Vulnerable to SQL injection via f-string concatenation
    return frappe.db.sql(f"SELECT name, item_name FROM `tabItem` WHERE item_name LIKE '%{query}%'")
```

#### Compliant Pattern

```python
@frappe.whitelist()
def search_items(query):
    # Uses parameterized query tuples or Query Builder
    return frappe.db.sql("SELECT name, item_name FROM `tabItem` WHERE item_name LIKE %s", (f"%{query}%",))
```

---

### `FR-INJ-001`: Unsafe Dynamic Code Execution (`eval` / `exec`)

- **Severity**: Critical
- **Impact Class**: `rce`
- **Description**: Executes dynamic Python code strings using built-in `eval()` or `exec()` functions.

---

## 3. Event Handlers and Lifecycle Isolation (`FR-HOOK`)

### `FR-HOOK-001`: Unisolated Child Table Mutation in Lifecycle Hooks

- **Severity**: Medium
- **Impact Class**: `data_corruption`
- **Description**: Document lifecycle event handlers (`before_save`, `on_update`) mutate child table records or cross-doctype references without enforcing transaction boundaries.

---

### `FR-HOOK-006`: Unhandled Bare Exception Catch Clause

- **Severity**: Low
- **Impact Class**: `unhandled_exception`
- **Description**: Uses bare `except:` clauses, swallowing system exceptions and transaction rollback signals.

---

## 4. Workflow State Corruption (`FR-WKFL`)

### `FR-WKFL-001`: Direct `workflow_state` Database Field Modification

- **Severity**: Medium
- **Impact Class**: `workflow_bypass`
- **Description**: Directly alters the `workflow_state` database column via `frappe.db.set_value` instead of executing `frappe.model.workflow.apply_workflow()`.

---

## Complete Taxonomy Summary

| Rule ID | Category | Default Severity | Description |
| :--- | :--- | :---: | :--- |
| **`FR-PERM-001`** | Permission | High | Missing DocType permission check in `@frappe.whitelist` |
| **`FR-PERM-002`** | Permission | High | Unrestricted `ignore_permissions=True` usage |
| **`FR-PERM-003`** | Permission | High | Direct SQL data mutation lacking permission controls |
| **`FR-PERM-004`** | Permission | Medium | Guest endpoint missing rate limiting |
| **`FR-PERM-005`** | Permission | Medium | Insecure role assumption |
| **`FR-SQLI-001`** | Injection | Critical | String format interpolation in `frappe.db.sql()` |
| **`FR-SQLI-002`** | Injection | Critical | Formatted parameter substitution in SQL query |
| **`FR-SQLI-003`** | Injection | High | Dynamic SQL table identifier concatenation |
| **`FR-SQLI-004`** | Injection | High | Unsanitized `ORDER BY` clause interpolation |
| **`FR-DATA-001`** | Data Privacy | High | Unmasked credential or secret key logging |
| **`FR-WKFL-001`** | Workflow | Medium | Direct `workflow_state` database field modification |
| **`FR-WKFL-002`** | Workflow | Medium | Missing approval state validation |
| **`FR-WKFL-003`** | Workflow | Medium | State machine transition bypass |
| **`FR-WKFL-004`** | Workflow | Low | Unhandled document cancellation hook |
| **`FR-HOOK-001`** | Lifecycle Hooks | Medium | Unisolated child table mutation in lifecycle hook |
| **`FR-HOOK-006`** | Lifecycle Hooks | Low | Unhandled bare exception catch clause |
| **`FR-HOOK-007`** | Lifecycle Hooks | Low | Mutable default argument in endpoint signature |
| **`FR-INJ-001`** | Injection | Critical | Unsafe dynamic code execution (`eval` / `exec`) |
