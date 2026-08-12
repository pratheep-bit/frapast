# frapAST Security Engine — False Positive Suppression Manual

This guide describes mechanisms for reviewing, suppressing, and auditing security candidate findings within frapAST.

---

## 1. Source Code Suppressions

Benign findings can be suppressed directly within Python source code by appending an `# frapast:ignore` annotation on the target line or the line preceding it.

### Annotation Syntax

```python
# Suppress a specific rule ID
doc.save(ignore_permissions=True)  # frapast:ignore FR-PERM-002

# Suppress with mandatory audit justification
doc.save(ignore_permissions=True)  # frapast:ignore FR-PERM-002: Authorized system setup task
```

---

## 2. Declarative Baseline Configuration (`fp-log.yaml`)

To maintain project-wide suppressions without altering application source code, maintain a `findings/fp-log.yaml` baseline file:

```yaml
false_positives:
  - rule_id: FR-PERM-001
    file: erpnext/hr/doctype/salary_slip/salary_slip.py
    function: get_emp_salary
    reason: "Internal helper function called exclusively from permission-checked parent context."

  - rule_id: FR-SQLI-001
    file: erpnext/controllers/queries.py
    function: item_query
    reason: "Query string constructed using validated internal dictionary keys."
```

---

## 3. Continuous Integration Verification

To enforce baseline verification in automated continuous integration workflows:

```bash
frapast scan ./apps/erpnext --fp-log ./findings/fp-log.yaml --severity
```

If an unreviewed security finding is detected that is not declared in `fp-log.yaml` or marked with an `# frapast:ignore` annotation, the CLI terminates with exit status `1`.
