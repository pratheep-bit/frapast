/* ==========================================================================
   frapAST Searchable Rules Reference Page Script
   Zero-lag static rendering with custom accessible dropdown filters.
   ========================================================================== */

const EMBEDDED_RULES = [
  {
    "id": "FR-SQLI-001",
    "category": "Injection and Access Control",
    "severity": "Critical",
    "description": "Dynamic `frappe.db.sql()` query with f-string or string concatenation lacking parameter bindings",
    "proof_basis": "Tier 2",
    "status": "Validated (Synthetic GHSA-745c-5q8r-vgj2)",
    "code_before": "# Vulnerable: dynamic f-string in SQL query without parameter binding\n@frappe.whitelist()\ndef get_user_records(user_id):\n    return frappe.db.sql(f\"SELECT * FROM `tabUser` WHERE name = '{user_id}'\")",
    "code_after": "# Secure: parameterized query with positional/dict bindings\n@frappe.whitelist()\ndef get_user_records(user_id):\n    return frappe.db.sql(\"SELECT * FROM `tabUser` WHERE name = %s\", (user_id,), as_dict=True)"
  },
  {
    "id": "FR-SQLI-002",
    "category": "Injection and Access Control",
    "severity": "Critical",
    "description": "Raw SQL query referencing a submittable DocType table without a `docstatus` filter",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: queries submittable DocType without docstatus check\ndef get_submitted_invoices():\n    return frappe.db.sql(\"SELECT name, total FROM `tabSales Invoice` WHERE customer = %s\", (customer,))",
    "code_after": "# Secure: explicitly filters by docstatus == 1 (Submitted)\ndef get_submitted_invoices():\n    return frappe.db.sql(\"SELECT name, total FROM `tabSales Invoice` WHERE customer = %s AND docstatus = 1\", (customer,))"
  },
  {
    "id": "FR-SQLI-003",
    "category": "Injection and Access Control",
    "severity": "High",
    "description": "`frappe.db.set_value` invoked from whitelisted RPC bypassing controller `validate()` and `before_save()` hooks",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: bypasses controller validate() and before_save() hooks\n@frappe.whitelist()\ndef update_salary(employee, salary):\n    frappe.db.set_value(\"Employee\", employee, \"salary\", salary)",
    "code_after": "# Secure: load document and save through the controller ORM chain\n@frappe.whitelist()\ndef update_salary(employee, salary):\n    doc = frappe.get_doc(\"Employee\", employee)\n    doc.salary = salary\n    doc.save()"
  },
  {
    "id": "FR-SQLI-004",
    "category": "Injection and Access Control",
    "severity": "High",
    "description": "`frappe.qb.DocType()` or `frappe.qb.from_()` using request-controlled dynamic table identifiers",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: dynamic string concatenation into QueryBuilder DocType\n@frappe.whitelist()\ndef fetch_table(user_table):\n    table = frappe.qb.DocType(user_table)\n    return frappe.qb.from_(table).select(\"*\").run()",
    "code_after": "# Secure: validate table against an explicit allowlist\nALLOWED_TABLES = {\"Task\", \"Project\"}\n@frappe.whitelist()\ndef fetch_table(user_table):\n    if user_table not in ALLOWED_TABLES:\n        frappe.throw(\"Invalid table\")\n    table = frappe.qb.DocType(user_table)\n    return frappe.qb.from_(table).select(\"*\").run()"
  },
  {
    "id": "FR-INJ-001",
    "category": "Injection and Access Control",
    "severity": "Critical",
    "description": "Request parameters unpacked directly into `frappe.get_doc(kwargs)` (mass assignment risk)",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: raw kwargs unpacked into get_doc (mass-assignment)\n@frappe.whitelist()\ndef create_lead(**kwargs):\n    doc = frappe.get_doc(kwargs)\n    doc.insert()",
    "code_after": "# Secure: unpack only validated fields\n@frappe.whitelist()\ndef create_lead(lead_name, email):\n    doc = frappe.get_doc({\n        \"doctype\": \"Lead\",\n        \"lead_name\": lead_name,\n        \"email_id\": email\n    })\n    doc.insert()"
  },
  {
    "id": "FR-INJ-002",
    "category": "Injection and Access Control",
    "severity": "Critical",
    "description": "`eval()` or `exec()` called with request-controlled input reachable from whitelisted RPC",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: request parameter passed directly to eval()\n@frappe.whitelist()\ndef calculate_formula(formula, context):\n    return eval(formula, {}, json.loads(context))",
    "code_after": "# Secure: use safe expression evaluation\nfrom frappe.utils.safe_exec import safe_eval\n@frappe.whitelist()\ndef calculate_formula(formula, context):\n    return safe_eval(formula, None, json.loads(context))"
  },
  {
    "id": "FR-INJ-005",
    "category": "Injection and Access Control",
    "severity": "Disabled",
    "description": "`frappe.msgprint()` or `frappe.throw()` format strings",
    "proof_basis": "Static",
    "status": "Disabled (requires interprocedural taint analysis)",
    "code_before": null,
    "code_after": null
  },
  {
    "id": "FR-PATH-001",
    "category": "Injection and Access Control",
    "severity": "High",
    "description": "User-controlled file path passed to file I/O operations without directory containment checks",
    "proof_basis": "Tier 2",
    "status": "Validated (Synthetic TALOS-2020-1091)",
    "code_before": "# Vulnerable: path traversal in file read\n@frappe.whitelist()\ndef read_exported_file(filename):\n    filepath = os.path.join(frappe.get_site_path(\"private\"), filename)\n    with open(filepath, \"r\") as f:\n        return f.read()",
    "code_after": "# Secure: directory containment check\n@frappe.whitelist()\ndef read_exported_file(filename):\n    base = Path(frappe.get_site_path(\"private\")).resolve()\n    target = (base / filename).resolve()\n    if not target.is_relative_to(base) or not target.is_file():\n        frappe.throw(\"Access denied\")\n    return target.read_text()"
  },
  {
    "id": "FR-SSRF-001",
    "category": "Injection and Access Control",
    "severity": "High",
    "description": "User-controlled URL passed to outbound HTTP requests (`requests.get`, `urlopen`) with no allowlist",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: user-controlled URL in outbound request\n@frappe.whitelist()\ndef fetch_external_feed(feed_url):\n    return requests.get(feed_url).text",
    "code_after": "# Secure: check URL against domain allowlist & block private IP ranges\n@frappe.whitelist()\ndef fetch_external_feed(feed_url):\n    if not is_allowed_domain(feed_url):\n        frappe.throw(\"Disallowed feed URL\")\n    return requests.get(feed_url, timeout=5).text"
  },
  {
    "id": "FR-CSRF-001",
    "category": "Injection and Access Control",
    "severity": "High",
    "description": "Guest-accessible (`allow_guest=True`) endpoint performing state-changing database modifications",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: allow_guest=True endpoint modifying state\n@frappe.whitelist(allow_guest=True)\ndef update_newsletter_preferences(email, subscribed):\n    frappe.db.set_value(\"Newsletter Subscriber\", email, \"subscribed\", subscribed)",
    "code_after": "# Secure: require authentication or token validation\n@frappe.whitelist()\ndef update_newsletter_preferences(subscribed):\n    frappe.db.set_value(\"Newsletter Subscriber\", frappe.session.user, \"subscribed\", subscribed)"
  },
  {
    "id": "FR-PERM-001",
    "category": "Authorization and Permission Enforcement",
    "severity": "High / Critical",
    "description": "`@frappe.whitelist()` endpoint lacking explicit permission validation (`has_permission`, `only_for`)",
    "proof_basis": "Tier 2",
    "status": "Validated (100% on Mutating Tier)",
    "code_before": "# Vulnerable: whitelisted mutating RPC without permission check\n@frappe.whitelist()\ndef cancel_subscription(sub_id):\n    doc = frappe.get_doc(\"Subscription\", sub_id)\n    doc.status = \"Cancelled\"\n    doc.save()",
    "code_after": "# Secure: explicit permission check or frappe.only_for()\n@frappe.whitelist()\ndef cancel_subscription(sub_id):\n    doc = frappe.get_doc(\"Subscription\", sub_id)\n    doc.check_permission(\"write\")\n    doc.status = \"Cancelled\"\n    doc.save()"
  },
  {
    "id": "FR-PERM-002",
    "category": "Authorization and Permission Enforcement",
    "severity": "High",
    "description": "`ignore_permissions=True` reachable within one hop of an unguarded public whitelisted endpoint",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: ignore_permissions=True without prior permission validation\n@frappe.whitelist()\ndef update_status(task_id, new_status):\n    doc = frappe.get_doc(\"Task\", task_id)\n    doc.status = new_status\n    doc.save(ignore_permissions=True)",
    "code_after": "# Secure: validate role before ignoring permissions\n@frappe.whitelist()\ndef update_status(task_id, new_status):\n    frappe.only_for(\"System Manager\")\n    doc = frappe.get_doc(\"Task\", task_id)\n    doc.status = new_status\n    doc.save(ignore_permissions=True)"
  },
  {
    "id": "FR-PERM-003",
    "category": "Authorization and Permission Enforcement",
    "severity": "High",
    "description": "`frappe.db.set_value` on an `if_owner`-scoped DocType bypassing owner permission enforcement",
    "proof_basis": "Tier 2",
    "status": "Validated",
    "code_before": "# Vulnerable: set_value on if_owner DocType bypasses owner check\n@frappe.whitelist()\ndef update_memo(memo_id, text):\n    frappe.db.set_value(\"Confidential Memo\", memo_id, \"text\", text)",
    "code_after": "# Secure: ORM enforces owner check on load/save\n@frappe.whitelist()\ndef update_memo(memo_id, text):\n    doc = frappe.get_doc(\"Confidential Memo\", memo_id)\n    doc.text = text\n    doc.save()"
  },
  {
    "id": "FR-PERM-004",
    "category": "Authorization and Permission Enforcement",
    "severity": "Medium",
    "description": "Report query bypassing DocType `permission_query_conditions` hooks",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: Script Report query ignores permission_query_conditions\ndef execute(filters=None):\n    return columns, frappe.db.sql(\"SELECT * FROM `tabCustomer`\")",
    "code_after": "# Secure: include permission query conditions hook\ndef execute(filters=None):\n    conditions = frappe.get_attr(\"frappe.desk.reportview.get_filters_cond\")(\"Customer\", filters, [])\n    return columns, frappe.db.sql(f\"SELECT * FROM `tabCustomer` WHERE 1=1 {conditions}\")"
  },
  {
    "id": "FR-PERM-005",
    "category": "Authorization and Permission Enforcement",
    "severity": "Medium",
    "description": "Internal SQL query bypassing DocType `has_permission` row-level security hooks",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: internal query bypasses has_permission hook\n@frappe.whitelist()\ndef list_sensitive_logs():\n    return frappe.db.sql(\"SELECT * FROM `tabAudit Log`\")",
    "code_after": "# Secure: use frappe.get_list which executes has_permission hooks\n@frappe.whitelist()\ndef list_sensitive_logs():\n    return frappe.get_list(\"Audit Log\", fields=[\"*\"])"
  },
  {
    "id": "FR-PERM-006",
    "category": "Authorization and Permission Enforcement",
    "severity": "High",
    "description": "`frappe.db.set_value` on a child table DocType (`istable=1`) leaving parent document totals uncalculated",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: direct set_value on child table leaves parent un-recalculated\n@frappe.whitelist()\ndef update_item_rate(child_row_name, new_rate):\n    frappe.db.set_value(\"Sales Invoice Item\", child_row_name, \"rate\", new_rate)",
    "code_after": "# Secure: load parent document and recalculate totals\n@frappe.whitelist()\ndef update_item_rate(parent_name, child_row_name, new_rate):\n    parent = frappe.get_doc(\"Sales Invoice\", parent_name)\n    for item in parent.items:\n        if item.name == child_row_name:\n            item.rate = new_rate\n    parent.save()"
  },
  {
    "id": "FR-HOOK-001",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Medium",
    "description": "Controller class defines `on_submit` but not `on_cancel` (missing reversal logic)",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: defines on_submit but no on_cancel reversal handler\nclass StockEntry(Document):\n    def on_submit(self):\n        frappe.db.set_value(\"Warehouse\", self.warehouse, \"stock\", self.qty)",
    "code_after": "# Secure: implement symmetrical on_cancel rollback\nclass StockEntry(Document):\n    def on_submit(self):\n        frappe.db.set_value(\"Warehouse\", self.warehouse, \"stock\", self.qty)\n\n    def on_cancel(self):\n        frappe.db.set_value(\"Warehouse\", self.warehouse, \"stock\", -self.qty)"
  },
  {
    "id": "FR-HOOK-002",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Medium",
    "description": "Multiple applications registering conflicting handlers on the same `(doctype, event)` hook",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: multiple apps hooking same doc_event without order declaration\n# App A hooks.py: doc_events = {\"Sales Invoice\": {\"on_submit\": \"app_a.handler\"}}\n# App B hooks.py: doc_events = {\"Sales Invoice\": {\"on_submit\": \"app_b.handler\"}}",
    "code_after": "# Secure: consolidate hook dispatch or declare explicit ordering in app config"
  },
  {
    "id": "FR-HOOK-003",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Medium",
    "description": "Whitelisted fast-path writing fields directly without validating lifecycle state transitions",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: whitelisted endpoint writes field directly via db.set_value\n@frappe.whitelist()\ndef mark_approved(docname):\n    frappe.db.set_value(\"Leave Application\", docname, \"status\", \"Approved\")",
    "code_after": "# Secure: trigger lifecycle transition via ORM\n@frappe.whitelist()\ndef mark_approved(docname):\n    doc = frappe.get_doc(\"Leave Application\", docname)\n    doc.status = \"Approved\"\n    doc.save()"
  },
  {
    "id": "FR-HOOK-004",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Medium",
    "description": "`frappe.enqueue()` invoked without deduplication keys, risking duplicate queue execution",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: background job enqueued without deduplication key\n@frappe.whitelist()\ndef trigger_sync():\n    frappe.enqueue(\"erpnext.sync.run_sync\", queue=\"long\")",
    "code_after": "# Secure: inject deduplicate=True to avoid queue storms\n@frappe.whitelist()\ndef trigger_sync():\n    frappe.enqueue(\"erpnext.sync.run_sync\", queue=\"long\", deduplicate=True)"
  },
  {
    "id": "FR-HOOK-005",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Low",
    "description": "`frappe.db.commit()` called within a lifecycle hook, breaking atomic transaction rollbacks",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: db.commit() inside controller hook breaks transaction atomicity\nclass Payment(Document):\n    def on_submit(self):\n        self.post_ledger()\n        frappe.db.commit()  # Breaks rollback if later hook fails",
    "code_after": "# Secure: remove explicit commit, allowing framework to commit on success\nclass Payment(Document):\n    def on_submit(self):\n        self.post_ledger()"
  },
  {
    "id": "FR-WKFL-001",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Medium",
    "description": "`frappe.db.set_value` on submittable DocType without validating document draft status (`docstatus == 0`)",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: set_value on submittable DocType without docstatus check\n@frappe.whitelist()\ndef edit_item_code(item_id, new_code):\n    frappe.db.set_value(\"Quotation\", item_id, \"item_code\", new_code)",
    "code_after": "# Secure: verify document is in draft state before modifying\n@frappe.whitelist()\ndef edit_item_code(item_id, new_code):\n    doc = frappe.get_doc(\"Quotation\", item_id)\n    if doc.docstatus != 0:\n        frappe.throw(\"Cannot modify submitted document\")\n    doc.item_code = new_code\n    doc.save()"
  },
  {
    "id": "FR-WKFL-002",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Medium",
    "description": "Direct database write to `workflow_state` bypassing the Frappe workflow transition engine",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": "# Vulnerable: direct write to workflow_state\n@frappe.whitelist()\ndef force_state(docname, state):\n    frappe.db.set_value(\"Expense Claim\", docname, \"workflow_state\", state)",
    "code_after": "# Secure: use apply_workflow transition engine\nfrom frappe.model.workflow import apply_workflow\n@frappe.whitelist()\ndef transition_state(docname, action):\n    doc = frappe.get_doc(\"Expense Claim\", docname)\n    apply_workflow(doc, action)"
  },
  {
    "id": "FR-WKFL-003",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Medium",
    "description": "`status` updated without updating `docstatus` on submittable DocTypes",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: status updated without docstatus synchronization\ndef update_cancel_status(docname):\n    frappe.db.set_value(\"Purchase Order\", docname, \"status\", \"Cancelled\")",
    "code_after": "# Secure: synchronize status and docstatus together\ndef cancel_order(docname):\n    doc = frappe.get_doc(\"Purchase Order\", docname)\n    doc.cancel()"
  },
  {
    "id": "FR-WKFL-004",
    "category": "Framework Lifecycle and Workflow Integrity",
    "severity": "Disabled",
    "description": "Amendment chain field leakage",
    "proof_basis": "Static",
    "status": "Disabled (natively handled by Frappe `no_copy=1`)",
    "code_before": null,
    "code_after": null
  },
  {
    "id": "FR-PERF-001",
    "category": "Performance, Correctness and Reliability",
    "severity": "Low",
    "description": "`frappe.get_doc()` called inside a loop over query results (N+1 query bottleneck)",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: get_doc inside loop over query result (N+1 query)\ncustomers = frappe.get_all(\"Customer\", fields=[\"name\"])\nfor c in customers:\n    doc = frappe.get_doc(\"Customer\", c.name)\n    print(doc.customer_name)",
    "code_after": "# Secure: batch fetch required fields in single query\ncustomers = frappe.get_all(\"Customer\", fields=[\"name\", \"customer_name\"])\nfor c in customers:\n    print(c.customer_name)"
  },
  {
    "id": "FR-HOOK-006",
    "category": "Performance, Correctness and Reliability",
    "severity": "Low",
    "description": "Bare `except:` block swallowing framework execution signals and exceptions",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: bare except swallows framework signals and rollbacks\ntry:\n    perform_action()\nexcept:\n    pass",
    "code_after": "# Secure: catch explicit Exception or log error\ntry:\n    perform_action()\nexcept Exception as e:\n    frappe.log_error(title=\"Action failed\", message=str(e))"
  },
  {
    "id": "FR-HOOK-007",
    "category": "Performance, Correctness and Reliability",
    "severity": "Low",
    "description": "Mutable default argument (`[]`, `{}`) in function definition signature",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: mutable default argument shared across all invocations\ndef process_items(items=[]):\n    items.append(\"default\")\n    return items",
    "code_after": "# Secure: use None sentinel\ndef process_items(items=None):\n    if items is None:\n        items = []\n    items.append(\"default\")\n    return items"
  },
  {
    "id": "FR-DATA-001",
    "category": "Performance, Correctness and Reliability",
    "severity": "Low",
    "description": "DocType field reference accessing a non-existent schema fieldname",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: references field not present in DocType schema\ndoc = frappe.get_doc(\"Employee\", emp_id)\ntotal = doc.non_existent_field + 100",
    "code_after": "# Secure: reference valid schema fieldname\ndoc = frappe.get_doc(\"Employee\", emp_id)\ntotal = (doc.salary or 0) + 100"
  },
  {
    "id": "FR-DATA-002",
    "category": "Performance, Correctness and Reliability",
    "severity": "Low",
    "description": "Missing `db.commit()` after asynchronous background processing state writes",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": null,
    "code_after": null
  },
  {
    "id": "FR-DATA-003",
    "category": "Performance, Correctness and Reliability",
    "severity": "Low",
    "description": "Raw database delete on parent document leaving orphan child table rows",
    "proof_basis": "Static",
    "status": "Validated",
    "code_before": null,
    "code_after": null
  },
  {
    "id": "FR-I18N-001",
    "category": "Performance, Correctness and Reliability",
    "severity": "Low",
    "description": "Hardcoded user-facing message string in `msgprint` or `throw` without `frappe._()`",
    "proof_basis": "Tier 1",
    "status": "Validated",
    "code_before": "# Vulnerable: hardcoded English string in user-facing message\nfrappe.throw(\"Invalid password supplied for user.\")",
    "code_after": "# Secure: wrapped with frappe._() translation marker\nfrappe.throw(frappe._(\"Invalid password supplied for user.\"))"
  }
];

document.addEventListener('DOMContentLoaded', async () => {
    const rulesContainer = document.getElementById('rules-container');
    const searchInput = document.getElementById('rule-search-input');
    const ruleCountEl = document.getElementById('rule-count-display');

    if (!rulesContainer) return;

    let allRules = EMBEDDED_RULES;
    let selectedCategory = '';
    let selectedSeverity = '';

    // Async attempt to load fresh rules-data.json if hosted
    try {
        const res = await fetch('rules-data.json');
        if (res.ok) {
            allRules = await res.json();
        }
    } catch (e) {
        // Use embedded rules fallback
    }

    // 1. Setup Custom Dropdown for Categories
    const categoryMenu = document.getElementById('category-menu');
    const categoryTrigger = document.getElementById('category-trigger');
    const categoryLabel = document.getElementById('category-label');
    const categoryWrap = document.getElementById('category-select-wrap');

    if (categoryMenu) {
        const categories = Array.from(new Set(allRules.map(r => r.category))).filter(Boolean);
        categories.forEach(cat => {
            const item = document.createElement('div');
            item.className = 'custom-select-item';
            item.setAttribute('data-value', cat);
            item.setAttribute('role', 'option');
            item.innerHTML = `
                <span>${escapeHtml(cat)}</span>
                <svg class="icon item-check" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>
            `;
            categoryMenu.appendChild(item);
        });
    }

    // 2. Setup Custom Dropdown Interactivity
    function setupCustomDropdown(wrapId, onSelect) {
        const wrap = document.getElementById(wrapId);
        if (!wrap) return;
        const trigger = wrap.querySelector('.custom-select-trigger');
        const label = wrap.querySelector('.custom-select-trigger span');
        const items = wrap.querySelectorAll('.custom-select-item');

        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = wrap.classList.contains('open');
            document.querySelectorAll('.custom-select-wrap').forEach(w => w.classList.remove('open'));
            if (!isOpen) {
                wrap.classList.add('open');
                trigger.setAttribute('aria-expanded', 'true');
            } else {
                trigger.setAttribute('aria-expanded', 'false');
            }
        });

        wrap.addEventListener('click', (e) => {
            const item = e.target.closest('.custom-select-item');
            if (!item) return;
            e.stopPropagation();
            const val = item.getAttribute('data-value') || '';
            const text = item.querySelector('span').textContent;

            wrap.querySelectorAll('.custom-select-item').forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
            label.textContent = text;
            wrap.classList.remove('open');
            trigger.setAttribute('aria-expanded', 'false');

            onSelect(val);
        });
    }

    setupCustomDropdown('category-select-wrap', (val) => {
        selectedCategory = val;
        applyFilter();
    });

    setupCustomDropdown('severity-select-wrap', (val) => {
        selectedSeverity = val;
        applyFilter();
    });

    // Close all custom dropdowns on outside click or Escape
    document.addEventListener('click', () => {
        document.querySelectorAll('.custom-select-wrap').forEach(w => {
            w.classList.remove('open');
            const t = w.querySelector('.custom-select-trigger');
            if (t) t.setAttribute('aria-expanded', 'false');
        });
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.custom-select-wrap').forEach(w => {
                w.classList.remove('open');
                const t = w.querySelector('.custom-select-trigger');
                if (t) t.setAttribute('aria-expanded', 'false');
            });
        }
    });

    // 3. Render Rules
    function renderRules(rules) {
        if (ruleCountEl) {
            ruleCountEl.textContent = `Showing ${rules.length} of ${allRules.length} rules`;
        }

        if (rules.length === 0) {
            rulesContainer.innerHTML = `
                <div class="rule-card" style="text-align: center; padding: 40px 20px;">
                    <p style="color: var(--ink-faint); margin-bottom: 12px;">No security rules match your filter criteria.</p>
                    <button class="btn-github" id="clear-filters-btn" type="button">Clear Filters</button>
                </div>
            `;
            const clearBtn = document.getElementById('clear-filters-btn');
            if (clearBtn) {
                clearBtn.addEventListener('click', () => {
                    if (searchInput) searchInput.value = '';
                    selectedCategory = '';
                    selectedSeverity = '';
                    
                    const catLabel = document.querySelector('#category-select-wrap .custom-select-trigger span');
                    if (catLabel) catLabel.textContent = 'All Categories';
                    document.querySelectorAll('#category-select-wrap .custom-select-item').forEach(i => {
                        i.classList.toggle('selected', !i.getAttribute('data-value'));
                    });

                    const sevLabel = document.querySelector('#severity-select-wrap .custom-select-trigger span');
                    if (sevLabel) sevLabel.textContent = 'All Severities';
                    document.querySelectorAll('#severity-select-wrap .custom-select-item').forEach(i => {
                        i.classList.toggle('selected', !i.getAttribute('data-value'));
                    });

                    applyFilter();
                });
            }
            return;
        }

        rulesContainer.innerHTML = rules.map(rule => {
            const sevClass = (rule.severity || '').toLowerCase().replace(/[^a-z0-9]/g, '');
            const proofClass = (rule.proof_basis || '').toLowerCase().replace(/\s+/g, '');
            
            let diffHtml = '';
            if (rule.code_before || rule.code_after) {
                const beforeFormatted = window.highlightCode ? window.highlightCode(rule.code_before || '# No vulnerable pattern available') : escapeHtml(rule.code_before || '# No vulnerable pattern available');
                const afterFormatted = window.highlightCode ? window.highlightCode(rule.code_after || '# No patch pattern available') : escapeHtml(rule.code_after || '# No patch pattern available');
                diffHtml = `
                    <div class="rule-diff-box">
                        <div class="diff-pane">
                            <div class="diff-pane-title vuln">
                                <svg class="icon icon-sm" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
                                <span>Vulnerable Pattern</span>
                            </div>
                            <pre class="diff-code">${beforeFormatted}</pre>
                        </div>
                        <div class="diff-pane">
                            <div class="diff-pane-title safe">
                                <svg class="icon icon-sm" viewBox="0 0 24 24" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                                <span>Secure / Patched Pattern</span>
                            </div>
                            <pre class="diff-code">${afterFormatted}</pre>
                        </div>
                    </div>
                `;
            }

            return `
                <article class="rule-card" id="${rule.id}">
                    <div class="rule-card-header">
                        <div>
                            <a href="#${rule.id}" class="rule-id-link">${rule.id}</a>
                            <span style="margin-left: 8px; font-size: 13px; color: var(--ink-faint); font-family: 'JetBrains Mono', monospace;">${escapeHtml(rule.category)}</span>
                        </div>
                        <div class="badge-group">
                            <span class="badge ${sevClass}">${escapeHtml(rule.severity || 'Medium')}</span>
                            <span class="badge ${proofClass}">${escapeHtml(rule.proof_basis || 'Tier 1')}</span>
                            ${rule.status && rule.status.includes('Disabled') ? '<span class="badge disabled">Disabled</span>' : ''}
                        </div>
                    </div>
                    <p class="rule-desc">${escapeHtml(rule.description)}</p>
                    ${diffHtml}
                </article>
            `;
        }).join('');

        checkHashTarget();
    }

    function escapeHtml(text) {
        if (!text) return '';
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // 4. Filtering Logic
    function applyFilter() {
        const query = (searchInput ? searchInput.value : '').toLowerCase().trim();
        const cat = selectedCategory;
        const sev = selectedSeverity;

        const filtered = allRules.filter(r => {
            const matchesQuery = !query || 
                r.id.toLowerCase().includes(query) ||
                (r.description && r.description.toLowerCase().includes(query)) ||
                (r.category && r.category.toLowerCase().includes(query));
            
            const matchesCat = !cat || r.category === cat;
            const matchesSev = !sev || (r.severity && r.severity.toLowerCase().includes(sev.toLowerCase()));

            return matchesQuery && matchesCat && matchesSev;
        });

        renderRules(filtered);
    }

    if (searchInput) searchInput.addEventListener('input', applyFilter);

    // Initial instant render
    renderRules(allRules);

    // Hash change handler
    function checkHashTarget() {
        if (!window.location.hash) return;
        const targetId = window.location.hash.substring(1);
        const card = document.getElementById(targetId);
        if (card) {
            document.querySelectorAll('.rule-card').forEach(c => c.classList.remove('highlighted'));
            card.classList.add('highlighted');
            card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }

    window.addEventListener('hashchange', checkHashTarget);
});
