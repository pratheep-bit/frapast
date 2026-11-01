from __future__ import annotations

import contextvars
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from scanner.callgraph import CallGraph, build_call_graph
from scanner.hooks import HookIndex
from scanner.python import PythonSymbolIndex
from scanner.schema import SchemaIndex
from scanner.shared import stable_hash

# Single source of truth for rule-function -> emitted taxonomy ID. Renames
# happen here, not in docstrings, so a future function rename can't silently
# desync from the ID it emits. _assert_taxonomy_consistency() enforces this
# at import time instead of relying on someone reading a comment.
RENAMED_TAXONOMY: dict[str, str] = {
	"fr_corr_001_bare_except": "FR-HOOK-006",     # was FR-CORR-001
	"fr_corr_002_mutable_default": "FR-HOOK-007", # was FR-CORR-002
	# fr_xss_001 (old msgprint-based rule, FR-INJ-005) was removed in Phase 2.
	# The new fr_xss_001 emits FR-XSS-001 directly (stored HTML field writes).
}


_PUBLIC_METADATA_FUNCTIONS: frozenset[str] = frozenset({
	"get_currency_symbols",
	"get_company_currencies",
	"get_doctype_fields",
	"get_doctype_states",
	"get_workflow",
	"get_hr_settings",
	"are_push_notifications_enabled",
	"oauth_providers",
	"get_default_company",
	"get_attendance_years",
	"get_years",
	"get_retirement_date",
	"get_payroll_settings_for_payment_days",
	"get_country",
	"get_leave_types",
	"get_expense_claim_types",
	"get_expense_type_description",
	"get_attachments",
})

# ---------------------------------------------------------------------------
# FR-PERM-001: Authentication & session lifecycle safe patterns
# ---------------------------------------------------------------------------
# These Frappe core function names are intentionally exempt from the FR-PERM-001
# "mutating endpoint lacks permission check" rule.
# Rationale:
#   1. Session termination (logout, web_logout, user_logout): Acts exclusively on
#      frappe.local.login_manager (the caller's own active session). Logging out
#      of one's own session does not require System Manager or DocType-level
#      privilege.
#   2. Token/Guest-gated Password Recovery (reset_password, update_password):
#      Initiating password reset sends an email token; finalizing update_password
#      validates the one-time `reset_password_key` rather than a session cookie.
#   3. Public Onboarding / Auth Challenge (sign_up, verify_otp, send_token):
#      Self-service account registration and two-factor challenge verification are
#      intentionally guest-accessible entry points protected by rate limits and
#      cryptographic verification rather than DocType permission rules.
_PERM_001_AUTH_SAFE: frozenset[str] = frozenset({
	# Session termination
	"logout",
	"web_logout",
	"user_logout",
	# Password recovery & reset
	"reset_password",
	"update_password",
	"update_password_page",
	# Public onboarding & 2FA verification
	"sign_up",
	"verify_otp",
	"send_token",
})

# ---------------------------------------------------------------------------
# FR-CSRF-001: Token-based authentication safe patterns
# ---------------------------------------------------------------------------
# These Frappe core function names are intentionally exempt from the FR-CSRF-001
# "guest-accessible state-changing endpoint" rule.  The password reset/update
# flow uses short-lived single-use cryptographic tokens instead of session
# cookies, so the standard CSRF threat model does not apply:
#   1. The endpoint validates a `reset_password_key` (or equivalent) token that
#      was delivered out-of-band (email), not via a session cookie.
#   2. A cross-origin attacker cannot read the token from a victim's mailbox, so
#      the auto-submitting-form attack vector that CSRF protects against is not
#      applicable here.
#   3. The Frappe framework clears the token after first use, preventing replay.
# Source: frappe/core/doctype/user/user.py — update_password()
#         frappe/www/update-password.py — update_password() web page handler
_CSRF_001_TOKEN_AUTH_SAFE: frozenset[str] = frozenset({
	# frappe/core/doctype/user/user.py — token-gated password reset
	"update_password",
	# frappe/www/update-password.py — same flow via the web page handler
	"update_password_page",
	# frappe/core/doctype/user/user.py — old/compat name used in some versions
	"reset_password",
})


HOOK_LIFECYCLE_METHODS = frozenset(
	{
		"after_insert",
		"after_save",
		"before_cancel",
		"before_insert",
		"before_save",
		"before_submit",
		"before_update_after_submit",
		"before_validate",
		"on_cancel",
		"on_submit",
		"on_update",
		"on_update_after_submit",
		"validate",
	}
)

RULE_VERSIONS = {
	"FR-PERM-002": "1.1.0",
}


@dataclass(frozen=True)
class Candidate:
	rule_id: str
	rule_version: str
	taxonomy_id: str
	file: str
	line: int
	function: str
	code_location_hash: str
	evidence: str
	proof_recipe: str
	proof_tier: int = 0
	status: str = "candidate"
	fix_confidence: str = "none"
	target_arg: str | None = None

	def with_status(self, status: str) -> Candidate:
		return replace(self, status=status)


Rule = Callable[[SchemaIndex, HookIndex, PythonSymbolIndex, CallGraph], list[Candidate]]


# ---------------------------------------------------------------------------
# FR-SQLI family
# ---------------------------------------------------------------------------


def fr_sqli_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SQLI-001: Unparameterized frappe.db.sql() built from request-controlled input.

	Flags dynamic SQL strings reachable within one call-graph hop of a
	whitelisted endpoint that lack parameter binding.
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-SQLI-001",
			call.span.file,
			call.span.line_start,
			call.function,
			call.span.hash,
			"Dynamic frappe.db.sql query has no parameter binding.",
			"Seed a controlled value through the endpoint, invoke it over HTTP, and verify it cannot alter the SQL predicate.",
		)
		for call in python.sql_calls
		if call.dynamic and call.request_controlled and not call.parameterized and call.symbol_id in reachable
	]


def fr_sqli_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SQLI-002: Raw SQL against a submittable DocType with no docstatus filter.

	Draft/cancelled rows can silently leak into query results that assume
	only submitted documents matter.
	"""
	candidates: list[Candidate] = []
	for call in python.sql_calls:
		if call.query is None or "docstatus" in call.query.lower() or _is_non_runtime_path(call.span.file):
			continue
		for doctype in schema.submittable_doctypes():
			if _query_mentions_table(call.query, doctype.table_name):
				candidates.append(
					_candidate(
						"FR-SQLI-002",
						call.span.file,
						call.span.line_start,
						call.function,
						call.span.hash,
						f"Raw SQL references submittable {doctype.name} without a docstatus filter.",
						"Seed draft, submitted, and cancelled records; invoke the query over HTTP and verify cancelled or draft records cannot change the result.",
					)
				)
	return candidates


def fr_sqli_003(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SQLI-003: frappe.db.set_value/db_update skipping controller validate/before_save hooks.

	Flags set_value calls reachable from whitelisted endpoints — these bypass the
	controller's validate() and before_save() chain, silently desyncing derived fields.
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	perm_check_symbols = {p.symbol_id for p in python.permission_checks}
	return [
		_candidate(
			"FR-SQLI-003",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			f"frappe.db.set_value writes to '{record.field_name or 'unknown'}' bypassing controller validate/before_save hooks.",
			"Invoke the endpoint, then verify the target doctype's validate() was not triggered and derived fields are stale.",
		)
		for record in python.set_value_calls
		if record.symbol_id in reachable
		and not _is_non_runtime_path(record.span.file)
		and record.symbol_id not in perm_check_symbols
		and record.field_name not in {"read", "is_read", "seen", "viewed", "docstatus"}
	]


def fr_sqli_004(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SQLI-004: Dynamic table/column names in frappe.qb builder.

	Flags frappe.qb.from_() or frappe.qb.DocType() calls where the table name is
	not a string literal — string concatenation can re-embed SQL injection.
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-SQLI-004",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			"frappe.qb uses a dynamic (non-literal) table/column name.",
			"Supply a crafted table name through the endpoint and verify it cannot alter the query structure.",
		)
		for record in python.query_builder_calls
		if record.dynamic_table and record.symbol_id in reachable
	]


# ---------------------------------------------------------------------------
# FR-PERM family
# ---------------------------------------------------------------------------


def fr_perm_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERM-001: Missing permission check on whitelisted endpoint.

	Flags @frappe.whitelist() endpoints with no has_permission/only_for check
	in their body or within one hop of their call graph.
	Differentiates mutating endpoints (high fix_confidence) from read-only endpoints (low fix_confidence).

	Exemptions:
	  - Authentication & session lifecycle functions (see _PERM_001_AUTH_SAFE): these
	    operate exclusively on session/login managers or token-based challenge flows
	    and therefore do not require a DocType-level permission guard.
	"""
	permission_checks = {record.symbol_id for record in python.permission_checks}
	mutations = {record.symbol_id for record in python.mutations}
	out = []
	for endpoint in python.whitelisted_endpoints:
		# Bare function name (strip module path, e.g. "frappe.handler.logout" -> "logout")
		fn_name = endpoint.function.rsplit(".", 1)[-1]
		# Skip authentication and session-lifecycle functions
		if fn_name in _PERM_001_AUTH_SAFE:
			continue
		if not _path_has_permission_check(endpoint.symbol_id, graph, permission_checks):
			has_mutation = _path_has_mutation(endpoint.symbol_id, graph, mutations)
			if has_mutation:
				out.append(_candidate(
					"FR-PERM-001",
					endpoint.span.file,
					endpoint.span.line_start,
					endpoint.function,
					endpoint.span.hash,
					"Whitelisted endpoint modifies data with no permission check in body or within one hop.",
					"Invoke the endpoint as a low-privilege user and verify unauthorized modification is rejected.",
					fix_confidence="high",
				))
			else:
				if fn_name in _PUBLIC_METADATA_FUNCTIONS:
					continue
				out.append(_candidate(
					"FR-PERM-001",
					endpoint.span.file,
					endpoint.span.line_start,
					endpoint.function,
					endpoint.span.hash,
					"Whitelisted endpoint has no permission check in body or within one hop (read-only data exposure).",
					"Invoke the endpoint as an unauthorized user and verify data exposure is restricted.",
					fix_confidence="low",
				))
	return out


def fr_perm_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERM-002: ignore_permissions=True reachable from an unguarded whitelisted endpoint.

	Excludes read-only helpers (get_all/get_list/get_value/count) and .insert()
	calls, which are common, low-risk uses of the flag.
	"""
	permission_checks = {record.symbol_id for record in python.permission_checks}
	safe_calls = {
		"frappe.get_all", "frappe.get_list", "frappe.get_value",
		"frappe.db.get_all", "frappe.db.get_list", "frappe.db.get_value",
		"frappe.db.count", "frappe.count"
	}
	candidates: list[Candidate] = []
	for record in python.ignore_permissions:
		if not record.value:
			continue
		if record.call_name in safe_calls or (record.call_name and record.call_name.endswith(".insert")):
			continue
		if not _has_unchecked_whitelisted_path(record.symbol_id, python, graph, permission_checks):
			continue
		candidates.append(
			_candidate(
				"FR-PERM-002",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				"ignore_permissions=True is reachable within one hop of a whitelisted endpoint without an indexed permission guard.",
				"Invoke the endpoint as the lowest allowed role against an unauthorized document and verify access is rejected.",
			)
		)
	return candidates


def fr_perm_003(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERM-003: if_owner bypass via frappe.db.set_value on owner-scoped DocTypes.

	Owner-scoping is enforced in get_doc()/save() path, not in raw DB writes.
	"""
	owner_scoped = {doctype.name for doctype in schema.owner_scoped_doctypes()}
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-PERM-003",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			f"frappe.db.set_value on owner-scoped DocType '{record.doctype_arg}' bypasses if_owner enforcement.",
			"Invoke the endpoint as a non-owner user and verify the write is rejected.",
		)
		for record in python.set_value_calls
		if record.doctype_arg in owner_scoped
		and record.symbol_id in reachable
		and not _is_non_runtime_path(record.span.file)
	]


def fr_perm_004(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERM-004: Script/Query Report using raw SQL without permission query conditions.

	Script Reports bypass the ORM's user-permission injection; they need an explicit
	get_permission_query_conditions-equivalent filter.
	"""
	report_doctypes_with_hooks = set(hooks.permission_query_conditions.keys())
	table_to_doctype = {d.table_name: d for d in schema.doctypes if d.table_name}
	candidates: list[Candidate] = []
	for call in python.sql_calls:
		if not _is_report_path(call.span.file):
			continue
		# Check if any mentioned table has a permission_query_conditions hook
		if call.query:
			backticked = set(re.findall(r"`(tab[^`]+)`", call.query))
			unquoted_query = re.sub(r"`[^`]+`", " ", call.query)
			words = set(re.findall(r'[A-Za-z0-9_]+', unquoted_query)) | backticked
			mentioned_tables = words.intersection(table_to_doctype.keys())
			for table_name in mentioned_tables:
				doctype = table_to_doctype[table_name]
				if doctype.name in report_doctypes_with_hooks:
					candidates.append(
						_candidate(
							"FR-PERM-004",
							call.span.file,
							call.span.line_start,
							call.function,
							stable_hash(f"{call.span.hash}:{doctype.name}"),
							f"Script Report uses raw SQL on '{doctype.name}' without permission_query_conditions hook coverage.",
							"Run the report as a restricted user and verify rows belonging to other users are not exposed.",
						)
					)
	return candidates


def fr_perm_005(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERM-005: has_permission hook gap — internal frappe.get_all skips the hook.

	DocTypes with has_permission hooks have list-view protection, but internal
	frappe.get_all calls from whitelisted endpoints may bypass it.
	"""
	doctypes_with_has_perm = set(hooks.has_permission.keys())
	if not doctypes_with_has_perm:
		return []
	table_to_doctype = {d.table_name: d for d in schema.doctypes if d.table_name}
	reachable = _reachable_from_whitelisted(python, graph)
	candidates: list[Candidate] = []
	for call in python.sql_calls:
		if call.symbol_id not in reachable or call.query is None:
			continue
		backticked = set(re.findall(r"`(tab[^`]+)`", call.query))
		unquoted_query = re.sub(r"`[^`]+`", " ", call.query)
		words = set(re.findall(r'[A-Za-z0-9_]+', unquoted_query)) | backticked
		mentioned_tables = words.intersection(table_to_doctype.keys())
		for table_name in mentioned_tables:
			doctype = table_to_doctype[table_name]
			if doctype.name in doctypes_with_has_perm:
				candidates.append(
					_candidate(
						"FR-PERM-005",
						call.span.file,
						call.span.line_start,
						call.function,
						call.span.hash,
						f"Internal query on '{doctype.name}' bypasses has_permission hook that protects list views.",
						"Invoke the endpoint as a restricted user and verify rows filtered by has_permission are not exposed.",
					)
				)
	return candidates


def fr_perm_006(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERM-006: Child table mutation without parent re-validation.

	Bulk updates via set_value on child tables (istable=1) never trigger the
	parent's validate(), so parent-level totals/permissions go stale.
	"""
	child_tables = {doctype.name for doctype in schema.doctypes if doctype.istable}
	reachable = _reachable_from_whitelisted(python, graph)
	candidates: list[Candidate] = []
	for record in python.set_value_calls:
		if (
			record.doctype_arg in child_tables
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(
				_candidate(
					"FR-PERM-006",
					record.span.file,
					record.span.line_start,
					record.function,
					record.span.hash,
					f"frappe.db.set_value on child table '{record.doctype_arg}' bypasses parent validate().",
					"Modify the child table via this path and verify the parent's totals/validation is re-triggered.",
				)
			)
	return candidates


def fr_perm_007(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERM-007: User Permission Filter Bypass / Missing User Permission Guard.

	Scans:
	  1. Explicit bypass: queries with `ignore_user_permissions=True` reachable from
	     whitelisted endpoints or script reports.
	  2. Implicit bypass: `frappe.get_all()` on DocTypes subject to User Permissions
	     (e.g., DocTypes with company, customer, supplier, employee links, or standard
	     multi-tenant DocTypes) in whitelisted endpoints without `strict_user_permissions=True`
	     and lacking explicit permission validation.
	"""
	candidates: list[Candidate] = []
	reachable = _reachable_from_whitelisted(python, graph)

	# 1. Explicit bypass via ignore_user_permissions=True
	for record in getattr(python, "ignore_user_permissions", ()):
		if (record.symbol_id in reachable or _is_whitelisted_symbol(record.symbol_id, python)) and not _is_non_runtime_path(record.span.file):
			call_desc = f" in {record.call_name}()" if record.call_name else ""
			candidates.append(
				_candidate(
					"FR-PERM-007",
					record.span.file,
					record.span.line_start,
					record.function,
					record.span.hash,
					f"Query{call_desc} explicitly specifies ignore_user_permissions=True in a whitelisted path.",
					"Remove ignore_user_permissions=True or enforce explicit permission verification before query execution.",
					fix_confidence="high",
				)
			)

	# 2. Implicit bypass via frappe.get_all on DocTypes with user permissions
	_STANDARD_UP_DOCTYPES = frozenset({
		"Company", "Customer", "Supplier", "Employee", "Sales Invoice",
		"Purchase Invoice", "Journal Entry", "Payment Entry", "Delivery Note",
		"Purchase Receipt", "Sales Order", "Purchase Order", "Stock Entry",
		"Timesheet", "Quotation", "Opportunity", "Lead",
	})
	_UP_FIELD_NAMES = frozenset({
		"company", "customer", "supplier", "employee", "branch",
		"cost_center", "territory", "department", "user",
	})

	user_perm_doctypes = set(_STANDARD_UP_DOCTYPES)
	for dt in getattr(schema, "doctypes", ()):
		if any(f.fieldname.lower() in _UP_FIELD_NAMES or (f.options and f.options.lower() in {"company", "customer", "supplier", "employee"}) for f in dt.fields):
			user_perm_doctypes.add(dt.name)

	checked_functions = {
		pc.symbol_id for pc in getattr(python, "permission_checks", ())
	}

	for record in getattr(python, "get_all_calls", ()):
		if (
			(record.symbol_id in reachable or _is_whitelisted_symbol(record.symbol_id, python))
			and not record.strict_user_permissions
			and not _is_non_runtime_path(record.span.file)
			and record.symbol_id not in checked_functions
		):
			dt = record.doctype
			if dt and dt in user_perm_doctypes:
				candidates.append(
					_candidate(
						"FR-PERM-007",
						record.span.file,
						record.span.line_start,
						record.function,
						record.span.hash,
						f"frappe.get_all on multi-tenant DocType '{dt}' in a whitelisted path does not apply user permissions.",
						f"Use frappe.get_list('{dt}') or pass strict_user_permissions=True to enforce User Permissions.",
						fix_confidence="high",
					)
				)

	return candidates


# ---------------------------------------------------------------------------
# FR-HOOK family
# ---------------------------------------------------------------------------


def fr_hook_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-HOOK-001: on_submit defined without matching on_cancel (asymmetric lifecycle).

	Submit-side logic with no inverse on cancel means cancelling a document
	doesn't undo its side effects (stock deduction, ledger posting, etc.).
	"""
	return [
		_candidate(
			"FR-HOOK-001",
			record.file,
			record.span.line_start,
			record.class_name,
			record.span.hash,
			f"Class '{record.class_name}' defines on_submit but not on_cancel — submit side-effects are not reversed on cancel.",
			"Submit a document, then cancel it, and verify all side effects (ledger entries, stock, etc.) are fully reversed.",
		)
		for record in python.class_lifecycles
		if record.has_on_submit and not record.has_on_cancel
	]


def fr_hook_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-HOOK-002: Cross-app hook collision on same (doctype, event).

	Multiple apps hooking the same doc_events entry with execution order
	determined by install order, not declared dependency.
	"""
	return [
		_candidate(
			"FR-HOOK-002",
			str(collision.handlers[0].path),
			0,
			f"{collision.doctype}.{collision.event}",
			f"hook_collision_{collision.doctype}_{collision.event}",
			f"Cross-app hook collision: {len(collision.handlers)} apps hook '{collision.doctype}.{collision.event}' — execution order depends on install order.",
			"Install apps in different orders and verify the hook behavior is consistent.",
		)
		for collision in hooks.collisions()
	]


def fr_hook_003(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-HOOK-003: API fast-path divergence — whitelisted endpoint writes via
	frappe.db directly instead of get_doc().save(), silently skipping the doctype's
	own validation chain.
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	permission_checks = {record.symbol_id for record in python.permission_checks}
	candidates: list[Candidate] = []
	for record in python.set_value_calls:
		if (
			record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
			and record.symbol_id not in permission_checks
		):
			candidates.append(
				_candidate(
					"FR-HOOK-003",
					record.span.file,
					record.span.line_start,
					record.function,
					record.span.hash,
					f"Whitelisted path writes '{record.field_name or 'field'}' via db.set_value, skipping the doctype's validate() chain.",
					"Invoke the endpoint, then check whether the doctype's validate/before_save hooks were triggered.",
				)
			)
	return candidates


def fr_hook_004(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-HOOK-004: frappe.enqueue without dedupe/lock key.

	Enqueued jobs without deduplication can double-process after a worker crash
	and RQ re-queue (double stock deduction, duplicate payment capture).
	"""
	return [
		_candidate(
			"FR-HOOK-004",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			"frappe.enqueue() called without a deduplicate/job_id key — job may re-execute after worker crash.",
			"Kill the worker mid-job, verify re-queued execution doesn't double-process.",
			fix_confidence="medium",
		)
		for record in python.enqueue_calls
		if not record.has_dedupe_key and not _is_non_runtime_path(record.span.file)
	]


def fr_hook_005(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	handler_names = {handler.handler.rsplit(".", 1)[-1] for handler in hooks.handlers}
	candidates: list[Candidate] = []
	for record in python.commit_calls:
		# record.function is fully qualified (e.g. "SalesInvoice.on_submit") for
		# DocType controller class methods -- the dominant real-world pattern --
		# but HOOK_LIFECYCLE_METHODS/handler_names hold bare method names. Strip
		# qualification before comparing, or this rule only ever matches
		# module-level hook functions and silently misses controller methods.
		bare_name = record.function.rsplit(".", 1)[-1]
		if bare_name in HOOK_LIFECYCLE_METHODS or bare_name in handler_names:
			candidates.append(
				_candidate(
					"FR-HOOK-005",
					record.span.file,
					record.span.line_start,
					record.function,
					record.span.hash,
					"frappe.db.commit() occurs inside a Frappe lifecycle hook.",
					"Trigger the hook in the owned bench, force a later hook failure, and verify the complete transaction rolls back.",
				)
			)
	return candidates


# ---------------------------------------------------------------------------
# FR-WKFL family
# ---------------------------------------------------------------------------


def fr_wkfl_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-WKFL-001: Missing docstatus guard on submittable DocType mutation.

	Mutations on submittable DocType fields that don't branch on self.docstatus
	can corrupt submitted or cancelled documents.
	"""
	submittable_names = {doctype.name for doctype in schema.submittable_doctypes()}
	reachable = _reachable_from_whitelisted(python, graph)
	perm_check_symbols = {p.symbol_id for p in python.permission_checks}
	candidates: list[Candidate] = []
	for record in python.set_value_calls:
		if (
			record.doctype_arg in submittable_names
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
			and record.symbol_id not in perm_check_symbols
			and record.field_name not in {"docstatus"}
		):
			candidates.append(
				_candidate(
					"FR-WKFL-001",
					record.span.file,
					record.span.line_start,
					record.function,
					record.span.hash,
					f"Mutation on submittable '{record.doctype_arg}' via set_value without docstatus guard.",
					"Create submitted and cancelled records, invoke the endpoint, and verify mutations are blocked on non-draft documents.",
					fix_confidence="medium",
				)
			)
	return candidates


def fr_wkfl_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-WKFL-002",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			"A whitelisted path directly writes workflow_state outside the workflow engine.",
			"Invoke the endpoint over HTTP as a role denied the target transition and verify workflow permissions cannot be bypassed.",
		)
		for record in python.direct_writes
		if record.field_name == "workflow_state"
		and record.symbol_id in reachable
		and not _is_workflow_engine_path(record.span.file)
	]


def fr_wkfl_003(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-WKFL-003: status vs docstatus desync.

	Controller hooks that set `status` without updating `docstatus` (or vice versa)
	on submittable DocTypes cause human-readable status to diverge from docstatus.
	"""
	candidates: list[Candidate] = []
	docstatus_writes_by_func = set()
	for record in python.direct_writes:
		if record.field_name == "docstatus":
			docstatus_writes_by_func.add((record.span.file, record.function))
	for s_rec in python.set_value_calls:
		if s_rec.field_name == "docstatus":
			docstatus_writes_by_func.add((s_rec.span.file, s_rec.function))

	for record in python.set_value_calls:
		if _is_non_runtime_path(record.span.file):
			continue
		if record.field_name == "status":
			# Only alert if the target DocType is submittable (non-submittable DocTypes have no docstatus lifecycle)
			if record.doctype_arg:
				dt = schema.get_doctype(record.doctype_arg)
				if dt is not None and not dt.is_submittable:
					continue
			has_docstatus_write = (record.span.file, record.function) in docstatus_writes_by_func
			if not has_docstatus_write:
				candidates.append(
					_candidate(
						"FR-WKFL-003",
						record.span.file,
						record.span.line_start,
						record.function,
						record.span.hash,
						"frappe.db.set_value writes 'status' without a corresponding 'docstatus' update in the same function.",
						"Set status via this path, then verify docstatus is consistent.",
					)
				)
	return candidates


def fr_wkfl_004(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-WKFL-004: Amendment chain leakage.

	amended_from linking lets a cancelled doc become a new draft; if child-table
	data or workflow_state aren't reset on amendment, stale state leaks.

	Guard: only fires when the DocType JSON explicitly enables amendment
	(`is_amendable = 1`). Without this check the rule fires on every controller
	with on_submit, producing an overwhelming false-positive rate — most ERPNext
	DocTypes are submittable but not amendable.

	When no schema is available (e.g. scanning a bare Python repo without
	DocType JSONs) the amendable set is empty and the rule produces no results,
	which is a better default than drowning the report in FPs.
	"""
	amendable_names = schema.amendable_doctype_names()
	candidates: list[Candidate] = []
	for record in python.class_lifecycles:
		if not record.has_on_submit:
			continue
		# Skip classes whose DocType is not configured as amendable.
		# class_name is the bare class name (e.g. "SalesInvoice"), which matches
		# the DocType name used in the schema index.
		if amendable_names and record.class_name not in amendable_names:
			continue
		# Look for classes that handle submission but don't define an amend method
		# or before_insert that would reset fields on amendment.
		method_set = set(record.methods)
		has_amend_handler = "before_insert" in method_set or "after_insert" in method_set
		if not has_amend_handler:
			candidates.append(
				_candidate(
					"FR-WKFL-004",
					record.file,
					record.span.line_start,
					record.class_name,
					record.span.hash,
					f"Amendable class '{record.class_name}' has on_submit but no before_insert/after_insert to handle amendment chain field resets.",
					"Create a document, submit it, cancel it, amend it, and verify workflow_state and child tables are reset.",
				)
			)
	return candidates



# ---------------------------------------------------------------------------
# FR-INJ family
# ---------------------------------------------------------------------------


def fr_inj_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-INJ-001: Mass assignment via kwargs.

	A whitelisted method passing a raw request dict into frappe.get_doc(kwargs).insert()
	without an explicit field allowlist lets a client set owner, docstatus, etc.
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-INJ-001",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			"Request-controlled data flows directly into frappe.get_doc() — mass assignment risk.",
			"Pass unexpected fields (owner, docstatus, name) through the endpoint and verify they are rejected.",
		)
		for record in python.get_doc_kwargs
		if record.request_controlled and record.symbol_id in reachable
	]


def fr_inj_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-INJ-002: eval()/exec() with request-controlled input.

	Any eval or exec call where the input is traceable to request parameters
	is a potential remote code execution vector.
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-INJ-002",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			f"{record.call_type}() called with request-controlled input — potential RCE.",
			"Pass a crafted payload through the endpoint and verify arbitrary code cannot execute.",
		)
		for record in python.eval_exec_calls
		if record.request_controlled and record.symbol_id in reachable
	]


# ---------------------------------------------------------------------------
# FR-XSS family
# ---------------------------------------------------------------------------

# HTML / rich-text field names commonly used as rendered sinks in Frappe DocTypes.
# These fields are stored to the database and later rendered unescaped inside
# print formats, web pages, or email bodies — a classic stored XSS vector.
_XSS_HTML_FIELDS: frozenset[str] = frozenset({
	"description", "message", "content", "email_content", "html_content",
	"body", "body_html", "html", "notes", "remarks", "comment",
	"instructions", "terms", "terms_and_conditions", "footer",
	"header", "signature", "email_body", "print_format", "address_html",
	"letter_head", "item_description", "custom_html",
})

# Frappe helpers that sanitize / escape HTML output — their presence on the
# propagation path means the output is no longer untrusted user HTML.
_XSS_SANITIZE_CALLS: frozenset[str] = frozenset({
	"frappe.utils.sanitize_html",
	"sanitize_html",
	"frappe.utils.escape_html",
	"escape_html",
	"html.escape",
	"cgi.escape",
	"markupsafe.escape",
	"bleach.clean",
	"bleach.linkify",
})

# Frappe server-side HTML-producing helpers whose output is *not* user-supplied
# raw HTML — they generate predictable, framework-controlled markup.
_XSS_SAFE_SERVER_HTML_FUNCS: frozenset[str] = frozenset({
	"frappe.bold",
	"frappe.get_link_to_form",
	"frappe.utils.get_link_to_form",
	"get_link_to_form",
	"frappe.format",
	"frappe.format_value",
	"frappe.utils.formatdate",
	"frappe.utils.format_currency",
	"frappe.utils.money_in_words",
	"get_formatted_list_for_bulk_print",
	"frappe.get_gravatar",
})


def _call_uses_sanitizer(caller_symbol_id: str, python: PythonSymbolIndex) -> bool:
	"""Return True if any call made directly within this function body is a known sanitizer."""
	return any(
		any(san in c.callee_name for san in _XSS_SANITIZE_CALLS)
		for c in python.calls
		if c.caller_id == caller_symbol_id
	)


def _arg_is_server_html_only(arg_node: object, values: dict) -> bool:
	"""Return True when the argument is purely composed of safe server-HTML helpers.

	This catches patterns like:
	    frappe.throw(frappe.bold(doc.name) + " is invalid")   # safe — framework HTML
	But NOT:
	    frappe.msgprint(frappe.bold(user_input) + custom_text) # still unsafe

	We check only the top-level call — deep nesting is conservatively flagged.
	"""
	import ast as _ast
	if isinstance(arg_node, _ast.Call):
		func_name = _call_name(arg_node.func)
		if func_name in _XSS_SAFE_SERVER_HTML_FUNCS:
			return True
	return False


def fr_xss_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-XSS-001: Stored XSS — user-controlled input written to an HTML field via db.set_value.

	The original broad msgprint-based rule was disabled because Frappe Desk escapes
	server-generated HTML (frappe.bold, get_link_to_form, etc.) before rendering.
	This redesigned rule targets the *stored* XSS vector: user-controlled content
	written to a rich-text or HTML field via db.set_value(), where it will later be
	rendered unescaped inside print formats, email bodies, or custom web views.

	Maps to advisories (Moderate / High):
	  GHSA-hxfh-hh23-fvch  — Stored XSS via unescaped user input in HTML field (frappe/frappe)
	  GHSA-vxmp-h244-wv3r  — Stored XSS in custom HTML field via whitelisted endpoint
	  GHSA-cx24-w5gm-5vv9  — Stored XSS via item_description / notes field (frappe/erpnext)
	  GHSA-7p3m-h76m-hg9v  — Stored XSS via remarks/terms field in purchase document
	  GHSA-v248-pv3c-jvgw  — Stored XSS via address_html / letter_head rendering
	  GHSA-7m8v-g2pr-h2f7  — XSS and Open Redirect in Sign Up (message field)
	  GHSA-2wx6-8gmq-x4fw  — Stored XSS via image upload (profile image html field)
	  GHSA-7f28-gm9h-q6rg  — Stored XSS via Data Import (description field)
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	candidates: list[Candidate] = []

	# Vector 1: db.set_value writing to known HTML/rich-text fields.
	for record in python.set_value_calls:
		if (
			record.field_name in _XSS_HTML_FIELDS
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
			and not _call_uses_sanitizer(record.symbol_id, python)
		):
			candidates.append(_candidate(
				"FR-XSS-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				f"User-controlled input written to HTML field '{record.field_name}' via db.set_value() — "
				"if this field is rendered inside a print format, email body, or web page without "
				"frappe.utils.sanitize_html(), a Stored XSS is possible.",
				"Set the field to a payload such as <img src=x onerror=alert(document.domain)> "
				"via the endpoint, then render a print format or email that includes this field "
				"and verify the payload does not execute in the browser.",
				fix_confidence="high",
			))

	# Vector 2: direct attribute writes to HTML fields on self (doc.description = user_input)
	for record in python.direct_writes:
		if (
			record.field_name in _XSS_HTML_FIELDS
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
			and not _call_uses_sanitizer(record.symbol_id, python)
		):
			candidates.append(_candidate(
				"FR-XSS-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				f"User-controlled input written to HTML field '{record.field_name}' — "
				"verify frappe.utils.sanitize_html() is applied before saving.",
				"Set the field to a payload such as <script>alert(1)</script> via the endpoint "
				"and verify the script does not execute when the document is rendered.",
				fix_confidence="high",
			))

	return candidates


def fr_xss_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-XSS-002: Reflected XSS — user input passed unsanitized to respond_as_web_page or sendmail.

	Detects mutations where `frappe.respond_as_web_page()`, `frappe.sendmail()`, or
	`frappe.get_print()` is called from a whitelisted endpoint and the calling function
	has no `sanitize_html()` guard on the content/message/body argument path.

	This rule specifically targets the *reflected* XSS vectors where user-controlled input
	flows directly into an HTML-rendered HTTP response or email without sanitization.

	Maps to advisories (Moderate / High):
	  GHSA-hxfh-hh23-fvch  — XSS via respond_as_web_page without sanitize_html
	  GHSA-7m8v-g2pr-h2f7  — XSS in Sign Up page via user-controlled message parameter
	  GHSA-cx24-w5gm-5vv9  — XSS in email notification body via unsanitized user input
	  GHSA-v248-pv3c-jvgw  — Reflected XSS via web form HTML rendering path
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	# Frappe output-rendering sinks that produce an HTML response to the browser or
	# to an external mail recipient without implicit server-side escaping.
	_REFLECT_SINKS: frozenset[str] = frozenset({
		"frappe.respond_as_web_page",
		"respond_as_web_page",
		"frappe.sendmail",
		"sendmail",
		"frappe.get_print",
		"get_print",
		"frappe.utils.pdf_generator.get_pdf",
		"get_pdf",
	})
	candidates: list[Candidate] = []
	for record in python.mutations:
		if record.symbol_id not in reachable:
			continue
		if _is_non_runtime_path(record.span.file):
			continue
		# Match on any of the reflect sinks
		kind_lower = record.kind.lower() if record.kind else ""
		is_reflect_sink = (
			record.kind in _REFLECT_SINKS
			or any(record.kind.endswith("." + s.split(".")[-1]) for s in _REFLECT_SINKS if "." in s)
		)
		if not is_reflect_sink:
			continue
		# Only flag if the caller function does NOT contain a sanitizer call
		if _call_uses_sanitizer(record.symbol_id, python):
			continue
		candidates.append(_candidate(
			"FR-XSS-002",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			f"{record.kind}() called from a whitelisted endpoint without sanitize_html() guard — "
			"if any argument contains user-controlled HTML, reflected or stored XSS is possible.",
			"Pass an HTML payload (e.g. <script>alert(document.domain)</script>) as a content "
			"argument through the endpoint and verify the payload is not executed in the browser "
			"or reflected into an email body without escaping.",
			fix_confidence="high",
		))
	return candidates


def fr_xss_003(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-XSS-003: XSS via email template / Jinja context — unescaped user field in render_template.

	Detects cases where frappe.render_template() is called with a context dictionary
	that contains user-supplied values, from a whitelisted endpoint, without an
	application-level sanitize_html() or escape call on the field value.

	This is distinct from FR-SSTI-001 (which flags user-controlled *template strings*):
	FR-XSS-003 flags user-controlled *context variable values* passed into a
	server-side template, which can lead to XSS if the template renders them without
	the `| e` or `| escape` Jinja2 filter.

	Maps to advisories (Moderate):
	  GHSA-hxfh-hh23-fvch  — XSS in email template via unescaped user field in context
	  GHSA-vxmp-h244-wv3r  — Stored XSS via Jinja2 template context without | escape filter
	  GHSA-cx24-w5gm-5vv9  — XSS via print format Jinja2 context variable
	  GHSA-7p3m-h76m-hg9v  — XSS via purchase document Jinja2 template context
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	_TEMPLATE_RENDER_CALLS: frozenset[str] = frozenset({
		"frappe.render_template",
		"render_template",
		"frappe.utils.jinja.render_template",
		"get_jenv",
		"frappe.get_template",
		"get_template",
	})
	candidates: list[Candidate] = []
	for record in python.mutations:
		if record.symbol_id not in reachable:
			continue
		if _is_non_runtime_path(record.span.file):
			continue
		# Match template rendering calls
		is_template_call = (
			record.kind in _TEMPLATE_RENDER_CALLS
			or any(record.kind.endswith("." + s.split(".")[-1]) for s in _TEMPLATE_RENDER_CALLS if "." in s)
		)
		if not is_template_call:
			continue
		# For FR-XSS-003 (context-variable XSS) we exclude cases already caught by
		# FR-SSTI-001 (which flags dynamic *template strings*). The distinguishing
		# condition: the context dict may be dynamic, but the template string itself is a literal.
		# We flag unconditionally here (both a literal template with dynamic context *and*
		# a dynamic template with dynamic context) and rely on deduplication to merge with
		# FR-SSTI-001 findings when they overlap on the same span.
		if _call_uses_sanitizer(record.symbol_id, python):
			continue
		candidates.append(_candidate(
			"FR-XSS-003",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			f"{record.kind}() called from a whitelisted endpoint — verify all user-supplied values "
			"passed in the template context are escaped with | e (or | escape) in the Jinja2 template, "
			"or sanitized with frappe.utils.sanitize_html() before insertion into the context dict.",
			"Pass an HTML payload (e.g. <img src=x onerror=alert(document.domain)>) as a context "
			"variable value, render the template, and verify the output does not contain the unescaped payload.",
			fix_confidence="medium",
		))
	return candidates


# ---------------------------------------------------------------------------
# FR-CSRF family
# ---------------------------------------------------------------------------


def fr_csrf_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-CSRF-001: Guest-accessible state-changing endpoint lacks CSRF protection.

	Exemptions:
	  - Token-based password-reset functions (see _CSRF_001_TOKEN_AUTH_SAFE): these
	    validate a short-lived cryptographic reset_password_key token delivered
	    out-of-band (email), not a browser session cookie.  The cross-origin
	    form-submission attack vector that CSRF guards against is not applicable
	    because an attacker cannot read the one-time token from the victim's inbox.
	"""
	write_symbol_ids = {record.symbol_id for record in python.set_value_calls} | {
		record.symbol_id for record in python.direct_writes
	}
	out = []
	for endpoint in python.whitelisted_endpoints:
		if not (endpoint.allow_guest and endpoint.symbol_id in write_symbol_ids):
			continue
		# Skip token-based password-reset flow: protected by a short-lived
		# cryptographic token (reset_password_key), not by a session cookie,
		# so the standard CSRF attack vector does not apply here.
		fn_name = endpoint.function.rsplit(".", 1)[-1]
		if fn_name in _CSRF_001_TOKEN_AUTH_SAFE:
			continue
		out.append(_candidate(
			"FR-CSRF-001",
			endpoint.span.file,
			endpoint.span.line_start,
			endpoint.function,
			endpoint.span.hash,
			"Guest-accessible state-changing endpoint lacks CSRF protection.",
			"Construct a cross-origin auto-submitting form targeting this "
			"endpoint and verify the write succeeds without a valid CSRF token.",
		))
	return out


# ---------------------------------------------------------------------------
# FR-SSRF family
# ---------------------------------------------------------------------------


def fr_ssrf_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SSRF-001: User-controlled URL passed to outbound request.

	Maps to advisories: GHSA-mggg-hmjm-j6c2 (frappe/frappe SSRF), GHSA-6qcc-cw7f-328g (erpnext SSRF),
	GHSA-m4m4-j2m2-7fcw (erpnext SSRF), GHSA-pj59-9hv9-rmrv (pdfkit SSRF/LFI).
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-SSRF-001",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			"Outbound request URL is user-controlled with no allowlist.",
			"Pass an internal address (e.g. http://169.254.169.254/) as "
			"the URL parameter and verify the request is actually made.",
		)
		for record in python.outbound_request_calls
		if record.url_arg_is_dynamic and record.symbol_id in reachable
	]


# ---------------------------------------------------------------------------
# FR-SSTI family
# ---------------------------------------------------------------------------


def fr_ssti_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SSTI-001: User-controlled string evaluated as a Jinja2 template.

	Detects eval_exec_calls where a Jinja render function (frappe.render_template,
	env.from_string, Template()) is called with a non-literal template argument, plus
	any reachable eval_exec_call whose call_type indicates template rendering.

	Maps to advisories (Critical/High):
	  GHSA-6pmg-vc6m-6wrr — Possibility of Server Side Template Injection (Oct 2026)
	  GHSA-qq98-vfv9-xmxh — Possibility of RCE due to SSTI (Dec 2025)
	  GHSA-v342-4xr9-x3q3 — Possibility of Remote Code Execution due to improper validation (Mar 2025)
	  GHSA-w996-r7v3-87wr — Server-Side Template Injection leading to RCE (Jul 2026, erpnext)
	  GHSA-6w83-8777-v93q — Possibility of SSTI due to missing validation (Aug 2026, erpnext)
	  GHSA-qq49-v74j-hjh7 — Possibility of SSTI due to missing validation (Aug 2026, erpnext)
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	candidates: list[Candidate] = []
	# Catch eval/exec calls — covers frappe.safe_eval and custom render paths
	for record in python.eval_exec_calls:
		if record.request_controlled and record.symbol_id in reachable:
			candidates.append(_candidate(
				"FR-SSTI-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				f"Request-controlled input passed to {record.call_type}() — potential SSTI/RCE via template evaluation.",
				"Pass a Jinja2 payload such as {{7*7}} or {{''.__class__.__mro__[1].__subclasses__()}} "
				"through the endpoint and verify arbitrary template evaluation is rejected.",
				fix_confidence="high",
			))
	# Also catch render_template / jinja2.Environment().from_string() with dynamic
	# template string — these are recorded as outbound_request_calls in some configs
	# but more precisely detected via the dynamic get_doc_kwargs pattern: a whitelisted
	# endpoint feeding form_dict values into frappe.render_template(non_literal).
	# We reuse get_doc_kwargs as the closest available "dynamic first arg" proxy and
	# also flag any reachable set_value_call where field_name is 'message' or 'subject'
	# being directly passed without escaping (common SSTI vector via email templates).
	_SSTI_TRIGGER_FIELDS: frozenset[str] = frozenset({
		"message", "subject", "content", "email_body", "print_format", "template",
	})
	for record in python.set_value_calls:
		if (
			record.field_name in _SSTI_TRIGGER_FIELDS
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(_candidate(
				"FR-SSTI-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				f"Template-rendered field '{record.field_name}' written via db.set_value from a whitelisted endpoint — "
				"if this value is later passed to frappe.render_template(), the result is an SSTI sink.",
				"Verify the stored value is rendered only as escaped plain text, never as a Jinja template.",
				fix_confidence="medium",
			))
	return candidates


# ---------------------------------------------------------------------------
# FR-ARCH family
# ---------------------------------------------------------------------------


def fr_arch_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-ARCH-001: Unsafe archive extraction (TarSlip / ZipSlip).

	Detects tarfile.extractall() and zipfile.extractall() calls reachable from
	whitelisted endpoints where member-path validation is absent.

	Maps to advisories:
	  GHSA-58w2-4cjg-hvp6 — TarSlip RCE in Package Import (Jul 2026, High)
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	candidates: list[Candidate] = []
	# Walk path_traversals for extractall patterns — the path_traversal index
	# captures open/read_text/shutil sinks. extractall is a write sink that
	# the index does not currently cover, so we detect it via outbound_request_calls
	# (which may not apply) OR by inspecting mutations with call_kind matching
	# extractall in the mutations list. Since MutationRecord.kind holds the
	# call name, we can match on it directly.
	for record in python.mutations:
		if (
			(record.kind in {"tarfile.extractall", "extractall", "zipfile.extractall"} or (record.kind and record.kind.endswith(".extractall")))
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(_candidate(
				"FR-ARCH-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				"Archive extractall() called from a whitelisted endpoint — verify member paths are validated "
				"against '..' and absolute-path prefixes before extraction (TarSlip / ZipSlip).",
				"Upload an archive containing a member named '../../sensitive_file' and verify "
				"the extracted file cannot escape the intended target directory.",
				fix_confidence="high",
			))
	# Supplementary: flag any path_traversal record where call_name contains 'extractall'
	for record in python.path_traversals:
		if (
			"extractall" in record.call_name
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(_candidate(
				"FR-ARCH-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				"Archive extractall() with user-controlled path — TarSlip/ZipSlip risk.",
				"Upload an archive containing a member named '../../sensitive_file' and verify "
				"the extracted file cannot escape the intended target directory.",
				fix_confidence="high",
			))
	return candidates


# ---------------------------------------------------------------------------
# FR-UPLOAD family
# ---------------------------------------------------------------------------


def fr_upload_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-UPLOAD-001: File save call reachable from whitelisted endpoint without MIME/extension guard.

	Detects save_file / handle_upload paths that are reachable from whitelisted endpoints
	where the function body contains no extension allowlist check.

	Maps to advisories:
	  GHSA-2wx6-8gmq-x4fw — Stored XSS in User Profile through Image Upload (May 2026, Moderate)
	  GHSA-7f28-gm9h-q6rg — Stored XSS via Data Import (Aug 2026, Low)
	  GHSA-fwrv-4rw4-97fw — Arbitrary File Attachment Injection via File-Handling API (Jun 2026, Moderate)
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	_FILE_SAVE_CALLS: frozenset[str] = frozenset({
		"frappe.utils.file_manager.save_file",
		"frappe.handler.upload_file",
		"save_file",
		"upload_file",
		"handle_upload",
	})
	_EXTENSION_GUARDS: frozenset[str] = frozenset({
		"splitext", "endswith", "allowed_content_types", "ALLOWED_EXTENSIONS",
		"SAFE_EXTENSIONS", "validate_file_type", "check_file_extension",
	})
	candidates: list[Candidate] = []
	# Use mutations index — save_file / upload_file are write operations
	for record in python.mutations:
		if record.kind not in _FILE_SAVE_CALLS and not (record.kind and any(record.kind.endswith("." + s) for s in ("save_file", "upload_file", "handle_upload"))):
			continue
		if record.symbol_id not in reachable:
			continue
		if _is_non_runtime_path(record.span.file):
			continue
		# Check whether the function calls any extension validation guard
		caller_calls = {c.callee_name for c in python.calls if c.caller_id == record.symbol_id}
		if any(any(guard.lower() in call.lower() for guard in _EXTENSION_GUARDS) for call in caller_calls):
			continue
		candidates.append(_candidate(
			"FR-UPLOAD-001",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			f"{record.kind}() is reachable from a whitelisted endpoint — verify the uploaded file's "
			"extension and content-type are validated against a safe allowlist before saving.",
			"Upload an SVG file containing an embedded script tag and verify the server rejects "
			"the upload before the file is written to disk.",
			fix_confidence="medium",
		))
	return candidates


# ---------------------------------------------------------------------------
# FR-REDIR family
# ---------------------------------------------------------------------------


def fr_redir_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-REDIR-001: Unvalidated URL parameter used as redirect target.

	Detects direct_writes where field_name is 'redirect_to' / 'location' or
	set_value calls whose field_name suggests a redirect, reachable from whitelisted
	endpoints with no allowlist guard.

	Maps to advisories:
	  GHSA-j9jr-qrpj-g855 — Open Redirect on Login Page (Oct 2025, Moderate)
	  GHSA-7g27-q225-j894 — Open redirect on login page (May 2024, Moderate)
	  GHSA-78c5-55xg-jm7m — Open Redirect via Unsanitized OAuth State Param (Sep 2026, Moderate)
	  GHSA-7m8v-g2pr-h2f7 — XSS and Open Redirect in Sign Up (Feb 2026, Moderate)
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	_REDIRECT_FIELDS: frozenset[str] = frozenset({
		"redirect_to", "location", "next", "return_url", "redirect_url",
		"redirect", "back_to", "state",
	})
	candidates: list[Candidate] = []
	for record in python.direct_writes:
		if (
			record.field_name in _REDIRECT_FIELDS
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(_candidate(
				"FR-REDIR-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				f"Redirect target field '{record.field_name}' written from a whitelisted endpoint — "
				"verify the URL is validated against an allowlist of trusted domains before use.",
				"Pass an external URL (e.g. https://evil.example/) as the redirect parameter and "
				"verify the server refuses to redirect to untrusted domains.",
				fix_confidence="high",
			))
	for record in python.set_value_calls:
		if (
			record.field_name in _REDIRECT_FIELDS
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(_candidate(
				"FR-REDIR-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				f"Redirect field '{record.field_name}' set via db.set_value from a whitelisted endpoint — "
				"verify redirect target is validated against a trusted domain allowlist.",
				"Pass an external URL as the redirect parameter and verify untrusted domains are rejected.",
				fix_confidence="high",
			))
	return candidates


# ---------------------------------------------------------------------------
# FR-SECRET family
# ---------------------------------------------------------------------------


def fr_secret_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SECRET-001: Sensitive field (secret/token/key/password) written via whitelisted endpoint
	and potentially exposed in response or logs.

	Detects set_value calls targeting known-sensitive field names reachable from whitelisted
	endpoints — these indicate that a secret value may be overwritten (mass assignment) or
	leaked if the same endpoint echoes the record back.

	Maps to advisories:
	  GHSA-p284-r7rh-wq7j — Account takeover via password reset token leakage (Jun 2025, High)
	  GHSA-qrv3-jc3h-f3m6 — Information disclosure leading to account takeover (Mar 2025, High)
	  GHSA-9c55-cq5r-qj5x — DB Schema Enumeration (Jun 2026, Moderate)
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	_SENSITIVE_FIELDS: frozenset[str] = frozenset({
		"password", "api_secret", "api_key", "secret", "token",
		"reset_password_key", "login_token", "new_password", "old_password",
		"auth_token", "access_token", "refresh_token", "private_key",
	})
	candidates: list[Candidate] = []
	for record in python.set_value_calls:
		if (
			record.field_name in _SENSITIVE_FIELDS
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(_candidate(
				"FR-SECRET-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				f"Sensitive field '{record.field_name}' written via db.set_value from a whitelisted endpoint — "
				"verify this field cannot be overwritten by an unprivileged caller or leaked in the response.",
				"Invoke the endpoint as a low-privilege user attempting to set or read the sensitive field and "
				"verify the operation is rejected and the field value is not echoed in the response.",
				fix_confidence="high",
			))
	return candidates


def _resolve_repo_root(schema: SchemaIndex, python: PythonSymbolIndex) -> Path | None:
	sources = getattr(python, "sources", ())
	if sources:
		root = getattr(sources[0], "root", None)
		if root and Path(root).is_dir():
			return Path(root)
	if getattr(schema, "doctypes", ()):
		first_dt = schema.doctypes[0]
		if hasattr(first_dt, "path") and first_dt.path:
			p = Path(first_dt.path).resolve()
			for parent in p.parents:
				if (parent / "hooks.py").is_file() or (parent / "setup.py").is_file() or (parent / "pyproject.toml").is_file():
					return parent
			return p.parent.parent.parent
	for f_rec in getattr(python, "functions", ()):
		p = Path(f_rec.span.file)
		if p.is_absolute() and p.exists():
			return p.parents[1] if len(p.parents) > 1 else p.parent
	cwd = Path.cwd()
	return cwd if cwd.is_dir() else None


def fr_secret_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SECRET-002: Hardcoded plaintext credentials, keys, or committed configuration secrets.

	Scans:
	  1. Python source files for hardcoded secrets assigned to sensitive variables
	     or matching high-confidence credential signatures (private keys, AWS keys, etc.).
	  2. Configuration files (site_config.json, common_site_config.json, .env files) in the
	     project/bench root for committed plaintext passwords (db_password, admin_password,
	     encryption_key, redis/mail passwords, api_secrets).
	"""
	candidates: list[Candidate] = []

	# 1. Hardcoded secrets in Python source files
	for record in getattr(python, "hardcoded_secrets", ()):
		if not _is_non_runtime_path(record.span.file):
			candidates.append(_candidate(
				"FR-SECRET-002",
				record.span.file,
				record.span.line_start,
				record.variable_name,
				record.span.hash,
				f"Hardcoded credential or token detected in source code: '{record.variable_name}' is set to a static secret ({record.masked_value}).",
				"Move the secret to site_config.json or runtime environment variables and rotate the exposed credential immediately.",
				fix_confidence="high",
			))

	# 2. Configuration files (site_config.json, common_site_config.json, .env*)
	repo_root = _resolve_repo_root(schema, python)

	if repo_root and repo_root.is_dir():
		_CONFIG_SECRET_KEYS = frozenset({
			"db_password", "root_password", "admin_password", "encryption_key",
			"redis_cache", "redis_queue", "redis_socketio", "mail_password",
			"secret_key", "webhook_secret", "s3_secret_access_key",
			"backup_aws_secret_key", "dropbox_access_key", "api_secret",
			"paystack_secret_key", "stripe_secret_key", "razorpay_key_secret",
		})
		_SAFE_CONFIG_VALS = frozenset({
			"", "none", "null", "false", "true", "password", "secret", "admin", "test",
			"dummy", "placeholder", "changeme", "your_password", "your_secret",
			"your_api_key", "your_secret_key", "xxx", "123456", "example", "root",
		})

		scanned_paths: set[Path] = set()
		json_patterns = ("site_config.json", "common_site_config.json", "sites/**/site_config.json", "sites/common_site_config.json")
		for pat in json_patterns:
			for path in repo_root.glob(pat):
				if path.is_file() and path not in scanned_paths and not _is_non_runtime_path(str(path)):
					scanned_paths.add(path)
					try:
						content = path.read_text(encoding="utf-8")
						data = json.loads(content)
					except Exception:
						continue

					if not isinstance(data, dict):
						continue

					lines = content.splitlines()
					try:
						rel_file = path.relative_to(repo_root).as_posix()
					except ValueError:
						rel_file = path.name

					for k, v in data.items():
						k_lower = k.lower()
						if k_lower in _CONFIG_SECRET_KEYS and isinstance(v, str):
							v_clean = v.strip()
							v_lower = v_clean.lower()
							if (
								v_clean
								and v_lower not in _SAFE_CONFIG_VALS
								and not (v_clean.startswith("<") and v_clean.endswith(">"))
								and not (v_clean.startswith("{{") and v_clean.endswith("}}"))
								and not v_clean.startswith("$")
							):
								line_num = 1
								for idx, line in enumerate(lines, 1):
									if f'"{k}"' in line or f"'{k}'" in line:
										line_num = idx
										break
								masked = f"{v_clean[:2]}...{v_clean[-2:]}" if len(v_clean) > 4 else "***"
								loc_hash = stable_hash(f"{rel_file}:{line_num}:{k}")
								candidates.append(_candidate(
									"FR-SECRET-002",
									rel_file,
									line_num,
									k,
									loc_hash,
									f"Committed secret in {rel_file}: '{k}' contains a plaintext credential ({masked}).",
									"Remove the committed configuration secret, add the file to .gitignore, and rotate the credential immediately.",
									fix_confidence="high",
								))

		for env_path in repo_root.glob(".env*"):
			if env_path.is_file() and env_path not in scanned_paths and not _is_non_runtime_path(str(env_path)):
				if env_path.name in (".env.example", ".env.sample", ".env.template", ".env.test"):
					continue
				scanned_paths.add(env_path)
				try:
					lines = env_path.read_text(encoding="utf-8").splitlines()
				except Exception:
					continue

				try:
					rel_file = env_path.relative_to(repo_root).as_posix()
				except ValueError:
					rel_file = env_path.name

				for idx, line in enumerate(lines, 1):
					stripped = line.strip()
					if not stripped or stripped.startswith("#"):
						continue
					if "=" in stripped:
						key_part, val_part = stripped.split("=", 1)
						key = key_part.strip()
						val = val_part.strip().strip("\"'")
						k_upper = key.upper()
						if any(s in k_upper for s in ("PASSWORD", "SECRET", "TOKEN", "KEY", "PRIVATE", "AUTH")) and not k_upper.endswith("_PUBLIC"):
							v_lower = val.lower()
							if (
								val
								and v_lower not in _SAFE_CONFIG_VALS
								and not (val.startswith("<") and val.endswith(">"))
								and not (val.startswith("{{") and val.endswith("}}"))
								and not val.startswith("$")
							):
								masked = f"{val[:2]}...{val[-2:]}" if len(val) > 4 else "***"
								loc_hash = stable_hash(f"{rel_file}:{idx}:{key}")
								candidates.append(_candidate(
									"FR-SECRET-002",
									rel_file,
									idx,
									key,
									loc_hash,
									f"Committed environment credential in {rel_file}: '{key}' is hardcoded ({masked}).",
									"Remove hardcoded credentials from environment files, add .env to .gitignore, and rotate the secret.",
									fix_confidence="high",
								))

	return candidates


# ---------------------------------------------------------------------------
# FR-MASSASSIGN family
# ---------------------------------------------------------------------------


def fr_massassign_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-MASSASSIGN-001: Mass assignment via request-controlled kwargs into get_doc or frappe.db.

	Extends FR-INJ-001 (get_doc kwargs) with additional detection of set_value calls where
	the doctype argument is None (dynamic / caller-supplied) from a whitelisted endpoint —
	a pattern that allows an attacker to target arbitrary DocTypes and fields.

	Maps to advisories:
	  GHSA-2c6h-wv85-fxvj — Mass assignment in client endpoint (Aug 2026, Moderate)
	  GHSA-583g-fg76-fhfr — Possibility of SQL injection in bulk_update (Apr 2026, High)
	  GHSA-2c4m-999q-xhx4 — Possibility of SQL Injection due to improper field sanitization (Mar 2026, Moderate)
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	permission_checks = {record.symbol_id for record in python.permission_checks}
	candidates: list[Candidate] = []
	# Dynamic doctype arg (None means the doctype could not be statically resolved — likely
	# caller-supplied via frappe.form_dict) is the mass-assignment indicator.
	for record in python.set_value_calls:
		if (
			record.doctype_arg is None
			and record.symbol_id in reachable
			and record.symbol_id not in permission_checks
			and not _is_non_runtime_path(record.span.file)
		):
			candidates.append(_candidate(
				"FR-MASSASSIGN-001",
				record.span.file,
				record.span.line_start,
				record.function,
				record.span.hash,
				"frappe.db.set_value called with a dynamically-resolved DocType from a whitelisted endpoint "
				"— an attacker may supply an arbitrary DocType and field name to overwrite protected data.",
				"Pass an unexpected DocType (e.g. 'User') and field (e.g. 'api_secret') through the endpoint "
				"and verify the write is rejected.",
				fix_confidence="high",
			))
	return candidates



# Verified complete set of identifiers that are valid on every Frappe Document/BaseDocument
# instance and must NOT be flagged as missing-field references.
#
# Source: frappe/frappe GitHub, develop branch, 2026-08
#   - Standard metadata fields: frappe/model/__init__.py, optional_fields / default_fields
#   - Document methods: frappe/model/document.py (class Document)
#   - BaseDocument methods: frappe/model/base_document.py (class BaseDocument)
#
# Rule: when a new method is added to Frappe's Document base class, add it here too.
# Naming: use the actual method/property name as it appears in Python source.
_RESERVED_DOC_ATTRS: frozenset[str] = frozenset({
    # -------------------------------------------------------------------------
    # Standard DocType metadata fields (every document has these columns)
    # -------------------------------------------------------------------------
    "name", "creation", "modified", "modified_by", "owner",
    "docstatus", "idx", "parent", "parentfield", "parenttype",
    "doctype", "naming_series", "amended_from", "amendment_date",
    # -------------------------------------------------------------------------
    # BaseDocument public methods (frappe/model/base_document.py)
    # -------------------------------------------------------------------------
    "update", "update_if_missing", "get_db_value", "get", "getone",
    "set", "delete_key", "append", "extend", "remove", "parent_doc",
    "meta", "permitted_fieldnames",
    "get_valid_dict", "init_child_tables", "init_valid_columns",
    "get_valid_columns", "is_new", "as_dict", "as_json",
    "get_table_field_doctype", "get_parentfield_of_doctype",
    "db_insert", "db_update", "db_update_all",
    "show_unique_validation_message", "get_field_name_by_key_name",
    "get_label_from_fieldname", "update_modified",
    "get_invalid_links", "set_fetch_from_value",
    # internal but commonly called from controllers:
    "_table_fieldnames", "_non_computed_table_fieldnames",
    "_get_table_fields", "_init_child", "_fix_numeric_types",
    "_get_missing_mandatory_fields", "_validate_selects",
    "_validate_data_fields", "_validate_constants", "_validate_length",
    "_validate_code_fields", "_sync_autoname_field",
    # -------------------------------------------------------------------------
    # Document public methods (frappe/model/document.py)
    # -------------------------------------------------------------------------
    "load_from_db", "mask_fields", "load_children_from_db",
    "_load_child_table_from_db", "reload", "get_latest",
    "check_permission", "has_permission", "raise_no_permission_to",
    "insert", "check_if_locked", "save", "_save",
    "validate_amended_from", "copy_attachments_from_amended_from",
    "update_children", "update_child_table", "reset_computed_child_tables",
    "get_doc_before_save", "has_value_changed", "get_value_before_save",
    "set_new_name", "get_title", "set_title_field",
    "update_single", "set_user_and_timestamp", "set_docstatus",
    "_validate", "_validate_non_negative", "_validate_min_max_value",
    "_fix_rating_value", "validate_workflow", "validate_set_only_once",
    "is_child_table_same", "apply_fieldlevel_read_permissions",
    "validate_higher_perm_levels", "get_permlevel_access",
    "has_permlevel_access_to", "get_permissions", "_set_defaults",
    "check_if_latest", "check_docstatus_transition",
    "set_parent_in_children", "set_name_in_children",
    "validate_update_after_submit", "_validate_mandatory",
    "_prefetch_link_values", "_validate_links",
    "run_method", "notify_update",
    "db_set", "db_get",
    "add_comment", "set_onload", "add_tag",
    # Commonly used Frappe controller utilities (set_status from frappe.model.workflow)
    "set_status",
    # Frappe publish/realtime
    "publish_update", "publish_realtime",
    # Child-table helpers
    "get_all_children",
    # Common inherited from controllers in erpnext/hrms
    "run_notifications", "queue_action",
    # Python built-ins that are valid on any object
    "__init__", "__repr__", "__str__", "__dict__", "__class__",
    "__doc__", "__module__", "__weakref__",
    # Frappe document flags and locals
    "flags", "ignore_permissions", "ignore_links", "ignore_mandatory",
    "ignore_validate", "ignore_version", "ignore_linked_doctypes", "locals", "_locals",
    # Onload data bag
    "_onload",
})


def fr_corr_001_bare_except(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""Bare except that swallows control flow, hiding real errors."""
	rule_id = RENAMED_TAXONOMY["fr_corr_001_bare_except"]
	return [
		_candidate(
			rule_id, rec.span.file, rec.span.line_start, rec.symbol_id.rsplit(":", 1)[-1], rec.span.hash,
			"Bare except silently swallows all exceptions including framework signals.",
			"Synthesize unit test to trigger exception",
			fix_confidence="none",
		)
		for rec in python.bare_except_blocks
		if rec.catches_base_exception and rec.swallows_return
	]

def fr_corr_002_mutable_default(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""Mutable default argument — classic shared-state bug."""
	rule_id = RENAMED_TAXONOMY["fr_corr_002_mutable_default"]
	return [
		_candidate(
			rule_id, rec.span.file, rec.span.line_start, rec.symbol_id.rsplit(":", 1)[-1], rec.span.hash,
			f"Argument '{rec.arg_name}' defaults to a mutable {rec.default_kind}, which is shared across all calls.",
			"Synthesize unit test to trigger shared state",
			fix_confidence="high",
			target_arg=rec.arg_name,
		)
		for rec in python.mutable_default_args
	]

def fr_data_001_bad_fieldname(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""Reference to a fieldname that doesn't exist on the resolved DocType."""
	valid_fields = {d.name: {f.fieldname for f in d.fields} for d in schema.doctypes}
	out = []
	for ref in python.fieldname_references:
		if ref.doctype_resolution_confidence == "low":
			continue
		valid = valid_fields.get(ref.doctype)
		if valid is None or ref.fieldname in valid or ref.fieldname in _RESERVED_DOC_ATTRS:
			continue
		out.append(_candidate(
			"FR-DATA-001", ref.span.file, ref.span.line_start, ref.symbol_id.rsplit(":", 1)[-1], ref.span.hash,
			f"Field '{ref.fieldname}' does not exist on DocType '{ref.doctype}' (resolution confidence: {ref.doctype_resolution_confidence}).",
			"Synthesize unit test to trigger AttributeError",
			fix_confidence="none",
		))
	return out


_LEDGER_TABLE_NAMES = frozenset({"tabgl entry", "tabstock ledger entry"})
_LEDGER_DOCTYPES = frozenset({"gl entry", "stock ledger entry"})
_LEDGER_POSTING_FILES = frozenset({"general_ledger.py", "stock_ledger.py"})
_LEDGER_POSTING_FUNCTIONS = frozenset({
	"make_gl_entries",
	"make_entry",
	"make_sl_entries",
	"make_stock_entry",
	"repost_ledger",
	"repost_entries",
	"repost",
})
_SQL_WRITE_PATTERN = re.compile(
	r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO)\b",
	re.IGNORECASE,
)


def fr_data_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-DATA-002: Direct Ledger Mutation Guard.

	Flags direct SQL INSERT/UPDATE/DELETE mutations or frappe.db.set_value calls
	on General Ledger (tabGL Entry) and Stock Ledger (tabStock Ledger Entry) tables
	outside standard posting routines.
	"""
	candidates: list[Candidate] = []

	# Check raw SQL calls
	for rec in getattr(python, "sql_calls", ()):
		if _is_non_runtime_path(rec.span.file):
			continue
		fname = Path(rec.span.file).name
		if fname in _LEDGER_POSTING_FILES or rec.function in _LEDGER_POSTING_FUNCTIONS:
			continue
		if not rec.query:
			continue
		if _SQL_WRITE_PATTERN.search(rec.query):
			for tbl in ("tabGL Entry", "tabStock Ledger Entry"):
				if _query_mentions_table(rec.query, tbl):
					candidates.append(
						_candidate(
							"FR-DATA-002",
							rec.span.file,
							rec.span.line_start,
							rec.function,
							rec.span.hash,
							f"Direct SQL write on immutable ledger table '{tbl}'. Raw mutations bypass double-entry and stock balance validation.",
							"Route financial/stock mutations through standard posting functions (make_gl_entries, make_sl_entries) or cancellation/amendment flows.",
							fix_confidence="low",
						)
					)

	# Check set_value calls
	for rec in getattr(python, "set_value_calls", ()):
		if _is_non_runtime_path(rec.span.file):
			continue
		fname = Path(rec.span.file).name
		if fname in _LEDGER_POSTING_FILES or rec.function in _LEDGER_POSTING_FUNCTIONS:
			continue
		if rec.doctype_arg and rec.doctype_arg.strip().lower() in _LEDGER_DOCTYPES:
			candidates.append(
				_candidate(
					"FR-DATA-002",
					rec.span.file,
					rec.span.line_start,
					rec.function,
					rec.span.hash,
					f"Direct set_value on immutable ledger DocType '{rec.doctype_arg}'. Mutating posted ledger records corrupts financial/stock integrity.",
					"Route mutations through standard posting functions (make_gl_entries, make_sl_entries) or cancellation/amendment flows.",
					fix_confidence="low",
				)
			)

	return candidates


def fr_perf_001_query_in_loop(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""N+1 query pattern: get_doc() called per-iteration over a get_all() result."""
	return [
		_candidate(
			"FR-PERF-001", rec.span.file, rec.span.line_start, rec.symbol_id.rsplit(":", 1)[-1], rec.span.hash,
			"frappe.get_doc() is called once per loop iteration over a query result.",
			"Synthetic load test to measure N+1 overhead",
			fix_confidence="low",
		)
		for rec in python.queries_in_loop
		if rec.query_kind == "get_doc" and rec.loop_iterates_over_query_result and not _is_non_runtime_path(rec.span.file)
	]


_STANDARD_INDEXED_FIELDS = frozenset({
	"name", "creation", "modified", "modified_by", "owner", "docstatus",
	"parent", "parenttype", "parentfield", "idx",
})


def fr_perf_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERF-002: Unindexed Filter in Query/Report.

	Flags queries or reports filtering on DocType fields that lack database indexes
	(search_index, in_standard_filter, db_index not enabled), triggering expensive
	full table scans on high-volume tables.
	"""
	candidates: list[Candidate] = []
	doctype_map = {dt.name: {f.fieldname: f for f in dt.fields} for dt in schema.doctypes}

	for rec in getattr(python, "query_filters", ()):
		if _is_non_runtime_path(rec.span.file):
			continue
		if not rec.doctype or rec.doctype not in doctype_map:
			continue
		dt_fields = doctype_map[rec.doctype]
		for field in rec.filter_fields:
			if field in _STANDARD_INDEXED_FIELDS:
				continue
			if field not in dt_fields:
				continue
			field_rec = dt_fields[field]
			is_indexed = (
				field_rec.search_index
				or field_rec.in_standard_filter
				or field_rec.db_index
				or field_rec.fieldtype in {"Link", "Check", "Dynamic Link"}
			)
			if not is_indexed:
				candidates.append(
					_candidate(
						"FR-PERF-002",
						rec.span.file,
						rec.span.line_start,
						rec.function,
						rec.span.hash,
						f"Filter on unindexed field '{field}' in {rec.call_name}() for DocType '{rec.doctype}' may cause full table scans.",
						f"Add 'search_index: 1', 'in_standard_filter: 1', or 'db_index: 1' to '{field}' in '{rec.doctype}' DocType JSON.",
						fix_confidence="high",
					)
				)

	return candidates


_HEAVY_TRANSACTION_TABLES = {
	"tabGL Entry": "GL Entry",
	"tabStock Ledger Entry": "Stock Ledger Entry",
	"tabAttendance": "Attendance",
	"tabTimesheet": "Timesheet",
	"tabEmail Queue": "Email Queue",
	"tabActivity Log": "Activity Log",
	"tabRoute History": "Route History",
}
_HEAVY_TRANSACTION_DOCTYPES = frozenset(_HEAVY_TRANSACTION_TABLES.values())

_QUERY_BOUND_PATTERN = re.compile(
	r"\b(LIMIT\s+\d+|BETWEEN\b|posting_date|transaction_date|attendance_date|creation|modified|from_date|to_date|start_date|end_date)\b",
	re.IGNORECASE,
)
_DATE_FILTER_NAMES = frozenset({
	"posting_date", "transaction_date", "attendance_date", "creation", "modified",
	"from_date", "to_date", "start_date", "end_date", "date",
})


def fr_perf_003(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PERF-003: Unbounded Transaction Scan in Report.

	Flags Script Report queries against heavy transactional DocTypes (GL Entry,
	Stock Ledger Entry, Attendance, Timesheet, Email Queue) lacking date range filters
	or a LIMIT clause, causing potential worker memory exhaustion or query timeouts.
	"""
	candidates: list[Candidate] = []

	# SQL calls in report paths
	for rec in getattr(python, "sql_calls", ()):
		if _is_non_runtime_path(rec.span.file):
			continue
		if not _is_report_path(rec.span.file) and rec.function != "execute":
			continue
		if not rec.query:
			continue
		for tbl, dt_name in _HEAVY_TRANSACTION_TABLES.items():
			if _query_mentions_table(rec.query, tbl):
				if not _QUERY_BOUND_PATTERN.search(rec.query):
					candidates.append(
						_candidate(
							"FR-PERF-003",
							rec.span.file,
							rec.span.line_start,
							rec.function,
							rec.span.hash,
							f"Unbounded query on transactional table '{tbl}' in Script Report lacking date filters or LIMIT clause.",
							"Add mandatory date range filters (from_date, to_date, posting_date) or a LIMIT clause to bound report data retrieval.",
							fix_confidence="low",
						)
					)

	# Query filter calls in report paths
	for q_rec in getattr(python, "query_filters", ()):
		if _is_non_runtime_path(q_rec.span.file):
			continue
		if not _is_report_path(q_rec.span.file) and q_rec.function != "execute":
			continue
		if q_rec.doctype in _HEAVY_TRANSACTION_DOCTYPES:
			if not any(f.lower() in _DATE_FILTER_NAMES for f in q_rec.filter_fields):
				candidates.append(
					_candidate(
						"FR-PERF-003",
						q_rec.span.file,
						q_rec.span.line_start,
						q_rec.function,
						q_rec.span.hash,
						f"Unbounded query on transactional DocType '{q_rec.doctype}' in Script Report lacking date filters.",
						"Add mandatory date range filters (from_date, to_date, posting_date) to bound report data retrieval.",
						fix_confidence="low",
					)
				)

	return candidates

def fr_i18n_001_hardcoded_string(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""User-facing string not wrapped in frappe._() for translation.

	Note: every HardcodedStringRecord is, by construction (see visit_Call's collection-time
	isinstance(node.args[0], ast.Constant) check), always an un-wrapped literal — if it had been
	wrapped in frappe._(...), the arg would be an ast.Call, not a Constant, and no record would
	exist. So no further filtering is needed here.
	"""
	return [
		_candidate(
			"FR-I18N-001", rec.span.file, rec.span.line_start, rec.symbol_id.rsplit(":", 1)[-1], rec.span.hash,
			f"User-facing string in {rec.call_kind}() is not wrapped in frappe._().",
			"Synthesize unit test to trigger missing translation",
			fix_confidence="high",
		)
		for rec in python.hardcoded_user_strings
	]


def fr_path_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-PATH-001: Unrestricted file path traversal in file I/O operations.

	Flags user-controlled file paths passed to open(), os.remove(), shutil.*, etc.
	without directory containment or validation guards.
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	candidates: list[Candidate] = []
	for record in python.path_traversals:
		if _is_non_runtime_path(record.span.file):
			continue
		if record.request_controlled and not record.has_guard and (record.symbol_id in reachable or _is_whitelisted_symbol(record.symbol_id, python)):
			candidates.append(
				_candidate(
					"FR-PATH-001",
					record.span.file,
					record.span.line_start,
					record.function,
					record.span.hash,
					f"User-controlled file path passed to {record.call_name}() without path containment validation.",
					"Verify the resolved path begins with the allowed base directory using os.path.commonpath or startswith.",
					fix_confidence="high",
				)
			)
	return candidates


_target_version_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
	"_target_version_var", default=None
)
_from_version_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
	"_from_version_var", default=None
)


def set_target_version(version: str | None, from_version: str | None = None) -> None:
	_target_version_var.set(version)
	_from_version_var.set(from_version)


def get_target_version() -> str | None:
	return _target_version_var.get()


def get_from_version() -> str | None:
	return _from_version_var.get()


_api_changes_cache: dict[str, dict] = {}


def _get_api_changes_data(custom_path: Path | None = None) -> dict:
	target_path = custom_path or (Path(__file__).resolve().parents[1] / "data" / "frappe_api_changes.json")
	p_str = str(target_path)
	if p_str not in _api_changes_cache:
		if target_path.is_file():
			try:
				_api_changes_cache[p_str] = json.loads(target_path.read_text(encoding="utf-8"))
			except Exception:
				_api_changes_cache[p_str] = {}
		else:
			_api_changes_cache[p_str] = {}
	return _api_changes_cache[p_str]


def fr_compat_001(
	schema: SchemaIndex,
	hooks: HookIndex,
	python: PythonSymbolIndex,
	graph: CallGraph,
	*,
	target_version: str | None = None,
	from_version: str | None = None,
	data_path: Path | None = None,
) -> list[Candidate]:
	"""FR-COMPAT-001: Deprecated or Removed Frappe Framework API.

	Scans public API change database derived from Frappe git branch trees.
	Runs ONLY when target_version is configured. Emits findings for removed,
	moved, and deprecated symbols when target_version >= breaking version.
	"""
	tv = target_version or get_target_version()
	if not tv:
		return []

	fv = from_version or get_from_version()
	tv_match = re.search(r"(\d+)", str(tv))
	if not tv_match:
		return []
	tv_num = int(tv_match.group(1))
	fv_num = int(re.search(r"(\d+)", str(fv)).group(1)) if fv and re.search(r"(\d+)", str(fv)) else None

	data = _get_api_changes_data(data_path)
	changes = data.get("changes", [])
	if not changes:
		return []

	change_map: dict[str, dict] = {c["name"]: c for c in changes}

	# Map imports per file for symbol resolution
	imports_by_file: dict[str, dict[str, str]] = {}
	for imp in python.imports:
		if imp.file not in imports_by_file:
			imports_by_file[imp.file] = {}
		imports_by_file[imp.file][imp.local_name] = f"{imp.module}.{imp.imported_name}"

	candidates: list[Candidate] = []
	seen_keys: set[str] = set()

	for call in python.calls:
		if _is_non_runtime_path(call.span.file):
			continue

		callee = call.callee_name
		resolved = callee

		# Resolve alias or local import
		file_imps = imports_by_file.get(call.span.file, {})
		parts = callee.split(".")
		if parts[0] in file_imps:
			base = file_imps[parts[0]]
			resolved = ".".join([base] + parts[1:]) if len(parts) > 1 else base

		entry = change_map.get(resolved) or change_map.get(callee)
		if entry is None and callee.startswith("frappe."):
			if callee.startswith("frappe.db."):
				canon = "frappe.database.database.Database." + callee[len("frappe.db."):]
				entry = change_map.get(canon)

		if not entry:
			continue

		status = entry["status"]
		ref_branch = entry.get("missing_in") if status in ("removed", "moved") else entry.get("last_present_in")
		if not ref_branch:
			continue

		b_match = re.search(r"(\d+)", ref_branch)
		if not b_match:
			continue
		b_num = int(b_match.group(1))

		# Check target version boundary
		if b_num > tv_num:
			continue
		if fv_num is not None and b_num <= fv_num:
			continue

		sym_name = entry["name"]
		key = f"{call.span.file}:{call.span.line_start}:{sym_name}"
		if key in seen_keys:
			continue
		seen_keys.add(key)

		caller_name = call.caller_id.rsplit(":", 1)[-1] if ":" in call.caller_id else call.caller_id
		evidence_path = entry.get("evidence", "")

		if status == "removed":
			msg = f"Frappe API symbol '{sym_name}' was removed in {ref_branch} (evidence: {evidence_path})."
			recipe = f"Update call to modern framework API before upgrading to Frappe {ref_branch}."
		elif status == "moved":
			moved_candidates = entry.get("moved_to") or []
			cand_str = f" Moved to: {', '.join(moved_candidates)}." if moved_candidates else ""
			msg = f"Frappe API symbol '{sym_name}' was moved in {ref_branch}.{cand_str} (evidence: {evidence_path})."
			recipe = f"Update import path before upgrading to Frappe {ref_branch}."
		else:
			dep_msg = f": {entry['deprecation_message']}" if entry.get("deprecation_message") else ""
			msg = f"Frappe API symbol '{sym_name}' is deprecated in {ref_branch}{dep_msg} (evidence: {evidence_path})."
			recipe = f"Migrate deprecated usage before upgrading to Frappe {ref_branch}."

		candidates.append(
			_candidate(
				"FR-COMPAT-001",
				call.span.file,
				call.span.line_start,
				caller_name,
				call.span.hash,
				msg,
				recipe,
				fix_confidence="high" if status == "moved" else "none",
			)
		)

	return candidates


_JS_DEPRECATIONS: tuple[tuple[re.Pattern[str], str, str, str, str], ...] = (
	(
		re.compile(r"\bcur_frm\.cscript\b"),
		"cur_frm.cscript",
		"v14",
		"frappe.ui.form.on('<DocType>', { ... })",
		"cur_frm.cscript is obsolete. Use frappe.ui.form.on() for form event handling.",
	),
	(
		re.compile(r"\bfrappe\.views\.GridReport\b"),
		"frappe.views.GridReport",
		"v15",
		"frappe.views.ReportView or Query Report",
		"frappe.views.GridReport was removed in Frappe v15.",
	),
	(
		re.compile(r"\bcur_dialog\b"),
		"cur_dialog",
		"v15",
		"let d = new frappe.ui.Dialog(...) stored in local/class scope",
		"Global cur_dialog is deprecated in v15+ due to multi-modal lifecycle conflicts.",
	),
)

_JS_SKIP_DIRS = frozenset({"node_modules", ".git", "dist", "build", "coverage", "tests", "patches", ".bench", "env", "venv", ".venv"})


def fr_compat_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-COMPAT-002: Client-side JavaScript Deprecations.

	Detects client-side JavaScript referencing deprecated or removed Frappe client
	APIs (cur_frm.cscript, frappe.views.GridReport, cur_dialog) that cause UI script
	failures upon framework upgrades.
	"""
	candidates: list[Candidate] = []
	repo_root = _resolve_repo_root(schema, python)
	if not repo_root or not repo_root.is_dir():
		return candidates

	for js_file in repo_root.rglob("*.js"):
		if any(part in _JS_SKIP_DIRS for part in js_file.parts):
			continue
		if js_file.name.endswith(".min.js") or js_file.name.endswith(".bundle.js"):
			continue
		if _is_non_runtime_path(str(js_file)):
			continue
		try:
			rel_path = js_file.relative_to(repo_root).as_posix()
		except ValueError:
			rel_path = js_file.as_posix()
		try:
			content = js_file.read_text(encoding="utf-8", errors="ignore")
		except Exception:
			continue
		lines = content.splitlines()
		for idx, line in enumerate(lines, start=1):
			stripped = line.strip()
			if stripped.startswith("//") or stripped.startswith("*"):
				continue
			for pat, api_name, rem_in, repl, details in _JS_DEPRECATIONS:
				if pat.search(line):
					line_hash = stable_hash(f"{rel_path}:{idx}:{line.strip()}")
					candidates.append(
						_candidate(
							"FR-COMPAT-002",
							rel_path,
							idx,
							"client_script",
							line_hash,
							f"Deprecated client-side API '{api_name}' used in JavaScript ({details}).",
							f"Migrate to '{repl}' before upgrading to Frappe {rem_in}.",
							fix_confidence="high",
						)
					)

	return candidates


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------


ALL_RULES: tuple[Rule, ...] = (
	# FR-SQLI family
	fr_sqli_001,
	fr_sqli_002,
	fr_sqli_003,
	fr_sqli_004,
	# FR-PERM family
	fr_perm_001,
	fr_perm_002,
	fr_perm_003,
	fr_perm_004,
	fr_perm_005,
	fr_perm_006,
	fr_perm_007,
	# FR-HOOK family
	fr_hook_001,
	fr_hook_002,
	fr_hook_003,
	fr_hook_004,
	fr_hook_005,
	# FR-WKFL family
	fr_wkfl_001,
	fr_wkfl_002,
	fr_wkfl_003,
	# fr_wkfl_004,  # Disabled: 0/20 precision on real-world validation (frappe/hrms) — rule's premise that amendable DocTypes need custom before_insert/after_insert is incorrect; Frappe core handles field reset via no_copy=1 natively. Needs full redesign before re-enabling.
	# FR-INJ family
	fr_inj_001,
	fr_inj_002,
	# FR-XSS family — Phase 2 precision-tuned XSS rules (replaces disabled FR-INJ-005 / old fr_xss_001)
	# FR-XSS-001: Stored XSS — user input written to HTML fields via db.set_value / direct write
	fr_xss_001,
	# FR-XSS-002: Reflected XSS — user input passed to respond_as_web_page / sendmail without sanitize_html
	fr_xss_002,
	# FR-XSS-003: Template context XSS — user input in Jinja2 render_template context without | escape
	fr_xss_003,
	# FR-CSRF family
	fr_csrf_001,
	# FR-SSRF family
	fr_ssrf_001,
	# FR-SSTI family — GHSA-6pmg-vc6m-6wrr, GHSA-qq98-vfv9-xmxh, GHSA-v342-4xr9-x3q3, GHSA-w996-r7v3-87wr, GHSA-6w83-8777-v93q, GHSA-qq49-v74j-hjh7
	fr_ssti_001,
	# FR-ARCH family — GHSA-58w2-4cjg-hvp6 (TarSlip RCE)
	fr_arch_001,
	# FR-UPLOAD family — GHSA-2wx6-8gmq-x4fw, GHSA-7f28-gm9h-q6rg, GHSA-fwrv-4rw4-97fw
	fr_upload_001,
	# FR-REDIR family — GHSA-j9jr-qrpj-g855, GHSA-7g27-q225-j894, GHSA-78c5-55xg-jm7m, GHSA-7m8v-g2pr-h2f7
	fr_redir_001,
	# FR-SECRET family — GHSA-p284-r7rh-wq7j, GHSA-qrv3-jc3h-f3m6, GHSA-9c55-cq5r-qj5x
	fr_secret_001,
	fr_secret_002,
	# FR-MASSASSIGN family — GHSA-2c6h-wv85-fxvj, GHSA-583g-fg76-fhfr, GHSA-2c4m-999q-xhx4
	fr_massassign_001,
	# FR-CORR family
	fr_corr_001_bare_except,
	fr_corr_002_mutable_default,
	# FR-DATA family
	fr_data_001_bad_fieldname,
	fr_data_002,
	# FR-PATH family
	fr_path_001,
	# FR-PERF family
	fr_perf_001_query_in_loop,
	fr_perf_002,
	fr_perf_003,
	# FR-I18N family
	fr_i18n_001_hardcoded_string,
	# FR-COMPAT family
	fr_compat_001,
	fr_compat_002,
)


def _assert_taxonomy_consistency() -> None:
	rule_names = {rule.__name__ for rule in ALL_RULES}
	unknown = RENAMED_TAXONOMY.keys() - rule_names
	if unknown:
		raise AssertionError(f"RENAMED_TAXONOMY references unknown rule functions: {unknown}")

_assert_taxonomy_consistency()


@dataclass
class _RuleCache:
	reachable: dict[tuple[int, int], set[str]] = field(default_factory=dict)
	endpoint_reachable: dict[tuple[int, int, str], set[str]] = field(default_factory=dict)


# Scoped per execute_rules() call via contextvars instead of a module-level
# dict, so concurrent scans (threads, asyncio tasks) can't corrupt each
# other's cache or read stale entries from a prior run.
_rule_cache_var: contextvars.ContextVar[_RuleCache | None] = contextvars.ContextVar(
	"_rule_cache_var", default=None
)


_last_skipped_rules_count: int = 0


def get_skipped_rules_count() -> int:
	"""Return the number of rules that raised an unhandled exception in the last scan."""
	return _last_skipped_rules_count


def clear_rule_caches() -> None:
	"""Reset rule caches and context-level configuration."""
	set_target_version(None, None)


def execute_rules(
	schema: SchemaIndex,
	hooks: HookIndex,
	python: PythonSymbolIndex,
	call_graph: CallGraph | None = None,
) -> list[Candidate]:
	global _last_skipped_rules_count
	from scanner.logger import logger as _logger
	token = _rule_cache_var.set(_RuleCache())
	skipped_count = 0
	try:
		graph = call_graph or build_call_graph(python)
		candidates: list[Candidate] = []
		for rule in ALL_RULES:
			try:
				candidates.extend(rule(schema, hooks, python, graph))
			except Exception as exc:
				# A single rule failure must not abort the scan. Log the error so it
				# is visible in CI output and --log-level debug without crashing.
				skipped_count += 1
				_logger.warning(
					"Rule %s raised an unexpected exception and was skipped: %s: %s",
					getattr(rule, "__name__", repr(rule)),
					type(exc).__name__,
					exc,
				)
		_last_skipped_rules_count = skipped_count
		candidates = _filter_suppressed_candidates(candidates, python)
		return _deduplicate(candidates)
	finally:
		_rule_cache_var.reset(token)


def _filter_suppressed_candidates(candidates: list[Candidate], python: PythonSymbolIndex) -> list[Candidate]:
	file_lines_cache: dict[str, list[str]] = {}

	def get_lines(file_path_str: str) -> list[str]:
		if file_path_str not in file_lines_cache:
			p = Path(file_path_str)
			if not p.is_file():
				sources = getattr(python, "sources", [])
				for src in sources:
					if str(getattr(src, "path", "")).endswith(file_path_str):
						p = src.path
						break
			if p.is_file():
				try:
					file_lines_cache[file_path_str] = p.read_text(encoding="utf-8").splitlines()
				except Exception:
					file_lines_cache[file_path_str] = []
			else:
				file_lines_cache[file_path_str] = []
		return file_lines_cache[file_path_str]

	filtered: list[Candidate] = []
	for c in candidates:
		lines = get_lines(c.file)
		if lines and 1 <= c.line <= len(lines):
			line_text = lines[c.line - 1]
			if "# frapast:ignore" in line_text:
				comment_part = line_text.split("# frapast:ignore", 1)[1].strip()
				if not comment_part or c.rule_id in comment_part or c.taxonomy_id in comment_part:
					continue
		filtered.append(c)
	return filtered


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _candidate(
	rule_id: str,
	file: str,
	line: int,
	function: str,
	code_location_hash: str,
	evidence: str,
	proof_recipe: str,
	fix_confidence: str = "none",
	target_arg: str | None = None,
) -> Candidate:
	return Candidate(
		rule_id=rule_id,
		rule_version=RULE_VERSIONS.get(rule_id, "1.0.0"),
		taxonomy_id=rule_id,
		file=file,
		line=line,
		function=function,
		code_location_hash=code_location_hash,
		evidence=evidence,
		proof_recipe=proof_recipe,
		fix_confidence=fix_confidence,
		target_arg=target_arg,
	)


def _reachable_from_whitelisted(python: PythonSymbolIndex, graph: CallGraph) -> set[str]:
	cache = _rule_cache_var.get()
	cache_key = (id(python), id(graph))
	if cache is not None and cache_key in cache.reachable:
		return cache.reachable[cache_key]
	entry_points = [endpoint.symbol_id for endpoint in python.whitelisted_endpoints]
	entry_points.extend(report.symbol_id for report in getattr(python, "report_entry_points", ()))
	result = {
		symbol_id
		for ep in entry_points
		for symbol_id in graph.reachable_from(ep, max_hops=3)
	}
	if cache is not None:
		cache.reachable[cache_key] = result
	return result


def _is_whitelisted_symbol(symbol_id: str, python: PythonSymbolIndex) -> bool:
	return any(ep.symbol_id == symbol_id for ep in python.whitelisted_endpoints) or any(
		rp.symbol_id == symbol_id for rp in getattr(python, "report_entry_points", ())
	)


def _has_unchecked_whitelisted_path(
	sink_id: str,
	python: PythonSymbolIndex,
	graph: CallGraph,
	permission_checks: set[str],
) -> bool:
	cache = _rule_cache_var.get()
	for endpoint in python.whitelisted_endpoints:
		is_direct_sink = sink_id == endpoint.symbol_id
		is_one_hop_sink = sink_id in graph.edges.get(endpoint.symbol_id, ())
		if not (is_direct_sink or is_one_hop_sink):
			continue

		# If the endpoint or its 1-hop helpers have a permission check, it's considered guarded
		cache_key = (id(python), id(graph), endpoint.symbol_id)
		if cache is not None and cache_key in cache.endpoint_reachable:
			endpoint_reachable = cache.endpoint_reachable[cache_key]
		else:
			endpoint_reachable = set(graph.reachable_from(endpoint.symbol_id, max_hops=1))
			if cache is not None:
				cache.endpoint_reachable[cache_key] = endpoint_reachable

		if not (endpoint_reachable & permission_checks):
			return True
	return False


def _path_has_permission_check(symbol_id: str, graph: CallGraph, permission_checks: set[str]) -> bool:
	"""Check if a symbol or any of its 1-hop callees has a permission check."""
	reachable = set(graph.reachable_from(symbol_id, max_hops=1))
	return bool(reachable & permission_checks)


def _path_has_mutation(symbol_id: str, graph: CallGraph, mutations: set[str]) -> bool:
	"""Check if a symbol or any of its 1-hop callees performs a mutation/write."""
	reachable = set(graph.reachable_from(symbol_id, max_hops=1))
	return bool(reachable & mutations)


def _query_mentions_table(query: str, table_name: str) -> bool:
	return bool(re.search(rf"(?<![A-Za-z0-9_])`?{re.escape(table_name)}`?(?![A-Za-z0-9_])", query, re.IGNORECASE))


def _is_workflow_engine_path(path: str) -> bool:
	parts = {part.lower() for part in path.replace("\\", "/").split("/")}
	return "workflow" in parts or "workflow_action" in parts


def _is_non_runtime_path(path: str) -> bool:
	parts = [part.lower() for part in path.replace("\\", "/").split("/")]
	filename = parts[-1] if parts else ""
	return "patches" in parts or "tests" in parts or filename.startswith("test_") or filename in {"setup.py", "install.py"}


def _is_report_path(path: str) -> bool:
	"""Detect Script Report / Query Report files."""
	parts = [part.lower() for part in path.replace("\\", "/").split("/")]
	return "report" in parts or any(part.endswith("_report") for part in parts)


def _deduplicate(candidates: list[Candidate]) -> list[Candidate]:
	unique = {
		(candidate.rule_id, candidate.file, candidate.line, candidate.code_location_hash): candidate
		for candidate in candidates
	}
	return sorted(unique.values(), key=lambda item: (item.rule_id, item.file, item.line, item.function))
