from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from scanner.callgraph import CallGraph, build_call_graph
from scanner.hooks import HookIndex
from scanner.python import PythonSymbolIndex
from scanner.schema import SchemaIndex
from scanner.shared import stable_hash


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

	def with_status(self, status: str) -> "Candidate":
		return replace(self, status=status)


Rule = Callable[[SchemaIndex, HookIndex, PythonSymbolIndex, CallGraph], list[Candidate]]


# ---------------------------------------------------------------------------
# FR-SQLI family
# ---------------------------------------------------------------------------


def fr_sqli_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
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
		if record.symbol_id in reachable and not _is_non_runtime_path(record.span.file)
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
	"""
	permission_checks = {record.symbol_id for record in python.permission_checks}
	return [
		_candidate(
			"FR-PERM-001",
			endpoint.span.file,
			endpoint.span.line_start,
			endpoint.function,
			endpoint.span.hash,
			"Whitelisted endpoint has no permission check in body or within one hop.",
			"Invoke the endpoint as a low-privilege user and verify access is rejected for unauthorized documents.",
			fix_confidence="medium",
		)
		for endpoint in python.whitelisted_endpoints
		if not _path_has_permission_check(endpoint.symbol_id, graph, permission_checks)
	]


def fr_perm_002(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
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
			words = set(re.findall(r'[A-Za-z0-9_]+', call.query))
			mentioned_tables = words.intersection(table_to_doctype.keys())
			for table_name in mentioned_tables:
				doctype = table_to_doctype[table_name]
				if doctype.name not in report_doctypes_with_hooks:
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
		words = set(re.findall(r'[A-Za-z0-9_]+', call.query))
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
	candidates: list[Candidate] = []
	for record in python.set_value_calls:
		if (
			record.doctype_arg in submittable_names
			and record.symbol_id in reachable
			and not _is_non_runtime_path(record.span.file)
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
			
	for record in python.direct_writes:
		if _is_non_runtime_path(record.span.file):
			continue
		if record.field_name == "status":
			# Check if there's a matching docstatus write in the same function
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
	"""
	candidates: list[Candidate] = []
	for record in python.class_lifecycles:
		if not record.has_on_submit:
			continue
		# Look for classes that handle submission but don't define an amend method
		# or before_insert that would reset fields
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
					f"Submittable class '{record.class_name}' has on_submit but no before_insert/after_insert to handle amendment chain field resets.",
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


def fr_xss_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""Unescaped user input rendered via frappe.msgprint/throw.

	NOTE: taxonomy_id is FR-INJ-005 (renamed from FR-XSS-001).
	"""
	reachable = _reachable_from_whitelisted(python, graph)
	return [
		_candidate(
			"FR-INJ-005",
			record.span.file,
			record.span.line_start,
			record.function,
			record.span.hash,
			"frappe.msgprint/throw renders unescaped user-controlled input.",
			"Submit a payload like <img src=x onerror=alert(1)> as the "
			"relevant field and confirm it renders unescaped in the browser.",
		)
		for record in python.msgprint_calls
		if record.uses_unescaped_user_input and record.symbol_id in reachable
	]


# ---------------------------------------------------------------------------
# FR-CSRF family
# ---------------------------------------------------------------------------


def fr_csrf_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-CSRF-001: Guest-accessible state-changing endpoint lacks CSRF protection."""
	write_symbol_ids = {record.symbol_id for record in python.set_value_calls} | {
		record.symbol_id for record in python.direct_writes
	}
	return [
		_candidate(
			"FR-CSRF-001",
			endpoint.span.file,
			endpoint.span.line_start,
			endpoint.function,
			endpoint.span.hash,
			"Guest-accessible state-changing endpoint lacks CSRF protection.",
			"Construct a cross-origin auto-submitting form targeting this "
			"endpoint and verify the write succeeds without a valid CSRF token.",
		)
		for endpoint in python.whitelisted_endpoints
		if endpoint.allow_guest and endpoint.symbol_id in write_symbol_ids
	]


# ---------------------------------------------------------------------------
# FR-SSRF family
# ---------------------------------------------------------------------------


def fr_ssrf_001(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""FR-SSRF-001: User-controlled URL passed to outbound request."""
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


_RESERVED_DOC_ATTRS = {"name", "creation", "modified", "modified_by", "owner", "docstatus", "idx", "parent", "parentfield", "parenttype", "doctype"}

def fr_corr_001_bare_except(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""Bare except that swallows control flow, hiding real errors.

	NOTE: taxonomy_id is FR-HOOK-006 (renamed from FR-CORR-001 — see
	taxonomy_registry.yaml `extensions`). Function name is kept for git-blame
	continuity but the emitted ID MUST match the registry, not the old name.
	"""
	return [
		_candidate(
			"FR-HOOK-006", rec.span.file, rec.span.line_start, rec.symbol_id.rsplit(":", 1)[-1], rec.span.hash,
			"Bare except silently swallows all exceptions including framework signals.",
			"Synthesize unit test to trigger exception",
			fix_confidence="none",
		)
		for rec in python.bare_except_blocks
		if rec.catches_base_exception and rec.swallows_return
	]

def fr_corr_002_mutable_default(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, graph: CallGraph) -> list[Candidate]:
	"""Mutable default argument — classic shared-state bug.

	NOTE: taxonomy_id is FR-HOOK-007 (renamed from FR-CORR-002).
	"""
	return [
		_candidate(
			"FR-HOOK-007", rec.span.file, rec.span.line_start, rec.symbol_id.rsplit(":", 1)[-1], rec.span.hash,
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
		if rec.query_kind == "get_doc" and rec.loop_iterates_over_query_result
	]

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
	fr_wkfl_004,
	# FR-INJ family
	fr_inj_001,
	fr_inj_002,
	# FR-XSS family
	fr_xss_001,
	# FR-CSRF family
	fr_csrf_001,
	# FR-SSRF family
	fr_ssrf_001,
	# FR-CORR family
	fr_corr_001_bare_except,
	fr_corr_002_mutable_default,
	# FR-DATA family
	fr_data_001_bad_fieldname,
	# FR-PERF family
	fr_perf_001_query_in_loop,
	# FR-I18N family
	fr_i18n_001_hardcoded_string,
)


def clear_rule_caches() -> None:
	_REACHABLE_CACHE.clear()
	_ENDPOINT_REACHABLE_CACHE.clear()


def execute_rules(
	schema: SchemaIndex,
	hooks: HookIndex,
	python: PythonSymbolIndex,
	call_graph: CallGraph | None = None,
) -> list[Candidate]:
	clear_rule_caches()
	graph = call_graph or build_call_graph(python)
	candidates = [candidate for rule in ALL_RULES for candidate in rule(schema, hooks, python, graph)]
	candidates = _filter_suppressed_candidates(candidates, python)
	return _deduplicate(candidates)


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


_REACHABLE_CACHE: dict[tuple[int, int], tuple[object, object, set[str]]] = {}

def _reachable_from_whitelisted(python: PythonSymbolIndex, graph: CallGraph) -> set[str]:
	cache_key = (id(python), id(graph))
	cached = _REACHABLE_CACHE.get(cache_key)
	if cached is not None and cached[0] is python and cached[1] is graph:
		return cached[2]
	result = {
		symbol_id
		for endpoint in python.whitelisted_endpoints
		for symbol_id in graph.reachable_from(endpoint.symbol_id, max_hops=1)
	}
	_REACHABLE_CACHE[cache_key] = (python, graph, result)
	return result


_ENDPOINT_REACHABLE_CACHE: dict[tuple[int, int, str], tuple[object, object, set[str]]] = {}

def _has_unchecked_whitelisted_path(
	sink_id: str,
	python: PythonSymbolIndex,
	graph: CallGraph,
	permission_checks: set[str],
) -> bool:
	for endpoint in python.whitelisted_endpoints:
		if sink_id == endpoint.symbol_id:
			pass
		elif sink_id in graph.edges.get(endpoint.symbol_id, ()):
			pass
		else:
			continue
		
		# If the endpoint or its 1-hop helpers have a permission check, it's considered guarded
		cache_key = (id(python), id(graph), endpoint.symbol_id)
		cached = _ENDPOINT_REACHABLE_CACHE.get(cache_key)
		if cached is not None and cached[0] is python and cached[1] is graph:
			endpoint_reachable = cached[2]
		else:
			endpoint_reachable = set(graph.reachable_from(endpoint.symbol_id, max_hops=1))
			_ENDPOINT_REACHABLE_CACHE[cache_key] = (python, graph, endpoint_reachable)
		
		if not (endpoint_reachable & permission_checks):
			return True
	return False


def _path_has_permission_check(symbol_id: str, graph: CallGraph, permission_checks: set[str]) -> bool:
	"""Check if a symbol or any of its 1-hop callees has a permission check."""
	reachable = set(graph.reachable_from(symbol_id, max_hops=1))
	return bool(reachable & permission_checks)


def _query_mentions_table(query: str, table_name: str) -> bool:
	return bool(re.search(rf"(?<![A-Za-z0-9_])`?{re.escape(table_name)}`?(?![A-Za-z0-9_])", query, re.IGNORECASE))


def _is_workflow_engine_path(path: str) -> bool:
	parts = {part.lower() for part in path.split("/")}
	return "workflow" in parts or "workflow_action" in parts


def _is_non_runtime_path(path: str) -> bool:
	parts = [part.lower() for part in path.split("/")]
	filename = parts[-1] if parts else ""
	return "patches" in parts or "tests" in parts or filename.startswith("test_")


def _is_report_path(path: str) -> bool:
	"""Detect Script Report / Query Report files."""
	parts = [part.lower() for part in path.split("/")]
	return "report" in parts or any(part.endswith("_report") for part in parts)


def _deduplicate(candidates: list[Candidate]) -> list[Candidate]:
	unique = {
		(candidate.rule_id, candidate.file, candidate.line, candidate.code_location_hash): candidate
		for candidate in candidates
	}
	return sorted(unique.values(), key=lambda item: (item.rule_id, item.file, item.line, item.function))
