from __future__ import annotations

from dataclasses import dataclass

from scanner.shared import SourceSpan


class PythonParseError(ValueError):
	code = "AST_PARSE_ERROR"


@dataclass(frozen=True)
class WhitelistedEndpoint:
	function: str
	allow_guest: bool
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class IgnorePermissionsRecord:
	function: str
	value: bool
	span: SourceSpan
	symbol_id: str
	call_name: str | None = None


@dataclass(frozen=True)
class SqlCallRecord:
	function: str
	parameterized: bool
	dynamic: bool
	request_controlled: bool
	span: SourceSpan
	symbol_id: str
	query: str | None


@dataclass(frozen=True)
class PermCheckRecord:
	function: str
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class CommitCallRecord:
	function: str
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class DirectWriteRecord:
	function: str
	field_name: str | None
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class MutationRecord:
	function: str
	span: SourceSpan
	symbol_id: str
	kind: str


@dataclass(frozen=True)
class PathTraversalRecord:
	function: str
	span: SourceSpan
	symbol_id: str
	call_name: str
	has_guard: bool
	request_controlled: bool


@dataclass(frozen=True)
class ReportEntryPointRecord:
	file: str
	function: str
	symbol_id: str
	span: SourceSpan


@dataclass(frozen=True)
class FunctionRecord:
	id: str
	file: str
	function: str
	qualified_name: str
	span: SourceSpan


@dataclass(frozen=True)
class CallRecord:
	caller_id: str
	callee_name: str
	span: SourceSpan


@dataclass(frozen=True)
class StringDispatchRecord:
	"""Tracks frappe.call('a.b.c') / frappe.enqueue('a.b.c') string-literal dispatch."""

	caller_symbol_id: str
	target_dotted_path: str
	span: SourceSpan


@dataclass(frozen=True)
class DynamicMethodCallRecord:
	"""Tracks frappe.get_doc(...).method_name() dynamic method dispatch."""

	caller_symbol_id: str
	method_name: str
	span: SourceSpan


@dataclass(frozen=True)
class ImportRecord:
	file: str
	local_name: str
	module: str
	imported_name: str


@dataclass(frozen=True)
class EnqueueCallRecord:
	"""Tracks frappe.enqueue() calls — mutating jobs without dedupe keys are risky."""

	function: str
	has_dedupe_key: bool
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class EvalExecRecord:
	"""Tracks eval()/exec() calls — request-controlled input is critical."""

	function: str
	call_type: str  # "eval" or "exec"
	request_controlled: bool
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class QueryBuilderRecord:
	"""Tracks frappe.qb usage with dynamic table/column names via string concat."""

	function: str
	dynamic_table: bool
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class GetDocKwargsRecord:
	"""Tracks frappe.get_doc(kwargs) where kwargs is request-controlled — mass assignment risk."""

	function: str
	request_controlled: bool
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class SetValueRecord:
	"""Tracks frappe.db.set_value calls — bypasses controller validate/before_save hooks."""

	function: str
	doctype_arg: str | None
	field_name: str | None
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class MsgprintRecord:
	"""Tracks frappe.msgprint/frappe.throw calls with unescaped user input."""

	function: str
	uses_unescaped_user_input: bool
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class OutboundRequestRecord:
	"""Tracks requests.get/post or similar outbound HTTP calls with dynamic URL."""

	function: str
	url_arg_is_dynamic: bool
	span: SourceSpan
	symbol_id: str


@dataclass(frozen=True)
class ClassLifecycleRecord:
	"""Tracks which lifecycle methods a DocType controller class defines."""

	class_name: str
	file: str
	has_on_submit: bool
	has_on_cancel: bool
	has_before_save: bool
	has_validate: bool
	has_before_submit: bool
	methods: tuple[str, ...]
	span: SourceSpan


@dataclass(frozen=True)
class BareExceptRecord:
	symbol_id: str
	span: SourceSpan
	swallows_return: bool
	catches_base_exception: bool


@dataclass(frozen=True)
class MutableDefaultArgRecord:
	symbol_id: str
	span: SourceSpan
	arg_name: str
	default_kind: str


@dataclass(frozen=True)
class FieldnameRefRecord:
	symbol_id: str
	span: SourceSpan
	doctype: str
	fieldname: str
	access_kind: str
	doctype_resolution_confidence: str


@dataclass(frozen=True)
class QueryInLoopRecord:
	symbol_id: str
	span: SourceSpan
	query_kind: str
	loop_iterates_over_query_result: bool


@dataclass(frozen=True)
class HardcodedStringRecord:
	symbol_id: str
	span: SourceSpan
	call_kind: str
	literal: str


@dataclass(frozen=True)
class PythonParseErrorRecord:
	file: str
	message: str


@dataclass(frozen=True)
class UnusedImportRecord:
	file: str
	local_name: str


@dataclass(frozen=True)
class PythonSymbolIndex:
	whitelisted_endpoints: tuple[WhitelistedEndpoint, ...]
	ignore_permissions: tuple[IgnorePermissionsRecord, ...]
	sql_calls: tuple[SqlCallRecord, ...]
	permission_checks: tuple[PermCheckRecord, ...]
	commit_calls: tuple[CommitCallRecord, ...]
	direct_writes: tuple[DirectWriteRecord, ...]
	functions: tuple[FunctionRecord, ...]
	calls: tuple[CallRecord, ...]
	imports: tuple[ImportRecord, ...]
	unresolved: tuple[str, ...]
	parser_backend: str
	enqueue_calls: tuple[EnqueueCallRecord, ...] = ()
	eval_exec_calls: tuple[EvalExecRecord, ...] = ()
	query_builder_calls: tuple[QueryBuilderRecord, ...] = ()
	get_doc_kwargs: tuple[GetDocKwargsRecord, ...] = ()
	set_value_calls: tuple[SetValueRecord, ...] = ()
	class_lifecycles: tuple[ClassLifecycleRecord, ...] = ()
	direct_calls: tuple[tuple[str, str], ...] = ()
	string_dispatch_calls: tuple[StringDispatchRecord, ...] = ()
	dynamic_method_calls: tuple[DynamicMethodCallRecord, ...] = ()
	msgprint_calls: tuple[MsgprintRecord, ...] = ()
	outbound_request_calls: tuple[OutboundRequestRecord, ...] = ()
	bare_except_blocks: tuple[BareExceptRecord, ...] = ()
	mutable_default_args: tuple[MutableDefaultArgRecord, ...] = ()
	fieldname_references: tuple[FieldnameRefRecord, ...] = ()
	queries_in_loop: tuple[QueryInLoopRecord, ...] = ()
	hardcoded_user_strings: tuple[HardcodedStringRecord, ...] = ()
	mutations: tuple[MutationRecord, ...] = ()
	path_traversals: tuple[PathTraversalRecord, ...] = ()
	report_entry_points: tuple[ReportEntryPointRecord, ...] = ()
	unused_imports: tuple[UnusedImportRecord, ...] = ()
	parse_errors: tuple[PythonParseErrorRecord, ...] = ()

