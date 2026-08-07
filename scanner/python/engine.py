from __future__ import annotations

import ast
from pathlib import Path

from scanner.python.models import (
	CallRecord,
	ClassLifecycleRecord,
	CommitCallRecord,
	DirectWriteRecord,
	DynamicMethodCallRecord,
	EnqueueCallRecord,
	EvalExecRecord,
	FunctionRecord,
	GetDocKwargsRecord,
	IgnorePermissionsRecord,
	ImportRecord,
	MsgprintRecord,
	OutboundRequestRecord,
	PermCheckRecord,
	PythonParseError,
	PythonSymbolIndex,
	QueryBuilderRecord,
	SetValueRecord,
	SqlCallRecord,
	BareExceptRecord,
	MutableDefaultArgRecord,
	FieldnameRefRecord,
	QueryInLoopRecord,
	HardcodedStringRecord,
	UnusedImportRecord,
	StringDispatchRecord,
	WhitelistedEndpoint,
)
from scanner.shared import SourceFile, SourceSpan, stable_hash


SKIP_DIRS = {".git", "node_modules", ".venv", "env", "__pycache__", "benchmark", "fixtures", "scratch", "tmp", "sites"}

LIFECYCLE_METHODS = frozenset(
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


def discover_python_files(app_roots: str | Path | list[str | Path] | tuple[str | Path, ...]) -> list[SourceFile]:
	roots = _normalize_roots(app_roots)
	files: list[SourceFile] = []
	for root in roots:
		for path in sorted(root.rglob("*.py")):
			try:
				rel_parts = path.relative_to(root).parts[:-1]
			except ValueError:
				rel_parts = path.parts[:-1]
			if any(part in SKIP_DIRS for part in rel_parts):
				continue
			files.append(SourceFile(path=path, root=root))
	return files


from scanner.logger import logger

def build_python_index(files: list[SourceFile] | tuple[SourceFile, ...]) -> PythonSymbolIndex:
	collector = _IndexCollector()
	for source in files:
		try:
			text = source.path.read_text(encoding="utf-8")
			tree = ast.parse(text, filename=str(source.path))
			collector.collect(source, tree, text.splitlines())
		except Exception as exc:
			logger.warning("Skipping %s due to parse error: %s", source.path, exc)
			continue
	return collector.build()


def load(repo_path: str | Path) -> PythonSymbolIndex:
	return build_python_index(discover_python_files(Path(repo_path)))


def _normalize_roots(app_roots: str | Path | list[str | Path] | tuple[str | Path, ...]) -> list[Path]:
	if isinstance(app_roots, (str, Path)):
		return [Path(app_roots)]
	return [Path(root) for root in app_roots]


def _parser_backend() -> str:
	try:
		import libcst  # noqa: F401

		return "libcst_available_ast_semantic_index"
	except ImportError:
		return "python_ast_semantic_index"


class _IndexCollector:
	def __init__(self) -> None:
		self.whitelisted: list[WhitelistedEndpoint] = []
		self.ignore_permissions: list[IgnorePermissionsRecord] = []
		self.sql_calls: list[SqlCallRecord] = []
		self.permission_checks: list[PermCheckRecord] = []
		self.commit_calls: list[CommitCallRecord] = []
		self.direct_writes: list[DirectWriteRecord] = []
		self.functions: list[FunctionRecord] = []
		self.calls: list[CallRecord] = []
		self.imports: list[ImportRecord] = []
		self.unresolved: list[str] = []
		self.enqueue_calls: list[EnqueueCallRecord] = []
		self.eval_exec_calls: list[EvalExecRecord] = []
		self.query_builder_calls: list[QueryBuilderRecord] = []
		self.get_doc_kwargs: list[GetDocKwargsRecord] = []
		self.set_value_calls: list[SetValueRecord] = []
		self.class_lifecycles: list[ClassLifecycleRecord] = []
		self.string_dispatch_calls: list[StringDispatchRecord] = []
		self.dynamic_method_calls: list[DynamicMethodCallRecord] = []
		self.msgprint_calls: list[MsgprintRecord] = []
		self.outbound_request_calls: list[OutboundRequestRecord] = []
		self.bare_except_blocks: list[BareExceptRecord] = []
		self.mutable_default_args: list[MutableDefaultArgRecord] = []
		self.fieldname_references: list[FieldnameRefRecord] = []
		self.queries_in_loop: list[QueryInLoopRecord] = []
		self.hardcoded_user_strings: list[HardcodedStringRecord] = []
		self.unused_imports: list[UnusedImportRecord] = []
		self._document_subclass_names: set[str] = set()
		self._non_document_bases: set[str] = set()

	def collect(self, source: SourceFile, tree: ast.Module, lines: list[str]) -> None:
		for node in tree.body:
			if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
				for imported in node.names:
					if imported.name != "*":
						self.imports.append(
							ImportRecord(
								source.relative_path,
								imported.asname or imported.name,
								node.module,
								imported.name,
							)
						)
			elif isinstance(node, ast.Import):
				for imported in node.names:
					if imported.asname:
						# "import a.b.c as x" binds x -> a.b.c; x.<attr> should resolve to a.b.c.<attr>
						self.imports.append(
							ImportRecord(source.relative_path, imported.asname, "", imported.name)
						)
					else:
						# "import a.b.c" (no alias) only binds the top-level name "a" in the
						# namespace; "a.<anything>" is already the correct dotted path as-is, so
						# no rewriting is needed (or wanted) for the bound name.
						top_level = imported.name.split(".")[0]
						self.imports.append(
							ImportRecord(source.relative_path, top_level, "", top_level)
						)
			elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
				self._collect_function(source, node, lines, ())
			elif isinstance(node, ast.ClassDef):
				self._collect_class(source, node, lines)

	def _collect_class(self, source: SourceFile, node: ast.ClassDef, lines: list[str]) -> None:
		method_names: list[str] = []

		known_base_names = {base_node.name for base_node in getattr(self, "_class_records_seen", ())}
		is_document_subclass = any(
			(isinstance(base, ast.Name) and (base.id.endswith("Document") or base.id in self._non_document_bases))
			or (isinstance(base, ast.Attribute) and base.attr.endswith("Document"))
			for base in node.bases
		)
		if not is_document_subclass:
			for base in node.bases:
				base_name = base.id if isinstance(base, ast.Name) else (base.attr if isinstance(base, ast.Attribute) else None)
				if base_name and base_name in self._document_subclass_names:
					is_document_subclass = True
					break
		if is_document_subclass:
			self._document_subclass_names.add(node.name)
		else:
			self._non_document_bases.add(node.name)

		def _class_name_to_doctype(class_name: str) -> str:
			import re
			# Treat a run of capitals as one token (POSInvoice -> "POS Invoice", not "P O S Invoice"),
			# then split before a capital that starts a new lowercase word.
			spaced = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", class_name)
			spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
			return spaced

		doctype_name = _class_name_to_doctype(node.name) if is_document_subclass else None

		for child in node.body:
			if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
				method_names.append(child.name)
				self._collect_function(source, child, lines, (node.name,), doctype_name)

		lifecycle_names = set(method_names) & LIFECYCLE_METHODS
		if lifecycle_names:
			self.class_lifecycles.append(
				ClassLifecycleRecord(
					class_name=node.name,
					file=source.relative_path,
					has_on_submit="on_submit" in lifecycle_names,
					has_on_cancel="on_cancel" in lifecycle_names,
					has_before_save="before_save" in lifecycle_names,
					has_validate="validate" in lifecycle_names,
					has_before_submit="before_submit" in lifecycle_names,
					methods=tuple(sorted(lifecycle_names)),
					span=_span(source, node, lines),
				)
			)

	def _collect_function(
		self,
		source: SourceFile,
		node: ast.FunctionDef | ast.AsyncFunctionDef,
		lines: list[str],
		class_stack: tuple[str, ...],
		doctype_name: str | None = None,
	) -> None:
		span = _span(source, node, lines)
		qualified_name = ".".join((*class_stack, node.name))
		symbol_id = f"{source.relative_path}:{qualified_name}"
		
		import_map = {
			imp.local_name: f"{imp.module}.{imp.imported_name}" if imp.module else imp.imported_name
			for imp in self.imports
			if imp.file == source.relative_path
		}
		
		self.functions.append(FunctionRecord(symbol_id, source.relative_path, node.name, qualified_name, span))
		if _is_whitelisted(node, import_map):
			self.whitelisted.append(WhitelistedEndpoint(qualified_name, _allow_guest(node, import_map), span, symbol_id))
		visitor = _FunctionBodyVisitor(
			source,
			lines,
			qualified_name,
			symbol_id,
			{argument.arg for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)},
			collector=self,
			qualified_name=qualified_name,
			import_map=import_map,
		)
		visitor._current_class_doctype = doctype_name
		
		# Collect mutable default args
		def _check_default(default_node: ast.AST, arg_name: str) -> None:
			if isinstance(default_node, ast.List):
				self.mutable_default_args.append(MutableDefaultArgRecord(symbol_id, span, arg_name, "list"))
			elif isinstance(default_node, ast.Dict):
				self.mutable_default_args.append(MutableDefaultArgRecord(symbol_id, span, arg_name, "dict"))
			elif isinstance(default_node, ast.Set):
				self.mutable_default_args.append(MutableDefaultArgRecord(symbol_id, span, arg_name, "set"))
			elif (
				isinstance(default_node, ast.Call)
				and isinstance(default_node.func, ast.Name)
				and default_node.func.id in {"list", "dict", "set"}
				and not default_node.args
				and not default_node.keywords
			):
				self.mutable_default_args.append(
					MutableDefaultArgRecord(symbol_id, span, arg_name, default_node.func.id)
				)

		combined_args = node.args.posonlyargs + node.args.args
		offset = len(combined_args) - len(node.args.defaults)
		for i, default in enumerate(node.args.defaults):
			_check_default(default, combined_args[offset + i].arg)
		for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
			if default:
				_check_default(default, arg.arg)
		for statement in node.body:
			visitor.visit(statement)
		self.ignore_permissions.extend(visitor.ignore_permissions)
		self.sql_calls.extend(visitor.sql_calls)
		self.permission_checks.extend(visitor.permission_checks)
		self.commit_calls.extend(visitor.commit_calls)
		self.direct_writes.extend(visitor.direct_writes)
		self.calls.extend(visitor.calls)
		self.unresolved.extend(visitor.unresolved)
		self.enqueue_calls.extend(visitor.enqueue_calls)
		self.eval_exec_calls.extend(visitor.eval_exec_calls)
		self.query_builder_calls.extend(visitor.query_builder_calls)
		self.get_doc_kwargs.extend(visitor.get_doc_kwargs)
		self.set_value_calls.extend(visitor.set_value_calls)
		self.string_dispatch_calls.extend(visitor.string_dispatch_calls)
		self.dynamic_method_calls.extend(visitor.dynamic_method_calls)
		self.msgprint_calls.extend(visitor.msgprint_calls)
		self.outbound_request_calls.extend(visitor.outbound_request_calls)
		self.bare_except_blocks.extend(visitor.bare_except_blocks)
		self.fieldname_references.extend(visitor.fieldname_references)
		self.queries_in_loop.extend(visitor.queries_in_loop)
		self.hardcoded_user_strings.extend(visitor.hardcoded_user_strings)

	def build(self) -> PythonSymbolIndex:
		return PythonSymbolIndex(
			whitelisted_endpoints=tuple(self.whitelisted),
			ignore_permissions=tuple(self.ignore_permissions),
			sql_calls=tuple(self.sql_calls),
			permission_checks=tuple(self.permission_checks),
			commit_calls=tuple(self.commit_calls),
			direct_writes=tuple(self.direct_writes),
			functions=tuple(self.functions),
			calls=tuple(self.calls),
			imports=tuple(self.imports),
			unresolved=tuple(sorted(set(self.unresolved))),
			parser_backend=_parser_backend(),
			enqueue_calls=tuple(self.enqueue_calls),
			eval_exec_calls=tuple(self.eval_exec_calls),
			query_builder_calls=tuple(self.query_builder_calls),
			get_doc_kwargs=tuple(self.get_doc_kwargs),
			set_value_calls=tuple(self.set_value_calls),
			class_lifecycles=tuple(self.class_lifecycles),
			string_dispatch_calls=tuple(self.string_dispatch_calls),
			dynamic_method_calls=tuple(self.dynamic_method_calls),
			msgprint_calls=tuple(self.msgprint_calls),
			outbound_request_calls=tuple(self.outbound_request_calls),
			bare_except_blocks=tuple(self.bare_except_blocks),
			mutable_default_args=tuple(self.mutable_default_args),
			fieldname_references=tuple(self.fieldname_references),
			queries_in_loop=tuple(self.queries_in_loop),
			hardcoded_user_strings=tuple(self.hardcoded_user_strings),
			unused_imports=tuple(self.unused_imports),
		)


class _FunctionBodyVisitor(ast.NodeVisitor):
	def __init__(
		self,
		source: SourceFile,
		lines: list[str],
		function: str,
		symbol_id: str,
		parameters: set[str],
		collector: _IndexCollector,
		qualified_name: str,
		import_map: dict[str, str],
	) -> None:
		self.source = source
		self.lines = lines
		self.function = qualified_name
		self.symbol_id = symbol_id
		self.parameters = parameters
		self.collector = collector
		self.qualified_name = qualified_name
		self.import_map = import_map
		self._current_class_doctype: str | None = None
		self.values: dict[str, ast.AST] = {}
		self.ignore_permissions: list[IgnorePermissionsRecord] = []
		self.sql_calls: list[SqlCallRecord] = []
		self.permission_checks: list[PermCheckRecord] = []
		self.commit_calls: list[CommitCallRecord] = []
		self.direct_writes: list[DirectWriteRecord] = []
		self.calls: list[CallRecord] = []
		self.unresolved: list[str] = []
		self.enqueue_calls: list[EnqueueCallRecord] = []
		self.eval_exec_calls: list[EvalExecRecord] = []
		self.query_builder_calls: list[QueryBuilderRecord] = []
		self.get_doc_kwargs: list[GetDocKwargsRecord] = []
		self.set_value_calls: list[SetValueRecord] = []
		self.string_dispatch_calls: list[StringDispatchRecord] = []
		self.dynamic_method_calls: list[DynamicMethodCallRecord] = []
		self.msgprint_calls: list[MsgprintRecord] = []
		self.outbound_request_calls: list[OutboundRequestRecord] = []
		self.bare_except_blocks: list[BareExceptRecord] = []
		self.fieldname_references: list[FieldnameRefRecord] = []
		self.queries_in_loop: list[QueryInLoopRecord] = []
		self.hardcoded_user_strings: list[HardcodedStringRecord] = []

	def visit_Try(self, node: ast.Try) -> None:
		for handler in node.handlers:
			catches_base = handler.type is None or (
				isinstance(handler.type, ast.Name) and handler.type.id == "Exception"
			)
			body_is_noop = len(handler.body) == 0 or all(
				isinstance(stmt, (ast.Pass, ast.Continue)) or
				(isinstance(stmt, ast.Return) and stmt.value is None)
				for stmt in handler.body
			)
			if catches_base and body_is_noop:
				self.bare_except_blocks.append(BareExceptRecord(
					symbol_id=self.symbol_id,
					span=_span(self.source, handler, self.lines),
					swallows_return=body_is_noop,
					catches_base_exception=catches_base,
				))
		self.generic_visit(node)

	def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
		self.collector._collect_function(self.source, node, self.lines, (self.qualified_name,))

	def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
		self.collector._collect_function(self.source, node, self.lines, (self.qualified_name,))

	def visit_Attribute(self, node: ast.Attribute) -> None:
		if isinstance(node.value, ast.Name):
			doctype, confidence = self._resolve_doctype_for_var(node.value.id)
			if doctype is not None and isinstance(node.ctx, (ast.Load, ast.Store)):
				self.fieldname_references.append(FieldnameRefRecord(
					symbol_id=self.symbol_id,
					span=_span(self.source, node, self.lines),
					doctype=doctype,
					fieldname=node.attr,
					access_kind="attr",
					doctype_resolution_confidence=confidence,
				))
		self.generic_visit(node)

	def _resolve_doctype_for_var(self, var_name: str) -> tuple[str | None, str]:
		if var_name == "self" and self._current_class_doctype is not None:
			return self._current_class_doctype, "medium"
		assigned = self.values.get(var_name)
		if isinstance(assigned, ast.Call) and _call_name(assigned.func) == "frappe.get_doc":
			if assigned.args and isinstance(assigned.args[0], ast.Constant) and isinstance(assigned.args[0].value, str):
				return assigned.args[0].value, "high"
		return None, "low"

	def visit_For(self, node: ast.For) -> None:
		iterates_query_result = self._iter_is_query_result(node.iter)
		if iterates_query_result:
			for inner in ast.walk(node):
				if isinstance(inner, ast.Call) and _call_name(inner.func) == "frappe.get_doc":
					self.queries_in_loop.append(QueryInLoopRecord(
						symbol_id=self.symbol_id,
						span=_span(self.source, inner, self.lines),
						query_kind="get_doc",
						loop_iterates_over_query_result=True,
					))
		self.generic_visit(node)

	def _iter_is_query_result(self, iter_node: ast.AST) -> bool:
		candidate = iter_node
		if isinstance(candidate, ast.Name):
			candidate = self.values.get(candidate.id, candidate)
		if isinstance(candidate, ast.Call):
			return _call_name(candidate.func) in {"frappe.get_all", "frappe.get_list", "frappe.db.get_all", "frappe.db.get_list"}
		return False

	def visit_AugAssign(self, node: ast.AugAssign) -> None:
		if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
			current = self.values.get(node.target.id)
			if current is not None:
				right_val = _literal_string(node.value)
				if right_val is not None:
					current_val = _literal_string(current)
					if current_val is not None:
						self.values[node.target.id] = ast.Constant(value=current_val + right_val)
		self.generic_visit(node)

	def visit_Assign(self, node: ast.Assign) -> None:
		for target in node.targets:
			if isinstance(target, ast.Name):
				self.values[target.id] = node.value
		self.generic_visit(node)

	def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
		if isinstance(node.target, ast.Name) and node.value is not None:
			self.values[node.target.id] = node.value
		self.generic_visit(node)

	def visit_If(self, node: ast.If) -> None:
		if _is_explicit_owner_or_role_guard(node, self.import_map, self.values):
			self.permission_checks.append(
				PermCheckRecord(self.function, _span(self.source, node, self.lines), self.symbol_id)
			)
		self.generic_visit(node)

	def visit_Call(self, node: ast.Call) -> None:
		name = _call_name(node.func, self.import_map)
		span = _span(self.source, node, self.lines)
		if name == "frappe.db.sql":
			query_node = _resolve_expression(node.args[0], self.values) if node.args else None
			query = _literal_string(query_node)
			self.sql_calls.append(
				SqlCallRecord(
					self.function,
					_parameterized_sql(node),
					query is None,
					_request_controlled(query_node, self.values, self.parameters, self.import_map),
					span,
					self.symbol_id,
					query,
				)
			)
		if name in {"frappe.has_permission", "frappe.only_for"}:
			self.permission_checks.append(PermCheckRecord(self.function, span, self.symbol_id))
		if name == "frappe.db.commit":
			self.commit_calls.append(CommitCallRecord(self.function, span, self.symbol_id))
		if name == "frappe.db.set_value":
			self.direct_writes.append(
				DirectWriteRecord(self.function, _set_value_field_name(node), span, self.symbol_id)
			)
			self.set_value_calls.append(
				SetValueRecord(
					self.function,
					_set_value_doctype_arg(node),
					_set_value_field_name(node),
					span,
					self.symbol_id,
				)
			)
		if name == "frappe.db.set_value" or name == "frappe.db.sql":
			pass  # already handled above
		# frappe.enqueue detection
		if name == "frappe.enqueue":
			has_dedupe = any(keyword.arg in {"deduplicate", "job_id", "queue_id"} for keyword in node.keywords)
			self.enqueue_calls.append(
				EnqueueCallRecord(self.function, has_dedupe, span, self.symbol_id)
			)
		# eval/exec detection
		if name in {"eval", "exec"}:
			controlled = False
			if node.args:
				controlled = _request_controlled(node.args[0], self.values, self.parameters)
			self.eval_exec_calls.append(
				EvalExecRecord(self.function, name, controlled, span, self.symbol_id)
			)
		# frappe.qb dynamic table detection
		if name in {"frappe.qb.from_", "frappe.qb.DocType"}:
			dynamic = _is_dynamic_qb_target(node.args[0] if node.args else None, self.values)
			self.query_builder_calls.append(
				QueryBuilderRecord(self.function, dynamic, span, self.symbol_id)
			)
		# frappe.get_doc mass assignment detection
		if name == "frappe.get_doc":
			controlled = False
			if node.args:
				arg = node.args[0]
				if isinstance(arg, ast.Name) and arg.id in self.parameters:
					controlled = True
				elif isinstance(arg, ast.Dict):
					controlled = False
				elif isinstance(arg, ast.Name):
					controlled = _request_controlled(arg, self.values, self.parameters)
				elif isinstance(arg, ast.Call):
					controlled = _request_controlled(arg, self.values, self.parameters)
			if node.keywords:
				for keyword in node.keywords:
					if keyword.arg is None:  # **kwargs spread
						controlled = True
			if controlled:
				self.get_doc_kwargs.append(
					GetDocKwargsRecord(self.function, controlled, span, self.symbol_id)
				)
		for keyword in node.keywords:
			if keyword.arg == "ignore_permissions" and _is_true(keyword.value):
				self.ignore_permissions.append(
					IgnorePermissionsRecord(
						self.function,
						True,
						_span(self.source, keyword, self.lines),
						self.symbol_id,
						call_name=name,
					)
				)
		if isinstance(node.func, ast.Name):
			self.calls.append(CallRecord(self.symbol_id, node.func.id, span))
		elif not name:
			self.unresolved.append(f"{self.symbol_id}:{span.line_start}:dynamic_call")
		self.generic_visit(node)

		# String dispatch: frappe.call("a.b.c") / frappe.enqueue("a.b.c")
		if name in {"frappe.call", "frappe.enqueue"}:
			if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
				self.string_dispatch_calls.append(
					StringDispatchRecord(
						caller_symbol_id=self.symbol_id,
						target_dotted_path=node.args[0].value,
						span=span,
					)
				)

		# Dynamic method: frappe.get_doc(...).some_method()
		if (
			isinstance(node.func, ast.Attribute)
			and isinstance(node.func.value, ast.Call)
			and _call_name(node.func.value.func) == "frappe.get_doc"
		):
			self.dynamic_method_calls.append(
				DynamicMethodCallRecord(
					caller_symbol_id=self.symbol_id,
					method_name=node.func.attr,
					span=span,
				)
			)

		# Hardcoded string detection (for i18n)
		if name in {"frappe.msgprint", "frappe.throw"}:
			if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
				self.hardcoded_user_strings.append(
					HardcodedStringRecord(self.symbol_id, span, name, node.args[0].value)
				)

		# frappe.msgprint / frappe.throw with user input (XSS detection)
		if name in {"frappe.msgprint", "frappe.throw"}:
			uses_user_input = False
			if node.args:
				uses_user_input = _request_controlled(node.args[0], self.values, self.parameters)
			if uses_user_input:
				self.msgprint_calls.append(
					MsgprintRecord(self.function, uses_user_input, span, self.symbol_id)
				)

		# requests.get / requests.post / urllib outbound calls (SSRF detection)
		if name in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request", "urllib.request.urlopen"}:
			url_dynamic = False
			if node.args:
				url_dynamic = not isinstance(node.args[0], ast.Constant)
			self.outbound_request_calls.append(
				OutboundRequestRecord(self.function, url_dynamic, span, self.symbol_id)
			)


def _is_whitelisted(node: ast.FunctionDef | ast.AsyncFunctionDef, import_map: dict[str, str] | None = None) -> bool:
	return any(
		_call_name(decorator.func if isinstance(decorator, ast.Call) else decorator, import_map) == "frappe.whitelist"
		for decorator in node.decorator_list
	)


def _allow_guest(node: ast.FunctionDef | ast.AsyncFunctionDef, import_map: dict[str, str] | None = None) -> bool:
	for decorator in node.decorator_list:
		if isinstance(decorator, ast.Call) and _call_name(decorator.func, import_map) == "frappe.whitelist":
			for keyword in decorator.keywords:
				if keyword.arg == "allow_guest" and isinstance(keyword.value, ast.Constant):
					return bool(keyword.value.value)
	return False


def _call_name(node: ast.AST, import_map: dict[str, str] | None = None) -> str:
	if isinstance(node, ast.Name):
		base = node.id
		if import_map and base in import_map:
			return import_map[base]
		return base
	if isinstance(node, ast.Attribute):
		parent = _call_name(node.value, import_map)
		return f"{parent}.{node.attr}" if parent else node.attr
	return ""


def _resolve_expression(node: ast.AST | None, values: dict[str, ast.AST]) -> ast.AST | None:
	if isinstance(node, ast.Name):
		return values.get(node.id, node)
	return node


def _literal_string(node: ast.AST | None) -> str | None:
	if isinstance(node, ast.Constant) and isinstance(node.value, str):
		return node.value
	if isinstance(node, ast.JoinedStr):
		parts = []
		for part in node.values:
			if isinstance(part, ast.Constant) and isinstance(part.value, str):
				parts.append(part.value)
			elif isinstance(part, ast.FormattedValue):
				parts.append("%")
		return "".join(parts)
	return None


def _parameterized_sql(node: ast.Call) -> bool:
	if len(node.args) > 1:
		return True
	return any(keyword.arg == "values" for keyword in node.keywords)


def _request_controlled(
	node: ast.AST | None, values: dict[str, ast.AST], parameters: set[str], import_map: dict[str, str] | None = None, seen: set[str] | None = None
) -> bool:
	if node is None:
		return False
	if isinstance(node, ast.Name):
		if node.id in parameters:
			return True
		if node.id not in values:
			return False
		seen = seen or set()
		if node.id in seen:
			return False
		return _request_controlled(values[node.id], values, parameters, import_map, seen | {node.id})
	if isinstance(node, ast.Attribute):
		attr_name = _call_name(node, import_map)
		return attr_name.startswith("frappe.form_dict") or attr_name.startswith("frappe.local.form_dict") or attr_name.startswith("frappe.request")
	if isinstance(node, ast.Call):
		func_name = _call_name(node.func, import_map)
		is_source = func_name.startswith("frappe.form_dict") or func_name.startswith("frappe.local.form_dict") or func_name.startswith("frappe.request")
		return is_source or any(
			_request_controlled(argument, values, parameters, import_map, seen)
			for argument in (*node.args, *(item.value for item in node.keywords))
		)
	return any(_request_controlled(child, values, parameters, import_map, seen) for child in ast.iter_child_nodes(node))


def _is_dynamic_qb_target(node: ast.AST | None, values: dict[str, ast.AST]) -> bool:
	if node is None:
		return False
	resolved = _resolve_expression(node, values)
	if isinstance(resolved, ast.Constant):
		return False
	if isinstance(resolved, ast.Call):
		func_name = _call_name(resolved.func)
		if func_name in {"frappe.qb.DocType", "DocType"} and resolved.args:
			arg_res = _resolve_expression(resolved.args[0], values)
			if isinstance(arg_res, ast.Constant):
				return False
	return True


def _set_value_field_name(node: ast.Call) -> str | None:
	if len(node.args) >= 3:
		return _literal_string(node.args[2])
	for keyword in node.keywords:
		if keyword.arg in {"fieldname", "field"}:
			return _literal_string(keyword.value)
	return None


def _set_value_doctype_arg(node: ast.Call) -> str | None:
	if node.args:
		return _literal_string(node.args[0])
	for keyword in node.keywords:
		if keyword.arg == "doctype":
			return _literal_string(keyword.value)
	return None


def _is_true(node: ast.AST) -> bool:
	return isinstance(node, ast.Constant) and node.value is True


_ROLE_PERMISSION_CALL_NAMES = {
	"frappe.has_permission",
	"frappe.has_role",
	"frappe.get_roles",
	"frappe.only_for",
	"frappe.permissions.has_permission",
	"frappe.permissions.has_role",
	"frappe.permissions.get_roles",
}
_ROLE_PERMISSION_CALL_SUFFIXES = (".has_role", ".has_permission", ".get_roles", ".only_for")


def _is_explicit_owner_or_role_guard(node: ast.If, import_map: dict[str, str] | None = None, values: dict[str, ast.AST] | None = None) -> bool:
	"""Recognize direct deny branches that compare the caller to owner or roles.

	`has_role_check` previously matched ANY identifier containing the
	substrings "role", "permission", or "manager" anywhere in the condition —
	e.g. `if frappe.session.user != doc.owner and "Manager" not in
	employee.designation:` would match purely because the string literal
	"Manager" appears next to `.designation`, with no actual role/permission
	API involved. That's a false "this is guarded" signal, which makes
	FR-PERM-001 silently skip a real gap. has_role_check now requires an
	actual call to a known role/permission-check function instead of a
	substring match on any name.
	"""
	def _get_names(n: ast.AST, seen: set[str] | None = None) -> set[str]:
		seen = seen or set()
		names = set()
		for item in ast.walk(n):
			if isinstance(item, ast.Name):
				if values and item.id in values and item.id not in seen:
					names.update(_get_names(values[item.id], seen | {item.id}))
				else:
					names.add(_call_name(item, import_map))
			elif isinstance(item, ast.Attribute):
				names.add(_call_name(item, import_map))
		return names

	def _get_call_names(n: ast.AST) -> set[str]:
		return {
			_call_name(item.func, import_map)
			for item in ast.walk(n)
			if isinstance(item, ast.Call)
		}

	condition_names = _get_names(node.test)
	condition_calls = _get_call_names(node.test)
	has_session_user = "frappe.session.user" in condition_names
	has_owner = any(name.endswith(".owner") for name in condition_names)
	has_role_check = any(
		call in _ROLE_PERMISSION_CALL_NAMES or call.endswith(_ROLE_PERMISSION_CALL_SUFFIXES)
		for call in condition_calls
	)

	if not has_session_user or not (has_owner or has_role_check):
		return False

	for statement in node.body:
		if isinstance(statement, (ast.Raise, ast.Return)):
			return True
		for call in ast.walk(statement):
			if isinstance(call, ast.Call):
				call_name = _call_name(call.func, import_map)
				if call_name in {"frappe.throw", "frappe.msgprint"} or call_name.endswith(".throw"):
					return True
	return False


def _span(source: SourceFile, node: ast.AST, lines: list[str]) -> SourceSpan:
	line_start = getattr(node, "lineno", 1)
	line_end = getattr(node, "end_lineno", line_start)
	fragment = "\n".join(lines[line_start - 1 : line_end])
	return SourceSpan(source.relative_path, line_start, line_end, stable_hash(fragment))
