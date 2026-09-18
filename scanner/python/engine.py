from __future__ import annotations

import ast
import os
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scanner.logger import logger
from scanner.python.models import (
	BareExceptRecord,
	CallRecord,
	ClassLifecycleRecord,
	CommitCallRecord,
	DirectWriteRecord,
	DynamicMethodCallRecord,
	EnqueueCallRecord,
	EvalExecRecord,
	FieldnameRefRecord,
	FunctionRecord,
	GetDocKwargsRecord,
	HardcodedStringRecord,
	IgnorePermissionsRecord,
	ImportRecord,
	MsgprintRecord,
	MutableDefaultArgRecord,
	MutationRecord,
	OutboundRequestRecord,
	PathTraversalRecord,
	PermCheckRecord,
	PythonParseErrorRecord,
	PythonSymbolIndex,
	QueryBuilderRecord,
	QueryInLoopRecord,
	ReportEntryPointRecord,
	SetValueRecord,
	SqlCallRecord,
	StringDispatchRecord,
	UnusedImportRecord,
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

# Compiled once at import time instead of per ClassDef scanned — this ran
# through `import re` and two re.sub() compiles for every class in every
# file, which shows up in profiles on large monorepos.
_CAPS_RUN_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_LOWER_TO_UPPER_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def discover_python_files(
	app_roots: str | Path | list[str | Path] | tuple[str | Path, ...],
	return_skipped: bool = False,
) -> list[SourceFile] | tuple[list[SourceFile], int]:
	roots = _normalize_roots(app_roots)
	files: list[SourceFile] = []
	skipped_count = 0
	for root in roots:
		if not root.exists():
			continue
		try:
			for dirpath, dirs, filenames in os.walk(root):
				# Prune ignored directories in-place so os.walk NEVER descends into them
				orig_dirs_len = len(dirs)
				dirs[:] = [
					d for d in dirs
					if d not in SKIP_DIRS and not (d.startswith(".") and d != ".")
				]
				skipped_count += (orig_dirs_len - len(dirs))
				for fname in sorted(filenames):
					if fname.endswith(".py"):
						files.append(SourceFile(path=Path(dirpath) / fname, root=root))
		except Exception as exc:
			logger.warning("Error accessing path %s: %s", root, exc)
			continue
	if return_skipped:
		return files, skipped_count
	return files


def _parse_one(
	source: SourceFile,
) -> tuple[SourceFile, ast.AST | None, list[str], Exception | None]:
	"""Read and parse a single source file. Returns (source, tree, lines, error)."""
	try:
		text = source.path.read_text(encoding="utf-8")
		tree = ast.parse(text, filename=str(source.path))
		return source, tree, text.splitlines(), None
	except Exception as exc:
		return source, None, [], exc


def build_python_index(
	files: list[SourceFile] | tuple[SourceFile, ...],
	progress_callback: Callable[[int, int], None] | None = None,
	workers: int | None = None,
) -> PythonSymbolIndex:
	"""Build a PythonSymbolIndex from the given source files.

	File reading and AST parsing are performed in parallel using a
	ThreadPoolExecutor (workers defaults to min(cpu_count, 8)) which
	yields a 2-4x wall-clock speedup on large repositories dominated
	by disk I/O.
	"""
	collector = _IndexCollector()
	total = len(files)
	if total == 0:
		return collector.build()

	max_workers = min(workers or (os.cpu_count() or 1), 8)

	# Parse all files in parallel, preserving original order for progress reporting.
	results: list[tuple[SourceFile, ast.AST | None, list[str], Exception | None]] = [None] * total  # type: ignore[list-item]
	with ThreadPoolExecutor(max_workers=max_workers) as pool:
		future_to_idx = {pool.submit(_parse_one, src): idx for idx, src in enumerate(files)}
		for fut in as_completed(future_to_idx):
			idx = future_to_idx[fut]
			results[idx] = fut.result()

	# Collect results sequentially (collector is not thread-safe).
	for i, (source, tree, lines, exc) in enumerate(results, 1):
		if progress_callback is not None:
			progress_callback(i, total)
		if exc is not None:
			if isinstance(exc, (SyntaxError, UnicodeDecodeError, ValueError)):
				collector.parse_errors.append(PythonParseErrorRecord(file=source.relative_path, message=str(exc)))
				logger.warning("Skipping %s due to parse error: %s", source.path, exc)
			else:
				collector.parse_errors.append(PythonParseErrorRecord(file=source.relative_path, message="unexpected indexing error"))
				logger.exception("Unexpected error indexing %s", source.path, exc_info=exc)
		else:
			collector.collect(source, tree, lines)  # type: ignore[arg-type]

	parse_error_count = len(collector.parse_errors)
	if parse_error_count > 0:
		logger.warning(
			"Indexed %d/%d Python files cleanly (%d files skipped due to parse errors).",
			total - parse_error_count, total, parse_error_count,
		)
	return collector.build()


def load(
	repo_path: str | Path,
	progress_callback: Callable[[int, int], None] | None = None,
	files: list[SourceFile] | tuple[SourceFile, ...] | None = None,
	workers: int | None = None,
) -> PythonSymbolIndex:
	resolved_files = files if files is not None else discover_python_files(Path(repo_path))
	return build_python_index(resolved_files, progress_callback=progress_callback, workers=workers)


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
		self.mutations: list[MutationRecord] = []
		self.path_traversals: list[PathTraversalRecord] = []
		self.report_entry_points: list[ReportEntryPointRecord] = []
		self.unused_imports: list[UnusedImportRecord] = []
		self.parse_errors: list[PythonParseErrorRecord] = []
		self._document_subclass_names: set[str] = set()
		self._non_document_bases: set[str] = set()

	def collect(self, source: SourceFile, tree: ast.Module, lines: list[str]) -> None:
		rel_path = source.relative_path
		import_map: dict[str, str] = {}
		for node in tree.body:
			if isinstance(node, ast.ImportFrom) and node.module:
				# Relative imports ("from .models import Y", node.level > 0) are
				# the norm inside a Frappe app's own package and were previously
				# skipped outright — meaning intra-app helper calls never
				# resolved through import_map, a real source of missed
				# reachability. Leading dots keep the target distinguishable
				# from an absolute import of the same trailing name.
				module_prefix = "." * node.level + node.module
				for imported in node.names:
					if imported.name != "*":
						local_name = imported.asname or imported.name
						target_name = f"{module_prefix}.{imported.name}"
						import_map[local_name] = target_name
						self.imports.append(
							ImportRecord(
								rel_path,
								local_name,
								module_prefix,
								imported.name,
							)
						)
			elif isinstance(node, ast.Import):
				for imported in node.names:
					if imported.asname:
						import_map[imported.asname] = imported.name
						self.imports.append(
							ImportRecord(rel_path, imported.asname, "", imported.name)
						)
					else:
						# "import a.b.c" (no alias) only binds the top-level name "a" in the
						# namespace; "a.<anything>" is already the correct dotted path as-is, so
						# no rewriting is needed (or wanted) for the bound name.
						top_level = imported.name.split(".")[0]
						import_map[top_level] = top_level
						self.imports.append(
							ImportRecord(rel_path, top_level, "", top_level)
						)

		for node in tree.body:
			if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
				self._collect_function(source, node, lines, (), import_map=import_map)
			elif isinstance(node, ast.ClassDef):
				self._collect_class(source, node, lines, import_map=import_map)

		self._collect_unused_imports(source, tree, import_map)

	def _collect_class(
		self, source: SourceFile, node: ast.ClassDef, lines: list[str], import_map: dict[str, str]
	) -> None:
		method_names: list[str] = []

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
			# Treat a run of capitals as one token (POSInvoice -> "POS Invoice", not "P O S Invoice"),
			# then split before a capital that starts a new lowercase word.
			spaced = _CAPS_RUN_BOUNDARY_RE.sub(" ", class_name)
			spaced = _LOWER_TO_UPPER_BOUNDARY_RE.sub(" ", spaced)
			return spaced

		doctype_name = _class_name_to_doctype(node.name) if is_document_subclass else None

		# FIX B & FIX A: collect every method/property name and every instance attribute
		# explicitly assigned to `self` directly in this class body.
		# These names are valid attribute accesses on `self` even if not in the DocType
		# JSON schema (e.g. @cached_property, @property, regular methods, or runtime
		# cache/state attributes initialized in methods like `self.allow_multiple_shifts = ...`).
		# Passing this set into each child visitor prevents false positives on valid controller state.
		class_valid_attrs: set[str] = {
			child.name
			for child in node.body
			if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
		}
		for stmt in ast.walk(node):
			if isinstance(stmt, ast.Assign):
				for target in stmt.targets:
					if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
						class_valid_attrs.add(target.attr)
					elif isinstance(target, (ast.Tuple, ast.List)):
						for elt in target.elts:
							if isinstance(elt, ast.Attribute) and isinstance(elt.value, ast.Name) and elt.value.id == "self":
								class_valid_attrs.add(elt.attr)
			elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
				if isinstance(stmt.target, ast.Attribute) and isinstance(stmt.target.value, ast.Name) and stmt.target.value.id == "self":
					class_valid_attrs.add(stmt.target.attr)

		frozen_class_valid_attrs = frozenset(class_valid_attrs)

		for child in node.body:
			if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
				method_names.append(child.name)
				self._collect_function(
					source, child, lines, (node.name,), doctype_name,
					import_map=import_map,
					class_valid_attrs=frozen_class_valid_attrs,
				)

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
		import_map: dict[str, str] | None = None,
		class_valid_attrs: frozenset[str] = frozenset(),
	) -> None:
		if import_map is None:
			import_map = {}
		span = _span(source, node, lines)
		qualified_name = ".".join((*class_stack, node.name))
		symbol_id = f"{source.relative_path}:{qualified_name}"

		self.functions.append(FunctionRecord(symbol_id, source.relative_path, node.name, qualified_name, span))
		if _is_whitelisted(node, import_map):
			self.whitelisted.append(WhitelistedEndpoint(qualified_name, _allow_guest(node, import_map), span, symbol_id))
		if _is_report_path(source.relative_path) and node.name == "execute":
			self.report_entry_points.append(ReportEntryPointRecord(source.relative_path, node.name, symbol_id, span))
		if _has_search_inputs_validator(node, import_map):
			self.permission_checks.append(PermCheckRecord(qualified_name, span, symbol_id))
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
		visitor._class_valid_attrs = class_valid_attrs

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
		for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=False):
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
		self.mutations.extend(visitor.mutations)
		for span, call_name in visitor.raw_path_traversals:
			self.path_traversals.append(
				PathTraversalRecord(
					function=qualified_name,
					span=span,
					symbol_id=symbol_id,
					call_name=call_name,
					has_guard=visitor.has_path_guard,
					request_controlled=True,
				)
			)

	def _collect_unused_imports(
		self, source: SourceFile, tree: ast.Module, import_map: dict[str, str]
	) -> None:
		"""Flag imports whose bound local name is never referenced elsewhere in
		the module. One pass over the tree, not one pass per import, to stay
		O(nodes) instead of O(imports * nodes).
		"""
		used_names: set[str] = set()
		for node in ast.walk(tree):
			if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
				used_names.add(node.id)
			elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
				used_names.add(node.value.id)

		for local_name in import_map:
			if local_name == "*" or local_name.startswith("_"):
				continue
			if local_name not in used_names:
				self.unused_imports.append(
					UnusedImportRecord(file=source.relative_path, local_name=local_name)
				)

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
			unresolved=tuple(self.unresolved),
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
			mutations=tuple(self.mutations),
			path_traversals=tuple(self.path_traversals),
			report_entry_points=tuple(self.report_entry_points),
			unused_imports=tuple(self.unused_imports),
			parse_errors=tuple(self.parse_errors),
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
		# Guard: True while we are visiting the `func` child of an ast.Call node.
		# When True, visit_Attribute must NOT record a fieldname_reference because
		# the attribute is the callee of a method invocation, not a field read.
		# Example: `self.set_status()` — the `self.set_status` Attribute node has
		# ctx=Load, identical to a field read — this flag is the only way to
		# distinguish them inside a NodeVisitor traversal.
		self._in_call_func: bool = False
		# FIX B & FIX A: names of methods/properties and instance attributes defined
		# directly in the enclosing class body.
		# These are valid attribute names on `self` even if absent from the DocType schema.
		# Set by _collect_function from the per-class set built in _collect_class.
		self._class_valid_attrs: frozenset[str] = frozenset()
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
		self.mutations: list[MutationRecord] = []
		self.raw_path_traversals: list[tuple[SourceSpan, str]] = []
		self.has_path_guard: bool = False

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
		# Check for frappe.session.user access (session-user scoped query/logic)
		if _call_name(node, self.import_map) == "frappe.session.user":
			self.permission_checks.append(
				PermCheckRecord(self.function, _span(self.source, node, self.lines), self.symbol_id)
			)
		# Skip when this Attribute node is the `func` of an enclosing Call node
		# (i.e. a method invocation target like `self.set_status` in `self.set_status()`).
		# Both method call targets and field reads have ctx=Load; the _in_call_func
		# flag set by visit_Call is the only reliable way to distinguish them.
		if not self._in_call_func and isinstance(node.value, ast.Name):
			attr_name = node.attr
			# FIX A: exclude leading-underscore attributes unconditionally.
			# Python convention for private/internal attrs (_x, __x). These are never
			# persisted DocType fields. Firing on them is always a false positive.
			# Examples from hrms: self._condition, self._advance_deduction_entries,
			# self._holidays_between_dates, salary_structure._doc_before_save.
			if attr_name.startswith("_"):
				self.generic_visit(node)
				return
			# FIX A: assignments to self (ast.Store context) define/update instance attributes,
			# not schema field reads.
			if node.value.id == "self" and isinstance(node.ctx, ast.Store):
				self.generic_visit(node)
				return
			doctype, confidence = self._resolve_doctype_for_var(node.value.id)
			if doctype is not None and isinstance(node.ctx, (ast.Load, ast.Store)):
				# FIX B & FIX A: exclude names that are methods/properties or instance attributes
				# defined in the same class body on `self`.
				if node.value.id == "self" and attr_name in self._class_valid_attrs:
					self.generic_visit(node)
					return
				self.fieldname_references.append(FieldnameRefRecord(
					symbol_id=self.symbol_id,
					span=_span(self.source, node, self.lines),
					doctype=doctype,
					fieldname=attr_name,
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
					# Only count as database read if first arg is NOT a dict literal
					# e.g. frappe.get_doc("DocType", name) -> DB read query
					# frappe.get_doc({"doctype": ...}) or frappe.get_doc(dict(...)) -> in-memory construction
					is_dict_construction = False
					if inner.args:
						first_arg = inner.args[0]
						if isinstance(first_arg, ast.Dict):
							is_dict_construction = True
						elif isinstance(first_arg, ast.Call) and _call_name(first_arg.func) == "dict":
							is_dict_construction = True
					elif inner.keywords:
						is_dict_construction = any(kw.arg == "doctype" for kw in inner.keywords)

					if not is_dict_construction:
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
		if self._check_path_guard(node.test):
			self.has_path_guard = True
		self.generic_visit(node)

	def _check_path_guard(self, test_node: ast.AST) -> bool:
		for subnode in ast.walk(test_node):
			if isinstance(subnode, ast.Call):
				fn_name = _call_name(subnode.func, self.import_map)
				attr = subnode.func.attr if isinstance(subnode.func, ast.Attribute) else ""
				if attr in {"startswith", "is_relative_to", "is_safe_path"} or fn_name in {
					"is_safe_path", "frappe.utils.file_manager.is_safe_path",
					"os.path.commonpath", "os.path.commonprefix", "validate_path"
				}:
					return True
		return False

	def visit_Raise(self, node: ast.Raise) -> None:
		if node.exc:
			exc_target = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
			exc_name = _call_name(exc_target, self.import_map)
			if "PermissionError" in exc_name:
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
		# Permission checks:
		# a) frappe.has_permission, frappe.only_for, frappe.permissions.*
		# b) instance methods: self.check_permission, doc.check_permission, *.has_permission, *.only_for
		if (
			name in {"frappe.has_permission", "frappe.only_for", "frappe.permissions.has_permission", "frappe.permissions.has_role"}
			or (isinstance(node.func, ast.Attribute) and node.func.attr in {"check_permission", "has_permission", "only_for"})
		):
			self.permission_checks.append(PermCheckRecord(self.function, span, self.symbol_id))

		# c) Explicit PermissionError throw
		if name in {"frappe.throw", "throw"} or (isinstance(node.func, ast.Attribute) and node.func.attr == "throw"):
			has_perm_err = any(
				"PermissionError" in _call_name(arg, self.import_map)
				for arg in node.args
			) or any(
				keyword.arg == "exc" and "PermissionError" in _call_name(keyword.value, self.import_map)
				for keyword in node.keywords
			)
			if has_perm_err:
				self.permission_checks.append(PermCheckRecord(self.function, span, self.symbol_id))

		# d) Session-scoped helpers
		if name in {"get_current_employee", "get_current_user_info", "get_current_user", "frappe.session.user", "frappe.get_user"}:
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
		# Mutation / write operation detection
		is_mutation = False
		if isinstance(node.func, ast.Attribute) and node.func.attr in {
			"save", "insert", "delete", "cancel", "submit", "db_set", "db_insert", "db_update", "db_delete",
		}:
			is_mutation = True
		elif name in {
			"frappe.db.set_value", "frappe.db.set_values", "frappe.db.delete",
			"frappe.delete_doc", "frappe.db.commit", "frappe.db.truncate", "frappe.enqueue",
		}:
			is_mutation = True
		elif name == "frappe.db.sql":
			query_node = _resolve_expression(node.args[0], self.values) if node.args else None
			query = _literal_string(query_node)
			if query and re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|REPLACE|TRUNCATE)\b", query, re.IGNORECASE):
				is_mutation = True

		if is_mutation:
			self.mutations.append(MutationRecord(self.function, span, self.symbol_id, name))

		# Path traversal detection (FR-PATH-001)
		is_file_sink = False
		path_arg = None
		if name in {"open", "io.open", "frappe.get_file", "frappe.read_file", "os.remove", "os.unlink", "os.listdir", "os.scandir", "os.walk"}:
			is_file_sink = True
			path_arg = node.args[0] if node.args else None
		elif name in {"shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move", "shutil.rmtree"}:
			is_file_sink = True
			path_arg = node.args[0] if node.args else None
		elif isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes"}:
			is_file_sink = True
			path_arg = node.func.value

		if is_file_sink and path_arg is not None:
			is_controlled = _request_controlled(path_arg, self.values, self.parameters, self.import_map)
			if is_controlled:
				self.raw_path_traversals.append((span, name or node.func.attr))

		# frappe.enqueue detection (for FR-HOOK-004)
		if name == "frappe.enqueue":
			has_dedupe = any(keyword.arg in {"deduplicate", "job_id", "queue_id"} for keyword in node.keywords)
			self.enqueue_calls.append(
				EnqueueCallRecord(self.function, has_dedupe, span, self.symbol_id)
			)
		# eval/exec detection
		if name in {"eval", "exec"}:
			controlled = False
			if node.args:
				controlled = _request_controlled(node.args[0], self.values, self.parameters, self.import_map)
			self.eval_exec_calls.append(
				EvalExecRecord(self.function, name, controlled, span, self.symbol_id)
			)
		# frappe.qb dynamic table detection
		if name in {"frappe.qb.from_", "frappe.qb.DocType"}:
			dynamic = _is_dynamic_qb_target(node.args[0] if node.args else None, self.values, self.parameters, self.import_map)
			self.query_builder_calls.append(
				QueryBuilderRecord(self.function, dynamic, span, self.symbol_id)
			)
		# frappe.get_doc mass assignment detection
		if name == "frappe.get_doc":
			controlled = False
			if len(node.args) == 1:
				arg = node.args[0]
				if isinstance(arg, ast.Name) and arg.id in self.parameters:
					controlled = True
				elif isinstance(arg, ast.Dict):
					controlled = False
				elif isinstance(arg, ast.Name):
					controlled = _request_controlled(arg, self.values, self.parameters, self.import_map)
				elif isinstance(arg, ast.Call):
					controlled = _request_controlled(arg, self.values, self.parameters, self.import_map)
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
		# Visit the func child with the guard raised so that visit_Attribute
		# knows not to treat method callee attributes as field references.
		self._in_call_func = True
		try:
			self.visit(node.func)
		finally:
			self._in_call_func = False
		# Visit args/keywords normally (field reads inside arguments are valid).
		for child in (*node.args, *node.keywords):
			self.visit(child)

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

		# Dynamic method dispatch: frappe.get_doc(...).method_name()
		if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
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
				uses_user_input = _is_dangerous_msgprint_arg(node.args[0], self.values, self.parameters, self.import_map)
			if uses_user_input:
				self.msgprint_calls.append(
					MsgprintRecord(self.function, uses_user_input, span, self.symbol_id)
				)

		# requests.get / requests.post / urllib outbound calls (SSRF detection)
		if name in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request", "urllib.request.urlopen"}:
			url_dynamic = False
			if node.args:
				first_arg = node.args[0]
				if not isinstance(first_arg, ast.Constant):
					is_fixed_domain = False
					if isinstance(first_arg, ast.JoinedStr):
						if first_arg.values and isinstance(first_arg.values[0], ast.Constant):
							val = str(first_arg.values[0].value)
							if (val.startswith("http://") or val.startswith("https://")) and "/" in val.split("://", 1)[1]:
								is_fixed_domain = True
					elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
						target_str = _literal_string(_resolve_expression(first_arg.func.value, self.values))
						if target_str and (target_str.startswith("http://") or target_str.startswith("https://")) and "/" in target_str.split("://", 1)[1]:
							is_fixed_domain = True
					elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
						target_str = _literal_string(_resolve_expression(first_arg.left, self.values))
						if target_str and (target_str.startswith("http://") or target_str.startswith("https://")) and "/" in target_str.split("://", 1)[1]:
							is_fixed_domain = True

					if not is_fixed_domain:
						url_dynamic = True
			if url_dynamic:
				self.outbound_request_calls.append(
					OutboundRequestRecord(self.function, url_dynamic, span, self.symbol_id)
				)


def _is_report_path(path: str) -> bool:
	parts = [part.lower() for part in path.replace("\\", "/").split("/")]
	return "report" in parts or any(part.endswith("_report") for part in parts)


def _is_whitelisted(node: ast.FunctionDef | ast.AsyncFunctionDef, import_map: dict[str, str] | None = None) -> bool:
	return any(
		_call_name(decorator.func if isinstance(decorator, ast.Call) else decorator, import_map) == "frappe.whitelist"
		for decorator in node.decorator_list
	)


def _has_search_inputs_validator(node: ast.FunctionDef | ast.AsyncFunctionDef, import_map: dict[str, str] | None = None) -> bool:
	return any(
		_call_name(decorator.func if isinstance(decorator, ast.Call) else decorator, import_map) in {
			"frappe.validate_and_sanitize_search_inputs",
			"validate_and_sanitize_search_inputs",
		}
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
			else:
				# Contains dynamic formatted value/expression — not a static literal string
				return None
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
		if attr_name.startswith("frappe.form_dict") or attr_name.startswith("frappe.local.form_dict") or attr_name.startswith("frappe.request"):
			return True
		return _request_controlled(node.value, values, parameters, import_map, seen)
	if isinstance(node, ast.Subscript):
		return _request_controlled(node.value, values, parameters, import_map, seen)
	if isinstance(node, ast.Call):
		func_name = _call_name(node.func, import_map)
		is_source = func_name.startswith("frappe.form_dict") or func_name.startswith("frappe.local.form_dict") or func_name.startswith("frappe.request")
		if is_source:
			return True
		if isinstance(node.func, ast.Attribute) and _request_controlled(node.func.value, values, parameters, import_map, seen):
			return True
		return any(
			_request_controlled(argument, values, parameters, import_map, seen)
			for argument in (*node.args, *(item.value for item in node.keywords))
		)
	return any(_request_controlled(child, values, parameters, import_map, seen) for child in ast.iter_child_nodes(node))


def _is_dangerous_msgprint_arg(
	arg: ast.AST, values: dict[str, ast.AST], parameters: set[str], import_map: dict[str, str] | None = None
) -> bool:
	if not _request_controlled(arg, values, parameters, import_map):
		return False
	# Plain string translations without HTML tags are escaped by Frappe Desk UI
	if isinstance(arg, ast.Call):
		func_name = _call_name(arg.func, import_map)
		if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
			target_str = _literal_string(_resolve_expression(arg.func.value, values))
			if target_str and ("<" not in target_str and ">" not in target_str):
				return False
		elif func_name in {"_", "frappe._"} or func_name.endswith("._"):
			return False
	return True


def _is_dynamic_qb_target(
	node: ast.AST | None, values: dict[str, ast.AST], parameters: set[str] | None = None, import_map: dict[str, str] | None = None
) -> bool:
	if node is None:
		return False
	resolved = _resolve_expression(node, values)
	if isinstance(resolved, ast.Constant):
		return False
	if isinstance(resolved, (ast.JoinedStr, ast.BinOp)):
		return True
	if isinstance(resolved, ast.Call):
		func_name = _call_name(resolved.func, import_map)
		if (func_name in {"frappe.qb.DocType", "qb.DocType", "DocType"} or func_name.endswith(".DocType")) and resolved.args:
			arg_res = _resolve_expression(resolved.args[0], values)
			if isinstance(arg_res, ast.Constant):
				return False
			if isinstance(arg_res, (ast.JoinedStr, ast.BinOp)):
				return True
			if parameters is not None:
				return _request_controlled(arg_res, values, parameters, import_map)
	if parameters is not None:
		return _request_controlled(resolved, values, parameters, import_map)
	return False


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
	has_dev_mode = any(name.endswith("developer_mode") for name in condition_names)

	if has_dev_mode:
		for statement in node.body:
			if isinstance(statement, (ast.Raise, ast.Return)):
				return True
			for call in ast.walk(statement):
				if isinstance(call, ast.Call):
					call_name = _call_name(call.func, import_map)
					if call_name in {"frappe.throw", "frappe.msgprint"} or call_name.endswith(".throw"):
						return True

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
