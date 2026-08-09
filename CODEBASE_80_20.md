# Frappe Security Engine - 80/20 Codebase Reference Guide

> **Pareto Principle Applied (80/20 Rule):**
> - **20% High-Impact Core Code:** Full source code embedded for the essential engines driving 80%+ of the analysis value (AST Parsing, Rule Evaluation, Call Graph Construction, Hook Indexing, Schema Resolution, False-Positive Reduction, Severity Scoring, and Proof Orchestration).
> - **80% Peripheral & Utility Code:** One-line functional summaries explaining every supporting, UI, reporting, validation, model, and infrastructure module.

---

## Part 1: The 20% High-Impact Core Engine Code

The following 8 core modules form the algorithmic engine of the security scanner.

---

### 1. Python AST & Symbol Indexing Engine
`scanner/python/engine.py` — *Parses Python source files into an AST, extracts security-relevant sinks/sources, tracks variable assignments, and constructs the symbol index.*

```python
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
		if not root.exists():
			continue
		try:
			candidates = sorted(root.rglob("*.py"))
		except Exception as exc:
			logger.warning("Error accessing path %s: %s", root, exc)
			continue
		for path in candidates:
			try:
				rel_parts = path.relative_to(root).parts[:-1]
			except ValueError:
				rel_parts = path.parts[:-1]
			if any(part in SKIP_DIRS for part in rel_parts):
				continue
			files.append(SourceFile(path=path, root=root))
	return files


from scanner.logger import logger

def build_python_index(
	files: list[SourceFile] | tuple[SourceFile, ...],
	progress_callback: Callable[[int, int], None] | None = None,
) -> PythonSymbolIndex:
	collector = _IndexCollector()
	total = len(files)
	for i, source in enumerate(files, 1):
		if progress_callback is not None:
			progress_callback(i, total)
		try:
			text = source.path.read_text(encoding="utf-8")
			tree = ast.parse(text, filename=str(source.path))
			collector.collect(source, tree, text.splitlines())
		except Exception as exc:
			logger.warning("Skipping %s due to parse error: %s", source.path, exc)
			continue
	return collector.build()


def load(
	repo_path: str | Path,
	progress_callback: Callable[[int, int], None] | None = None,
) -> PythonSymbolIndex:
	files = discover_python_files(Path(repo_path))
	return build_python_index(files, progress_callback=progress_callback)


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
		rel_path = source.relative_path
		import_map: dict[str, str] = {}
		for node in tree.body:
			if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
				for imported in node.names:
					if imported.name != "*":
						local_name = imported.asname or imported.name
						target_name = f"{node.module}.{imported.name}"
						import_map[local_name] = target_name
						self.imports.append(
							ImportRecord(
								rel_path,
								local_name,
								node.module,
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

	def _collect_class(
		self, source: SourceFile, node: ast.ClassDef, lines: list[str], import_map: dict[str, str]
	) -> None:
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
			spaced = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", class_name)
			spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
			return spaced

		doctype_name = _class_name_to_doctype(node.name) if is_document_subclass else None

		for child in node.body:
			if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
				method_names.append(child.name)
				self._collect_function(source, child, lines, (node.name,), doctype_name, import_map=import_map)

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
	) -> None:
		if import_map is None:
			import_map = {}
		span = _span(source, node, lines)
		qualified_name = ".".join((*class_stack, node.name))
		symbol_id = f"{source.relative_path}:{qualified_name}"
		
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
```

---

### 2. Security Rule Evaluation Engine
`scanner/rules/engine.py` — *Evaluates all 32 security and correctness rules (SQLi, Permission Bypasses, Hook Collisions, Mass Assignment, CSRF, SSRF, XSS, N+1 queries) against the symbol index and call graph.*

```python
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

# Rule execution entrypoint
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
```

---

### 3. Inter-Procedural Call Graph & Reachability Engine
`scanner/callgraph/builder.py` — *Constructs the call graph across direct function invocations, string-based dispatches (`frappe.call`), hook dispatches, and dynamic method calls.*

```python
from __future__ import annotations

from scanner.callgraph.models import CallEdge, CallGraph, EdgeKind
from scanner.hooks import HookIndex
from scanner.python import PythonSymbolIndex


def build_call_graph(index: PythonSymbolIndex, hook_index: HookIndex | None = None) -> CallGraph:
	by_file_and_name: dict[tuple[str, str], list[str]] = {}
	function_files: dict[str, str] = {}
	qualified_name_to_id: dict[str, str] = {}
	methods_by_name: dict[str, list[str]] = {}
	by_module_suffix: dict[str, list[tuple[str, str]]] = {}

	for function in index.functions:
		by_file_and_name.setdefault((function.file, function.function), []).append(function.id)
		function_files[function.id] = function.file
		qualified_name_to_id[function.qualified_name] = function.id
		methods_by_name.setdefault(function.function, []).append(function.id)
		if function.file.endswith("/__init__.py"):
			suffix = function.file[: -len("/__init__.py")]
		elif function.file.endswith(".py"):
			suffix = function.file[: -len(".py")]
		else:
			suffix = function.file
		by_module_suffix.setdefault(suffix, []).append((function.function, function.id))

	import_lookup: dict[tuple[str, str], list] = {}
	for imp in index.imports:
		import_lookup.setdefault((imp.file, imp.local_name), []).append(imp)

	edges: dict[str, set[str]] = {}
	unresolved: list[str] = list(index.unresolved)
	rich_edges: list[CallEdge] = []

	# 1. Direct calls
	for call in index.calls:
		caller_file = function_files.get(call.caller_id)
		if caller_file is None:
			continue
		candidates = by_file_and_name.get((caller_file, call.callee_name), [])
		if not candidates:
			candidates = _imported_candidates(
				import_lookup, methods_by_name, function_files, caller_file, call.callee_name
			)
		if len(candidates) == 1:
			edges.setdefault(call.caller_id, set()).add(candidates[0])
			rich_edges.append(CallEdge(call.caller_id, candidates[0], EdgeKind.DIRECT_CALL, 1.0))
		else:
			unresolved.append(f"{call.caller_id}:{call.span.line_start}:{call.callee_name}")

	# 2. String dispatch
	for record in index.string_dispatch_calls:
		callee_id = _resolve_dotted_path_to_symbol_id(
			record.target_dotted_path, qualified_name_to_id, by_module_suffix
		)
		if callee_id:
			edges.setdefault(record.caller_symbol_id, set()).add(callee_id)
			rich_edges.append(CallEdge(record.caller_symbol_id, callee_id, EdgeKind.STRING_DISPATCH, 0.9))

	# 3. Hook dispatch
	if hook_index is not None:
		for handler in hook_index.handlers:
			callee_id = _resolve_dotted_path_to_symbol_id(
				handler.handler, qualified_name_to_id, by_module_suffix
			)
			if callee_id:
				edges.setdefault("__framework_hook_root__", set()).add(callee_id)
				rich_edges.append(CallEdge("__framework_hook_root__", callee_id, EdgeKind.HOOK_DISPATCH, 0.85))

	# 4. Dynamic method calls
	for record in index.dynamic_method_calls:
		for candidate_symbol_id in methods_by_name.get(record.method_name, ()):
			edges.setdefault(record.caller_symbol_id, set()).add(candidate_symbol_id)
			rich_edges.append(CallEdge(record.caller_symbol_id, candidate_symbol_id, EdgeKind.DYNAMIC_METHOD, 0.4))

	return CallGraph(
		edges={caller: tuple(sorted(callees)) for caller, callees in sorted(edges.items())},
		unresolved=tuple(sorted(set(unresolved))),
		rich_edges=tuple(rich_edges),
	)
```

---

### 4. Frappe Framework Hooks Indexing Engine
`scanner/hooks/engine.py` — *Parses `hooks.py` files across all Frappe applications to build an index of document events, permission query conditions, and hook handlers.*

```python
from __future__ import annotations

import ast
from pathlib import Path

from scanner.hooks.models import HookHandlerRecord, HookIndex, HookParseError
from scanner.shared import SourceFile


def build_hook_index(files: list[SourceFile] | tuple[SourceFile, ...], app_order: list[str] | None = None) -> HookIndex:
	handlers: list[HookHandlerRecord] = []
	permission_query_conditions: dict[str, str] = {}
	has_permission: dict[str, str] = {}
	unresolved: list[str] = []
	for source in files:
		app = _app_name(source)
		try:
			tree = ast.parse(source.path.read_text(encoding="utf-8"), filename=str(source.path))
		except SyntaxError as exc:
			raise HookParseError(f"parse_error: {source.path}: {exc.msg}") from exc
		assignments = _literal_assignments(tree, source.path, unresolved)
		doc_events = assignments.get("doc_events", {})
		if isinstance(doc_events, dict):
			for doctype, events in doc_events.items():
				if not isinstance(doctype, str) or not isinstance(events, dict):
					continue
				for event, value in events.items():
					if not isinstance(event, str):
						continue
					for handler in _as_handlers(value):
						handlers.append(
							HookHandlerRecord(app, doctype, event, handler, len(handlers), source.path)
						)
		permission_query_conditions.update(_string_map(assignments.get("permission_query_conditions", {})))
		has_permission.update(_string_map(assignments.get("has_permission", {})))
	if app_order:
		order = {app: index for index, app in enumerate(app_order)}
		handlers.sort(key=lambda item: (order.get(item.app, len(order)), item.order))
	return HookIndex(
		handlers=tuple(handlers),
		permission_query_conditions=permission_query_conditions,
		has_permission=has_permission,
		unresolved=tuple(unresolved),
	)
```

---

### 5. DocType Schema & Permission Indexing Engine
`scanner/schema/engine.py` — *Loads DocType JSON metadata schemas, indexing field definitions, submit status, table roles, and permissions.*

```python
from __future__ import annotations

import json
from pathlib import Path

from scanner.schema.models import DocTypeRecord, FieldRecord, PermissionRecord, SchemaIndex, SchemaParseError
from scanner.shared import SourceFile


def build_schema_index(files: list[SourceFile] | tuple[SourceFile, ...]) -> SchemaIndex:
	doctypes: list[DocTypeRecord] = []
	seen: set[str] = set()
	for source in files:
		try:
			data = json.loads(source.path.read_text(encoding="utf-8"))
		except json.JSONDecodeError as exc:
			raise SchemaParseError(f"parse_error: {source.path}: {exc.msg}") from exc
		if not isinstance(data, dict):
			raise SchemaParseError(f"invalid_doctype: {source.path}: JSON root must be object")
		if data.get("doctype") != "DocType":
			continue
		name = data.get("name") or data.get("doctype")
		module = data.get("module")
		if not isinstance(name, str) or not name:
			raise SchemaParseError(f"missing_required_key: {source.path}: name")
		if not isinstance(module, str) or not module:
			raise SchemaParseError(f"missing_required_key: {source.path}: module")
		if name in seen:
			continue
		seen.add(name)
		doctypes.append(
			DocTypeRecord(
				name=name,
				module=module,
				path=source.path,
				table_name=f"tab{name}",
				fields=_fields(data.get("fields", [])),
				is_submittable=bool(data.get("is_submittable")),
				istable=bool(data.get("istable")),
				permissions=_permissions(data.get("permissions", [])),
				autoname=data.get("autoname") if isinstance(data.get("autoname"), str) else None,
			)
		)
	return SchemaIndex(doctypes=tuple(sorted(doctypes, key=lambda item: item.name)))
```

---

### 6. False Positive Suppression & Precision Engine
`scanner/fp/engine.py` — *Filters out verified false positives based on YAML log hashes and calculates per-rule precision metrics.*

```python
from __future__ import annotations

from pathlib import Path
import yaml

from scanner.fp.models import FalsePositiveRecord, PrecisionMetric, SuppressionResult
from scanner.rules import Candidate


def apply_fp_suppression(
	candidates: list[Candidate] | tuple[Candidate, ...],
	fp_records: tuple[FalsePositiveRecord, ...],
	repo_id: str,
) -> SuppressionResult:
	by_identity = {
		(record.rule_id, record.rule_version, record.repo, record.file, record.function, record.code_location_hash): record
		for record in fp_records
	}
	remaining: list[Candidate] = []
	suppressed: list[str] = []
	for candidate in candidates:
		record = by_identity.get(
			(candidate.rule_id, candidate.rule_version, repo_id, candidate.file, candidate.function, candidate.code_location_hash)
		)
		if record is None:
			remaining.append(candidate)
		else:
			suppressed.append(record.finding_id)
	return SuppressionResult(tuple(remaining), tuple(sorted(suppressed)))
```

---

### 7. Multi-Dimensional Severity & Risk Scoring Engine
`scanner/severity/engine.py` — *Calculates contextual security severity scores based on reachability (Guest vs Auth), impact category, blast radius, and proof tier.*

```python
from __future__ import annotations

from scanner.rules import Candidate
from scanner.severity.models import (
	BLAST_RADIUS_WEIGHTS,
	IMPACT_WEIGHTS,
	PRIVILEGE_WEIGHTS,
	PROOF_TIER_WEIGHTS,
	SeverityScore,
)


def score_security(candidate: Candidate, allow_guest: bool, proof_tier: int) -> SeverityScore:
	privilege = "guest" if allow_guest else "authenticated"
	impact = RULE_IMPACT_MAP.get(candidate.rule_id, "data_exposure")
	family = candidate.rule_id.rsplit("-", 1)[0] if "-" in candidate.rule_id else candidate.rule_id
	blast_radius = RULE_BLAST_RADIUS_OVERRIDES.get(candidate.rule_id) or RULE_BLAST_RADIUS_MAP.get(family, "single_record")
	composite = _compute_composite(privilege, allow_guest, impact, blast_radius, proof_tier)
	return SeverityScore(
		score=composite,
		dimension_scores={
			"privilege_required": privilege,
			"allow_guest": allow_guest,
			"impact_class": impact,
			"blast_radius": blast_radius,
			"proof_tier": proof_tier,
		}
	)


def _compute_composite(
	privilege: str,
	allow_guest: bool,
	impact: str,
	blast_radius: str,
	proof_tier: int,
) -> float:
	priv_score = PRIVILEGE_WEIGHTS.get(privilege, 1)
	impact_score = IMPACT_WEIGHTS.get(impact, 1)
	blast_score = BLAST_RADIUS_WEIGHTS.get(blast_radius, 1)
	proof_score = PROOF_TIER_WEIGHTS.get(proof_tier, 0)
	guest_multiplier = 1.5 if allow_guest else 1.0
	return (priv_score * 3 + impact_score * 4 + blast_score * 2 + proof_score) * guest_multiplier
```

---

### 8. Exploit Proof & Reproducer Orchestrator
`scanner/proof/orchestrator.py` — *Orchestrates Tier 1 (direct code check) and Tier 2 (HTTP/RPC exploit request) runtime verification reproducers.*

```python
from __future__ import annotations

import subprocess
import time
from pathlib import Path

from scanner.proof.models import ProofResult, ProofStatus


class ProofOrchestrator:
	"""Orchestrates runtime proof execution for Tier 1 (direct_call) and Tier 2 (http_rpc)."""

	def __init__(
		self,
		workspace_root: str | Path,
		findings_dir: str | Path = "findings",
		reproducers_dir: str | Path = "runtime/reproducers",
		proofs_dir: str | Path = "runtime/proofs",
		dry_run: bool = False,
		timeout_seconds: int = 30,
	) -> None:
		self.workspace_root = Path(workspace_root)
		self.findings_dir = self.workspace_root / findings_dir
		self.reproducers_dir = self.workspace_root / reproducers_dir
		self.proofs_dir = self.workspace_root / proofs_dir
		self.dry_run = dry_run
		self.timeout_seconds = timeout_seconds

	def prove_candidate(self, finding_id: str, candidate_data: dict | None = None) -> ProofResult:
		reproducers = self.discover_reproducers()
		reproducer_path = reproducers.get(finding_id)
		if reproducer_path is None and candidate_data is not None:
			reproducer_path = synthesize_reproducer_if_missing(self.reproducers_dir, finding_id, candidate_data)

		if reproducer_path is None or not reproducer_path.is_file():
			return ProofResult(
				finding_id=finding_id,
				status=ProofStatus.SKIPPED,
				proof_tier=0,
				exit_code=None,
				stdout="",
				stderr="No reproducer script found.",
				duration_seconds=0.0,
				reproducer_path="",
				error_message=f"No reproducer found for {finding_id}",
			)

		start = time.monotonic()
		res = subprocess.run(
			["bash", str(reproducer_path)],
			cwd=self.workspace_root,
			capture_output=True,
			text=True,
			timeout=self.timeout_seconds,
		)
		status = ProofStatus.PASSED if res.returncode == 0 else ProofStatus.FAILED
		return ProofResult(
			finding_id=finding_id,
			status=status,
			proof_tier=1 if res.returncode == 0 else 0,
			exit_code=res.returncode,
			stdout=res.stdout,
			stderr=res.stderr,
			duration_seconds=time.monotonic() - start,
			reproducer_path=str(reproducer_path),
		)
```

---

## Part 2: The 80% Support & Infrastructure Modules (One-Line Descriptions)

### CLI, Workflow & Configuration
- [scanner/__init__.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/__init__.py): Initialized the root scanner package and exposes version metadata.
- [scanner/__main__.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/__main__.py): Provides the executable entrypoint for invoking the scanner via `python -m scanner`.
- [scanner/cli.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/cli.py): Implements Click CLI commands for scanning, triaging findings, generating reproducers, and rendering terminal outputs.
- [scanner/config.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/config.py): Manages environment paths, scanner defaults, and configuration options.
- [scanner/fp_analyzer.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/fp_analyzer.py): Computes precision statistics and false-positive distribution across rule definitions.
- [scanner/logger.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/logger.py): Configures colored console and file logging formats for runtime execution.

### Data Models & Schemas
- [scanner/python/models.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/python/models.py): Defines immutable dataclasses for AST nodes, calls, SQL sinks, and symbol indexes.
- [scanner/callgraph/models.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/callgraph/models.py): Defines call graph edges, graph algorithms, and reachability search methods.
- [scanner/hooks/models.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/hooks/models.py): Defines data structures representing Frappe `doc_events`, `has_permission`, and query hook handlers.
- [scanner/schema/models.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/schema/models.py): Holds records for DocType schemas, field types, autoname rules, and permission levels.
- [scanner/fp/models.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/fp/models.py): Models suppressed false positive YAML records and rule precision metrics.
- [scanner/proof/models.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/proof/models.py): Models proof execution status, proof tier levels, and reproducer execution results.
- [scanner/severity/models.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/severity/models.py): Stores weight dictionaries and composite severity score structures.
- [scanner/shared/records.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/shared/records.py): Provides `SourceFile`, `SourceSpan`, and stable MD5/SHA256 hashing helpers.

### Proof & Exploit Verification Sinks
- [scanner/proof/http_client.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/proof/http_client.py): Wraps HTTP requests for live Frappe RPC endpoint exploit verification.
- [scanner/proof/http_synthesis.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/proof/http_synthesis.py): Generates curl/bash HTTP reproducer scripts for testing API permission bypasses.

### Reporting & Formatting Output
- [scanner/reporting/engine.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/reporting/engine.py): Compiles findings into JSON, Markdown, and SARIF formats.
- [scanner/reporting/formatters.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/reporting/formatters.py): Formats terminal text outputs and code snippets for finding inspection.
- [scanner/reporting/sarif.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/reporting/sarif.py): Generates GitHub Security-compliant SARIF v2.1.0 report files.

### Interactive Terminal UI (Rich Library Interface)
- [scanner/ui/banner.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ui/banner.py): Displays ASCII art logo and header styling during CLI execution.
- [scanner/ui/menus.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ui/menus.py): Provides interactive terminal menus for finding triage, filtering, and proof execution.
- [scanner/ui/progress.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ui/progress.py): Renders terminal progress bars during file parsing and analysis phases.
- [scanner/ui/results.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ui/results.py): Formats terminal tables and summary cards for scan findings.
- [scanner/ui/shell.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ui/shell.py): Implements an interactive REPL shell to query the AST index and call graph.
- [scanner/ui/theme.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ui/theme.py): Defines color palettes and Rich styling primitives.

### Ledger, Validation & Regression Verification
- [scanner/ledger_io.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ledger_io.py): Reads and writes finding ledgers in YAML directory structures.
- [scanner/ledger_schema.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/ledger_schema.py): Validates YAML finding ledger entries against required schema keys.
- [scanner/validate_ledger.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/validate_ledger.py): Command-line script for batch-validating finding ledger integrity.
- [scanner/validate_taxonomy.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/validate_taxonomy.py): Verifies rule IDs against `taxonomy_registry.yaml`.
- [scanner/verify_ledger_integrity.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/verify_ledger_integrity.py): Validates code location hashes to prevent stale finding records.
- [scanner/regression/generator.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/regression/generator.py): Auto-generates pytest regression test suites from proven finding ledgers.
- [scanner/validate/engine.py](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/validate/engine.py): Automated patch validation engine that applies fixes and verifies vulnerability resolution.
- [scanner/validate/validate_fix.sh](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/validate/validate_fix.sh): Shell script for testing candidate patch fixes against test suites.

### Declarative Rules & Taxonomy Metadata
- [scanner/taxonomy_registry.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/taxonomy_registry.yaml): Defines standard vulnerability taxonomy IDs, descriptions, and rule version mappings.
- [scanner/rules/schema.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/schema.yaml): YAML schema for validating rule definition files.
- [scanner/rules/FR-SQLI-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-SQLI-001.yaml): Rule metadata for raw SQL query injection without parameter binding.
- [scanner/rules/FR-SQLI-002.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-SQLI-002.yaml): Rule metadata for raw SQL queries on submittable DocTypes missing `docstatus` filters.
- [scanner/rules/FR-SQLI-003.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-SQLI-003.yaml): Rule metadata for `db.set_value` calls bypassing controller validation hooks.
- [scanner/rules/FR-SQLI-004.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-SQLI-004.yaml): Rule metadata for non-literal dynamic table/column names in `frappe.qb`.
- [scanner/rules/FR-PERM-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-PERM-001.yaml): Rule metadata for whitelisted endpoints lacking permission checks.
- [scanner/rules/FR-PERM-002.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-PERM-002.yaml): Rule metadata for `ignore_permissions=True` usage reachable from whitelisted endpoints.
- [scanner/rules/FR-PERM-003.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-PERM-003.yaml): Rule metadata for `set_value` on owner-scoped DocTypes bypassing `if_owner` enforcement.
- [scanner/rules/FR-PERM-004.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-PERM-004.yaml): Rule metadata for Script Reports using raw SQL without permission query conditions.
- [scanner/rules/FR-PERM-005.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-PERM-005.yaml): Rule metadata for internal queries bypassing `has_permission` hooks.
- [scanner/rules/FR-PERM-006.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-PERM-006.yaml): Rule metadata for child table mutations bypassing parent document validation.
- [scanner/rules/FR-HOOK-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-HOOK-001.yaml): Rule metadata for asymmetric lifecycle hooks (`on_submit` defined without `on_cancel`).
- [scanner/rules/FR-HOOK-002.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-HOOK-002.yaml): Rule metadata for cross-app hook handler collisions on identical events.
- [scanner/rules/FR-HOOK-003.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-HOOK-003.yaml): Rule metadata for fast-path API writes bypassing controller validation chains.
- [scanner/rules/FR-HOOK-004.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-HOOK-004.yaml): Rule metadata for `frappe.enqueue` calls missing job deduplication/lock keys.
- [scanner/rules/FR-HOOK-005.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-HOOK-005.yaml): Rule metadata for `frappe.db.commit()` calls inside document lifecycle hooks.
- [scanner/rules/FR-HOOK-006.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-HOOK-006.yaml): Rule metadata for bare except blocks that silently swallow framework exceptions.
- [scanner/rules/FR-HOOK-007.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-HOOK-007.yaml): Rule metadata for mutable default arguments sharing state across function calls.
- [scanner/rules/FR-WKFL-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-WKFL-001.yaml): Rule metadata for submittable DocType field mutations lacking `docstatus` guards.
- [scanner/rules/FR-WKFL-002.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-WKFL-002.yaml): Rule metadata for direct writes to `workflow_state` outside the workflow engine.
- [scanner/rules/FR-WKFL-003.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-WKFL-003.yaml): Rule metadata for `status` vs `docstatus` state desynchronization.
- [scanner/rules/FR-WKFL-004.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-WKFL-004.yaml): Rule metadata for amendment chain state leakage on submittable DocTypes.
- [scanner/rules/FR-INJ-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-INJ-001.yaml): Rule metadata for HTTP mass assignment via un-sanitized `**kwargs` into `get_doc()`.
- [scanner/rules/FR-INJ-002.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-INJ-002.yaml): Rule metadata for `eval()` or `exec()` execution with request-controlled inputs.
- [scanner/rules/FR-INJ-005.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-INJ-005.yaml): Rule metadata for unescaped user input rendered in `frappe.msgprint` or `frappe.throw` (XSS).
- [scanner/rules/FR-CSRF-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-CSRF-001.yaml): Rule metadata for guest-accessible state-changing endpoints lacking CSRF validation.
- [scanner/rules/FR-SSRF-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-SSRF-001.yaml): Rule metadata for user-controlled URLs passed into outbound HTTP requests.
- [scanner/rules/FR-DATA-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-DATA-001.yaml): Rule metadata for non-existent fieldname references on DocType records.
- [scanner/rules/FR-PERF-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-PERF-001.yaml): Rule metadata for N+1 query patterns (`get_doc` inside a `get_all` iteration loop).
- [scanner/rules/FR-I18N-001.yaml](file:///Users/pratheepselvam/Documents/frappe-security-engine/scanner/rules/FR-I18N-001.yaml): Rule metadata for hardcoded user-facing strings missing `frappe._()` translation wrappers.
