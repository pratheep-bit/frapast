from __future__ import annotations

from scanner.callgraph.models import CallEdge, CallGraph, EdgeKind
from scanner.hooks import HookIndex
from scanner.python import PythonSymbolIndex


def build_call_graph(index: PythonSymbolIndex, hook_index: HookIndex | None = None) -> CallGraph:
	"""Build a call graph from the Python index and optional hook index.

	Performance optimization: build lookup maps once up front (qualified_name -> id,
	method_name -> [ids], module_suffix -> [(name, id)]) to resolve call targets in
	O(1) / O(k) time per call site instead of re-scanning all functions for every
	dispatch site (O(N*D)).
	"""
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

	# 2. String dispatch: frappe.call("a.b.c.func") / frappe.enqueue("a.b.c.func")
	for record in index.string_dispatch_calls:
		callee_id = _resolve_dotted_path_to_symbol_id(
			record.target_dotted_path, qualified_name_to_id, by_module_suffix
		)
		if callee_id:
			edges.setdefault(record.caller_symbol_id, set()).add(callee_id)
			rich_edges.append(CallEdge(record.caller_symbol_id, callee_id, EdgeKind.STRING_DISPATCH, 0.9))

	# 3. Hook dispatch: hooks.py registers "app.module.func" strings
	if hook_index is not None:
		for handler in hook_index.handlers:
			callee_id = _resolve_dotted_path_to_symbol_id(
				handler.handler, qualified_name_to_id, by_module_suffix
			)
			if callee_id:
				edges.setdefault("__framework_hook_root__", set()).add(callee_id)
				rich_edges.append(CallEdge("__framework_hook_root__", callee_id, EdgeKind.HOOK_DISPATCH, 0.85))

	# 4. Dynamic method calls on frappe.get_doc(...).method_name()
	for record in index.dynamic_method_calls:
		for candidate_symbol_id in methods_by_name.get(record.method_name, ()):
			edges.setdefault(record.caller_symbol_id, set()).add(candidate_symbol_id)
			rich_edges.append(CallEdge(record.caller_symbol_id, candidate_symbol_id, EdgeKind.DYNAMIC_METHOD, 0.4))

	return CallGraph(
		edges={caller: tuple(sorted(callees)) for caller, callees in sorted(edges.items())},
		unresolved=tuple(sorted(set(unresolved))),
		rich_edges=tuple(rich_edges),
	)


def _imported_candidates(
	import_lookup: dict[tuple[str, str], list],
	methods_by_name: dict[str, list[str]],
	function_files: dict[str, str],
	caller_file: str,
	local_name: str,
) -> list[str]:
	imports = import_lookup.get((caller_file, local_name), [])
	if len(imports) != 1:
		return []
	imported = imports[0]
	if not imported.module:
		return []
	module_path = imported.module.replace(".", "/")
	accepted_suffixes = (f"{module_path}.py", f"{module_path}/__init__.py")
	candidate_ids = methods_by_name.get(imported.imported_name, ())
	return [fid for fid in candidate_ids if function_files.get(fid, "").endswith(accepted_suffixes)]


def _resolve_dotted_path_to_symbol_id(
	dotted_path: str,
	qualified_name_to_id: dict[str, str],
	by_module_suffix: dict[str, list[tuple[str, str]]],
) -> str | None:
	"""Map 'myapp.utils.on_submit' to the symbol_id of the FunctionRecord
	whose qualified_name matches. Return None if not found in this repo."""
	if dotted_path in qualified_name_to_id:
		return qualified_name_to_id[dotted_path]
	parts = dotted_path.rsplit(".", 1)
	if len(parts) == 2:
		module_path, func_name = parts
		expected_suffix = module_path.replace(".", "/")
		candidates = by_module_suffix.get(expected_suffix, [])
		for fname, fid in candidates:
			if fname == func_name:
				return fid
	return None
