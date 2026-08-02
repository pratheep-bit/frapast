from __future__ import annotations

import ast
from pathlib import Path

from scanner.hooks.models import HookHandlerRecord, HookIndex, HookParseError
from scanner.shared import SourceFile


SKIP_DIRS = {".git", "node_modules", ".venv", "env", "__pycache__", "benchmark", "fixtures", "scratch", "tmp", "sites"}


def discover_hooks_files(app_roots: str | Path | list[str | Path] | tuple[str | Path, ...]) -> list[SourceFile]:
	roots = _normalize_roots(app_roots)
	files: list[SourceFile] = []
	for root in roots:
		for path in sorted(root.rglob("hooks.py")):
			if any(part in SKIP_DIRS for part in path.parts):
				continue
			files.append(SourceFile(path=path, root=root))
	return files


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


def load(repo_path: str | Path) -> HookIndex:
	return build_hook_index(discover_hooks_files(Path(repo_path)))


def _normalize_roots(app_roots: str | Path | list[str | Path] | tuple[str | Path, ...]) -> list[Path]:
	if isinstance(app_roots, (str, Path)):
		return [Path(app_roots)]
	return [Path(root) for root in app_roots]


def _literal_assignments(tree: ast.Module, path: Path, unresolved: list[str]) -> dict[str, object]:
	values: dict[str, object] = {}
	for node in tree.body:
		if not isinstance(node, ast.Assign):
			continue
		for target in node.targets:
			if not isinstance(target, ast.Name):
				continue
			try:
				values[target.id] = ast.literal_eval(node.value)
			except (ValueError, TypeError):
				unresolved.append(f"{path}:{target.id}")
	return values


def _as_handlers(value: object) -> tuple[str, ...]:
	if isinstance(value, str):
		return (value,)
	if isinstance(value, list):
		return tuple(item for item in value if isinstance(item, str))
	return ()


def _string_map(value: object) -> dict[str, str]:
	if not isinstance(value, dict):
		return {}
	return {key: item for key, item in value.items() if isinstance(key, str) and isinstance(item, str)}


def _app_name(source: SourceFile) -> str:
	try:
		relative = source.path.relative_to(source.root)
		return relative.parts[0] if len(relative.parts) > 1 else source.path.parent.name
	except ValueError:
		return source.path.parent.name
