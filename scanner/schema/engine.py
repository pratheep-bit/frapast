from __future__ import annotations

import json
from pathlib import Path

from scanner.schema.models import DocTypeRecord, FieldRecord, PermissionRecord, SchemaIndex, SchemaParseError
from scanner.shared import SourceFile


SKIP_DIRS = {".git", "node_modules", ".venv", "env", "__pycache__", "tests", "benchmark", "fixtures", "scratch", "tmp", "sites"}


def discover_doctype_json(app_roots: str | Path | list[str | Path] | tuple[str | Path, ...]) -> list[SourceFile]:
	roots = _normalize_roots(app_roots)
	files: list[SourceFile] = []
	for root in roots:
		for path in sorted(root.rglob("*.json")):
			try:
				rel_parts = path.relative_to(root).parts[:-1]
			except ValueError:
				rel_parts = path.parts[:-1]
			if any(part in SKIP_DIRS for part in rel_parts):
				continue
			if path.parent.name != path.stem:
				continue
			files.append(SourceFile(path=path, root=root))
	return files


def build_schema_index(
	files: list[SourceFile] | tuple[SourceFile, ...],
	*,
	strict: bool = False,
) -> SchemaIndex:
	"""Build a SchemaIndex from discovered DocType JSON files.

	One malformed DocType JSON previously aborted the entire scan — no caller
	of load() catches SchemaParseError. build_python_index() already treats a
	per-file parse failure as "skip and log", not "abort the run"; schema
	loading now matches that by default. Pass strict=True to restore the old
	fail-fast behaviour (useful for CI validation of the DocType JSON files
	themselves, as opposed to scanning an app that merely contains one).
	"""
	from scanner.logger import logger

	doctypes: list[DocTypeRecord] = []
	seen: set[str] = set()
	for source in files:
		try:
			doctype = _parse_doctype_json(source)
		except SchemaParseError as exc:
			if strict:
				raise
			logger.warning("Skipping DocType JSON %s: %s", source.path, exc)
			continue
		if doctype is None or doctype.name in seen:
			continue
		seen.add(doctype.name)
		doctypes.append(doctype)
	return SchemaIndex(doctypes=tuple(sorted(doctypes, key=lambda item: item.name)))


def _parse_doctype_json(source: SourceFile) -> DocTypeRecord | None:
	"""Parse one DocType JSON file. None means "parses fine, not a DocType"
	(a routine skip); SchemaParseError means genuinely malformed."""
	try:
		data = json.loads(source.path.read_text(encoding="utf-8"))
	except json.JSONDecodeError as exc:
		raise SchemaParseError(f"parse_error: {source.path}: {exc.msg}") from exc
	except OSError as exc:
		raise SchemaParseError(f"read_error: {source.path}: {exc}") from exc
	if not isinstance(data, dict):
		raise SchemaParseError(f"invalid_doctype: {source.path}: JSON root must be object")
	if data.get("doctype") != "DocType":
		return None
	name = data.get("name") or data.get("doctype")
	module = data.get("module")
	if not isinstance(name, str) or not name:
		raise SchemaParseError(f"missing_required_key: {source.path}: name")
	if not isinstance(module, str) or not module:
		raise SchemaParseError(f"missing_required_key: {source.path}: module")
	return DocTypeRecord(
		name=name,
		module=module,
		path=source.path,
		table_name=f"tab{name}",
		fields=_fields(data.get("fields", [])),
		is_submittable=bool(data.get("is_submittable")),
		istable=bool(data.get("istable")),
		is_amendable=bool(data.get("is_amendable")),
		permissions=_permissions(data.get("permissions", [])),
		autoname=data.get("autoname") if isinstance(data.get("autoname"), str) else None,
	)


def load(repo_path: str | Path, *, strict: bool = False) -> SchemaIndex:
	return build_schema_index(discover_doctype_json(Path(repo_path)), strict=strict)


def _normalize_roots(app_roots: str | Path | list[str | Path] | tuple[str | Path, ...]) -> list[Path]:
	if isinstance(app_roots, (str, Path)):
		return [Path(app_roots)]
	return [Path(root) for root in app_roots]


def _fields(values: object) -> tuple[FieldRecord, ...]:
	if not isinstance(values, list):
		return ()
	fields: list[FieldRecord] = []
	for value in values:
		if not isinstance(value, dict):
			continue
		fieldname = value.get("fieldname")
		fieldtype = value.get("fieldtype")
		if isinstance(fieldname, str) and isinstance(fieldtype, str):
			options = value.get("options")
			fields.append(FieldRecord(fieldname, fieldtype, options if isinstance(options, str) else None))
	return tuple(fields)


def _permissions(values: object) -> tuple[PermissionRecord, ...]:
	if not isinstance(values, list):
		return ()
	permissions: list[PermissionRecord] = []
	for value in values:
		if not isinstance(value, dict):
			continue
		role = value.get("role")
		if not isinstance(role, str):
			continue
		permissions.append(
			PermissionRecord(
				role=role,
				permlevel=int(value.get("permlevel") or 0),
				read=bool(value.get("read")),
				write=bool(value.get("write")),
				create=bool(value.get("create")),
				submit=bool(value.get("submit")),
				cancel=bool(value.get("cancel")),
				if_owner=bool(value.get("if_owner")),
			)
		)
	return tuple(permissions)
