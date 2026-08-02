from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class SchemaParseError(ValueError):
	code = "SCHEMA_PARSE_ERROR"


@dataclass(frozen=True)
class FieldRecord:
	fieldname: str
	fieldtype: str
	options: str | None = None


@dataclass(frozen=True)
class PermissionRecord:
	role: str
	permlevel: int
	read: bool
	write: bool
	create: bool
	submit: bool
	cancel: bool
	if_owner: bool


@dataclass(frozen=True)
class DocTypeRecord:
	name: str
	module: str
	path: Path
	table_name: str
	fields: tuple[FieldRecord, ...]
	is_submittable: bool
	istable: bool
	permissions: tuple[PermissionRecord, ...]
	autoname: str | None


@dataclass(frozen=True)
class SchemaIndex:
	doctypes: tuple[DocTypeRecord, ...]

	def get_doctype(self, name: str) -> DocTypeRecord | None:
		return next((doctype for doctype in self.doctypes if doctype.name == name), None)

	def submittable_doctypes(self) -> tuple[DocTypeRecord, ...]:
		return tuple(doctype for doctype in self.doctypes if doctype.is_submittable)

	def owner_scoped_doctypes(self) -> tuple[DocTypeRecord, ...]:
		return tuple(
			doctype
			for doctype in self.doctypes
			if any(permission.if_owner for permission in doctype.permissions)
		)

	def child_table_graph(self) -> dict[str, tuple[str, ...]]:
		graph: dict[str, list[str]] = {}
		for doctype in self.doctypes:
			for field in doctype.fields:
				if field.fieldtype == "Table" and field.options:
					graph.setdefault(doctype.name, []).append(field.options)
		return {parent: tuple(children) for parent, children in graph.items()}
