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
	# True when the DocType JSON has `"is_amendable": 1`. Only submittable
	# DocTypes can be amended; non-amendable ones should never trigger
	# FR-WKFL-004 even if they define on_submit.
	is_amendable: bool = False
	permissions: tuple[PermissionRecord, ...] = ()
	autoname: str | None = None


@dataclass(frozen=True)
class SchemaIndex:
	doctypes: tuple[DocTypeRecord, ...]

	def __post_init__(self) -> None:
		# Immutable, shared read-only across every rule in a scan — each rule
		# re-scanning the full tuple is O(rules * doctypes) for data that never
		# changes. Precompute once; object.__setattr__ is required since frozen.
		object.__setattr__(self, "_by_name", {d.name: d for d in self.doctypes})
		object.__setattr__(self, "_submittable", tuple(d for d in self.doctypes if d.is_submittable))
		object.__setattr__(
			self,
			"_owner_scoped",
			tuple(d for d in self.doctypes if any(p.if_owner for p in d.permissions)),
		)
		object.__setattr__(
			self,
			"_amendable_names",
			frozenset(d.name for d in self.doctypes if d.is_amendable),
		)

	def get_doctype(self, name: str) -> DocTypeRecord | None:
		return getattr(self, "_by_name", {}).get(name)

	def submittable_doctypes(self) -> tuple[DocTypeRecord, ...]:
		return getattr(self, "_submittable", ())

	def amendable_doctype_names(self) -> frozenset[str]:
		"""Return the names of DocTypes where amendment is explicitly enabled.

		`is_amendable` is a Frappe DocType JSON key (value 1) that must be set
		for the framework to expose the 'Amend' button and create amended_from
		links.  Rules that flag amendment-chain issues (FR-WKFL-004) should only
		fire for DocTypes in this set to avoid flooding controllers that happen
		to have on_submit but are never amended.
		"""
		return getattr(self, "_amendable_names", frozenset())

	def owner_scoped_doctypes(self) -> tuple[DocTypeRecord, ...]:
		return getattr(self, "_owner_scoped", ())

	def child_table_graph(self) -> dict[str, tuple[str, ...]]:
		graph: dict[str, list[str]] = {}
		for doctype in self.doctypes:
			for field in doctype.fields:
				if field.fieldtype == "Table" and field.options:
					graph.setdefault(doctype.name, []).append(field.options)
		return {parent: tuple(children) for parent, children in graph.items()}
