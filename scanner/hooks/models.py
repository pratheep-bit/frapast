from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class HookParseError(ValueError):
	code = "HOOK_PARSE_ERROR"


@dataclass(frozen=True)
class HookHandlerRecord:
	app: str
	doctype: str
	event: str
	handler: str
	order: int
	path: Path


@dataclass(frozen=True)
class HookCollisionRecord:
	doctype: str
	event: str
	handlers: tuple[HookHandlerRecord, ...]


@dataclass(frozen=True)
class HookIndex:
	handlers: tuple[HookHandlerRecord, ...]
	permission_query_conditions: dict[str, str]
	has_permission: dict[str, str]
	unresolved: tuple[str, ...]

	def handlers_for(self, doctype: str, event: str) -> tuple[HookHandlerRecord, ...]:
		return tuple(
			handler for handler in self.handlers if handler.doctype == doctype and handler.event == event
		)

	def permission_hooks_for(self, doctype: str) -> tuple[str, ...]:
		values = []
		if doctype in self.permission_query_conditions:
			values.append(self.permission_query_conditions[doctype])
		if doctype in self.has_permission:
			values.append(self.has_permission[doctype])
		return tuple(values)

	def collisions(self) -> tuple[HookCollisionRecord, ...]:
		grouped: dict[tuple[str, str], list[HookHandlerRecord]] = {}
		for handler in self.handlers:
			grouped.setdefault((handler.doctype, handler.event), []).append(handler)
		return tuple(
			HookCollisionRecord(doctype, event, tuple(handlers))
			for (doctype, event), handlers in sorted(grouped.items())
			if len({handler.app for handler in handlers}) > 1
		)
