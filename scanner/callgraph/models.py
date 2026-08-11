from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum


class EdgeKind(str, Enum):
	DIRECT_CALL = "direct_call"  # foo() / module.foo()
	STRING_DISPATCH = "string_dispatch"  # frappe.call("a.b.c") / frappe.enqueue("a.b.c")
	HOOK_DISPATCH = "hook_dispatch"  # hooks.py string path invoked by framework
	DYNAMIC_METHOD = "dynamic_method"  # frappe.get_doc(...).method() best-effort


@dataclass(frozen=True)
class CallEdge:
	caller_symbol_id: str
	callee_symbol_id: str
	kind: EdgeKind
	confidence: float  # 1.0 = certain, <1.0 = best-effort/heuristic


@dataclass(frozen=True)
class CallGraph:
	edges: dict[str, tuple[str, ...]] = field(hash=False)
	unresolved: tuple[str, ...]
	rich_edges: tuple[CallEdge, ...] = field(default_factory=tuple)
	_cache: dict[str, object] = field(default_factory=dict, repr=False, compare=False)
	_cache_lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

	def get_cached(self, key: str):
		with self._cache_lock:
			return self._cache.get(key)

	def set_cached(self, key: str, value) -> None:
		with self._cache_lock:
			self._cache[key] = value

	def get_or_compute(self, key: str, compute):
		"""Atomic get-or-compute: `compute` (a zero-arg callable) runs at
		most once per key per CallGraph instance, even under concurrent
		access from multiple threads."""
		with self._cache_lock:
			if key in self._cache:
				return self._cache[key]
			value = compute()
			self._cache[key] = value
			return value

	def reachable_from(self, symbol_id: str, max_hops: int = 1) -> tuple[str, ...]:
		seen = {symbol_id}
		frontier = {symbol_id}
		for _ in range(max_hops):
			next_frontier = {callee for caller in frontier for callee in self.edges.get(caller, ()) if callee not in seen}
			seen.update(next_frontier)
			frontier = next_frontier
		return tuple(sorted(seen))

	def reachable_from_set(self, root_symbol_ids: set[str]) -> set[str]:
		"""BFS over edges. Returns the set of symbol_ids reachable from any
		root, INCLUDING the roots themselves."""
		adjacency: dict[str, list[str]] = {}
		for caller, callees in self.edges.items():
			adjacency.setdefault(caller, []).extend(callees)

		visited: set[str] = set(root_symbol_ids)
		frontier = list(root_symbol_ids)
		while frontier:
			current = frontier.pop()
			for neighbor in adjacency.get(current, []):
				if neighbor not in visited:
					visited.add(neighbor)
					frontier.append(neighbor)
		return visited
