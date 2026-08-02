from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FalsePositiveRecord:
	finding_id: str
	rule_id: str
	rule_version: str
	repo: str
	file: str
	function: str
	code_location_hash: str
	reason: str


@dataclass(frozen=True)
class SuppressionResult:
	candidates: tuple[object, ...]
	suppressed_finding_ids: tuple[str, ...]


@dataclass(frozen=True)
class PrecisionMetric:
	rule_id: str
	rule_version: str
	proven: int
	false_positives: int
	precision: float | None
