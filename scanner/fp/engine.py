from __future__ import annotations

from pathlib import Path

import yaml

from scanner.fp.models import FalsePositiveRecord, PrecisionMetric, SuppressionResult
from scanner.rules import Candidate

PROVEN_STATUSES = frozenset({"proven", "merged", "patched", "regressed"})


def load_false_positives(path: str | Path) -> tuple[FalsePositiveRecord, ...]:
	data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
	entries = data.get("false_positives", [])
	if not isinstance(entries, list):
		raise ValueError("FP_LOG_INVALID: false_positives must be a list")
	records: list[FalsePositiveRecord] = []
	for entry in entries:
		if not isinstance(entry, dict):
			raise ValueError("FP_LOG_INVALID: entry must be an object")
		required = ("finding_id", "rule_id", "rule_version", "repo", "file", "function", "code_location_hash", "reason")
		missing = [field for field in required if not isinstance(entry.get(field), str) or not entry[field]]
		if missing:
			raise ValueError(f"FP_LOG_INVALID: missing {','.join(missing)}")
		records.append(
			FalsePositiveRecord(
				finding_id=entry["finding_id"],
				rule_id=entry["rule_id"],
				rule_version=entry["rule_version"],
				repo=entry["repo"],
				file=entry["file"],
				function=entry["function"],
				code_location_hash=entry["code_location_hash"],
				reason=entry["reason"],
			)
		)
	return tuple(sorted(records, key=lambda item: item.finding_id))


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


def precision_by_rule(findings_dir: str | Path) -> tuple[PrecisionMetric, ...]:
	from scanner.ledger_io import discover_all_findings_dirs

	counts: dict[tuple[str, str], dict[str, int]] = {}
	all_dirs = discover_all_findings_dirs(findings_dir)
	for fdir in all_dirs:
		for path in sorted(fdir.glob("FR-*.yaml")):
			try:
				record = yaml.safe_load(path.read_text(encoding="utf-8"))
			except Exception:
				continue
			if not isinstance(record, dict):
				continue
			rule_id = record.get("rule_id")
			rule_version = record.get("rule_version")
			status = record.get("status")
			if not isinstance(rule_id, str) or not isinstance(rule_version, str) or not isinstance(status, str):
				continue
			bucket = counts.setdefault((rule_id, rule_version), {"proven": 0, "false_positives": 0})
			if status in PROVEN_STATUSES:
				bucket["proven"] += 1
			elif status == "false_positive":
				bucket["false_positives"] += 1
	metrics: list[PrecisionMetric] = []
	for (rule_id, rule_version), bucket in sorted(counts.items()):
		denominator = bucket["proven"] + bucket["false_positives"]
		metrics.append(
			PrecisionMetric(
				rule_id=rule_id,
				rule_version=rule_version,
				proven=bucket["proven"],
				false_positives=bucket["false_positives"],
				precision=bucket["proven"] / denominator if denominator else None,
			)
		)
	return tuple(metrics)
