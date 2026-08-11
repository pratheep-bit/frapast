from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml

from scanner.fp import precision_by_rule


STATUS_ORDER = ("candidate", "proven", "merged", "patched", "false_positive", "regressed")

RULE_FAMILIES = {
	"FR-PERM": "Permission & Access Control",
	"FR-SQLI": "ORM vs. Raw SQL Boundary",
	"FR-HOOK": "Hook Execution & Lifecycle",
	"FR-WKFL": "Docstatus / Workflow State Machine",
	"FR-DATA": "Child Tables, Multi-Tenancy, Integrity",
	"FR-INJ": "API / Injection Surfaces",
	"FR-CSRF": "Cross-Site Request Forgery",
	"FR-SSRF": "Server-Side Request Forgery",
	"FR-PERF": "Performance Anti-Patterns",
	"FR-I18N": "Internationalization & Formatting",
}


def render_track_record(findings_dir: str | Path) -> str:
	from scanner.ledger_io import discover_all_findings_dirs

	path = Path(findings_dir)
	all_dirs = discover_all_findings_dirs(findings_dir)
	findings = [
		f
		for d in all_dirs
		for item in sorted(d.glob("FR-*.yaml"))
		for f in [_load_finding(item)]
		if f is not None
	]
	counts = Counter(finding["status"] for finding in findings)
	lines = [
		"# Frappe Security Scanner Track Record",
		"",
		"## Evidence Status",
		"",
		"Static candidates are internal-only Tier 0 records. They are not vulnerability claims or external submissions.",
		"",
		"| Status | Count |",
		"| --- | ---: |",
	]
	for status in STATUS_ORDER:
		lines.append(f"| {status} | {counts[status]} |")

	# Rule precision
	lines.extend([
		"",
		"## Rule Precision",
		"",
		"Precision is proven / (proven + false_positive). Unresolved candidates are excluded.",
		"",
		"| Rule | Proven | False Positives | Precision |",
		"| --- | ---: | ---: | ---: |",
	])
	for metric in precision_by_rule(path):
		precision = "N/A" if metric.precision is None else f"{metric.precision:.0%}"
		lines.append(
			f"| {metric.rule_id} v{metric.rule_version} | {metric.proven} | {metric.false_positives} | {precision} |"
		)

	# Rule coverage
	lines.extend(["", "## Rule Coverage", "", "| Family | Category | Findings |", "| --- | --- | ---: |"])
	family_counts: dict[str, int] = Counter()
	for finding in findings:
		taxonomy_id = finding.get("taxonomy_id", "")
		if isinstance(taxonomy_id, str):
			family = taxonomy_id.rsplit("-", 1)[0] if "-" in taxonomy_id else taxonomy_id
			family_counts[family] += 1
	for family_prefix, family_name in RULE_FAMILIES.items():
		count = sum(v for k, v in family_counts.items() if k.startswith(family_prefix))
		lines.append(f"| {family_prefix} | {family_name} | {count} |")

	# Per-repo breakdown
	repo_counts: dict[str, Counter[str]] = {}
	for finding in findings:
		repo = finding.get("repo", "unknown")
		if isinstance(repo, str):
			repo_counts.setdefault(repo, Counter())[finding["status"]] += 1
	if len(repo_counts) > 1:
		lines.extend(["", "## Per-Repo Breakdown", "", "| Repo | Candidates | Proven | Merged | FP |", "| --- | ---: | ---: | ---: | ---: |"])
		for repo, counts_by_status in sorted(repo_counts.items()):
			lines.append(
				f"| {repo} | {counts_by_status['candidate']} | {counts_by_status['proven']} "
				f"| {counts_by_status['merged']} | {counts_by_status['false_positive']} |"
			)

	# Severity distribution
	severity_counts: Counter[str] = Counter()
	for finding in findings:
		impact = finding.get("impact_class")
		if isinstance(impact, str):
			severity_counts[impact] += 1
	if severity_counts:
		lines.extend([
			"",
			"## Severity Distribution",
			"",
			"| Impact Class | Count |",
			"| --- | ---: |",
		])
		for impact_class in ("rce", "privilege_escalation", "data_corruption", "data_exposure", "availability"):
			if severity_counts[impact_class]:
				lines.append(f"| {impact_class} | {severity_counts[impact_class]} |")

	# Upstream history
	lines.extend(["", "## Upstream History", ""])
	has_upstream = False
	for finding in findings:
		if finding["status"] == "merged" and isinstance(finding.get("upstream_pr"), str):
			lines.append(f"- {finding['id']}: merged upstream at {finding['upstream_pr']}")
			has_upstream = True
	if not has_upstream:
		lines.append("- No merged upstream records.")

	return "\n".join(lines) + "\n"


def _load_finding(path: Path) -> dict[str, object] | None:
	"""Load a single ledger YAML entry.

	Returns None (and logs a warning) if the file is corrupt, unreadable,
	or missing the mandatory `status` field — rather than raising and crashing
	the entire report command. The caller must filter None values out.
	"""
	try:
		finding = yaml.safe_load(path.read_text(encoding="utf-8"))
	except Exception as exc:
		from scanner.logger import logger as _logger
		_logger.warning("Skipping corrupt ledger entry %s: %s", path, exc)
		return None
	if not isinstance(finding, dict) or not isinstance(finding.get("status"), str):
		from scanner.logger import logger as _logger
		_logger.warning(
			"Skipping invalid ledger entry %s: missing or non-string 'status' field.", path
		)
		return None
	return finding
