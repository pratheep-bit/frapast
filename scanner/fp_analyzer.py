from __future__ import annotations

from collections import defaultdict

from scanner.ledger_io import discover_all_findings_dirs, read_ledger_entry

# Any status past "proven" in the lifecycle is still a confirmed true positive
# for precision purposes. "regressed" means it was real, got fixed, and broke
# again — still a real bug, not a false positive. Only "false_positive" counts
# against precision.
TRUE_POSITIVE_STATUSES = {"proven", "merged", "patched", "regressed"}


def analyze_fp_rates(findings_dir: str = "findings") -> dict[str, dict]:
	# Keyed by (rule_id, rule_version) — NOT rule_id alone — so that fixing a
	# rule (e.g. v1 -> v3) shows up as a clean version-over-version precision
	# trend instead of being averaged away with the old, worse data.
	counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
		lambda: {"proven": 0, "false_positive": 0, "total": 0}
	)

	all_dirs = discover_all_findings_dirs(findings_dir)
	if not all_dirs:
		return {}

	for findings_path in all_dirs:
		for path in findings_path.glob("*.yaml"):
			finding = read_ledger_entry(path)
			if finding is None:
				continue
			rule_id = finding.get("rule_id")
			rule_version = finding.get("rule_version", "unknown")
			status = finding.get("status")
			if rule_id is None or status is None:
				continue
			key = (rule_id, rule_version)
			counts[key]["total"] += 1
			if status in TRUE_POSITIVE_STATUSES:
				counts[key]["proven"] += 1
			elif status == "false_positive":
				counts[key]["false_positive"] += 1

	report = {}
	for (rule_id, rule_version), c in counts.items():
		attempts = c["proven"] + c["false_positive"]
		if attempts == 0:
			continue
		fp_rate = c["false_positive"] / attempts
		label = f"{rule_id}@{rule_version}"
		report[label] = {
			"rule_id": rule_id,
			"rule_version": rule_version,
			"attempts": attempts,
			"fp_rate": round(fp_rate, 2),
			"needs_logic_review": attempts >= 5 and fp_rate > 0.5,
		}
	return report


def print_report(findings_dir: str = "findings") -> None:
	report = analyze_fp_rates(findings_dir)
	print(f"{'Rule@Version':<26}{'Attempts':<10}{'FP Rate':<10}{'Flag'}")
	for label, data in sorted(report.items(), key=lambda kv: -kv[1]["fp_rate"]):
		flag = "⚠️  REVIEW RULE LOGIC" if data["needs_logic_review"] else ""
		print(f"{label:<26}{data['attempts']:<10}{data['fp_rate']:<10}{flag}")


if __name__ == "__main__":
	print_report()
