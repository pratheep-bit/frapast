"""Schema definition and validation for findings/*.yaml ledger entries."""
from __future__ import annotations

REQUIRED_FIELDS = {
	"id", "taxonomy_id", "rule_id", "rule_version", "repo", "file", "function",
	"status", "proof_tier", "code_location_hash", "discovered",
}

VALID_STATUSES = {"candidate", "proven", "merged", "patched", "false_positive", "regressed"}


def validate_entry(entry: dict, source_name: str = "<unknown>") -> list[str]:
	"""Return a list of human-readable problems; empty list means valid."""
	problems = []
	if not isinstance(entry, dict):
		return [f"{source_name}: not a dict"]

	missing = REQUIRED_FIELDS - entry.keys()
	if missing:
		problems.append(f"{source_name}: missing required fields: {sorted(missing)}")

	status = entry.get("status")
	if status is not None and status not in VALID_STATUSES:
		problems.append(f"{source_name}: invalid status '{status}' (expected one of {sorted(VALID_STATUSES)})")

	tier = entry.get("proof_tier")
	if tier is not None and (not isinstance(tier, int) or not (0 <= tier <= 3)):
		problems.append(f"{source_name}: proof_tier must be an int 0-3, got {tier!r}")

	if status == "proven" and not entry.get("proven"):
		problems.append(f"{source_name}: status is 'proven' but 'proven' date is not set")

	return problems
