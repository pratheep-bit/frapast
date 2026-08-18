"""CI gate: every findings/*.yaml entry must pass ledger_schema.validate_entry."""
import sys

import yaml

from scanner.ledger_io import discover_all_findings_dirs
from scanner.ledger_schema import validate_entry

FINDINGS_DIRS = discover_all_findings_dirs("findings")


def main() -> int:
	all_problems = []
	for fdir in FINDINGS_DIRS:
		if not fdir.is_dir():
			continue
		for path in fdir.glob("*.yaml"):
			if path.name in ("fp-log.yaml", "schema.yaml") or path.name.startswith("."):
				continue
			try:
				entry = yaml.safe_load(path.read_text(encoding="utf-8"))
			except Exception as e:
				all_problems.append(f"{path.name}: failed to parse YAML: {e}")
				continue
			all_problems.extend(validate_entry(entry, source_name=path.name))

	if all_problems:
		print("Ledger schema violations found:")
		for p in all_problems:
			print(f"  - {p}")
		return 1
	print("All ledger entries pass schema validation.")
	return 0


if __name__ == "__main__":
	sys.exit(main())
