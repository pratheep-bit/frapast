"""CI gate: every finding claiming proof_tier >= 1 must have a reproducer_hash
that matches the CURRENT content of its reproducer file. A mismatch means the
reproducer changed since the proof ran — the claim is stale and must be
flagged, not silently trusted. A missing reproducer file means the claim
can no longer be independently re-verified at all.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import yaml

from scanner.ledger_io import discover_all_findings_dirs

FINDINGS_DIRS = discover_all_findings_dirs("findings")
REPRODUCERS_DIR = Path("runtime/reproducers")


def reproducer_path_for(entry: dict) -> Path | None:
	finding_id = entry.get("id")
	if not finding_id:
		return None
	for ext in (".sh", ".py"):
		p = REPRODUCERS_DIR / f"{finding_id}{ext}"
		if p.is_file():
			return p
	return None


def main() -> int:
	problems = []
	for fdir in FINDINGS_DIRS:
		if not fdir.is_dir():
			continue
		for path in fdir.glob("*.yaml"):
			if path.name == "fp-log.yaml":
				continue
			try:
				entry = yaml.safe_load(path.read_text(encoding="utf-8"))
			except Exception:
				continue
			if not isinstance(entry, dict):
				continue
			stored_hash = entry.get("reproducer_hash")
			if not stored_hash:
				continue

			repro_path = reproducer_path_for(entry)
			if repro_path is None or not repro_path.is_file():
				problems.append(f"{path.name}: reproducer_hash recorded but reproducer file missing — proof claim cannot be re-verified")
				continue

			current_hash = hashlib.sha256(repro_path.read_bytes()).hexdigest()[:16]
			if current_hash != stored_hash:
				problems.append(f"{path.name}: reproducer changed since proof ran — stale/tampered claim (stored: {stored_hash}, current: {current_hash})")

	if problems:
		print("Ledger integrity problems found:")
		for p in problems:
			print(f"  - {p}")
		return 1
	print("All proven findings' reproducer hashes match current content.")
	return 0


if __name__ == "__main__":
	sys.exit(main())
