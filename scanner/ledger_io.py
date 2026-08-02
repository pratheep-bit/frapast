"""Atomic, corruption-safe read/write helpers and concurrency locking for the findings ledger.

Every write goes through a temp file in the same directory, followed by
os.replace() (atomic on POSIX and Windows) — so a crash mid-write can never
leave a truncated or partially-written YAML file in findings/. Use these
helpers everywhere the ledger is touched; never call yaml.safe_dump directly
against a ledger path.
"""
from __future__ import annotations

import contextlib
from datetime import date
import hashlib
import os
import tempfile
import time
from pathlib import Path

import yaml


def write_ledger_entry(path: Path, entry: dict) -> None:
	"""Write `entry` to `path` atomically."""
	path = Path(path)
	path.parent.mkdir(parents=True, exist_ok=True)
	fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as f:
			yaml.safe_dump(entry, f, sort_keys=False)
		os.replace(tmp_path, path)
	except Exception:
		if os.path.exists(tmp_path):
			os.remove(tmp_path)
		raise


def read_ledger_entry(path: Path) -> dict | None:
	"""Read a ledger entry, returning None on missing/invalid file rather than raising."""
	try:
		with open(path, "r", encoding="utf-8") as f:
			data = yaml.safe_load(f)
		return data if isinstance(data, dict) else None
	except (FileNotFoundError, yaml.YAMLError):
		return None


@contextlib.contextmanager
def ledger_lock(findings_dir: Path, timeout: float = 15.0):
	"""Simple advisory lock over the whole findings directory for the duration
	of a ledger-writing operation. Not a substitute for a real database's
	transaction guarantees, but sufficient to stop two concurrent scanner runs
	from silently clobbering each other's status_history appends."""
	findings_dir = Path(findings_dir)
	findings_dir.mkdir(parents=True, exist_ok=True)
	lock_path = findings_dir / ".ledger.lock"
	start = time.monotonic()
	while lock_path.exists():
		if time.monotonic() - start > timeout:
			raise RuntimeError(
				f"Ledger at {findings_dir} is locked by another process "
				f"(stale lock at {lock_path}? delete it manually if you're sure "
				f"nothing else is running)."
			)
		time.sleep(0.1)
	lock_path.write_text(str(os.getpid()), encoding="utf-8")
	try:
		yield
	finally:
		lock_path.unlink(missing_ok=True)


def update_ledger_after_proof(findings_dir: str | Path, result) -> None:
	"""Single, hardened path for writing a proof result back to its ledger
	entry. Appends to status_history rather than overwriting, uses atomic
	writes, and records reproducer_hash. This is the ONLY function that should
	ever write proof outcomes to findings/*.yaml — do not reintroduce a second
	write path."""
	findings_path = Path(findings_dir)
	if not findings_path.is_dir():
		return
	with ledger_lock(findings_path):
		for path in findings_path.glob("*.yaml"):
			entry = read_ledger_entry(path)
			if entry is None:
				continue
			loc_hash = getattr(result, "code_location_hash", None)
			fid = getattr(result, "finding_id", None)
			if entry.get("code_location_hash") != loc_hash and entry.get("id") != fid and path.stem != fid:
				continue

			status_val = getattr(result.status, "value", result.status)
			new_status = entry.get("status")
			if status_val == "passed":
				new_status = "proven"
			elif status_val == "failed":
				new_status = "false_positive"
			elif status_val == "dry_run":
				return  # dry runs must never write — see Round 2 TASK 10

			reproducer_path = getattr(result, "reproducer_path", None)
			reproducer_hash = None
			if reproducer_path and Path(reproducer_path).is_file():
				reproducer_hash = hashlib.sha256(Path(reproducer_path).read_bytes()).hexdigest()[:16]

			proof_tier = getattr(result, "proof_tier", entry.get("proof_tier", 0))

			history_entry = {
				"date": date.today().isoformat(),
				"status": new_status,
				"proof_tier": proof_tier,
				"reproducer_hash": reproducer_hash,
			}
			entry.setdefault("status_history", []).append(history_entry)

			entry["status"] = new_status
			entry["proof_tier"] = proof_tier
			entry["reproducer_hash"] = reproducer_hash
			if new_status == "proven":
				entry["proven"] = date.today().isoformat()

			write_ledger_entry(path, entry)
			return


def discover_all_findings_dirs(primary_dir: str | Path) -> list[Path]:
	"""Given the primary findings directory, also discover sibling legacy
	findings_latest_* directories nested under the scanner/ package itself
	(NOT under workspace_root — see TASK 28 for why that distinction matters).
	Every report/precision command needs to see these directories or its
	numbers are silently incomplete."""
	primary = Path(primary_dir)
	dirs = [primary] if primary.is_dir() else []
	scanner_pkg_dir = Path(__file__).resolve().parent
	for sibling in sorted(scanner_pkg_dir.glob("findings_latest_*")):
		if sibling.is_dir() and sibling not in dirs:
			dirs.append(sibling)
	if primary.is_dir() and primary.parent.is_dir():
		for sibling in sorted(primary.parent.glob("findings_latest_*")):
			if sibling.is_dir() and sibling not in dirs:
				dirs.append(sibling)
	return dirs
