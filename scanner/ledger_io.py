"""Atomic, corruption-safe read/write helpers and concurrency locking for the findings ledger.

Every write goes through a temp file in the same directory, followed by
os.replace() (atomic on POSIX and Windows) — so a crash mid-write can never
leave a truncated or partially-written YAML file in findings/. Use these
helpers everywhere the ledger is touched; never call yaml.safe_dump directly
against a ledger path.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
import time
from datetime import date
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
		with open(path, encoding="utf-8") as f:
			data = yaml.safe_load(f)
		return data if isinstance(data, dict) else None
	except (FileNotFoundError, yaml.YAMLError):
		return None


@contextlib.contextmanager
def ledger_lock(findings_dir: Path, timeout: float = 15.0):
	"""Atomic advisory lock over the findings directory using POSIX O_EXCL.

	``open(path, 'x')`` (exclusive create) is atomic on POSIX — the kernel
	guarantees that exactly one caller succeeds even when two processes race.
	This replaces the previous ``write_text`` approach which had a TOCTOU
	window between ``lock_path.exists()`` and the actual write.

	The lock file stores this process's PID so stale locks can be diagnosed.
	If the lock is not released within `timeout` seconds a RuntimeError is
	raised with enough context for an operator to delete it manually.
	"""
	findings_dir = Path(findings_dir)
	findings_dir.mkdir(parents=True, exist_ok=True)
	lock_path = findings_dir / ".ledger.lock"
	start = time.monotonic()
	while True:
		try:
			# O_EXCL exclusive create — atomic on POSIX
			with open(lock_path, "x", encoding="utf-8") as fh:
				fh.write(str(os.getpid()))
			break  # lock acquired
		except FileExistsError:
			try:
				pid_str = lock_path.read_text(encoding="utf-8").strip()
				pid = int(pid_str)
				os.kill(pid, 0)
			except (ValueError, OSError, ProcessLookupError):
				# Process PID is no longer running or unreadable — stale lock!
				try:
					lock_path.unlink(missing_ok=True)
					continue
				except OSError:
					pass

			if time.monotonic() - start > timeout:
				raise RuntimeError(
					f"Ledger at {findings_dir} is locked by another process "
					f"(stale lock at {lock_path}? delete it manually if you're sure "
					f"nothing else is running)."
				) from None
			time.sleep(0.05)
	try:
		yield
	finally:
		lock_path.unlink(missing_ok=True)



def index_ledger_entries(findings_dir: str | Path) -> dict[str, Path]:
	"""Map code_location_hash / id / filename-stem -> ledger file path, built
	once and reused across a whole proof run instead of
	update_ledger_after_proof() re-globbing + re-parsing every *.yaml file
	for every single candidate (previously O(candidates_proved * ledger_size))."""
	findings_path = Path(findings_dir)
	index: dict[str, Path] = {}
	if not findings_path.is_dir():
		return index
	for path in findings_path.glob("*.yaml"):
		entry = read_ledger_entry(path)
		if entry is None:
			continue
		if entry.get("code_location_hash"):
			index.setdefault(entry["code_location_hash"], path)
		if entry.get("id"):
			index.setdefault(entry["id"], path)
		index.setdefault(path.stem, path)
	return index


def update_ledger_after_proof(
	findings_dir: str | Path, result, _index: dict[str, Path] | None = None
) -> None:
	"""Single, hardened path for writing a proof result back to its ledger
	entry. Pass a pre-built `_index` (see index_ledger_entries) to avoid
	rescanning the directory on every call within a batch; omit it and the
	old per-call behavior is preserved."""
	findings_path = Path(findings_dir)
	if not findings_path.is_dir():
		return
	loc_hash = getattr(result, "code_location_hash", None)
	fid = getattr(result, "finding_id", None)
	with ledger_lock(findings_path):
		index = _index if _index is not None else index_ledger_entries(findings_path)
		path = index.get(loc_hash) or index.get(fid)
		if path is None:
			return
		entry = read_ledger_entry(path)
		if entry is None:
			return

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
