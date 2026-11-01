from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
	sys.path.insert(0, str(ROOT))

import pytest


@pytest.mark.skipif(shutil.which("git") is None, reason="'git' executable is missing")
def test_build_api_change_data_synthetic_repo(tmp_path: Path) -> None:
	"""Test API change generator against a synthetic 3-branch repository."""
	repo_dir = tmp_path / "synthetic_frappe"
	repo_dir.mkdir()

	def _git(*args: str) -> str:
		return subprocess.check_output(
			["git", "-C", str(repo_dir)] + list(args),
			text=True,
		).strip()

	# Initialize synthetic repo
	_git("init")
	_git("config", "user.name", "Test User")
	_git("config", "user.email", "test@example.com")

	# Branch 1: v14
	frappe_pkg = repo_dir / "frappe"
	frappe_pkg.mkdir()
	(frappe_pkg / "__init__.py").write_text("def whitelist():\n    return lambda f: f\n", encoding="utf-8")
	(frappe_pkg / "mod_a.py").write_text(
		"import frappe\n\n"
		"def func_stay():\n"
		"    pass\n\n"
		"def func_removed():\n"
		"    pass\n\n"
		"def func_moved():\n"
		"    pass\n\n"
		"@frappe.whitelist()\n"
		"def whitelisted_removed():\n"
		"    pass\n\n"
		"def _private_removed():\n"
		"    pass\n",
		encoding="utf-8",
	)
	_git("add", ".")
	_git("commit", "-m", "Branch 1 (v14)")
	_git("branch", "-M", "version-14")

	# Branch 2: v15
	_git("checkout", "-b", "version-15")
	# func_stay stays
	# func_removed deleted
	# func_moved moved to mod_b.py
	# whitelisted_removed deleted
	# _private_removed deleted
	(frappe_pkg / "mod_a.py").write_text(
		"def func_stay():\n    pass\n",
		encoding="utf-8",
	)
	(frappe_pkg / "mod_b.py").write_text(
		"def func_moved():\n    pass\n",
		encoding="utf-8",
	)
	_git("add", ".")
	_git("commit", "-m", "Branch 2 (v15)")

	# Branch 3: v16
	_git("checkout", "-b", "version-16")
	(frappe_pkg / "mod_c.py").write_text(
		"def new_in_v16():\n    pass\n",
		encoding="utf-8",
	)
	_git("add", ".")
	_git("commit", "-m", "Branch 3 (v16)")

	# Run generator script
	from scripts.build_api_change_data import generate_api_changes

	out1 = tmp_path / "changes1.json"
	out2 = tmp_path / "changes2.json"

	generate_api_changes(
		repo_path=repo_dir,
		branches=["version-14", "version-15", "version-16"],
		out_path=out1,
		timestamp="2026-01-01T00:00:00Z",
	)
	generate_api_changes(
		repo_path=repo_dir,
		branches=["version-14", "version-15", "version-16"],
		out_path=out2,
		timestamp="2026-01-01T00:00:00Z",
	)

	# Assert deterministic byte-identical output
	bytes1 = out1.read_bytes()
	bytes2 = out2.read_bytes()
	assert bytes1 == bytes2, "Two generator runs must produce byte-identical output"

	data = json.loads(out1.read_text(encoding="utf-8"))
	assert data["schema_version"] == "1.0.0"
	assert "version-14" in data["branches"]
	assert "version-15" in data["branches"]
	assert "version-16" in data["branches"]

	changes = {c["name"]: c for c in data["changes"]}

	# 1. func_removed must be classified as 'removed' with high confidence
	assert "frappe.mod_a.func_removed" in changes
	c_rem = changes["frappe.mod_a.func_removed"]
	assert c_rem["status"] == "removed"
	assert c_rem["confidence"] == "high"
	assert c_rem["last_present_in"] == "version-14"
	assert c_rem["missing_in"] == "version-15"

	# 2. func_moved must be classified as 'moved' with medium confidence and moved_to candidate
	assert "frappe.mod_a.func_moved" in changes
	c_mov = changes["frappe.mod_a.func_moved"]
	assert c_mov["status"] == "moved"
	assert c_mov["confidence"] == "medium"
	assert c_mov["moved_to"] is not None
	assert any("frappe.mod_b.func_moved" in cand for cand in c_mov["moved_to"])

	# 3. whitelisted_removed must be classified as 'removed'
	assert "frappe.mod_a.whitelisted_removed" in changes
	assert changes["frappe.mod_a.whitelisted_removed"]["status"] == "removed"

	# 4. func_stay must NOT be in changes
	assert "frappe.mod_a.func_stay" not in changes

	# 5. _private_removed must NOT be in changes
	assert "frappe.mod_a._private_removed" not in changes
