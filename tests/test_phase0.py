"""test_phase0.py — Phase 0 infrastructure checks.

Tests for docker-compose.yml and runtime/reproducers/001.sh were removed in
this commit because:
- docker-compose.yml is no longer part of the repository (removed after the
  docker-based proof approach was superseded by frapast bench-check + HTTP client).
- runtime/reproducers/001.sh was a legacy naming convention; all reproducers
  are now named FR-<rule_id>-<hash>.sh and are gitignored.
- findings/.schema.yaml and findings/FR-PERM-001-0001.yaml were removed when
  the findings ledger grew beyond hand-authored examples; the schema is now
  validated via test_audit_fixes.py and the YAML schema validator.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_yaml(path: Path):
	return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_makefile_contains_required_targets():
	text = (ROOT / "Makefile").read_text(encoding="utf-8")
	for target in ["site-new", "site-seed", "repro", "teardown", "test", "lint", "logs"]:
		assert f"{target}:" in text


def test_phase0_make_targets_do_not_mask_failures():
	text = (ROOT / "Makefile").read_text(encoding="utf-8")
	for target in ["site-new", "site-seed", "repro"]:
		section = text.split(f"{target}:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
		assert "|| true" not in section
