"""Regression tests for Round 1 to Round 5 hardening fixes."""
import tempfile
import unittest
from pathlib import Path

import yaml


class TestIdentityHashStability(unittest.TestCase):
	def test_identity_excludes_line_number(self):
		import inspect

		from scanner.cli import _write_candidates
		src = inspect.getsource(_write_candidates)
		self.assertNotIn("candidate['line']", src.replace('"', "'"))
		self.assertIn("candidate['function']", src.replace('"', "'"))


class TestTaxonomyValidator(unittest.TestCase):
	def test_registry_has_no_unresolved_placeholders_silently_passing(self):
		registry_path = Path("scanner/taxonomy/taxonomy_registry.yaml")
		if not registry_path.exists():
			registry_path = Path("scanner/taxonomy_registry.yaml")
		registry = yaml.safe_load(registry_path.read_text())
		additional = registry.get("additional_categories", {})
		for _prefix, meta in additional.items():
			blob = " ".join(str(v) for v in meta.values())
			if "FILL IN" in blob or "TBD" in blob:
				validator_src = Path("scanner/validate_taxonomy.py").read_text()
				self.assertIn("PLACEHOLDER_MARKERS", validator_src)


class TestFPAnalyzerGroupsByVersion(unittest.TestCase):
	def test_true_positive_statuses_includes_merged_and_patched(self):
		from scanner.fp_analyzer import TRUE_POSITIVE_STATUSES
		self.assertIn("merged", TRUE_POSITIVE_STATUSES)
		self.assertIn("patched", TRUE_POSITIVE_STATUSES)
		self.assertIn("regressed", TRUE_POSITIVE_STATUSES)
		self.assertIn("proven", TRUE_POSITIVE_STATUSES)


class TestAtomicLedgerIO(unittest.TestCase):
	def test_read_ledger_entry_handles_corrupt_yaml(self):
		with tempfile.TemporaryDirectory() as tmpdir:
			p = Path(tmpdir) / "broken.yaml"
			p.write_text("id: FR-TEST\n  bad:", encoding="utf-8")
			from scanner.ledger_io import read_ledger_entry
			self.assertIsNone(read_ledger_entry(p))


class TestLedgerSchemaValidation(unittest.TestCase):
	def test_validate_entry_detects_invalid_status(self):
		from scanner.ledger_schema import validate_entry
		problems = validate_entry({"status": "invalid_status"})
		self.assertTrue(any("invalid status" in p for p in problems))


class TestRound5Hardening(unittest.TestCase):
	def test_task31_severity_override_correctness(self):
		from scanner.rules import Candidate
		from scanner.severity import score_candidate
		cand = Candidate(
			taxonomy_id="FR-HOOK-006", rule_id="FR-HOOK-006", rule_version="1.0.0",
			file="f.py", line=1, function="func", code_location_hash="h1",
			evidence="ev", proof_recipe="rec"
		)
		score = score_candidate(cand)
		self.assertEqual(score.dimension_scores.get("category"), "correctness")


if __name__ == "__main__":
	unittest.main()
