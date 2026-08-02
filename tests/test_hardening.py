"""Regression tests for Round 1 to Round 5 hardening fixes."""
import tempfile
import unittest
from pathlib import Path

import yaml


class TestIdentityHashStability(unittest.TestCase):
	def test_identity_excludes_line_number(self):
		from scanner.cli import _write_candidates
		import inspect
		src = inspect.getsource(_write_candidates)
		self.assertNotIn("candidate['line']", src.replace('"', "'"))
		self.assertIn("candidate['function']", src.replace('"', "'"))


class TestDryRunDoesNotMutateLedger(unittest.TestCase):
	def test_dry_run_flag_guards_ledger_write(self):
		import inspect
		from scanner import cli
		src = inspect.getsource(cli.main)
		self.assertIn("if not args.dry_run:", src)


class TestTaxonomyValidator(unittest.TestCase):
	def test_registry_has_no_unresolved_placeholders_silently_passing(self):
		registry_path = Path("scanner/taxonomy_registry.yaml")
		registry = yaml.safe_load(registry_path.read_text())
		additional = registry.get("additional_categories", {})
		for prefix, meta in additional.items():
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


class TestStatusHistoryAppendOnly(unittest.TestCase):
	def test_update_ledger_appends_history(self):
		from scanner.ledger_io import read_ledger_entry, update_ledger_after_proof
		from scanner.proof.models import ProofResult, ProofStatus
		with tempfile.TemporaryDirectory() as tmpdir:
			fdir = Path(tmpdir)
			fpath = fdir / "FR-TEST.yaml"
			fpath.write_text(yaml.safe_dump({"id": "FR-TEST", "code_location_hash": "hash1"}, sort_keys=False))
			res1 = ProofResult("FR-TEST", ProofStatus.PASSED, 1, 0, "", "", 0.1, "", code_location_hash="hash1")
			update_ledger_after_proof(fdir, res1)
			res2 = ProofResult("FR-TEST", ProofStatus.PASSED, 2, 0, "", "", 0.1, "", code_location_hash="hash1")
			update_ledger_after_proof(fdir, res2)
			data = read_ledger_entry(fpath)
			self.assertEqual(len(data.get("status_history", [])), 2)


class TestLedgerSchemaValidation(unittest.TestCase):
	def test_validate_entry_detects_invalid_status(self):
		from scanner.ledger_schema import validate_entry
		problems = validate_entry({"status": "invalid_status"})
		self.assertTrue(any("invalid status" in p for p in problems))


class TestReproducerMarkersValidation(unittest.TestCase):
	def test_validate_reproducer_markers_script(self):
		import scanner.proof.validate_reproducer_markers as vrm
		ret = vrm.main()
		self.assertEqual(ret, 0)


class TestMultiDirectoryWriteBack(unittest.TestCase):
	def test_locate_finding_dir(self):
		import scanner.ledger_io as ledger_io_module
		from scanner.proof.orchestrator import ProofOrchestrator
		with tempfile.TemporaryDirectory() as tmpdir:
			td = Path(tmpdir)
			fdir = td / "findings"
			fdir.mkdir()
			fake_scanner_pkg = td / "fake_scanner_pkg"
			fake_scanner_pkg.mkdir()
			hrms_dir = fake_scanner_pkg / "findings_latest_hrms"
			hrms_dir.mkdir()
			(hrms_dir / "FR-LOCATE-001.yaml").write_text("id: FR-LOCATE-001\n")

			original_file = ledger_io_module.__file__
			try:
				ledger_io_module.__file__ = str(fake_scanner_pkg / "ledger_io.py")
				orch = ProofOrchestrator(workspace_root=td, findings_dir=fdir)
				located = orch._locate_finding_dir("FR-LOCATE-001")
				self.assertIsNotNone(located)
				self.assertEqual(located.resolve(), hrms_dir.resolve())
			finally:
				ledger_io_module.__file__ = original_file


class TestRound5Hardening(unittest.TestCase):
	def test_task24_synthesize_fix_no_frozen_mutation(self):
		from scanner.rules import Candidate
		from scanner.fix import synthesize_fix
		cand = Candidate(
			taxonomy_id="FR-PERM-002", rule_id="FR-PERM-002", rule_version="1.0.0",
			file="f.py", line=1, function="func", code_location_hash="h1",
			evidence="ev", proof_recipe="rec"
		)
		self.assertIsNone(synthesize_fix(cand, Path(".")))

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
