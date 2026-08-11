"""Unit test suite for frapast CLI exit codes and command dispatch."""
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scanner.cli import main, _run_scan_command
from scanner.proof.models import ProofResult, ProofStatus


class TestCLIExitCodes(unittest.TestCase):
	@patch("scanner.cli._scan_repo_with_severity")
	def test_scan_no_candidates_returns_zero(self, mock_scan):
		mock_scan.return_value = ([], 10, 0.5)
		with patch("sys.argv", ["frapast", "scan", "."]):
			code = main()
			self.assertEqual(code, 0)

	@patch("scanner.cli._scan_repo_with_severity")
	def test_scan_with_candidates_returns_one(self, mock_scan):
		mock_scan.return_value = ([{
			"rule_id": "FR-PERM-001",
			"taxonomy_id": "FR-PERM-001",
			"file": "test.py",
			"line": 10,
			"function": "test_func",
			"code_location_hash": "abc",
			"evidence": "ev",
			"proof_recipe": "pr",
			"status": "candidate",
		}], 10, 0.5)
		with patch("sys.argv", ["frapast", "scan", "."]):
			code = main()
			self.assertEqual(code, 1)

	@patch("scanner.proof.orchestrator.ProofOrchestrator")
	@patch("scanner.cli._scan_repo_with_severity")
	def test_prove_all_skipped_returns_zero(self, mock_scan, mock_orch_cls):
		candidate = {
			"rule_id": "FR-PERM-001",
			"taxonomy_id": "FR-PERM-001",
			"file": "test.py",
			"line": 10,
			"function": "test_func",
			"code_location_hash": "abc",
			"evidence": "ev",
			"proof_recipe": "pr",
			"status": "candidate",
		}
		mock_scan.return_value = ([candidate], 10, 0.5)
		
		mock_orch = MagicMock()
		mock_orch.prove_candidate.return_value = ProofResult(
			finding_id="FR-PERM-001-abc",
			status=ProofStatus.SKIPPED,
			proof_tier=0,
			exit_code=None,
			stdout="",
			stderr="",
			duration_seconds=0.1,
			reproducer_path="",
		)
		mock_orch_cls.return_value = mock_orch

		with patch("sys.argv", ["frapast", "scan", ".", "--prove"]):
			code = main()
			self.assertEqual(code, 0)

	@patch("scanner.proof.orchestrator.ProofOrchestrator")
	@patch("scanner.cli._scan_repo_with_severity")
	def test_prove_with_proven_finding_returns_one(self, mock_scan, mock_orch_cls):
		candidate = {
			"rule_id": "FR-HOOK-007",
			"taxonomy_id": "FR-HOOK-007",
			"file": "test.py",
			"line": 10,
			"function": "test_func",
			"code_location_hash": "abc",
			"evidence": "ev",
			"proof_recipe": "pr",
			"status": "candidate",
		}
		mock_scan.return_value = ([candidate], 10, 0.5)
		
		mock_orch = MagicMock()
		mock_orch.prove_candidate.return_value = ProofResult(
			finding_id="FR-HOOK-007-abc",
			status=ProofStatus.PASSED,
			proof_tier=1,
			exit_code=0,
			stdout="Mutable default detected",
			stderr="",
			duration_seconds=0.1,
			reproducer_path="FR-HOOK-007.sh",
		)
		mock_orch_cls.return_value = mock_orch

		with patch("sys.argv", ["frapast", "scan", ".", "--prove"]):
			code = main()
			self.assertEqual(code, 1)


if __name__ == "__main__":
	unittest.main()
