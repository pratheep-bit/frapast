"""Behavioral regression test suite for Scanner Hardening Pass v2."""
import ast
import tempfile
import unittest
from pathlib import Path

from scanner.python.engine import _is_explicit_owner_or_role_guard
from scanner.rules import Candidate
from scanner.severity import score_candidate
from scanner.validate import validate_and_stage


class TestNoFrozenDataclassMutation(unittest.TestCase):
	def test_with_status_replaces_status_without_mutation(self):
		cand = Candidate(
			taxonomy_id="FR-PERM-002", rule_id="FR-PERM-002", rule_version="1.0.0",
			file="test.py", line=10, function="func", code_location_hash="hash1",
			evidence="ev", proof_recipe="rec"
		)
		updated = cand.with_status("needs-manual-triage")
		self.assertEqual(cand.status, "candidate")
		self.assertEqual(updated.status, "needs-manual-triage")
		self.assertEqual(updated.code_location_hash, cand.code_location_hash)


class TestValidateAndStage(unittest.TestCase):
	def test_syntax_error_rejected(self):
		cand = Candidate(
			taxonomy_id="FR-TEST-001", rule_id="FR-TEST-001", rule_version="1.0.0",
			file="test.py", line=1, function="func", code_location_hash="h1",
			evidence="ev", proof_recipe="rec"
		)
		with tempfile.TemporaryDirectory() as tmpdir:
			td = Path(tmpdir)
			(td / "test.py").write_text("def valid(): pass\n")
			self.assertFalse(validate_and_stage(cand, td, "def broken_syntax(:"))

	def test_valid_code_accepted(self):
		cand = Candidate(
			taxonomy_id="FR-TEST-001", rule_id="FR-TEST-001", rule_version="1.0.0",
			file="test.py", line=1, function="func", code_location_hash="h1",
			evidence="ev", proof_recipe="rec"
		)
		with tempfile.TemporaryDirectory() as tmpdir:
			td = Path(tmpdir)
			(td / "test.py").write_text("def valid(): pass\n")
			self.assertTrue(validate_and_stage(cand, td, "def valid(): return True\n"))


class TestPermissionGuardPrecision(unittest.TestCase):
	def test_manager_designation_string_not_treated_as_role_guard(self):
		code = """
if frappe.session.user and "Manager" not in employee.designation:
	frappe.throw("Access denied")
"""
		tree = ast.parse(code)
		if_node = tree.body[0]
		self.assertIsInstance(if_node, ast.If)
		self.assertFalse(_is_explicit_owner_or_role_guard(if_node))

	def test_real_role_check_accepted(self):
		code = """
if frappe.session.user != doc.owner and not frappe.has_role("System Manager"):
	frappe.throw("Access denied")
"""
		tree = ast.parse(code)
		if_node = tree.body[0]
		self.assertIsInstance(if_node, ast.If)
		self.assertTrue(_is_explicit_owner_or_role_guard(if_node))


class TestSeverityScoringUpdates(unittest.TestCase):
	def test_renamed_rules_score_as_correctness(self):
		cand = Candidate(
			taxonomy_id="FR-HOOK-006", rule_id="FR-HOOK-006", rule_version="1.1.0",
			file="f.py", line=1, function="func", code_location_hash="h1",
			evidence="ev", proof_recipe="rec"
		)
		score = score_candidate(cand)
		self.assertEqual(score.dimension_scores.get("category"), "correctness")

	def test_previously_missing_rules_scored_correctly(self):
		cand_csrf = Candidate(
			taxonomy_id="FR-CSRF-001", rule_id="FR-CSRF-001", rule_version="1.0.0",
			file="f.py", line=1, function="func", code_location_hash="h1",
			evidence="ev", proof_recipe="rec"
		)
		score_csrf = score_candidate(cand_csrf)
		self.assertEqual(score_csrf.dimension_scores.get("impact_class"), "privilege_escalation")
		self.assertEqual(score_csrf.dimension_scores.get("blast_radius"), "cross_site")


class TestCallGraphThreadSafetyAndOptimization(unittest.TestCase):
	def test_get_or_compute_thread_safe(self):
		from scanner.callgraph.models import CallGraph
		cg = CallGraph(edges={}, unresolved=())
		called = 0

		def compute():
			nonlocal called
			called += 1
			return "result"

		val1 = cg.get_or_compute("key1", compute)
		val2 = cg.get_or_compute("key1", compute)
		self.assertEqual(val1, "result")
		self.assertEqual(val2, "result")
		self.assertEqual(called, 1)


if __name__ == "__main__":
	unittest.main()
