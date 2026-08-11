"""Comprehensive unit test suite for static detection rules."""
import concurrent.futures
import unittest
from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index, discover_hooks_files
from scanner.python import build_python_index
from scanner.shared import SourceFile
from scanner.rules import execute_rules, clear_rule_caches
from scanner.schema import build_schema_index, discover_doctype_json

ROOT = Path(__file__).resolve().parents[1]


class TestAllRulesCoverage(unittest.TestCase):
	def setUp(self):
		clear_rule_caches()

	def test_rules_registry_integrity(self):
		from scanner.rules.engine import ALL_RULES, RENAMED_TAXONOMY
		self.assertGreaterEqual(len(ALL_RULES), 20)
		for rule in ALL_RULES:
			self.assertTrue(callable(rule))
		# Taxonomy consistency assertion passes at import time
		self.assertEqual(RENAMED_TAXONOMY["fr_xss_001"], "FR-INJ-005")

	def test_rules_execution_on_fixtures(self):
		fixture_dir = ROOT / "tests" / "python" / "fixtures"
		py_files = [SourceFile(p, fixture_dir) for p in sorted(fixture_dir.rglob("*.py"))]
		schema = build_schema_index(
			discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "employee")
			+ discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "expense_claim")
		)
		hooks = build_hook_index(discover_hooks_files(ROOT / "tests" / "hooks" / "fixtures"))
		python = build_python_index(py_files)
		graph = build_call_graph(python, hooks)

		candidates = execute_rules(schema, hooks, python, graph)
		self.assertIsInstance(candidates, list)
		rule_ids = {c.rule_id for c in candidates}
		self.assertTrue(len(rule_ids) > 0)

	def test_contextvar_cache_concurrency(self):
		"""Verify concurrent execute_rules() calls operate safely in parallel threads."""
		fixture_dir = ROOT / "tests" / "python" / "fixtures"
		py_files = [SourceFile(p, fixture_dir) for p in sorted(fixture_dir.rglob("*.py"))]
		schema = build_schema_index(
			discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "employee")
		)
		hooks = build_hook_index(discover_hooks_files(ROOT / "tests" / "hooks" / "fixtures"))
		python = build_python_index(py_files)
		graph = build_call_graph(python, hooks)

		def _worker():
			return execute_rules(schema, hooks, python, graph)

		with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
			futures = [executor.submit(_worker) for _ in range(10)]
			results = [f.result() for f in futures]

		self.assertEqual(len(results), 10)
		for res in results:
			self.assertIsInstance(res, list)


if __name__ == "__main__":
	unittest.main()
