"""Comprehensive unit test suite for static detection rules."""
import concurrent.futures
import unittest
from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index, discover_hooks_files
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index, discover_doctype_json
from scanner.shared import SourceFile

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

	def test_fr_sqli_001_fstring_detection(self):
		"""Verify FR-SQLI-001 properly flags f-string SQL injections with variable interpolation."""
		import tempfile

		from scanner.rules.engine import fr_sqli_001
		with tempfile.TemporaryDirectory() as td:
			p = Path(td)
			(p / "app.py").write_text("""\
import frappe
@frappe.whitelist()
def search_users(term):
    return frappe.db.sql(f"SELECT name FROM tabUser WHERE email = '{term}'")
""", encoding="utf-8")
			sf = [SourceFile(p / "app.py", p)]
			py = build_python_index(sf)
			cg = build_call_graph(py)
			schema = build_schema_index([])
			hooks = build_hook_index([])
			cands = fr_sqli_001(schema, hooks, py, cg)
			self.assertEqual(len(cands), 1)
			self.assertEqual(cands[0].rule_id, "FR-SQLI-001")


if __name__ == "__main__":
	unittest.main()
