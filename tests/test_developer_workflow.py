from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner.python import load as load_python
from scanner.rules.engine import Candidate, _filter_suppressed_candidates
from scanner.reporting.sarif import export_sarif


class TestDeveloperWorkflowFeatures(unittest.TestCase):
	def test_sarif_exporter(self) -> None:
		candidates = [
			{
				"rule_id": "FR-SQLI-001",
				"taxonomy_id": "FR-SQLI-001",
				"file": "app/demo.py",
				"line": 42,
				"evidence": "Unsanitized SQL query",
				"severity": {"score": 75.0},
			}
		]
		sarif_json = export_sarif(candidates, Path("/tmp"))
		data = json.loads(sarif_json)
		self.assertEqual(data["version"], "2.1.0")
		self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "frapast")
		self.assertEqual(data["runs"][0]["results"][0]["ruleId"], "FR-SQLI-001")
		self.assertEqual(data["runs"][0]["results"][0]["level"], "error")

	def test_inline_suppression(self) -> None:
		with TemporaryDirectory() as tmpdir:
			file_path = Path(tmpdir) / "vulnerable.py"
			file_path.write_text(
				"frappe.db.sql(query)  # frapast:ignore FR-SQLI-001\n"
				"frappe.db.sql(query2)\n",
				encoding="utf-8",
			)
			cand1 = Candidate("FR-SQLI-001", "1.0", "FR-SQLI-001", str(file_path), 1, "foo", "hash1", "ev", "recipe")
			cand2 = Candidate("FR-SQLI-001", "1.0", "FR-SQLI-001", str(file_path), 2, "foo", "hash2", "ev", "recipe")

			python = load_python(Path(tmpdir))
			filtered = _filter_suppressed_candidates([cand1, cand2], python)
			self.assertEqual(len(filtered), 1)
			self.assertEqual(filtered[0].line, 2)


if __name__ == "__main__":
	unittest.main()
