"""Unit tests for the 8 newly implemented Tier 1 AST reproducer generators."""
import tempfile
import unittest
from pathlib import Path

from scanner.proof.orchestrator import ProofOrchestrator, synthesize_reproducer_if_missing


class TestTier1ReproducerGenerators(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.repro_dir = self.root / "reproducers"
        self.repro_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_fr_hook_006_bare_except_generator(self):
        test_file = self.root / "test_hook006.py"
        test_file.write_text("def foo():\n    try:\n        pass\n    except:\n        pass\n")

        finding_data = {
            "rule_id": "FR-HOOK-006",
            "file": str(test_file),
            "line": 4,
        }
        repro_path = synthesize_reproducer_if_missing(self.repro_dir, "FR-HOOK-006-test", finding_data)
        self.assertIsNotNone(repro_path)
        self.assertTrue(repro_path.is_file())

        orch = ProofOrchestrator(workspace_root=self.root)
        res = orch._run_tier1("FR-HOOK-006-test", repro_path)
        self.assertEqual(res.exit_code, 0)

    def test_fr_hook_004_enqueue_without_dedup_generator(self):
        test_file = self.root / "test_hook004.py"
        test_file.write_text("import frappe\ndef run():\n    frappe.enqueue('my_job')\n")

        finding_data = {
            "rule_id": "FR-HOOK-004",
            "file": str(test_file),
            "line": 3,
        }
        repro_path = synthesize_reproducer_if_missing(self.repro_dir, "FR-HOOK-004-test", finding_data)
        self.assertIsNotNone(repro_path)

        orch = ProofOrchestrator(workspace_root=self.root)
        res = orch._run_tier1("FR-HOOK-004-test", repro_path)
        self.assertEqual(res.exit_code, 0)

    def test_fr_hook_004_enqueue_with_aliased_import(self):
        test_file = self.root / "test_hook004_alias.py"
        test_file.write_text("from frappe import enqueue as bg_task\ndef run():\n    bg_task('my_job')\n")

        finding_data = {
            "rule_id": "FR-HOOK-004",
            "file": str(test_file),
            "line": 3,
        }
        repro_path = synthesize_reproducer_if_missing(self.repro_dir, "FR-HOOK-004-alias-test", finding_data)
        self.assertIsNotNone(repro_path)

        orch = ProofOrchestrator(workspace_root=self.root)
        res = orch._run_tier1("FR-HOOK-004-alias-test", repro_path)
        self.assertEqual(res.exit_code, 0)

    def test_fr_perf_001_query_in_loop_generator(self):
        test_file = self.root / "test_perf001.py"
        test_file.write_text("import frappe\ndef run(items):\n    for item in items:\n        doc = frappe.get_doc('Item', item)\n")

        finding_data = {
            "rule_id": "FR-PERF-001",
            "file": str(test_file),
            "line": 3,
        }
        repro_path = synthesize_reproducer_if_missing(self.repro_dir, "FR-PERF-001-test", finding_data)
        self.assertIsNotNone(repro_path)

        orch = ProofOrchestrator(workspace_root=self.root)
        res = orch._run_tier1("FR-PERF-001-test", repro_path)
        self.assertEqual(res.exit_code, 0)

    def test_fr_hook_001_submit_without_cancel_generator(self):
        test_file = self.root / "test_hook001.py"
        test_file.write_text("class Doc:\n    def on_submit(self):\n        pass\n")

        finding_data = {
            "rule_id": "FR-HOOK-001",
            "file": str(test_file),
            "line": 1,
        }
        repro_path = synthesize_reproducer_if_missing(self.repro_dir, "FR-HOOK-001-test", finding_data)
        self.assertIsNotNone(repro_path)

        orch = ProofOrchestrator(workspace_root=self.root)
        res = orch._run_tier1("FR-HOOK-001-test", repro_path)
        self.assertEqual(res.exit_code, 0)

    def test_fr_data_001_evidence_regex_extraction(self):
        test_file = self.root / "test_data001.py"
        test_file.write_text("doc.custom_fieldname\n")

        finding_data = {
            "rule_id": "FR-DATA-001",
            "file": str(test_file),
            "line": 1,
            "evidence": "Reference to non-existent field 'custom_fieldname' on DocType Item",
        }
        repro_path = synthesize_reproducer_if_missing(self.repro_dir, "FR-DATA-001-regex-test", finding_data)
        self.assertIsNotNone(repro_path)

        orch = ProofOrchestrator(workspace_root=self.root)
        res = orch._run_tier1("FR-DATA-001-regex-test", repro_path)
        self.assertEqual(res.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
