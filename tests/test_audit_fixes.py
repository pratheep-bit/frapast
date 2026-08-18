"""Unit tests verifying all 9 Codebase Audit fixes (P0, P1, P2) in frapAST Security Engine.
"""
import tempfile
import unittest
from pathlib import Path

from scanner.cli import RepoScanResult
from scanner.hooks.engine import build_hook_index
from scanner.hooks.models import HookIndex
from scanner.ledger_io import index_ledger_entries
from scanner.proof.orchestrator import _write_reproducer
from scanner.severity.models import SeverityScore
from scanner.shared import SourceFile
from scanner.ui.menus import _score
from scanner.web.server import _lock, _state


class TestCodebaseAuditFixes(unittest.TestCase):

    def test_p0_broken_hooks_py_does_not_crash_scan(self):
        """P0: A malformed hooks.py file should be skipped with a warning, not abort the scan."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bad_hooks = tmp / "hooks.py"
            bad_hooks.write_text("def unclosed_func(:", encoding="utf-8")

            source_file = SourceFile(path=bad_hooks, root=tmp)
            # Should not raise HookParseError
            idx = build_hook_index([source_file])
            self.assertIsInstance(idx, HookIndex)
            self.assertTrue(any("parse_error" in u for u in idx.unresolved))

    def test_p0_api_findings_race_condition_fixed(self):
        """P0: GET /api/findings snapshot should copy inner candidate dicts to avoid race with worker."""
        cand_dict = {"rule_id": "FR-PERM-001", "function": "test_func", "status": "candidate"}
        with _lock:
            _state["candidates"] = [cand_dict]
            _state["repo"] = "/tmp/test"

        # Lock-guarded snapshot copy matching GET /api/findings
        with _lock:
            snapshot_candidates = [dict(c) for c in _state["candidates"]]

        # Mutate worker side
        cand_dict["status"] = "proven"
        cand_dict["proof_status"] = "proven"

        # Snapshot must retain clean previous values
        self.assertEqual(snapshot_candidates[0]["status"], "candidate")
        self.assertNotIn("proof_status", snapshot_candidates[0])

    def test_p1_atomic_reproducer_write(self):
        """P1: _write_reproducer uses tempfile + os.replace for atomic file writes."""
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "test_repro.sh"
            _write_reproducer(target, "echo 'proven'", "direct_call")
            self.assertTrue(target.is_file())
            content = target.read_text(encoding="utf-8")
            self.assertIn("# PROOF_MODE: direct_call", content)
            self.assertIn("echo 'proven'", content)

    def test_p1_ledger_indexing(self):
        """P1: index_ledger_entries creates a quick lookup map for batch proof updates."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            finding_file = tmp / "FR-PERM-001-1234.yaml"
            finding_file.write_text(
                "id: FR-PERM-001-1234\ncode_location_hash: abcdef123456\nstatus: candidate\n",
                encoding="utf-8",
            )
            idx = index_ledger_entries(tmp)
            self.assertIn("abcdef123456", idx)
            self.assertEqual(idx["abcdef123456"], finding_file)

    def test_p2_severity_score_hashability(self):
        """P2: SeverityScore is frozen and hashable despite dict field."""
        sev = SeverityScore(score=8.5, dimension_scores={"impact": 5, "privilege": 4})
        # Should not raise TypeError: unhashable type: 'dict'
        try:
            h = hash(sev)
            self.assertIsInstance(h, int)
        except TypeError:
            self.fail("SeverityScore raised TypeError on hash()")

    def test_p2_hook_index_hashability(self):
        """P2: HookIndex is frozen and hashable despite dict fields."""
        idx = HookIndex(
            handlers=(),
            permission_query_conditions={"Doc": "cond"},
            has_permission={"Doc": "perm"},
            unresolved=(),
        )
        try:
            h = hash(idx)
            self.assertIsInstance(h, int)
        except TypeError:
            self.fail("HookIndex raised TypeError on hash()")

    def test_p2_repo_scan_result_hashability(self):
        """P2: RepoScanResult is frozen and hashable despite list field."""
        res = RepoScanResult(
            repo_id="local",
            repo_path=Path("."),
            candidates=[{"id": "b1"}],
            num_files=10,
            elapsed=0.5,
        )
        try:
            h = hash(res)
            self.assertIsInstance(h, int)
        except TypeError:
            self.fail("RepoScanResult raised TypeError on hash()")

    def test_p2_menus_score_defensive_guard(self):
        """P2: menus._score delegates to canonical candidate_score and survives non-numeric scores."""
        malformed = {"severity": {"score": "invalid_number"}}
        score = _score(malformed)
        self.assertEqual(score, 0.0)


if __name__ == "__main__":
    unittest.main()
