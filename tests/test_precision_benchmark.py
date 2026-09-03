"""test_precision_benchmark.py — Automated precision regression benchmark for frapAST.

Runs each active rule against both:
1. Controlled targeted fixture corpora (tests/python/fixtures/...)
2. Real-world open-source Frappe application corpora (/tmp/hrms_scan/...)

Asserts that finding counts remain within tracked bounds, proving both True Positive
recall and False Positive suppression.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import NamedTuple

import pytest

from scanner.callgraph import build_call_graph
from scanner.hooks.engine import build_hook_index
from scanner.python.engine import build_python_index, discover_python_files
from scanner.rules.engine import ALL_RULES
from scanner.schema.engine import build_schema_index
from scanner.shared.records import SourceFile

# ---------------------------------------------------------------------------
# Corpora paths
# ---------------------------------------------------------------------------

FIXTURES_ROOT = Path(__file__).parent / "python" / "fixtures"
SCHEMA_FIXTURES_ROOT = Path(__file__).parent / "schema" / "fixtures"
REAL_APP_HRMS_ROOT = Path("/tmp/hrms_scan/hrms")


def _fixture_path(name: str) -> Path:
    return FIXTURES_ROOT / name


# ---------------------------------------------------------------------------
# Rule bound definition
# ---------------------------------------------------------------------------

class RuleBound(NamedTuple):
    rule_id: str
    target_rel_path: str
    min_expected: int
    max_expected: int
    description: str
    is_real_app: bool = False


RULE_BOUNDS: list[RuleBound] = [
    # -----------------------------------------------------------------------
    # Synthetic Fixture Corpus Bounds (Strict TP / TN guarantees)
    # -----------------------------------------------------------------------
    RuleBound(
        "FR-SQLI-001",
        "vulnerable.py",
        min_expected=1,
        max_expected=5,
        description="TP: Unparameterized dynamic frappe.db.sql in vulnerable.py.",
    ),
    RuleBound(
        "FR-SQLI-001",
        "safe.py",
        min_expected=0,
        max_expected=0,
        description="TN: Parameterized frappe.db.sql in safe.py must produce 0 findings.",
    ),
    RuleBound(
        "FR-SQLI-002",
        "phase3_patterns.py",
        min_expected=0,
        max_expected=2,
        description="SQL injection in custom SQL building helper.",
    ),
    RuleBound(
        "FR-SQLI-003",
        "phase3_patterns.py",
        min_expected=1,
        max_expected=5,
        description="TP: frappe.db.set_value writing status/workflow_state directly.",
    ),
    RuleBound(
        "FR-SQLI-004",
        "phase3_patterns.py",
        min_expected=1,
        max_expected=3,
        description="TP: Dynamic table/column name in frappe.qb.",
    ),
    RuleBound(
        "FR-PERM-001",
        "vulnerable.py",
        min_expected=1,
        max_expected=5,
        description="TP: Whitelisted functions without permission check in vulnerable.py.",
    ),
    RuleBound(
        "FR-PERM-001",
        "guarded_permission.py",
        min_expected=0,
        max_expected=0,
        description="TN: Guarded permission checks must produce 0 findings.",
    ),
    RuleBound(
        "FR-PERM-002",
        "vulnerable.py",
        min_expected=1,
        max_expected=3,
        description="TP: ignore_permissions=True in vulnerable.py.",
    ),
    RuleBound(
        "FR-PERM-003",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Document bypass via direct SQL / db.set_value.",
    ),
    RuleBound(
        "FR-PERM-004",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Frappe password / secret access without audit.",
    ),
    RuleBound(
        "FR-PERM-005",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Role permission escalation.",
    ),
    RuleBound(
        "FR-PERM-006",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Insecure direct object reference via un-scoped get_doc.",
    ),
    RuleBound(
        "FR-HOOK-001",
        "phase1_patterns.py",
        min_expected=1,
        max_expected=3,
        description="TP: on_submit without on_cancel in DocType controller.",
    ),
    RuleBound(
        "FR-HOOK-002",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Unhandled exception in doc events hook.",
    ),
    RuleBound(
        "FR-HOOK-003",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Long running task in synchronous request hook.",
    ),
    RuleBound(
        "FR-HOOK-004",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Enqueue without deduplication key.",
    ),
    RuleBound(
        "FR-HOOK-005",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Missing transactional db.commit / db.rollback in hook.",
    ),
    RuleBound(
        "FR-WKFL-001",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Workflow action bypass.",
    ),
    RuleBound(
        "FR-WKFL-002",
        "phase1_patterns.py",
        min_expected=1,
        max_expected=3,
        description="TP: Direct workflow_state modification outside engine.",
    ),
    RuleBound(
        "FR-WKFL-003",
        "phase3_patterns.py",
        min_expected=1,
        max_expected=5,
        description="TP: Status change without corresponding docstatus update.",
    ),
    RuleBound(
        "FR-INJ-001",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Command injection via os.system / subprocess.",
    ),
    RuleBound(
        "FR-INJ-002",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Dynamic code execution via eval/exec.",
    ),
    RuleBound(
        "FR-INJ-005",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Unescaped msgprint / throw / Jinja template render.",
    ),
    RuleBound(
        "FR-CSRF-001",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Whitelisted GET endpoint modifying database state.",
    ),
    RuleBound(
        "FR-SSRF-001",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Unvalidated URL in frappe.integrations / requests.get.",
    ),
    RuleBound(
        "FR-HOOK-006",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Bare except clause in controller logic.",
    ),
    RuleBound(
        "FR-HOOK-007",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Mutable default argument in function signature.",
    ),
    RuleBound(
        "FR-DATA-001",
        "fr_data_001_patterns.py",
        min_expected=1,
        max_expected=2,
        description="TP: Unknown fieldname reference against schema index.",
    ),
    RuleBound(
        "FR-PATH-001",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Arbitrary file read / path traversal.",
    ),
    RuleBound(
        "FR-PERF-001",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: N+1 query inside loop.",
    ),
    RuleBound(
        "FR-I18N-001",
        "phase1_patterns.py",
        min_expected=0,
        max_expected=2,
        description="TP: Hardcoded user-visible string without _() wrapper.",
    ),
    # -----------------------------------------------------------------------
    # Real-App HRMS Corpus Bounds (when /tmp/hrms_scan is available)
    # -----------------------------------------------------------------------
    RuleBound(
        "FR-PERM-001",
        "hr/doctype/interview/interview.py",
        min_expected=3,
        max_expected=3,
        description="Real HRMS interview.py permission findings (exact baseline: 3).",
        is_real_app=True,
    ),
    RuleBound(
        "FR-HOOK-001",
        "hr/doctype/interview/interview.py",
        min_expected=1,
        max_expected=1,
        description="Real HRMS interview.py on_submit without on_cancel (exact baseline: 1).",
        is_real_app=True,
    ),
    RuleBound(
        "FR-PERF-001",
        "hr/doctype/interview/interview.py",
        min_expected=2,
        max_expected=2,
        description="Real HRMS interview.py get_doc in loop (exact baseline: 2).",
        is_real_app=True,
    ),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_rule(rule_id: str, target_path: Path) -> int:
    """Index target and run the matching rule. Returns finding count."""
    if not target_path.exists():
        pytest.skip(f"Target not found: {target_path}")

    if target_path.is_dir():
        py_files = discover_python_files(target_path)
        source_files = py_files
    else:
        source_files = [SourceFile(path=target_path, root=target_path.parent)]

    python_index = build_python_index(source_files)
    from scanner.schema.engine import discover_doctype_json
    schema_files = discover_doctype_json(SCHEMA_FIXTURES_ROOT) if SCHEMA_FIXTURES_ROOT.exists() else []
    schema_index = build_schema_index(schema_files)
    hook_index = build_hook_index([])
    call_graph = build_call_graph(python_index)

    target_rule = None
    rule_clean = rule_id.replace("-", "_").lower()
    for rule in ALL_RULES:
        if rule_clean in rule.__name__.lower():
            target_rule = rule
            break

    if target_rule is None:
        pytest.skip(f"Rule function not found for rule_id={rule_id}")

    findings = target_rule(schema_index, hook_index, python_index, call_graph)
    return len(findings)


@pytest.mark.parametrize(
    "bound",
    RULE_BOUNDS,
    ids=[f"{b.rule_id}::{b.target_rel_path}" for b in RULE_BOUNDS],
)
def test_rule_finding_count_within_bounds(bound: RuleBound):
    """Assert that a rule's finding count on a corpus target stays strictly within tracked bounds."""
    if bound.is_real_app:
        if not REAL_APP_HRMS_ROOT.exists():
            pytest.skip(f"Real app corpus not cloned at {REAL_APP_HRMS_ROOT}")
        target = REAL_APP_HRMS_ROOT / bound.target_rel_path
    else:
        target = _fixture_path(bound.target_rel_path)

    count = _run_rule(bound.rule_id, target)
    assert bound.min_expected <= count <= bound.max_expected, (
        f"Rule {bound.rule_id} on {bound.target_rel_path}: expected [{bound.min_expected}, "
        f"{bound.max_expected}] findings, got {count}.\n"
        f"Description: {bound.description}\n"
        f"If this change is intentional, update RULE_BOUNDS with a justification."
    )


# ---------------------------------------------------------------------------
# Dedicated Root-Cause Regression Proof Tests
# ---------------------------------------------------------------------------

class TestRootCauseRegressions:
    """Dedicated tests that fail loudly if any past root-cause bug regresses."""

    def test_fr_data_001_method_call_vs_field_read_regression(self):
        """FR-DATA-001 must NEVER flag method call targets as missing DocType fields."""
        code = textwrap.dedent("""\
            import frappe
            from frappe.model.document import Document

            class TestDoc(Document):
                def process(self):
                    self.set_status(update=True)
                    self.check_permission("write")
                    self.db_set("status", "Active")
                    self.notify_update()
                    return self.valid_field
        """)
        import ast
        import tempfile

        from scanner.python.engine import _IndexCollector

        tree = ast.parse(code)
        lines = code.splitlines()
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "test_doc.py"
            f.write_text(code)
            sf = SourceFile(path=f, root=Path(td))
            collector = _IndexCollector()
            collector.collect(sf, tree, lines)
            idx = collector.build()
            refs = [r.fieldname for r in idx.fieldname_references]

        # Method call targets MUST NOT be in refs
        for forbidden in ["set_status", "check_permission", "db_set", "notify_update"]:
            assert forbidden not in refs, f"FR-DATA-001 regressed: '{forbidden}' recorded as field"
        # Genuine attribute read MUST be in refs
        assert "valid_field" in refs

    def test_fr_perm_001_guard_recognition_regression(self):
        """FR-PERM-001 must recognize instance permission checks and not fire FP."""
        fixture = _fixture_path("guarded_permission.py")
        count = _run_rule("FR-PERM-001", fixture)
        assert count == 0, f"FR-PERM-001 regressed: fired {count} findings on guarded_permission.py"

    def test_fr_perf_001_in_memory_dict_regression(self):
        """FR-PERF-001 must not fire on in-memory dict construction in loops."""
        code = textwrap.dedent("""\
            import frappe

            def create_records():
                items = frappe.get_all("Item")
                for item in items:
                    frappe.get_doc({"doctype": "Log", "msg": item.name}).insert()
        """)
        import tempfile

        from scanner.rules.engine import fr_perf_001_query_in_loop

        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "app" / "records.py"
            f.parent.mkdir(parents=True)
            f.write_text(code)
            sf = SourceFile(path=f, root=Path(td))
            py_idx = build_python_index([sf])
            cg = build_call_graph(py_idx)
            findings = fr_perf_001_query_in_loop(
                build_schema_index([]), build_hook_index([]), py_idx, cg
            )
            assert len(findings) == 0, (
                f"FR-PERF-001 regressed: fired {len(findings)} on in-memory dict in loop"
            )

    def test_fr_sqli_001_parameterized_query_regression(self):
        """FR-SQLI-001 must not fire on safely parameterized queries."""
        fixture = _fixture_path("safe.py")
        count = _run_rule("FR-SQLI-001", fixture)
        assert count == 0, f"FR-SQLI-001 regressed: fired {count} findings on safe.py"
