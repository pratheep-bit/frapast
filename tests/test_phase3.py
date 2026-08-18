from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index, discover_hooks_files
from scanner.python import build_python_index, discover_python_files
from scanner.rules import execute_rules
from scanner.schema import build_schema_index, discover_doctype_json

ROOT = Path(__file__).resolve().parents[1]

def test_phase3_rules_detect_new_patterns():
    # Setup standard context with employee fixture and the new python fixture
    schema = build_schema_index(
        discover_doctype_json(ROOT / "tests" / "schema" / "fixtures" / "employee")
    )
    hooks = build_hook_index(discover_hooks_files(ROOT / "tests" / "hooks" / "fixtures"))
    python = build_python_index(discover_python_files(ROOT / "tests" / "python" / "fixtures"))

    # We should detect patterns in phase3_patterns.py
    graph = build_call_graph(python)
    candidates = execute_rules(schema, hooks, python, graph)

    by_rule = {candidate.rule_id: candidate for candidate in candidates if "phase3_patterns.py" in candidate.file}

    # Assert specific rules fired on the new patterns
    assert "FR-INJ-001" in by_rule, "Should detect mass_assign via get_doc(kwargs)"
    assert "FR-INJ-002" in by_rule, "Should detect dangerous_eval"
    assert "FR-HOOK-004" in by_rule, "Should detect enqueue_without_job_id"
    assert "FR-SQLI-004" in by_rule, "Should detect query_builder_dynamic"
    assert "FR-WKFL-003" in by_rule, "Should detect sync_status_without_docstatus"
    assert "FR-HOOK-001" in by_rule, "Should detect BrokenLifecycle asymmetric on_submit"
