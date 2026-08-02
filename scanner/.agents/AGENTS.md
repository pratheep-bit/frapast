# Scanner Engine Agent Behavioral Rules & Architectural Constraints

## 1. Core Architecture & Execution Pipeline
- **Orchestration**: `scanner/cli.py` is the central CLI entrypoint.
- **Rule Execution Engine**: `scanner/rules/engine.py` executes all rules in `ALL_RULES`.
- **AST & Symbol Indexing**: `scanner/python/engine.py`, `scanner/schema/engine.py`, and `scanner/hooks/engine.py` build immutable indexes per scan.
- **CallGraph**: `scanner/callgraph/builder.py` constructs call graphs for reachability checks across RPC endpoints, string dispatches (`frappe.call`), and hook handlers (`hooks.py`).

## 2. Mandatory Rules & Constraints
- **Frozen Dataclasses**: `Candidate` and other record dataclasses are frozen. Use `dataclasses.replace` or `Candidate.with_status()` to create modified instances. NEVER attempt in-place mutation.
- **Multi-Directory Findings Discovery**: ALWAYS use `scanner.ledger_io.discover_all_findings_dirs()` when scanning or validating finding directories to avoid missing legacy or sibling directories (`findings_latest_*`).
- **Cache Management**: Call `scanner.rules.clear_rule_caches()` if running multiple scans sequentially in long-running processes to clear `_REACHABLE_CACHE` and `_ENDPOINT_REACHABLE_CACHE`.
- **Proof-Gated Fix Synthesis**: Tier 2+ runtime proof (`proof_tier >= 2`) is a hard gate for fix synthesis or PR creation. Never attempt to automate PR creation for unproven or Tier 0/1 findings.
- **Taxonomy Propagation**: When modifying rule IDs or taxonomy classifications, ensure synchronized updates across `rules/engine.py`, `rules/FR-*.yaml`, `taxonomy/FR-*.yaml`, `taxonomy_registry.yaml`, and severity maps.

## 3. Verification & Testing Requirements
- Every new rule or engine modification MUST be accompanied by unit tests in `tests/` or `scanner/tests/`.
- Ensure `python -m pytest tests/` passes cleanly before requesting review or committing code.
