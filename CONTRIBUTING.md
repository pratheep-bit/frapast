# Contributing to Frappe Security Scanner

Thank you for contributing to the Frappe Security Scanner! This guide provides step-by-step instructions for adding rules, updating taxonomy, running tests, and developing the engine.

---

## 🚀 Quick Development Setup

```bash
# Set PYTHONPATH to scanner root
export PYTHONPATH=.

# Run test suite
python -m pytest tests/ -v
python -m pytest scanner/tests/ -v
```

---

## 🛠️ Step-by-Step: Adding a New Detector Rule

To add a new static analysis rule (e.g. `FR-PERM-007`):

1. **Implement Rule Logic**:
   - Add detector function in `scanner/rules/engine.py`.
   - Function signature must match `(schema: SchemaIndex, hooks: HookIndex, python: PythonSymbolIndex, call_graph: CallGraph) -> list[Candidate]`.
   - Use `_candidate(...)` helper to instantiate `Candidate` objects.
   - Register the function in `ALL_RULES` tuple in `scanner/rules/engine.py`.

2. **Add Rule & Taxonomy Metadata**:
   - Create descriptor file `scanner/rules/FR-PERM-007.yaml`.
   - Create taxonomy definition `taxonomy/FR-PERM-007.yaml`.
   - Update `scanner/taxonomy_registry.yaml` under the appropriate scope (`core_scope`, `documented_undetected`, or `additional_categories`).

3. **Severity Mapping**:
   - Update `RULE_IMPACT_MAP` and `RULE_BLAST_RADIUS_OVERRIDES` in `scanner/severity/engine.py`.

4. **Unit Testing**:
   - Add unit test coverage in `tests/test_phase3.py` or a dedicated test file.
   - Verify pattern detection and ensure zero false positives on safe code fixtures.

---

## 🔬 Testing & Verification Rules

- **Unit Tests**: Always run `python -m pytest tests/` and `python -m pytest scanner/tests/` before committing.
- **Ledger & Taxonomy Validation**:
  - Run `python scanner/validate_taxonomy.py` to ensure rules match the taxonomy registry.
  - Run `python scanner/validate_ledger.py` to check ledger entry schema compliance.
  - Run `python scanner/verify_ledger_integrity.py` to verify reproducer hashes.

---

## 🔒 Code Guidelines

- **Immutability**: `Candidate` dataclass instances are frozen. Never attempt in-place mutations; use `Candidate.with_status()` or `dataclasses.replace()`.
- **Directory Discovery**: Use `scanner.ledger_io.discover_all_findings_dirs()` for finding directory traversals.
- **Proof-Gated Automation**: Fix synthesis and PR creation are strictly gated on Tier 2+ runtime proofs.
