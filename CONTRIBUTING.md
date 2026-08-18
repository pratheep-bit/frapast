# Contributing to frapAST

This document covers how to set up a local development environment, run the test suite,
add a new rule, and what a pull request must include before it can be merged.

---

## Development Environment Setup

### Prerequisites

- Python 3.10 or higher
- Git

### Install for Development

```bash
git clone https://github.com/pratheep-bit/frapast.git
cd frapast
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

This installs frapAST in editable mode with all test and lint dependencies.

### Run the Test Suite

```bash
pytest
```

All 200+ tests should pass. This is the minimum bar for any contribution.

### Run the Linter

```bash
ruff check .
```

No lint errors are acceptable in a PR. Fix all issues before opening a PR.

---

## Project Layout

```
scanner/
  cli.py             — CLI entrypoint
  rules/engine.py    — All rule detectors (ALL_RULES tuple)
  rules/*.yaml       — Per-rule metadata (severity, description, references)
  taxonomy/          — Canonical taxonomy definitions
  python/engine.py   — AST and symbol indexer
  schema/engine.py   — DocType JSON schema indexer
  hooks/engine.py    — hooks.py parser
  callgraph/         — Call graph builder for endpoint reachability
  proof/             — Tier 2 runtime HTTP proof synthesis
  suppression.py     — Inline suppression, baseline, and config loader
  web/               — Local web dashboard server
tests/
  test_all_rules.py              — Core rule regression tests
  test_precision_benchmark.py    — Precision bounds per rule
  test_security_hardening_regression.py — Security regression tests
  test_suppression.py            — Suppression engine tests
```

---

## Adding a New Rule

frapAST enforces strict precision and root-cause engineering standards. A rule is not considered "done" because a basic AST check passes; it must be proven safe against false positives and validated across real Frappe/ERPNext application trees.

A complete rule addition requires following the steps below:

### 1. Root-Cause Diagnosis and AST Visitor Mechanics

When designing a detector function in `scanner/rules/engine.py`:

- **Distinguish Method Invocations from Attribute Reads**: If detecting an unvalidated field access or method call, ensure your AST visitor distinguishes `visit_Call` from `visit_Attribute`. Never confuse `doc.fieldname` with `doc.method_name()`.
- **Fail-Closed Schema Resolution**: When querying DocType schemas via `SchemaIndex`, only assert missing fields if the DocType definition was resolved with 100% confidence. If schema resolution is ambiguous, do not emit spurious findings.
- **Respect Reserved Framework Attributes**: Always check against `_RESERVED_DOC_ATTRS` and standard `BaseDocument`/`Document` methods before flagging attribute accesses.
- **Function Signature**: Follow the standard detector signature:

```python
def fr_perm_007(
    schema: SchemaIndex,
    hooks: HookIndex,
    python: PythonSymbolIndex,
    graph: CallGraph,
) -> list[Candidate]:
    """FR-PERM-007: Short descriptive title.

    Detailed root-cause explanation:
    - Vulnerability class and mechanism.
    - Conditions under which this triggers.
    - Known false-positive edge cases and how they are handled.
    """
    ...
```

### 2. Register the Rule in `ALL_RULES`

Add your detector function to the `ALL_RULES` tuple at the bottom of `scanner/rules/engine.py`.

### 3. Add Rule and Taxonomy YAML Metadata

1. **Rule Descriptor (`scanner/rules/FR-PERM-007.yaml`)**:
   ```yaml
   taxonomy_id: FR-PERM-007
   rule_version: "1.0.0"
   severity: high
   title: "Missing Permission Check on Sensitive DocType Method"
   description: |
     Detailed explanation of what the detector checks and the remediation guidance.
   references:
     - https://frappeframework.com/docs/user/en/api/document
   ```

2. **Taxonomy Descriptor (`scanner/taxonomy/FR-PERM-007.yaml`)**:
   ```yaml
   id: FR-PERM-007
   runtime_required: true
   detector_status: implemented
   category: permission
   title: "Missing Permission Check"
   description: |
     Canonical taxonomy entry for this rule class.
   references: []
   ```

3. **Registry Registration**: Add the rule ID under the `implemented` list in `scanner/taxonomy/taxonomy_registry.yaml`.

### 4. Mandatory Dual Unit Test Suite (TP & TN Fixtures)

Every rule **must** have both positive and negative unit tests in `tests/test_ast_rule_coverage.py` or a dedicated test module:

- **True-Positive (TP) Test**: Asserts that vulnerable code patterns produce exact candidates with accurate line numbers, rule IDs, and evidence strings.
- **True-Negative (TN) Test**: Asserts that safe, idiomatic Frappe patterns (e.g., proper permission checks, whitelisted endpoints with guards, doc.save() with validation) produce **zero** findings.

### 5. Real-World Application Revalidation

Before submitting a PR, test your new rule against real open-source Frappe applications (e.g. `frappe/erpnext`, `frappe/hrms`):

```bash
# Example: Run scanner against a real Frappe app clone
frapast scan /path/to/cloned/erpnext --rule FR-PERM-007 --format json
```

Verify that all reported findings are legitimate true positives and that valid business logic is not falsely flagged.

### 6. Register Precision Benchmark Bounds

Add or update the expected finding count range in `RULE_BOUNDS` in `tests/test_precision_benchmark.py`. This ensures automated CI regression gates prevent precision drift across releases:

```python
RULE_BOUNDS = {
    ...
    "FR-PERM-007": (1, 3),  # (min_expected, max_expected) on standard benchmark corpus
}
```

### 7. Tier 1 / Tier 2 Runtime Proof Integration (If Applicable)

If the vulnerability class can be proven at runtime:
- **Tier 1**: Implement shell/bash reproducer generation in `scanner/proof/orchestrator.py`.
- **Tier 2**: Implement HTTP RPC proof synthesis in `scanner/proof/http_synthesis.py` and `scanner/proof/bench_runner.py`.
- **Security Invariant**: Always sanitize synthesized strings with `_reject_if_newline()` to eliminate reproducer script injection risks.

### 8. Full Local Verification

Run the entire verification suite locally:

```bash
pytest
ruff check .
python scanner/validate_taxonomy.py
```

---

## Suppression and Baseline

To suppress a specific finding inline:

```python
frappe.db.sql(query)  # frapast: ignore FR-SQLI-001
```

To suppress all rules on a line:

```python
frappe.db.sql(query)  # frapast: ignore
```

To generate a baseline of existing findings (for legacy codebases):

```bash
frapast scan ./myapp --generate-baseline .frapast-baseline.json
```

To run future scans reporting only new findings:

```bash
frapast scan ./myapp --baseline .frapast-baseline.json
```

---

## Integration & GitHub Action Testing

The repository [`pratheep-bit/frapast-action-test`](https://github.com/pratheep-bit/frapast-action-test) is maintained as a permanent, public smoke-test fixture to verify end-to-end composite action workflows (`action.yml`), SARIF generation, and Code Scanning alert ingestion against live GitHub infrastructure.

---

## Privacy and Confidentiality

All contributions must comply with [AGENTS.md](AGENTS.md):

- Do not reference private company names, client identities, or proprietary
  infrastructure in code, comments, or commit messages.
- Use only open-source repositories (frappe/erpnext, frappe/hrms) as corpus references.
- Do not mention proprietary commercial products by name in documentation.

---

## Pull Request Requirements

See [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) for the full
checklist. The short version:

1. `pytest` passes with zero failures.
2. `ruff check .` reports no errors.
3. New rules have both positive and negative unit tests.
4. No private corporate identities are referenced.

---

## Reporting Security Issues

Do not open a public GitHub issue for security vulnerabilities in frapAST itself.
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
