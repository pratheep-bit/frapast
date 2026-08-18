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

A complete rule addition requires the following:

### 1. Add the detector function to `scanner/rules/engine.py`

Follow the naming convention `fr_<category>_<number>` and the existing function
signature:

```python
def fr_perm_007(
    schema: SchemaIndex,
    hooks: HookIndex,
    python: PythonSymbolIndex,
    graph: CallGraph,
) -> list[Candidate]:
    """FR-PERM-007: Brief one-line description.

    Detailed explanation of what this rule detects, why it is a vulnerability,
    and any known false-positive patterns.
    """
    ...
```

### 2. Register the rule in `ALL_RULES`

Add your function to the `ALL_RULES` tuple at the bottom of `scanner/rules/engine.py`.

### 3. Add a rule YAML file (`scanner/rules/FR-PERM-007.yaml`)

```yaml
taxonomy_id: FR-PERM-007
rule_version: "1.0.0"
severity: high
title: "Short human-readable title"
description: |
  What this rule detects and why it matters for Frappe applications.
references:
  - https://frappeframework.com/docs/user/en/api/... (if applicable)
```

### 4. Add a taxonomy YAML file (`scanner/taxonomy/FR-PERM-007.yaml`)

```yaml
id: FR-PERM-007
runtime_required: true
detector_status: implemented
category: permission
title: "Short title"
description: |
  Stable taxonomy definition.
references: []
```

### 5. Register in `scanner/taxonomy/taxonomy_registry.yaml`

Add the new ID under the `implemented` section.

### 6. Write unit tests

**Mandatory minimum**:

- One test that feeds code triggering the rule and asserts a non-empty finding list.
- One test that feeds the safe equivalent and asserts an empty finding list.

Add these to `tests/test_all_rules.py` or a dedicated `tests/test_fr_perm_007.py`.

### 7. Add precision bounds

Add an entry to `RULE_BOUNDS` in `tests/test_precision_benchmark.py` with the
expected finding count range on the fixture corpus.

### 8. Verify everything passes

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
