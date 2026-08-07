<div align="center">

# Sentinel-FR — Runtime-Proven Static Analysis for Frappe & ERPNext

**A static-analysis security scanner purpose-built for the Frappe framework, with a mandatory runtime-proof pipeline that turns raw candidates into verified, exploitable findings — not noise.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Proprietary-lightgrey.svg)](#license)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)
[![Frappe](https://img.shields.io/badge/framework-Frappe%20%2F%20ERPNext-orange.svg)](https://frappeframework.com/)

</div>

---

## Why Sentinel-FR exists

Generic SAST tools treat Frappe apps like any other Python codebase — they don't understand `frappe.whitelist()`, doc_events hooks, docstatus state machines, or the ORM/raw-SQL boundary that defines where Frappe's permission layer actually applies. That mismatch produces two failure modes: **floods of false positives** on framework idioms that are actually safe, and **silent misses** on framework-specific bypass patterns (`ignore_permissions=True`, `frappe.db.set_value` skipping `validate()`, hook-dispatch reachability, etc.).

Sentinel-FR is built from the ground up around Frappe's actual execution model. It parses DocType JSON schemas, `hooks.py` registrations, and Python source into three cooperating indexes, builds a call graph that understands Frappe-specific dispatch patterns (string dispatch via `frappe.call()`, hook dispatch, dynamic method calls), and runs a taxonomy of rules against that graph — every rule backed by a **proof recipe**, not just a pattern match.

Critically: **a static match is never treated as a finding.** Every candidate is a Tier 0, internal-only signal until it clears a runtime proof gate against a real, containerized Frappe bench. Nothing reaches fix synthesis or PR automation without first passing Tier 2+ proof.

---

## Table of Contents

- [Core Design Principles](#core-design-principles)
- [Architecture](#architecture)
- [Vulnerability Taxonomy](#vulnerability-taxonomy)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [The Runtime Proof Pipeline](#the-runtime-proof-pipeline)
- [Automated Fix Synthesis](#automated-fix-synthesis)
- [False-Positive Management & Precision Tracking](#false-positive-management--precision-tracking)
- [Multi-Repo Scanning](#multi-repo-scanning)
- [Ledger & Data Integrity](#ledger--data-integrity)
- [Testing](#testing)
- [Benchmarking Against Known CVEs](#benchmarking-against-known-cves)
- [Project Layout](#project-layout)
- [Contributing](#contributing)
- [License](#license)

---

## Core Design Principles

| Principle | What it means in practice |
|---|---|
| **Static candidates are not claims** | Every finding starts life at `status: candidate`, `proof_tier: 0`. It is explicitly labeled internal-only until proven. |
| **Proof is mandatory, not optional** | Fix synthesis and PR creation are hard-gated behind Tier 2+ proof (`_load_proven_findings`). There is no CLI flag that bypasses this. |
| **Fail closed, not open** | Ambiguous permission inference, unresolved dotted-path dispatch, and dynamic SQL identifiers all abstain rather than guess. See `assert_safe_identifier` and the various fixer abstention paths. |
| **Atomic, corruption-safe ledger writes** | Every ledger mutation goes through a temp-file + `os.replace()` pattern with an advisory directory lock — a crash mid-write can never corrupt `findings/*.yaml`. |
| **Traceable proof provenance** | Every reproducer script declares an explicit `# PROOF_MODE:` marker (`direct_call` or `http_rpc`). Proof tier is *never* inferred by keyword-sniffing a script's contents — a CI gate (`validate_reproducer_markers.py`) enforces this. |
| **Precision is measured, not assumed** | Per-rule, per-version precision (`proven / (proven + false_positive)`) is tracked continuously so a regressed rule is visible immediately, not discovered months later. |

---

## Architecture

Sentinel-FR is organized as a pipeline of independent, composable indexes feeding a rule engine:

```
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  Schema Index    │   │   Hook Index     │   │  Python Index   │
│  (DocType JSON)  │   │  (hooks.py AST)  │   │  (source AST)   │
└────────┬─────────┘   └────────┬─────────┘   └────────┬────────┘
         │                      │                       │
         └──────────────────────┴───────────────────────┘
                                 │
                        ┌────────▼─────────┐
                        │   Call Graph      │
                        │  (4 edge kinds)   │
                        └────────┬──────────┘
                                 │
                        ┌────────▼─────────┐
                        │   Rule Engine      │
                        │  (29 taxonomy      │
                        │   rules)           │
                        └────────┬──────────┘
                                 │
                        ┌────────▼──────────┐
                        │  Severity Scoring  │
                        │  (5-dimension      │
                        │   composite)       │
                        └────────┬──────────┘
                                 │
                        ┌────────▼──────────┐
                        │  Findings Ledger   │
                        │  (atomic YAML)     │
                        └────────┬──────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
     ┌────────────────┐ ┌────────────────┐ ┌─────────────────┐
     │ Proof           │ │ Fix Synthesis  │ │  Reporting &     │
     │ Orchestrator    │ │ (libcst)       │ │  Precision       │
     │ (Tier 1/2)      │ │  → PR Engine   │ │  Tracking        │
     └────────────────┘ └────────────────┘ └─────────────────┘
```

### Index layer

- **Schema Index** (`scanner/schema/`) — Parses DocType JSON definitions into a queryable model: submittable doctypes, owner-scoped (`if_owner`) doctypes, child-table relationships, and field definitions. Fails loudly (`SchemaParseError`) on malformed JSON or missing required keys — it never silently skips a doctype.
- **Hook Index** (`scanner/hooks/`) — Parses `hooks.py` via `ast.literal_eval`, extracting `doc_events`, `permission_query_conditions`, and `has_permission` registrations. Detects cross-app hook collisions on the same `(doctype, event)` pair.
- **Python Index** (`scanner/python/`) — A single-pass AST visitor that extracts 20+ record types per function: SQL calls (with parameterization/dynamism/request-taint tracking), `ignore_permissions` usage, permission checks, `frappe.enqueue` dedup keys, mass-assignment patterns, eval/exec calls, dynamic query-builder identifiers, and more.

### Call Graph

The call graph (`scanner/callgraph/`) resolves four distinct dispatch mechanisms, because Frappe code rarely calls functions directly:

| Edge kind | Pattern | Confidence |
|---|---|---|
| `DIRECT_CALL` | `foo()` / `module.foo()` | 1.0 |
| `STRING_DISPATCH` | `frappe.call("a.b.c.func")` / `frappe.enqueue("a.b.c.func")` | 0.9 |
| `HOOK_DISPATCH` | `hooks.py` string-path handler invoked by the framework | 0.85 |
| `DYNAMIC_METHOD` | `frappe.get_doc(...).method_name()` (best-effort) | 0.4 |

Lookups are pre-indexed (qualified name, method name, module suffix) rather than re-scanned per call site, keeping reachability analysis linear instead of quadratic across the codebase. The `CallGraph` object also exposes a thread-safe `get_or_compute` cache so repeated reachability queries across rules never redo the same BFS.

### Rule Engine

29 rules across 11 taxonomy families, each rule a pure function of `(schema, hooks, python, call_graph) -> list[Candidate]`. Every emitted `Candidate` carries a `proof_recipe` — a human-readable description of exactly what to do at runtime to confirm or refute the finding.

---

## Vulnerability Taxonomy

| Family | Focus | Example rules |
|---|---|---|
| **FR-SQLI** | ORM vs. raw-SQL boundary | Unparameterized dynamic SQL, missing `docstatus` filters, `set_value` bypassing hooks, dynamic `frappe.qb` identifiers |
| **FR-PERM** | Permission & access control | Missing checks on whitelisted endpoints, unguarded `ignore_permissions=True`, `if_owner` bypass via raw writes, Script Report permission-query gaps |
| **FR-HOOK** | Hook execution & lifecycle | Asymmetric `on_submit`/`on_cancel`, cross-app hook collisions, API fast-path validation bypass, `enqueue()` without dedup keys, `commit()` inside lifecycle hooks |
| **FR-WKFL** | Docstatus / workflow state machine | Missing docstatus guards on mutation, direct `workflow_state` writes bypassing the workflow engine, `status`/`docstatus` desync, amendment-chain leakage |
| **FR-INJ** | API / injection surfaces | Mass assignment via unfiltered kwargs, `eval`/`exec` with request-controlled input, unescaped user input in `msgprint`/`throw` |
| **FR-CSRF** | Cross-site request forgery | Guest-accessible, state-changing endpoints without CSRF protection |
| **FR-SSRF** | Server-side request forgery | User-controlled outbound request URLs with no allowlist |
| **FR-HOOK-006/007** | Correctness (bare `except`, mutable default args) | Scored separately from security findings via a dedicated correctness rubric |
| **FR-DATA** | Data integrity | Field references that don't resolve against the target DocType's schema |
| **FR-PERF** | Performance anti-patterns | N+1 query patterns (`get_doc()` per iteration over a `get_all()` result) |
| **FR-I18N** | Internationalization | User-facing strings not wrapped in `frappe._()` |

Every rule's `rule_id` and `taxonomy_id` are validated against `taxonomy_registry.yaml` in CI (`validate_taxonomy.py`) — a rule can never silently drift from its documented category, and unresolved placeholder categories fail loudly rather than passing silently.

---

## Installation

### Install from GitHub (recommended)

```bash
pip install git+https://github.com/pratheep-bit/frappe-security-engine.git
```

### Install from a local clone (for development)

```bash
git clone https://github.com/pratheep-bit/frappe-security-engine.git
cd frappe-security-engine
pip install -e .
```

---

## Quick Start

Once installed, the `frappe-security-scan` command is available on your PATH:

```bash
# Check version
frappe-security-scan --version

# Scan a single Frappe app, print candidates as YAML
frappe-security-scan scan /path/to/frappe-app

# Scan with severity scoring and JSON output
frappe-security-scan scan /path/to/frappe-app --severity --format json

# Scan and persist findings to the ledger
frappe-security-scan scan /path/to/frappe-app --write-ledger --repo-id my-app

# Scan multiple repos from a config file
frappe-security-scan scan --config scan_config.yaml
```

Example `scan_config.yaml`:

```yaml
findings_dir: findings
fp_log: findings/fp-log.yaml
repos:
  - id: erpnext
    path: /repos/erpnext
    enabled: true
  - id: hrms
    path: /repos/hrms
    enabled: true
```

---

## CLI Reference

```
frappe-security-scan {scan,prove,report,fp-report,fix,pr}
```

| Command | Purpose |
|---|---|
| `scan` | Run static analysis against one or more repos; optionally write to the findings ledger |
| `prove` | Execute runtime proof reproducers (Tier 1/Tier 2) against a live bench, updating the ledger |
| `report` | Render a full track-record report: status breakdown, per-rule precision, coverage, severity distribution, upstream history |
| `fp-report` | Print false-positive rates per `(rule_id, rule_version)`, flagging rules that need logic review |
| `fix` | Synthesize + statically validate fixes for Tier 2+ proven findings, writing preview files |
| `pr` | Synthesize, validate, and open draft PRs for proven findings (dry-run by default; `--live` to actually push) |

<details>
<summary><strong>Full flag reference</strong></summary>

```
scan  [repo_path] [--config PATH] [--write-ledger] [--ledger-dir DIR]
      [--repo-id ID] [--fp-log PATH] [--severity] [--format {yaml,json}]

prove [--finding-id ID] [--dry-run] [--workspace DIR]

report [--findings-dir DIR]

fp-report [--findings-dir DIR]

fix   repo_path [--finding-file PATH]

pr    repo_path [--live] [--max-prs N]
```

</details>

---

## The Runtime Proof Pipeline

Static analysis alone is treated as **Tier 0** evidence — internal-only, not an external claim. The proof orchestrator (`scanner/proof/orchestrator.py`) escalates candidates through two verified tiers against a real, containerized Frappe bench:

| Tier | Mode | What it proves |
|---|---|---|
| 0 | — | Static pattern match only. Never externally reported. |
| 1 | `direct_call` | Reproducer executes in-process against the code (e.g. AST-verifies a mutable-default pattern actually exists) |
| 2 | `http_rpc` | Reproducer authenticates as a **low-privilege user** and invokes the flagged endpoint over real HTTP — the strongest form of proof this scanner produces |

**Proof mode is never inferred from a script's contents.** Every reproducer must declare its mode on the first line:

```bash
# PROOF_MODE: http_rpc
```

This is enforced two ways:
1. `synthesize_reproducer_if_missing` / `synthesize_http_rpc_reproducer` always write the marker explicitly at generation time.
2. `scanner/proof/validate_reproducer_markers.py` is a CI gate — any reproducer missing the marker fails the build.

A one-time migration script (`retrofit_reproducer_markers.py`) exists for legacy reproducers predating this convention, and it **explicitly flags every retrofitted guess as requiring manual verification** rather than silently promoting it to a trusted marker.

```bash
# Prove all unproven candidates
python -m scanner.cli prove --workspace .

# Prove a specific finding
python -m scanner.cli prove --finding-id FR-PERM-001-a1b2c3d4

# Preview what would run without touching the ledger
python -m scanner.cli prove --dry-run
```

Every proof result is written back through a single, hardened path (`update_ledger_after_proof`) that **appends** to `status_history` rather than overwriting — the full audit trail of every status transition is preserved.

---

## Automated Fix Synthesis

For rules with `fix_confidence` of `high` or `medium`, Sentinel-FR can synthesize a mechanical, AST-level fix using `libcst`:

| Rule | Fixer | Strategy |
|---|---|---|
| `FR-HOOK-007` | `MutableDefaultArgFixer` | Rewrites mutable default args to the `None` + in-body-init idiom |
| `FR-I18N-001` | `HardcodedStringI18nFixer` | Wraps hardcoded user-facing strings in `frappe._()` |
| `FR-PERM-001` | `PermissionCheckGuardFixer` | Infers the target DocType and access pattern (single-record vs. list) via AST analysis; abstains on ambiguity, self-scoped lookups, or `allow_guest` endpoints |
| `FR-HOOK-004` | `EnqueueDedupeKeyFixer` | Derives a deterministic `job_id` from the enqueued target |
| `FR-WKFL-001` | `WkflDocstatusGuardFixer` | Injects a `docstatus != 1` guard at the top of the method |
| `FR-SQLI-002` | `SqlDocstatusFilterFixer` | Splices a `docstatus` predicate into the raw SQL's `WHERE` clause |
| `FR-SQLI-003` | `DbSetValueHooksFixer` | Rewrites `frappe.db.set_value` into the `get_doc().save()` idiom to restore validation hooks |

Rules like `FR-PERM-002` and `FR-SQLI-004` **deliberately abstain** from automated fixing — the correct fix requires human-supplied context (a resolved doctype expression, or an allow-list of legitimate SQL identifiers) that cannot be safely inferred from the AST alone. `scanner/fix/security.py`'s `assert_safe_identifier` helper fails closed by design: an empty allow-list raises on every call until a developer fills it in.

Every synthesized fix passes through a static validation gate (`scanner/validate/engine.py`) before being staged — syntax check, byte-compilation, and a "didn't collapse to near-nothing" sanity check — **before** it's ever eligible for a PR.

```bash
# Preview fixes without opening PRs
python -m scanner.cli fix /path/to/repo

# Dry-run PR creation (default — shows diffs, creates nothing)
python -m scanner.cli pr /path/to/repo

# Actually open draft PRs (max 5 per run by default)
python -m scanner.cli pr /path/to/repo --live --max-prs 3
```

The PR engine checks for existing open/closed/merged PRs or issues referencing the same `code_location_hash` before creating a duplicate, and **fails closed** (treats state as "duplicate exists") if the `gh` CLI call itself fails — it never proceeds as if the check passed clean.

---

## False-Positive Management & Precision Tracking

False positives are tracked in `findings/fp-log.yaml` and suppressed by **exact identity match** — `(rule_id, rule_version, repo, file, function, code_location_hash)`. Bumping a rule's version deliberately un-suppresses previously-logged false positives so a rule fix can be re-validated against the cases that originally broke it.

```bash
python -m scanner.cli fp-report --findings-dir findings
```

```
Rule@Version              Attempts  FP Rate   Flag
FR-SQLI-004@1.0.0         12        0.58      ⚠️  REVIEW RULE LOGIC
FR-PERM-001@1.0.0         34        0.12
FR-PERM-002@1.1.0         9         0.00
```

Rules with ≥5 attempts and >50% false-positive rate are automatically flagged for logic review — precision regressions surface immediately instead of being discovered months later in a track-record report.

---

## Multi-Repo Scanning

Sentinel-FR is designed to run continuously across a fleet of Frappe apps (core `frappe`, `erpnext`, `hrms`, and custom apps) from a single config file, sharing one false-positive log and one findings ledger, with per-repo identity namespacing so findings never collide across repos.

```bash
python -m scanner.cli scan --config scan_config.yaml --format json > results.json
```

---

## Ledger & Data Integrity

Every finding lives as an individual YAML file under `findings/`, validated against a strict schema (`scanner/ledger_schema.py`) — required fields, valid `status` enum, `proof_tier` range, and a hard rule that any `proven` finding must carry a `proven` date.

Three independent CI gates protect the ledger's integrity:

| Gate | Script | Checks |
|---|---|---|
| Schema validity | `validate_ledger.py` | Every finding has required fields, valid status/tier values |
| Taxonomy consistency | `validate_taxonomy.py` | Every emitted `rule_id`/`taxonomy_id` is registered; warns loudly on unresolved placeholder categories |
| Proof integrity | `verify_ledger_integrity.py` | Any finding claiming `proof_tier >= 1` has a `reproducer_hash` matching the **current** content of its reproducer file — a changed reproducer since the proof ran means the claim is stale and must be flagged |

All writes go through `write_ledger_entry` (atomic temp-file + `os.replace()`) and `ledger_lock` (advisory directory lock with staleness timeout) — concurrent scanner runs can never silently clobber each other's `status_history`.

---

## Testing

```bash
python -m unittest discover -s tests -p "test_*.py" -v
python -m unittest discover -s scanner/tests -p "test_*.py" -v
```

The test suite spans:
- **Phase 0–3 acceptance tests** (`tests/test_phase0.py`–`test_phase3.py`) covering environment setup, index engines, rule execution, and false-positive suppression semantics
- **Hardening regression suites** (`scanner/tests/test_hardening.py`, `test_hardening_v2.py`) — each test pinned to a specific fixed bug (frozen-dataclass mutation, ledger corruption handling, permission-guard false-positive precision, thread-safe call-graph caching, reproducer marker validation)
- **Call-graph dispatch tests** (`tests/test_callgraph_dispatch.py`) verifying string-dispatch, dynamic-method, and hook-dispatch reachability edges resolve correctly

---

## Benchmarking Against Known CVEs

```bash
python benchmark/run_benchmark.py
```

Clones each tracked repo at its known-vulnerable tag and confirms the scanner's static candidates actually fire for the mapped rule — a necessary but not sufficient signal, since full proof still requires the runtime bench per CVE.

```bash
python benchmark/bugfix_benchmark.py <fix-commit-sha> <rule-id> --repo /path/to/repo
```

Verifies a specific rule fires on the pre-fix commit and goes silent on the post-fix commit — the gold-standard regression check for rule logic.

---

## Project Layout

```
scanner/
├── schema/          # DocType JSON index
├── hooks/           # hooks.py index
├── python/          # Python AST index (20+ record types)
├── callgraph/        # 4-edge-kind call graph builder
├── rules/           # 29 taxonomy rules
├── severity/         # 5-dimension composite severity scoring
├── proof/           # Tier 1/2 runtime proof orchestration
├── fix/             # libcst-based automated fix synthesis
├── validate/         # Static safety gate for synthesized fixes
├── pr/               # PR routing, creation, duplicate detection
├── fp/               # False-positive suppression & precision metrics
├── reporting/         # Track-record report rendering
├── regression/        # Auto-generated regression tests from proven findings
├── ledger_io.py      # Atomic, corruption-safe ledger read/write
├── ledger_schema.py   # Ledger entry schema validation
├── validate_ledger.py         # CI gate: schema
├── validate_taxonomy.py       # CI gate: taxonomy drift
├── verify_ledger_integrity.py # CI gate: proof provenance
└── cli.py            # scan / prove / report / fp-report / fix / pr

tests/                # Cross-cutting acceptance & phase tests
benchmark/             # CVE regression benchmarking
findings/              # The ledger (generated)
runtime/               # Reproducers, proofs, artifacts (generated)
```

---

## Contributing

1. New rules go in `scanner/rules/engine.py` and **must** be registered in `taxonomy_registry.yaml` — `validate_taxonomy.py` will fail CI otherwise.
2. Every new rule needs a `proof_recipe` describing exactly how to verify it at runtime — rules without a credible proof path don't get merged.
3. Run the full hardening regression suite before submitting; if you're touching `ledger_io.py`, `callgraph/models.py`, or `proof/orchestrator.py`, add a test to `scanner/tests/test_hardening_v2.py` in the same style as existing entries.
4. Fix synthesizers must abstain (return `patched = False`) rather than guess on any ambiguous case — see `PermissionCheckGuardFixer`'s self-scoped/allow_guest abstention logic as the reference pattern.

---

## License

Proprietary. All rights reserved.

</div>
