<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="scanner/web/static/logo.svg">
  <img src="scanner/web/static/logo-light.svg" alt="frapAST Logo" width="96" height="96">
</picture>

# frapAST

### Runtime-Proven Static Security and Performance Engine for Frappe and ERPNext

[![PyPI version](https://img.shields.io/badge/pypi-v0.1.0-blue.svg)](https://pypi.org/project/frapast/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-287%20passed-green.svg)](#test-suite-and-quality-assurance)
[![Rules](https://img.shields.io/badge/detectors-28%20active-blue.svg)](#rule-taxonomy)
[![Benchmark Speed](https://img.shields.io/badge/speed-16%2C700%2B%20files%2Fsec-green.svg)](#industry-benchmarks-and-performance)
[![Privacy](https://img.shields.io/badge/privacy-100%25%20Local%20and%20Airgapped-blue.svg)](#data-privacy-and-air-gapped-execution)

Find the vulnerability. Synthesize the reproducer. Prove it live. Ship the autofix.

[Quickstart](#quickstart) | [Industry Benchmarks](#industry-benchmarks-and-performance) | [Architecture Comparison](#architectural-comparison) | [Developer Experience](#developer-experience-dx) | [Rule Taxonomy](#rule-taxonomy) | [Engine Architecture](#how-it-works) | [Web Dashboard](#interactive-web-dashboard)

</div>

---

## Overview

Generic SAST tools analyze Frappe applications as generic Python scripts. Consequently, they fail to recognize that `@frappe.whitelist()` exposes a public HTTP endpoint, cannot resolve dynamic DocType schema permissions, miss string-literal dispatches such as `frappe.call("dotted.path")`, and generate significant false-positive noise.

frapAST is designed from the Frappe framework layer outward. It indexes DocType JSON schemas, parses `hooks.py`, walks module AST structures, and constructs an interprocedural static call graph modeling direct calls, string-based RPC dispatches, lifecycle hooks, dynamic document methods, and report execution entry points.

Candidate findings are scored across a multi-dimensional risk matrix and can be escalated through an Active Two-Tier Proof Engine that synthesizes standalone HTTP/RPC reproducers to verify exploitability against a running Frappe bench.

---

## Industry Benchmarks and Performance

Evaluated against open-source enterprise Frappe codebases on macOS (Apple Silicon) and Linux (x86_64) using Python 3.10 through 3.14:

### 1. Throughput and Scalability
| Target Repository | Total Files | Code Volume | Scan Time | Indexing Throughput | Active Candidates |
|---|:---:|:---:|:---:|:---:|:---:|
| Synthetic Scale Corpus | 5,000 files | ~250,000 LOC | 0.30s | 16,728 files/sec | 0 |
| Frappe HRMS (`hrms`) | 670 files | ~155,000 LOC | 0.95s | 705 files/sec | 150 |
| ERPNext Core (`erpnext`) | 3,842 files | ~980,000 LOC | 5.82s | 660 files/sec | 684 |

### 2. Empirical Detection Precision (Audited on Frappe HRMS)
| Rule Family | Detection Target | Verified TP | Audited Precision | Ground-Truth Outcome |
|---|---|:---:|:---:|---|
| `FR-PERM-001` | Mutating whitelisted RPC lacking permission checks | 19 / 19 | 100.0% | Identified unauthenticated write operations (mutating tier) |
| `FR-HOOK-001` | Controller `on_submit` without `on_cancel` | 6 / 7 | 85.7% | Identified uncancelled ledger and allocation records |
| `FR-HOOK-004` | Un-deduplicated `frappe.enqueue()` background jobs | 11 / 11 | 100.0% | Prevented duplicate background job queue storms |
| `FR-HOOK-006` | Bare `except:` statements swallowing framework signals | 3 / 3 | 100.0% | Prevented silent database transaction aborts in patches |
| `FR-DATA-001` | Non-existent DocType schema field access | 3 / 3 | 100.0% | Identified invalid field references in controllers |
| `FR-WKFL-003` | DocType `status` mutation without `docstatus` update | 4 / 4 | 100.0% | Identified state synchronization desyncs on submittables |
| `FR-INJ-001` | Single-dict parameter injection into `frappe.get_doc` | 5 / 5 | 100.0% | Identified mass-assignment risks in batch endpoints |
| `FR-PERF-001` | Database queries inside loops (N+1 query pattern) | 10 / 10 | 100.0% | Sampled batch loop database bottlenecks ($n=10$, seed=42) |
| `FR-PATH-001` | User-controlled file path traversal | Synthetic | Verified | Validated against synthetic `TALOS-2020-1091` reproductions |
| `FR-SQLI-001` | Script Report multi-hop dynamic SQL injection | Synthetic | Verified | Validated against synthetic `GHSA-745c-5q8r-vgj2` reproductions |

---

## Live-Bench Active Verification Case Study

frapAST includes live integration testing against local and staging Frappe benches. The Tier 2 proof engine generates and executes direct HTTP RPC reproducers to verify whether a static candidate is exploitable over the wire:

* **Unprotected RPC Endpoint (`frappe.client.get_time_zone`)**:
  ```text
  GET /api/method/frappe.client.get_time_zone HTTP/1.1 -> HTTP 200 OK
  {"message":{"time_zone":"Asia/Kolkata"}}
  [PROVEN]: Endpoint permits unauthenticated guest execution.
  ```

* **Protected RPC Endpoint (`frappe.auth.get_logged_user`)**:
  ```text
  GET /api/method/frappe.auth.get_logged_user HTTP/1.1 -> HTTP 403 Forbidden
  {"exc_type":"PermissionError","message":"You are not permitted to access this resource"}
  [REFUTED]: Endpoint enforces authentication guard.
  ```

---

## Architectural Comparison

| Capability | Generic SAST (Bandit / SonarQube) | Cloud Static Scanners | frapAST |
|---|:---:|:---:|:---:|
| Frappe Framework Modeling | None (generic Python only) | Partial regex matching | Full (DocType JSONs, `hooks.py`, ORM, DocEvents, Reports) |
| Active Proof Verification | None (static alerts only) | None (static alerts only) | Two-Tier Active Proof (synthesizes live HTTP reproducers) |
| Data Privacy and Sovereignty | Depends on deployment | Source code sent to third-party cloud | 100% Local and Air-Gapped (runs on localhost, zero data egress) |
| Automated Remediation | None | Manual refactoring | CLI AST Autofix (`frapast fix` with diff previews) |
| Native Bench Integration | None | None | Native `bench frapast` CLI command group |
| CI/CD Pipeline Support | Generic exit codes | Proprietary webhooks | OASIS SARIF 2.1.0 and Reusable GitHub Composite Action |
| Indexing Speed | 100-300 files/sec | Queue-dependent | 16,700+ files/sec (sub-second local execution) |

---

## Data Privacy and Air-Gapped Execution

frapAST is engineered with strict data confidentiality:

1. **Zero Data Egress**: All parsing, AST traversal, call graph generation, and proof execution run locally on `127.0.0.1`. No telemetry or source code is transmitted externally.
2. **Confidentiality by Design**: No company names, client data, or proprietary identifiers are stored or required. All references in reports adhere strictly to open-source repository paths.
3. **Local Origin Gating**: The web dashboard is bound exclusively to localhost and enforces origin headers against unauthorized cross-origin requests.

---

## Quickstart

### Installation

```bash
# Install via pip
pip install frapast

# Or install in editable mode for development
pip install -e .
```

### 1. Launch the Visual Dashboard
```bash
frapast
# Automatically starts local server and opens http://localhost:7777
```

### 2. Run a CLI Security and Performance Audit
```bash
# Perform static scan
frapast scan /path/to/frappe-app

# Perform scan with active bench verification
frapast scan /path/to/frappe-app --prove --bench-url http://localhost:8000

# Export SARIF 2.1.0 for GitHub Code Scanning
frapast scan /path/to/frappe-app --format sarif > results.sarif
```

### 3. Apply Automated Fixes via CLI
> **Note**: Automated code remediation is provided via the command-line interface (`frapast fix`) and the Python library. It is intentionally decoupled from the web dashboard REST API.

```bash
# Preview AST modifications as unified diffs (dry-run)
frapast fix /path/to/frappe-app

# Apply modifications directly to source files
frapast fix /path/to/frappe-app --apply
```

---

## Developer Experience (DX)

### 1. Native Frappe Bench CLI (`bench frapast`)
frapAST registers directly into Frappe's native `bench` CLI:

```bash
# Run security and performance audit on an app
bench frapast audit my_custom_app

# Apply automated security patches
bench frapast fix my_custom_app --apply

# Verify live HTTP exploitability on an active bench site
bench frapast prove my_custom_app --site dev.local

# Diagnose bench connectivity and port availability
bench frapast check --port 8000
```

### 2. Reusable GitHub Action
Add `.github/workflows/frapast.yml` to your repository for automated PR security checks and SARIF code scanning annotations:

```yaml
name: frapAST Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run frapAST Audit
        uses: pratheep-bit/frapast@main
        with:
          repo-path: '.'
          fail-on: 'critical'
          upload-sarif: 'true'
```

### 3. Automated Autofix Engine (`frapast fix`)
Automated AST patch generation handles routine security boilerplate:
- `FR-HOOK-001`: Automatically generates symmetrical `on_cancel(self)` methods for DocTypes implementing `on_submit`.
- `FR-HOOK-004`: Injects `deduplicate=True` into `frappe.enqueue()` calls.
- `FR-HOOK-006`: Replaces bare `except:` blocks with `except Exception:` to preserve framework execution signals.
- `FR-PERM-001`: Injects `frappe.only_for("System Manager")` permission checks into unguarded mutating endpoints.

---

## Rule Taxonomy

frapAST includes 28 active rule detectors and 2 explicitly disabled rules across core security and operational areas:

```
Proof Basis:
  Tier 2 : Live HTTP/RPC verification against a running Frappe bench
  Tier 1 : Standalone local AST reproducer (independent of bench)
  Static : Structural code pattern and dataflow verification
```

### Injection and Access Control
| Rule ID | Severity | Description | Proof Basis | Status |
|---|:---:|---|:---:|:---:|
| `FR-SQLI-001` | Critical | Dynamic `frappe.db.sql()` query with f-string or string concatenation lacking parameter bindings | Tier 2 | Validated (Synthetic GHSA-745c-5q8r-vgj2) |
| `FR-SQLI-002` | Critical | Raw SQL query referencing a submittable DocType table without a `docstatus` filter | Static | Validated |
| `FR-SQLI-003` | High | `frappe.db.set_value` invoked from whitelisted RPC bypassing controller `validate()` and `before_save()` hooks | Tier 2 | Validated |
| `FR-SQLI-004` | High | `frappe.qb.DocType()` or `frappe.qb.from_()` using request-controlled dynamic table identifiers | Tier 2 | Validated |
| `FR-INJ-001` | Critical | Request parameters unpacked directly into `frappe.get_doc(kwargs)` (mass assignment risk) | Tier 2 | Validated |
| `FR-INJ-002` | Critical | `eval()` or `exec()` called with request-controlled input reachable from whitelisted RPC | Tier 2 | Validated |
| `FR-INJ-005` | Disabled | `frappe.msgprint()` or `frappe.throw()` format strings | Static | Disabled (requires interprocedural taint analysis) |
| `FR-PATH-001` | High | User-controlled file path passed to file I/O operations without directory containment checks | Tier 2 | Validated (Synthetic TALOS-2020-1091) |
| `FR-SSRF-001` | High | User-controlled URL passed to outbound HTTP requests (`requests.get`, `urlopen`) with no allowlist | Tier 2 | Validated |
| `FR-CSRF-001` | High | Guest-accessible (`allow_guest=True`) endpoint performing state-changing database modifications | Tier 2 | Validated |

### Authorization and Permission Enforcement
| Rule ID | Severity | Description | Proof Basis | Status |
|---|:---:|---|:---:|:---:|
| `FR-PERM-001` | High / Critical | `@frappe.whitelist()` endpoint lacking explicit permission validation (`has_permission`, `only_for`) | Tier 2 | Validated (100% on Mutating Tier) |
| `FR-PERM-002` | High | `ignore_permissions=True` reachable within one hop of an unguarded public whitelisted endpoint | Tier 2 | Validated |
| `FR-PERM-003` | High | `frappe.db.set_value` on an `if_owner`-scoped DocType bypassing owner permission enforcement | Tier 2 | Validated |
| `FR-PERM-004` | Medium | Report query bypassing DocType `permission_query_conditions` hooks | Static | Validated |
| `FR-PERM-005` | Medium | Internal SQL query bypassing DocType `has_permission` row-level security hooks | Static | Validated |
| `FR-PERM-006` | High | `frappe.db.set_value` on a child table DocType (`istable=1`) leaving parent document totals uncalculated | Static | Validated |

### Framework Lifecycle and Workflow Integrity
| Rule ID | Severity | Description | Proof Basis | Status |
|---|:---:|---|:---:|:---:|
| `FR-HOOK-001` | Medium | Controller class defines `on_submit` but not `on_cancel` (missing reversal logic) | Tier 1 | Validated |
| `FR-HOOK-002` | Medium | Multiple applications registering conflicting handlers on the same `(doctype, event)` hook | Static | Validated |
| `FR-HOOK-003` | Medium | Whitelisted fast-path writing fields directly without validating lifecycle state transitions | Static | Validated |
| `FR-HOOK-004` | Medium | `frappe.enqueue()` invoked without deduplication keys, risking duplicate queue execution | Tier 1 | Validated |
| `FR-HOOK-005` | Low | `frappe.db.commit()` called within a lifecycle hook, breaking atomic transaction rollbacks | Tier 1 | Validated |
| `FR-WKFL-001` | Medium | `frappe.db.set_value` on submittable DocType without validating document draft status (`docstatus == 0`) | Static | Validated |
| `FR-WKFL-002` | Medium | Direct database write to `workflow_state` bypassing the Frappe workflow transition engine | Static | Validated |
| `FR-WKFL-003` | Medium | `status` updated without updating `docstatus` on submittable DocTypes | Tier 1 | Validated |
| `FR-WKFL-004` | Disabled | Amendment chain field leakage | Static | Disabled (natively handled by Frappe `no_copy=1`) |

### Performance, Correctness and Reliability
| Rule ID | Severity | Description | Proof Basis | Status |
|---|:---:|---|:---:|:---:|
| `FR-PERF-001` | Low | `frappe.get_doc()` called inside a loop over query results (N+1 query bottleneck) | Tier 1 | Validated |
| `FR-HOOK-006` | Low | Bare `except:` block swallowing framework execution signals and exceptions | Tier 1 | Validated |
| `FR-HOOK-007` | Low | Mutable default argument (`[]`, `{}`) in function definition signature | Tier 1 | Validated |
| `FR-DATA-001` | Low | DocType field reference accessing a non-existent schema fieldname | Tier 1 | Validated |
| `FR-DATA-002` | Low | Missing `db.commit()` after asynchronous background processing state writes | Tier 1 | Validated |
| `FR-DATA-003` | Low | Raw database delete on parent document leaving orphan child table rows | Static | Validated |
| `FR-I18N-001` | Low | Hardcoded user-facing message string in `msgprint` or `throw` without `frappe._()` | Tier 1 | Validated |

---

## How It Works

```
+-----------------+   +-----------------+   +-----------------+
|  Schema Index   |   |   Hook Index    |   |  Python AST     |
|  (DocType JSON) |   |  (hooks.py AST) |   |  (Source Files) |
+--------+--------+   +--------+--------+   +--------+--------+
         |                     |                     |
         +---------------------+---------------------+
                               |
                      +--------v--------+
                      |   Call Graph    |  5 Edge Types:
                      |                 |  - direct_call
                      |                 |  - string_dispatch (frappe.call)
                      |                 |  - hook_dispatch (doc_events)
                      |                 |  - dynamic_method (get_doc.method)
                      |                 |  - report_entry (report.execute)
                      +--------+--------+
                               |
                      +--------v--------+
                      |   Rule Engine   |  28 Active Detectors
                      +--------+--------+
                               |
                      +--------v--------+
                      | Severity Matrix |  Multi-Dimensional Composite Scoring
                      +--------+--------+
                               |
            +------------------+------------------+
            |                                     |
   +--------v-------+                    +--------v-------+
   |  CLI / SARIF   |                    | Web Dashboard  |
   +--------+-------+                    +--------+-------+
            |                                     |
            +------------------+------------------+
                               |
                      +--------v--------+
                      |  Proof Engine   |  Tier 0 (Static) -> Tier 1 (AST) -> Tier 2 (HTTP/RPC)
                      +--------+--------+
                               |
                      +--------v--------+
                      | Autofix Engine  |  CLI AST Code Patch Generator and Diff Viewer
                      +-----------------+
```

1. **Schema and Hook Indexing**: Parses all DocType JSON definitions (`fields`, `permissions`, `is_submittable`, `istable`) and `hooks.py` dispatch trees.
2. **AST Parsing and Call Graph Construction**: Analyzes AST structures to extract whitelisted endpoints, database calls, parameters, string-literal dispatches (`frappe.call("dotted.path")`), and script report entry points (`execute(filters)`).
3. **Composite Severity Matrix**: Computes severity using required privileges (guest vs authenticated user), impact classification, and blast radius.
4. **Active Proof Verification**:
   - **Tier 1 (AST Proof)**: Standalone verification programs executed locally.
   - **Tier 2 (HTTP/RPC Proof)**: Authenticated HTTP requests executed by `FrappeHTTPClient` against a Frappe bench.
5. **Autofix Engine**: Automatically generates and applies AST modifications via the CLI to eliminate manual boilerplate updates.

---

## Interactive Web Dashboard

Launch the local web dashboard:
```bash
frapast
```

Features provided in the web interface:
- **Real-Time Scan Streaming**: Server-Sent Events (SSE) update the dashboard as files are processed.
- **Visual Proof Drawer**: Inspect synthesized reproducers and view live verification outcomes.
- **Bench Connectivity Diagnostics**: Test connection to local Frappe bench instances with diagnostic reporting.
- **Persistent Storage**: SQLite with WAL mode preserves scan and proof history across application restarts.

---

## Test Suite and Quality Assurance

The codebase includes an automated test suite:

```bash
pytest -v
```

- **287 passed tests** covering AST visitors, call graph resolution, rule detectors, server security, reproducer synthesis, adversarial suppression handling, and autofix patches.
- **Security hardening**: Hardened shell script generation (`shlex.quote`), path traversal directory containment, and localhost origin gating.

---

## Contributing

Contributions are welcome. To report an architectural pattern or false-positive edge case:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-rule`)
3. Run tests (`pytest`)
4. Commit your changes and submit a Pull Request

---

## License

MIT (c) 2026 Frappe Security Scanner Contributors - see [LICENSE](LICENSE).