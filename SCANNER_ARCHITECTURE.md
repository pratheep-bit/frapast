# FRAPAST — Architecture & Roadmap

## A Static Analysis Engine Purpose-Built for the Frappe Framework

> **Reading guide:** This document is split into two halves.
> **Part I (Sections 1–10)** describes what actually exists today — code that compiles,
> runs, and has been tested against real Frappe applications.
> **Part II (Sections 11–20)** is the roadmap — things that don't exist yet, clearly
> marked as such, with honest assessments of what each phase requires.
>
> If a section doesn't say BUILT, it isn't built. No exceptions.

---

## Table of Contents

### Part I — What Exists Today

1. [Problem Statement](#1-problem-statement)
2. [What Generic SAST Tools Miss About Frappe](#2-what-generic-sast-tools-miss-about-frappe)
3. [Honest Competitive Position](#3-honest-competitive-position)
4. [Design Principles](#4-design-principles)
5. [Architecture Overview (Current State)](#5-architecture-overview-current-state)
6. [Core Engines — Built and Verified](#6-core-engines--built-and-verified)
7. [Rule Set — 29 Detection Rules](#7-rule-set--29-detection-rules)
8. [Support Infrastructure — Built](#8-support-infrastructure--built)
9. [Current Capabilities and Limitations](#9-current-capabilities-and-limitations)
10. [File Map (Actual)](#10-file-map-actual)

### Part II — Roadmap (Not Yet Built)

11. [Roadmap Overview](#11-roadmap-overview)
12. [Phase 0 — Proof-Mandatory Severity Cap](#12-phase-0--proof-mandatory-severity-cap)
13. [Phase 1 — Interprocedural Taint Engine](#13-phase-1--interprocedural-taint-engine)
14. [Phase 2 — ERPNext PR Corpus Ingestion](#14-phase-2--erpnext-pr-corpus-ingestion)
15. [Phase 3 — Empirical Severity Calibration](#15-phase-3--empirical-severity-calibration)
16. [Phase 4 — Sandboxed Runtime Proof](#16-phase-4--sandboxed-runtime-proof)
17. [Phase 5 — New Attack Surfaces](#17-phase-5--new-attack-surfaces)
18. [Phases 6-9 — CLI, Fix Loop, Benchmark, Diff Scan](#18-phases-6-9--cli-fix-loop-benchmark-diff-scan)
19. [Planned Rule Expansion](#19-planned-rule-expansion)
20. [Glossary](#20-glossary)

---

# Part I — What Exists Today

---

## 1. Problem Statement

The Frappe Framework powers ERPNext — widely deployed open-source ERP
handling financials, HR, manufacturing, and healthcare. A security
vulnerability here doesn't just leak data — it can corrupt financial
ledgers, expose payroll, and halt supply chains.

Generic SAST tools treat Frappe apps as plain Python. They don't model
the framework-specific execution semantics that determine whether code
is actually vulnerable in a Frappe context. FRAPAST exists to fill
that specific gap.

---

## 2. What Generic SAST Tools Miss About Frappe

These are Frappe-specific execution semantics that no generic Python
scanner models. This is the concrete, technical reason FRAPAST exists.

### 2.1 hooks.py as an Implicit Second Call Graph

Frappe's `hooks.py` defines `doc_events` — a dispatch table that wires
document lifecycle events (`on_submit`, `on_cancel`, `validate`,
`before_save`, etc.) to handler functions. These handlers can live in
completely different applications. A generic call graph builder will
never see that `on_submit` in App A calls `handler_x()` in App B,
because there's no Python-level import or function call connecting them.

### 2.2 The DocType Permission Matrix

Frappe's permission model is declarative (JSON), not code-level:

- `permlevel` — field-level permission tiers (level 0 = everyone with
  role access, level 1+ = elevated roles only)
- `if_owner` — scopes access to documents the requesting user created
- `ignore_permissions=True` — a keyword argument that bypasses the
  entire permission matrix when passed to `get_doc`, `save`, etc.

A generic scanner sees `ignore_permissions=True` as just a keyword
argument. FRAPAST cross-references it against the DocType's permission
configuration and the call path from whitelisted endpoints to determine
whether it's actually a security bypass.

### 2.3 frappe.whitelist() as the HTTP Attack Surface Boundary

Any function decorated with `@frappe.whitelist()` becomes an HTTP API
endpoint at `/api/method/<dotted.path>`. With `allow_guest=True`, it's
reachable without authentication. A generic scanner doesn't know this
decorator defines the trust boundary.

### 2.4 frappe.db.sql vs frappe.qb — Different Injection Surfaces

`frappe.db.sql(query)` accepts raw SQL strings — classic injection surface.
`frappe.qb` is a query builder with different (but still present) injection
vectors when table or column names are dynamic. A generic scanner treats
both as ordinary function calls.

### 2.5 frappe.db.set_value — The Controller Bypass

`frappe.db.set_value(doctype, name, field, value)` writes directly to the
database, bypassing the entire controller chain: no `validate()`, no
`before_save()`, no permission hooks. Generic scanners have no concept
of this implicit bypass.

### 2.6 Surfaces Invisible to Python-Only Analysis

Print Formats (Jinja templates stored in JSON), Server Scripts (Python
code stored in JSON string fields), Client Scripts (JavaScript in JSON),
and Website routes are entire attack surfaces that a Python AST walker
structurally cannot see. They require dedicated parsers.

---

## 3. Honest Competitive Position

| Capability | Semgrep / Bandit | CodeQL | Snyk Code | FRAPAST (today) |
|---|---|---|---|---|
| Understands hooks.py dispatch | No | No | No | Yes — built |
| Models DocType permission matrix | No | No | No | Yes — built |
| Cross-file dispatch-aware call graph | Generic | Strong generic | Partial | Frappe-specific, 4 edge types |
| Interprocedural taint (source to sink) | Pattern only | **Yes — industry-leading** | Partial | **Not built yet** |
| Exploit proof before severity | No | No | No | Scaffolded, not enforced as cap |
| Validated against framework's own bugs | No | No | No | Not built yet |
| Fully offline, deterministic | Yes | Yes | No (cloud) | Yes |
| Print Format / Server Script coverage | No | No | No | Not built yet |

**Honest assessment:**

- **Where FRAPAST is genuinely ahead:** Frappe-specific domain modeling —
  hooks dispatch, permission matrix cross-referencing, DocType-aware
  severity scoring. No other tool does this at all.
- **Where FRAPAST is behind:** CodeQL has years of engineering investment
  in interprocedural taint analysis. FRAPAST does reachability-based
  detection (is a sink reachable from a source?) but not real dataflow
  taint tracking (does attacker data actually flow to the sink?). The
  Phase 1 roadmap addresses this.
- **Where FRAPAST is comparable:** Offline/deterministic operation, pattern
  matching rule quality. 29 Frappe-specific rules vs. Semgrep/Bandit's
  generic Python rules that need to be taught what `frappe.whitelist` means.

---

## 4. Design Principles

### Principle 1 — No LLM at Runtime, Ever

The scanner is 100% static analysis. No LLM calls, no embeddings, no
AI-assisted triage. Every finding is reproducible byte-for-byte on every
run. Determinism and offline capability are features, not limitations.

### Principle 2 — Everything Must Be Explainable

Every finding traces to the exact AST node(s) that triggered it and the
exact rule ID that fired. No finding should ever require "trust me."

### Principle 3 — Reuse Before Rebuild

New capabilities extend existing data models and engines. No parallel
implementations of functionality that already exists.

### Principle 4 — Degrade Gracefully

A parse failure on one file logs a warning and continues — never aborts
the whole scan. A missing hooks.py or DocType JSON directory is handled
gracefully. The tool should always produce some output, even on incomplete
input.

---

## 5. Architecture Overview (Current State)

This diagram shows what actually exists and runs today.

```
+------------------------------------------------------------------+
|              LAYER 5 — OUTPUT (Built)                             |
|  CLI (argparse, 941 lines) · JSON/Markdown Reports               |
|  SARIF v2.1.0 (68 lines, not stress-tested)                     |
|  Regression Test Generator · Fix Engine (scaffolded)             |
+------------------------------------------------------------------+
|              LAYER 4 — SCORING & FP (Built)                      |
|  Severity Engine (multi-dimensional weighted scoring)            |
|  FP Suppression (YAML ledger + inline comments)                  |
|  Precision Tracking (fp_analyzer.py)                             |
+------------------------------------------------------------------+
|              LAYER 3 — PROOF (Scaffolded)                        |
|  Tier 1: In-process reproducer (orchestrator.py, 175 lines)     |
|  Tier 2: HTTP client + synthesis (exists, needs live Frappe)     |
|  WARNING: Not enforced as severity gate — findings can be High   |
|  without proof. Phase 0 roadmap fixes this.                      |
+------------------------------------------------------------------+
|              LAYER 2 — RULE EVALUATION (Built)                   |
|  29 rules across 10 families (rules/engine.py, 985 lines)       |
|  Reachability-based detection via call graph                     |
|  WARNING: No taint tracking — sink presence, not dataflow        |
+------------------------------------------------------------------+
|              LAYER 1 — INDEXING (Built)                           |
|  Python Symbol Index (838 lines, 20+ record types)               |
|  Call Graph (127 lines, 4 edge types)                            |
|  Hook Index (109 lines, doc_events + permission hooks)           |
|  Schema Index (114 lines, DocType JSON + permissions)            |
+------------------------------------------------------------------+
|              LAYER 0 — INGESTION (Built)                         |
|  Python .py file walker                                          |
|  hooks.py walker                                                 |
|  DocType JSON walker                                             |
|  NOT BUILT: template/script/route/webhook walkers                |
+------------------------------------------------------------------+
```

**What actually happens when you run the scanner:**

1. Walk the target app's file tree — discover `.py`, `hooks.py`, DocType JSON
2. Parse every `.py` file via `ast.parse()` — extract 20+ record types into `PythonSymbolIndex`
3. Parse `hooks.py` files — build `HookIndex` (doc_events, permission hooks)
4. Parse DocType JSON files — build `SchemaIndex` (fields, permissions, submit config)
5. Build call graph from symbol index (direct, string dispatch, hook dispatch, dynamic method)
6. Run 29 rules against the combined indexes — produce `Candidate` list
7. Filter via FP suppression (YAML ledger + inline `# frapast:ignore`)
8. Score each candidate via multi-dimensional severity engine
9. Proof orchestrator can attempt Tier 1 verification (not enforced as gate)
10. Render output: terminal tables, JSON, or Markdown

---

## 6. Core Engines — Built and Verified

### 6.1 Python AST and Symbol Indexer — BUILT

**File:** `scanner/python/engine.py` — 838 lines
**Models:** `scanner/python/models.py`

The heart of the scanner. The `_FunctionBodyVisitor` walks every function
body and extracts structured records for security-relevant patterns:

| Record Type | What It Detects | Count in typical app |
|---|---|---|
| `WhitelistedEndpoint` | `@frappe.whitelist()` decorated functions | ~50-200 |
| `SqlCallRecord` | `frappe.db.sql()` with query structure analysis | ~100-500 |
| `IgnorePermissionsRecord` | `ignore_permissions=True` keyword args | ~30-100 |
| `PermCheckRecord` | `frappe.has_permission()` / `frappe.only_for()` calls | ~20-80 |
| `CommitCallRecord` | `frappe.db.commit()` in lifecycle hooks | ~5-20 |
| `DirectWriteRecord` | `frappe.db.set_value()` field writes | ~50-200 |
| `EvalExecRecord` | `eval()` / `exec()` with input analysis | ~0-5 |
| `EnqueueCallRecord` | `frappe.enqueue()` without dedup keys | ~10-30 |
| `QueryBuilderRecord` | `frappe.qb` with dynamic table/column names | ~20-50 |
| `GetDocKwargsRecord` | `frappe.get_doc(kwargs)` from request data | ~5-15 |
| `MsgprintRecord` | `frappe.msgprint/throw` with user input | ~10-40 |
| `OutboundRequestRecord` | `requests.get/post` with dynamic URLs | ~0-10 |
| `BareExceptRecord` | Bare `except:` blocks | varies |
| `MutableDefaultArgRecord` | `def f(x=[])` mutable default args | varies |
| `QueryInLoopRecord` | `get_doc()` inside `get_all()` loop | ~5-20 |
| `HardcodedStringRecord` | Un-translated user-facing strings | varies |

**Key design detail:** The visitor tracks variable assignments through
`self.values` to resolve constant propagation — if `query = f"SELECT..."` is
assigned and later passed to `frappe.db.sql(query)`, the indexer traces
through the assignment chain to detect the injection pattern.

**Known limitation:** This is intra-function assignment tracking only.
It does not follow data across function boundaries (that's what the
Phase 1 taint engine would add).

### 6.2 Call Graph Builder — BUILT

**File:** `scanner/callgraph/builder.py` — 127 lines
**Models:** `scanner/callgraph/models.py`

Builds cross-file call graph with four edge types:

| Edge Type | Weight | How It Resolves |
|---|---|---|
| `DIRECT_CALL` | 1.0 | Function name matched against symbol index |
| `STRING_DISPATCH` | 0.9 | `frappe.call("a.b.c")` — dotted path lookup |
| `HOOK_DISPATCH` | 0.85 | `doc_events` handler path — function resolution |
| `DYNAMIC_METHOD` | 0.4 | `frappe.get_doc(...).method()` — method name fan-out |

Lookup maps are built once upfront so each call site resolves in O(1).
The graph provides `reachable_from(entry_point)` queries used by rules
like FR-PERM-002 to check if `ignore_permissions=True` is reachable
from a whitelisted endpoint.

### 6.3 Hook Index — BUILT

**File:** `scanner/hooks/engine.py` — 109 lines
**Models:** `scanner/hooks/models.py`

Parses `hooks.py` `doc_events` dictionaries via `ast.literal_eval`:

- Ordered handler list per `(app, doctype, event)` tuple
- `permission_query_conditions` per DocType
- `has_permission` hook mapping
- Collision detection for multi-app hook overlaps

### 6.4 Schema and Permission Index — BUILT

**File:** `scanner/schema/engine.py` — 114 lines
**Models:** `scanner/schema/models.py`

Loads DocType JSON into `DocTypeRecord` instances:

- Field definitions: `fieldname`, `fieldtype`, `options`
- Permission matrix: `role`, `permlevel`, `read/write/create/submit/cancel`, `if_owner`
- Submittable status, child table flag, autoname configuration
- Derived queries: `submittable_doctypes()`, `owner_scoped_doctypes()`, `child_tables()`

### 6.5 Rule Engine — BUILT

**File:** `scanner/rules/engine.py` — 985 lines

Executes all rules from `ALL_RULES` registry against the combined indexes.
Each rule is a pure function:

```python
Rule = Callable[[SchemaIndex, HookIndex, PythonSymbolIndex, CallGraph], list[Candidate]]
```

Rules are stateless and deterministic. The engine handles deduplication,
inline suppression filtering, and candidate construction.

**Current detection approach:** Reachability-based. Rules check whether a
dangerous pattern (sink) exists and whether it's reachable from an attack
surface entry point (whitelisted endpoint) via the call graph. This catches
real bugs but also produces false positives when the sink exists but the
data flowing to it is server-generated, not attacker-controlled. The Phase 1
taint engine addresses this gap.

### 6.6 Severity Scoring Engine — BUILT

**File:** `scanner/severity/engine.py` — 192 lines
**Models:** `scanner/severity/models.py`

Multi-dimensional weighted composite scoring:

```
Dimensions:
  privilege_required  — guest (x3) vs authenticated (x1)
  impact_class        — rce (x4), privilege_escalation (x3), data_exposure (x2)
  blast_radius        — framework_wide (x3), cross_doctype (x2), single_record (x0.5)
  proof_tier          — adds +0/+2/+4 to composite
  guest_multiplier    — x1.5 if allow_guest=True
```

**Current limitation:** `proof_tier` is folded in as a weighted additive
term, not as a hard gate. A finding with `proof_tier=0` (static match only,
no runtime verification) can still be labeled Critical or High if the
other dimensions score high enough. The Phase 0 severity cap changes this
to a hard rule: `proof_tier=0` means never Critical or High.

### 6.7 False-Positive Suppression — BUILT

**File:** `scanner/fp/engine.py` — 99 lines
**Models:** `scanner/fp/models.py`

Two suppression mechanisms:

1. **Inline:** `# frapast:ignore` comments (optionally scoped by rule ID)
2. **YAML ledger:** Persistent FP records keyed by
   `(rule_id, rule_version, repo, file, function, code_location_hash)` —
   version-aware so a rule logic change doesn't silently keep suppressing
   a finding whose detection changed.

### 6.8 Proof Orchestrator — SCAFFOLDED

**File:** `scanner/proof/orchestrator.py` — 175 lines
**Support:** `scanner/proof/http_client.py`, `scanner/proof/http_synthesis.py`

The proof infrastructure exists:

- Tier 1 proof runner (in-process function call reproducers)
- HTTP client for Tier 2 (requires a running Frappe site to test against)
- HTTP reproducer script synthesis (generates curl/bash scripts)

**What's scaffolded but not enforced:** The proof results are recorded on
candidates but don't gate severity. A finding can be labeled Critical
without any proof. The Phase 0 roadmap makes proof mandatory for Critical/High.

**What's missing entirely:** Automated sandbox provisioning. Tier 2 proof
currently requires someone to manually point the scanner at a live Frappe
instance. Docker is not installed on the current development machine.

---

## 7. Rule Set — 29 Detection Rules

Every rule listed here exists in `scanner/rules/engine.py` and runs today.

### SQL Injection (4 rules)

| Rule ID | What It Detects |
|---|---|
| `FR-SQLI-001` | Raw `frappe.db.sql()` with string formatting (f-strings, `.format()`, `%`) instead of parameter binding |
| `FR-SQLI-002` | Raw SQL on submittable DocTypes without a `docstatus` filter — can expose draft/cancelled records |
| `FR-SQLI-003` | `frappe.db.set_value` / `db_update` bypassing controller `validate()` / `before_save()` hooks |
| `FR-SQLI-004` | Non-literal dynamic table or column names passed to `frappe.qb` query builder |

### Permission Bypass (6 rules)

| Rule ID | What It Detects |
|---|---|
| `FR-PERM-001` | `@frappe.whitelist()` endpoint with no permission check in the function body or its 1-hop callees |
| `FR-PERM-002` | `ignore_permissions=True` reachable from a whitelisted endpoint via call graph |
| `FR-PERM-003` | `frappe.db.set_value` writing to an `if_owner`-scoped DocType without checking ownership |
| `FR-PERM-004` | Script/Query Report executing raw SQL without `permission_query_conditions` |
| `FR-PERM-005` | Internal `frappe.get_all` query path that skips `has_permission` hooks |
| `FR-PERM-006` | Child table mutation without triggering parent document `validate()` |

### Hook Integrity and Correctness (7 rules)

| Rule ID | What It Detects |
|---|---|
| `FR-HOOK-001` | `on_submit` defined without matching `on_cancel` — asymmetric lifecycle |
| `FR-HOOK-002` | Multiple apps hooking the same `(doctype, event)` — collision risk |
| `FR-HOOK-003` | Whitelisted endpoint writing via `db.set_value`/`db_update` instead of `doc.save()`, bypassing hooks |
| `FR-HOOK-004` | `frappe.enqueue()` without deduplication or lock key |
| `FR-HOOK-005` | `frappe.db.commit()` inside a document lifecycle hook |
| `FR-HOOK-006` | Bare `except:` swallowing framework exceptions (renamed from FR-CORR-001) |
| `FR-HOOK-007` | Mutable default arguments sharing state across calls (renamed from FR-CORR-002) |

### Workflow Integrity (4 rules)

| Rule ID | What It Detects |
|---|---|
| `FR-WKFL-001` | Submittable field mutation without `docstatus` guard |
| `FR-WKFL-002` | Direct `workflow_state` field write outside the workflow engine |
| `FR-WKFL-003` | `status` vs `docstatus` desynchronization |
| `FR-WKFL-004` | Amendment chain state leakage on submittable DocTypes |

### Injection and XSS (3 rules)

| Rule ID | What It Detects |
|---|---|
| `FR-INJ-001` | Mass assignment via unsanitized `**kwargs` into `frappe.get_doc()` |
| `FR-INJ-002` | `eval()` / `exec()` with request-controlled input |
| `FR-INJ-005` | Unescaped user input in `frappe.msgprint()` / `frappe.throw()` |

### Other (5 rules)

| Rule ID | What It Detects |
|---|---|
| `FR-CSRF-001` | Guest-accessible state-changing endpoint lacking CSRF validation |
| `FR-SSRF-001` | User-controlled URL in outbound HTTP request |
| `FR-DATA-001` | Non-existent fieldname reference on a DocType record |
| `FR-PERF-001` | N+1 query pattern: `get_doc()` inside a `get_all()` loop |
| `FR-I18N-001` | Hardcoded user-facing string missing `frappe._()` wrapper |

---

## 8. Support Infrastructure — Built

### CLI — BUILT

**File:** `scanner/cli.py` — 941 lines, **argparse-based** (not Click)

Subcommands: scan, triage menus, ledger management, proof orchestration.
Entry point: `python -m scanner` or direct invocation.

### Reporting — BUILT

**File:** `scanner/reporting/engine.py` — JSON and Markdown output
**File:** `scanner/reporting/sarif.py` — 68 lines, SARIF v2.1.0 skeleton

The SARIF output exists but has not been tested against GitHub's Security
tab or any other SARIF consumer. It should be considered untested until
verified against a real SARIF validator.

### Terminal UI — BUILT

**Directory:** `scanner/ui/` — banner, menus, progress bars, result tables,
interactive shell, color theming (Rich library)

### Regression Test Generator — BUILT

**File:** `scanner/regression/generator.py` — 114 lines

Generates pytest test functions from proven findings in the ledger.

### Fix Validation Engine — SCAFFOLDED

**File:** `scanner/validate/engine.py` — exists but not wired end-to-end.
The patch validation pipeline (apply fix, re-run proof, check test suite)
is defined but not connected to the CLI or proof orchestrator in a working
loop.

### Configuration — BUILT

**File:** `scanner/config.py` — paths, defaults, per-scan configuration

### Logging — BUILT

**File:** `scanner/logger.py` — structured colored logging, all modules log
through this shared configuration

### Shared Utilities — BUILT

**File:** `scanner/shared/records.py` — `SourceFile`, `SourceSpan`,
`stable_hash()` for content-addressable identity

---

## 9. Current Capabilities and Limitations

### What FRAPAST Can Do Today

1. **Parse and index** an entire Frappe application's Python codebase,
   extracting 20+ types of security-relevant AST records
2. **Build a cross-file call graph** with 4 edge types including Frappe-specific
   dispatch (hook dispatch, string dispatch, dynamic method calls)
3. **Cross-reference** hook dispatch tables, DocType permission matrices,
   and code patterns to detect Frappe-specific vulnerability patterns
4. **Run 29 detection rules** that no generic SAST tool implements
5. **Score findings** on a multi-dimensional severity model that accounts for
   privilege level, impact class, blast radius, and proof tier
6. **Suppress false positives** via inline comments and a versioned YAML ledger
7. **Generate regression tests** from proven findings
8. **Output** to terminal, JSON, or Markdown

### What FRAPAST Cannot Do Today (Honest Gaps)

1. **No real taint tracking.** Detection is reachability-based: "this sink
   exists in a function reachable from an entry point." It does not trace
   whether attacker-controlled data actually flows to the sink's argument.
   This is the number one source of false positives.

2. **No proof-mandatory severity gate.** A finding can be labeled Critical
   based on pattern matching alone. The proof infrastructure exists but
   isn't enforced as a prerequisite for high severity labels.

3. **No coverage of non-Python surfaces.** Print Formats, Server Scripts,
   Client Scripts, Website routes, Webhooks, and Query Report definitions
   are invisible to the current scanner. These are real attack surfaces.

4. **No automated sandbox proof.** Tier 2 (HTTP/RPC) proof requires
   manually pointing at a running Frappe instance. Docker is not installed
   on the current development machine.

5. **No corpus-driven rule validation.** Rules are tested against hand-written
   fixtures, not against real ERPNext historical bugs. No empirical evidence
   that the rules catch what ERPNext has actually had to fix.

6. **No diff-aware incremental scanning.** Every scan re-parses the entire
   codebase. No caching between runs.

7. **SARIF output is untested.** The 68-line SARIF generator exists but
   hasn't been validated against GitHub's Security tab or any SARIF consumer.

---

## 10. File Map (Actual)

Every file that exists in `scanner/` today, with real line counts where measured.

### Core Engines

| File | Lines | Status |
|---|---|---|
| `scanner/python/engine.py` | 838 | BUILT — core indexer |
| `scanner/python/models.py` | — | BUILT — immutable dataclasses for all record types |
| `scanner/rules/engine.py` | 985 | BUILT — 29 rules implemented |
| `scanner/callgraph/builder.py` | 127 | BUILT — 4 edge types |
| `scanner/callgraph/models.py` | — | BUILT — CallEdge, CallGraph, reachability |
| `scanner/hooks/engine.py` | 109 | BUILT — doc_events + permission hooks |
| `scanner/hooks/models.py` | — | BUILT — HookHandlerRecord, HookIndex |
| `scanner/schema/engine.py` | 114 | BUILT — DocType JSON to SchemaIndex |
| `scanner/schema/models.py` | — | BUILT — DocTypeRecord, permissions |
| `scanner/severity/engine.py` | 192 | BUILT — multi-dimensional scoring |
| `scanner/severity/models.py` | — | BUILT — SeverityScore, weight tables |
| `scanner/fp/engine.py` | 99 | BUILT — YAML ledger + inline suppression |
| `scanner/fp/models.py` | — | BUILT — FalsePositiveRecord |
| `scanner/proof/orchestrator.py` | 175 | SCAFFOLDED — not enforced |
| `scanner/proof/models.py` | — | BUILT — ProofResult, ProofStatus |
| `scanner/proof/http_client.py` | — | SCAFFOLDED — needs live Frappe instance |
| `scanner/proof/http_synthesis.py` | — | SCAFFOLDED — generates scripts, untested e2e |

### CLI and Reporting

| File | Lines | Status |
|---|---|---|
| `scanner/cli.py` | 941 | BUILT — argparse CLI, primary user surface |
| `scanner/reporting/engine.py` | — | BUILT — JSON + Markdown reports |
| `scanner/reporting/sarif.py` | 68 | EXISTS — not validated against consumers |
| `scanner/reporting/formatters.py` | — | BUILT — terminal text formatting |

### Infrastructure

| File | Lines | Status |
|---|---|---|
| `scanner/config.py` | — | BUILT — configuration loading |
| `scanner/logger.py` | — | BUILT — structured logging |
| `scanner/shared/records.py` | — | BUILT — SourceFile, SourceSpan, stable_hash |
| `scanner/ledger_io.py` | — | BUILT — finding ledger YAML I/O |
| `scanner/ledger_schema.py` | — | BUILT — ledger validation schema |
| `scanner/fp_analyzer.py` | — | BUILT — precision stats per rule |
| `scanner/regression/generator.py` | 114 | BUILT — regression test generation |
| `scanner/validate/engine.py` | — | SCAFFOLDED — not wired e2e |
| `scanner/ui/` | — | BUILT — banner, menus, progress, results, shell, theme |
| `scanner/taxonomy_registry.yaml` | — | BUILT — rule ID to taxonomy mapping |
| `scanner/rules/schema.yaml` | — | BUILT — rule definition schema |

### Directories That Do NOT Exist

```
scanner/taint/          <-- Phase 1 roadmap
scanner/corpus/         <-- Phase 2 roadmap
scanner/surfaces/       <-- Phase 5 roadmap
benchmark/              <-- Phase 8 roadmap
```

---

# Part II — Roadmap (Not Yet Built)

> **Everything below this line is planned work. None of it exists as code.
> Timelines are estimates based on scope, not commitments.**

---

## 11. Roadmap Overview

The roadmap follows a strict dependency order. Each phase builds on the
previous one. No phase should be started until the previous phase compiles
and its tests pass.

```
Phase 0 --- Proof-mandatory severity cap
    |       Smallest diff, highest trust impact.
    |       Modify: severity/engine.py, severity/models.py
    |       Estimated effort: 1 day
    v
Phase 1 --- Interprocedural taint engine
    |       Transform reachability-based detection into dataflow analysis.
    |       Create: scanner/taint/models.py, scanner/taint/engine.py
    |       Modify: python/engine.py (add assignment tracking), rules/engine.py
    |       Estimated effort: 1-2 weeks
    v
Phase 2 --- ERPNext PR corpus ingestion
    |       Ingest ~3,000 PR summaries. Keyword classification, diff mining.
    |       Create: scanner/corpus/ (5 files)
    |       Estimated effort: 1 week
    v
Phase 3 --- Empirical severity calibration
    |       Fold corpus frequency into scoring as bounded tiebreaker.
    |       Create: severity/priors.py. Modify: severity/engine.py
    |       Estimated effort: 1-2 days
    v
Phase 4 --- Sandboxed runtime proof (Docker)
    |       Ephemeral Docker Compose stack for automated Tier 2 proof.
    |       Prerequisite: Docker installed. Create: proof/sandbox.py
    |       Estimated effort: 1 week
    v
Phase 5 --- New attack surface walkers
    |       Print Formats, Server Scripts, Client Scripts, Website routes,
    |       Webhooks, Query Reports, File uploads.
    |       Create: scanner/surfaces/ (7 files) + new rules
    |       Estimated effort: 2-3 weeks
    v
Phase 6 --- CLI improvements
    |       Add corpus-report, benchmark, --diff, --fix subcommands.
    |       Modify: scanner/cli.py
    |       Estimated effort: 3-5 days
    v
Phase 7 --- Fix, re-proof, regression loop
    |       End-to-end verified auto-patching.
    |       Modify: validate/engine.py, wire to CLI
    |       Estimated effort: 1 week
    v
Phase 8 --- Corpus-sourced benchmark + CI gate
    |       Per-rule precision/recall on real-world fixture pairs.
    |       Create: benchmark/ directory
    |       Estimated effort: 1 week
    v
Phase 9 --- Diff-aware incremental scanning
            Content-hash caching, git-diff-scoped analysis.
            Modify: python/engine.py, cli.py
            Estimated effort: 1 week
```

---

## 12. Phase 0 — Proof-Mandatory Severity Cap

**Status:** NOT BUILT
**Why this is first:** Highest leverage. One small code change eliminates
the entire class of "SAST tool cried wolf" — the number one reason security
teams stop trusting scanner output.

**The change:** After `_compute_composite` produces a score and
`_label_from_score` assigns a severity label, add a hard cap:

```
if proof_tier == 0 and label in ("Critical", "High"):
    label = "Medium"
```

This means: if the scanner hasn't actually reproduced the exploit (Tier 1
in-process or Tier 2 HTTP/RPC), the finding is capped at Medium. This is
not a weight adjustment — it's a structural guarantee that "Critical" always
means "we have a working exploit."

**Files to modify:**

- `scanner/severity/models.py` — add `label` field to `SeverityScore`
- `scanner/severity/engine.py` — add `_label_from_score()` with documented
  thresholds, add the hard cap logic

**Test requirement:** Property-based or exhaustive enumeration test asserting
that for all valid `(candidate, allow_guest, proof_tier=0)` inputs, the
output label is never "Critical" or "High".

---

## 13. Phase 1 — Interprocedural Taint Engine

**Status:** NOT BUILT — `scanner/taint/` directory does not exist

**Why this matters:** This is what transforms the tool from a pattern scanner
into a real analyzer. Currently, FR-SQLI-001 fires if `frappe.db.sql` with
an f-string argument exists in a function reachable from a whitelisted endpoint.
With taint tracking, it would only fire if attacker-controlled data from the
endpoint's parameters actually reaches that f-string argument through the
assignment chain and call graph.

**Data model** (`scanner/taint/models.py`):

- `TaintSource` — where attacker data enters (whitelisted_param, form_dict, request_arg)
- `TaintSink` — where it causes harm (sql, eval_exec, ignore_permissions, etc.)
- `TaintPath` — source to sink with hop chain, edge kinds, confidence score
- `AssignRecord` — LHS variable, RHS source variables, per assignment statement

**Algorithm** (`scanner/taint/engine.py`):

1. **Seed** — mark whitelisted endpoint parameters and `frappe.form_dict`
   accesses as taint sources
2. **Intra-procedural propagation** — within each function, trace assignment
   chains to fixed point (flow-insensitive, intentional over-approximation)
3. **Inter-procedural propagation** — follow tainted variables through call
   graph edges, multiplying confidence by edge weight per hop
4. **Sink matching** — check if any known sink's argument is in the tainted set

**Prerequisite change:** `scanner/python/engine.py`'s `_FunctionBodyVisitor`
needs `visit_Assign` / `visit_AnnAssign` to emit `AssignRecord` entries.
Currently it records calls but not assignments.

**Test requirement:** 15 hand-written fixture pairs — 5 confirmed taint paths,
10 look-alikes where a sink exists but the argument is server-generated.

---

## 14. Phase 2 — ERPNext PR Corpus Ingestion

**Status:** NOT BUILT — `scanner/corpus/` directory does not exist

**Input available:** We have a JSON dataset of roughly 3,000 ERPNext merged PR
summaries (title, labels, basic metadata). This data exists as a file but has
not been ingested into any structured pipeline.

**What this phase builds:**

1. **Ingestion** (`scanner/corpus/ingest.py`) — defensive parser that
   accepts JSONL or directory-of-files format. Only `pr_number` is required;
   everything else gracefully degrades. A corrupt record is logged and skipped,
   never crashes the scan.

2. **Keyword classification** (`scanner/corpus/taxonomy.py`) — deterministic
   bag-of-keywords classifier. No ML, no LLM. A hand-curated table of
   category to keyword phrase mappings. Fully reproducible.

3. **Structural diff mining** (`scanner/corpus/diff_miner.py`) — where
   `diff_text` is available, parse before/after code via `ast.parse()` and
   compare sink records structurally. This produces real benchmark fixture
   pairs sourced from actual merged fixes.

4. **Gap report** (`scanner/corpus/gap_report.py`) — cross-tabulates
   corpus category frequency against existing `FR-*` rule coverage.
   Categories with high frequency and zero rule coverage are the empirically
   justified candidates for new rules.

**Important note:** The actual category frequencies and distribution will only
be known after this pipeline runs against the real data. Any statistics
quoted before that point are made up.

---

## 15. Phase 3 — Empirical Severity Calibration

**Status:** NOT BUILT
**Depends on:** Phase 2 (needs real corpus frequency data)

**The idea:** Categories that ERPNext has had to fix most often historically
carry marginally higher real-world risk. Fold this into severity scoring
as a bounded multiplier in [0.9, 1.3] — never enough to push Medium
to Critical on its own, only a tiebreaker.

Categories with fewer than 10 corpus data points get multiplier 1.0
(no adjustment) to avoid overfitting on sparse data.

The specific multiplier values will be computed from the actual corpus
data in Phase 2. They cannot be specified in advance.

---

## 16. Phase 4 — Sandboxed Runtime Proof

**Status:** NOT BUILT. Docker is not installed on the current dev machine.
**Depends on:** Phase 0 (proof cap makes this meaningful)

**The idea:** Spin up an ephemeral Docker Compose stack (Frappe + MariaDB
+ Redis), install the target app, run `bench migrate`, then execute Tier 2
HTTP/RPC reproducers against the live instance. Tear down after.

**Critical requirements:**

- `try/finally` teardown — never leak containers
- Explicit timeout on every network operation
- Graceful fallback: if Docker is unavailable, log clearly and continue
  with Tier 1 only
- `--no-sandbox` flag for CI environments without Docker

**Prerequisite:** Install Docker. This is a real blocker, not a code issue.

---

## 17. Phase 5 — New Attack Surfaces

**Status:** NOT BUILT — `scanner/surfaces/` directory does not exist
**Depends on:** Phase 2 gap report (prioritize by real frequency data)

Seven new walkers, each independent and additive:

| Walker | Surface | What It Parses |
|---|---|---|
| `print_format.py` | Print Format JSON | Jinja expression blocks, flag unescaped doc fields |
| `server_script.py` | Server Script JSON | `ast.parse()` the `script` string field |
| `client_script.py` | Client Script JSON | Regex/tokenization of JS `script` field |
| `website_routes.py` | DocType JSON | `has_web_view` crossed with permission matrix |
| `webhooks.py` | Webhook JSON | Attacker-configurable outbound URLs |
| `report_builder.py` | Query Report JSON | Raw SQL in report definitions |
| `file_upload.py` | Attachment code paths | Path traversal, file type restrictions |

None of these modify `scanner/python/engine.py`. They populate parallel
indexes consumed by new rules, exactly as `SchemaIndex` and `HookIndex`
are consumed today.

---

## 18. Phases 6-9 — CLI, Fix Loop, Benchmark, Diff Scan

### Phase 6 — CLI Improvements

Add `corpus-report`, `benchmark`, `--diff`, `--fix`, `--no-sandbox` to the
existing argparse CLI. Not a rewrite — extensions to the existing 941-line
`scanner/cli.py`.

### Phase 7 — Fix, Re-Proof, Regression Loop

Wire `scanner/validate/engine.py` end-to-end: generate patch, apply in
scratch worktree, re-run the exact reproducer (must now fail), run app
test suite, emit diff + regression test. Never ship an unverified fix.

### Phase 8 — Corpus-Sourced Benchmark + CI Gate

Create `benchmark/<rule_id>/vulnerable.py` + `safe.py` pairs, traced to
source PRs. CI command asserts at least 90% precision per rule. Fail the
build if any rule regresses.

### Phase 9 — Diff-Aware Incremental Scanning

Restrict file walker to `git diff` changed files + their call graph
transitive closure. Cache indexes by content hash. Target: sub-10-second
incremental scans on typical PRs.

---

## 19. Planned Rule Expansion

Rules listed here are candidates based on the master spec. None exist as
code. Actual prioritization depends on Phase 2 corpus gap report data —
build rules for bugs ERPNext actually has, not bugs we guess it might have.

| ID | Surface | What It Would Detect |
|---|---|---|
| `FR-PERM-007` | Query Report | Raw SQL with no permission query condition |
| `FR-PERM-008` | REST API | `permlevel`-restricted field exposed without check |
| `FR-HOOK-008` | Cron hooks | `scheduler_events` handler asymmetry |
| `FR-TMPL-001` | Print Format | SSTI / stored XSS via unescaped Jinja fields |
| `FR-SCRIPT-001` | Server Script | Sandbox escape — disallowed module import |
| `FR-SCRIPT-002` | Server Script | Overprivileged raw SQL in sandboxed context |
| `FR-CLIENT-001` | Client Script | Reflected DOM XSS via unescaped `frm.doc.*` |
| `FR-WEB-001` | Website Routes | Guest-reachable page bypassing `@whitelist` |
| `FR-SSRF-002` | Webhooks | Attacker-configurable outbound URL |
| `FR-FILE-001` | Attachments | Path traversal via `file_name` |
| `FR-FILE-002` | Attachments | Unrestricted file type upload |
| `FR-AUTH-001` | Session handling | Session fixation, key logging, weak JWT |
| `FR-EMAIL-001` | Notifications | Email header injection in templates |
| `FR-PDF-001` | Print rendering | Unsanitized content to wkhtmltopdf |
| `FR-IMPORT-001` | Data Import | CSV/formula injection in bulk import |
| `FR-RATE-001` | Auth endpoints | No rate limit on brute-forceable operations |
| `FR-NAME-001` | Naming | Autoname collision race condition |
| `FR-JOB-001` | Background jobs | `enqueue` with no timeout (worker hang) |
| `FR-TENANT-001` | Multi-tenancy | Site isolation boundary crossed |

Each of these should only be implemented after the corpus gap report confirms
the category has meaningful real-world frequency. Building rules ahead of
evidence is guesswork.

---

## 20. Glossary

| Term | Meaning in this codebase |
|---|---|
| Candidate | A single finding, pre- or post-proof. Produced by `rules/engine.py` |
| Sink | Any operation that causes harm with attacker data (SQL call, eval, etc.) |
| Source | Any point where attacker data enters (form_dict, whitelisted params) |
| Reachability | A call-graph path exists from entry point to sink (ignoring dataflow) |
| Taint | (Phase 1) Property of a variable tracing to a source without sanitization |
| Taint Path | (Phase 1) Full source, hop chain, sink trace with confidence score |
| Proof Tier 0 | Static pattern match only — no runtime verification |
| Proof Tier 1 | In-process function call reproduced the exploit |
| Proof Tier 2 | Live HTTP/RPC request against running Frappe confirmed exploit |
| Proof Cap | (Phase 0) Structural rule: no Critical/High without Tier 1+ proof |
| Corpus Prior | (Phase 3) Bounded severity multiplier from real fix frequency |
| Gap Report | (Phase 2) Frequency x coverage cross-tab — rules to build next |
| `ignore_permissions` | Frappe kwarg bypassing the entire DocType permission matrix |
| `permlevel` | Frappe field-level permission tier (0=base, 1+=elevated) |
| `if_owner` | Permission rule scoping access to docs the user created |
| Whitelisted | `@frappe.whitelist()` — makes a function HTTP-reachable |
| `allow_guest` | Whitelist argument permitting unauthenticated access |
| Blast Radius | Impact scope: single record, doctype, cross-doctype, framework |
| SARIF | Static Analysis Results Interchange Format — GitHub Security standard |

---

> **End of document.**
>
> **Part I** covers ~3,580 lines of real, running code across 54 Python files:
> 8 core engines, 29 detection rules, argparse CLI, reporting, and support infra.
>
> **Part II** covers 10 phases of planned work, with honest "not built" labels,
> real dependency chains, and no fabricated statistics.
>
> The tool's genuine advantage is Frappe-specific domain modeling that no generic
> scanner provides. The roadmap's value is turning that advantage from "reachability-
> based pattern matching" into "real interprocedural taint analysis validated against
> ERPNext's own bug history." That's a credible direction, not a done deal.
