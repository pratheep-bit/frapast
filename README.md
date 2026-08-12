<div align="center">

# frapAST

**Runtime-Proven Static Security Analysis Engine for Frappe & ERPNext**

[![PyPI version](https://img.shields.io/pypi/v/frapast.svg)](https://pypi.org/project/frapast/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Rules](https://img.shields.io/badge/detectors-29-orange.svg)](#rule-taxonomy)

*Find the vulnerability. Prove it's real. Ship the fix.*

[Quickstart](#quickstart) · [Rule Taxonomy](#rule-taxonomy) · [How It Works](#how-it-works) · [Dashboard](#dashboard) · [Contributing](#contributing)

</div>

---

## Why frapAST exists

Generic Python SAST tools treat Frappe apps like plain Python — they miss the framework entirely. They don't know that a `@frappe.whitelist()` function is a public HTTP endpoint. They don't know what a DocType's permission model actually enforces. They can't tell a routine `doc.save()` from a workflow-state bypass, or a legitimate `ignore_permissions=True` from an authorization hole.

**frapAST is built from the Frappe framework outward.** It indexes your DocType schemas, parses `hooks.py`, walks the AST of every Python module, and builds a real call graph across direct calls, `frappe.call()` string dispatches, lifecycle hooks, and dynamic document methods — the actual ways code executes in a Frappe app. Findings aren't just pattern matches; they carry a composite severity score and, optionally, **active runtime proof** against a real bench, so you know which findings are exploitable and which are noise.

---

## What makes it different

- **Framework-aware, not generic.** Understands DocTypes, `hooks.py`, whitelisted endpoints, and workflow state machines — not just Python syntax.
- **A real call graph.** Four edge kinds (`direct_call`, `string_dispatch`, `hook_dispatch`, `dynamic_method`) model how Frappe actually dispatches code at runtime, including `frappe.call("a.b.c")` and hook-driven execution.
- **Composite severity scoring**, not a flat High/Medium/Low guess — privilege level, impact class, blast radius, and proof tier all feed into one score.
- **Active proof, not just static guesses.** Findings can be escalated from a static candidate (Tier 0) to a locally-executed reproducer (Tier 1) to a live verification against a running Frappe bench (Tier 2).
- **CI-ready output.** JSON, YAML, and OASIS **SARIF 2.1.0** — drop it straight into GitHub code scanning.
- **A local dashboard**, not a hosted SaaS — everything runs on your machine, gated to `127.0.0.1`.

---

## Quickstart

```bash
pip install frapast

# Launch the interactive dashboard (no args)
frapast

# Scan a repo from the CLI
frapast scan /path/to/your/frappe-app

# Scan with active proof verification against a local bench
frapast scan /path/to/your/frappe-app --prove --bench-url http://localhost:8005

# Output SARIF for CI / GitHub code scanning
frapast scan /path/to/your/frappe-app --format sarif > results.sarif

# Only scan what changed in a diff (fast PR checks)
frapast scan . --diff origin/main
```

### Core commands

| Command | Purpose |
|---|---|
| `frapast` | Launch the local web dashboard at `http://localhost:7777` |
| `frapast scan [path]` | Run a static scan, optionally with `--prove`, `--diff`, `--format` |
| `frapast prove [path]` | Run active proof verification on existing findings |
| `frapast shell [path]` | Interactive REPL with history and tab completion |
| `frapast report` | Render a Markdown security track-record report |
| `frapast fp-report` | Summarize false-positive categorization from your fp-log |
| `frapast bench-check` | Diagnose connectivity to a local/remote Frappe bench |
| `frapast fix` / `frapast pr` | Stage automated patches and generate a pull request |

Findings can be persisted to a YAML ledger (`--write-ledger`) for tracking over time, deduplicated by `(rule_id, file, line, code_location_hash)` so re-scans don't create noise.

---

## Rule taxonomy

29 detectors across 10 categories, spanning injection, authorization, workflow integrity, and code correctness.

### Injection

| Rule ID | Severity | Description |
|---|:---:|---|
| `FR-SQLI-001` | 🔴 Critical | String interpolation in `frappe.db.sql()` |
| `FR-SQLI-002` | 🔴 Critical | Formatted/`%`-style parameter substitution in SQL |
| `FR-SQLI-003` | 🟠 High | Dynamic SQL table/column identifier concatenation |
| `FR-SQLI-004` | 🟠 High | Unsanitized `ORDER BY` clause interpolation |
| `FR-INJ-001` | 🔴 Critical | Unsafe dynamic code execution (`eval` / `exec`) |
| `FR-INJ-002` | 🔴 Critical | Unsafe OS command execution (`os.system`, `shell=True`) |
| `FR-INJ-005` | 🟠 High | Unescaped HTML rendering in Jinja / script reports (XSS) |
| `FR-SSRF-001` | 🟠 High | Unsanitized URL passed to `requests.get()` / `make_get_request()` |
| `FR-CSRF-001` | 🟠 High | `GET` endpoint performing a state-changing write |

### Permissions

| Rule ID | Severity | Description |
|---|:---:|---|
| `FR-PERM-001` | 🟠 High | Missing DocType permission check in `@frappe.whitelist` |
| `FR-PERM-002` | 🟠 High | Unrestricted `ignore_permissions=True` |
| `FR-PERM-003` | 🟠 High | Direct SQL write bypassing permission checks |
| `FR-PERM-006` | 🟠 High | Permission query handler returns unfiltered SQL condition |
| `FR-PERM-004` | 🟡 Medium | Guest endpoint missing rate limiting |
| `FR-PERM-005` | 🟡 Medium | Insecure role assumption / unchecked role comparison |

### Lifecycle hooks

| Rule ID | Severity | Description |
|---|:---:|---|
| `FR-HOOK-001` | 🟡 Medium | Unisolated child table mutation in a hook |
| `FR-HOOK-002` | 🟡 Medium | Direct DB update in `doc_events`, bypassing the controller |
| `FR-HOOK-003` | 🟡 Medium | Unvalidated `docstatus` transition in a hook |
| `FR-HOOK-004` | 🟡 Medium | Infinite recursion risk (`doc.save()` inside `on_update`/`validate`) |
| `FR-HOOK-005` | 🟢 Low | Missing exception handling in an async background hook |

### Workflow integrity

| Rule ID | Severity | Description |
|---|:---:|---|
| `FR-WKFL-001` | 🟡 Medium | Direct `workflow_state` DB write, bypassing the workflow engine |
| `FR-WKFL-002` | 🟡 Medium | Document submitted without approval-state validation |
| `FR-WKFL-003` | 🟡 Medium | State machine transition bypass |
| `FR-WKFL-004` | 🟢 Low | Missing `on_cancel` handler in a workflow action |

### Code correctness, data & performance

| Rule ID | Severity | Description |
|---|:---:|---|
| `FR-HOOK-006` | 🟢 Low | Bare `except:` swallowing exceptions |
| `FR-HOOK-007` | 🟢 Low | Mutable default argument in a function signature |
| `FR-DATA-001` | 🟢 Low | Reference to a field that doesn't exist on the target DocType |
| `FR-PERF-001` | 🟢 Low | N+1 query pattern (`get_doc` inside a loop over `get_all`) |
| `FR-I18N-001` | 🟢 Low | User-facing string not wrapped in `frappe._()` |

Findings can be silenced inline with `# frapast:ignore` when you've reviewed and accepted the risk.

---

## How it works

```
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  Schema Index    │   │   Hook Index     │   │  Python Index   │
│  (DocType JSON)  │   │  (hooks.py AST)  │   │  (source AST)   │
└────────┬─────────┘   └────────┬─────────┘   └────────┬────────┘
         └──────────────────────┴───────────────────────┘
                                 │
                        ┌────────▼─────────┐
                        │   Call Graph      │  4 edge kinds:
                        │                   │  direct_call · string_dispatch
                        │                   │  hook_dispatch · dynamic_method
                        └────────┬──────────┘
                                 │
                        ┌────────▼─────────┐
                        │   Rule Engine      │  29 detectors, 10 categories
                        └────────┬──────────┘
                                 │
                        ┌────────▼──────────┐
                        │  Severity Scoring  │  4-dimension composite
                        └────────┬──────────┘
                                 │
               ┌─────────────────┴─────────────────┐
               ▼                                   ▼
      ┌────────────────┐                  ┌────────────────┐
      │  CLI (Rich UI)  │                  │  Web Dashboard  │
      └───────┬────────┘                  └───────┬────────┘
              └─────────────────┬─────────────────┘
                                 ▼
                        ┌────────────────┐
                        │  Proof Engine   │  Tier 0 → 1 → 2
                        └────────────────┘
```

1. **Indexing.** `SchemaIndex` parses every DocType JSON in your app; `HookIndex` walks `hooks.py` for `doc_events`, `override_whitelisted_methods`, and `scheduler_events`; `PythonSymbolIndex` parses your source with Python's `ast` module to find whitelisted endpoints, SQL calls, imports, and field references.
2. **Call graph.** These indexes feed a call graph connecting how code actually executes in Frappe — including string-based dispatch (`frappe.call("a.b.c")`) and hook-triggered execution that a naive call-graph would miss entirely.
3. **Rule engine.** All 29 rules run against the indexed, graph-connected codebase. Findings are deduplicated by `(rule_id, file, line, code_location_hash)` so re-scanning a stable codebase doesn't create duplicate noise.
4. **Severity scoring.** Every finding gets a composite score (see below) instead of a flat label.
5. **Proof engine (optional).** Findings can be escalated with runtime evidence — see [Proof Verification](#proof-verification).

---

## Severity scoring

Every finding is scored across four weighted dimensions rather than assigned a flat label:

```
Score = (privilege_weight × 3 + impact_weight × 4 + blast_radius_weight × 2 + proof_tier_weight) × guest_multiplier
```

| Dimension | Values (weight) |
|---|---|
| **Privilege required** | guest (5) · authenticated (4) · operational role (3) · elevated role (2) · system manager (1) |
| **Impact class** | RCE (5) · privilege escalation (4) · data corruption (3) · data exposure (2) · availability (2) |
| **Blast radius** | cross-site (5) · framework-wide (4) · cross-DocType (3) · single DocType (2) · single record (1) |
| **Proof tier** | Tier 0 (0) · Tier 1 (1) · Tier 2 (3) · Tier 3 (5) |

A `1.5×` multiplier applies to findings reachable by unauthenticated (guest) requests.

| Score | Triage bucket |
|---|---|
| ≥ 60 | 🔴 Critical |
| ≥ 40 | 🟠 High |
| ≥ 20 | 🟡 Medium |
| < 20 | 🟢 Low |

The lower the privilege required to trigger a finding and the wider its blast radius, the higher it scores — and a finding backed by active proof will always outrank an unverified one with the same static shape.

---

## Proof verification

A static match isn't proof of exploitability. frapAST can escalate any finding through three tiers of evidence:

| Tier | What it means |
|:---:|---|
| **Tier 0** | Static AST match only — no runtime verification. |
| **Tier 1** | A standalone reproducer script is generated and executed in an isolated local subprocess. |
| **Tier 2** | A live HTTP/RPC reproducer runs against a real (containerized or local) Frappe bench to confirm the vulnerability actually fires. |

```bash
frapast scan . --prove --bench-url http://localhost:8005 --bench-user Administrator
```

Each proof run returns a `ProofResult` with a status of `passed`, `failed`, `skipped` (no reproducer strategy exists yet for that rule), `error`, or `dry_run`, plus stdout/stderr and duration — so a finding that fails proof is documented, not just dropped.

---

## Dashboard

```bash
frapast
```

Opens a local web dashboard at `http://localhost:7777` (auto-falls back to the next free port up to `7786`).

- Live scan progress over Server-Sent Events
- Findings table with severity, proof status, and source snippets inline
- One-click proof runs — all findings, top 5, or a selected subset
- JSON / SARIF export and a Markdown compliance report, generated in-browser
- Bench connection config for Tier 2 proof, with a built-in connectivity check

**Security note:** the dashboard binds to `127.0.0.1` only and enforces origin gating — every request's `Origin` header must resolve to `localhost`, `127.0.0.1`, or `::1`, or it's rejected with `403`. Request bodies are capped at 5 MiB.

---

## Output formats

| Format | Flag / endpoint |
|---|---|
| Rich terminal tables | default |
| JSON | `--format json` · `GET /api/export/json` |
| YAML | `--format yaml` |
| SARIF 2.1.0 | `--format sarif` · `GET /api/export/sarif` — drop straight into GitHub code scanning |
| Markdown report | `frapast report` · `GET /api/report` |

---

## Configuration

Scan multiple repos and set defaults via `frapast.yaml`:

```yaml
repos:
  - path: "/path/to/erpnext"
    id: "erpnext"
    enabled: true
findings_dir: "findings"
fp_log: "findings/fp-log.yaml"
output_format: "yaml"
timeout_seconds: 300
max_retries: 3
```

```bash
frapast scan --config frapast.yaml
```

---

## Installation

```bash
pip install frapast

# with the interactive shell
pip install "frapast[shell]"

# for local development
pip install "frapast[dev]"
```

Requires **Python 3.10+**.

---

## Roadmap

- [ ] Tier 3 proof: auto-generated minimal reproduction scripts attached to each finding
- [ ] Taint tracking from `@frappe.whitelist` entry points through to dangerous sinks, to cut false positives further
- [ ] Frappe version-awareness (v14 vs v15 API differences)
- [ ] Cross-app analysis for custom apps that extend core DocTypes
- [ ] Public benchmark corpus of known-vulnerable Frappe fixtures for regression testing

Have an idea or a rule request? Open an issue — real-world false positives and false negatives are the most valuable input we get.

---

## Contributing

frapAST is strongest when it's tested against real Frappe/ERPNext codebases. Contributions of new rules, taint-tracking improvements, and false-positive reports are especially welcome.

```bash
git clone https://github.com/<your-org>/frapast.git
cd frapast
pip install -e ".[dev]"
pytest
```

If you found a security issue *in frapAST itself* (e.g. in the local dashboard server), please report it privately rather than opening a public issue — see `SECURITY.md`.

---

## License

MIT © 2026 Frappe Security Scanner Contributors — see [LICENSE](LICENSE).