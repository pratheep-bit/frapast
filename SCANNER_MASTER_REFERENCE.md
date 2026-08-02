# 🛡️ Frappe Security Scanner — Master Reference Manual

An enterprise-grade, static-analysis and runtime-proof security engine built specifically for the **Frappe Framework ecosystem** (Frappe core, ERPNext, HRMS, and custom Frappe apps).

---

## 1. Executive Summary

The Frappe Security Scanner detects security flaws, access control bypasses, and state-machine violations in Frappe applications. Unlike standard static analysis tools that flood developers with false positives, this scanner enforces a **mandatory runtime proof gate** before any candidate vulnerability is promoted for automated fix synthesis or Pull Request creation.

---

## 2. Pipeline Architecture

The scanner operates across 6 sequential phases:

```mermaid
flowchart TD
    subgraph "Phase 0: Multi-Index Generation"
        A1["DocType Schema Indexer"]
        A2["hooks.py RPC/Event Indexer"]
        A3["Python AST Symbol Indexer"]
        A4["CallGraph Builder (String/Hook/Dynamic Dispatch)"]
    end

    subgraph "Phase 1: Rule Detection & FP Filtering"
        B1["Rule Execution Engine (27 Rules)"]
        B2["Framework FP Suppressor (fp-log.yaml)"]
        A1 & A2 & A3 & A4 --> B1 --> B2
    end

    subgraph "Phase 2: Severity & Ledger Persistence"
        C1["Contextual Severity Scorer"]
        C2["Atomic Ledger Writer (findings/*.yaml)"]
        B2 --> C1 --> C2
    end

    subgraph "Phase 3: Runtime Proof Engine"
        D1["Proof Orchestrator (Docker Bench Container)"]
        D2["Reproducer Script Execution (# PROOF_MODE)"]
        C2 --> D1 --> D2
    end

    subgraph "Phase 4: Automated Fix Synthesis"
        E1["LibCST Transformer Fixers (9 Auto-Fixers)"]
        E2["Static Bytecode & Syntax Validation Gate"]
        D2 -->|Proof Passed (Tier 2+)| E1 --> E2
    end

    subgraph "Phase 5: Automated PR Routing"
        F1["Git Worktree + GitHub CLI (gh pr create)"]
        E2 --> F1
    end
```

---

## 3. Core Taxonomy & Rules Registry

The scanner enforces 27 rules across 6 primary security families:

| Family | Category | Key Rule IDs | Description |
|---|---|---|---|
| **`FR-PERM`** | Permission & Access Control | `FR-PERM-001` - `FR-PERM-006` | Missing `has_permission()` in whitelisted RPC endpoints; `ignore_permissions=True` bypasses. |
| **`FR-SQLI`** | ORM vs Raw SQL Boundary | `FR-SQLI-001` - `FR-SQLI-004` | Format-string SQL injection in `frappe.db.sql()`; missing `docstatus` filter; raw `set_value`. |
| **`FR-HOOK`** | Hook & Lifecycle Safety | `FR-HOOK-001` - `FR-HOOK-007` | Asymmetric `on_submit` lifecycle hooks; missing job deduplication keys in `frappe.enqueue()`. |
| **`FR-WKFL`** | Workflow & State Machine | `FR-WKFL-001` - `FR-WKFL-004` | Status field mutation missing `docstatus` guard; submittable amendment chain reset missing. |
| **`FR-INJ`** | API & Injection Surfaces | `FR-INJ-001` - `FR-INJ-005` | Mass assignment via `get_doc(kwargs)`; dangerous `eval()`; unsanitized HTML rendering in RPC. |
| **`FR-DATA`** | Child Tables & Multi-Tenancy | `FR-DATA-001` - `FR-DATA-003` | DocType field name mismatches; child table orphan records; cross-tenant query leaks. |

---

## 4. Tiered Proof System & Reproducer Markers

Findings progress through 4 evidence tiers to ensure zero-false-positive PR automation:

| Tier | Status | Trigger / Mechanism | Requirement for PR |
|---|---|---|---|
| **Tier 0** | Candidate | Static AST rule match | ❌ Cannot trigger fix or PR |
| **Tier 1** | Direct Call Proven | Python reproducer script execution (`# PROOF_MODE: direct_call`) | ❌ Internal evidence only |
| **Tier 2** | HTTP RPC Proven | Authentic HTTP POST assertion against bench site (`# PROOF_MODE: http_rpc`) | ✅ **Mandatory Hard Gate** |
| **Tier 3** | Upstream Merged | PR merged into Frappe/ERPNext/HRMS upstream core | ✅ Upstream proof artifact |

```python
# Reproducer scripts MUST declare explicit PROOF_MODE header:
# PROOF_MODE: http_rpc
# Unmarked scripts stay at Tier 0 to prevent accidental promotion.
```

---

## 5. Automated Fix Synthesis (LibCST)

When a candidate achieves Tier 2+ proof, the fix engine applies automated LibCST code transformers:

- **`PermissionCheckGuardFixer`** (`FR-PERM-001`): Inserts explicit `frappe.has_permission(doctype, 'read', throw=True)` guards.
- **`WkflDocstatusGuardFixer`** (`FR-WKFL-001`): Inserts `if self.docstatus != 1: frappe.throw(...)` state guards.
- **`SqlDocstatusFilterFixer`** (`FR-SQLI-002`): Injects `WHERE docstatus < 2` into raw SQL queries.
- **`DbSetValueHooksFixer`** (`FR-SQLI-003`): Replaces direct `frappe.db.set_value` database bypasses with ORM `.save()`.
- **`EnqueueDedupeKeyFixer`** (`FR-HOOK-004`): Generates dynamic `job_id="{doctype}_{name}__{method}"` deduplication keys.
- **`MutableDefaultArgFixer`** (`FR-HOOK-007`): Replaces mutable default arguments `def f(opts={})` with `None` checks.

---

## 6. Architectural Hardening & Memory Safety

The scanner implements 5 critical architectural invariants:

1. **Frozen Dataclass Protection**: `Candidate` instances are immutable. All mutations use `Candidate.with_status()` or `dataclasses.replace()`.
2. **GC-Safe Double-Tuple Caching**: Reachability caches use `(id(python), id(graph))` identity keys and validate `cached[0] is python and cached[1] is graph` to prevent stale evaluation from Python GC address re-use.
3. **Multi-Directory Findings Discovery**: `discover_all_findings_dirs()` dynamically discovers `findings/` and sibling `findings_latest_*` directories.
4. **Validation Pipeline Gate**: `validate_and_stage()` byte-compiles generated code and rejects fixes that shrink file length by >50%.
5. **Atomic Disk Persistence**: `ledger_io.py` writes ledgers using `NamedTemporaryFile` + `os.replace` under thread-safe file locks.

---

## 7. Package Directory Structure

```
scanner/                          <- Workspace Root
├── pyproject.toml                <- PEP 621 build configuration
├── README.md                     <- Open-source product manual
├── CONTRIBUTING.md               <- Developer contribution guide
├── CHANGELOG.md                  <- Release & hardening history
├── Makefile                      <- Build, test, & docker targets
├── docker-compose.yml            <- Bench environment composition
│
├── scanner/                      <- Core Python Package
│   ├── __init__.py               <- Public API exports
│   ├── __main__.py               <- python -m scanner entrypoint
│   ├── cli.py                    <- CLI command dispatcher
│   ├── config.py                 <- ScanConfig & RepoConfig
│   ├── logger.py                 <- Structured logger
│   ├── ledger_io.py              <- Atomic ledger persistence
│   ├── validate_ledger.py        <- Ledger schema validation gate
│   ├── verify_ledger_integrity.py<- Reproducer hash integrity gate
│   ├── validate_taxonomy.py      <- Taxonomy alignment gate
│   ├── callgraph/                <- CallGraph builder
│   ├── fix/                      <- LibCST fix synthesis
│   ├── fp/                       <- FP suppression engine
│   ├── hooks/                    <- hooks.py AST indexer
│   ├── proof/                    <- Bench proof orchestrator
│   ├── python/                   <- Python AST indexer
│   ├── rules/                    <- Detection rules & registry
│   ├── schema/                   <- DocType JSON indexer
│   └── severity/                 <- Contextual severity scorer
│
├── tests/                        <- Unit & Acceptance Test Suite (24 Tests)
├── taxonomy/                     <- Taxonomy YAML Descriptors
├── data/                         <- Project Status & Datasets
└── .github/workflows/            <- GitHub Actions CI Pipeline
```

---

## 8. CLI & API Quick Reference

### Command Line Interface

```bash
# 1. Run static security scan against a Frappe app
PYTHONPATH=. python -m scanner scan /path/to/frappe_app --severity --write-ledger

# 2. Execute containerized bench proofs for unproven candidates
PYTHONPATH=. python -m scanner prove --workspace .

# 3. Synthesize LibCST auto-fix for proven findings
PYTHONPATH=. python -m scanner fix --finding-id FR-PERM-001-xxxx

# 4. Generate track-record precision report
PYTHONPATH=. python -m scanner report

# 5. Execute full validation test suite
PYTHONPATH=. python -m unittest discover -s tests/
```

### Python Public API

```python
from scanner import scan, scan_multi, execute_rules, ProofOrchestrator, synthesize_fix, load_config

# Load scan configuration
config = load_config("scanner.yaml")

# Run multi-repository scan
results = scan_multi("scanner.yaml", include_severity=True)

# Synthesize automated fix for candidate
fixed_code = synthesize_fix(candidate, repo_path)
```
