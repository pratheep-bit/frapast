# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-18

### Added
- **Core Static Analysis Engine**:
  - DocType JSON schema parser indexing fields, permissions, `is_submittable`, and child table structures.
  - `hooks.py` parser indexing doc_events, override_whitelisted_methods, and scheduler events.
  - Python AST visitor extracting whitelisted endpoints, database calls, query builders, string dispatches, dynamic document methods, and script report entry points.
  - Interprocedural static call graph constructor connecting multi-hop call chains.
- **Rule Taxonomy (28 Active Detectors)**:
  - Injection & Access Control: `FR-SQLI-001`, `FR-SQLI-002`, `FR-SQLI-003`, `FR-SQLI-004`, `FR-INJ-001`, `FR-INJ-002`, `FR-PATH-001`, `FR-SSRF-001`, `FR-CSRF-001`.
  - Permissions: `FR-PERM-001`, `FR-PERM-002`, `FR-PERM-003`, `FR-PERM-004`, `FR-PERM-005`, `FR-PERM-006`.
  - Lifecycle & Workflow: `FR-HOOK-001`, `FR-HOOK-002`, `FR-HOOK-003`, `FR-HOOK-004`, `FR-HOOK-005`, `FR-WKFL-001`, `FR-WKFL-002`, `FR-WKFL-003`.
  - Reliability & Correctness: `FR-PERF-001`, `FR-HOOK-006`, `FR-HOOK-007`, `FR-DATA-001`, `FR-DATA-002`, `FR-DATA-003`, `FR-I18N-001`.
- **Two-Tier Active Proof Engine**:
  - Tier 1: Standalone executable AST verification reproducers.
  - Tier 2: Live HTTP RPC verification client (`FrappeHTTPClient` / `BenchRunner`) executing authenticated tests against running Frappe bench instances.
- **CLI Remediation Engine (`frapast fix`)**:
  - Unified diff preview and atomic in-place code modification for `FR-HOOK-001`, `FR-HOOK-004`, `FR-HOOK-006`, and `FR-PERM-001`.

### Changed (Breaking Taxonomy Renames)
- Standardized rule ID prefixing to align with the canonical 6-category taxonomy:
  - `FR-CORR-001` → `FR-HOOK-006` (Bare exception swallowing in controller/hook execution)
  - `FR-CORR-002` → `FR-HOOK-007` (Mutable default argument in function signatures)
  - `FR-XSS-001` → `FR-INJ-005` (Unsanitized HTML/template rendering in whitelisted endpoints)
- **Developer Experience**:
  - Frappe Bench native CLI command integration (`bench frapast`).
  - OASIS SARIF 2.1.0 output generation for GitHub Code Scanning integration.
  - Reusable GitHub Composite Action (`action.yml`).
  - Interactive local web dashboard with real-time SSE streaming and proof inspection.
- **Suppression & Baseline System**:
  - Line-shift resilient cryptographic finding fingerprints (`sha256(rule_id|file|function|code_location_hash)`).
  - Inline comment directives (`# nosemgrep: RULE_ID`, `# noqa: RULE_ID`, `# frapast: ignore RULE_ID`).
  - Configuration support via `.frapastignore` and `frapast.toml`.
