# Changelog

All notable changes to the Frappe Security Scanner are documented in this file.

## [1.2.0] - 2026-08-02

### Added
- **Dynamic Findings Directory Discovery**: Updated `validate_ledger.py` and `verify_ledger_integrity.py` to use `discover_all_findings_dirs()` for full coverage across legacy `findings_latest_*` directories.
- **GC-Safe Rule Cache**: Upgraded `_ENDPOINT_REACHABLE_CACHE` and `_REACHABLE_CACHE` in `rules/engine.py` to validate `python` and `graph` object identities. Exposed `clear_rule_caches()`.
- **Structured Logging**: Created `scanner/logger.py` with standard `logging` levels to replace raw `print()` statements.
- **Config Wiring**: Wired up `timeout_seconds`, `max_retries`, and `output_format` settings from `ScanConfig`.
- **Dev Scaffolding**: Added `scanner/.agents/AGENTS.md` and `CONTRIBUTING.md`.
- **Comprehensive Unit Tests**: Added `tests/test_all_rules.py` covering static detection rules.

## [1.1.0] - 2026-07-25

### Fixed
- **Frozen Instance Mutation**: Added `Candidate.with_status()` method to prevent `FrozenInstanceError`.
- **Taxonomy Alignment**: Fixed `FR-HOOK-006` and `FR-HOOK-007` rule ID output consistency.
- **Severity Score Persistence**: Guaranteed severity scores are saved to findings YAML during ledger writes.
- **Reproducer Markers**: Introduced `# PROOF_MODE: direct_call` and `http_rpc` markers for reproducer scripts.

## [1.0.0] - 2026-07-15

### Added
- Initial release of Frappe Security Scanner.
- Python AST indexer, DocType JSON schema parser, and `hooks.py` event indexer.
- CallGraph reachability engine for string dispatches (`frappe.call`) and dynamic method calls.
- Proof Orchestrator for containerized Frappe bench verification.
- LibCST auto-fix synthesis and GitHub PR automation engine.
