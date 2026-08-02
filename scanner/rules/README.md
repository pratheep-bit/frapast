# Rule Engine

Rules are deterministic pure functions over `SchemaIndex`, `HookIndex`, and `PythonSymbolIndex`.
They emit `Candidate` records only. A candidate is Tier 0 until the runtime proof engine proves it.

Phase 1 includes:

- `FR-SQLI-001`
- `FR-SQLI-003`
- `FR-PERM-002`
- `FR-HOOK-004`
- `FR-WKFL-003`

The last three rule IDs are present as deterministic stubs when the Phase 1 AST scope does not expose the required signal. They must not invent filesystem access or expand AST scope silently.
