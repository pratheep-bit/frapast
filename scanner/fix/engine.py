try:
    import libcst as cst
except ImportError:
    cst = None
from pathlib import Path

from scanner.rules import Candidate
from scanner.fix.fixers import (
    MutableDefaultArgFixer, 
    HardcodedStringI18nFixer,
    IgnorePermissionsGuardFixer,
    SqlDocstatusFilterFixer,
    DbSetValueHooksFixer,
    QbDynamicIdentifierFixer,
    PermissionCheckGuardFixer,
    WkflDocstatusGuardFixer,
    EnqueueDedupeKeyFixer,
)

def synthesize_fix(
    candidate: Candidate,
    repo_path: Path,
    schema=None,
    hooks=None,
) -> str | None:
    """
    Parses the candidate's file, applies the appropriate auto-fixer based on rule_id,
    and returns the patched source code. Returns None if the fix fails or is not supported.

    Optional ``schema`` (SchemaIndex) and ``hooks`` (HookIndex) enable row-level
    permission awareness for FR-PERM-001 fixes.
    """
    if cst is None or candidate.fix_confidence not in ("high", "medium"):
        return None

    file_path = repo_path / candidate.file
    if not file_path.exists():
        return None

    source_code = file_path.read_text(encoding="utf-8")
    
    try:
        tree = cst.parse_module(source_code)
        wrapper = cst.MetadataWrapper(tree)
    except Exception:
        return None

    fixer = None
    if candidate.rule_id == "FR-HOOK-007":
        fixer = MutableDefaultArgFixer(target_line=candidate.line, target_arg=candidate.target_arg)
    elif candidate.rule_id == "FR-I18N-001":
        fixer = HardcodedStringI18nFixer(target_line=candidate.line)
    elif candidate.rule_id == "FR-PERM-001":
        row_level = _compute_row_level_doctypes(schema, hooks)
        fixer = PermissionCheckGuardFixer(target_line=candidate.line, row_level_doctypes=row_level)
    elif candidate.rule_id == "FR-HOOK-004":
        fixer = EnqueueDedupeKeyFixer(target_line=candidate.line)
    elif candidate.rule_id == "FR-WKFL-001":
        fixer = WkflDocstatusGuardFixer(target_line=candidate.line)
    elif candidate.rule_id == "FR-PERM-002":
        # Needs a resolved doctype expression IgnorePermissionsGuardFixer can't
        # infer from the AST alone — routes to manual triage rather than raising.
        return None
    elif candidate.rule_id == "FR-SQLI-002":
        fixer = SqlDocstatusFilterFixer(target_line=candidate.line, docstatus_filter="docstatus < 2")
    elif candidate.rule_id == "FR-SQLI-003":
        fixer = DbSetValueHooksFixer(target_line=candidate.line, doc_var="_doc")
    elif candidate.rule_id == "FR-SQLI-004":
        # QbDynamicIdentifierFixer needs an allowed_values set only a human
        # can supply safely. Manual triage, not an automatic fix.
        return None
    
    if fixer is None:
        return None

    modified_tree = wrapper.visit(fixer)
    
    if fixer.patched:
        return modified_tree.code
    
    return None


def _compute_row_level_doctypes(schema, hooks) -> frozenset[str]:
    """Compute the set of doctype names with row-level permission rules."""
    names: set[str] = set()
    if schema is not None:
        for dt in schema.owner_scoped_doctypes():
            names.add(dt.name)
    if hooks is not None:
        names.update(hooks.permission_query_conditions.keys())
        names.update(hooks.has_permission.keys())
    return frozenset(names)

