"""Autofix engine for frapAST findings."""
from __future__ import annotations

import ast
import difflib
import re
from pathlib import Path
from typing import Callable

from scanner.autofix.models import FixPatch


def _generate_diff(file_path: str | Path, original: str, modified: str) -> str:
    """Generate a unified diff between original and modified source."""
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="\n",
    )
    return "".join(diff)


# ---------------------------------------------------------------------------
# Rule Fixers
# ---------------------------------------------------------------------------


def fix_hook_001(file_path: Path, source: str, finding_data: dict) -> FixPatch | None:
    """FR-HOOK-001: Missing on_cancel in DocType controller.

    Appends a standardized on_cancel(self) handler to the Document subclass.
    """
    try:
        tree = ast.parse(source)
    except Exception:
        return None

    target_func = finding_data.get("function", "")
    target_class_name = target_func.split(".")[0] if "." in target_func else target_func

    target_class_node: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if target_class_name and node.name == target_class_name:
                target_class_node = node
                break
            # If function is not specified or top-level class, match the first class that has on_submit
            has_submit = any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "on_submit"
                for item in node.body
            )
            has_cancel = any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "on_cancel"
                for item in node.body
            )
            if has_submit and not has_cancel:
                target_class_node = node
                break

    if target_class_node is None:
        return None

    lines = source.splitlines(keepends=True)
    # Determine class indentation from the first method in the class
    class_indent = "    "
    for item in target_class_node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            item_line = lines[item.lineno - 1]
            match = re.match(r"^(\s+)", item_line)
            if match:
                class_indent = match.group(1)
                break

    cancel_method_lines = [
        f"\n",
        f"{class_indent}def on_cancel(self):\n",
        f"{class_indent}    # Automatically generated rollback handler by frapAST\n",
        f"{class_indent}    pass\n",
    ]

    # Insert after the last statement in the class
    last_node = target_class_node.body[-1]
    insert_line_idx = getattr(last_node, "end_lineno", last_node.lineno)

    new_lines = lines[:insert_line_idx] + cancel_method_lines + lines[insert_line_idx:]
    modified_source = "".join(new_lines)
    diff = _generate_diff(file_path, source, modified_source)

    return FixPatch(
        finding_id=str(finding_data.get("id") or finding_data.get("finding_id", "FR-HOOK-001")),
        rule_id="FR-HOOK-001",
        file_path=file_path,
        start_line=insert_line_idx + 1,
        end_line=insert_line_idx + len(cancel_method_lines),
        original_source=source,
        modified_source=modified_source,
        diff=diff,
        description="Add missing on_cancel(self) rollback handler to DocType controller",
    )


def fix_hook_004(file_path: Path, source: str, finding_data: dict) -> FixPatch | None:
    """FR-HOOK-004: Unhashed/un-deduplicated background job.

    Injects deduplicate=True into frappe.enqueue(...) calls.
    """
    target_line = finding_data.get("line")
    lines = source.splitlines(keepends=True)
    if not target_line or target_line > len(lines):
        return None

    orig_line = lines[target_line - 1]
    if "frappe.enqueue(" not in orig_line:
        # Check nearby lines in case multiline call
        found_idx = None
        for idx in range(max(0, target_line - 3), min(len(lines), target_line + 3)):
            if "frappe.enqueue(" in lines[idx]:
                found_idx = idx
                break
        if found_idx is None:
            return None
        target_line = found_idx + 1
        orig_line = lines[found_idx]

    if "deduplicate=" in orig_line or "job_name=" in orig_line:
        return None

    # Replace frappe.enqueue( with frappe.enqueue(deduplicate=True,
    # or append deduplicate=True
    if orig_line.strip().endswith("("):
        modified_line = orig_line.replace("frappe.enqueue(", "frappe.enqueue(deduplicate=True, ")
    elif orig_line.strip().endswith(")"):
        modified_line = re.sub(r"\)\s*$", ", deduplicate=True)\n", orig_line)
    else:
        modified_line = orig_line.replace("frappe.enqueue(", "frappe.enqueue(deduplicate=True, ")

    if modified_line == orig_line:
        return None

    new_lines = list(lines)
    new_lines[target_line - 1] = modified_line
    modified_source = "".join(new_lines)
    diff = _generate_diff(file_path, source, modified_source)

    return FixPatch(
        finding_id=str(finding_data.get("id") or finding_data.get("finding_id", "FR-HOOK-004")),
        rule_id="FR-HOOK-004",
        file_path=file_path,
        start_line=target_line,
        end_line=target_line,
        original_source=source,
        modified_source=modified_source,
        diff=diff,
        description="Add deduplicate=True to frappe.enqueue() to prevent queue flooding",
    )


def fix_hook_006(file_path: Path, source: str, finding_data: dict) -> FixPatch | None:
    """FR-HOOK-006: Bare except statement.

    Replaces `except:` with `except Exception:`.
    """
    target_line = finding_data.get("line")
    lines = source.splitlines(keepends=True)
    if not target_line or target_line > len(lines):
        return None

    orig_line = lines[target_line - 1]
    # Match bare except: with optional whitespace
    match = re.match(r"^(\s*)except\s*:\s*$", orig_line)
    if not match:
        return None

    indent = match.group(1)
    modified_line = f"{indent}except Exception:\n"

    new_lines = list(lines)
    new_lines[target_line - 1] = modified_line
    modified_source = "".join(new_lines)
    diff = _generate_diff(file_path, source, modified_source)

    return FixPatch(
        finding_id=str(finding_data.get("id") or finding_data.get("finding_id", "FR-HOOK-006")),
        rule_id="FR-HOOK-006",
        file_path=file_path,
        start_line=target_line,
        end_line=target_line,
        original_source=source,
        modified_source=modified_source,
        diff=diff,
        description="Replace bare except: with explicit except Exception:",
    )


def fix_perm_001(file_path: Path, source: str, finding_data: dict) -> FixPatch | None:
    """FR-PERM-001: Missing permission check on mutating whitelisted RPC.

    Injects frappe.only_for("System Manager") or permission check guard at start of function.
    """
    try:
        tree = ast.parse(source)
    except Exception:
        return None

    func_name = finding_data.get("function", "")
    short_name = func_name.split(".")[-1] if "." in func_name else func_name

    target_func_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == short_name:
            target_func_node = node
            break

    if target_func_node is None or not target_func_node.body:
        return None

    lines = source.splitlines(keepends=True)
    first_stmt = target_func_node.body[0]
    first_stmt_line_idx = first_stmt.lineno - 1

    # Extract indentation of the function body
    first_stmt_line = lines[first_stmt_line_idx]
    match = re.match(r"^(\s+)", first_stmt_line)
    body_indent = match.group(1) if match else "    "

    # If first statement is a docstring, insert after docstring
    if isinstance(first_stmt, ast.Expr) and isinstance(getattr(first_stmt, "value", None), ast.Constant):
        docstring_end = getattr(first_stmt, "end_lineno", first_stmt.lineno)
        insert_line_idx = docstring_end
    else:
        insert_line_idx = first_stmt_line_idx

    guard_line = f"{body_indent}frappe.only_for('System Manager')\n"
    new_lines = lines[:insert_line_idx] + [guard_line] + lines[insert_line_idx:]
    modified_source = "".join(new_lines)
    diff = _generate_diff(file_path, source, modified_source)

    return FixPatch(
        finding_id=str(finding_data.get("id") or finding_data.get("finding_id", "FR-PERM-001")),
        rule_id="FR-PERM-001",
        file_path=file_path,
        start_line=insert_line_idx + 1,
        end_line=insert_line_idx + 1,
        original_source=source,
        modified_source=modified_source,
        diff=diff,
        description="Inject frappe.only_for('System Manager') permission guard",
    )


# ---------------------------------------------------------------------------
# Router & Orchestrator
# ---------------------------------------------------------------------------

_FIXERS: dict[str, Callable[[Path, str, dict], FixPatch | None]] = {
    "FR-HOOK-001": fix_hook_001,
    "FR-HOOK-004": fix_hook_004,
    "FR-HOOK-006": fix_hook_006,
    "FR-PERM-001": fix_perm_001,
}


class FixEngine:
    """Orchestrates code patch synthesis and application."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def generate_patch(self, finding: dict) -> FixPatch | None:
        """Synthesize a patch for a single finding."""
        rule_id = str(finding.get("rule_id", ""))
        rel_file = str(finding.get("file", ""))
        if not rel_file:
            return None

        file_path = (self.workspace_root / rel_file).resolve()
        if not file_path.is_file():
            return None

        fixer = _FIXERS.get(rule_id)
        if fixer is None:
            return None

        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception:
            return None

        return fixer(file_path, source, finding)

    def generate_patches(self, findings: list[dict], rule_filter: str | None = None) -> list[FixPatch]:
        """Synthesize patches for all eligible findings."""
        patches: list[FixPatch] = []
        for f in findings:
            r_id = f.get("rule_id", "")
            if rule_filter and r_id != rule_filter:
                continue
            patch = self.generate_patch(f)
            if patch is not None:
                patches.append(patch)
        return patches

    def apply_patch(self, patch: FixPatch) -> bool:
        """Atomically write a patch to disk."""
        try:
            patch.file_path.write_text(patch.modified_source, encoding="utf-8")
            return True
        except Exception:
            return False
