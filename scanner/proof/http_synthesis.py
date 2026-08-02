"""Tier 2 (http_rpc) Reproducer Synthesizer for FR-PERM-001 findings."""
from __future__ import annotations

import ast
from pathlib import Path

from scanner.proof.models import PROOF_MODE_MARKER


def file_to_module_path(file_path_str: str) -> str | None:
    """
    Converts a relative file path (e.g. 'hrms/api/__init__.py' or 'hr/doctype/goal/goal.py')
    to its Frappe dotted module path (e.g. 'hrms.api' or 'hrms.hr.doctype.goal.goal').
    """
    p = Path(file_path_str)
    parts = list(p.parts)
    if not parts:
        return None

    # Strip .py extension
    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts.pop()

    # Ensure app name 'hrms' is prefix
    if parts and parts[0] != "hrms":
        parts.insert(0, "hrms")

    return ".".join(parts) if parts else None


def analyze_endpoint_ast(source_code: str, target_function: str, target_line: int) -> dict:
    """
    Parses function AST to determine if it is allow_guest=True, self-scoped, or ambiguous.
    Returns a info dict: {'is_allow_guest': bool, 'is_self_scoped': bool, 'valid': bool}
    """
    try:
        tree = ast.parse(source_code)
    except Exception:
        return {"valid": False}

    func_name = target_function.split(".")[-1]
    target_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == func_name or getattr(node, "lineno", 0) == target_line:
                target_node = node
                break

    if not target_node:
        return {"valid": False}

    is_allow_guest = False
    for dec in target_node.decorator_list:
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "allow_guest" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    is_allow_guest = True

    is_self_scoped = False
    for child in ast.walk(target_node):
        if isinstance(child, ast.Attribute) and child.attr == "user":
            if isinstance(child.value, ast.Attribute) and child.value.attr == "session":
                if isinstance(child.value.value, ast.Name) and child.value.value.id == "frappe":
                    is_self_scoped = True
                    break

    return {
        "valid": True,
        "is_allow_guest": is_allow_guest,
        "is_self_scoped": is_self_scoped,
    }


def synthesize_http_rpc_reproducer(
    reproducers_dir: Path,
    finding_id: str,
    finding_data: dict,
    repo_path: Path,
) -> Path | None:
    """
    Synthesizes a Tier 2 (http_rpc) reproducer script for FR-PERM-001 candidates.
    Abstains (returns None) if candidate is ambiguous, allow_guest, or self-scoped.
    """
    rule_id = finding_data.get("rule_id", "")
    if rule_id != "FR-PERM-001":
        return None

    target_file = finding_data.get("file", "")
    target_function = finding_data.get("function", "")
    target_line = finding_data.get("line", 1)

    if not target_file or not target_function:
        return None

    full_file_path = repo_path / target_file
    if not full_file_path.exists():
        full_file_path = repo_path / "hrms" / target_file
    if not full_file_path.exists():
        return None

    source_code = full_file_path.read_text(encoding="utf-8", errors="ignore")
    analysis = analyze_endpoint_ast(source_code, target_function, target_line)
    if not analysis.get("valid") or analysis.get("is_allow_guest") or analysis.get("is_self_scoped"):
        return None

    module_path = file_to_module_path(target_file)
    if not module_path:
        return None

    dotted_method = f"{module_path}.{target_function}"

    reproducers_dir.mkdir(parents=True, exist_ok=True)
    out_path = reproducers_dir / f"{finding_id}.sh"

    script_body = f"""{PROOF_MODE_MARKER} http_rpc
#!/usr/bin/env bash
python3 -c "
import sys
from scanner.proof.http_client import make_frappe_request

base_url = 'http://localhost:8000'
status, body = make_frappe_request(
    base_url=base_url,
    method_path='{dotted_method}',
    username='test_low_priv@example.com',
    password='password',
)

# Candidate is vulnerable (unprotected endpoint) if low-privilege call succeeds (200 OK)
if status == 200:
    print('Vulnerability confirmed: low-privilege user accessed whitelisted endpoint {dotted_method}')
    sys.exit(0)
else:
    print(f'Assertion failed: endpoint returned HTTP {{status}}, body: {{body}}')
    sys.exit(1)
"
"""

    out_path.write_text(script_body, encoding="utf-8")
    out_path.chmod(0o755)
    return out_path
