from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

import yaml

from scanner.proof.models import ProofResult, ProofStatus, PROOF_MODE_MARKER, VALID_PROOF_MODES

# ---------------------------------------------------------------------------
# Tier 1 reproducer helpers
# ---------------------------------------------------------------------------


def _write_reproducer(path: Path, content: str, mode: str) -> None:
    if mode not in VALID_PROOF_MODES:
        raise ValueError(f"mode must be one of {VALID_PROOF_MODES}, got {mode!r}")
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"{PROOF_MODE_MARKER} {mode}\n{content}")
        os.chmod(tmp_name, 0o755)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


# Rules whose Tier 1 proof was previously synthesized as a bare file-existence
# check ("if file exists → exit 0 → PASSED"). A file-existence check is not
# runtime proof of exploitability: it fires on any false positive that lives in
# an existing file, which is every false positive. These rules require either a
# Tier 2 HTTP/RPC proof (handled by http_synthesis.py) or a real AST assertion.
# Until a proper Tier 1 strategy exists for each, we return None here so the
# orchestrator issues ProofStatus.SKIPPED with an honest message rather than a
# misleading PASSED.
#
# NOTE: FR-HOOK-001, FR-HOOK-003, FR-HOOK-004, FR-HOOK-006, FR-DATA-001,
# FR-PERF-001, FR-WKFL-003, FR-WKFL-004 have been promoted out of this set —
# they now have real Tier 1 AST assertions below. Only the Tier 2 HTTP/RPC
# rules (proven via http_synthesis.py, not this function) remain here, plus
# FR-HOOK-005, FR-I18N-001, and FR-WKFL-002 which still lack any Tier 1
# strategy.
_FILE_EXISTENCE_ONLY_RULES = frozenset({
    "FR-PERM-001", "FR-PERM-002",
    "FR-SQLI-003", "FR-SQLI-004",
    "FR-INJ-001", "FR-INJ-002",
})


# ---------------------------------------------------------------------------
# Shared AST helper source, inlined into every generated Tier 1 script.
#
# Each Tier 1 reproducer is a standalone bash script (it runs via
# `bash reproducer.sh` in a subprocess, possibly on a different checkout of
# the target repo, at a later time) so it cannot import a shared Python
# module from frapAST itself. We therefore duplicate this small helper
# library, verbatim, into each generated script body rather than reaching
# outside the sandbox — same approach as the FR-HOOK-007 reference impl.
# ---------------------------------------------------------------------------
_AST_HELPERS = """
def _contains_line(node, line):
    start = getattr(node, 'lineno', None)
    end = getattr(node, 'end_lineno', start)
    if start is None:
        return False
    return start <= line <= (end if end is not None else start)


def _call_name(call):
    func = call.func
    if isinstance(func, ast.Attribute):
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))
    if isinstance(func, ast.Name):
        return func.id
    return ''


def _enclosing(tree, line, node_types):
    candidates = [n for n in ast.walk(tree) if isinstance(n, node_types) and _contains_line(n, line)]
    if not candidates:
        return None
    # Innermost enclosing node = the one whose body starts latest (deepest nesting).
    return max(candidates, key=lambda n: getattr(n, 'lineno', 0))


def _import_aliases(tree):
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                aliases[a.asname or a.name] = f'{node.module}.{a.name}'
        elif isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name] = a.name
    return aliases


def _canonical_name(name, aliases):
    if not name:
        return name
    parts = name.split('.')
    parts[0] = aliases.get(parts[0], parts[0])
    return '.'.join(parts)
""".strip("\n")


def synthesize_reproducer_if_missing(reproducers_dir: Path, finding_id: str, finding_data: dict) -> Path | None:
    """Synthesize a Tier 1 python/bash reproducer script for direct AST/code structure checks.

    Returns None for rules that have no meaningful Tier 1 strategy so that the
    orchestrator emits ProofStatus.SKIPPED rather than a misleading PASSED based
    solely on file existence.

    Security note: target_file and target_line are sanitized (shlex.quote /
    int()) before interpolation into shell scripts to prevent injection from
    crafted file paths in a scanned repo. Any additional untrusted strings
    pulled from finding_data (target_arg, evidence, function name) are passed
    through the same `export FOO={shlex.quote(...)}` + `os.environ.get(...)`
    pattern rather than interpolated directly into Python source.
    """
    rule_id = finding_data.get("rule_id", "")
    target_file = str(finding_data.get("file", ""))
    try:
        target_line = int(finding_data.get("line", 1))
    except (TypeError, ValueError):
        target_line = 1
    target_arg = finding_data.get("target_arg") or ""
    evidence = finding_data.get("evidence") or ""

    # Rules that only had a file-existence check: return None → caller emits SKIPPED.
    if rule_id in _FILE_EXISTENCE_ONLY_RULES:
        return None

    if "\n" in target_file or "\r" in target_file:
        # Reject filenames with embedded newlines to prevent heredoc boundary corruption
        return None

    reproducers_dir.mkdir(parents=True, exist_ok=True)
    out_path = reproducers_dir / f"{finding_id}.sh"

    if rule_id == "FR-HOOK-007":
        # Real AST assertion: check for mutable default argument at the
        # specific line number reported by the scanner.
        # Pass target_file via bash environment variable to prevent Python string
        # literal escaping corruption (e.g. backslashes treated as escape codes).
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

tree = ast.parse(file_path.read_text(encoding='utf-8'))
for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and getattr(node, 'lineno', 0) == {target_line}:
        for d in node.args.defaults:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                print('Mutable default detected')
                sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-HOOK-006":
        # Bare/broad `except:` block swallowing signals: locate the ast.Try
        # enclosing target_line and check whether any handler catches
        # everything (bare `except:`) or explicitly catches
        # Exception/BaseException.
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

{_AST_HELPERS}


def _is_bare_or_broad(handler):
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name) and handler.type.id in ('BaseException', 'Exception'):
        return True
    if isinstance(handler.type, ast.Tuple):
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name) and elt.id in ('BaseException', 'Exception'):
                return True
    return False


for node in ast.walk(tree):
    if isinstance(node, ast.Try) and _contains_line(node, target_line):
        for handler in node.handlers:
            if _is_bare_or_broad(handler):
                print('Bare/broad except block confirmed')
                sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-HOOK-004":
        # frappe.enqueue() without a dedup/lock key: find the Call node
        # covering target_line and check its keyword args for job_id,
        # deduplicate, or queue.
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

{_AST_HELPERS}

_DEDUP_KEYS = {{'job_id', 'deduplicate', 'queue'}}

_aliases = _import_aliases(tree)
for node in ast.walk(tree):
    if isinstance(node, ast.Call) and _contains_line(node, target_line):
        name = _canonical_name(_call_name(node), _aliases)
        if name in ('frappe.enqueue', 'enqueue') or name.endswith('.enqueue'):
            kw_names = {{kw.arg for kw in node.keywords if kw.arg}}
            if not (_DEDUP_KEYS & kw_names):
                print('enqueue() without dedup/lock key confirmed')
                sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-PERF-001":
        # N+1 query in loop: find the for/while loop covering target_line
        # and check whether its body contains a get_doc/get_value call.
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

{_AST_HELPERS}

_QUERY_CALLS = {{'frappe.get_doc', 'frappe.get_value', 'frappe.db.get_value', 'get_doc', 'get_value'}}

_aliases = _import_aliases(tree)
for node in ast.walk(tree):
    if isinstance(node, (ast.For, ast.While)) and _contains_line(node, target_line):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and _canonical_name(_call_name(sub), _aliases) in _QUERY_CALLS:
                print('Query call inside loop confirmed')
                sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-HOOK-001":
        # on_submit defined without on_cancel in the same controller class.
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

{_AST_HELPERS}

cls = _enclosing(tree, target_line, (ast.ClassDef,))
if cls is None:
    sys.exit(1)

methods = {{n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}}
if 'on_submit' in methods and 'on_cancel' not in methods:
    print('on_submit without on_cancel confirmed')
    sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-WKFL-003":
        # frappe.db.set_value writing 'status' without a matching 'docstatus'
        # update in the same enclosing function.
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

{_AST_HELPERS}


def _set_value_targets_field(call, field_name):
    args = call.args
    # frappe.db.set_value(doctype, name, {{'status': ..., 'docstatus': ...}})
    if len(args) >= 3 and isinstance(args[2], ast.Dict):
        for k in args[2].keys:
            if isinstance(k, ast.Constant) and k.value == field_name:
                return True
    # frappe.db.set_value(doctype, name, 'status', value)
    if len(args) >= 3 and isinstance(args[2], ast.Constant) and args[2].value == field_name:
        return True
    for kw in call.keywords:
        if kw.arg == 'fieldname' and isinstance(kw.value, ast.Constant) and kw.value.value == field_name:
            return True
    return False


func = _enclosing(tree, target_line, (ast.FunctionDef, ast.AsyncFunctionDef))
if func is None:
    sys.exit(1)

_aliases = _import_aliases(tree)
sets_status = False
sets_docstatus = False
for sub in ast.walk(func):
    if isinstance(sub, ast.Call):
        name = _canonical_name(_call_name(sub), _aliases)
        if name in ('frappe.db.set_value', 'set_value') or name.endswith('.set_value'):
            if _set_value_targets_field(sub, 'status'):
                sets_status = True
            if _set_value_targets_field(sub, 'docstatus'):
                sets_docstatus = True

if sets_status and not sets_docstatus:
    print('status write without docstatus update confirmed')
    sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-WKFL-004":
        # Submittable class (has on_submit) missing before_insert/after_insert.
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

{_AST_HELPERS}

cls = _enclosing(tree, target_line, (ast.ClassDef,))
if cls is None:
    sys.exit(1)

methods = {{n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}}
if 'on_submit' in methods and 'before_insert' not in methods and 'after_insert' not in methods:
    print('submittable class missing before_insert/after_insert confirmed')
    sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-HOOK-003":
        # Whitelisted API fast-path calling db.set_value directly without
        # going through doc.validate()/doc.save().
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

{_AST_HELPERS}


def _is_whitelisted(func_node, aliases):
    for dec in func_node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, (ast.Attribute, ast.Name)):
            name = _canonical_name(_call_name(ast.Call(func=target, args=[], keywords=[])), aliases)
            if name in ('frappe.whitelist', 'whitelist'):
                return True
    return False


func = _enclosing(tree, target_line, (ast.FunctionDef, ast.AsyncFunctionDef))
if func is None:
    sys.exit(1)

_aliases = _import_aliases(tree)
has_set_value = False
has_validate_or_save = False
for sub in ast.walk(func):
    if isinstance(sub, ast.Call):
        name = _canonical_name(_call_name(sub), _aliases)
        if name in ('frappe.db.set_value', 'set_value') or name.endswith('.set_value'):
            has_set_value = True
        if name.endswith('.validate') or name.endswith('.save') or name in ('validate', 'save'):
            has_validate_or_save = True

if _is_whitelisted(func, _aliases) and has_set_value and not has_validate_or_save:
    print('whitelisted fast-path db.set_value without validation confirmed')
    sys.exit(0)
sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    if rule_id == "FR-DATA-001":
        # Reference to a bad/non-existent fieldname: confirm the field name
        # captured by the scanner (target_arg, falling back to evidence) is
        # still referenced (as an attribute, string literal, or subscript
        # key) at target_line. If the field name isn't available at all we
        # cannot re-verify anything meaningful, so we refuse to synthesize
        # a script (None → SKIPPED) rather than emit a vacuous PASS/FAIL.
        field_name = target_arg
        if not field_name and evidence:
            _m = re.search(r"""['"]([A-Za-z_][A-Za-z0-9_]*)['"]""", evidence)
            field_name = _m.group(1) if _m else ""
        if not field_name:
            return None
        script_body = f"""#!/usr/bin/env bash
export FRAPAST_TARGET_FILE={shlex.quote(target_file)}
export FRAPAST_TARGET_FIELD={shlex.quote(field_name)}
python3 - <<'PYEOF'
import ast, os, sys
from pathlib import Path

target_file = os.environ.get('FRAPAST_TARGET_FILE', '')
target_field = os.environ.get('FRAPAST_TARGET_FIELD', '')
target_line = {target_line}

file_path = Path(target_file)
if not file_path.exists():
    sys.exit(1)

if not target_field:
    sys.exit(1)

try:
    tree = ast.parse(file_path.read_text(encoding='utf-8'))
except SyntaxError:
    sys.exit(1)

for node in ast.walk(tree):
    lineno = getattr(node, 'lineno', None)
    if lineno != target_line:
        continue
    if isinstance(node, ast.Attribute) and node.attr == target_field:
        print('Bad fieldname reference (attribute) confirmed')
        sys.exit(0)
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value == target_field:
        print('Bad fieldname reference (string literal) confirmed')
        sys.exit(0)
    if isinstance(node, ast.Subscript):
        sl = node.slice
        # Py3.9+: node.slice is the index expression directly.
        if isinstance(sl, ast.Constant) and sl.value == target_field:
            print('Bad fieldname reference (subscript) confirmed')
            sys.exit(0)

sys.exit(1)
PYEOF
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path

    return None


# ---------------------------------------------------------------------------
# Proof mode detection helper
# ---------------------------------------------------------------------------


def _detect_proof_mode(reproducer_path: Path) -> str:
    """Read the PROOF_MODE marker from the first 3 lines of a reproducer script."""
    try:
        lines = reproducer_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in lines[:3]:
            stripped = line.strip()
            if stripped.startswith(PROOF_MODE_MARKER):
                mode = stripped[len(PROOF_MODE_MARKER):].strip()
                if mode in VALID_PROOF_MODES:
                    return mode
    except OSError:
        pass
    return "direct_call"  # safe default — runs via bash


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class ProofOrchestrator:
    """Orchestrates runtime proof execution for Tier 1 (direct_call) and Tier 2 (http_rpc)."""

    def __init__(
        self,
        workspace_root: str | Path,
        findings_dir: str | Path = "findings",
        reproducers_dir: str | Path = "runtime/reproducers",
        proofs_dir: str | Path = "runtime/proofs",
        dry_run: bool = False,
        timeout_seconds: int = 30,
        bench_url: str = "",
        bench_user: str = "",
        bench_password: str = "",
        bench_site_name: str = "",
    ) -> None:
        self.workspace_root = Path(workspace_root)
        self.findings_dir = self.workspace_root / findings_dir
        self.reproducers_dir = self.workspace_root / reproducers_dir
        self.proofs_dir = self.workspace_root / proofs_dir
        self.dry_run = dry_run
        self.timeout_seconds = timeout_seconds
        self.bench_url = bench_url.strip()
        self.bench_user = bench_user.strip()
        self.bench_password = bench_password.strip()
        self.bench_site_name = bench_site_name.strip()
        self._bench_runner: object | None = None

    def prune_old_reproducers(self, max_scripts: int = 1000) -> None:
        """Removes the oldest cached reproducer scripts if count exceeds max_scripts."""
        if not self.reproducers_dir.is_dir():
            return
        try:
            scripts = sorted(self.reproducers_dir.glob("FR-*.sh"), key=lambda p: p.stat().st_mtime)
            if len(scripts) > max_scripts:
                for old in scripts[: len(scripts) - max_scripts]:
                    old.unlink(missing_ok=True)
                    old.with_suffix(".version").unlink(missing_ok=True)
        except Exception:
            pass

    def discover_reproducers(self) -> dict[str, Path]:
        """Discover reproducer scripts in the reproducers directory.

        Reads a .version sidecar file next to each FR-*.sh script. If the
        sidecar is absent or its version does not match the current
        SYNTHESIS_VERSION (from http_synthesis.py), the stale script is
        deleted and excluded from the returned map so prove_candidate()
        will resynthesize it with up-to-date (hardened) logic.
        """
        from scanner.proof.http_synthesis import SYNTHESIS_VERSION

        reproducers: dict[str, Path] = {}
        if not self.reproducers_dir.is_dir():
            return reproducers
        for path in sorted(self.reproducers_dir.glob("FR-*.sh")):
            finding_id = path.stem
            sidecar = path.with_suffix(".version")
            # Check version — stale scripts are silently regenerated, never reused
            if sidecar.exists():
                on_disk_version = sidecar.read_text(encoding="utf-8").strip()
                if on_disk_version != SYNTHESIS_VERSION:
                    # Version mismatch: delete stale script + sidecar, skip
                    path.unlink(missing_ok=True)
                    sidecar.unlink(missing_ok=True)
                    continue
            else:
                # No sidecar means the script was generated before versioning
                # was introduced (pre-hardening). Treat as stale.
                path.unlink(missing_ok=True)
                continue
            reproducers[finding_id] = path
        return reproducers

    def discover_unproven_findings(self) -> list[tuple[str, Path]]:
        return []

    def prove_candidate(self, finding_id: str, candidate_data: dict | None = None) -> ProofResult:
        reproducers = self.discover_reproducers()
        reproducer_path = reproducers.get(finding_id)

        if reproducer_path is None and candidate_data is not None:
            if self.dry_run:
                return ProofResult(
                    finding_id=finding_id,
                    status=ProofStatus.DRY_RUN,
                    proof_tier=0,
                    exit_code=0,
                    stdout="[dry-run] skipped reproducer synthesis",
                    stderr="",
                    duration_seconds=0.0,
                    reproducer_path="",
                )
            rule_id = candidate_data.get("rule_id", "")
            _HTTP_PROVABLE = {
                "FR-PERM-001", "FR-PERM-002", "FR-PERM-003",
                "FR-SQLI-001", "FR-SQLI-003", "FR-SQLI-004",
                "FR-INJ-001", "FR-INJ-002",
                "FR-CSRF-001", "FR-SSRF-001",
            }
            if rule_id in _HTTP_PROVABLE:
                from scanner.proof.http_synthesis import synthesize_http_rpc_reproducer
                reproducer_path = synthesize_http_rpc_reproducer(
                    self.reproducers_dir, finding_id, candidate_data, self.workspace_root
                )
            if reproducer_path is None:
                reproducer_path = synthesize_reproducer_if_missing(
                    self.reproducers_dir, finding_id, candidate_data
                )

        if reproducer_path is None or not reproducer_path.is_file():
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.SKIPPED,
                proof_tier=0,
                exit_code=None,
                stdout="",
                stderr="No reproducer script found.",
                duration_seconds=0.0,
                reproducer_path="",
                error_message=f"No reproducer found for {finding_id}",
            )

        proof_mode = _detect_proof_mode(reproducer_path)

        if proof_mode == "http_rpc":
            return self._run_tier2(finding_id, candidate_data or {}, reproducer_path)
        else:
            return self._run_tier1(finding_id, reproducer_path)

    def _run_tier1(self, finding_id: str, reproducer_path: Path) -> ProofResult:
        if self.dry_run:
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.DRY_RUN,
                proof_tier=0,
                exit_code=0,
                stdout="Dry run",
                stderr="",
                duration_seconds=0.0,
                reproducer_path=str(reproducer_path),
            )

        start = time.monotonic()
        try:
            res = subprocess.run(
                ["bash", str(reproducer_path)],
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            duration = time.monotonic() - start
            if res.returncode == 0:
                status = ProofStatus.PASSED
                tier = 1
            else:
                status = ProofStatus.FAILED
                tier = 0
            return ProofResult(
                finding_id=finding_id,
                status=status,
                proof_tier=tier,
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                duration_seconds=duration,
                reproducer_path=str(reproducer_path),
            )
        except Exception as exc:
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.ERROR,
                proof_tier=0,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                duration_seconds=time.monotonic() - start,
                reproducer_path=str(reproducer_path),
                error_message=str(exc),
            )

    def _bench_configured(self) -> bool:
        if not self.bench_url:
            env_url = os.environ.get("FRAPAST_BENCH_URL")
            if env_url:
                self.bench_url = env_url
            else:
                from scanner.proof.bench_runner import auto_detect_bench_url
                detected = auto_detect_bench_url()
                if detected:
                    self.bench_url = detected
        return bool(self.bench_url)

    def _get_bench_runner(self):
        if self._bench_runner is None:
            from scanner.proof.bench_runner import BenchRunner
            kwargs: dict[str, object] = {
                "base_url": self.bench_url,
                "timeout": self.timeout_seconds,
                "dry_run": self.dry_run,
                "workspace_root": self.workspace_root,
                "reproducers_dir": self.reproducers_dir,
            }
            if self.bench_user:
                kwargs["username"] = self.bench_user
            if self.bench_password:
                kwargs["password"] = self.bench_password
            if self.bench_site_name:
                kwargs["site_name"] = self.bench_site_name
            self._bench_runner = BenchRunner(**kwargs)
        return self._bench_runner

    def _run_tier2(self, finding_id: str, candidate_data: dict, reproducer_path: Path) -> ProofResult:
        if not self._bench_configured():
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.SKIPPED,
                proof_tier=2,
                exit_code=None,
                stdout="",
                stderr="",
                duration_seconds=0.0,
                reproducer_path=str(reproducer_path),
                error_message=(
                    "Tier 2 HTTP proof skipped: no bench configured. "
                    "Pass --bench-url (and optionally --bench-user / --bench-password) "
                    "to the `prove` command, or set FRAPAST_BENCH_URL in your environment."
                ),
            )

        runner = self._get_bench_runner()
        return runner.run_http_proof(finding_id, candidate_data)
