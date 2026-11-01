"""Unit tests for Phase 1 CVE-derived detection rules.

Covers:
- FR-SSTI-001: Server-Side Template Injection via eval/render_template
- FR-ARCH-001: TarSlip / ZipSlip arbitrary file overwrite via extractall
- FR-UPLOAD-001: Dangerous / unvalidated file upload
- FR-REDIR-001: Open redirect via user-controlled target URL
- FR-SECRET-001: Sensitive credential / token exposure or mutation
- FR-MASSASSIGN-001: Mass assignment via dynamic DocType / kwargs
"""

from pathlib import Path
import pytest

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def _scan_snippet(code: str, tmp_path: Path):
	file_path = tmp_path / "app" / "module.py"
	file_path.parent.mkdir(parents=True, exist_ok=True)
	file_path.write_text(code)

	source = SourceFile(path=file_path, root=tmp_path)
	clear_rule_caches()
	py_idx = build_python_index([source])
	cg = build_call_graph(py_idx)
	schema = build_schema_index([])
	hooks = build_hook_index([])

	return execute_rules(schema, hooks, py_idx, call_graph=cg)


def test_fr_ssti_001_eval_exec(tmp_path):
	"""Verify FR-SSTI-001 flags user input passed to eval/render_template."""
	code = """
import frappe

@frappe.whitelist()
def preview_template(template_str):
    return frappe.render_template(template_str, {})
"""
	candidates = _scan_snippet(code, tmp_path)
	ssti = [c for c in candidates if c.rule_id == "FR-SSTI-001"]
	assert len(ssti) >= 1
	assert ssti[0].function == "preview_template"


def test_fr_ssti_001_safe_no_finding(tmp_path):
	"""Verify FR-SSTI-001 does not flag static string formatting."""
	code = """
import frappe

@frappe.whitelist()
def safe_greeting(name):
    frappe.has_permission("User", "read", throw=True)
    return f"Hello {name}"
"""
	candidates = _scan_snippet(code, tmp_path)
	ssti = [c for c in candidates if c.rule_id == "FR-SSTI-001"]
	assert len(ssti) == 0


def test_fr_arch_001_extractall(tmp_path):
	"""Verify FR-ARCH-001 flags archive extractall in whitelisted endpoint."""
	code = """
import frappe
import tarfile

@frappe.whitelist()
def import_package(archive_path):
    with tarfile.open(archive_path) as tar:
        tar.extractall("/tmp/extracted")
"""
	candidates = _scan_snippet(code, tmp_path)
	arch = [c for c in candidates if c.rule_id == "FR-ARCH-001"]
	assert len(arch) >= 1
	assert arch[0].function == "import_package"


def test_fr_upload_001_unrestricted_upload(tmp_path):
	"""Verify FR-UPLOAD-001 flags save_file without permission guards."""
	code = """
import frappe
from frappe.utils.file_manager import save_file

@frappe.whitelist()
def upload_avatar(filename, content):
    save_file(filename, content, "User", frappe.session.user)
"""
	candidates = _scan_snippet(code, tmp_path)
	upload = [c for c in candidates if c.rule_id == "FR-UPLOAD-001"]
	assert len(upload) >= 1
	assert upload[0].function == "upload_avatar"


def test_fr_redir_001_open_redirect(tmp_path):
	"""Verify FR-REDIR-001 flags writing user-supplied redirect_to."""
	code = """
import frappe

@frappe.whitelist()
def set_login_target(target):
    frappe.db.set_value("User Session", frappe.session.user, "redirect_to", target)
"""
	candidates = _scan_snippet(code, tmp_path)
	redir = [c for c in candidates if c.rule_id == "FR-REDIR-001"]
	assert len(redir) >= 1
	assert redir[0].function == "set_login_target"


def test_fr_secret_001_sensitive_field_write(tmp_path):
	"""Verify FR-SECRET-001 flags writing api_secret/password via set_value."""
	code = """
import frappe

@frappe.whitelist()
def reset_user_key(user, new_secret):
    frappe.db.set_value("User", user, "api_secret", new_secret)
"""
	candidates = _scan_snippet(code, tmp_path)
	secret = [c for c in candidates if c.rule_id == "FR-SECRET-001"]
	assert len(secret) >= 1
	assert secret[0].function == "reset_user_key"


def test_fr_massassign_001_dynamic_doctype(tmp_path):
	"""Verify FR-MASSASSIGN-001 flags set_value with dynamic/unresolved doctype."""
	code = """
import frappe

@frappe.whitelist()
def bulk_update_field(doctype, docname, fieldname, value):
    frappe.db.set_value(doctype, docname, fieldname, value)
"""
	candidates = _scan_snippet(code, tmp_path)
	massassign = [c for c in candidates if c.rule_id == "FR-MASSASSIGN-001"]
	assert len(massassign) >= 1
	assert massassign[0].function == "bulk_update_field"
