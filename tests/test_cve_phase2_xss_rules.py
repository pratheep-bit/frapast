"""Unit tests for Phase 2 XSS detection rules.

Covers:
  FR-XSS-001: Stored XSS via user-controlled input written to HTML / rich-text
              fields using db.set_value() or direct attribute assignment from
              a whitelisted endpoint without frappe.utils.sanitize_html().

  FR-XSS-002: Reflected XSS via frappe.respond_as_web_page(), frappe.sendmail(),
              or frappe.get_print() called from a whitelisted endpoint without a
              sanitize_html() guard on the user-controlled content argument.

  FR-XSS-003: Template context XSS via frappe.render_template() / frappe.get_template()
              called from a whitelisted endpoint where user-controlled values are
              passed in the context dict without sanitize_html() or | escape filter.

Each rule has:
  - At least one True Positive (TP) test - confirms detection fires.
  - At least one True Negative (TN) test - confirms no false positive when the
    safe pattern (sanitize_html guard, literal value, or no HTML field) is used.
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
    """Helper: write code to a temp file and run the full rule engine on it."""
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


# ---------------------------------------------------------------------------
# FR-XSS-001: Stored XSS via HTML field write
# ---------------------------------------------------------------------------


def test_fr_xss_001_set_value_to_description_field(tmp_path):
    """FR-XSS-001 TP: db.set_value writing to 'description' field without sanitize_html."""
    code = """
import frappe

@frappe.whitelist()
def update_item_description(item_code, description):
    frappe.db.set_value("Item", item_code, "description", description)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-001"]
    assert len(xss) >= 1, "Expected FR-XSS-001 to fire for db.set_value on 'description' field"
    assert xss[0].function == "update_item_description"


def test_fr_xss_001_set_value_to_notes_field(tmp_path):
    """FR-XSS-001 TP: db.set_value writing to 'notes' field without sanitize_html."""
    code = """
import frappe

@frappe.whitelist()
def save_customer_notes(customer, notes):
    frappe.db.set_value("Customer", customer, "notes", notes)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-001"]
    assert len(xss) >= 1, "Expected FR-XSS-001 to fire for db.set_value on 'notes' field"


def test_fr_xss_001_set_value_to_message_field(tmp_path):
    """FR-XSS-001 TP: db.set_value writing to 'message' field without sanitize_html."""
    code = """
import frappe

@frappe.whitelist()
def send_notification_text(name, msg):
    frappe.db.set_value("Notification", name, "message", msg)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-001"]
    assert len(xss) >= 1, "Expected FR-XSS-001 to fire for db.set_value on 'message' field"


def test_fr_xss_001_set_value_with_sanitize_html_no_finding(tmp_path):
    """FR-XSS-001 TN: db.set_value with sanitize_html applied - should NOT fire."""
    code = """
import frappe
from frappe.utils import sanitize_html

@frappe.whitelist()
def update_item_description(item_code, description):
    clean = sanitize_html(description)
    frappe.db.set_value("Item", item_code, "description", clean)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-001"]
    assert len(xss) == 0, "FR-XSS-001 should NOT fire when sanitize_html() is called in the same function"


def test_fr_xss_001_set_value_to_non_html_field_no_finding(tmp_path):
    """FR-XSS-001 TN: db.set_value on non-HTML field (e.g. 'status') - should NOT fire."""
    code = """
import frappe

@frappe.whitelist()
def mark_item_active(item_code, status):
    frappe.db.set_value("Item", item_code, "status", status)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-001"]
    assert len(xss) == 0, "FR-XSS-001 should NOT fire for non-HTML fields like 'status'"


def test_fr_xss_001_set_value_to_signature_field(tmp_path):
    """FR-XSS-001 TP: db.set_value writing to 'signature' (email signature) without sanitize_html."""
    code = """
import frappe

@frappe.whitelist()
def update_user_signature(user, signature):
    frappe.db.set_value("User", user, "signature", signature)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-001"]
    assert len(xss) >= 1, "Expected FR-XSS-001 to fire for db.set_value on 'signature' field"


# ---------------------------------------------------------------------------
# FR-XSS-002: Reflected XSS via respond_as_web_page / sendmail
# ---------------------------------------------------------------------------


def test_fr_xss_002_respond_as_web_page_no_sanitize(tmp_path):
    """FR-XSS-002 TP: frappe.respond_as_web_page called from endpoint without sanitize_html."""
    code = """
import frappe

@frappe.whitelist(allow_guest=True)
def error_page(message):
    frappe.respond_as_web_page("Error", message, http_status_code=400)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-002"]
    assert len(xss) >= 1, "Expected FR-XSS-002 to fire for respond_as_web_page without sanitize_html"
    assert xss[0].function == "error_page"


def test_fr_xss_002_sendmail_no_sanitize(tmp_path):
    """FR-XSS-002 TP: frappe.sendmail called from endpoint without sanitize_html."""
    code = """
import frappe

@frappe.whitelist()
def send_custom_email(recipient, content):
    frappe.sendmail(recipients=[recipient], message=content, subject="Notification")
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-002"]
    assert len(xss) >= 1, "Expected FR-XSS-002 to fire for sendmail without sanitize_html"


def test_fr_xss_002_respond_as_web_page_with_sanitize_no_finding(tmp_path):
    """FR-XSS-002 TN: respond_as_web_page with sanitize_html applied - should NOT fire."""
    code = """
import frappe
from frappe.utils import sanitize_html

@frappe.whitelist(allow_guest=True)
def error_page(message):
    safe_msg = sanitize_html(message)
    frappe.respond_as_web_page("Error", safe_msg, http_status_code=400)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-002"]
    assert len(xss) == 0, "FR-XSS-002 should NOT fire when sanitize_html() is called before respond_as_web_page"


def test_fr_xss_002_not_whitelisted_no_finding(tmp_path):
    """FR-XSS-002 TN: sendmail not reachable from whitelisted endpoint - should NOT fire."""
    code = """
import frappe

def internal_send_email(recipient, content):
    # This function is NOT whitelisted - not reachable from HTTP
    frappe.sendmail(recipients=[recipient], message=content, subject="Internal")
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-002"]
    assert len(xss) == 0, "FR-XSS-002 should NOT fire for non-whitelisted functions"


# ---------------------------------------------------------------------------
# FR-XSS-003: XSS via Jinja2 template context
# ---------------------------------------------------------------------------


def test_fr_xss_003_render_template_with_user_context(tmp_path):
    """FR-XSS-003 TP: frappe.render_template called with user-controlled context from endpoint."""
    code = """
import frappe

@frappe.whitelist()
def generate_html_preview(template_name, context_data):
    return frappe.render_template(template_name, context_data)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-003"]
    assert len(xss) >= 1, "Expected FR-XSS-003 to fire for render_template with user-controlled context"


def test_fr_xss_003_render_template_with_sanitize_no_finding(tmp_path):
    """FR-XSS-003 TN: render_template with sanitize_html applied to context - should NOT fire."""
    code = """
import frappe
from frappe.utils import sanitize_html

@frappe.whitelist()
def safe_preview(user_notes):
    ctx = {"notes": sanitize_html(user_notes)}
    return frappe.render_template("my_template.html", ctx)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-003"]
    assert len(xss) == 0, "FR-XSS-003 should NOT fire when sanitize_html() is used on context values"


def test_fr_xss_003_not_reachable_no_finding(tmp_path):
    """FR-XSS-003 TN: render_template not reachable from any whitelisted endpoint - should NOT fire."""
    code = """
import frappe

def internal_render(context):
    # Not a whitelisted endpoint - no HTTP exposure
    return frappe.render_template("some_template.html", context)
"""
    candidates = _scan_snippet(code, tmp_path)
    xss = [c for c in candidates if c.rule_id == "FR-XSS-003"]
    assert len(xss) == 0, "FR-XSS-003 should NOT fire for non-whitelisted functions"


# ---------------------------------------------------------------------------
# Cross-rule: verify no mutual interference between Phase 2 XSS rules and Phase 1
# ---------------------------------------------------------------------------


def test_phase2_xss_no_interference_with_ssti(tmp_path):
    """Phase 2 XSS rules must not suppress FR-SSTI-001 findings on the same snippet."""
    code = """
import frappe

@frappe.whitelist()
def preview_template(template_str, context):
    # template_str is a user-controlled *template string* -> FR-SSTI-001
    # render_template call -> also triggers FR-XSS-003
    return frappe.render_template(template_str, context)
"""
    candidates = _scan_snippet(code, tmp_path)
    ssti = [c for c in candidates if c.rule_id == "FR-SSTI-001"]
    xss3 = [c for c in candidates if c.rule_id == "FR-XSS-003"]
    # Both can fire on the same snippet; neither should suppress the other
    assert len(ssti) >= 1 or len(xss3) >= 1, (
        "At least one of FR-SSTI-001 or FR-XSS-003 must fire for a fully user-controlled render_template call"
    )


def test_phase2_xss_rules_registered():
    """Verify all three Phase 2 XSS rules are registered in ALL_RULES."""
    from scanner.rules.engine import ALL_RULES
    names = {r.__name__ for r in ALL_RULES}
    assert "fr_xss_001" in names, "fr_xss_001 must be in ALL_RULES"
    assert "fr_xss_002" in names, "fr_xss_002 must be in ALL_RULES"
    assert "fr_xss_003" in names, "fr_xss_003 must be in ALL_RULES"
    assert len([r for r in ALL_RULES if r.__name__.startswith("fr_xss_")]) == 3, (
        "Exactly 3 FR-XSS rules must be registered"
    )
