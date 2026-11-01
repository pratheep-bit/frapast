"""Tests for FR-COMPAT-002: Client-side JavaScript Deprecations.

Coverage:
  1. cur_frm.cscript legacy form scripts (TP).
  2. frappe.views.GridReport removed view class (TP).
  3. cur_dialog global modal mutations (TP).
  4. Modern event handlers via frappe.ui.form.on (TN).
  5. Local Dialog instance usage (TN).
  6. Minified JavaScript files (*.min.js) excluded (TN).
  7. JavaScript test files and comment-only mentions (TN).
"""
from __future__ import annotations

from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


def _scan(tmp_path: Path, js_content: str, filename: str = "public/js/custom_app.js") -> list:
    app_dir = tmp_path / "myapp"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("")
    (app_dir / "hooks.py").write_text("app_name = 'myapp'\n")

    target_file = tmp_path / filename
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(js_content, encoding="utf-8")

    sources = [
        SourceFile(path=app_dir / "__init__.py", root=tmp_path),
        SourceFile(path=app_dir / "hooks.py", root=tmp_path),
    ]

    clear_rule_caches()
    py_idx = build_python_index(sources)
    cg = build_call_graph(py_idx)
    schema = build_schema_index([])
    hooks = build_hook_index([])
    candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
    return [c for c in candidates if c.rule_id == "FR-COMPAT-002"]


class TestClientDeprecationTruePositives:
    """FR-COMPAT-002 must flag deprecated client-side JavaScript APIs."""

    def test_cur_frm_cscript_flagged(self, tmp_path):
        """cur_frm.cscript was deprecated in v14 and must be flagged."""
        js = """
cur_frm.cscript.custom_onload = function(doc) {
    console.log("legacy onload");
};
"""
        findings = _scan(tmp_path, js)
        assert len(findings) == 1
        assert "cur_frm.cscript" in findings[0].evidence
        assert "frappe.ui.form.on" in findings[0].proof_recipe

    def test_grid_report_flagged(self, tmp_path):
        """frappe.views.GridReport was removed in v15 and must be flagged."""
        js = """
frappe.views.CustomReport = frappe.views.GridReport.extend({
    init: function() {
        this._super();
    }
});
"""
        findings = _scan(tmp_path, js)
        assert len(findings) == 1
        assert "frappe.views.GridReport" in findings[0].evidence
        assert "v15" in findings[0].proof_recipe

    def test_cur_dialog_flagged(self, tmp_path):
        """Direct manipulation of global cur_dialog is deprecated in v15+."""
        js = """
function submitPrompt() {
    cur_dialog.set_value("amount", 500);
    cur_dialog.hide();
}
"""
        findings = _scan(tmp_path, js)
        assert len(findings) >= 1
        assert any("cur_dialog" in f.evidence for f in findings)


class TestClientDeprecationTrueNegatives:
    """FR-COMPAT-002 must not flag modern patterns, minified files, or comments."""

    def test_modern_form_handler_not_flagged(self, tmp_path):
        """frappe.ui.form.on is the standard modern form event pattern."""
        js = """
frappe.ui.form.on("Sales Invoice", {
    refresh: function(frm) {
        frm.add_custom_button(__("Process"), () => {});
    }
});
"""
        findings = _scan(tmp_path, js)
        assert len(findings) == 0

    def test_local_dialog_instance_not_flagged(self, tmp_path):
        """Creating and holding local Dialog instances is the recommended approach."""
        js = """
function openModal() {
    let dialog = new frappe.ui.Dialog({
        title: __("Confirm Action"),
        fields: [{ fieldname: "reason", fieldtype: "Data" }]
    });
    dialog.show();
}
"""
        findings = _scan(tmp_path, js)
        assert len(findings) == 0

    def test_minified_file_excluded(self, tmp_path):
        """Minified assets (*.min.js) must be ignored."""
        js = "var x=cur_frm.cscript;console.log(x);"
        findings = _scan(tmp_path, js, filename="public/dist/bundle.min.js")
        assert len(findings) == 0

    def test_commented_code_not_flagged(self, tmp_path):
        """Comments mentioning deprecated APIs for documentation must not be flagged."""
        js = """
// Note: cur_frm.cscript is obsolete, use frappe.ui.form.on instead
frappe.ui.form.on("Quotation", {
    setup: function(frm) {}
});
"""
        findings = _scan(tmp_path, js)
        assert len(findings) == 0

    def test_test_files_excluded(self, tmp_path):
        """Files in tests directory must be excluded."""
        js = "cur_frm.cscript.test = 1;"
        findings = _scan(tmp_path, js, filename="tests/test_script.js")
        assert len(findings) == 0
