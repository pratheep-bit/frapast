"""Unit tests for the Tier 2 HTTP proof pipeline.

All tests run fully offline — no live Frappe bench is required. Network calls
are intercepted via unittest.mock so this suite passes in CI without Docker.

Test classes:
    TestFrappeHTTPClientParsing     — body parsing, cookie handling, error classification
    TestFrappeHTTPClientAuthFlow    — login/logout session lifecycle (mocked urlopen)
    TestHTTPSynthesisPerRule        — every rule produces valid script with correct marker
    TestValidateReproducerMarkers   — CI gate detects missing / invalid markers
    TestBenchRunnerOffline          — SKIPPED result when bench is unreachable
    TestOrchestratorTier2Dispatch   — orchestrator routes http_rpc to BenchRunner
"""
from __future__ import annotations

import stat
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup so tests run from the project root without install
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.proof.http_client import (
    FrappeAuthError,
    FrappeHTTPClient,
    FrappePermissionError,
    FrappeResponse,
)
from scanner.proof.http_synthesis import synthesize_http_rpc_reproducer
from scanner.proof.models import PROOF_MODE_MARKER, ProofStatus
from scanner.proof.validate_reproducer_markers import (
    run_validation,
    validate_file,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_response(status: int, body_bytes: bytes, headers: dict | None = None) -> MagicMock:
    """Construct a mock urllib response object."""
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.read.return_value = body_bytes
    mock_info = MagicMock()
    mock_info.get_all.return_value = list((headers or {}).get("Set-Cookie", []))
    mock_resp.info.return_value = mock_info
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# 1. FrappeHTTPClient — body parsing and error classification
# ---------------------------------------------------------------------------


class TestFrappeHTTPClientParsing(unittest.TestCase):
    """Tests for body parsing, cookie extraction, and error type mapping."""

    def test_parse_valid_json(self):
        parsed = FrappeHTTPClient._parse_body('{"message": "pong"}')
        self.assertEqual(parsed, {"message": "pong"})

    def test_parse_empty_body(self):
        parsed = FrappeHTTPClient._parse_body("")
        self.assertEqual(parsed, {})

    def test_parse_non_dict_json(self):
        parsed = FrappeHTTPClient._parse_body('"hello"')
        self.assertEqual(parsed, {"message": "hello"})

    def test_parse_invalid_json_returns_raw(self):
        parsed = FrappeHTTPClient._parse_body("<html>Not JSON</html>")
        self.assertIn("raw", parsed)

    def test_frappe_response_ok(self):
        resp = FrappeResponse(status=200, body={"message": "pong"})
        self.assertTrue(resp.ok)
        self.assertEqual(resp.message, "pong")

    def test_frappe_response_not_ok(self):
        resp = FrappeResponse(status=403, body={"exc_type": "PermissionError"})
        self.assertFalse(resp.ok)
        self.assertTrue(resp.is_permission_error)

    def test_frappe_response_auth_error(self):
        resp = FrappeResponse(status=401, body={"exc_type": "AuthenticationError"})
        self.assertTrue(resp.is_auth_error)

    def test_frappe_response_data_accessor(self):
        resp = FrappeResponse(status=200, body={"message": "ok", "token": "abc123"})
        self.assertEqual(resp.data("token"), "abc123")
        self.assertIsNone(resp.data("missing_key"))


# ---------------------------------------------------------------------------
# 2. FrappeHTTPClient — authentication flow (mocked)
# ---------------------------------------------------------------------------


class TestFrappeHTTPClientAuthFlow(unittest.TestCase):

    def _client(self) -> FrappeHTTPClient:
        return FrappeHTTPClient("http://localhost:8000", timeout=5)

    @patch("urllib.request.urlopen")
    def test_ping_returns_true_on_pong(self, mock_urlopen):
        mock_urlopen.return_value = _make_mock_response(200, b'{"message": "pong"}')
        client = self._client()
        self.assertTrue(client.ping())

    @patch("urllib.request.urlopen")
    def test_ping_returns_false_on_connection_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        client = self._client()
        self.assertFalse(client.ping())

    @patch("urllib.request.urlopen")
    def test_login_succeeds_and_stores_cookie(self, mock_urlopen):
        mock_resp = _make_mock_response(
            200,
            b'{"message": "Logged In", "home_page": "/desk"}',
            {"Set-Cookie": ["sid=abc123; Path=/; HttpOnly"]},
        )
        mock_urlopen.return_value = mock_resp
        client = self._client()
        resp = client.login("admin@example.com", "password")
        self.assertTrue(resp.ok)
        self.assertIn("sid", client._cookies)

    @patch("urllib.request.urlopen")
    def test_login_raises_auth_error_on_401(self, mock_urlopen):
        import urllib.error
        http_err = urllib.error.HTTPError(
            url="http://localhost:8000/api/method/login",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(get_all=lambda k: []),
            fp=BytesIO(b'{"message": "Incorrect password"}'),
        )
        mock_urlopen.side_effect = http_err
        client = self._client()
        with self.assertRaises(FrappeAuthError):
            client.login("bad@user.com", "wrong")

    @patch("urllib.request.urlopen")
    def test_post_includes_cookie_header(self, mock_urlopen):
        mock_urlopen.return_value = _make_mock_response(200, b'{"message": "ok"}')
        client = self._client()
        client._cookies = {"sid": "testsession"}
        client.post("some.method")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertIn("sid=testsession", req.get_header("Cookie"))

    @patch("urllib.request.urlopen")
    def test_call_as_guest_clears_session(self, mock_urlopen):
        mock_urlopen.return_value = _make_mock_response(200, b'{"message": "data"}')
        client = self._client()
        client._cookies = {"sid": "authenticated_session"}
        client.call_as_guest("some.method")
        # After call_as_guest, the original cookies must be restored
        self.assertEqual(client._cookies, {"sid": "authenticated_session"})
        # The actual request should have had NO Cookie header
        req = mock_urlopen.call_args[0][0]
        # Guest call removes cookies before sending
        self.assertNotIn("Cookie", req.headers if hasattr(req, "headers") else {})

    @patch("urllib.request.urlopen")
    def test_http_417_raises_frappe_permission_error(self, mock_urlopen):
        import urllib.error
        http_err = urllib.error.HTTPError(
            url="http://localhost:8000/api/method/test",
            code=417,
            msg="Expectation Failed",
            hdrs=MagicMock(get_all=lambda k: []),
            fp=BytesIO(b'{"exc_type": "PermissionError"}'),
        )
        mock_urlopen.side_effect = http_err
        client = self._client()
        with self.assertRaises(FrappePermissionError):
            client.post("test.method")


# ---------------------------------------------------------------------------
# 3. HTTP Synthesis — per-rule script generation
# ---------------------------------------------------------------------------


class TestHTTPSynthesisPerRule(unittest.TestCase):
    """Verify synthesis produces valid scripts with correct PROOF_MODE markers."""

    HTTP_RULES = [
        ("FR-PERM-001", {"rule_id": "FR-PERM-001", "function": "my_app.api.get_data"}),
        ("FR-PERM-002", {"rule_id": "FR-PERM-002", "function": "my_app.api.update_doc"}),
        ("FR-PERM-003", {"rule_id": "FR-PERM-003", "function": "my_app.api.set_owner"}),
        ("FR-SQLI-001", {"rule_id": "FR-SQLI-001", "function": "my_app.reports.run_query"}),
        ("FR-SQLI-003", {"rule_id": "FR-SQLI-003", "function": "my_app.utils.bulk_update"}),
        ("FR-SQLI-004", {"rule_id": "FR-SQLI-004", "function": "my_app.api.dynamic_table"}),
        ("FR-INJ-001",  {"rule_id": "FR-INJ-001",  "function": "my_app.api.create_doc"}),
        ("FR-INJ-002",  {"rule_id": "FR-INJ-002",  "function": "my_app.api.run_code"}),
        ("FR-PATH-001", {"rule_id": "FR-PATH-001", "function": "my_app.api.read_template"}),
        ("FR-CSRF-001", {"rule_id": "FR-CSRF-001", "function": "my_app.api.submit_form"}),
        ("FR-SSRF-001", {"rule_id": "FR-SSRF-001", "function": "my_app.api.fetch_url"}),
    ]

    def _run_synthesis(self, rule_id: str, finding_data: dict, tmp_dir: Path) -> Path | None:
        return synthesize_http_rpc_reproducer(
            tmp_dir / "reproducers",
            f"{rule_id}-test001",
            finding_data,
            tmp_dir,
        )

    def test_all_http_provable_rules_generate_scripts(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for rule_id, data in self.HTTP_RULES:
                with self.subTest(rule=rule_id):
                    path = self._run_synthesis(rule_id, data, tmp)
                    self.assertIsNotNone(path, f"{rule_id} should produce a reproducer")
                    self.assertTrue(path.exists(), f"Reproducer file should exist for {rule_id}")

    def test_all_scripts_have_proof_mode_marker(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for rule_id, data in self.HTTP_RULES:
                with self.subTest(rule=rule_id):
                    path = self._run_synthesis(rule_id, data, tmp)
                    if path is None:
                        continue
                    content = path.read_text()
                    lines = content.splitlines()
                    found = any(
                        line.strip().startswith(PROOF_MODE_MARKER)
                        for line in lines[:3]
                    )
                    self.assertTrue(found, f"Missing {PROOF_MODE_MARKER} in {rule_id} reproducer")

    def test_all_scripts_have_http_rpc_mode(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for rule_id, data in self.HTTP_RULES:
                with self.subTest(rule=rule_id):
                    path = self._run_synthesis(rule_id, data, tmp)
                    if path is None:
                        continue
                    content = path.read_text()
                    lines = content.splitlines()
                    marker_lines = [line.strip() for line in lines[:3] if PROOF_MODE_MARKER in line]
                    self.assertTrue(marker_lines, f"No marker line in {rule_id}")
                    mode = marker_lines[0][len(PROOF_MODE_MARKER):].strip()
                    self.assertEqual(mode, "http_rpc", f"Wrong mode for {rule_id}: {mode!r}")

    def test_all_scripts_are_executable(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for rule_id, data in self.HTTP_RULES:
                with self.subTest(rule=rule_id):
                    path = self._run_synthesis(rule_id, data, tmp)
                    if path is None:
                        continue
                    file_stat = path.stat()
                    self.assertTrue(file_stat.st_mode & stat.S_IXUSR, f"{rule_id} script not executable")

    def test_unknown_rule_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            result = synthesize_http_rpc_reproducer(
                tmp / "reproducers",
                "FR-UNKNOWN-999-abcdef",
                {"rule_id": "FR-UNKNOWN-999", "function": "some.func"},
                tmp,
            )
            self.assertIsNone(result)

    def test_missing_function_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            result = synthesize_http_rpc_reproducer(
                tmp / "reproducers",
                "FR-PERM-001-abcdef",
                {"rule_id": "FR-PERM-001", "function": ""},
                tmp,
            )
            self.assertIsNone(result)

    def test_script_body_contains_bench_url_env_var(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = self._run_synthesis(
                "FR-PERM-001", {"rule_id": "FR-PERM-001", "function": "my_app.api.get_data"}, tmp
            )
            content = path.read_text()
            self.assertIn("FRAPAST_BENCH_URL", content)

    def test_perm_001_script_contains_guest_call(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = self._run_synthesis(
                "FR-PERM-001", {"rule_id": "FR-PERM-001", "function": "my_app.api.get_data"}, tmp
            )
            content = path.read_text()
            self.assertIn("call_as_guest", content)

    def test_csrf_001_script_contains_no_csrf_hint(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = self._run_synthesis(
                "FR-CSRF-001", {"rule_id": "FR-CSRF-001", "function": "my_app.api.submit"}, tmp
            )
            content = path.read_text()
            self.assertIn("CSRF", content)


# ---------------------------------------------------------------------------
# 4. validate_reproducer_markers — CI gate
# ---------------------------------------------------------------------------


class TestValidateReproducerMarkers(unittest.TestCase):

    def test_valid_marker_accepted(self):
        with tempfile.NamedTemporaryFile(suffix=".sh", mode="w", delete=False) as f:
            f.write("# PROOF_MODE: direct_call\n#!/usr/bin/env bash\necho ok\n")
            path = Path(f.name)
        try:
            self.assertIsNone(validate_file(path))
        finally:
            path.unlink()

    def test_http_rpc_marker_accepted(self):
        with tempfile.NamedTemporaryFile(suffix=".sh", mode="w", delete=False) as f:
            f.write("#!/usr/bin/env bash\n# PROOF_MODE: http_rpc\necho ok\n")
            path = Path(f.name)
        try:
            self.assertIsNone(validate_file(path))
        finally:
            path.unlink()

    def test_missing_marker_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".sh", mode="w", delete=False) as f:
            f.write("#!/usr/bin/env bash\necho no marker here\n")
            path = Path(f.name)
        try:
            err = validate_file(path)
            self.assertIsNotNone(err)
            self.assertIn("missing", err.lower())
        finally:
            path.unlink()

    def test_invalid_mode_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".sh", mode="w", delete=False) as f:
            f.write("# PROOF_MODE: banana\necho bad mode\n")
            path = Path(f.name)
        try:
            err = validate_file(path)
            self.assertIsNotNone(err)
        finally:
            path.unlink()

    def test_fixture_reproducers_all_valid(self):
        """All checked-in fixture reproducers must pass the marker gate."""
        fixture_dir = ROOT / "tests" / "python" / "fixtures" / "runtime" / "reproducers"
        if not fixture_dir.is_dir():
            self.skipTest("Fixture reproducer directory not found")
        failures = []
        for sh_file in fixture_dir.glob("*.sh"):
            err = validate_file(sh_file)
            if err:
                failures.append(f"{sh_file.name}: {err}")
        self.assertFalse(failures, "Some fixture reproducers have invalid/missing PROOF_MODE markers:\n" + "\n".join(failures))

    def test_run_validation_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            ok, fail, msgs = run_validation(Path(td))
            self.assertEqual(ok, 0)
            self.assertEqual(fail, 0)
            self.assertEqual(msgs, [])


# ---------------------------------------------------------------------------
# 5. BenchRunner — offline / SKIPPED behaviour
# ---------------------------------------------------------------------------


class TestBenchRunnerOffline(unittest.TestCase):

    def _runner(self, **kwargs):
        from scanner.proof.bench_runner import BenchRunner
        with tempfile.TemporaryDirectory() as td:
            return BenchRunner(
                base_url="http://localhost:19999",  # deliberately unreachable
                workspace_root=Path(td),
                **kwargs,
            ), td

    def test_is_bench_alive_returns_false_when_offline(self):
        from scanner.proof.bench_runner import BenchRunner
        with tempfile.TemporaryDirectory() as td:
            runner = BenchRunner(base_url="http://localhost:19999", workspace_root=Path(td))
            self.assertFalse(runner.is_bench_alive())

    def test_run_http_proof_returns_skipped_when_offline(self):
        from scanner.proof.bench_runner import BenchRunner
        with tempfile.TemporaryDirectory() as td:
            runner = BenchRunner(base_url="http://localhost:19999", workspace_root=Path(td))
            result = runner.run_http_proof(
                "FR-PERM-001-test999",
                {"rule_id": "FR-PERM-001", "function": "my_app.api.test"},
            )
            self.assertEqual(result.status, ProofStatus.SKIPPED)
            self.assertEqual(result.proof_tier, 2)
            self.assertIsNotNone(result.error_message)
            self.assertIn("not reachable", result.error_message)

    def test_run_http_proof_dry_run_skips_execution(self):
        from scanner.proof.bench_runner import BenchRunner
        with tempfile.TemporaryDirectory() as td:
            # dry_run + no bench = DRY_RUN after reachability fails (SKIPPED wins)
            # but if we mock ping() to return True, we get DRY_RUN
            runner = BenchRunner(base_url="http://localhost:19999", workspace_root=Path(td), dry_run=True)
            with patch.object(runner, "is_bench_alive", return_value=True):
                result = runner.run_http_proof(
                    "FR-PERM-001-drytest",
                    {"rule_id": "FR-PERM-001", "function": "my_app.api.test"},
                )
            self.assertEqual(result.status, ProofStatus.DRY_RUN)
            self.assertEqual(result.proof_tier, 2)


# ---------------------------------------------------------------------------
# 6. ProofOrchestrator — Tier 2 dispatch
# ---------------------------------------------------------------------------


class TestOrchestratorTier2Dispatch(unittest.TestCase):

    @patch("scanner.proof.bench_runner.auto_detect_bench_url", return_value=None)
    def test_prove_candidate_returns_skipped_for_http_rpc_without_bench(self, _mock_auto):
        """Tier 2 reproducers SKIPPED cleanly when no bench URL provided."""
        from scanner.proof.orchestrator import ProofOrchestrator
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "runtime" / "reproducers").mkdir(parents=True)
            repro_path = tmp / "runtime" / "reproducers" / "FR-PERM-001-abc001.sh"
            repro_path.write_text("# PROOF_MODE: http_rpc\n#!/usr/bin/env bash\necho test\n")
            repro_path.chmod(0o755)

            orch = ProofOrchestrator(workspace_root=tmp)  # no bench_url
            result = orch.prove_candidate("FR-PERM-001-abc001", {"rule_id": "FR-PERM-001", "function": "my_app.api.test"})
            self.assertEqual(result.status, ProofStatus.SKIPPED)
            self.assertIn("Tier 2", result.error_message)

    def test_prove_candidate_tier1_still_runs_for_direct_call(self):
        """Tier 1 direct_call reproducers always run regardless of bench config."""
        from scanner.proof.orchestrator import ProofOrchestrator
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "runtime" / "reproducers").mkdir(parents=True)
            repro_path = tmp / "runtime" / "reproducers" / "FR-HOOK-007-abc002.sh"
            repro_path.write_text("# PROOF_MODE: direct_call\n#!/usr/bin/env bash\nexit 0\n")
            repro_path.chmod(0o755)

            orch = ProofOrchestrator(workspace_root=tmp)
            result = orch.prove_candidate("FR-HOOK-007-abc002", {"rule_id": "FR-HOOK-007", "function": "my_app.hooks.test"})
            # Should run (passed or failed) — never SKIPPED due to missing bench
            self.assertNotEqual(result.status, ProofStatus.SKIPPED)

    @patch("scanner.proof.bench_runner.auto_detect_bench_url", return_value=None)
    def test_bench_configured_flag(self, _mock_auto):
        from scanner.proof.orchestrator import ProofOrchestrator
        with tempfile.TemporaryDirectory() as td:
            orch_no_bench = ProofOrchestrator(workspace_root=Path(td))
            orch_with_bench = ProofOrchestrator(workspace_root=Path(td), bench_url="http://localhost:8000")
            self.assertFalse(orch_no_bench._bench_configured())
            self.assertTrue(orch_with_bench._bench_configured())


if __name__ == "__main__":
    unittest.main()
