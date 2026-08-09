"""BenchRunner — high-level Tier 2 HTTP proof executor.

Wraps FrappeHTTPClient to execute HTTP/RPC proofs against a live Frappe bench
and translate the outcomes into typed ProofResult objects consumed by
ProofOrchestrator.

Design decisions:
- BenchRunner owns the session lifecycle (login → run → logout) for each
  proof. This guarantees clean state between findings.
- "Bench unreachable" (FrappeConnectionError) maps to ProofStatus.SKIPPED,
  not FAILED. A Tier 2 skip does not degrade the finding's Tier 1 status.
- Environment variables (FRAPAST_BENCH_URL / USER / PWD / SITE_NAME) can
  override constructor defaults, making it easy to inject bench config in
  Docker Compose test environments without changing CLI flags.
- The reproducer is still written to runtime/reproducers/ even in dry_run
  mode, so CI can validate markers without executing.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from scanner.proof.http_client import (
    FrappeAuthError,
    FrappeConnectionError,
    FrappeHTTPClient,
    FrappeHTTPError,
)
from scanner.proof.http_synthesis import synthesize_http_rpc_reproducer
from scanner.proof.models import ProofResult, ProofStatus


class BenchRunner:
    """Executes Tier 2 HTTP/RPC proofs against a live Frappe bench.

    Args:
        base_url:       Frappe bench base URL (e.g. ``http://localhost:8000``).
        username:       Frappe username to authenticate with.
        password:       Frappe password.
        site_name:      Frappe site name for the Host header (optional).
        timeout:        Per-request timeout in seconds.
        dry_run:        If True, synthesise reproducers but do not execute.
        workspace_root: Root of the repository being analysed (for reproducer paths).
        reproducers_dir: Where to write synthesised reproducer scripts.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        username: str = "Administrator",
        password: str = "admin",
        site_name: str = "",
        timeout: int = 30,
        dry_run: bool = False,
        workspace_root: str | Path = ".",
        reproducers_dir: str | Path = "runtime/reproducers",
    ) -> None:
        # Honour environment variable overrides (useful in Docker / CI contexts)
        self.base_url = os.environ.get("FRAPAST_BENCH_URL", base_url)
        self.username = os.environ.get("FRAPAST_BENCH_USER", username)
        self.password = os.environ.get("FRAPAST_BENCH_PWD", password)
        self.site_name = os.environ.get("FRAPAST_SITE_NAME", site_name)
        self.timeout = timeout
        self.dry_run = dry_run
        self.workspace_root = Path(workspace_root)
        self.reproducers_dir = (
            self.workspace_root / reproducers_dir
            if not Path(reproducers_dir).is_absolute()
            else Path(reproducers_dir)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_bench_alive(self) -> bool:
        """Return True if the bench is reachable and healthy."""
        client = FrappeHTTPClient(self.base_url, timeout=self.timeout, site_name=self.site_name)
        return client.ping()

    def run_http_proof(self, finding_id: str, candidate_data: dict) -> ProofResult:
        """Execute a Tier 2 HTTP proof for the given finding.

        Steps:
        1. Synthesise / locate the reproducer script.
        2. Health-check the bench.
        3. If dry_run, return DRY_RUN status.
        4. Login → execute → logout via FrappeHTTPClient.
        5. Return a ProofResult with proof_tier=2.

        The reproducer script is always written to disk (step 1) so the CI
        marker validator can inspect it regardless of dry_run.
        """
        t0 = time.perf_counter()

        # Step 1 — synthesise reproducer (always, even in dry_run)
        reproducer_path = synthesize_http_rpc_reproducer(
            self.reproducers_dir,
            finding_id,
            candidate_data,
            self.workspace_root,
        )
        reproducer_path_str = str(reproducer_path) if reproducer_path else ""

        # Step 2 — check bench reachability
        if not self.is_bench_alive():
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.SKIPPED,
                proof_tier=2,
                exit_code=None,
                stdout="",
                stderr="",
                duration_seconds=time.perf_counter() - t0,
                reproducer_path=reproducer_path_str,
                error_message=(
                    f"Bench at {self.base_url} is not reachable. "
                    "Tier 2 proof skipped. Start the bench with `make site-serve` "
                    "or set FRAPAST_BENCH_URL to the correct URL."
                ),
            )

        # Step 3 — dry run short-circuit
        if self.dry_run:
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.DRY_RUN,
                proof_tier=2,
                exit_code=None,
                stdout="[dry-run] would execute HTTP proof against " + self.base_url,
                stderr="",
                duration_seconds=time.perf_counter() - t0,
                reproducer_path=reproducer_path_str,
                error_message=None,
            )

        # Step 4 — execute the proof via FrappeHTTPClient
        return self._execute_proof(finding_id, candidate_data, reproducer_path_str, t0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_proof(
        self,
        finding_id: str,
        candidate_data: dict,
        reproducer_path_str: str,
        t0: float,
    ) -> ProofResult:
        """Run the actual HTTP proof and return a typed ProofResult."""
        client = FrappeHTTPClient(self.base_url, timeout=self.timeout, site_name=self.site_name)
        rule_id: str = candidate_data.get("rule_id", "")
        func_name: str = candidate_data.get("function", "")
        api_method = func_name.replace("/", ".").strip(".")

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        try:
            # Authenticate
            try:
                client.login(self.username, self.password)
                stdout_lines.append(f"Authenticated as {self.username} at {self.base_url}")
            except FrappeAuthError as exc:
                return ProofResult(
                    finding_id=finding_id,
                    status=ProofStatus.SKIPPED,
                    proof_tier=2,
                    exit_code=None,
                    stdout="",
                    stderr=str(exc),
                    duration_seconds=time.perf_counter() - t0,
                    reproducer_path=reproducer_path_str,
                    error_message=f"Authentication failed: {exc}",
                )

            # Dispatch per-rule proof
            proven, stdout_extra, stderr_extra = self._dispatch_rule_proof(
                rule_id, api_method, client, candidate_data
            )
            stdout_lines.extend(stdout_extra)
            stderr_lines.extend(stderr_extra)

            client.logout()
            duration = time.perf_counter() - t0

            status = ProofStatus.PASSED if proven else ProofStatus.FAILED
            return ProofResult(
                finding_id=finding_id,
                status=status,
                proof_tier=2,
                exit_code=0 if proven else 1,
                stdout="\n".join(stdout_lines),
                stderr="\n".join(stderr_lines),
                duration_seconds=duration,
                reproducer_path=reproducer_path_str,
                error_message=None,
            )

        except FrappeConnectionError as exc:
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.SKIPPED,
                proof_tier=2,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                duration_seconds=time.perf_counter() - t0,
                reproducer_path=reproducer_path_str,
                error_message=f"Bench connection lost mid-proof: {exc}",
            )
        except Exception as exc:
            return ProofResult(
                finding_id=finding_id,
                status=ProofStatus.ERROR,
                proof_tier=2,
                exit_code=None,
                stdout="\n".join(stdout_lines),
                stderr=str(exc),
                duration_seconds=time.perf_counter() - t0,
                reproducer_path=reproducer_path_str,
                error_message=f"Unexpected error during Tier 2 proof: {type(exc).__name__}: {exc}",
            )

    def _dispatch_rule_proof(
        self,
        rule_id: str,
        api_method: str,
        client: FrappeHTTPClient,
        candidate_data: dict,
    ) -> tuple[bool, list[str], list[str]]:
        """Execute the rule-specific HTTP proof logic.

        Returns (proven: bool, stdout_lines, stderr_lines).
        """
        stdout: list[str] = []
        stderr: list[str] = []

        if not api_method:
            stderr.append(f"No function name in finding data for {rule_id} — cannot execute HTTP proof")
            return False, stdout, stderr

        if rule_id == "FR-PERM-001":
            return self._proof_perm_001(api_method, client, stdout, stderr)

        if rule_id == "FR-PERM-002":
            return self._proof_perm_002(api_method, client, stdout, stderr)

        if rule_id == "FR-PERM-003":
            return self._proof_perm_003(api_method, client, stdout, stderr)

        if rule_id == "FR-SQLI-001":
            return self._proof_sqli_001(api_method, client, stdout, stderr)

        if rule_id == "FR-SQLI-003":
            return self._proof_sqli_003(api_method, client, stdout, stderr)

        if rule_id == "FR-SQLI-004":
            return self._proof_sqli_004(api_method, client, stdout, stderr)

        if rule_id == "FR-INJ-001":
            return self._proof_inj_001(api_method, client, stdout, stderr)

        if rule_id == "FR-INJ-002":
            return self._proof_inj_002(api_method, client, stdout, stderr)

        if rule_id == "FR-CSRF-001":
            return self._proof_csrf_001(api_method, client, stdout, stderr)

        if rule_id == "FR-SSRF-001":
            return self._proof_ssrf_001(api_method, client, stdout, stderr)

        stderr.append(f"No Tier 2 HTTP proof strategy for rule {rule_id}")
        return False, stdout, stderr

    # ------------------------------------------------------------------
    # Per-rule proof implementations
    # ------------------------------------------------------------------

    def _proof_perm_001(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-PERM-001: call endpoint as Guest; proven if returns 200 without permission error."""
        resp = client.call_as_guest(method)
        stdout.append(f"Guest call to {method}: HTTP {resp.status}")
        if resp.status == 200 and not resp.is_permission_error:
            stdout.append("PROVEN: endpoint returned 200 for unauthenticated caller — permission check missing")
            return True, stdout, stderr
        stdout.append(f"REFUTED: endpoint rejected guest access (HTTP {resp.status})")
        return False, stdout, stderr

    def _proof_perm_002(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-PERM-002: authenticated low-priv call; proven if returns 200 for restricted data."""
        resp = client.post(method)
        stdout.append(f"Authenticated call to {method}: HTTP {resp.status}")
        if resp.status == 200 and not resp.is_permission_error:
            stdout.append("POTENTIAL PROOF: endpoint returned 200 — ignore_permissions may bypass role check")
            return True, stdout, stderr
        stdout.append(f"REFUTED: endpoint blocked low-privilege access (HTTP {resp.status})")
        return False, stdout, stderr

    def _proof_perm_003(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-PERM-003: probe if_owner bypass via mutation endpoint."""
        resp = client.post(method, {"name": "__probe__", "field": "__sentinel__"})
        stdout.append(f"Mutation call to {method}: HTTP {resp.status}")
        if resp.status == 200 and not resp.is_permission_error:
            stdout.append("POTENTIAL PROOF: write succeeded without ownership validation")
            return True, stdout, stderr
        stdout.append(f"REFUTED: ownership check present (HTTP {resp.status})")
        return False, stdout, stderr

    def _proof_sqli_001(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-SQLI-001: inject SQL payload and check for DB error in response."""
        payloads = ["' OR '1'='1", "'; SELECT SLEEP(1); --"]
        for payload in payloads:
            resp = client.post(method, {"filters": payload, "name": payload})
            body_str = str(resp.body)
            if any(s in body_str for s in ("ProgrammingError", "OperationalError", "1064", "syntax error")):
                stdout.append(f"PROVEN: SQL error in response to injection payload {payload!r}")
                return True, stdout, stderr
        stdout.append("REFUTED or INCONCLUSIVE: no SQL error observed")
        return False, stdout, stderr

    def _proof_sqli_003(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-SQLI-003: set_value endpoint is reachable; validate() hooks bypassed."""
        resp = client.post(method)
        stdout.append(f"set_value endpoint {method}: HTTP {resp.status}")
        if resp.status == 200:
            stdout.append("POTENTIAL PROOF: set_value endpoint is reachable — validate() hooks bypassed")
            return True, stdout, stderr
        return False, stdout, stderr

    def _proof_sqli_004(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-SQLI-004: dynamic table name injection via frappe.qb."""
        injection = "tabUser`; SELECT SLEEP(1); --"
        resp = client.post(method, {"doctype": injection})
        body_str = str(resp.body)
        if any(s in body_str for s in ("ProgrammingError", "OperationalError", "1064")):
            stdout.append("PROVEN: SQL error via dynamic table name in frappe.qb")
            return True, stdout, stderr
        return False, stdout, stderr

    def _proof_inj_001(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-INJ-001: mass assignment via extra kwargs."""
        payload = {"name": "__probe__", "__islocal": 1, "owner": "hacker@example.com"}
        resp = client.post(method, payload)
        stdout.append(f"Mass-assign call to {method}: HTTP {resp.status}")
        if resp.status == 200 and not resp.is_permission_error:
            stdout.append("POTENTIAL PROOF: endpoint accepted unexpected fields — mass assignment possible")
            return True, stdout, stderr
        return False, stdout, stderr

    def _proof_inj_002(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-INJ-002: eval() payload sentinel."""
        sentinel = "__frapast_probe_7f3a__"
        resp = client.post(method, {"code": sentinel, "expr": sentinel})
        if sentinel in str(resp.body) or resp.status == 200:
            stdout.append("POTENTIAL PROOF: eval payload may have been executed")
            return True, stdout, stderr
        return False, stdout, stderr

    def _proof_csrf_001(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-CSRF-001: POST without CSRF token — proven if returns 200 instead of 417."""
        resp = client.post(method, include_csrf=False)
        stdout.append(f"No-CSRF call to {method}: HTTP {resp.status}")
        if resp.status == 417 or "CSRFTokenError" in str(resp.body):
            stdout.append("REFUTED: CSRF protection enforced (HTTP 417)")
            return False, stdout, stderr
        if resp.status == 200:
            stdout.append("PROVEN: endpoint accepted state-changing POST without CSRF token")
            return True, stdout, stderr
        return False, stdout, stderr

    def _proof_ssrf_001(self, method: str, client: FrappeHTTPClient, stdout: list, stderr: list) -> tuple[bool, list, list]:
        """FR-SSRF-001: user-controlled URL accepted without validation."""
        target = f"{self.base_url}/api/method/ping"
        resp = client.post(method, {"url": target, "endpoint": target})
        stdout.append(f"SSRF probe to {method}: HTTP {resp.status}")
        if resp.status == 200:
            stdout.append("POTENTIAL PROOF: endpoint accepted URL param — SSRF possible (verify with external listener)")
            return True, stdout, stderr
        return False, stdout, stderr
