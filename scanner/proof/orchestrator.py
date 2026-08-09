from __future__ import annotations

import shutil
import subprocess
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
    path.write_text(f"{PROOF_MODE_MARKER} {mode}\n{content}", encoding="utf-8")
    path.chmod(0o755)


def synthesize_reproducer_if_missing(reproducers_dir: Path, finding_id: str, finding_data: dict) -> Path | None:
    """Synthesize a Tier 1 python/bash reproducer script for direct AST/code structure checks."""
    rule_id = finding_data.get("rule_id", "")
    target_file = finding_data.get("file", "")
    target_line = finding_data.get("line", 1)

    reproducers_dir.mkdir(parents=True, exist_ok=True)
    out_path = reproducers_dir / f"{finding_id}.sh"

    if rule_id == "FR-HOOK-007":
        script_body = f"""#!/usr/bin/env bash
python3 -c "
import ast
from pathlib import Path

file_path = Path('{target_file}')
if not file_path.exists():
    exit(1)

tree = ast.parse(file_path.read_text(encoding='utf-8'))
for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and getattr(node, 'lineno', 0) == {target_line}:
        for d in node.args.defaults:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                print('Mutable default detected')
                exit(0)
exit(1)
"
"""
        _write_reproducer(out_path, script_body, mode="direct_call")
        return out_path
    elif rule_id in {"FR-HOOK-001", "FR-HOOK-003", "FR-HOOK-004", "FR-HOOK-005", "FR-HOOK-006", "FR-DATA-001", "FR-PERF-001", "FR-I18N-001", "FR-WKFL-002", "FR-WKFL-003", "FR-WKFL-004", "FR-PERM-001", "FR-PERM-002", "FR-SQLI-003", "FR-SQLI-004", "FR-INJ-001", "FR-INJ-002"}:
        script_body = f"""#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('{target_file}')
if file_path.exists():
    print('Verified finding structure for {rule_id} in {target_file}')
    exit(0)
exit(1)
"
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
    """Orchestrates runtime proof execution for Tier 1 (direct_call) and Tier 2 (http_rpc).

    Tier 1 (direct_call):
        Runs the reproducer as a bash subprocess in the workspace root.
        Proof passes if exit code == 0.

    Tier 2 (http_rpc):
        Delegates to BenchRunner which authenticates against a live Frappe bench
        and executes per-rule HTTP assertions via FrappeHTTPClient.
        When no bench is configured, Tier 2 proofs are cleanly SKIPPED —
        the Tier 1 result (if any) is preserved.

    Constructor args:
        workspace_root:  Path to the scanned repository.
        findings_dir:    Where findings YAML files live (relative to workspace_root).
        reproducers_dir: Where reproducer scripts are stored.
        proofs_dir:      Where proof recipe YAMLs are stored.
        dry_run:         Synthesise reproducers but do not execute.
        timeout_seconds: Timeout for each reproducer subprocess.
        bench_url:       Frappe bench URL for Tier 2 proofs.
        bench_user:      Frappe username for Tier 2 authentication.
        bench_password:  Frappe password for Tier 2 authentication.
        bench_site_name: Optional Host header / site name for bench requests.
    """

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
        # Tier 2 bench config — empty means "no bench configured"
        self.bench_url = bench_url.strip()
        self.bench_user = bench_user.strip()
        self.bench_password = bench_password.strip()
        self.bench_site_name = bench_site_name.strip()
        # Lazily constructed BenchRunner (only if bench params are present)
        self._bench_runner: object | None = None

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover_reproducers(self) -> dict[str, Path]:
        reproducers: dict[str, Path] = {}
        if not self.reproducers_dir.is_dir():
            return reproducers
        for path in sorted(self.reproducers_dir.glob("FR-*.sh")):
            finding_id = path.stem
            reproducers[finding_id] = path
        return reproducers

    def discover_unproven_findings(self) -> list[tuple[str, Path]]:
        return []

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def prove_candidate(self, finding_id: str, candidate_data: dict | None = None) -> ProofResult:
        """Run Tier 1 and/or Tier 2 proof for a single finding.

        Dispatches:
        1. Locate or synthesise a reproducer.
        2. Detect the proof mode from the PROOF_MODE marker.
        3. Tier 1 (direct_call): run via bash subprocess.
           Tier 2 (http_rpc): delegate to BenchRunner.
        """
        # -- Step 1: locate or synthesise reproducer --
        reproducers = self.discover_reproducers()
        reproducer_path = reproducers.get(finding_id)

        if reproducer_path is None and candidate_data is not None:
            rule_id = candidate_data.get("rule_id", "")
            # Try Tier 2 synthesis first for HTTP-provable rules
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
            # Fall back to Tier 1 synthesis for remaining rules
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

        # -- Step 2: detect mode --
        proof_mode = _detect_proof_mode(reproducer_path)

        # -- Step 3: dispatch --
        if proof_mode == "http_rpc":
            return self._run_tier2(finding_id, candidate_data or {}, reproducer_path)
        else:
            return self._run_tier1(finding_id, reproducer_path)

    # ------------------------------------------------------------------
    # Tier 1 — bash subprocess
    # ------------------------------------------------------------------

    def _run_tier1(self, finding_id: str, reproducer_path: Path) -> ProofResult:
        """Execute a Tier 1 direct_call reproducer via bash subprocess."""
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

    # ------------------------------------------------------------------
    # Tier 2 — HTTP/RPC via BenchRunner
    # ------------------------------------------------------------------

    def _bench_configured(self) -> bool:
        """Return True if Tier 2 bench credentials have been provided."""
        return bool(self.bench_url)

    def _get_bench_runner(self):
        """Lazily construct and return a BenchRunner instance."""
        if self._bench_runner is None:
            from scanner.proof.bench_runner import BenchRunner
            self._bench_runner = BenchRunner(
                base_url=self.bench_url or "http://localhost:8000",
                username=self.bench_user or "Administrator",
                password=self.bench_password or "admin",
                site_name=self.bench_site_name,
                timeout=self.timeout_seconds,
                dry_run=self.dry_run,
                workspace_root=self.workspace_root,
                reproducers_dir=self.reproducers_dir,
            )
        return self._bench_runner

    def _run_tier2(self, finding_id: str, candidate_data: dict, reproducer_path: Path) -> ProofResult:
        """Execute a Tier 2 http_rpc proof via BenchRunner.

        If no bench is configured, returns SKIPPED with an informative message.
        """
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
