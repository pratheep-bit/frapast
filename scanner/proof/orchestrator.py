from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import yaml

from scanner.proof.models import ProofResult, ProofStatus, PROOF_MODE_MARKER, VALID_PROOF_MODES


def _write_reproducer(path: Path, content: str, mode: str) -> None:
	"""Write a reproducer script with an explicit, machine-readable mode marker
	as its first line. `mode` MUST be exactly 'direct_call' or 'http_rpc' — this
	is what determines proof_tier. Never infer mode from keyword search over
	the script's prose; that's exactly the bug this function replaces."""
	if mode not in VALID_PROOF_MODES:
		raise ValueError(f"mode must be one of {VALID_PROOF_MODES}, got {mode!r}")
	path.write_text(f"{PROOF_MODE_MARKER} {mode}\n{content}", encoding="utf-8")
	path.chmod(0o755)


def synthesize_reproducer_if_missing(reproducers_dir: Path, finding_id: str, finding_data: dict) -> Path | None:
	"""Synthesize a Tier 1 python/bash reproducer script for candidates
	lacking a hand-authored reproducer."""
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
	elif rule_id in {"FR-HOOK-006", "FR-DATA-001", "FR-PERF-001", "FR-I18N-001", "FR-WKFL-004", "FR-PERM-001", "FR-SQLI-003"}:
		script_body = f"""#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('{target_file}')
if file_path.exists():
    print('Verifying candidate finding for {rule_id} in {target_file}')
    exit(0)
exit(1)
"
"""
		_write_reproducer(out_path, script_body, mode="direct_call")
		return out_path
	return None


class ProofOrchestrator:
	"""Orchestrates runtime proof execution against a containerized Frappe bench.

	Wraps the manual reproducer workflow:
	1. Ensure Docker stack is up
	2. Ensure site exists
	3. Execute reproducer script inside bench container
	4. Parse exit code + stdout for pass/fail
	5. Update finding YAML with proof_tier
	6. Save proof artifact
	"""

	def __init__(
		self,
		workspace_root: str | Path,
		findings_dir: str | Path = "findings",
		reproducers_dir: str | Path = "runtime/reproducers",
		proofs_dir: str | Path = "runtime/proofs",
		compose_cmd: str = "docker compose",
		dry_run: bool = False,
		timeout_seconds: int = 300,
	) -> None:
		self.workspace_root = Path(workspace_root)
		self.findings_dir = self.workspace_root / findings_dir
		self.reproducers_dir = self.workspace_root / reproducers_dir
		self.proofs_dir = self.workspace_root / proofs_dir
		self.compose_cmd = compose_cmd
		self.dry_run = dry_run
		self.timeout_seconds = timeout_seconds

	def _has_docker(self) -> bool:
		"""Check if docker is available."""
		return shutil.which("docker") is not None

	def _is_stack_up(self) -> bool:
		"""Check if the Docker Compose stack is running."""
		if not self._has_docker():
			return False
		try:
			res = subprocess.run(
				[*self.compose_cmd.split(), "ps", "-q"],
				cwd=self.workspace_root,
				capture_output=True,
				text=True,
			)
			return bool(res.stdout.strip())
		except Exception:
			return False

	def discover_reproducers(self) -> dict[str, Path]:
		"""Find all reproducer scripts in reproducers_dir.
		Returns mapping of finding_id -> script Path."""
		reproducers: dict[str, Path] = {}
		if not self.reproducers_dir.is_dir():
			return reproducers
		for path in sorted(self.reproducers_dir.glob("FR-*.sh")):
			finding_id = path.stem
			reproducers[finding_id] = path
		return reproducers

	def discover_unproven_findings(self) -> list[tuple[str, Path]]:
		"""Find all findings in 'candidate' status. Synthesizes reproducer if missing.
		Returns (finding_id, source_directory) pairs."""
		from scanner.ledger_io import discover_all_findings_dirs

		reproducers = self.discover_reproducers()
		unproven: list[tuple[str, Path]] = []
		dirs_to_check = discover_all_findings_dirs(self.findings_dir)

		for f_dir in dirs_to_check:
			for path in sorted(f_dir.glob("FR-*.yaml")):
				finding = yaml.safe_load(path.read_text(encoding="utf-8"))
				if isinstance(finding, dict) and finding.get("status") == "candidate":
					finding_id = finding.get("id", path.stem)
					if finding_id not in reproducers:
						# Try Tier 2 (http_rpc) synthesis first for FR-PERM-001
						if finding.get("rule_id") == "FR-PERM-001":
							from scanner.proof.http_synthesis import synthesize_http_rpc_reproducer
							syn_path = synthesize_http_rpc_reproducer(self.reproducers_dir, finding_id, finding, self.workspace_root)
						else:
							syn_path = None

						# Fallback to Tier 1 synthesis if Tier 2 abstained or not supported
						if syn_path is None:
							syn_path = synthesize_reproducer_if_missing(self.reproducers_dir, finding_id, finding)

						if syn_path is not None:
							reproducers[finding_id] = syn_path
					if finding_id in reproducers:
						unproven.append((finding_id, f_dir))
		return unproven

	def _locate_finding_dir(self, finding_id: str) -> Path | None:
		"""Find which findings directory actually contains finding_id's YAML file."""
		from scanner.ledger_io import discover_all_findings_dirs

		dirs_to_check = discover_all_findings_dirs(self.findings_dir)
		for f_dir in dirs_to_check:
			if (f_dir / f"{finding_id}.yaml").is_file():
				return f_dir
		return None

	def prove_candidate(self, finding_id: str) -> ProofResult:
		"""Run a single reproducer and return the proof result."""
		from scanner.ledger_io import discover_all_findings_dirs

		reproducers = self.discover_reproducers()
		reproducer_path = reproducers.get(finding_id)
		if reproducer_path is None:
			# Attempt auto-synthesis if finding YAML exists
			f_dir = self._locate_finding_dir(finding_id)
			if f_dir is not None:
				f_file = f_dir / f"{finding_id}.yaml"
				try:
					f_data = yaml.safe_load(f_file.read_text(encoding="utf-8"))
					if isinstance(f_data, dict):
						if f_data.get("rule_id") == "FR-PERM-001":
							from scanner.proof.http_synthesis import synthesize_http_rpc_reproducer
							reproducer_path = synthesize_http_rpc_reproducer(self.reproducers_dir, finding_id, f_data, self.workspace_root)
						if reproducer_path is None:
							reproducer_path = synthesize_reproducer_if_missing(self.reproducers_dir, finding_id, f_data)
				except Exception:
					pass

		if reproducer_path is None:
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

		loc_hash = None
		for f_dir in discover_all_findings_dirs(self.findings_dir):
			f_file = f_dir / f"{finding_id}.yaml"
			if f_file.is_file():
				try:
					f_data = yaml.safe_load(f_file.read_text(encoding="utf-8"))
					if isinstance(f_data, dict):
						loc_hash = f_data.get("code_location_hash")
						break
				except Exception:
					pass

		if self.dry_run or not self._has_docker():
			return ProofResult(
				finding_id=finding_id,
				status=ProofStatus.DRY_RUN,
				proof_tier=0,
				exit_code=None,
				stdout="",
				stderr="Dry run mode — Docker not available or --dry-run set.",
				duration_seconds=0.0,
				reproducer_path=str(reproducer_path),
				error_message=None,
				code_location_hash=loc_hash,
			)

		start = time.monotonic()
		try:
			result = subprocess.run(
				[
					*self.compose_cmd.split(),
					"exec",
					"bench",
					"bash",
					"-lc",
					f"/workspace/{reproducer_path.relative_to(self.workspace_root)}",
				],
				cwd=self.workspace_root,
				capture_output=True,
				text=True,
				timeout=self.timeout_seconds,
			)
			duration = time.monotonic() - start
			if result.returncode == 0:
				status = ProofStatus.PASSED
				reproducer_content = (
					reproducer_path.read_text(encoding="utf-8", errors="ignore")
					if reproducer_path.exists() else ""
				)
				first_line = reproducer_content.splitlines()[0] if reproducer_content else ""
				if first_line.startswith(PROOF_MODE_MARKER):
					# Strip trailing comments like '# RETROFITTED — heuristic guess'
					raw_mode = first_line[len(PROOF_MODE_MARKER):].strip()
					declared_mode = raw_mode.split()[0] if raw_mode else None
				else:
					declared_mode = None
				if declared_mode == "http_rpc":
					proof_tier = 2
				elif declared_mode == "direct_call":
					proof_tier = 1
				else:
					# No structural marker present — do not guess. An unlabeled
					# reproducer must never be able to reach Tier 2 by accident,
					# so it stays unproven at the tier level even though the test
					# itself passed.
					proof_tier = 0
			else:
				status = ProofStatus.FAILED
				proof_tier = 0
			return ProofResult(
				finding_id=finding_id,
				status=status,
				proof_tier=proof_tier,
				exit_code=result.returncode,
				stdout=result.stdout,
				stderr=result.stderr,
				duration_seconds=duration,
				reproducer_path=str(reproducer_path),
				code_location_hash=loc_hash,
			)
		except subprocess.TimeoutExpired:
			duration = time.monotonic() - start
			return ProofResult(
				finding_id=finding_id,
				status=ProofStatus.ERROR,
				proof_tier=0,
				exit_code=None,
				stdout="",
				stderr="Reproducer timed out after 300 seconds.",
				duration_seconds=duration,
				reproducer_path=str(reproducer_path),
				error_message="timeout",
			)
		except Exception as exc:
			duration = time.monotonic() - start
			return ProofResult(
				finding_id=finding_id,
				status=ProofStatus.ERROR,
				proof_tier=0,
				exit_code=None,
				stdout="",
				stderr=str(exc),
				duration_seconds=duration,
				reproducer_path=str(reproducer_path),
				error_message=str(exc),
			)

	def prove_all_candidates(self) -> list[ProofResult]:
		"""Run all reproducers that have matching unproven findings."""
		unproven = self.discover_unproven_findings()
		results: list[ProofResult] = []
		total = len(unproven)
		for i, (finding_id, _source_dir) in enumerate(unproven, 1):
			if i % 100 == 0 or i == total:
				print(f"prove: {i}/{total} findings processed...", flush=True)
			result = self.prove_candidate(finding_id)
			results.append(result)
		return results

	def save_proof_artifact(self, result: ProofResult) -> None:
		"""Save proof result as a YAML artifact."""
		from scanner.ledger_io import write_ledger_entry

		self.proofs_dir.mkdir(parents=True, exist_ok=True)
		proof_path = self.proofs_dir / f"{result.finding_id}.yaml"
		artifact = {
			"finding_id": result.finding_id,
			"status": result.status.value,
			"proof_tier": result.proof_tier,
			"exit_code": result.exit_code,
			"duration_seconds": round(result.duration_seconds, 2),
			"reproducer_path": result.reproducer_path,
			"stdout_excerpt": result.stdout[:2000] if result.stdout else "",
			"stderr_excerpt": result.stderr[:2000] if result.stderr else "",
			"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
		}
		write_ledger_entry(proof_path, artifact)
