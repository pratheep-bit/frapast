from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections.abc import Callable
from datetime import date
from pathlib import Path

import yaml

__version__ = "0.3.1"

from scanner import ui
from scanner.config import default_config, load_config
from scanner.fp import apply_fp_suppression, load_false_positives
from scanner.hooks import load as load_hooks
from scanner.ledger_io import ledger_lock, read_ledger_entry, update_ledger_after_proof, write_ledger_entry
from scanner.python import load as load_python
from scanner.reporting import render_track_record
from scanner.rules import Candidate, execute_rules
from scanner.schema import load as load_schema
from scanner.severity import score_candidates
from scanner.shared import stable_hash
from scanner.ui.theme import console


def _get_version_string() -> str:
	py_ver = f"Python {platform.python_version()}"
	try:
		import rich
		rich_status = "rich: available"
	except ImportError:
		rich_status = "rich: unavailable"
	try:
		import libcst
		libcst_status = "libcst: available"
	except ImportError:
		libcst_status = "libcst: unavailable"
	return f"frapast {__version__} ({py_ver}, {rich_status}, {libcst_status})"


def _load_indexes(
	repo_path: Path,
	progress_callback: Callable[[int, int], None] | None = None,
):
	schema = load_schema(repo_path)
	hooks = load_hooks(repo_path)
	python = load_python(repo_path, progress_callback=progress_callback)
	return schema, hooks, python


def _load_proven_findings(findings_dir: str | Path, min_tier: int = 2) -> dict[str, dict]:
	"""Load ledger entries that have cleared runtime proof at or above min_tier."""
	proven: dict[str, dict] = {}
	findings_path = Path(findings_dir)
	if not findings_path.is_dir():
		return proven
	for path in findings_path.glob("*.yaml"):
		entry = read_ledger_entry(path)
		if entry is None:
			continue
		if entry.get("status") == "proven" and (entry.get("proof_tier") or 0) >= min_tier:
			loc_hash = entry.get("code_location_hash")
			if loc_hash:
				proven[loc_hash] = entry
	return proven


def _scan_repo_with_severity(
	repo_path: Path,
	*,
	fp_log_path: str | Path | None,
	repo_id: str,
	include_severity: bool,
	show_progress: bool = False,
) -> tuple[list[dict[str, object]], int, float]:
	t0 = time.perf_counter()
	python_files_count = [0]

	if show_progress:
		with ui.scan_progress(f"scanning {repo_path.name or repo_path}") as cb:
			def _progress(current: int, total: int) -> None:
				python_files_count[0] = total
				cb(current, total)

			schema, hooks, python = _load_indexes(repo_path, progress_callback=_progress)
	else:
		schema, hooks, python = _load_indexes(repo_path, progress_callback=None)

	candidate_objs = execute_rules(schema, hooks, python)
	if fp_log_path is not None and Path(fp_log_path).is_file():
		candidate_objs = list(
			apply_fp_suppression(candidate_objs, load_false_positives(fp_log_path), repo_id).candidates
		)
	candidates = [c.__dict__ for c in candidate_objs]
	guest_endpoints = {e.function for e in python.whitelisted_endpoints if e.allow_guest}
	scored = score_candidates(candidate_objs, guest_endpoints=guest_endpoints)
	score_by_key = {
		(c.rule_id, c.file, c.line, c.code_location_hash): score for c, score in scored
	}
	for c in candidates:
		key = (c["rule_id"], c["file"], c["line"], c["code_location_hash"])
		score = score_by_key.get(key)
		if score is not None:
			c["severity"] = score.__dict__

	elapsed = time.perf_counter() - t0
	num_files = python_files_count[0] or len(python.functions)

	return candidates, num_files, elapsed


def scan(
	repo_path: str | Path,
	*,
	fp_log_path: str | Path | None = None,
	repo_id: str | None = None,
	include_severity: bool = False,
	show_progress: bool = False,
) -> list[dict[str, object]]:
	candidates, _, _ = _scan_repo_with_severity(
		Path(repo_path),
		fp_log_path=fp_log_path,
		repo_id=repo_id or "local",
		include_severity=include_severity,
		show_progress=show_progress,
	)
	return candidates


def scan_multi(
	config_path: str | Path,
	*,
	include_severity: bool = False,
	show_progress: bool = False,
) -> dict[str, list[dict[str, object]]]:
	config = load_config(config_path)
	all_results: dict[str, list[dict[str, object]]] = {}
	fp_path = Path(config.fp_log) if Path(config.fp_log).is_file() else None
	for repo in config.repos:
		if not repo.enabled:
			continue
		repo_path = Path(repo.path)
		if not repo_path.exists():
			all_results[repo.id] = []
			continue
		c_list, _, _ = _scan_repo_with_severity(
			repo_path,
			fp_log_path=fp_path,
			repo_id=repo.id,
			include_severity=include_severity,
			show_progress=show_progress,
		)
		all_results[repo.id] = c_list
	return all_results


KNOWN_COMMANDS = {"scan", "prove", "report", "fp-report", "fix", "pr", "shell"}


def _build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		prog="frapast",
		description="frapast — Framework-aware static security scanner for Frappe & ERPNext applications.",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Examples:
  frapast                              launch the interactive shell
  frapast scan /path/to/erpnext
  frapast scan /path/to/frappe-app --severity --format json
  frapast scan --config scan_config.yaml
""",
	)
	parser.add_argument("--version", action="version", version=_get_version_string())
	subparsers = parser.add_subparsers(dest="command", help="Available commands")

	scan_parser = subparsers.add_parser(
		"scan",
		help="Run static security analysis against one or more Frappe repositories",
		description="Run static security analysis against one or more Frappe repositories.",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Examples:
  frapast scan /path/to/frappe-app
  frapast scan /path/to/frappe-app --severity --format json
  frapast scan --config scan_config.yaml --write-ledger
""",
	)
	scan_parser.add_argument("repo_path", nargs="?", help="Path to a single repo to scan")
	scan_parser.add_argument("--config", help="Path to multi-repo scan config YAML")
	scan_parser.add_argument("--prove", action="store_true", help="Automatically run Tier 1 & Tier 2 proof verification on findings")
	scan_parser.add_argument("--write-ledger", action="store_true", help="Write findings to ledger directory")
	scan_parser.add_argument("--ledger-dir", default="findings", help="Directory for findings YAML files")
	scan_parser.add_argument("--repo-id", default="local", help="Repository identifier for ledger entries")
	scan_parser.add_argument("--fp-log", default="findings/fp-log.yaml", help="Path to false-positive log")
	scan_parser.add_argument("--severity", action="store_true", help="Include severity scores in output")
	scan_parser.add_argument("--diff", help="Scan only files modified relative to a git branch/commit (e.g. main, origin/main)")
	scan_parser.add_argument("--limit", type=int, default=20, help="Maximum number of candidates to display in human output (default: 20; 0 for all)")
	scan_parser.add_argument("--format", choices=["human", "yaml", "json", "sarif"], default="human", help="Output format (default: human)")

	prove_parser = subparsers.add_parser("prove", help="Run Tier 1 & Tier 2 proof verification")
	prove_parser.add_argument("repo_path", nargs="?", default=".", help="Path to repository")
	prove_parser.add_argument("--finding-id", help="Prove a specific finding (or all candidates if omitted)")
	prove_parser.add_argument("--dry-run", action="store_true", help="Show what would be proven without executing")

	report_parser = subparsers.add_parser("report", help="Generate track-record report")
	report_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")

	fp_report_parser = subparsers.add_parser("fp-report", help="Show false-positive rates per rule")
	fp_report_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")

	shell_parser = subparsers.add_parser("shell", help="Launch the interactive frapast shell")
	shell_parser.add_argument("repo_path", nargs="?", help="Repository to pre-load as the shell's working target")

	return parser


def _write_json_or_yaml(payload: dict, fmt: str, repo_path: Path | None = None) -> None:
	if fmt == "sarif":
		from scanner.reporting.sarif import export_sarif
		cands = payload.get("candidates") or payload.get("proven") or []
		if isinstance(cands, list):
			print(export_sarif(cands, repo_path or Path(".")))
		else:
			print(json.dumps(payload, indent=2, default=str))
	elif fmt == "json":
		print(json.dumps(payload, indent=2, default=str))
	else:
		print(yaml.safe_dump(payload, sort_keys=False))


def _filter_candidates_by_diff(candidates: list[dict[str, object]], repo_path: Path, diff_ref: str) -> list[dict[str, object]]:
	import subprocess
	try:
		res = subprocess.run(
			["git", "diff", "--name-only", diff_ref],
			cwd=repo_path,
			capture_output=True,
			text=True,
			check=True,
		)
		changed_files = set(res.stdout.splitlines())
		if not changed_files:
			return []
		return [
			c for c in candidates
			if str(c.get("file", "")) in changed_files or any(str(c.get("file", "")).endswith(f) for f in changed_files)
		]
	except Exception as exc:
		sys.stderr.write(f"Warning: failed to compute git diff against '{diff_ref}': {exc}\n")
		return candidates


def _run_scan_command(args: argparse.Namespace) -> int:
	if args.config:
		config_path = Path(args.config)
		if not config_path.is_file():
			sys.stderr.write(f"Error: path '{args.config}' does not exist\n")
			return 2
		results = scan_multi(config_path, include_severity=args.severity, show_progress=True)
		total_candidates = sum(len(c_list) for c_list in results.values())
		output = {"results": results}
		if args.format in ("json", "yaml", "sarif"):
			_write_json_or_yaml(output, args.format)
		else:
			for repo_id, c_list in results.items():
				ui.render_results(Path(repo_id), c_list, len(c_list), 0.0, limit=args.limit)
		return 1 if total_candidates > 0 else 0

	if not args.repo_path:
		sys.stderr.write("Error: missing required argument 'repo_path' or '--config'\n")
		return 2

	repo = Path(args.repo_path)
	if not repo.exists():
		sys.stderr.write(f"Error: path '{args.repo_path}' does not exist\n")
		return 2

	from scanner.python.engine import discover_python_files
	py_files = discover_python_files(repo)
	if not py_files:
		sys.stderr.write(f"Error: No Python files found in '{args.repo_path}'\n")
		return 2

	fp_log_path = args.fp_log if Path(args.fp_log).is_file() else None
	candidates, num_files, elapsed = _scan_repo_with_severity(
		repo,
		fp_log_path=fp_log_path,
		repo_id=args.repo_id,
		include_severity=args.severity,
		show_progress=True,
	)

	if args.diff:
		candidates = _filter_candidates_by_diff(candidates, repo, args.diff)

	output = {"candidates": candidates}
	if args.write_ledger:
		_write_candidates(candidates, Path(args.ledger_dir), args.repo_id)

	candidates_to_prove: list[dict[str, object]] = []
	interactive = not args.prove and candidates and sys.stdout.isatty() and args.format == "human"
	if interactive:
		ui.render_results(repo, candidates, num_files, elapsed, limit=args.limit)
		candidates_to_prove = ui.select_proof_scope(candidates)
	elif args.prove:
		candidates_to_prove = candidates

	if candidates_to_prove:
		proven_findings = _run_proof_verification(candidates_to_prove, repo, args.repo_id)
		if args.format in ("json", "yaml", "sarif"):
			_write_json_or_yaml({"candidates": candidates, "proven": proven_findings}, args.format, repo)
		else:
			console.print(
				f"\n[success]✓ proof complete:[/success] "
				f"{len(proven_findings)} / {len(candidates_to_prove)} candidates verified as PROVEN."
			)
			ui.render_results(repo, proven_findings or candidates_to_prove, num_files, elapsed, limit=args.limit)
	else:
		if args.format in ("json", "yaml", "sarif"):
			_write_json_or_yaml(output, args.format, repo)
		elif not interactive:
			ui.render_results(repo, candidates, num_files, elapsed, limit=args.limit)

	return 1 if len(candidates) > 0 else 0


def _run_proof_verification(candidates_to_prove: list[dict], repo: Path, repo_id: str) -> list[dict]:
	from scanner.proof.orchestrator import ProofOrchestrator
	from scanner.proof.models import ProofStatus

	orchestrator = ProofOrchestrator(workspace_root=repo)
	proven_findings: list[dict] = []
	with ui.proof_progress(len(candidates_to_prove), "Verifying candidates") as advance:
		for c in candidates_to_prove:
			rule_id = c.get("rule_id", "")
			file_path = c.get("file", "")
			func = c.get("function", "")
			loc_hash = c.get("code_location_hash", "")
			identity = f"{repo_id}:{rule_id}:{file_path}:{func}:{loc_hash}"
			fid = f"{c['taxonomy_id']}-{stable_hash(identity)}"
			res = orchestrator.prove_candidate(fid, candidate_data=c)
			advance(f"{rule_id} in {func}")
			if res.status == ProofStatus.PASSED:
				c["proof_tier"] = res.proof_tier
				c["status"] = "proven"
				proven_findings.append(c)
	return proven_findings


def _run_interactive(initial_repo: str | None = None) -> int:
	state: dict[str, object] = {"repo": None, "repo_id": "local", "candidates": [], "num_files": 0, "elapsed": 0.0}

	def do_scan(*, path: str | None = None, config: str | None = None, severity: bool = False, limit: int = 20) -> None:
		if config:
			config_path = Path(config)
			if not config_path.is_file():
				console.print(f"[severity.critical]config '{config}' not found[/severity.critical]")
				return
			results = scan_multi(config_path, include_severity=severity, show_progress=True)
			total = sum(len(v) for v in results.values())
			for repo_id, c_list in results.items():
				ui.render_results(Path(repo_id), c_list, len(c_list), 0.0, limit=limit)
			state["candidates"] = [c for c_list in results.values() for c in c_list]
			state["repo"] = None
			state["repo_id"] = "multi"
			console.print(f"[muted]{total} total candidates across {len(results)} repos[/muted]\n")
			return

		repo = Path(path or ".")
		if not repo.exists():
			console.print(f"[severity.critical]path '{repo}' does not exist[/severity.critical]")
			return
		from scanner.python.engine import discover_python_files
		if not discover_python_files(repo):
			console.print(f"[muted]no Python files found in '{repo}'[/muted]")
			return

		fp_log_path = "findings/fp-log.yaml" if Path("findings/fp-log.yaml").is_file() else None
		candidates, num_files, elapsed = _scan_repo_with_severity(
			repo, fp_log_path=fp_log_path, repo_id="local", include_severity=severity, show_progress=True,
		)
		ui.render_results(repo, candidates, num_files, elapsed, limit=limit)
		state.update(repo=repo, repo_id="local", candidates=candidates, num_files=num_files, elapsed=elapsed)

	def do_prove(*, finding_id: str | None = None, dry_run: bool = False) -> None:
		from scanner.proof.orchestrator import ProofOrchestrator
		from scanner.proof.models import ProofStatus

		repo = state.get("repo") or Path(".")
		orchestrator = ProofOrchestrator(workspace_root=repo, dry_run=dry_run)

		if finding_id:
			result = orchestrator.prove_candidate(finding_id)
			proof_dict = {**result.__dict__, "status": getattr(result.status, "value", str(result.status))}
			console.print(yaml.safe_dump({"proof": proof_dict}, sort_keys=False))
			return

		candidates = state.get("candidates") or []
		if not candidates:
			console.print("[muted]nothing to prove yet — run /scan first[/muted]")
			return

		chosen = ui.select_proof_scope(candidates)
		if not chosen:
			console.print("[muted]skipped.[/muted]\n")
			return

		proven = _run_proof_verification(chosen, repo, str(state.get("repo_id", "local")))
		console.print(f"\n[success]✓ proof complete:[/success] {len(proven)} / {len(chosen)} verified as PROVEN.\n")
		ui.render_results(repo, proven or chosen, int(state.get("num_files", 0)), float(state.get("elapsed", 0.0)), limit=20)

	def do_report(*, findings_dir: str = "findings") -> None:
		console.print(render_track_record(findings_dir))

	def do_fp_report(*, findings_dir: str = "findings") -> None:
		from scanner.fp_analyzer import print_report
		print_report(findings_dir)

	shell = ui.InteractiveShell(
		version=__version__,
		run_scan=do_scan,
		run_prove=do_prove,
		run_report=do_report,
		run_fp_report=do_fp_report,
	)
	return shell.run(initial_repo=initial_repo)


def main(argv: list[str] | None = None) -> int:
	raw_args = sys.argv[1:] if argv is None else argv
	if raw_args and not raw_args[0].startswith("-") and raw_args[0] not in KNOWN_COMMANDS:
		return _legacy_main(raw_args)

	parser = _build_parser()
	args = parser.parse_args(argv)

	if args.command is None:
		if sys.stdout.isatty():
			return _run_interactive()
		parser.print_help()
		return 0

	if args.command == "shell":
		return _run_interactive(args.repo_path)

	if args.command == "scan":
		return _run_scan_command(args)

	if args.command == "prove":
		repo = Path(args.repo_path)
		from scanner.proof.orchestrator import ProofOrchestrator
		orchestrator = ProofOrchestrator(workspace_root=repo, dry_run=args.dry_run)
		if args.finding_id:
			result = orchestrator.prove_candidate(args.finding_id)
			proof_dict = {**result.__dict__, "status": getattr(result.status, "value", str(result.status))}
			print(yaml.safe_dump({"proof": proof_dict}, sort_keys=False))
		else:
			print(f"Proof engine ready for {repo}.")
		return 0

	if args.command == "report":
		print(render_track_record(args.findings_dir))
		return 0

	if args.command == "fp-report":
		from scanner.fp_analyzer import print_report
		print_report(args.findings_dir)
		return 0

	parser.print_help()
	return 0


def _legacy_main(argv: list[str] | None = None) -> int:
	"""Backward-compatible CLI for single repo_path argument."""
	parser = argparse.ArgumentParser(prog="frapast")
	parser.add_argument("repo_path")
	parser.add_argument("--write-ledger", action="store_true")
	parser.add_argument("--ledger-dir", default="findings")
	parser.add_argument("--repo-id", default="local")
	parser.add_argument("--fp-log", default="findings/fp-log.yaml")
	args = parser.parse_args(argv)

	repo = Path(args.repo_path)
	if not repo.exists():
		sys.stderr.write(f"Error: path '{args.repo_path}' does not exist\n")
		return 2

	from scanner.python.engine import discover_python_files
	py_files = discover_python_files(repo)
	if not py_files:
		sys.stderr.write(f"Error: No Python files found in '{args.repo_path}'\n")
		return 2

	candidates = scan(args.repo_path, fp_log_path=args.fp_log, repo_id=args.repo_id)
	print(yaml.safe_dump({"candidates": candidates}, sort_keys=False))
	if args.write_ledger:
		_write_candidates(candidates, Path(args.ledger_dir), args.repo_id)
	return 1 if len(candidates) > 0 else 0


def _write_candidates(candidates: list[dict[str, object]], findings: Path, repo_id: str) -> None:
	findings.mkdir(exist_ok=True)
	with ledger_lock(findings):
		for candidate in candidates:
			identity = (
				f"{repo_id}:{candidate['rule_id']}:{candidate['file']}:"
				f"{candidate['function']}:{candidate['code_location_hash']}"
			)
			finding_id = f"{candidate['taxonomy_id']}-{stable_hash(identity)}"
			path = findings / f"{finding_id}.yaml"
			if path.exists():
				continue

			severity = candidate.get("severity")
			if severity is None:
				from scanner.rules import Candidate as _CandidateCls
				from scanner.severity import score_candidate
				cand_obj = _CandidateCls(**{
					k: v for k, v in candidate.items() if k in _CandidateCls.__dataclass_fields__
				})
				score = score_candidate(
					cand_obj,
					allow_guest=bool(candidate.get("allow_guest", False)),
					proof_tier=candidate.get("proof_tier", 0) or 0,
				)
				severity = score.__dict__
			dims = severity.get("dimension_scores", {})

			record = {
				"id": finding_id,
				"taxonomy_id": candidate["taxonomy_id"],
				"rule_id": candidate["rule_id"],
				"rule_version": candidate["rule_version"],
				"repo": repo_id,
				"file": candidate["file"],
				"function": candidate["function"],
				"status": "candidate",
				"proof_tier": 0,
				"privilege_required": dims.get("privilege_required", "unknown"),
				"allow_guest": bool(dims.get("allow_guest", candidate.get("allow_guest", False))),
				"impact_class": dims.get("impact_class", "unknown"),
				"blast_radius": dims.get("blast_radius", "unknown"),
				"code_location_hash": candidate["code_location_hash"],
				"discovered": date.today().isoformat(),
				"proven": None,
				"notes": f"{candidate['evidence']} Proof recipe: {candidate['proof_recipe']}",
			}
			write_ledger_entry(path, record)


if __name__ == "__main__":
	raise SystemExit(main())
