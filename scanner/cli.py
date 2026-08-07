from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

import yaml

__version__ = "0.4.7"

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


@dataclass(frozen=True)
class RepoScanResult:
	repo_id: str
	repo_path: Path
	candidates: list[dict[str, object]]
	num_files: int
	elapsed: float


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


def _load_eligible_findings(
	findings_dir: str | Path,
	*,
	min_tier: int = 2,
	finding_id: str | None = None,
) -> list[dict[str, object]]:
	findings_path = Path(findings_dir)
	if not findings_path.is_dir():
		return []
	eligible: list[dict[str, object]] = []
	for path in sorted(findings_path.glob("*.yaml")):
		entry = read_ledger_entry(path)
		if entry is None:
			continue
		if finding_id and entry.get("id") != finding_id and path.stem != finding_id:
			continue
		if entry.get("status") == "proven" and (entry.get("proof_tier") or 0) >= min_tier:
			eligible.append(entry)
	return eligible


def _run_gated_workflow_command(args: argparse.Namespace, workflow_name: str) -> int:
	eligible = _load_eligible_findings(
		args.findings_dir,
		min_tier=args.min_tier,
		finding_id=args.finding_id,
	)
	payload = {
		"workflow": workflow_name,
		"min_tier": args.min_tier,
		"eligible": eligible,
	}
	if args.format in ("json", "yaml"):
		_write_json_or_yaml(payload, args.format)
		return 0 if eligible else 1

	if not eligible:
		console.print(
			f"[muted]No Tier {args.min_tier}+ proven findings are eligible for {workflow_name}. "
			"Run `frapast scan <repo> --write-ledger --prove` first.[/muted]"
		)
		return 1

	console.print(f"[heading]{workflow_name.title()} Eligibility[/heading]")
	for entry in eligible:
		console.print(
			f"  [bold]{entry.get('id')}[/bold]  "
			f"{entry.get('rule_id')}  {entry.get('file')}:{entry.get('line', '?')}  "
			f"tier={entry.get('proof_tier')}"
		)
	if workflow_name == "fix":
		console.print("[muted]Automatic fix synthesis is not implemented in this build; these findings satisfy the proof gate.[/muted]")
	else:
		console.print("[muted]Automatic PR creation is not implemented in this build; these findings satisfy the proof gate.[/muted]")
	return 0


def _finding_id(candidate: dict[str, object], repo_id: str) -> str:
	identity = (
		f"{repo_id}:{candidate['rule_id']}:{candidate['file']}:"
		f"{candidate['function']}:{candidate['code_location_hash']}"
	)
	return f"{candidate['taxonomy_id']}-{stable_hash(identity)}"


def _candidate_repo_id(candidate: dict[str, object], default_repo_id: str) -> str:
	value = candidate.get("_repo_id") or candidate.get("repo_id") or default_repo_id
	return str(value)


def _candidate_repo_path(candidate: dict[str, object], default_repo: Path) -> Path:
	value = candidate.get("_repo_path") or candidate.get("repo_path")
	return Path(str(value)) if value else default_repo


def _strip_internal_candidate_fields(candidate: dict[str, object]) -> dict[str, object]:
	return {key: value for key, value in candidate.items() if not str(key).startswith("_")}


def _prepare_output_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
	return [_strip_internal_candidate_fields(candidate) for candidate in candidates]


def _extract_candidate_list(payload: dict) -> list[dict[str, object]]:
	candidates = payload.get("candidates")
	if isinstance(candidates, list):
		return candidates
	proven = payload.get("proven")
	if isinstance(proven, list):
		return proven
	results = payload.get("results")
	if isinstance(results, dict):
		flattened: list[dict[str, object]] = []
		for value in results.values():
			if isinstance(value, list):
				flattened.extend(item for item in value if isinstance(item, dict))
		return flattened
	return []


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
	if include_severity:
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


def _scan_config_entries(
	config_path: str | Path,
	*,
	include_severity: bool,
	show_progress: bool,
	fp_log_path: str | Path | None = None,
	diff_ref: str | None = None,
) -> list[RepoScanResult]:
	config = load_config(config_path)
	config_fp_path = Path(fp_log_path or config.fp_log)
	fp_path = config_fp_path if config_fp_path.is_file() else None
	results: list[RepoScanResult] = []
	for repo in config.repos:
		if not repo.enabled:
			continue
		repo_path = Path(repo.path)
		if not repo_path.exists():
			results.append(RepoScanResult(repo.id, repo_path, [], 0, 0.0))
			continue
		c_list, num_files, elapsed = _scan_repo_with_severity(
			repo_path,
			fp_log_path=fp_path,
			repo_id=repo.id,
			include_severity=include_severity,
			show_progress=show_progress,
		)
		if diff_ref:
			c_list = _filter_candidates_by_diff(c_list, repo_path, diff_ref)
		for candidate in c_list:
			candidate["_repo_id"] = repo.id
			candidate["_repo_path"] = str(repo_path)
		results.append(RepoScanResult(repo.id, repo_path, c_list, num_files, elapsed))
	return results


def _config_findings_dir(config_path: str | Path, requested_ledger_dir: str | Path) -> Path:
	config = load_config(config_path)
	if str(requested_ledger_dir) == "findings":
		return Path(config.findings_dir)
	return Path(requested_ledger_dir)


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
	prove_parser.add_argument("--ledger-dir", default="findings", help="Directory for findings YAML files")
	prove_parser.add_argument("--repo-id", default="local", help="Repository identifier for generated finding IDs")
	prove_parser.add_argument("--format", choices=["human", "yaml", "json", "sarif"], default="human", help="Output format")
	prove_parser.add_argument("--limit", type=int, default=20, help="Maximum number of candidates to display in human output")

	fix_parser = subparsers.add_parser("fix", help="Show proof-gated findings eligible for fix work")
	fix_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")
	fix_parser.add_argument("--min-tier", type=int, default=2, help="Minimum proof tier required for fix eligibility")
	fix_parser.add_argument("--finding-id", help="Filter to one finding ID")
	fix_parser.add_argument("--format", choices=["human", "yaml", "json"], default="human", help="Output format")

	pr_parser = subparsers.add_parser("pr", help="Show proof-gated findings eligible for PR work")
	pr_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")
	pr_parser.add_argument("--min-tier", type=int, default=2, help="Minimum proof tier required for PR eligibility")
	pr_parser.add_argument("--finding-id", help="Filter to one finding ID")
	pr_parser.add_argument("--format", choices=["human", "yaml", "json"], default="human", help="Output format")

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
		print(export_sarif(_prepare_output_candidates(_extract_candidate_list(payload)), repo_path or Path(".")))
	elif fmt == "json":
		print(json.dumps(_prepare_payload_for_output(payload), indent=2, default=str))
	else:
		print(yaml.safe_dump(_prepare_payload_for_output(payload), sort_keys=False))


def _prepare_payload_for_output(payload: dict) -> dict:
	if isinstance(payload.get("candidates"), list) or isinstance(payload.get("proven"), list):
		prepared = dict(payload)
		if isinstance(payload.get("candidates"), list):
			prepared["candidates"] = _prepare_output_candidates(payload["candidates"])
		if isinstance(payload.get("proven"), list):
			prepared["proven"] = _prepare_output_candidates(payload["proven"])
		return prepared
	if isinstance(payload.get("results"), dict):
		results = {}
		for repo_id, candidates in payload["results"].items():
			if isinstance(candidates, list):
				results[repo_id] = _prepare_output_candidates(candidates)
			else:
				results[repo_id] = candidates
		return {**payload, "results": results}
	return payload


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
		need_severity = args.severity or args.format == "human" or args.prove
		scan_results = _scan_config_entries(
			config_path,
			include_severity=need_severity,
			show_progress=True,
			fp_log_path=args.fp_log,
			diff_ref=args.diff,
		)
		ledger_dir = _config_findings_dir(config_path, args.ledger_dir)
		if args.write_ledger:
			for result in scan_results:
				_write_candidates(result.candidates, ledger_dir, result.repo_id)
		proven_findings: list[dict[str, object]] = []
		if args.prove:
			for result in scan_results:
				proven_findings.extend(
					_run_proof_verification(
						result.candidates,
						result.repo_path,
						result.repo_id,
						findings_dir=ledger_dir if args.write_ledger else None,
					)
				)
		results = {result.repo_id: result.candidates for result in scan_results}
		total_candidates = sum(len(result.candidates) for result in scan_results)
		output = {"results": results}
		if proven_findings:
			output["proven"] = proven_findings
		if args.format in ("json", "yaml", "sarif"):
			_write_json_or_yaml(output, args.format)
		else:
			for result in scan_results:
				ui.render_results(result.repo_path, result.candidates, result.num_files, result.elapsed, limit=args.limit)
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
		include_severity=args.severity or args.format == "human" or args.prove,
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
		from scanner.ui.menus import select_post_scan_action, select_bug_to_view
		from scanner.ui.results import render_code_snippet, candidate_score

		active_candidates = candidates
		while True:
			action = select_post_scan_action(active_candidates)
			if action in ("prove_top10", "prove_top20", "prove_all"):
				if action == "prove_top10":
					candidates_to_prove = sorted(active_candidates, key=candidate_score, reverse=True)[:10]
				elif action == "prove_top20":
					candidates_to_prove = sorted(active_candidates, key=candidate_score, reverse=True)[:20]
				else:
					candidates_to_prove = active_candidates

				proven_findings = _run_proof_verification(
					candidates_to_prove,
					repo,
					args.repo_id,
					findings_dir=Path(args.ledger_dir) if args.write_ledger else None,
				)
				console.print(
					f"\n[success]✓ proof complete:[/success] "
					f"{len(proven_findings)} / {len(candidates_to_prove)} candidates verified as PROVEN."
				)
				active_candidates = candidates
				ui.render_results(repo, active_candidates, num_files, elapsed, limit=args.limit)

			elif action == "inspect":
				bug_idx = select_bug_to_view(active_candidates)
				if bug_idx is not None:
					sorted_cands = sorted(active_candidates, key=candidate_score, reverse=True)
					render_code_snippet(repo, sorted_cands[bug_idx - 1], bug_id=bug_idx)

			elif action == "filter_proven":
				proven_subset = [c for c in active_candidates if str(c.get("status", "")).lower() == "proven"]
				ui.render_results(repo, proven_subset, num_files, elapsed, limit=args.limit)

			elif action == "filter_all":
				ui.render_results(repo, active_candidates, num_files, elapsed, limit=args.limit)

			elif action == "export_json":
				out_file = repo / "frapast_findings.json"
				out_file.write_text(json.dumps({"candidates": active_candidates}, indent=2, default=str), encoding="utf-8")
				console.print(f"[success]✓ Saved {len(active_candidates)} findings to '{out_file.resolve()}'[/success]\n")

			elif action == "report":
				from rich.markdown import Markdown
				from scanner.reporting.engine import render_track_record
				console.print(Markdown(render_track_record("findings")))

			elif action == "exit":
				break
	elif args.prove:
		candidates_to_prove = candidates
		proven_findings = _run_proof_verification(
			candidates_to_prove,
			repo,
			args.repo_id,
			findings_dir=Path(args.ledger_dir) if args.write_ledger else None,
		)
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


def _run_post_scan_inspector_loop(repo: Path, candidates: list[dict]) -> None:
	from scanner.ui.menus import select_bug_to_view
	from scanner.ui.results import render_code_snippet, candidate_score
	bug_idx = select_bug_to_view(candidates)
	if bug_idx is not None:
		sorted_cands = sorted(candidates, key=candidate_score, reverse=True)
		render_code_snippet(repo, sorted_cands[bug_idx - 1], bug_id=bug_idx)


def _run_proof_verification(
	candidates_to_prove: list[dict],
	repo: Path,
	repo_id: str,
	*,
	findings_dir: str | Path | None = None,
) -> list[dict]:
	from scanner.proof.orchestrator import ProofOrchestrator
	from scanner.proof.models import ProofStatus

	orchestrator = ProofOrchestrator(workspace_root=repo)
	proven_findings: list[dict] = []
	if not candidates_to_prove:
		return proven_findings
	with ui.proof_progress(len(candidates_to_prove), "Verifying candidates") as advance:
		for c in candidates_to_prove:
			rule_id = c.get("rule_id", "")
			func = c.get("function", "")
			loc_hash = str(c.get("code_location_hash", ""))
			candidate_repo_id = _candidate_repo_id(c, repo_id)
			fid = _finding_id(c, candidate_repo_id)
			c["id"] = fid
			res = orchestrator.prove_candidate(fid, candidate_data=c)
			if loc_hash:
				res = replace(res, code_location_hash=loc_hash)
			c["proof_status"] = getattr(res.status, "value", str(res.status))
			c["proof_error"] = res.error_message
			advance(f"{rule_id} in {func}")
			if findings_dir is not None:
				update_ledger_after_proof(findings_dir, res)
			if res.status == ProofStatus.PASSED:
				c["proof_tier"] = res.proof_tier
				c["status"] = "proven"
				proven_findings.append(c)
	return proven_findings


def _run_interactive(initial_repo: str | None = None) -> int:
	state: dict[str, object] = {"repo": None, "repo_id": "local", "candidates": [], "num_files": 0, "elapsed": 0.0}

	def do_scan(
		*,
		path: str | None = None,
		config: str | None = None,
		severity: bool = False,
		limit: int = 20,
		write_ledger: bool = False,
		ledger_dir: str = "findings",
		repo_id: str = "local",
		fp_log: str = "findings/fp-log.yaml",
		prove: bool = False,
		diff: str | None = None,
	) -> None:
		if config:
			config_path = Path(config)
			if not config_path.is_file():
				console.print(f"[severity.critical]config '{config}' not found[/severity.critical]")
				return
			scan_results = _scan_config_entries(
				config_path,
				include_severity=True,
				show_progress=True,
				fp_log_path=fp_log,
				diff_ref=diff,
			)
			config_ledger_dir = _config_findings_dir(config_path, ledger_dir)
			if write_ledger:
				for result in scan_results:
					_write_candidates(result.candidates, config_ledger_dir, result.repo_id)
			if prove:
				for result in scan_results:
					_run_proof_verification(
						result.candidates,
						result.repo_path,
						result.repo_id,
						findings_dir=config_ledger_dir if write_ledger else None,
					)
			total = sum(len(result.candidates) for result in scan_results)
			for result in scan_results:
				ui.render_results(result.repo_path, result.candidates, result.num_files, result.elapsed, limit=limit)
			state["candidates"] = [c for result in scan_results for c in result.candidates]
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

		fp_log_path = fp_log if Path(fp_log).is_file() else None
		candidates, num_files, elapsed = _scan_repo_with_severity(
			repo, fp_log_path=fp_log_path, repo_id=repo_id, include_severity=True, show_progress=True,
		)
		if diff:
			candidates = _filter_candidates_by_diff(candidates, repo, diff)
		if write_ledger:
			_write_candidates(candidates, Path(ledger_dir), repo_id)
		if prove:
			_run_proof_verification(
				candidates,
				repo,
				repo_id,
				findings_dir=Path(ledger_dir) if write_ledger else None,
			)
		ui.render_results(repo, candidates, num_files, elapsed, limit=limit)
		state.update(repo=repo, repo_id=repo_id, candidates=candidates, num_files=num_files, elapsed=elapsed)

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
		ui.render_results(repo, candidates, int(state.get("num_files", 0)), float(state.get("elapsed", 0.0)), limit=20)

	def do_view(*, bug_id: int) -> None:
		from scanner.ui.results import render_code_snippet, candidate_score
		cands = state.get("candidates") or []
		repo = state.get("repo") or Path(".")
		if not cands:
			console.print("[muted]No findings to view yet — run /scan first.[/muted]")
			return
		sorted_cands = sorted(cands, key=candidate_score, reverse=True)
		if 1 <= bug_id <= len(sorted_cands):
			cand = sorted_cands[bug_id - 1]
			render_code_snippet(_candidate_repo_path(cand, repo), cand, bug_id=bug_id)
		else:
			console.print(f"[severity.critical]Invalid bug ID '{bug_id}'. Choose a number between 1 and {len(sorted_cands)}.[/severity.critical]")

	def do_report(*, findings_dir: str = "findings") -> None:
		from rich.markdown import Markdown
		console.print(Markdown(render_track_record(findings_dir)))

	def do_fix(*, findings_dir: str = "findings", min_tier: int = 2, finding_id: str | None = None) -> None:
		args = argparse.Namespace(findings_dir=findings_dir, min_tier=min_tier, finding_id=finding_id, format="human")
		_run_gated_workflow_command(args, "fix")

	def do_pr(*, findings_dir: str = "findings", min_tier: int = 2, finding_id: str | None = None) -> None:
		args = argparse.Namespace(findings_dir=findings_dir, min_tier=min_tier, finding_id=finding_id, format="human")
		_run_gated_workflow_command(args, "pr")

	def do_fp_report(*, findings_dir: str = "findings") -> None:
		from scanner.fp_analyzer import print_report
		print_report(findings_dir)

	shell = ui.InteractiveShell(
		version=__version__,
		run_scan=do_scan,
		run_prove=do_prove,
		run_report=do_report,
		run_fp_report=do_fp_report,
		run_view=do_view,
		run_fix=do_fix,
		run_pr=do_pr,
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
			update_ledger_after_proof(args.ledger_dir, result)
			proof_dict = {**result.__dict__, "status": getattr(result.status, "value", str(result.status))}
			if args.format == "json":
				print(json.dumps({"proof": proof_dict}, indent=2, default=str))
			else:
				print(yaml.safe_dump({"proof": proof_dict}, sort_keys=False))
		else:
			if not repo.exists():
				sys.stderr.write(f"Error: path '{args.repo_path}' does not exist\n")
				return 2
			candidates, num_files, elapsed = _scan_repo_with_severity(
				repo,
				fp_log_path=None,
				repo_id=args.repo_id,
				include_severity=True,
				show_progress=True,
			)
			_write_candidates(candidates, Path(args.ledger_dir), args.repo_id)
			proven_findings = _run_proof_verification(
				candidates,
				repo,
				args.repo_id,
				findings_dir=Path(args.ledger_dir),
			)
			if args.format in ("json", "yaml", "sarif"):
				_write_json_or_yaml({"candidates": candidates, "proven": proven_findings}, args.format, repo)
			else:
				console.print(
					f"\n[success]✓ proof complete:[/success] "
					f"{len(proven_findings)} / {len(candidates)} candidates verified as PROVEN."
				)
				ui.render_results(repo, candidates, num_files, elapsed, limit=args.limit)
			return 1 if candidates else 0
		return 0

	if args.command == "fix":
		return _run_gated_workflow_command(args, "fix")

	if args.command == "pr":
		return _run_gated_workflow_command(args, "pr")

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
		for raw_candidate in candidates:
			candidate = _strip_internal_candidate_fields(raw_candidate)
			finding_id = _finding_id(candidate, repo_id)
			raw_candidate["id"] = finding_id
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
