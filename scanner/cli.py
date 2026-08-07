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

__version__ = "0.1.0"

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

	def _progress(current: int, total: int) -> None:
		python_files_count[0] = total
		sys.stderr.write(f"\rScanning... [{current}/{total} files]")
		sys.stderr.flush()

	cb = _progress if show_progress else None
	schema, hooks, python = _load_indexes(repo_path, progress_callback=cb)
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

	if show_progress:
		sys.stderr.write("\r\033[K")
		sys.stderr.flush()

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


def _render_human_summary(
	repo_path: Path,
	candidates: list[dict[str, object]],
	num_files: int,
	elapsed: float,
	limit: int = 20,
) -> None:
	is_tty = sys.stdout.isatty()
	try:
		from rich.console import Console
		from rich.table import Table

		console = Console(force_terminal=is_tty, no_color=not is_tty)

		if not candidates:
			console.print(
				f"[bold green]✓[/bold green] Scanned [bold]{num_files}[/bold] files in "
				f"[bold]{elapsed:.2f}s[/bold] — [bold green]0 candidates found (clean)[/bold green]."
			)
			return

		# Sort candidates by severity score descending
		def _get_score(cand: dict[str, object]) -> float:
			sev = cand.get("severity")
			if isinstance(sev, dict):
				return float(sev.get("score", 0.0))
			return 0.0

		sorted_candidates = sorted(candidates, key=_get_score, reverse=True)

		display_candidates = sorted_candidates[:limit] if limit > 0 else sorted_candidates

		table = Table(
			title=f"Security Audit Results — {repo_path}",
			title_style="bold cyan",
			header_style="bold magenta",
		)
		table.add_column("Rule ID", style="bold yellow")
		table.add_column("File:Line", style="cyan")
		table.add_column("Function", style="white")
		table.add_column("Severity / Evidence", style="dim white")

		for c in display_candidates:
			sev_info = c.get("severity")
			score = sev_info.get("score", 0.0) if isinstance(sev_info, dict) else 0.0

			if score >= 60:
				sev_badge = f"[bold red]CRITICAL ({score:.0f})[/bold red]"
			elif score >= 40:
				sev_badge = f"[bold yellow]HIGH ({score:.0f})[/bold yellow]"
			elif score >= 20:
				sev_badge = f"[yellow]MEDIUM ({score:.0f})[/yellow]"
			elif score > 0:
				sev_badge = f"[green]LOW ({score:.0f})[/green]"
			else:
				sev_badge = ""

			file_line = f"{c.get('file', '')}:{c.get('line', '')}"
			func = str(c.get("function", ""))
			evidence = str(c.get("evidence", ""))

			evidence_str = f"{sev_badge} {evidence}" if sev_badge else evidence
			table.add_row(str(c.get("rule_id")), file_line, func, evidence_str)

		console.print(table)
		if limit > 0 and len(candidates) > limit:
			console.print(
				f"\n[bold]{len(candidates)}[/bold] candidates found across "
				f"[bold]{num_files}[/bold] files in [bold]{elapsed:.2f}s[/bold] "
				f"(showing top [bold]{limit}[/bold] by severity. Use [bold]--limit 0[/bold] for full list)."
			)
		else:
			console.print(
				f"\n[bold]{len(candidates)}[/bold] candidates found across "
				f"[bold]{num_files}[/bold] files in [bold]{elapsed:.2f}s[/bold]."
			)

	except ImportError:
		if not candidates:
			print(f"✓ Scanned {num_files} files in {elapsed:.2f}s — 0 candidates found (clean).")
			return
		print(f"\nSecurity Audit Results — {repo_path}\n" + "=" * 50)
		for c in candidates[:limit] if limit > 0 else candidates:
			print(f"  [{c.get('rule_id')}] {c.get('file')}:{c.get('line')} in {c.get('function')}: {c.get('evidence')}")
		print(f"\n{len(candidates)} candidates found across {num_files} files in {elapsed:.2f}s.")


KNOWN_COMMANDS = {"scan", "prove", "report", "fp-report", "fix", "pr"}


def main(argv: list[str] | None = None) -> int:
	raw_args = sys.argv[1:] if argv is None else argv
	if raw_args and not raw_args[0].startswith("-") and raw_args[0] not in KNOWN_COMMANDS:
		return _legacy_main(raw_args)

	parser = argparse.ArgumentParser(
		prog="frapast",
		description="frapast — Framework-aware static security scanner for Frappe & ERPNext applications.",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Examples:
  frapast scan /path/to/erpnext
  frapast scan /path/to/frappe-app --severity --format json
  frapast scan --config scan_config.yaml
""",
	)
	parser.add_argument("--version", action="version", version=_get_version_string())
	subparsers = parser.add_subparsers(dest="command", help="Available commands")

	# scan command
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
	scan_parser.add_argument("--limit", type=int, default=20, help="Maximum number of candidates to display in human output (default: 20; 0 for all)")
	scan_parser.add_argument("--format", choices=["human", "yaml", "json"], default="human", help="Output format (default: human)")

	# prove command
	prove_parser = subparsers.add_parser("prove", help="Run Tier 1 & Tier 2 proof verification")
	prove_parser.add_argument("repo_path", nargs="?", default=".", help="Path to repository")
	prove_parser.add_argument("--finding-id", help="Prove a specific finding (or all candidates if omitted)")
	prove_parser.add_argument("--dry-run", action="store_true", help="Show what would be proven without executing")

	# report command
	report_parser = subparsers.add_parser("report", help="Generate track-record report")
	report_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")

	# fp-report command
	fp_report_parser = subparsers.add_parser("fp-report", help="Show false-positive rates per rule")
	fp_report_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")

	args = parser.parse_args(argv)

	if args.command is None:
		parser.print_help()
		return 0

	if args.command == "scan":
		if args.config:
			config_path = Path(args.config)
			if not config_path.is_file():
				sys.stderr.write(f"Error: path '{args.config}' does not exist\n")
				return 2
			results = scan_multi(config_path, include_severity=args.severity, show_progress=True)
			total_candidates = sum(len(c_list) for c_list in results.values())
			output = {"results": results}
			if args.format == "json":
				print(json.dumps(output, indent=2, default=str))
			elif args.format == "yaml":
				print(yaml.safe_dump(output, sort_keys=False))
			else:
				for repo_id, c_list in results.items():
					_render_human_summary(Path(repo_id), c_list, len(c_list), 0.0, limit=args.limit)
			return 1 if total_candidates > 0 else 0

		elif args.repo_path:
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
			output = {"candidates": candidates}
			if args.write_ledger:
				_write_candidates(candidates, Path(args.ledger_dir), args.repo_id)

			should_prove = args.prove
			if not should_prove and candidates and sys.stdout.isatty() and args.format == "human":
				_render_human_summary(repo, candidates, num_files, elapsed, limit=args.limit)
				try:
					resp = input(f"\nFound {len(candidates)} candidates. Proceed to Tier 1 & Tier 2 proof verification? [y/N]: ")
					if resp.strip().lower() in {"y", "yes"}:
						should_prove = True
				except (KeyboardInterrupt, EOFError):
					print()

			if should_prove and candidates:
				from scanner.proof.orchestrator import ProofOrchestrator
				from scanner.proof.models import ProofStatus
				orchestrator = ProofOrchestrator(workspace_root=repo)
				proven_findings = []
				for c in candidates:
					rule_id = c.get("rule_id", "")
					file_path = c.get("file", "")
					func = c.get("function", "")
					loc_hash = c.get("code_location_hash", "")
					identity = f"{args.repo_id}:{rule_id}:{file_path}:{func}:{loc_hash}"
					fid = f"{c['taxonomy_id']}-{stable_hash(identity)}"
					res = orchestrator.prove_candidate(fid, candidate_data=c)
					if res.status == ProofStatus.PASSED:
						c["proof_tier"] = res.proof_tier
						c["status"] = "proven"
						proven_findings.append(c)

				if args.format == "json":
					print(json.dumps({"candidates": candidates, "proven": proven_findings}, indent=2, default=str))
				elif args.format == "yaml":
					print(yaml.safe_dump({"candidates": candidates, "proven": proven_findings}, sort_keys=False))
				else:
					_render_human_summary(repo, proven_findings if proven_findings else candidates, num_files, elapsed, limit=args.limit)
			else:
				if args.format == "json":
					print(json.dumps(output, indent=2, default=str))
				elif args.format == "yaml":
					print(yaml.safe_dump(output, sort_keys=False))
				elif not (candidates and sys.stdout.isatty() and not args.prove):
					_render_human_summary(repo, candidates, num_files, elapsed, limit=args.limit)

			return 1 if len(candidates) > 0 else 0

		else:
			sys.stderr.write("Error: missing required argument 'repo_path' or '--config'\n")
			scan_parser.print_help(sys.stderr)
			return 2

	elif args.command == "prove":
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

	elif args.command == "fp-report":
		from scanner.fp_analyzer import print_report

		print_report(args.findings_dir)
		return 0

	else:
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
