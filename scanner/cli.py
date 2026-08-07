from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from datetime import date

import yaml

__version__ = "0.1.0"

from scanner.ledger_io import read_ledger_entry, write_ledger_entry, update_ledger_after_proof, ledger_lock
from scanner.config import default_config, load_config
from scanner.fp import apply_fp_suppression, load_false_positives
from scanner.hooks import load as load_hooks
from scanner.python import load as load_python
from scanner.reporting import render_track_record
from scanner.rules import execute_rules, Candidate
import time
from collections.abc import Callable

from scanner.schema import load as load_schema
from scanner.severity import score_candidates
from scanner.shared import stable_hash


def _load_indexes(
	repo_path: Path,
	progress_callback: Callable[[int, int], None] | None = None,
):
	schema = load_schema(repo_path)
	hooks = load_hooks(repo_path)
	python = load_python(repo_path, progress_callback=progress_callback)
	return schema, hooks, python


def _load_proven_findings(findings_dir: str | Path, min_tier: int = 2) -> dict[str, dict]:
	"""Load ledger entries that have cleared runtime proof at or above min_tier.
	Only these are eligible for automated fix synthesis or PR creation — this is
	a hard gate, not a default that can be bypassed by a CLI flag."""
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
) -> list[dict[str, object]]:
	"""Single implementation shared by scan() and scan_multi() so single-repo
	and multi-repo scans can never drift apart in behavior again."""
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

	if show_progress:
		elapsed = time.perf_counter() - t0
		num_files = python_files_count[0] or len(python.functions)
		sys.stderr.write(
			f"\rScan complete: {num_files} files scanned in {elapsed:.2f}s ({len(candidates)} candidates found).\n"
		)
		sys.stderr.flush()

	return candidates


def scan(
	repo_path: str | Path,
	*,
	fp_log_path: str | Path | None = None,
	repo_id: str | None = None,
	include_severity: bool = False,
	show_progress: bool = False,
) -> list[dict[str, object]]:
	return _scan_repo_with_severity(
		Path(repo_path),
		fp_log_path=fp_log_path,
		repo_id=repo_id or "local",
		include_severity=include_severity,
		show_progress=show_progress,
	)


def scan_multi(
	config_path: str | Path,
	*,
	include_severity: bool = False,
	show_progress: bool = False,
) -> dict[str, list[dict[str, object]]]:
	"""Scan multiple repos using a config file."""
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
		all_results[repo.id] = _scan_repo_with_severity(
			repo_path,
			fp_log_path=fp_path,
			repo_id=repo.id,
			include_severity=include_severity,
			show_progress=show_progress,
		)
	return all_results





KNOWN_COMMANDS = {"scan", "prove", "report", "fp-report", "fix", "pr"}

def main(argv: list[str] | None = None) -> int:
	raw_args = sys.argv[1:] if argv is None else argv
	if raw_args and not raw_args[0].startswith("-") and raw_args[0] not in KNOWN_COMMANDS:
		return _legacy_main(raw_args)

	parser = argparse.ArgumentParser(
		prog="frappe-security-scan",
		description="Frappe-specific security scanner — static analysis with mandatory runtime proof.",
	)
	parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
	subparsers = parser.add_subparsers(dest="command", help="Available commands")

	# scan command
	scan_parser = subparsers.add_parser("scan", help="Run scanner against one or more repos")
	scan_parser.add_argument("repo_path", nargs="?", help="Path to a single repo to scan")
	scan_parser.add_argument("--config", help="Path to multi-repo scan config YAML")
	scan_parser.add_argument("--write-ledger", action="store_true", help="Write findings to ledger directory")
	scan_parser.add_argument("--ledger-dir", default="findings", help="Directory for findings YAML files")
	scan_parser.add_argument("--repo-id", default="local", help="Repository identifier for ledger entries")
	scan_parser.add_argument("--fp-log", default="findings/fp-log.yaml", help="Path to false-positive log")
	scan_parser.add_argument("--severity", action="store_true", help="Include severity scores in output")
	scan_parser.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output format")

	# prove command
	prove_parser = subparsers.add_parser("prove", help="Run runtime proof reproducers")
	prove_parser.add_argument("--finding-id", help="Prove a specific finding (or all unproven if omitted)")
	prove_parser.add_argument("--dry-run", action="store_true", help="Show what would be proven without executing")
	prove_parser.add_argument("--workspace", default=".", help="Workspace root directory")

	# report command
	report_parser = subparsers.add_parser("report", help="Generate track-record report")
	report_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")

	# fp-report command
	fp_report_parser = subparsers.add_parser("fp-report", help="Show false-positive rates per rule")
	fp_report_parser.add_argument("--findings-dir", default="findings", help="Path to findings directory")

	# fix command
	fix_parser = subparsers.add_parser("fix", help="Synthesize and validate fixes for candidates")
	fix_parser.add_argument("repo_path", help="Path to the repo")
	fix_parser.add_argument("--finding-file", help="Path to a specific finding yaml file")

	# pr command
	pr_parser = subparsers.add_parser("pr", help="Synthesize, validate, and create PRs")
	pr_parser.add_argument("repo_path", help="Path to the repo")
	pr_parser.add_argument(
		"--live", action="store_true",
		help="Actually create the PR. Without this flag, runs in dry-run preview mode (default).",
	)
	pr_parser.add_argument(
		"--max-prs", type=int, default=5,
		help="Maximum number of PRs to create per batch run (default: 5).",
	)
	
	args = parser.parse_args(argv)

	if args.command is None:
		parser.print_help()
		return 0

	if args.command == "scan":
		if args.config:
			results = scan_multi(args.config, include_severity=args.severity, show_progress=True)
			output = {"results": results}
		elif args.repo_path:
			repo = Path(args.repo_path)
			fp_log_path = args.fp_log if Path(args.fp_log).is_file() else None
			candidates = _scan_repo_with_severity(
				repo, fp_log_path=fp_log_path, repo_id=args.repo_id,
				include_severity=args.severity, show_progress=True,
			)
			output = {"candidates": candidates}
			if args.write_ledger:
				_write_candidates(candidates, Path(args.ledger_dir), args.repo_id)
		else:
			scan_parser.print_help()
			return 1

		if args.format == "json":
			print(json.dumps(output, indent=2, default=str))
		else:
			print(yaml.safe_dump(output, sort_keys=False))
		return 0

	elif args.command in {"prove", "fix", "pr"}:
		print(f"The '{args.command}' subcommand is part of the internal engine (runtime proof, fix synthesis, PR automation) and is not included in this open-source static scanner release.")
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
	parser = argparse.ArgumentParser(prog="frappe-security-scan")
	parser.add_argument("repo_path")
	parser.add_argument("--write-ledger", action="store_true")
	parser.add_argument("--ledger-dir", default="findings")
	parser.add_argument("--repo-id", default="local")
	parser.add_argument("--fp-log", default="findings/fp-log.yaml")
	args = parser.parse_args(argv)
	candidates = scan(args.repo_path, fp_log_path=args.fp_log, repo_id=args.repo_id)
	print(yaml.safe_dump({"candidates": candidates}, sort_keys=False))
	if args.write_ledger:
		_write_candidates(candidates, Path(args.ledger_dir), args.repo_id)
	return 0


def _write_candidates(candidates: list[dict[str, object]], findings: Path, repo_id: str) -> None:
	findings.mkdir(exist_ok=True)
	with ledger_lock(findings):
		for candidate in candidates:
			# NOTE: line number deliberately excluded — it shifts on any unrelated
			# upstream edit and would silently break dedup + FP-log matching.
			# function name + code_location_hash are the stable identity anchors.
			identity = (
				f"{repo_id}:{candidate['rule_id']}:{candidate['file']}:"
				f"{candidate['function']}:{candidate['code_location_hash']}"
			)
			finding_id = f"{candidate['taxonomy_id']}-{stable_hash(identity)}"
			path = findings / f"{finding_id}.yaml"
			if path.exists():
				continue

			# Compute REAL severity classification rather than hardcoding a
			# placeholder for every finding regardless of rule
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
