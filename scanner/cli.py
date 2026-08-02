from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from datetime import date

import yaml

from scanner.ledger_io import read_ledger_entry, write_ledger_entry, update_ledger_after_proof, ledger_lock
from scanner.config import default_config, load_config
from scanner.fp import apply_fp_suppression, load_false_positives
from scanner.hooks import load as load_hooks
from scanner.proof.orchestrator import ProofOrchestrator
from scanner.python import load as load_python
from scanner.reporting import render_track_record
from scanner.rules import execute_rules, Candidate
from scanner.schema import load as load_schema
from scanner.severity import score_candidates
from scanner.shared import stable_hash
from scanner.fix import synthesize_fix
from scanner.validate import validate_and_stage
from scanner.pr import route_candidate, create_pr, run_pr_batch


def _load_indexes(repo_path: Path):
	schema = load_schema(repo_path)
	hooks = load_hooks(repo_path)
	python = load_python(repo_path)
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
) -> list[dict[str, object]]:
	"""Single implementation shared by scan() and scan_multi() so single-repo
	and multi-repo scans can never drift apart in behavior again."""
	schema, hooks, python = _load_indexes(repo_path)
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
	return candidates


def scan(
	repo_path: str | Path,
	*,
	fp_log_path: str | Path | None = None,
	repo_id: str | None = None,
	include_severity: bool = False,
) -> list[dict[str, object]]:
	return _scan_repo_with_severity(
		Path(repo_path), fp_log_path=fp_log_path, repo_id=repo_id or "local",
		include_severity=include_severity,
	)


def scan_multi(config_path: str | Path, *, include_severity: bool = False) -> dict[str, list[dict[str, object]]]:
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
			repo_path, fp_log_path=fp_path, repo_id=repo.id, include_severity=include_severity,
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
			results = scan_multi(args.config, include_severity=args.severity)
			output = {"results": results}
		elif args.repo_path:
			repo = Path(args.repo_path)
			fp_log_path = args.fp_log if Path(args.fp_log).is_file() else None
			candidates = _scan_repo_with_severity(
				repo, fp_log_path=fp_log_path, repo_id=args.repo_id,
				include_severity=args.severity,
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

	elif args.command == "prove":
		orchestrator = ProofOrchestrator(
			workspace_root=args.workspace,
			dry_run=args.dry_run,
		)
		if args.finding_id:
			result = orchestrator.prove_candidate(args.finding_id)
			source_dir = orchestrator._locate_finding_dir(args.finding_id)
			if not args.dry_run and source_dir is not None:
				update_ledger_after_proof(source_dir, result)
				orchestrator.save_proof_artifact(result)
			elif not args.dry_run:
				print(f"Warning: could not locate ledger entry for {args.finding_id} in any findings directory; not written.")
			proof_dict = {**result.__dict__, "status": getattr(result.status, "value", str(result.status))}
			print(yaml.safe_dump({"proof": proof_dict}, sort_keys=False, default_flow_style=False))
		else:
			unproven = orchestrator.discover_unproven_findings()
			id_to_dir = dict(unproven)
			results = orchestrator.prove_all_candidates()
			if not args.dry_run:
				for r in results:
					source_dir = id_to_dir.get(r.finding_id) or orchestrator._locate_finding_dir(r.finding_id)
					if source_dir is not None:
						update_ledger_after_proof(source_dir, r)
					orchestrator.save_proof_artifact(r)
			summary = {
				"total": len(results),
				"passed": sum(1 for r in results if r.status.value == "passed"),
				"failed": sum(1 for r in results if r.status.value == "failed"),
				"error": sum(1 for r in results if r.status.value == "error"),
				"skipped": sum(1 for r in results if r.status.value == "skipped"),
				"dry_run": sum(1 for r in results if r.status.value == "dry_run"),
				"results": [{**r.__dict__, "status": r.status.value} for r in results],
			}
			print(yaml.safe_dump({"proof_run": summary}, sort_keys=False, default_flow_style=False))
		return 0

	elif args.command == "report":
		print(render_track_record(args.findings_dir))
		return 0

	elif args.command == "fix" or args.command == "pr":
		repo_path = Path(args.repo_path)
		findings_dir = repo_path / "findings" if (repo_path / "findings").is_dir() else Path("findings")
		
		# Auto-discover fp-log.yaml to apply FP suppression for fix/pr
		fp_log = findings_dir / "fp-log.yaml"
		fp_log_path = str(fp_log) if fp_log.is_file() else None
		
		candidates_data = scan(repo_path, fp_log_path=fp_log_path, repo_id="local")
		candidates = [
			Candidate(**{k: v for k, v in c.items() if k in Candidate.__dataclass_fields__})
			for c in candidates_data
		]

		# MANDATORY GATE — never synthesize a fix or open a PR for a finding that
		# hasn't cleared Tier 2+ runtime proof. Not optional, not bypassable by a flag.
		proven_findings = _load_proven_findings(findings_dir, min_tier=2)
		candidates = [c for c in candidates if c.code_location_hash in proven_findings]

		if not candidates:
			print("No Tier 2+ proven findings eligible for fix/PR. Run `prove` first.")
			return 0
		
		# If finding-file is provided (for fix)
		if getattr(args, "finding_file", None):
			finding = yaml.safe_load(Path(args.finding_file).read_text())
			candidates = [c for c in candidates if c.code_location_hash == finding.get("code_location_hash")]
		
		# Synthesize + statically validate every eligible candidate up front.
		from scanner.fix.engine import cst
		if cst is None:
			print("Warning: libcst is not installed in the python environment. Automated code fix synthesis is disabled and candidates will fall back to manual triage.")

		fixable: list[tuple[Candidate, str]] = []
		for candidate in candidates:
			if route_candidate(candidate) != "pr":
				continue

			print(f"Synthesizing fix for {candidate.rule_id} in {candidate.file}...")
			fixed_code = synthesize_fix(candidate, repo_path)
			if not fixed_code:
				print("Failed to synthesize fix.")
				continue

			print("Validating fix...")
			if not validate_and_stage(candidate, repo_path, fixed_code):
				print("Validation failed. Skipping PR/Fix.")
				continue

			print("Validation successful.")
			fixable.append((candidate, fixed_code))

		if args.command == "fix":
			for candidate, fixed_code in fixable:
				preview_path = repo_path / f"{candidate.file}.{candidate.rule_id}.fixed"
				preview_path.parent.mkdir(parents=True, exist_ok=True)
				preview_path.write_text(fixed_code)
				print(f"Wrote fix preview to {preview_path}")
		elif args.command == "pr":
			max_prs = getattr(args, "max_prs", 5)
			created = run_pr_batch(fixable, repo_path, live=args.live, max_prs=max_prs)
			if created == 0 and fixable:
				print("No PR was created this run (all candidates were duplicates or failed) — nothing left to try.")

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
