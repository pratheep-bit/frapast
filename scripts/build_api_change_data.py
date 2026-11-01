#!/usr/bin/env python3
"""Build Frappe framework public API change data across git branches.

Extracts public API symbols (functions, classes, methods, whitelisted RPC endpoints)
from git branches via AST parsing, tracks additions, removals, relocations, and
deprecation annotations, and exports a deterministic JSON database.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Alias Mapping Table
# ---------------------------------------------------------------------------
# Maps common runtime accessors/facades to their canonical definitions.
ALIAS_PREFIXES: dict[str, str] = {
	# frappe.db.<method> delegates to methods of Database in frappe/database/database.py
	"frappe.db": "frappe.database.database.Database",
}


@dataclass(frozen=True)
class SymbolRecord:
	name: str
	kind: str  # "function" | "class" | "method"
	file: str
	line: int
	whitelisted: bool
	deprecated: bool
	deprecation_msg: str | None


def _run_git(repo: Path, *args: str) -> str:
	res = subprocess.run(
		["git", "-C", str(repo)] + list(args),
		capture_output=True,
		text=True,
		check=True,
	)
	return res.stdout.strip()


def _get_branch_sha(repo: Path, ref: str) -> str:
	try:
		return _run_git(repo, "rev-parse", ref)
	except Exception:
		# Fallback to origin/<ref> if local ref not found
		return _run_git(repo, "rev-parse", f"origin/{ref}")


def _export_branch_to_temp(repo: Path, ref: str, dest_dir: Path) -> None:
	"""Export the tree of `ref` into `dest_dir` using git archive without checkout."""
	p1 = subprocess.Popen(
		["git", "-C", str(repo), "archive", ref],
		stdout=subprocess.PIPE,
	)
	p2 = subprocess.Popen(
		["tar", "-x", "-C", str(dest_dir)],
		stdin=p1.stdout,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
	)
	if p1.stdout:
		p1.stdout.close()
	p2.communicate()
	if p2.returncode != 0:
		raise RuntimeError(f"Failed to archive ref '{ref}'")


def _is_whitelisted_node(decorator_list: list[ast.expr]) -> bool:
	for dec in decorator_list:
		if isinstance(dec, ast.Name) and dec.id == "whitelist":
			return True
		if isinstance(dec, ast.Attribute) and dec.attr == "whitelist":
			return True
		if isinstance(dec, ast.Call):
			func = dec.func
			if isinstance(func, ast.Name) and func.id == "whitelist":
				return True
			if isinstance(func, ast.Attribute) and func.attr == "whitelist":
				return True
	return False


def _extract_deprecation_info(decorator_list: list[ast.expr], body: list[ast.stmt]) -> tuple[bool, str | None]:
	for dec in decorator_list:
		name = ""
		if isinstance(dec, ast.Name):
			name = dec.id
		elif isinstance(dec, ast.Attribute):
			name = dec.attr
		elif isinstance(dec, ast.Call):
			if isinstance(dec.func, ast.Name):
				name = dec.func.id
			elif isinstance(dec.func, ast.Attribute):
				name = dec.func.attr
			if name == "deprecated":
				# Extract message if present in call args
				for arg in dec.args:
					if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
						return True, arg.value
				for kw in dec.keywords:
					if isinstance(kw.value, ast.Constant) and isinstance(kw.value, str):
						return True, kw.value
				return True, None
		if name == "deprecated":
			return True, None

	# Check body for deprecation_warning(...) call
	for stmt in body:
		for subnode in ast.walk(stmt):
			if isinstance(subnode, ast.Call):
				call_name = ""
				if isinstance(subnode.func, ast.Name):
					call_name = subnode.func.id
				elif isinstance(subnode.func, ast.Attribute):
					call_name = subnode.func.attr
				if call_name == "deprecation_warning":
					for arg in subnode.args:
						if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
							return True, arg.value
					return True, None

	return False, None


def _parse_module_symbols(file_path: Path, rel_path: str, module_path: str) -> list[SymbolRecord]:
	try:
		tree = ast.parse(file_path.read_text(encoding="utf-8", errors="ignore"), filename=str(file_path))
	except Exception:
		return []

	symbols: list[SymbolRecord] = []

	for node in tree.body:
		# Module-level functions
		if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
			if node.name.startswith("_"):
				continue
			whitelisted = _is_whitelisted_node(node.decorator_list)
			deprecated, dep_msg = _extract_deprecation_info(node.decorator_list, node.body)
			full_name = f"{module_path}.{node.name}" if module_path else node.name
			symbols.append(
				SymbolRecord(
					name=full_name,
					kind="function",
					file=rel_path,
					line=node.lineno,
					whitelisted=whitelisted,
					deprecated=deprecated,
					deprecation_msg=dep_msg,
				)
			)

		# Module-level classes
		elif isinstance(node, ast.ClassDef):
			if node.name.startswith("_"):
				continue
			cls_full_name = f"{module_path}.{node.name}" if module_path else node.name
			deprecated, dep_msg = _extract_deprecation_info(node.decorator_list, node.body)
			symbols.append(
				SymbolRecord(
					name=cls_full_name,
					kind="class",
					file=rel_path,
					line=node.lineno,
					whitelisted=False,
					deprecated=deprecated,
					deprecation_msg=dep_msg,
				)
			)
			# Class methods
			for item in node.body:
				if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
					if item.name.startswith("_"):
						continue
					m_whitelisted = _is_whitelisted_node(item.decorator_list)
					m_deprecated, m_dep_msg = _extract_deprecation_info(item.decorator_list, item.body)
					method_full_name = f"{cls_full_name}.{item.name}"
					symbols.append(
						SymbolRecord(
							name=method_full_name,
							kind="method",
							file=rel_path,
							line=item.lineno,
							whitelisted=m_whitelisted,
							deprecated=m_deprecated,
							deprecation_msg=m_dep_msg,
						)
					)

		# Module re-exports in __init__.py
		elif isinstance(node, ast.ImportFrom) and file_path.name == "__init__.py":
			for alias in node.names:
				export_name = alias.asname or alias.name
				if export_name.startswith("_"):
					continue
				full_name = f"{module_path}.{export_name}" if module_path else export_name
				symbols.append(
					SymbolRecord(
						name=full_name,
						kind="function",
						file=rel_path,
						line=node.lineno,
						whitelisted=False,
						deprecated=False,
						deprecation_msg=None,
					)
				)

	return symbols


def extract_branch_symbols(root_dir: Path) -> dict[str, SymbolRecord]:
	"""Extract all public API symbols from extracted source tree."""
	frappe_dir = root_dir / "frappe"
	if not frappe_dir.is_dir():
		frappe_dir = root_dir

	symbols_by_name: dict[str, SymbolRecord] = {}

	for py_file in frappe_dir.rglob("*.py"):
		rel = py_file.relative_to(root_dir).as_posix()
		parts = py_file.relative_to(root_dir).parts
		# Skip tests, patches, and non-runtime files
		if any(part in ("tests", "test", "patches", "node_modules", "docs") for part in parts):
			continue
		if py_file.name.startswith("test_") or py_file.name == "setup.py":
			continue

		# Derive dotted module name
		module_parts = list(parts[:-1])
		if py_file.stem != "__init__":
			module_parts.append(py_file.stem)
		module_path = ".".join(module_parts)

		for sym in _parse_module_symbols(py_file, rel, module_path):
			symbols_by_name[sym.name] = sym

	# Apply alias expansions (e.g. frappe.database.database.Database.<m> -> frappe.db.<m>)
	aliases: dict[str, SymbolRecord] = {}
	for alias_prefix, canonical_prefix in ALIAS_PREFIXES.items():
		canon_len = len(canonical_prefix)
		for name, sym in symbols_by_name.items():
			if name.startswith(canonical_prefix + "."):
				suffix = name[canon_len:]
				alias_name = f"{alias_prefix}{suffix}"
				aliases[alias_name] = SymbolRecord(
					name=alias_name,
					kind=sym.kind,
					file=sym.file,
					line=sym.line,
					whitelisted=sym.whitelisted,
					deprecated=sym.deprecated,
					deprecation_msg=sym.deprecation_msg,
				)

	symbols_by_name.update(aliases)
	return symbols_by_name


def generate_api_changes(
	repo_path: Path,
	branches: list[str],
	out_path: Path,
	timestamp: str | None = None,
) -> dict:
	"""Generate API change dataset across given ordered branches."""
	branch_shas: dict[str, str] = {}
	branch_symbols: dict[str, dict[str, SymbolRecord]] = {}
	short_indices: dict[str, dict[str, list[str]]] = {}

	with tempfile.TemporaryDirectory() as td:
		temp_root = Path(td)
		for branch in branches:
			sha = _get_branch_sha(repo_path, branch)
			branch_shas[branch] = sha
			b_dir = temp_root / branch
			b_dir.mkdir(parents=True, exist_ok=True)
			_export_branch_to_temp(repo_path, branch, b_dir)
			syms = extract_branch_symbols(b_dir)
			branch_symbols[branch] = syms

			# Build short-name index
			short_idx: dict[str, list[str]] = {}
			for name in syms:
				short = name.split(".")[-1]
				short_idx.setdefault(short, []).append(name)
			short_indices[branch] = short_idx

	changes_dict: dict[str, dict] = {}
	branch_pair_counts: dict[str, dict[str, int]] = {}
	module_removal_counts: dict[str, int] = {}
	newest_branch = branches[-1]
	newest_symbols = set(branch_symbols[newest_branch].keys())

	# Compute transitions across consecutive branch pairs
	for i in range(len(branches) - 1):
		b_old = branches[i]
		b_new = branches[i + 1]
		pair_key = f"{b_old}->{b_new}"
		branch_pair_counts[pair_key] = {"removed": 0, "moved": 0, "deprecated": 0}

		old_syms = branch_symbols[b_old]
		new_syms = branch_symbols[b_new]
		new_short = short_indices[b_new]

		for name, sym in old_syms.items():
			if name not in new_syms:
				if name in changes_dict:
					continue  # Already recorded in an earlier removal/move
				if name in newest_symbols:
					continue  # Exists in newest branch (e.g. re-exported)

				short_name = name.split(".")[-1]
				candidates = [c for c in new_short.get(short_name, []) if c != name]
				if candidates:
					status = "moved"
					confidence = "medium"
					moved_to = sorted(candidates)
					branch_pair_counts[pair_key]["moved"] += 1
				else:
					status = "removed"
					confidence = "high"
					moved_to = None
					branch_pair_counts[pair_key]["removed"] += 1
					mod = ".".join(name.split(".")[:-1]) or "root"
					module_removal_counts[mod] = module_removal_counts.get(mod, 0) + 1

				changes_dict[name] = {
					"name": name,
					"kind": sym.kind,
					"status": status,
					"last_present_in": b_old,
					"missing_in": b_new,
					"moved_to": moved_to,
					"confidence": confidence,
					"evidence": f"{sym.file}:{sym.line}",
					"deprecation_message": sym.deprecation_msg,
				}

		# Check deprecations present in b_new
		for name, sym in new_syms.items():
			if sym.deprecated and name not in changes_dict:
				changes_dict[name] = {
					"name": name,
					"kind": sym.kind,
					"status": "deprecated",
					"last_present_in": b_new,
					"missing_in": None,
					"moved_to": None,
					"confidence": "high",
					"evidence": f"{sym.file}:{sym.line}",
					"deprecation_message": sym.deprecation_msg,
				}
				branch_pair_counts[pair_key]["deprecated"] += 1

	sorted_changes = sorted(changes_dict.values(), key=lambda c: c["name"])

	status_counts: dict[str, int] = {}
	for c in sorted_changes:
		st = c["status"]
		status_counts[st] = status_counts.get(st, 0) + 1

	ts = timestamp or datetime.now(timezone.utc).isoformat()
	output_data = {
		"schema_version": "1.0.0",
		"generated_at": ts,
		"branches": branch_shas,
		"newest_symbols": sorted(newest_symbols),
		"summary": {
			"total_changes": len(sorted_changes),
			"by_status": status_counts,
			"by_branch_pair": branch_pair_counts,
		},
		"changes": sorted_changes,
	}

	out_path.parent.mkdir(parents=True, exist_ok=True)
	out_path.write_text(json.dumps(output_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

	# Print Summary Report
	top_modules = sorted(module_removal_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
	print(f"API Change Extraction Complete: {len(sorted_changes)} change records exported to {out_path}")
	print(f"Summary by Status: {status_counts}")
	print(f"Summary by Branch Pair: {branch_pair_counts}")
	print("Top 10 Modules by Removed Names:")
	for mod, count in top_modules:
		print(f"  {mod}: {count} removed")

	return output_data


def main() -> int:
	parser = argparse.ArgumentParser(description="Build Frappe API change database across git branches.")
	parser.add_argument("--repo", required=True, help="Path to Frappe git checkout")
	parser.add_argument("--branches", nargs="+", default=["version-14", "version-15", "version-16"], help="Ordered branches from oldest to newest")
	parser.add_argument("--out", default="scanner/data/frappe_api_changes.json", help="Path to output JSON file")
	parser.add_argument("--timestamp", default=None, help="Fixed timestamp for deterministic runs")

	args = parser.parse_args()
	repo_path = Path(args.repo)
	out_path = Path(args.out)

	if not repo_path.is_dir():
		sys.stderr.write(f"Error: repo path '{args.repo}' does not exist\n")
		return 1

	generate_api_changes(repo_path, args.branches, out_path, timestamp=args.timestamp)
	return 0


if __name__ == "__main__":
	sys.exit(main())
