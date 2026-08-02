from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import yaml


def generate_regression_test(finding_path: str | Path) -> str:
	"""Generate a scanner regression test from a proven finding.

	Ensures the rule continues to fire on the original code pattern,
	catching regressions in rule logic.
	"""
	finding = yaml.safe_load(Path(finding_path).read_text(encoding="utf-8"))
	if not isinstance(finding, dict):
		raise ValueError(f"LEDGER_INVALID: {finding_path}")

	rule_id = finding["rule_id"]
	finding_id = finding["id"]
	file_path = finding["file"]
	function_name = finding["function"]
	rule_func = rule_id.lower().replace("-", "_")

	return dedent(f"""\
		\"\"\"Regression test for {finding_id}.

		Ensures {rule_id} continues to detect the pattern at:
		  {file_path}:{function_name}
		\"\"\"
		from scanner.hooks import load as load_hooks
		from scanner.python import load as load_python
		from scanner.rules import execute_rules
		from scanner.schema import load as load_schema


		def test_{rule_func}_regression_{finding_id.replace("-", "_")}():
		    schema = load_schema(".")
		    hooks = load_hooks(".")
		    python = load_python(".")
		    candidates = execute_rules(schema, hooks, python)
		    matching = [
		        c for c in candidates
		        if c.rule_id == "{rule_id}"
		        and c.file == "{file_path}"
		        and c.function == "{function_name}"
		    ]
		    assert matching, (
		        "Regression: {rule_id} no longer detects the pattern at "
		        "{file_path}:{function_name} — rule may have been weakened."
		    )
	""")


def generate_reproducer_template(finding_path: str | Path) -> str:
	"""Generate a reproducer shell script template from a finding."""
	finding = yaml.safe_load(Path(finding_path).read_text(encoding="utf-8"))
	if not isinstance(finding, dict):
		raise ValueError(f"LEDGER_INVALID: {finding_path}")

	finding_id = finding["id"]
	taxonomy_id = finding["taxonomy_id"]
	notes = finding.get("notes", "No notes available.")

	return dedent(f"""\
		#!/bin/bash
		# Reproducer for {finding_id}
		# Taxonomy: {taxonomy_id}
		# Evidence: {notes}
		#
		# This script runs inside the containerized bench environment.
		# Exit 0 = vulnerability confirmed (proof passed)
		# Exit 1 = vulnerability not present (proof failed)

		set -euo pipefail
		SITE_NAME="${{SITE_NAME:-security.localhost}}"
		BENCH_DIR="${{BENCH_DIR:-/home/frappe/bench-state/frappe-bench}}"
		cd "$BENCH_DIR"

		echo "=== Reproducer: {finding_id} ==="
		echo "Taxonomy: {taxonomy_id}"

		# Step 1: Seed test data
		echo "[1/3] Seeding test data..."
		# TODO: Add seeding commands specific to this finding

		# Step 2: Execute the vulnerable path
		echo "[2/3] Executing exploit path..."
		# TODO: Add HTTP request or bench command to trigger the vulnerability

		# Step 3: Verify the result
		echo "[3/3] Verifying result..."
		# TODO: Add verification logic
		# If vulnerability is confirmed, exit 0
		# If vulnerability is not present, exit 1

		echo "ERROR: Reproducer not yet implemented"
		exit 2
	""")


def generate_all_regression_tests(findings_dir: str | Path) -> str:
	"""Generate regression tests for all proven findings."""
	path = Path(findings_dir)
	tests: list[str] = []
	for finding_path in sorted(path.glob("FR-*.yaml")):
		finding = yaml.safe_load(finding_path.read_text(encoding="utf-8"))
		if isinstance(finding, dict) and finding.get("status") in ("proven", "merged", "patched"):
			try:
				test = generate_regression_test(finding_path)
				tests.append(test)
			except (KeyError, ValueError):
				continue
	return "\n\n".join(tests) if tests else "# No proven findings to generate regression tests from.\n"
