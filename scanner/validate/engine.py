"""Static, sandbox-free validation gate for synthesized fixes.

IMPORTANT SCOPE NOTE: this module does NOT replace runtime proof
(scanner/proof/orchestrator.py) and does NOT spin up a bench/container. It is
a fast, dependency-free guard that catches the class of error that would turn
an auto-generated "fix" into a new outage: a syntactically broken file, an
accidentally near-empty file, or a file that fails to byte-compile. A fix
that passes this gate is *not* proven safe — it is only not obviously broken.
The mandatory Tier 2+ proof gate in cli.py (`_load_proven_findings`) is what
actually establishes the underlying finding is real; this module only
protects the mechanical edit made on top of it.
"""
from __future__ import annotations

import ast
import py_compile
import tempfile
from pathlib import Path

from scanner.rules import Candidate


def validate_and_stage(candidate: Candidate, repo_path: Path, fixed_code: str) -> bool:
	"""Return True if `fixed_code` looks safe enough to write as a preview
	file or stage into a PR branch. Never raises — a validation error is
	reported via return value, not an exception, so callers in cli.py don't
	need extra try/except handling around every fix."""

	# 1. Must parse as valid Python.
	try:
		ast.parse(fixed_code, filename=str(candidate.file))
	except SyntaxError as exc:
		print(f"Validation failed: fixed code for {candidate.file} has a syntax error: {exc}")
		return False

	# 2. Must not have collapsed to (near) nothing. LibCST fixers only ever
	# insert or wrap code in this codebase, so a large shrink means something
	# went wrong in the transform, not a legitimate simplification.
	original_path = Path(repo_path) / candidate.file
	if original_path.is_file():
		try:
			original_len = len(original_path.read_text(encoding="utf-8"))
		except (UnicodeDecodeError, OSError):
			original_len = 0
		if original_len > 0 and len(fixed_code) < original_len * 0.5:
			print(
				f"Validation failed: fixed code for {candidate.file} is more than 50% "
				f"smaller than the original ({len(fixed_code)} vs {original_len} chars)."
			)
			return False

	# 3. Byte-compile in isolation. This catches some things ast.parse alone
	# doesn't, without ever touching the real working tree.
	tmp_path: str | None = None
	try:
		with tempfile.NamedTemporaryFile(
			mode="w", suffix=".py", delete=False, encoding="utf-8"
		) as tmp_file:
			tmp_file.write(fixed_code)
			tmp_path = tmp_file.name
		py_compile.compile(tmp_path, doraise=True)
	except py_compile.PyCompileError as exc:
		print(f"Validation failed: py_compile error for {candidate.file}: {exc}")
		return False
	except OSError as exc:
		print(f"Validation failed: could not write temp file to compile {candidate.file}: {exc}")
		return False
	finally:
		if tmp_path is not None:
			Path(tmp_path).unlink(missing_ok=True)

	return True
