"""Rendering for scan results: the candidates table and the closing
summary panel. Having a single `candidate_score` here removes the
duplicate `_get_score` helper that used to live in both `main()` and
`_render_human_summary()` in cli.py.

Fixes applied in this revision (see inline comments at each site):

1. Unescaped repo content in Rich markup — rule IDs, file paths,
   function names, evidence strings, and raw source lines were
   interpolated directly into Rich markup (table cells / f-strings)
   with no escaping. Rich parses `[...]` in those strings as markup
   tags, so ordinary source code containing brackets (`List[int]`,
   `data["key"]`, `[a-z]+` regexes, etc.) could throw a MarkupError
   and crash the render entirely, or silently misrender. Every piece
   of untrusted text is now either wrapped in `Text(...)` (which is
   never markup-parsed) or passed through `rich.markup.escape()`.

2. Duplicated, hand-maintained severity thresholds — the footer stats
   line reconstructed a label's color by calling `severity_style()`
   with a hardcoded guess at what score would land in that bucket
   (`{"CRITICAL": 60, ...}`). If the real thresholds in `theme.py`
   ever changed, the guessed score could land in the wrong bucket and
   the footer would show a label next to the wrong color. Fixed by
   capturing the (label, style) pair Rich actually computed for each
   candidate and reusing it, so there is exactly one source of truth
   for thresholds.

3. Score-of-zero vs. no-score-at-all — `candidate_score()` defaults to
   0.0 both when a candidate has no `severity` block at all and when
   it has one with a genuine score of 0. The numeric badge used
   `score > 0` to decide whether to show a number, which hid a real
   score of 0 exactly like "no data". Display logic now checks for
   the presence of severity data separately from the numeric value.

4. Stale `_display_id` — `_display_id` was written onto every
   candidate shown in the *current* call, but never cleared, so a
   candidate that was #1 in an earlier render (different limit/filter)
   kept that id even after it dropped out of the displayed list. A
   later "view 1" could then resolve ambiguously. IDs are now reset on
   every render before being reassigned.

5. `render_code_snippet` path handling — no validation that the
   resolved file actually lives inside the scanned repository (a
   `file` field containing `..` components could otherwise be used to
   read and print arbitrary files on disk — an awkward thing for a
   *security* tool to be vulnerable to), and a malformed or
   out-of-range `line` value could raise an uncaught exception or
   silently render an empty snippet with no explanation. Both are now
   handled with clear, contained error messages.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich.markup import escape as escape_markup
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner.ui.theme import console, severity_style


def candidate_score(candidate: dict) -> float:
	"""Return a candidate's severity score, defaulting to 0.0 when no
	severity data is present. Kept as the single shared implementation
	(see module docstring) — other modules such as cli.py depend on this
	exact `float` return contract, so it is intentionally *not* changed
	to distinguish "no data" from "scored zero"; see `_has_scored_severity`
	below for that distinction where it actually matters (display only).
	"""
	sev = candidate.get("severity")
	if isinstance(sev, dict):
		try:
			return float(sev.get("score", 0.0))
		except (TypeError, ValueError):
			return 0.0
	return 0.0


def _has_scored_severity(candidate: dict) -> bool:
	"""True only if the candidate actually carries a severity score,
	as opposed to `candidate_score` defaulting to 0.0 for a missing
	`severity` block. A real score of 0 is still "scored"; a missing
	block is not — the two used to be indistinguishable at display time.
	"""
	sev = candidate.get("severity")
	return isinstance(sev, dict) and "score" in sev and sev.get("score") is not None


def render_results(
	repo_path: Path,
	candidates: list[dict],
	num_files: int,
	elapsed: float,
	limit: int = 20,
	num_skipped: int = 0,
) -> None:
	skip_note = f" (skipped {num_skipped} in .git/node_modules/tmp/etc)" if num_skipped > 0 else ""
	if not candidates:
		console.print(
			Panel(
				f"[success]✓ 0 candidates found[/success]  ·  "
				f"scanned [bold]{num_files}[/bold] files{skip_note} in [bold]{elapsed:.2f}s[/bold]",
				border_style="success",
				padding=(0, 2),
			)
		)
		return

	sorted_candidates = sorted(candidates, key=candidate_score, reverse=True)
	display = sorted_candidates[:limit] if limit > 0 else sorted_candidates

	table = Table(
		title=f"Security Audit — {repo_path}",
		title_style="heading",
		header_style="heading",
		border_style="muted",
		expand=True,
	)
	table.add_column("#", style="bold yellow", width=5)
	table.add_column("Status", width=14)
	table.add_column("Severity", width=12)
	table.add_column("Rule", style="bold", no_wrap=True, min_width=14)
	table.add_column("Location", style="info")
	table.add_column("Function", no_wrap=True)
	table.add_column("Evidence", style="muted", ratio=2)

	# Reset every candidate's display id before reassigning: without
	# this, a candidate that scrolled out of range on a later render
	# (different limit, different filter, updated scores) kept its old
	# id from a previous call, so "view N" could resolve to the wrong
	# — or an unintended — candidate. See fix #4 in the module docstring.
	for c in candidates:
		c.pop("_display_id", None)

	for idx, c in enumerate(display, 1):
		c["_display_id"] = idx
		score = candidate_score(c)
		label, style = severity_style(score)
		badge = Text(f"{label}", style=style)
		if _has_scored_severity(c):
			badge.append(f" {score:.0f}", style="muted")

		status_raw = str(c.get("status", "candidate")).lower()
		tier = c.get("proof_tier", 0)
		if status_raw == "proven":
			tier_str = f" (T{tier})" if tier else ""
			status_badge = Text(f"✓ PROVEN{tier_str}", style="bold green")
		elif status_raw in ("unproven", "failed"):
			status_badge = Text("UNPROVEN", style="bold red")
		else:
			status_badge = Text("CANDIDATE", style="dim yellow")

		# rule_id / location / function / evidence all originate from the
		# scanned repository, not from this program, and must never be
		# treated as trusted markup. Wrapping them in `Text(...)` (rather
		# than passing plain strings to `add_row`) means Rich renders
		# them completely literally — a source line containing
		# `List[int]` or `data["key"]` can no longer be misparsed as a
		# markup tag and crash or corrupt the table. See fix #1.
		table.add_row(
			f"b{idx}",
			status_badge,
			badge,
			Text(str(c.get("rule_id", ""))),
			Text(f"{c.get('file', '')}:{c.get('line', '')}"),
			Text(str(c.get("function", ""))),
			Text(str(c.get("evidence", ""))),
		)

	console.print(table)

	# Compute each candidate's (label, style) exactly once, from the same
	# `severity_style()` call used to render its row, instead of guessing
	# a representative score per label after the fact. This removes the
	# duplicated/hardcoded threshold map that used to live here — see
	# fix #2 — and keeps this file's stated goal (one source of truth
	# per piece of logic) consistent with itself.
	severity_pairs = [severity_style(candidate_score(c)) for c in candidates]
	counts = Counter(label for label, _ in severity_pairs)
	style_by_label: dict[str, str] = {}
	for label, style in severity_pairs:
		style_by_label.setdefault(label, style)

	stat_bits = []
	for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
		n = counts.get(label)
		if not n:
			continue
		style = style_by_label.get(label, "muted")
		stat_bits.append(f"[{style}]{n} {label.lower()}[/{style}]")
	stats = "  ·  ".join(stat_bits) if stat_bits else "no severity data"

	footer = Text.from_markup(
		f"[bold]{len(candidates)}[/bold] candidates across [bold]{num_files}[/bold] files{skip_note} "
		f"in [bold]{elapsed:.2f}s[/bold]  —  {stats}"
	)
	footer.append(
		"\n[dim]Severity number = priority score (privilege × impact × blast radius, plus proof-tier bonus) — higher runs first.[/dim]"
	)
	footer.append("\n[muted]Tip: Type 'v 1' or 'view 1' to view the code context snippet for bug b1[/muted]")
	if limit > 0 and len(candidates) > limit:
		footer.append(f"\n[muted]showing top {limit} by severity · pass --limit 0 for full list[/muted]")

	console.print(footer)
	console.print()


def _resolve_candidate_path(repo_path: Path, file_str: str) -> Path | None:
	"""Resolve a candidate's `file` field to an actual file, without
	ever reading outside the scanned repository tree.

	Tries the path as given (it may already be absolute, or valid
	relative to the current working directory), then falls back to
	interpreting it relative to `repo_path`. Either way, the final
	resolved path is required to sit inside `repo_path` — a `file`
	value containing `..` components can no longer be used to read and
	print the contents of an arbitrary file on the machine running the
	scan. Returns None if no such (safe) file exists.
	"""
	if not file_str:
		return None

	repo_resolved = repo_path.resolve()

	for attempt in (Path(file_str), repo_path / file_str):
		if not attempt.is_file():
			continue
		resolved = attempt.resolve()
		try:
			resolved.relative_to(repo_resolved)
		except ValueError:
			continue  # exists, but escapes the repo tree — refuse it
		return resolved

	return None


def _resolve_line_number(candidate: dict) -> int | None:
	"""Parse the candidate's `line` field defensively. Returns None if
	the value can't be interpreted as a positive line number, instead
	of letting a malformed value (a non-numeric string, for instance)
	raise an uncaught exception and take down the whole snippet view.
	"""
	raw_line = candidate.get("line", 1)
	if raw_line in (None, ""):
		return 1
	try:
		line_num = int(raw_line)
	except (TypeError, ValueError):
		return None
	return line_num if line_num >= 1 else 1


def render_code_snippet(repo_path: Path, candidate: dict, bug_id: int = 1, before: int = 2, after: int = 3) -> None:
	"""Render a highlighted source code snippet context around a candidate finding."""
	file_str = str(candidate.get("file", ""))
	rule_id = str(candidate.get("rule_id", ""))
	evidence = str(candidate.get("evidence", ""))
	func = str(candidate.get("function", ""))

	if not file_str:
		console.print("[severity.critical]This finding has no file recorded — nothing to show.[/severity.critical]")
		return

	line_num = _resolve_line_number(candidate)
	if line_num is None:
		console.print(
			f"[severity.critical]Invalid line number "
			f"'{escape_markup(str(candidate.get('line')))}' for this finding.[/severity.critical]"
		)
		return

	resolved_path = _resolve_candidate_path(repo_path, file_str)
	if resolved_path is None:
		console.print(
			f"[severity.critical]File '{escape_markup(file_str)}' could not be opened, or "
			f"lies outside the scanned repository.[/severity.critical]"
		)
		return

	try:
		lines = resolved_path.read_text(encoding="utf-8").splitlines()
	except Exception as exc:
		console.print(f"[severity.critical]Error reading '{escape_markup(file_str)}': {escape_markup(str(exc))}[/severity.critical]")
		return

	total_lines = len(lines)
	if total_lines == 0:
		console.print(f"[severity.critical]'{escape_markup(file_str)}' is empty.[/severity.critical]")
		return
	if line_num > total_lines:
		# The original code clamped `end_line` to `len(lines)` but not
		# `line_num` itself, so an out-of-range line silently produced a
		# blank or truncated snippet with no explanation of why the
		# marked line never appeared. Surface it instead.
		console.print(
			f"[severity.critical]Line {line_num} is beyond the end of "
			f"'{escape_markup(file_str)}' ({total_lines} lines) — the file may have "
			f"changed since the scan.[/severity.critical]"
		)
		return

	start_line = max(1, line_num - before)
	end_line = min(total_lines, line_num + after)

	snippet_lines = []
	for idx in range(start_line, end_line + 1):
		code = escape_markup(lines[idx - 1])  # source content, not trusted markup — see fix #1
		if idx == line_num:
			snippet_lines.append(f"[bold red]▶ {idx:4d} | {code}[/bold red]  [bold red]← BUG {escape_markup(rule_id)}[/bold red]")
		else:
			snippet_lines.append(f"[dim white]  {idx:4d} | {code}[/dim white]")

	code_block = "\n".join(snippet_lines)
	score = candidate_score(candidate)
	label, style = severity_style(score)

	panel_content = (
		f"[bold cyan]{escape_markup(file_str)}:{line_num}[/bold cyan] in [bold white]{escape_markup(func)}()[/bold white]\n"
		f"[{style}]Severity: {label} ({score:.0f})[/{style}] — [bold yellow]{escape_markup(rule_id)}[/bold yellow]\n\n"
		f"{code_block}\n\n"
		f"[muted]Evidence: {escape_markup(evidence)}[/muted]"
	)

	console.print(
		Panel(
			panel_content,
			title=f"Bug b{bug_id} Code Inspector",
			border_style="red" if score >= 40 else "yellow",
			padding=(1, 2),
		)
	)
