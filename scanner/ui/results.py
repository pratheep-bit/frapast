"""Rendering for scan results: the candidates table and the closing
summary panel. Having a single `candidate_score` here removes the
duplicate `_get_score` helper that used to live in both `main()` and
`_render_human_summary()` in cli.py."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner.ui.theme import console, severity_style


def candidate_score(candidate: dict) -> float:
	sev = candidate.get("severity")
	if isinstance(sev, dict):
		return float(sev.get("score", 0.0))
	return 0.0


def render_results(
	repo_path: Path,
	candidates: list[dict],
	num_files: int,
	elapsed: float,
	limit: int = 20,
) -> None:
	if not candidates:
		console.print(
			Panel(
				f"[success]✓ 0 candidates found[/success]  ·  "
				f"scanned [bold]{num_files}[/bold] files in [bold]{elapsed:.2f}s[/bold]",
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
	table.add_column("Severity", width=12)
	table.add_column("Rule", style="bold")
	table.add_column("Location", style="info")
	table.add_column("Function")
	table.add_column("Evidence", style="muted", ratio=2)

	for idx, c in enumerate(display, 1):
		c["_display_id"] = idx
		score = candidate_score(c)
		label, style = severity_style(score)
		badge = Text(f"{label}", style=style)
		if score > 0:
			badge.append(f" {score:.0f}", style="muted")
		table.add_row(
			f"b{idx}",
			badge,
			str(c.get("rule_id", "")),
			f"{c.get('file', '')}:{c.get('line', '')}",
			str(c.get("function", "")),
			str(c.get("evidence", "")),
		)

	console.print(table)

	counts = Counter(severity_style(candidate_score(c))[0] for c in candidates)
	stat_bits = []
	for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
		if counts.get(label):
			_, style = severity_style({"CRITICAL": 60, "HIGH": 40, "MEDIUM": 20, "LOW": 1}[label])
			stat_bits.append(f"[{style}]{counts[label]} {label.lower()}[/{style}]")
	stats = "  ·  ".join(stat_bits) if stat_bits else "no severity data"

	footer = Text.from_markup(
		f"[bold]{len(candidates)}[/bold] candidates across [bold]{num_files}[/bold] files "
		f"in [bold]{elapsed:.2f}s[/bold]  —  {stats}"
	)
	footer.append("\n[muted]Tip: Type 'v 1' or 'view 1' to view the code context snippet for bug b1[/muted]")
	if limit > 0 and len(candidates) > limit:
		footer.append(f"\n[muted]showing top {limit} by severity · pass --limit 0 for full list[/muted]")

	console.print(footer)
	console.print()


def render_code_snippet(repo_path: Path, candidate: dict, bug_id: int = 1, before: int = 2, after: int = 3) -> None:
	"""Render a highlighted source code snippet context around a candidate finding."""
	file_str = str(candidate.get("file", ""))
	line_num = int(candidate.get("line", 1) or 1)
	rule_id = str(candidate.get("rule_id", ""))
	evidence = str(candidate.get("evidence", ""))
	func = str(candidate.get("function", ""))

	p = Path(file_str)
	if not p.is_file():
		p = repo_path / file_str

	if not p.is_file():
		console.print(f"[severity.critical]File '{file_str}' could not be opened.[/severity.critical]")
		return

	try:
		lines = p.read_text(encoding="utf-8").splitlines()
	except Exception as exc:
		console.print(f"[severity.critical]Error reading '{file_str}': {exc}[/severity.critical]")
		return

	start_line = max(1, line_num - before)
	end_line = min(len(lines), line_num + after)

	snippet_lines = []
	for idx in range(start_line, end_line + 1):
		code = lines[idx - 1]
		if idx == line_num:
			snippet_lines.append(f"[bold red]▶ {idx:4d} | {code}[/bold red]  [bold red]← BUG {rule_id}[/bold red]")
		else:
			snippet_lines.append(f"[dim white]  {idx:4d} | {code}[/dim white]")

	code_block = "\n".join(snippet_lines)
	score = candidate_score(candidate)
	label, style = severity_style(score)

	panel_content = (
		f"[bold cyan]{file_str}:{line_num}[/bold cyan] in [bold white]{func}()[/bold white]\n"
		f"[{style}]Severity: {label} ({score:.0f})[/{style}] — [bold yellow]{rule_id}[/bold yellow]\n\n"
		f"{code_block}\n\n"
		f"[muted]Evidence: {evidence}[/muted]"
	)

	console.print(
		Panel(
			panel_content,
			title=f"Bug b{bug_id} Code Inspector",
			border_style="red" if score >= 40 else "yellow",
			padding=(1, 2),
		)
	)

