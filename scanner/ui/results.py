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
	table.add_column("Severity", width=12)
	table.add_column("Rule", style="bold")
	table.add_column("Location", style="info")
	table.add_column("Function")
	table.add_column("Evidence", style="muted", ratio=2)

	for c in display:
		score = candidate_score(c)
		label, style = severity_style(score)
		badge = Text(f"{label}", style=style)
		if score > 0:
			badge.append(f" {score:.0f}", style="muted")
		table.add_row(
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
	if limit > 0 and len(candidates) > limit:
		footer.append(f"\n[muted]showing top {limit} by severity · pass --limit 0 for the full list[/muted]")

	console.print(footer)
	console.print()
