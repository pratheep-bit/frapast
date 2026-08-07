"""Arrow-key interactive menus used during scan/prove flows.

Falls back to plain numbered `input()` prompts when `questionary` isn't
installed, mirroring the optional-dependency pattern already used for
`rich` elsewhere in this codebase — the CLI must never hard-require a
terminal UI library to function.
"""

from __future__ import annotations

from scanner.ui.theme import ACCENT, console

try:
	import questionary
	from questionary import Style as _QStyle

	_HAS_QUESTIONARY = True
	_QSTYLE = _QStyle(
		[
			("qmark", f"fg:{ACCENT} bold"),
			("question", "bold"),
			("pointer", f"fg:{ACCENT} bold"),
			("highlighted", f"fg:{ACCENT} bold"),
			("selected", f"fg:{ACCENT}"),
			("answer", f"fg:{ACCENT} bold"),
		]
	)
except ImportError:
	_HAS_QUESTIONARY = False


def select_proof_scope(candidates: list[dict]) -> list[dict]:
	"""Ask the user which candidates to run runtime proof verification
	against. Returns the chosen subset (possibly empty to skip)."""

	def _score(c: dict) -> float:
		sev = c.get("severity")
		return float(sev.get("score", 0.0)) if isinstance(sev, dict) else 0.0

	sorted_candidates = sorted(candidates, key=_score, reverse=True)

	choices = [
		f"Top 10 high-severity candidates  (recommended for large repos)",
		f"Top 20 candidates",
		f"All {len(candidates)} candidates",
		"Filter by rule ID (e.g. FR-SQLI-001)",
		"Skip proof verification",
	]

	if not _HAS_QUESTIONARY:
		console.print("\n[bold]Select proof verification mode:[/bold]")
		console.print("  [1] Top 10 high-severity candidates (recommended for large repos)")
		console.print("  [2] Top 20 candidates")
		console.print(f"  [3] All {len(candidates)} candidates")
		console.print("  [4] Filter by rule ID")
		console.print("  [N] Skip proof (exit)")
		try:
			choice = input("\nEnter choice [1/2/3/4/N]: ").strip().lower()
		except (KeyboardInterrupt, EOFError):
			console.print()
			return []
		if choice == "1":
			return sorted_candidates[:10]
		if choice == "2":
			return sorted_candidates[:20]
		if choice == "3":
			return candidates
		if choice == "4":
			rule_filter = input("Enter Rule ID to prove (e.g. FR-SQLI-001): ").strip().upper()
			matched = [c for c in candidates if str(c.get("rule_id", "")).upper() == rule_filter]
			if not matched:
				console.print(f"[muted]No candidates found matching rule '{rule_filter}'.[/muted]")
			return matched
		return []

	answer = questionary.select(
		"Select proof verification scope:",
		choices=choices,
		style=_QSTYLE,
		qmark="?",
	).ask()

	if answer is None or answer == choices[4]:
		return []
	if answer == choices[0]:
		return sorted_candidates[:10]
	if answer == choices[1]:
		return sorted_candidates[:20]
	if answer == choices[2]:
		return candidates
	if answer == choices[3]:
		rule_filter = questionary.text("Rule ID:", style=_QSTYLE).ask()
		rule_filter = (rule_filter or "").strip().upper()
		matched = [c for c in candidates if str(c.get("rule_id", "")).upper() == rule_filter]
		if not matched:
			console.print(f"[muted]No candidates found matching rule '{rule_filter}'.[/muted]")
		return matched
	return []


def confirm(message: str, default: bool = True) -> bool:
	if not _HAS_QUESTIONARY:
		suffix = "[Y/n]" if default else "[y/N]"
		try:
			raw = input(f"{message} {suffix} ").strip().lower()
		except (KeyboardInterrupt, EOFError):
			return default
		if not raw:
			return default
		return raw.startswith("y")
	result = questionary.confirm(message, default=default, style=_QSTYLE).ask()
	return default if result is None else result


def select_repo(repo_ids: list[str]) -> str | None:
	"""Used by the interactive shell to pick a repo from a multi-repo config."""
	if not repo_ids:
		return None
	if len(repo_ids) == 1:
		return repo_ids[0]
	if not _HAS_QUESTIONARY:
		console.print("\n[bold]Select a repository:[/bold]")
		for i, rid in enumerate(repo_ids, 1):
			console.print(f"  [{i}] {rid}")
		try:
			raw = input("Enter number: ").strip()
			idx = int(raw) - 1
			return repo_ids[idx] if 0 <= idx < len(repo_ids) else None
		except (KeyboardInterrupt, EOFError, ValueError):
			return None
	return questionary.select("Select a repository:", choices=repo_ids, style=_QSTYLE).ask()
