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


def select_post_scan_action(candidates: list[dict]) -> str:
	"""Show an arrow-key selection menu listing all available post-scan actions."""
	choices = [
		f"🛡️  Run Proof Engine — Top 10 High-Severity (recommended)",
		f"🛡️  Run Proof Engine — Top 20 Candidates",
		f"🛡️  Run Proof Engine — All {len(candidates)} Candidates",
		f"👁️  Inspect Code Snippet for a Bug (e.g. b1, b2)",
		f"💾 Save Findings as JSON File",
		f"📊 View Track-Record Report",
		f"🚪 Exit",
	]

	if not _HAS_QUESTIONARY:
		console.print("\n[bold cyan]What would you like to do next?[/bold cyan]")
		console.print("  [1] Prove Top 10 High-Severity candidates")
		console.print("  [2] Prove Top 20 candidates")
		console.print(f"  [3] Prove All {len(candidates)} candidates")
		console.print("  [4] Inspect Code Snippet for a Bug")
		console.print("  [5] Save Findings as JSON File")
		console.print("  [6] View Track-Record Report")
		console.print("  [N] Exit\n")
		try:
			ans = input("Select option [1/2/3/4/5/6/N]: ").strip().lower()
			if ans == "1": return "prove_top10"
			if ans == "2": return "prove_top20"
			if ans == "3": return "prove_all"
			if ans == "4": return "inspect"
			if ans == "5": return "export_json"
			if ans == "6": return "report"
			return "exit"
		except (KeyboardInterrupt, EOFError):
			return "exit"

	answer = questionary.select(
		"What would you like to do next? (Use arrow keys ⬆/⬇):",
		choices=choices,
		style=_QSTYLE,
		qmark="❯",
	).ask()

	if answer is None or "Exit" in answer:
		return "exit"
	if "Top 10" in answer:
		return "prove_top10"
	if "Top 20" in answer:
		return "prove_top20"
	if "All" in answer:
		return "prove_all"
	if "Inspect Code" in answer:
		return "inspect"
	if "JSON" in answer:
		return "export_json"
	if "Track-Record" in answer:
		return "report"
	return "exit"


def select_bug_to_view(candidates: list[dict]) -> int | None:
	"""Arrow-key menu to select a specific bug snippet to inspect."""
	if not candidates:
		return None

	def _score(c: dict) -> float:
		sev = c.get("severity")
		return float(sev.get("score", 0.0)) if isinstance(sev, dict) else 0.0

	sorted_cands = sorted(candidates, key=_score, reverse=True)
	choices = []
	for idx, c in enumerate(sorted_cands[:30], 1):
		rule_id = c.get("rule_id", "")
		file_path = c.get("file", "")
		line = c.get("line", "")
		func = c.get("function", "")
		choices.append(f"b{idx}. [{rule_id}] {file_path}:{line} in {func}()")

	choices.append("⬅ Back to Menu")

	if not _HAS_QUESTIONARY:
		try:
			ans = input("Enter Bug # to view (e.g. 1, 2): ").strip().lstrip("bBvV")
			if ans.isdigit():
				val = int(ans)
				if 1 <= val <= len(sorted_cands):
					return val
		except (KeyboardInterrupt, EOFError):
			pass
		return None

	answer = questionary.select(
		"Select a bug to inspect source code snippet (Use arrow keys ⬆/⬇):",
		choices=choices,
		style=_QSTYLE,
		qmark="👁️",
	).ask()

	if answer is None or "Back" in answer:
		return None

	try:
		num_part = answer.split(".")[0].lstrip("bBvV")
		return int(num_part)
	except Exception:
		return None


def select_proof_scope(candidates: list[dict]) -> list[dict]:
	"""Ask the user which candidates to run runtime proof verification against."""
	def _score(c: dict) -> float:
		sev = c.get("severity")
		return float(sev.get("score", 0.0)) if isinstance(sev, dict) else 0.0

	sorted_candidates = sorted(candidates, key=_score, reverse=True)
	choices = [
		"Top 10 high-severity candidates (recommended for large repos)",
		"Top 20 candidates",
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


def select_repo_path(prompt_msg: str = "Target repository path:") -> str:
	if not _HAS_QUESTIONARY:
		return input(f"{prompt_msg} ").strip()
	ans = questionary.text(prompt_msg, default=".", style=_QSTYLE).ask()
	return (ans or ".").strip()


def confirm(message: str, default: bool = True) -> bool:
	if not _HAS_QUESTIONARY:
		prompt = "[Y/n]" if default else "[y/N]"
		try:
			ans = input(f"{message} {prompt} ").strip().lower()
		except (KeyboardInterrupt, EOFError):
			return default
		if not ans:
			return default
		return ans in ("y", "yes")
	return bool(questionary.confirm(message, default=default, style=_QSTYLE).ask())


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
