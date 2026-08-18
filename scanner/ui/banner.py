"""Startup splash screen for frapast, in the spirit of modern CLI tools
(Claude Code, Vercel, Docker) — a bold logo panel followed by a compact
orientation block (cwd, repo status, quick tips)."""

from __future__ import annotations

import os
from pathlib import Path

from rich.align import Align
from rich.panel import Panel
from rich.text import Text

from scanner.ui.theme import BANNER_GRADIENT, SYMBOL_ARROW, SYMBOL_BULLET, console

try:
	import pyfiglet

	_HAS_PYFIGLET = True
except ImportError:
	_HAS_PYFIGLET = False

_LOGO_FALLBACK = r"""
 _____ ____      _    ____   _    ____ _____
|  ___|  _ \    / \  |  _ \ / \  / ___|_   _|
| |_  | |_) |  / _ \ | |_) / _ \ \___ \ | |
|  _| |  _ <  / ___ \|  __/ ___ \ ___) || |
|_|   |_| \_\/_/   \_\_| /_/   \_\____/ |_|
""".strip("\n")


def _logo_lines() -> list[str]:
	if _HAS_PYFIGLET:
		try:
			art = pyfiglet.figlet_format("frapast", font="ansi_shadow")
			lines = [line for line in art.split("\n") if line.strip()]
			if lines:
				return lines
		except Exception:
			pass
	return _LOGO_FALLBACK.split("\n")


def _gradient_logo() -> Text:
	text = Text()
	lines = _logo_lines()
	for i, line in enumerate(lines):
		color = BANNER_GRADIENT[i % len(BANNER_GRADIENT)]
		text.append(line + "\n", style=f"bold {color}")
	return text


def render_banner(version: str, tagline: str = "Framework-aware security scanner for Frappe & ERPNext") -> Panel:
	body = Text()
	body.append_text(_gradient_logo())
	body.append("\n")
	body.append(tagline + "\n", style="tagline")
	body.append(f"v{version}", style="muted")
	return Panel(Align.center(body), border_style="accent", padding=(1, 4))


def print_banner(version: str) -> None:
	console.print(render_banner(version))


def print_orientation(repo_path: Path | str | None = None, tips: list[str] | None = None) -> None:
	"""Print the compact 'you are here' block shown right under the banner."""
	cwd = Path(repo_path) if repo_path else Path(os.getcwd())
	info = Text()
	info.append(f"  {SYMBOL_BULLET} ", style="accent")
	info.append("workspace  ", style="muted")
	info.append(str(cwd), style="bold")
	info.append("\n")

	default_tips = [
		"[bold]/scan[/bold] [muted]<path>[/muted]   run a full static security scan",
		"[bold]/prove[/bold]              verify candidates with runtime proof",
		"[bold]/report[/bold]             show the track-record report",
		"[bold]/help[/bold]               list every command",
		"[bold]/exit[/bold]               quit frapast",
	]
	for tip in tips or default_tips:
		info.append(f"  {SYMBOL_ARROW} ", style="accent.dim")
		info.append(Text.from_markup(tip))
		info.append("\n")

	console.print(info)
	console.print()
