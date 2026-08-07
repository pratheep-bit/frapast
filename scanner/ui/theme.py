"""Shared visual language for the frapast interactive UI.

Centralizing colors/symbols here keeps the banner, menus, tables, and shell
prompt visually consistent instead of each module picking its own palette.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

# Brand palette — warm terracotta accent with a neutral, high-contrast body.
ACCENT = "#DA7756"
ACCENT_DIM = "#B85C3E"
ACCENT_BRIGHT = "#FF9466"

CRITICAL = "#FF5C5C"
HIGH = "#FFB454"
MEDIUM = "#F5D76E"
LOW = "#8FD19E"
NEUTRAL = "#8A8A8A"
SUCCESS = "#5FD68A"
INFO = "#6EC1FF"

BANNER_GRADIENT = ["#FF9466", "#FF8552", "#F5744A", "#EB6542", "#DA5A3A", "#C94F33"]

SYMBOL_OK = "\u2713"
SYMBOL_FAIL = "\u2717"
SYMBOL_WARN = "\u26a0"
SYMBOL_ARROW = "\u276f"
SYMBOL_BULLET = "\u2022"
SYMBOL_DOT = "\u25cf"

THEME = Theme(
	{
		"accent": ACCENT,
		"accent.dim": ACCENT_DIM,
		"accent.bright": ACCENT_BRIGHT,
		"severity.critical": f"bold {CRITICAL}",
		"severity.high": f"bold {HIGH}",
		"severity.medium": MEDIUM,
		"severity.low": LOW,
		"muted": NEUTRAL,
		"success": f"bold {SUCCESS}",
		"info": INFO,
		"prompt": f"bold {ACCENT}",
		# Compound combinations must be registered as a single theme key —
		# Rich's theme lookup matches the *whole* style string, so writing
		# "bold accent" inline (two tokens) will NOT resolve "accent" via
		# the theme and raises MissingStyle. Any bold/italic/dim pairing
		# with a semantic name below.
		"heading": f"bold {ACCENT}",
		"tagline": f"italic {NEUTRAL}",
	}
)

console = Console(theme=THEME, highlight=False)
# Progress/spinners must never land on stdout: `frapast scan . --format json`
# pipes stdout to jq/files, so ephemeral progress output goes to stderr.
err_console = Console(theme=THEME, highlight=False, stderr=True)


def severity_style(score: float) -> tuple[str, str]:
	"""Return (label, rich style) for a given numeric severity score."""
	if score >= 60:
		return "CRITICAL", "severity.critical"
	if score >= 40:
		return "HIGH", "severity.high"
	if score >= 20:
		return "MEDIUM", "severity.medium"
	if score > 0:
		return "LOW", "severity.low"
	return "—", "muted"
