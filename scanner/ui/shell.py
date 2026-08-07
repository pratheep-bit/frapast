"""The frapast interactive shell.

Launched whenever `frapast` is run with no subcommand in a real terminal.
Gives a persistent `frapast ›` prompt with slash-commands, command
history, and tab-completion — the same shape as Claude Code's own REPL —
while staying a thin dispatcher over the existing scan/prove/report
functions so none of the underlying scan logic changes.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable
from pathlib import Path

from scanner.ui.banner import print_banner, print_orientation
from scanner.ui.theme import SYMBOL_ARROW, SYMBOL_BULLET, console

try:
	from prompt_toolkit import PromptSession
	from prompt_toolkit.completion import WordCompleter
	from prompt_toolkit.history import FileHistory
	from prompt_toolkit.styles import Style as PTStyle

	_HAS_PROMPT_TOOLKIT = True
except ImportError:
	_HAS_PROMPT_TOOLKIT = False

COMMANDS = [
	"/scan", "/prove", "/report", "/fp-report", "/view", "/fix", "/pr", "/help", "/clear", "/exit", "/quit",
	"scan", "prove", "report", "fp-report", "view", "fix", "pr", "help", "clear", "exit", "quit",
	"s", "p", "r", "f", "v", "h", "q", "?"
]

SHORTCUT_MAP = {
	"s": "/scan",
	"sc": "/scan",
	"/s": "/scan",
	"/sc": "/scan",
	"p": "/prove",
	"/p": "/prove",
	"pr": "/pr",
	"/pr": "/pr",
	"r": "/report",
	"rep": "/report",
	"/r": "/report",
	"/rep": "/report",
	"f": "/fp-report",
	"fp": "/fp-report",
	"/f": "/fp-report",
	"/fp": "/fp-report",
	"v": "/view",
	"view": "/view",
	"/v": "/view",
	"h": "/help",
	"?": "/help",
	"q": "/exit",
	"e": "/exit",
}

HELP_TEXT = """\
[heading]Commands & Shortcuts[/heading]
  [bold]s[/bold] or [bold]/scan[/bold] [muted]<path>[/muted]     run a static security scan (e.g. 's' or 's .')
  [bold]p[/bold] or [bold]/prove[/bold]            run runtime proof verification on findings (e.g. 'p')
  [bold]v[/bold] or [bold]/view[/bold] [muted]<N>[/muted]        inspect source code context snippet for bug #N (e.g. 'v 1' or 'b1')
  [bold]r[/bold] or [bold]/report[/bold]           show track-record report (e.g. 'r')
  [bold]f[/bold] or [bold]/fp-report[/bold]        show false-positive rates (e.g. 'f')
  [bold]fix[/bold] or [bold]/fix[/bold]          show Tier 2+ proven findings eligible for fixes
  [bold]pr[/bold] or [bold]/pr[/bold]            show Tier 2+ proven findings eligible for PRs
  [bold]h[/bold] or [bold]?[/bold] or [bold]/help[/bold]          show this help message
  [bold]q[/bold] or [bold]/exit[/bold]          quit frapast shell

[muted]Tip: Type 's' to scan, 'v 1' to view code snippet around bug #1, or 'p' to prove.[/muted]
"""


class InteractiveShell:
	def __init__(
		self,
		*,
		version: str,
		run_scan: Callable[..., None],
		run_prove: Callable[..., None],
		run_report: Callable[..., None],
		run_fp_report: Callable[..., None],
		run_view: Callable[..., None] | None = None,
		run_fix: Callable[..., None] | None = None,
		run_pr: Callable[..., None] | None = None,
	) -> None:
		self.version = version
		self._run_scan = run_scan
		self._run_prove = run_prove
		self._run_report = run_report
		self._run_fp_report = run_fp_report
		self._run_view = run_view
		self._run_fix = run_fix
		self._run_pr = run_pr
		self._session = self._build_session()

	def _build_session(self):
		if not _HAS_PROMPT_TOOLKIT:
			return None
		history_path = Path.home() / ".frapast_history"
		try:
			history = FileHistory(str(history_path))
		except OSError:
			history = None
		style = PTStyle.from_dict({"prompt": "bold #DA7756"})
		return PromptSession(
			history=history,
			completer=WordCompleter(COMMANDS, sentence=True, ignore_case=True),
			style=style,
		)

	def _read_line(self) -> str | None:
		try:
			if self._session is not None:
				return self._session.prompt([("class:prompt", "frapast › ")])
			return input("frapast \u203a ")
		except (KeyboardInterrupt, EOFError):
			return None

	def run(self, initial_repo: str | None = None) -> int:
		print_banner(self.version)
		print_orientation(initial_repo)

		if initial_repo and Path(initial_repo).exists():
			console.print(f"[muted]Scanning initial repository '{initial_repo}'...[/muted]")
			self._run_scan(path=initial_repo, limit=20)

		while True:
			line = self._read_line()
			if line is None:
				console.print("\n[muted]goodbye.[/muted]")
				return 0

			line = line.strip()
			if not line:
				continue

			try:
				if not self._dispatch(line):
					return 0
			except SystemExit:
				continue
			except Exception as exc:
				console.print(f"[severity.critical]{SYMBOL_BULLET} error:[/severity.critical] {exc}")

	def _dispatch(self, line: str) -> bool:
		"""Returns False to exit the shell."""
		parts = line.split(maxsplit=1)
		first_word = parts[0].lower()
		rest = parts[1] if len(parts) > 1 else ""

		# Support shortcuts like 'b1', 'b2', 'v1', 'v2', '1', '2'
		if first_word.startswith("b") and first_word[1:].isdigit():
			first_word = "v"
			rest = line[1:].strip()
		elif first_word.startswith("v") and len(first_word) > 1 and first_word[1:].isdigit():
			rest = first_word[1:]
			first_word = "v"
		elif first_word.isdigit():
			rest = first_word
			first_word = "v"

		# Expand 1-2 letter shortcuts (e.g. 's .' -> '/scan .', 'p' -> '/prove', 'v 1' -> '/view 1')
		if first_word in SHORTCUT_MAP:
			expanded = SHORTCUT_MAP[first_word]
			if expanded == "/scan" and not rest:
				line = "/scan ."
			elif rest:
				line = f"{expanded} {rest}"
			else:
				line = expanded

		if line in ("/exit", "/quit", "exit", "quit", "q"):
			console.print("[muted]goodbye.[/muted]")
			return False

		if line in ("/help", "help", "h", "?"):
			console.print(HELP_TEXT)
			return True

		if line == "/clear":
			console.clear()
			return True

		if line.startswith("/view"):
			self._handle_view(line)
			return True

		if line.startswith("/scan"):
			self._handle_scan(line)
			return True

		if line.startswith("/prove"):
			self._handle_prove(line)
			return True

		if line.startswith("/report"):
			self._handle_report(line)
			return True

		if line.startswith("/fp-report"):
			self._handle_fp_report(line)
			return True

		if line.startswith("/fix"):
			self._handle_fix(line)
			return True

		if line.startswith("/pr"):
			self._handle_pr(line)
			return True

		if line.startswith("/"):
			console.print(f"[muted]unknown command '{line.split()[0]}' — try /help[/muted]")
			return True

		# Bare input: treat as a scan target, Claude-Code-style shorthand.
		self._handle_scan("/scan " + line)
		return True

	@staticmethod
	def _tokens(line: str, drop: str) -> list[str]:
		try:
			parts = shlex.split(line)
		except ValueError as exc:
			console.print(f"[muted]couldn't parse command: {exc}[/muted]")
			return []
		return parts[1:] if parts and parts[0] == drop else parts

	def _handle_scan(self, line: str) -> None:
		import argparse

		parser = argparse.ArgumentParser(prog="/scan", add_help=False, exit_on_error=False)
		parser.add_argument("path", nargs="?")
		parser.add_argument("--severity", action="store_true")
		parser.add_argument("--limit", type=int, default=20)
		parser.add_argument("--config")
		try:
			args = parser.parse_args(self._tokens(line, "/scan"))
		except (argparse.ArgumentError, ValueError) as exc:
			console.print(f"[muted]usage: /scan <path> [--severity] [--limit N] [--config file] — {exc}[/muted]")
			return
		if not args.path and not args.config:
			console.print("[muted]usage: /scan <path> [--severity] [--limit N] [--config file][/muted]")
			return
		self._run_scan(path=args.path, config=args.config, severity=args.severity, limit=args.limit)

	def _handle_prove(self, line: str) -> None:
		import argparse

		parser = argparse.ArgumentParser(prog="/prove", add_help=False, exit_on_error=False)
		parser.add_argument("--finding-id")
		parser.add_argument("--dry-run", action="store_true")
		try:
			args = parser.parse_args(self._tokens(line, "/prove"))
		except (argparse.ArgumentError, ValueError) as exc:
			console.print(f"[muted]usage: /prove [--finding-id ID] [--dry-run] — {exc}[/muted]")
			return
		self._run_prove(finding_id=args.finding_id, dry_run=args.dry_run)

	def _handle_report(self, line: str) -> None:
		import argparse

		parser = argparse.ArgumentParser(prog="/report", add_help=False, exit_on_error=False)
		parser.add_argument("--findings-dir", default="findings")
		try:
			args = parser.parse_args(self._tokens(line, "/report"))
		except (argparse.ArgumentError, ValueError) as exc:
			console.print(f"[muted]usage: /report [--findings-dir dir] — {exc}[/muted]")
			return
		self._run_report(findings_dir=args.findings_dir)

	def _handle_fp_report(self, line: str) -> None:
		import argparse

		parser = argparse.ArgumentParser(prog="/fp-report", add_help=False, exit_on_error=False)
		parser.add_argument("--findings-dir", default="findings")
		try:
			args = parser.parse_args(self._tokens(line, "/fp-report"))
		except (argparse.ArgumentError, ValueError) as exc:
			console.print(f"[muted]usage: /fp-report [--findings-dir dir] — {exc}[/muted]")
			return
		self._run_fp_report(findings_dir=args.findings_dir)

	def _handle_fix(self, line: str) -> None:
		import argparse

		parser = argparse.ArgumentParser(prog="/fix", add_help=False, exit_on_error=False)
		parser.add_argument("--findings-dir", default="findings")
		parser.add_argument("--min-tier", type=int, default=2)
		parser.add_argument("--finding-id")
		try:
			args = parser.parse_args(self._tokens(line, "/fix"))
		except (argparse.ArgumentError, ValueError) as exc:
			console.print(f"[muted]usage: /fix [--findings-dir dir] [--min-tier N] [--finding-id ID] — {exc}[/muted]")
			return
		if self._run_fix is not None:
			self._run_fix(findings_dir=args.findings_dir, min_tier=args.min_tier, finding_id=args.finding_id)
		else:
			console.print("[muted]fix command unavailable.[/muted]")

	def _handle_pr(self, line: str) -> None:
		import argparse

		parser = argparse.ArgumentParser(prog="/pr", add_help=False, exit_on_error=False)
		parser.add_argument("--findings-dir", default="findings")
		parser.add_argument("--min-tier", type=int, default=2)
		parser.add_argument("--finding-id")
		try:
			args = parser.parse_args(self._tokens(line, "/pr"))
		except (argparse.ArgumentError, ValueError) as exc:
			console.print(f"[muted]usage: /pr [--findings-dir dir] [--min-tier N] [--finding-id ID] — {exc}[/muted]")
			return
		if self._run_pr is not None:
			self._run_pr(findings_dir=args.findings_dir, min_tier=args.min_tier, finding_id=args.finding_id)
		else:
			console.print("[muted]pr command unavailable.[/muted]")

	def _handle_view(self, line: str) -> None:
		parts = self._tokens(line, "/view")
		if not parts:
			console.print("[muted]usage: /view <N> (or 'v 1', 'b1', '1')[/muted]")
			return
		raw_id = parts[0].lstrip("bBvV")
		if not raw_id.isdigit():
			console.print(f"[muted]invalid bug ID '{parts[0]}' — use a number like 'v 1' or 'b1'[/muted]")
			return
		bug_id = int(raw_id)
		if self._run_view is not None:
			self._run_view(bug_id=bug_id)
		else:
			console.print("[muted]code inspector unavailable.[/muted]")
