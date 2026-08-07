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

COMMANDS = ["/scan", "/prove", "/report", "/fp-report", "/help", "/clear", "/exit", "/quit"]

HELP_TEXT = """\
[heading]Commands[/heading]
  [bold]/scan[/bold] [muted]<path>[/muted] [muted][--severity] [--limit N] [--config file][/muted]
        run a static security scan against a repo (or a multi-repo --config)
  [bold]/prove[/bold] [muted][--finding-id ID] [--dry-run][/muted]
        run runtime proof verification against the last scan's candidates
  [bold]/report[/bold] [muted][--findings-dir dir][/muted]
        show the track-record report generated from proven findings
  [bold]/fp-report[/bold] [muted][--findings-dir dir][/muted]
        show false-positive rates per rule
  [bold]/clear[/bold]      clear the screen
  [bold]/help[/bold]       show this message
  [bold]/exit[/bold]       leave frapast

[muted]Tip: typing a bare path (e.g. "." or "../erpnext") is shorthand for /scan[/muted]
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
	) -> None:
		self.version = version
		self._run_scan = run_scan
		self._run_prove = run_prove
		self._run_report = run_report
		self._run_fp_report = run_fp_report
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
				# argparse-style mini-parsers raise this on bad flags; the
				# handler already printed a usage message.
				continue
			except Exception as exc:  # keep the shell alive on command errors
				console.print(f"[severity.critical]{SYMBOL_BULLET} error:[/severity.critical] {exc}")

	def _dispatch(self, line: str) -> bool:
		"""Returns False to exit the shell."""
		if line in ("/exit", "/quit", "exit", "quit"):
			console.print("[muted]goodbye.[/muted]")
			return False

		if line == "/help":
			console.print(HELP_TEXT)
			return True

		if line == "/clear":
			console.clear()
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
