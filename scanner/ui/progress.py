"""Progress surfaces for long-running frapast operations.

Both helpers are context managers so callers keep full control of the loop
body; frapast's core scanning/proof code stays UI-agnostic and only ever
talks to a plain `callback(current, total)` / `advance()` function, matching
the signatures already used by `_load_indexes` and the proof orchestrator.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from rich.progress import (
	BarColumn,
	MofNCompleteColumn,
	Progress,
	SpinnerColumn,
	TextColumn,
	TimeElapsedColumn,
)

from scanner.ui.theme import err_console as console


@contextmanager
def scan_progress(description: str = "Scanning repository") -> Iterator[callable]:
	"""Yields a `callback(current, total)` suitable for progress_callback=."""
	progress = Progress(
		SpinnerColumn(style="accent"),
		TextColumn("[accent]{task.description}"),
		BarColumn(complete_style="accent", finished_style="success"),
		MofNCompleteColumn(),
		TextColumn("[muted]files"),
		TimeElapsedColumn(),
		console=console,
		transient=True,
	)
	with progress:
		task_id = progress.add_task(description, total=None)

		def _callback(current: int, total: int) -> None:
			if progress.tasks[task_id].total != total:
				progress.update(task_id, total=total)
			progress.update(task_id, completed=current)

		yield _callback


@contextmanager
def proof_progress(total: int, description: str = "Verifying candidates") -> Iterator[callable]:
	"""Yields `advance(label)` to call once per proven/rejected candidate."""
	progress = Progress(
		SpinnerColumn(style="accent"),
		TextColumn("[accent]{task.description}"),
		BarColumn(complete_style="accent", finished_style="success"),
		MofNCompleteColumn(),
		TimeElapsedColumn(),
		console=console,
		transient=False,
	)
	with progress:
		task_id = progress.add_task(description, total=total)

		def _advance(label: str = "") -> None:
			if label:
				progress.update(task_id, description=f"{description} · {label}")
			progress.advance(task_id)

		yield _advance
