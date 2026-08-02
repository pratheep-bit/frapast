from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceFile:
	path: Path
	root: Path

	@property
	def relative_path(self) -> str:
		try:
			return self.path.relative_to(self.root).as_posix()
		except ValueError:
			return self.path.as_posix()


@dataclass(frozen=True)
class SourceSpan:
	file: str
	line_start: int
	line_end: int
	hash: str


def stable_hash(value: str) -> str:
	return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
