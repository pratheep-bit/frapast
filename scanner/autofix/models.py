"""Data models for frapAST autofix engine."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FixPatch:
    """Represents a proposed or applied code transformation for a finding."""

    finding_id: str
    rule_id: str
    file_path: Path
    start_line: int
    end_line: int
    original_source: str
    modified_source: str
    diff: str
    description: str
    applied: bool = False
