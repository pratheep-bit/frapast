from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


PROOF_MODE_MARKER = "# PROOF_MODE:"
VALID_PROOF_MODES = ("direct_call", "http_rpc")


class ProofStatus(str, Enum):
	PASSED = "passed"
	FAILED = "failed"
	ERROR = "error"
	SKIPPED = "skipped"
	DRY_RUN = "dry_run"


@dataclass(frozen=True)
class ProofResult:
	"""Result of running a reproducer against a containerized bench."""

	finding_id: str
	status: ProofStatus
	proof_tier: int
	exit_code: int | None
	stdout: str
	stderr: str
	duration_seconds: float
	reproducer_path: str
	error_message: str | None = None
	code_location_hash: str | None = None

