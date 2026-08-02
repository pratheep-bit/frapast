from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SeverityScore:
	"""Agnostic severity scoring."""
	score: float
	dimension_scores: dict[str, str | int | float | bool]


PRIVILEGE_WEIGHTS = {
	"guest": 5,
	"authenticated": 4,
	"operational_role": 3,
	"elevated_role": 2,
	"system_manager": 1,
}

IMPACT_WEIGHTS = {
	"rce": 5,
	"privilege_escalation": 4,
	"data_corruption": 3,
	"data_exposure": 2,
	"availability": 2,
}

BLAST_RADIUS_WEIGHTS = {
	"cross_site": 5,
	"framework_wide": 4,
	"cross_doctype": 3,
	"single_doctype": 2,
	"single_record": 1,
}

PROOF_TIER_WEIGHTS = {
	0: 0,
	1: 1,
	2: 3,
	3: 5,
}
