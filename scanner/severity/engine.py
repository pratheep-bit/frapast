from __future__ import annotations

from scanner.rules import Candidate
from scanner.severity.models import (
	BLAST_RADIUS_WEIGHTS,
	IMPACT_WEIGHTS,
	PRIVILEGE_WEIGHTS,
	PROOF_TIER_WEIGHTS,
	SeverityScore,
)

# Map rule taxonomy families to default impact classes
RULE_IMPACT_MAP: dict[str, str] = {
	"FR-SQLI-001": "rce",
	"FR-SQLI-002": "data_exposure",
	"FR-SQLI-003": "data_corruption",
	"FR-SQLI-004": "rce",
	"FR-PERM-001": "privilege_escalation",
	"FR-PERM-002": "privilege_escalation",
	"FR-PERM-003": "privilege_escalation",
	"FR-PERM-004": "data_exposure",
	"FR-PERM-005": "data_exposure",
	"FR-PERM-006": "data_corruption",
	"FR-HOOK-001": "data_corruption",
	"FR-HOOK-002": "data_corruption",
	"FR-HOOK-003": "data_corruption",
	"FR-HOOK-004": "data_corruption",
	"FR-HOOK-005": "data_corruption",
	"FR-WKFL-001": "data_corruption",
	"FR-WKFL-002": "privilege_escalation",
	"FR-WKFL-003": "data_corruption",
	"FR-WKFL-004": "data_corruption",
	"FR-INJ-001": "privilege_escalation",
	"FR-INJ-002": "rce",
	# Previously missing: FR-XSS-001/CSRF-001/SSRF-001 fell through to the
	# generic "data_exposure" default in score_security below, silently
	# under-scoring genuinely severe, guest-reachable issues. Values below
	# are taken directly from each rule's own severity_defaults in its YAML
	# (scanner/rules/FR-CSRF-001.yaml, FR-INJ-005.yaml, FR-SSRF-001.yaml) so
	# there is exactly one place these are declared per rule, going forward.
	"FR-INJ-005": "data_exposure",       # formerly FR-XSS-001
	"FR-CSRF-001": "privilege_escalation",
	"FR-SSRF-001": "data_exposure",
	"FR-PATH-001": "data_exposure",
}

# Map rule families to default blast radius (used when no per-rule override
# exists in RULE_BLAST_RADIUS_OVERRIDES below).
RULE_BLAST_RADIUS_MAP: dict[str, str] = {
	"FR-SQLI": "cross_doctype",
	"FR-PERM": "single_doctype",
	"FR-HOOK": "single_doctype",
	"FR-WKFL": "single_doctype",
	"FR-INJ": "framework_wide",
	"FR-PATH": "framework_wide",
}

# Per-rule blast-radius overrides, checked before the family-level map above.
# FR-INJ-005 (formerly FR-XSS-001) and FR-CSRF-001 are cross_site issues, not
# framework_wide like the rest of their nominal family — a single rule_id can
# disagree with its family's default, and family-level RULE_BLAST_RADIUS_MAP
# alone can't express that.
RULE_BLAST_RADIUS_OVERRIDES: dict[str, str] = {
	"FR-INJ-005": "cross_site",
	"FR-CSRF-001": "cross_site",
	"FR-SSRF-001": "framework_wide",
	"FR-PATH-001": "framework_wide",
}


def score_security(candidate: Candidate, allow_guest: bool, proof_tier: int) -> SeverityScore:
	privilege = "guest" if allow_guest else "authenticated"
	impact = RULE_IMPACT_MAP.get(candidate.rule_id, "data_exposure")
	# If FR-PERM-001 is a read-only endpoint (low fix_confidence), lower impact to data_exposure
	if candidate.rule_id == "FR-PERM-001" and getattr(candidate, "fix_confidence", "") == "low":
		impact = "data_exposure"
	family = candidate.rule_id.rsplit("-", 1)[0] if "-" in candidate.rule_id else candidate.rule_id
	blast_radius = RULE_BLAST_RADIUS_OVERRIDES.get(candidate.rule_id) or RULE_BLAST_RADIUS_MAP.get(family, "single_record")
	composite = _compute_composite(privilege, allow_guest, impact, blast_radius, proof_tier)
	return SeverityScore(
		score=composite,
		dimension_scores={
			"privilege_required": privilege,
			"allow_guest": allow_guest,
			"impact_class": impact,
			"blast_radius": blast_radius,
			"proof_tier": proof_tier,
		}
	)


# FR-HOOK-006 / FR-HOOK-007 (bare except / mutable default, formerly
# FR-CORR-001/002 — see taxonomy_registry.yaml `extensions`) are correctness
# bugs, not security bugs, even though the taxonomy rename moved their
# rule_id prefix into the "FR-HOOK" family. score_candidate() below checks
# _SCORER_OVERRIDES for these two specific rule_ids before falling back to
# the family-level _SCORERS map, so they still get correctness scoring
# instead of being swept into score_security() by the FR-HOOK family default.
def score_correctness(candidate: Candidate, allow_guest: bool, proof_tier: int) -> SeverityScore:
	base = {"FR-HOOK-006": 7.0, "FR-HOOK-007": 5.0}.get(candidate.rule_id, 6.0)
	return SeverityScore(
		score=base + PROOF_TIER_WEIGHTS.get(proof_tier, 0),
		dimension_scores={"category": "correctness", "rule_id": candidate.rule_id, "proof_tier": proof_tier},
	)


def score_performance(candidate: Candidate, allow_guest: bool, proof_tier: int) -> SeverityScore:
	return SeverityScore(
		score=4.0 + PROOF_TIER_WEIGHTS.get(proof_tier, 0),
		dimension_scores={"category": "performance", "rule_id": candidate.rule_id, "proof_tier": proof_tier},
	)


def score_data(candidate: Candidate, allow_guest: bool, proof_tier: int) -> SeverityScore:
	return SeverityScore(
		score=7.0 + PROOF_TIER_WEIGHTS.get(proof_tier, 0),
		dimension_scores={"category": "data_integrity", "rule_id": candidate.rule_id, "proof_tier": proof_tier},
	)


def score_i18n(candidate: Candidate, allow_guest: bool, proof_tier: int) -> SeverityScore:
	return SeverityScore(
		score=2.0,
		dimension_scores={"category": "i18n", "rule_id": candidate.rule_id},
	)


_SCORER_OVERRIDES = {
	"FR-HOOK-006": score_correctness,
	"FR-HOOK-007": score_correctness,
}

_SCORERS = {
	"FR-SQLI": score_security,
	"FR-PERM": score_security,
	"FR-HOOK": score_security,  # default for the family; overridden per-rule above for -006/-007
	"FR-WKFL": score_security,
	"FR-INJ": score_security,
	"FR-CSRF": score_security,
	"FR-SSRF": score_security,
	"FR-PATH": score_security,
	"FR-PERF": score_performance,
	"FR-DATA": score_data,
	"FR-I18N": score_i18n,
}


def score_candidate(
	candidate: Candidate,
	allow_guest: bool = False,
	proof_tier: int = 0,
) -> SeverityScore:
	"""Score a candidate finding using the appropriate rubric for its taxonomy."""
	override = _SCORER_OVERRIDES.get(candidate.rule_id)
	if override is not None:
		return override(candidate, allow_guest, proof_tier)
	parts = candidate.rule_id.split("-")
	family = f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else candidate.rule_id
	scorer = _SCORERS.get(family, score_security)
	return scorer(candidate, allow_guest, proof_tier)


def score_candidates(
	candidates: list[Candidate],
	guest_endpoints: set[str] | None = None,
	proof_tiers: dict[str, int] | None = None,
) -> list[tuple[Candidate, SeverityScore]]:
	"""Score a list of candidates, returning (candidate, score) pairs sorted by severity."""
	guest_endpoints = guest_endpoints or set()
	proof_tiers = proof_tiers or {}
	scored = []
	for candidate in candidates:
		allow_guest = candidate.function in guest_endpoints
		proof_tier = proof_tiers.get(
			f"{candidate.rule_id}-{candidate.code_location_hash}", candidate.proof_tier
		)
		score = score_candidate(candidate, allow_guest=allow_guest, proof_tier=proof_tier)
		scored.append((candidate, score))
	scored.sort(key=lambda item: item[1].score, reverse=True)
	return scored


def _compute_composite(
	privilege: str,
	allow_guest: bool,
	impact: str,
	blast_radius: str,
	proof_tier: int,
) -> float:
	"""Weighted composite score for triage ordering.

	Higher score = higher priority to investigate/prove.
	"""
	priv_score = PRIVILEGE_WEIGHTS.get(privilege, 1)
	impact_score = IMPACT_WEIGHTS.get(impact, 1)
	blast_score = BLAST_RADIUS_WEIGHTS.get(blast_radius, 1)
	proof_score = PROOF_TIER_WEIGHTS.get(proof_tier, 0)
	guest_multiplier = 1.5 if allow_guest else 1.0
	return (priv_score * 3 + impact_score * 4 + blast_score * 2 + proof_score) * guest_multiplier
