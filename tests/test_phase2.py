from pathlib import Path

import yaml

from scanner.fp import apply_fp_suppression, load_false_positives, precision_by_rule
from scanner.reporting import render_track_record
from scanner.rules import Candidate

ROOT = Path(__file__).resolve().parents[1]
FINDING_ID = "FR-PERM-002-2226459924682f8b"
WORKSPACE_FINDING_ID = "FR-PERM-002-02e6094a1bfc8138"
COMMENT_FINDING_ID = "FR-PERM-002-4ecad3b50924b7c1"
PUBLICITY_FINDING_ID = "FR-PERM-002-fa1709c6f00cf8f5"
HISTORICAL_FINDING_IDS = (
	"FR-PERM-002-merged-erpnext-56132",
	"FR-PERM-002-merged-hrms-4738",
	"FR-PERM-002-merged-hrms-4740",
	"FR-PERM-002-merged-hrms-4739",
)


def test_runtime_false_positive_has_recipe_artifact_and_fp_log_entry():
	finding = yaml.safe_load((ROOT / "findings" / f"{FINDING_ID}.yaml").read_text(encoding="utf-8"))
	recipe_path = ROOT / "runtime" / "proofs" / f"{FINDING_ID}.yaml"
	artifact_path = ROOT / "runtime" / "artifacts" / FINDING_ID / "2026-07-15-contact-form.json"
	reproducer_path = ROOT / "runtime" / "reproducers" / f"{FINDING_ID}.sh"
	recipe = yaml.safe_load(recipe_path.read_text(encoding="utf-8"))
	fp_log = yaml.safe_load((ROOT / "findings" / "fp-log.yaml").read_text(encoding="utf-8"))

	assert finding["status"] == "false_positive"
	assert finding["proof_tier"] == 2
	assert finding["allow_guest"] is True
	assert recipe["finding_id"] == FINDING_ID
	assert recipe["tiers"]["tier2"]["mode"] == "http_post"
	assert artifact_path.is_file()
	assert reproducer_path.is_file()
	assert reproducer_path.stat().st_mode & 0o111
	assert any(entry["finding_id"] == FINDING_ID for entry in fp_log["false_positives"])


def test_workspace_ownership_false_positive_has_runtime_evidence_and_cleanup_reproducer():
	finding = yaml.safe_load((ROOT / "findings" / f"{WORKSPACE_FINDING_ID}.yaml").read_text(encoding="utf-8"))
	recipe = yaml.safe_load(
		(ROOT / "runtime" / "proofs" / f"{WORKSPACE_FINDING_ID}.yaml").read_text(encoding="utf-8")
	)
	artifact_path = ROOT / "runtime" / "artifacts" / WORKSPACE_FINDING_ID / "2026-07-15-workspace-ownership.json"
	reproducer_path = ROOT / "runtime" / "reproducers" / f"{WORKSPACE_FINDING_ID}.sh"
	fp_log = yaml.safe_load((ROOT / "findings" / "fp-log.yaml").read_text(encoding="utf-8"))

	assert finding["status"] == "false_positive"
	assert finding["proof_tier"] == 2
	assert finding["privilege_required"] == "ordinary_authenticated_user"
	assert recipe["finding_id"] == WORKSPACE_FINDING_ID
	assert recipe["tiers"]["tier1"]["mode"] == "direct_call"
	assert recipe["tiers"]["tier2"]["mode"] == "http_post"
	assert artifact_path.is_file()
	assert reproducer_path.is_file()
	assert reproducer_path.stat().st_mode & 0o111
	assert any(entry["finding_id"] == WORKSPACE_FINDING_ID for entry in fp_log["false_positives"])


def test_comment_ownership_false_positive_has_runtime_evidence_and_cleanup_reproducer():
	finding = yaml.safe_load((ROOT / "findings" / f"{COMMENT_FINDING_ID}.yaml").read_text(encoding="utf-8"))
	recipe = yaml.safe_load((ROOT / "runtime" / "proofs" / f"{COMMENT_FINDING_ID}.yaml").read_text(encoding="utf-8"))
	artifact_path = ROOT / "runtime" / "artifacts" / COMMENT_FINDING_ID / "2026-07-15-comment-ownership.json"
	reproducer_path = ROOT / "runtime" / "reproducers" / f"{COMMENT_FINDING_ID}.sh"
	fp_log = yaml.safe_load((ROOT / "findings" / "fp-log.yaml").read_text(encoding="utf-8"))

	assert finding["status"] == "false_positive"
	assert finding["proof_tier"] == 2
	assert finding["privilege_required"] == "ordinary_authenticated_user"
	assert recipe["finding_id"] == COMMENT_FINDING_ID
	assert recipe["tiers"]["tier1"]["mode"] == "direct_call"
	assert recipe["tiers"]["tier2"]["mode"] == "http_post"
	assert artifact_path.is_file()
	assert reproducer_path.is_file()
	assert reproducer_path.stat().st_mode & 0o111
	assert any(entry["finding_id"] == COMMENT_FINDING_ID for entry in fp_log["false_positives"])


def test_comment_publicity_false_positive_has_runtime_evidence_and_cleanup_reproducer():
	finding = yaml.safe_load((ROOT / "findings" / f"{PUBLICITY_FINDING_ID}.yaml").read_text(encoding="utf-8"))
	recipe = yaml.safe_load((ROOT / "runtime" / "proofs" / f"{PUBLICITY_FINDING_ID}.yaml").read_text(encoding="utf-8"))
	artifact_path = ROOT / "runtime" / "artifacts" / PUBLICITY_FINDING_ID / "2026-07-15-comment-publicity.json"
	reproducer_path = ROOT / "runtime" / "reproducers" / f"{PUBLICITY_FINDING_ID}.sh"
	fp_log = yaml.safe_load((ROOT / "findings" / "fp-log.yaml").read_text(encoding="utf-8"))

	assert finding["status"] == "false_positive"
	assert finding["proof_tier"] == 2
	assert finding["privilege_required"] == "ordinary_authenticated_user"
	assert recipe["finding_id"] == PUBLICITY_FINDING_ID
	assert recipe["tiers"]["tier1"]["mode"] == "direct_call"
	assert recipe["tiers"]["tier2"]["mode"] == "http_post"
	assert recipe["tiers"]["tier2"]["assertion"].find("HTTP 417") >= 0
	assert artifact_path.is_file()
	assert reproducer_path.is_file()
	assert reproducer_path.stat().st_mode & 0o111
	assert any(entry["finding_id"] == PUBLICITY_FINDING_ID for entry in fp_log["false_positives"])


def test_false_positive_suppression_is_exact_and_precision_excludes_candidates():
	fp_records = load_false_positives(ROOT / "findings" / "fp-log.yaml")
	known = Candidate(
		rule_id="FR-PERM-002",
		rule_version="1.0.0",
		taxonomy_id="FR-PERM-002",
		file="frappe/www/contact.py",
		line=73,
		function="send_message",
		code_location_hash="bcb497ea723786f4",
		evidence="static candidate",
		proof_recipe="runtime proof",
	)
	workspace = Candidate(
		rule_id="FR-PERM-002",
		rule_version="1.0.0",
		taxonomy_id="FR-PERM-002",
		file="frappe/desk/doctype/workspace/workspace.py",
		line=401,
		function="update_page",
		code_location_hash="778fcdfa12995025",
		evidence="static candidate",
		proof_recipe="runtime proof",
	)
	comment = Candidate(
		rule_id="FR-PERM-002",
		rule_version="1.0.0",
		taxonomy_id="FR-PERM-002",
		file="frappe/desk/form/utils.py",
		line=67,
		function="update_comment",
		code_location_hash="419a31b0ce27ebc2",
		evidence="static candidate",
		proof_recipe="runtime proof",
	)
	publicity = Candidate(
		rule_id="FR-PERM-002",
		rule_version="1.0.0",
		taxonomy_id="FR-PERM-002",
		file="frappe/desk/form/utils.py",
		line=77,
		function="update_comment_publicity",
		code_location_hash="419a31b0ce27ebc2",
		evidence="static candidate",
		proof_recipe="runtime proof",
	)
	changed_rule = Candidate(
		rule_id="FR-PERM-002",
		rule_version="1.0.1",
		taxonomy_id="FR-PERM-002",
		file=known.file,
		line=known.line,
		function=known.function,
		code_location_hash=known.code_location_hash,
		evidence=known.evidence,
		proof_recipe=known.proof_recipe,
	)
	result = apply_fp_suppression(
		(known, workspace, comment, publicity, changed_rule),
		fp_records,
		"frappe/frappe@e3f8e9da35ab8930abc0a632a5a2723a9c5c8cf5",
	)
	metrics = {(item.rule_id, item.rule_version): item for item in precision_by_rule(ROOT / "findings")}

	assert result.suppressed_finding_ids == (WORKSPACE_FINDING_ID, FINDING_ID, COMMENT_FINDING_ID, PUBLICITY_FINDING_ID)
	assert result.candidates == (changed_rule,)
	assert metrics[("FR-PERM-002", "1.0.0")].proven == 4
	assert metrics[("FR-PERM-002", "1.0.0")].false_positives == 5
	assert metrics[("FR-PERM-002", "1.0.0")].precision == 4 / 9


def test_historical_merged_findings_have_public_tier_two_evidence():
	for finding_id in HISTORICAL_FINDING_IDS:
		finding = yaml.safe_load(
			(ROOT / "findings" / f"{finding_id}.yaml").read_text(encoding="utf-8")
		)

		assert finding["status"] == "merged"
		assert finding["proof_tier"] == 2
		assert finding["proven"] is True
		assert finding["taxonomy_id"] == "FR-PERM-002"
		assert finding["upstream_pr"].startswith("https://github.com/")
		assert finding["proof_artifact"] == finding["upstream_pr"]


def test_track_record_is_derived_from_ledger_and_keeps_candidates_internal_only():
	report = render_track_record(ROOT / "findings")
	stored_report = (ROOT / "reports" / "track-record.md").read_text(encoding="utf-8")

	assert report == stored_report
	assert "Static candidates are internal-only Tier 0 records." in report
	assert "| candidate | 78 |" in report
	assert "| false_positive | 5 |" in report
	assert "| FR-PERM-002 v1.0.0 | 4 | 5 | 44% |" in report
