from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_yaml(path: Path):
	return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_docker_compose_exists_and_pins_mariadb():
	compose_path = ROOT / "docker-compose.yml"
	assert compose_path.exists()
	compose = load_yaml(compose_path)
	mariadb_image = compose["services"]["mariadb"]["image"]
	assert mariadb_image in {"mariadb:10.6.21", "mariadb:10.6"}
	assert "latest" not in mariadb_image
	assert not mariadb_image.startswith("mariadb:11")
	assert compose["services"]["mariadb"]["healthcheck"]
	assert compose["services"]["redis-cache"]["image"] == "redis:7-alpine"
	assert compose["services"]["redis-cache"]["healthcheck"]
	for service in ["bench", "worker", "scheduler"]:
		image = compose["services"][service]["image"]
		assert image.startswith("frappe/bench@sha256:")
		assert "latest" not in image


def test_makefile_contains_required_targets():
	text = (ROOT / "Makefile").read_text(encoding="utf-8")
	for target in ["site-new", "site-seed", "repro", "teardown", "test", "lint", "logs"]:
		assert f"{target}:" in text


def test_phase0_make_targets_do_not_mask_failures():
	text = (ROOT / "Makefile").read_text(encoding="utf-8")
	for target in ["site-new", "site-seed", "repro"]:
		section = text.split(f"{target}:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
		assert "|| true" not in section


def test_phase0_smoke_reproducer_exists():
	reproducer = ROOT / "runtime" / "reproducers" / "001.sh"
	assert reproducer.exists()
	assert reproducer.stat().st_mode & 0o111
	text = reproducer.read_text(encoding="utf-8")
	assert "site_config.json" in text
	assert "frappe.get_installed_apps" in text


def test_findings_schema_contains_required_field_names():
	schema_path = ROOT / "findings" / ".schema.yaml"
	assert schema_path.exists()
	schema = load_yaml(schema_path)
	for field in [
		"id",
		"taxonomy_id",
		"rule_id",
		"rule_version",
		"repo",
		"file",
		"function",
		"status",
		"proof_tier",
		"privilege_required",
		"allow_guest",
		"impact_class",
		"blast_radius",
		"code_location_hash",
		"discovered",
		"proven",
		"notes",
	]:
		assert field in schema["required"]


def test_example_finding_validates_against_schema():
	schema = load_yaml(ROOT / "findings" / ".schema.yaml")
	finding = load_yaml(ROOT / "findings" / "FR-PERM-001-0001.yaml")
	for field in schema["required"]:
		assert field in finding
	assert finding["status"] in schema["status_values"]
	assert finding["proof_tier"] in schema["proof_tier_values"]
	assert finding["taxonomy_id"] == "FR-PERM-001"
	assert finding["status"] == "merged"
