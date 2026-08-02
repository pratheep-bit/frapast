"""CI gate: fail if any rule_id/taxonomy_id in scanner/rules/*.yaml is not
listed in scanner/taxonomy_registry.yaml. Also warns loudly (does not merely
pass silently) if any additional_categories entry still has unresolved
placeholder fields — this is what stops new categories from being quietly
rubber-stamped the way FR-CSRF/SSRF/PERF/I18N were."""
import sys
from pathlib import Path
import yaml

REGISTRY = Path(__file__).parent / "taxonomy_registry.yaml"
RULES_DIR = Path(__file__).parent / "rules"

PLACEHOLDER_MARKERS = ("FILL IN", "TBD")


def main() -> int:
	registry = yaml.safe_load(REGISTRY.read_text())
	known_prefixes = set(registry.get("core_scope", {}).keys()) | set(
		registry.get("documented_undetected", {}).keys()
	) | set(registry.get("additional_categories", {}).keys())
	known_extensions = set(registry.get("extensions", {}).keys())

	failures = []
	for rule_file in RULES_DIR.glob("*.yaml"):
		if rule_file.name == "schema.yaml":
			continue
		rule = yaml.safe_load(rule_file.read_text())
		tid = rule.get("taxonomy_id") or rule.get("id") or rule.get("family") or ""
		prefix = tid.rsplit("-", 1)[0] if "-" in tid else tid
		if prefix not in known_prefixes and tid not in known_extensions:
			failures.append(f"{rule_file.name}: taxonomy_id '{tid}' not in registry")

	engine_path = RULES_DIR / "engine.py"
	if engine_path.is_file():
		import ast as _ast
		tree = _ast.parse(engine_path.read_text(encoding="utf-8"))
		for node in _ast.walk(tree):
			if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Name) and node.func.id == "_candidate":
				if node.args and isinstance(node.args[0], _ast.Constant) and isinstance(node.args[0].value, str):
					rule_id = node.args[0].value
					prefix = rule_id.rsplit("-", 1)[0] if "-" in rule_id else rule_id
					if prefix not in known_prefixes and rule_id not in known_extensions:
						failures.append(f"rules/engine.py: emits rule_id '{rule_id}' not in registry")

	if failures:
		print("Taxonomy drift detected:")
		for f in failures:
			print(f"  - {f}")
		return 1

	warnings = []
	for prefix, meta in registry.get("additional_categories", {}).items():
		blob = " ".join(str(v) for v in meta.values())
		if any(marker in blob for marker in PLACEHOLDER_MARKERS):
			warnings.append(
				f"{prefix}: additional_categories entry has unresolved placeholder "
				f"fields — this category was added without documented justification."
			)

	if warnings:
		print("⚠️  UNRESOLVED ADDITIONAL CATEGORIES (does not fail the build, but must "
		      "not be ignored):")
		for w in warnings:
			print(f"  - {w}")

	print("All taxonomy IDs match the registry.")
	return 0


if __name__ == "__main__":
	sys.exit(main())
