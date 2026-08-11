from __future__ import annotations

import json
from pathlib import Path


def _tool_version() -> str:
	"""Return the installed frapast version, falling back gracefully."""
	try:
		from scanner import __version__
		return __version__
	except Exception:
		return "unknown"


def export_sarif(candidates: list[dict[str, object]], repo_path: Path) -> str:
	"""Convert candidate findings into OASIS SARIF v2.1.0 JSON format."""
	rules_meta: dict[str, dict] = {}
	results = []

	for c in candidates:
		rule_id = str(c.get("rule_id", "UNKNOWN"))
		tax_id = str(c.get("taxonomy_id", rule_id))
		file_path = str(c.get("file", ""))
		line_num = int(c.get("line", 1) or 1)
		evidence = str(c.get("evidence", ""))
		sev_info = c.get("severity")
		score = float(sev_info.get("score", 0.0)) if isinstance(sev_info, dict) else 0.0

		if score >= 60:
			level = "error"
		elif score >= 20:
			level = "warning"
		else:
			level = "note"

		if rule_id not in rules_meta:
			rules_meta[rule_id] = {
				"id": rule_id,
				"shortDescription": {"text": f"Frappe Security Rule {rule_id}"},
				"fullDescription": {"text": evidence},
				"defaultConfiguration": {"level": level},
			}

		results.append({
			"ruleId": rule_id,
			"level": level,
			"message": {"text": evidence},
			"locations": [
				{
					"physicalLocation": {
						"artifactLocation": {"uri": file_path},
						"region": {"startLine": line_num},
					}
				}
			],
		})

	sarif_doc = {
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "frapast",
						# Dynamic version — always reflects the installed package.
						# Previously hardcoded as "0.3.0" which caused phantom
						# version regressions in GitHub Code Scanning on every run.
						"version": _tool_version(),
						"informationUri": "https://github.com/pratheep-bit/frapast",
						"rules": list(rules_meta.values()),
					}
				},
				"results": results,
			}
		],
	}

	return json.dumps(sarif_doc, indent=2)
