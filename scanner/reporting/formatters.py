"""Reporting output formatters for scan ledgers."""

import json


def format_json(findings: list[dict]) -> str:
	return json.dumps(findings, indent=2)

