from __future__ import annotations

from pathlib import Path
from scanner.proof.models import PROOF_MODE_MARKER, VALID_PROOF_MODES


def synthesize_http_rpc_reproducer(
	reproducers_dir: Path, finding_id: str, finding_data: dict, workspace_root: Path
) -> Path | None:
	"""Synthesizes a Tier 2 HTTP RPC verification reproducer for whitelisted endpoints."""
	rule_id = finding_data.get("rule_id", "")
	func_name = finding_data.get("function", "")

	if rule_id != "FR-PERM-001" or not func_name:
		return None

	reproducers_dir.mkdir(parents=True, exist_ok=True)
	out_path = reproducers_dir / f"{finding_id}.sh"

	script_body = f"""#!/usr/bin/env bash
{PROOF_MODE_MARKER} http_rpc
python3 -c "
import urllib.request
url = 'http://localhost:8000/api/method/{func_name}'
try:
    req = urllib.request.Request(url, method='POST')
    with urllib.request.urlopen(req, timeout=5) as resp:
        print('HTTP RPC endpoint accessible:', resp.status)
        exit(0)
except Exception as e:
    print('HTTP RPC request status:', e)
    exit(1)
"
"""
	out_path.write_text(script_body, encoding="utf-8")
	out_path.chmod(0o755)
	return out_path
