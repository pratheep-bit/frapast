#!/usr/bin/env bash
# PROOF_MODE: http_rpc
python3 - <<'PYEOF'
        # Tier 2 proof for FR-PERM-001-caa8612e3417a0ba — FR-PERM-001
        # Strategy: call the whitelisted endpoint as an unauthenticated (Guest) user.
        # A correct implementation should return HTTP 403 / PermissionError.
        # If it returns 200 with data, the permission check is missing — PROVEN.
        import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from scanner.proof.http_client import (
    FrappeHTTPClient, FrappeConnectionError, FrappeAuthError,
    FrappePermissionError, FrappeHTTPError,
)
BENCH_URL = os.environ.get('FRAPAST_BENCH_URL', 'http://localhost:8000')
BENCH_USER = os.environ.get('FRAPAST_BENCH_USER', 'Administrator')
BENCH_PWD  = os.environ.get('FRAPAST_BENCH_PWD', 'admin')
SITE_NAME  = os.environ.get('FRAPAST_SITE_NAME', '')

        client = FrappeHTTPClient(BENCH_URL, site_name=SITE_NAME)
if not client.ping():
    print(f'SKIP: bench at {BENCH_URL} is not reachable')
    sys.exit(2)  # exit 2 = SKIPPED (not a proof failure)

        print(f'Calling {BENCH_URL}/api/method/get_help_results_sections as Guest (no session)')
        resp = client.call_as_guest('get_help_results_sections')
        if resp.status == 200 and not resp.is_permission_error:
            print(f'PROVEN: endpoint returned HTTP {resp.status} without auth — permission check missing')
            sys.exit(0)
        elif resp.status in (403, 417) or resp.is_permission_error:
            print(f'REFUTED: endpoint correctly rejected guest access (HTTP {resp.status})')
            sys.exit(1)
        else:
            print(f'INCONCLUSIVE: unexpected status {resp.status} — {resp.message!r}')
            sys.exit(1)

PYEOF
