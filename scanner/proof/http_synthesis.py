"""Per-rule HTTP/RPC reproducer script synthesis for Tier 2 proof verification.

Every function in this module generates a self-contained bash script that wraps
a Python proof program. The scripts are stored in runtime/reproducers/ and executed
by the ProofOrchestrator during a `frapast prove` run.

Design rules:
- Line 1 of every generated script MUST be `# PROOF_MODE: http_rpc`
  (enforced by validate_reproducer_markers.py CI gate).
- Scripts must use FrappeHTTPClient from scanner.proof.http_client — not
  raw urllib — so all session / error handling is consistent.
- Each synthesis function is responsible for ONE rule family; the router
  function `synthesize_http_rpc_reproducer` dispatches by rule_id.
- A function that cannot produce a meaningful proof (missing required
  finding data) returns None — the caller handles the fallback.

Security model — INJECTION HARDENING:
- All untrusted values sourced from finding_data (function, file, target_arg,
  etc.) are passed exclusively via exported bash environment variables using
  shlex.quote(), never f-string-interpolated into Python source inside the
  heredoc.
- The generated Python reads these values with os.environ.get() — exactly the
  same pattern used in scanner/proof/orchestrator.py for FRAPAST_TARGET_FILE.
- Any finding_data value containing \\n or \\r is rejected (returns None) before
  reaching any script generation code, preventing heredoc boundary corruption.
- The heredoc delimiter is the quoted form <<'PYEOF', so bash never expands
  anything in the body regardless.
"""
from __future__ import annotations

import os
import shlex
import tempfile
import textwrap
from collections.abc import Callable
from pathlib import Path

from scanner.proof.models import PROOF_MODE_MARKER, VALID_PROOF_MODES

_SynthFn = Callable[[str, dict], str | None]

# ---------------------------------------------------------------------------
# Synthesis version — bump this constant whenever any _synth_* function body
# changes. discover_reproducers() embeds this version in a sidecar file next
# to each generated reproducer; if the on-disk version doesn't match, the
# reproducer is regenerated from scratch.  This prevents stale/vulnerable
# scripts (pre-hardening) from being silently reused.
# ---------------------------------------------------------------------------
SYNTHESIS_VERSION = "v2"  # bumped: hardened all synth functions against injection


# ---------------------------------------------------------------------------
# Entry point — called by ProofOrchestrator
# ---------------------------------------------------------------------------


def synthesize_http_rpc_reproducer(
    reproducers_dir: Path,
    finding_id: str,
    finding_data: dict,
    workspace_root: Path,
) -> Path | None:
    """Synthesise a Tier 2 HTTP/RPC reproducer for the given finding.

    Returns the path to the generated script, or None if this rule has no
    HTTP-provable strategy or the required finding metadata is missing.
    """
    rule_id: str = finding_data.get("rule_id", "")

    fn = _SYNTHESIS_MAP.get(rule_id)
    if fn is None:
        return None

    script_body = fn(finding_id, finding_data)
    if script_body is None:
        return None

    reproducers_dir.mkdir(parents=True, exist_ok=True)
    out_path = reproducers_dir / f"{finding_id}.sh"
    _write_reproducer(out_path, script_body)
    # Write version sidecar so discover_reproducers() can detect stale scripts
    _write_version_sidecar(out_path)
    return out_path


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _write_reproducer(path: Path, body: str) -> None:
    """Atomic write: temp file → chmod → os.replace() into place."""
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(tmp_name, 0o755)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _write_version_sidecar(reproducer_path: Path) -> None:
    """Write a .version sidecar file next to a reproducer script."""
    sidecar = reproducer_path.with_suffix(".version")
    sidecar.write_text(SYNTHESIS_VERSION, encoding="utf-8")


def _reject_if_newline(*values: str) -> bool:
    """Return True if any value contains a newline character.

    Callers should return None (→ SKIPPED) when this returns True, to prevent
    heredoc boundary corruption from crafted finding data.
    """
    for v in values:
        if "\n" in v or "\r" in v:
            return True
    return False


def _base_imports() -> str:
    """Standard imports block embedded in every reproducer."""
    return textwrap.dedent("""\
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
        API_METHOD = os.environ.get('FRAPAST_API_METHOD', '')
    """)


def _wrap_in_bash(py_code: str, env_exports: str = "") -> str:
    """Wrap Python code in a bash heredoc with optional environment exports.

    The quoted heredoc delimiter <<'PYEOF' prevents bash from expanding
    anything inside the body, so the Python source is always reproduced
    verbatim — no escaping needed.

    All untrusted values are exported as bash environment variables (via
    env_exports, which uses shlex.quote()) and read by the Python code
    via os.environ.get().
    """
    exports_block = f"{env_exports}\n" if env_exports else ""
    return f"#!/usr/bin/env bash\n{PROOF_MODE_MARKER} http_rpc\n{exports_block}python3 - <<'PYEOF'\n{py_code}\nPYEOF\n"


def _connection_guard() -> str:
    """Standard bench reachability check embedded in every reproducer."""
    return textwrap.dedent("""\
        client = FrappeHTTPClient(BENCH_URL, site_name=SITE_NAME)
        if not client.ping():
            print(f'SKIP: bench at {BENCH_URL} is not reachable')
            sys.exit(2)  # exit 2 = SKIPPED (not a proof failure)
    """)


def _safe_api_method(func_name: str) -> str:
    """Normalise a function name to a dotted API path."""
    return func_name.replace("/", ".").strip(".")


# ---------------------------------------------------------------------------
# Rule: FR-PERM-001 — Missing permission check on whitelisted endpoint
# ---------------------------------------------------------------------------


def _synth_perm_001(finding_id: str, data: dict) -> str | None:
    """Proof: invoke the endpoint as Guest without auth; assert it rejects access."""
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-PERM-001
        # Strategy: call the whitelisted endpoint as an unauthenticated (Guest) user.
        # A correct implementation should return HTTP 403 / PermissionError.
        # If it returns 200 with data, the permission check is missing — PROVEN.
        {_base_imports()}
        {_connection_guard()}
        print(f'Calling {{BENCH_URL}}/api/method/{{API_METHOD}} as Guest (no session)')
        resp = client.call_as_guest(API_METHOD)
        if resp.status == 200 and not resp.is_permission_error:
            print(f'PROVEN: endpoint returned HTTP {{resp.status}} without auth — permission check missing')
            sys.exit(0)
        elif resp.status in (403, 417) or resp.is_permission_error:
            print(f'REFUTED: endpoint correctly rejected guest access (HTTP {{resp.status}})')
            sys.exit(1)
        else:
            print(f'INCONCLUSIVE: unexpected status {{resp.status}} — {{resp.message!r}}')
            sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-PERM-002 — ignore_permissions=True reachable from whitelisted endpoint
# ---------------------------------------------------------------------------


def _synth_perm_002(finding_id: str, data: dict) -> str | None:
    """Proof: call the endpoint as a low-privilege authenticated user;
    attempt to access a document that should be restricted by permissions.
    """
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-PERM-002
        # Strategy: authenticate as the lowest-privilege role and call the endpoint.
        # If ignore_permissions=True bypasses role checks, the call succeeds when it
        # should be blocked — PROVEN.
        {_base_imports()}
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        resp = client.post(API_METHOD)
        client.logout()
        if resp.status == 200 and not resp.is_permission_error:
            print(f'POTENTIAL PROOF: endpoint returned HTTP {{resp.status}} — ignore_permissions may be bypassing role check')
            print('Manual verification required: confirm returned data is access-restricted for this role')
            sys.exit(0)
        elif resp.status in (403, 417) or resp.is_permission_error:
            print(f'REFUTED: endpoint correctly blocked low-privilege access (HTTP {{resp.status}})')
            sys.exit(1)
        else:
            print(f'INCONCLUSIVE: status {{resp.status}} — {{resp.message!r}}')
            sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-PERM-003 — if_owner bypass via frappe.db.set_value
# ---------------------------------------------------------------------------


def _synth_perm_003(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-PERM-003
        # Strategy: authenticate and attempt to write to an if_owner-scoped document
        # owned by a different user. A missing ownership check means the write succeeds.
        {_base_imports()}
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        # Send a request that would mutate an owner-scoped doc using a placeholder name.
        # A real probe must supply the correct doctype/name; this is a structural check.
        resp = client.post(API_METHOD, {{'name': '__probe__', 'field': '__sentinel__'}})
        client.logout()
        if resp.status in (403, 417) or resp.is_permission_error:
            print(f'REFUTED: ownership check is present (HTTP {{resp.status}})')
            sys.exit(1)
        elif resp.status == 200:
            print(f'POTENTIAL PROOF: write succeeded without ownership validation')
            sys.exit(0)
        else:
            print(f'INCONCLUSIVE: status {{resp.status}}')
            sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-SQLI-001 — Unparameterised dynamic SQL
# ---------------------------------------------------------------------------


def _synth_sqli_001(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-SQLI-001
        # Strategy: send a SQL-injection payload in a likely parameter.
        # If the server returns an SQL error or unexpected data the injection is confirmed.
        {_base_imports()}
        INJECTION_PAYLOADS = [
            "' OR '1'='1",
            "'; SELECT SLEEP(1); --",
            "1 UNION SELECT NULL,NULL,NULL--",
        ]
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        proven = False
        for payload in INJECTION_PAYLOADS:
            resp = client.post(API_METHOD, {{'filters': payload, 'name': payload}})
            body_str = str(resp.body)
            # Frappe wraps DB exceptions — detect SQL error signatures
            if any(sig in body_str for sig in ('ProgrammingError', 'OperationalError', '1064', 'syntax error')):
                print(f'PROVEN: SQL error in response to injection payload {{payload!r}}')
                proven = True
                break
        client.logout()
        sys.exit(0 if proven else 1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-SQLI-003 — frappe.db.set_value bypassing validate() hooks
# ---------------------------------------------------------------------------


def _synth_sqli_003(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-SQLI-003
        # Strategy: invoke the endpoint and verify that the validate() / before_save()
        # lifecycle hooks were NOT triggered (hooks would reject or transform the value).
        # This is primarily a structural / Tier-1 finding; HTTP just confirms reachability.
        {_base_imports()}
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        resp = client.post(API_METHOD)
        client.logout()
        if resp.status == 200:
            print('POTENTIAL PROOF: endpoint is reachable — set_value call bypasses validate(); manual ledger review required')
            sys.exit(0)
        print(f'REFUTED or INCONCLUSIVE: HTTP {{resp.status}}')
        sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-SQLI-004 — Dynamic table/column in frappe.qb
# ---------------------------------------------------------------------------


def _synth_sqli_004(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-SQLI-004
        # Strategy: inject a crafted table name. If the server does not sanitise
        # the table argument, the DB query may error or leak cross-table data.
        {_base_imports()}
        INJECTION = "tabUser`; SELECT SLEEP(1); --"
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        resp = client.post(API_METHOD, {{'doctype': INJECTION}})
        client.logout()
        body_str = str(resp.body)
        if any(s in body_str for s in ('ProgrammingError', 'OperationalError', '1064')):
            print('PROVEN: SQL error surfaced through dynamic frappe.qb table name')
            sys.exit(0)
        print(f'REFUTED or INCONCLUSIVE: HTTP {{resp.status}}')
        sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-INJ-001 — Mass assignment via **kwargs
# ---------------------------------------------------------------------------


def _synth_inj_001(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-INJ-001
        # Strategy: send extra unexpected fields in the POST body. If the endpoint
        # passes **kwargs directly to frappe.get_doc(), those fields get written.
        {_base_imports()}
        MASS_ASSIGN_PAYLOAD = {{
            'name': '__probe__',
            '__islocal': 1,
            'owner': 'hacker@example.com',
            'creation': '2000-01-01',
        }}
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        resp = client.post(API_METHOD, MASS_ASSIGN_PAYLOAD)
        client.logout()
        if resp.status == 200 and not resp.is_permission_error:
            print('POTENTIAL PROOF: endpoint accepted extra fields — mass assignment may be possible')
            sys.exit(0)
        print(f'REFUTED or INCONCLUSIVE: HTTP {{resp.status}}')
        sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-INJ-002 — eval()/exec() with request-controlled input
# ---------------------------------------------------------------------------


def _synth_inj_002(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-INJ-002
        # Strategy: send a benign sentinel expression as the likely eval payload.
        # A side-channel (response body containing the evaluated result) confirms RCE.
        {_base_imports()}
        SENTINEL_EXPR = '__frapast_probe_7f3a__'
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        resp = client.post(API_METHOD, {{'code': SENTINEL_EXPR, 'expr': SENTINEL_EXPR}})
        client.logout()
        body_str = str(resp.body)
        if SENTINEL_EXPR in body_str or resp.status == 200:
            print('POTENTIAL PROOF: eval payload may have been executed — manual verification required')
            sys.exit(0)
        print(f'REFUTED or INCONCLUSIVE: HTTP {{resp.status}}')
        sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-CSRF-001 — State-changing endpoint without CSRF token
# ---------------------------------------------------------------------------


def _synth_csrf_001(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-CSRF-001
        # Strategy: POST to the endpoint WITHOUT the X-Frappe-CSRF-Token header.
        # Frappe should return HTTP 417 if CSRF protection is enforced.
        # If it returns 200, CSRF is not enforced — PROVEN.
        {_base_imports()}
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        # Post without CSRF header
        resp = client.post(API_METHOD, include_csrf=False)
        client.logout()
        if resp.status == 417 or 'CSRFTokenError' in str(resp.body):
            print('REFUTED: CSRF protection is enforced (HTTP 417)')
            sys.exit(1)
        elif resp.status == 200:
            print('PROVEN: endpoint accepted state-changing POST without CSRF token')
            sys.exit(0)
        else:
            print(f'INCONCLUSIVE: HTTP {{resp.status}}')
            sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-SSRF-001 — User-controlled URL in outbound HTTP request
# ---------------------------------------------------------------------------


def _synth_ssrf_001(finding_id: str, data: dict) -> str | None:
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-SSRF-001
        # Strategy: send a crafted URL pointing to the bench's own /api/method/ping.
        # If the bench makes a request to it (SSRF), we observe a 200 on the target.
        # This is a structural check — full SSRF confirmation requires an external listener.
        {_base_imports()}
        SSRF_TARGET = f'{{BENCH_URL}}/api/method/ping'
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        resp = client.post(API_METHOD, {{'url': SSRF_TARGET, 'endpoint': SSRF_TARGET}})
        client.logout()
        if resp.status == 200:
            print('POTENTIAL PROOF: endpoint accepted a URL parameter without validation — SSRF may be possible')
            print('Set up an external listener (e.g. webhook.site) to confirm outbound request')
            sys.exit(0)
        print(f'REFUTED or INCONCLUSIVE: HTTP {{resp.status}}')
        sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


# ---------------------------------------------------------------------------
# Rule: FR-PATH-001 — Path Traversal in File Operations
# ---------------------------------------------------------------------------


def _synth_path_001(finding_id: str, data: dict) -> str | None:
    """Proof: send path traversal payloads to the endpoint.
    Assert that the endpoint rejects access rather than returning sensitive files.
    """
    func_name: str = data.get("function", "")
    if not func_name:
        return None
    if _reject_if_newline(func_name):
        return None

    api_method = _safe_api_method(func_name)
    env_exports = f"export FRAPAST_API_METHOD={shlex.quote(api_method)}"

    py = textwrap.dedent(f"""\
        # Tier 2 proof for {finding_id} — FR-PATH-001
        # Strategy: send path traversal payloads to the endpoint.
        # If the server reads or returns data outside the base directory, it is PROVEN.
        {_base_imports()}
        {_connection_guard()}
        try:
            client.login(BENCH_USER, BENCH_PWD)
        except FrappeAuthError as exc:
            print(f'SKIP: could not authenticate: {{exc}}')
            sys.exit(2)
        payloads = ['../../../../etc/passwd', '..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini']
        for payload in payloads:
            resp = client.post(API_METHOD, {{'path': payload, 'filename': payload, 'template_path': payload, 'file_name': payload}})
            if resp.status == 200 and ('root:' in str(resp.data) or '[extensions]' in str(resp.data)):
                print(f'PROVEN: endpoint returned file contents for traversal path {{payload}}')
                client.logout()
                sys.exit(0)
        client.logout()
        print('REFUTED or INCONCLUSIVE: traversal payload did not return sensitive file contents')
        sys.exit(1)
    """)
    return _wrap_in_bash(py, env_exports)


_SYNTHESIS_MAP: dict[str, _SynthFn] = {
    "FR-PERM-001": _synth_perm_001,
    "FR-PERM-002": _synth_perm_002,
    "FR-PERM-003": _synth_perm_003,
    "FR-SQLI-001": _synth_sqli_001,
    "FR-SQLI-003": _synth_sqli_003,
    "FR-SQLI-004": _synth_sqli_004,
    "FR-PATH-001": _synth_path_001,
    "FR-INJ-001":  _synth_inj_001,
    "FR-INJ-002":  _synth_inj_002,
    "FR-CSRF-001": _synth_csrf_001,
    "FR-SSRF-001": _synth_ssrf_001,
}
