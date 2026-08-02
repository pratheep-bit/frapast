"""Shared HTTP client for running Tier 2 (http_rpc) reproducer assertions against a Frappe bench site."""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

BENCH_HOST = os.environ.get("FRAPPE_BENCH_HOST", "security.localhost")


def make_frappe_request(
    base_url: str,
    method_path: str,
    username: str = "test_low_priv@example.com",
    password: str = "password",
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any] | str]:
    """
    Log in as username/password against a Frappe bench site at base_url,
    then invoke the Whitelisted endpoint method_path via HTTP POST.

    Returns:
        tuple[int, dict | str]: (HTTP status code, response json or raw body string)
    """
    base_url = base_url.rstrip("/")
    login_url = f"{base_url}/api/method/login"
    endpoint_url = f"{base_url}/api/method/{method_path}"

    # Use CookieJar / HTTPCookieProcessor for session management
    cj = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(cj)

    # 1. Authenticate / Login
    login_data = urllib.parse.urlencode({
        "usr": username,
        "pwd": password,
    }).encode("utf-8")

    login_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": BENCH_HOST,
    }

    req_login = urllib.request.Request(
        login_url,
        data=login_data,
        headers=login_headers,
        method="POST",
    )

    try:
        with opener.open(req_login) as resp:
            if resp.status != 200:
                return resp.status, "Login failed"
            body = resp.read().decode("utf-8", errors="ignore")
            # Frappe API login returns JSON with 'Logged In' or session keys
            if "Logged In" not in body and "message" not in body and "sid" not in body:
                return 401, f"Login response invalid (not authenticated): {body[:100]}"
    except urllib.error.HTTPError as e:
        return e.code, f"Login HTTPError: {e.reason}"
    except Exception as e:
        return 0, f"Login Exception: {e}"

    # 2. Invoke Whitelisted Endpoint
    post_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Host": BENCH_HOST,
    }
    if headers:
        post_headers.update(headers)

    payload = json.dumps(data or {}).encode("utf-8")
    req_endpoint = urllib.request.Request(
        endpoint_url,
        data=payload,
        headers=post_headers,
        method="POST",
    )

    try:
        with opener.open(req_endpoint) as resp:
            status = resp.status
            body_bytes = resp.read()
            body_str = body_bytes.decode("utf-8", errors="ignore")
            # Safeguard against HTML login redirect disguised as HTTP 200
            if body_str.lstrip().startswith("<!DOCTYPE") or "<html" in body_str.lower():
                return 401, f"Received HTML page instead of API JSON response: {body_str[:100]}"
            try:
                body_json = json.loads(body_str)
                return status, body_json
            except Exception:
                return status, body_str
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        body_str = body_bytes.decode("utf-8", errors="ignore")
        try:
            body_json = json.loads(body_str)
            return e.code, body_json
        except Exception:
            return e.code, body_str
    except Exception as e:
        return 0, f"Endpoint Exception: {e}"
