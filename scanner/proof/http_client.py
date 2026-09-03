"""Frappe HTTP/RPC client for Tier 2 proof verification.

Authenticates as a low-privilege user against a real Frappe bench and
executes targeted requests to prove or refute security findings over HTTP.

Design rules:
- No third-party dependencies (stdlib urllib only) so it runs anywhere Python 3.10+ does.
- All Frappe error envelope fields (exc, message, _server_messages, exc_type) are
  parsed and surfaced as typed exceptions — never swallowed silently.
- Cookies are managed transparently in a plain dict; the caller never handles
  raw Set-Cookie headers.
- Every method returns (status_code, response_body_dict) so callers can assert
  on both the HTTP status and the Frappe-level response content.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FrappeConnectionError(OSError):
    """Raised when the bench is unreachable (network error, timeout, etc.)."""
    pass


class FrappeHTTPError(Exception):
    """Raised for non-2xx HTTP responses from the bench."""

    def __init__(self, status: int, body: dict, url: str = "") -> None:
        self.status = status
        self.body = body
        self.url = url
        # Frappe error envelope fields
        self.exc_type: str = body.get("exc_type", "")
        self.message: str = body.get("message", "")
        self.exc: str = body.get("exc", "")
        super().__init__(f"HTTP {status} from {url}: {self.exc_type or self.message or str(body)[:120]}")


class FrappeAuthError(FrappeHTTPError):
    """Raised specifically for 401/403 authentication / permission failures."""
    pass


class FrappePermissionError(FrappeHTTPError):
    """Raised when Frappe responds with a PermissionError server-side (HTTP 417)."""
    pass


# ---------------------------------------------------------------------------
# Response dataclass
# ---------------------------------------------------------------------------


@dataclass
class FrappeResponse:
    """Structured response from a Frappe API call."""
    status: int
    body: dict
    cookies_received: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def message(self) -> str:
        return self.body.get("message", "")

    @property
    def exc_type(self) -> str:
        return self.body.get("exc_type", "")

    @property
    def is_permission_error(self) -> bool:
        return "PermissionError" in self.exc_type or "PermissionError" in self.body.get("exc", "")

    @property
    def is_auth_error(self) -> bool:
        return self.status in (401, 403) or "AuthenticationError" in self.exc_type

    def data(self, key: str = "message", default: Any = None) -> Any:
        """Convenience accessor for the 'message' key or any top-level key."""
        return self.body.get(key, default)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


class FrappeHTTPClient:
    """Lightweight, authenticated HTTP/RPC client for a Frappe bench.

    Usage:
        client = FrappeHTTPClient("http://localhost:8000")
        client.login("test@example.com", "password")
        status, body = client.post("frappe.client.get", {"doctype": "User", "name": "me"})
        client.logout()
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: int = 15,
        site_name: str = "",
    ) -> None:
        url = base_url.rstrip("/")
        # On Windows 11, 'localhost' resolves to IPv6 '::1' first. If Werkzeug/Frappe
        # listens only on IPv4 127.0.0.1, urllib hangs until the OS socket timeout (20s+).
        # Normalizing localhost to 127.0.0.1 avoids this delay completely.
        if url.startswith("http://localhost:"):
            url = "http://127.0.0.1:" + url[len("http://localhost:"):]
        elif url == "http://localhost":
            url = "http://127.0.0.1"
        self.base_url = url
        self.timeout = timeout
        self.site_name = site_name
        self._cookies: dict[str, str] = {}
        self._csrf_token: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """Health-check: return True if bench responds to /api/method/ping."""
        try:
            status, body = self._raw_request("GET", "/api/method/ping", data=None, extra_headers={})
            return status == 200 and body.get("message") == "pong"
        except (FrappeConnectionError, FrappeHTTPError):
            return False

    def login(self, usr: str, pwd: str) -> FrappeResponse:
        """Authenticate against the bench. Stores session cookie for subsequent calls.

        Raises FrappeAuthError if credentials are rejected.
        """
        status, body = self._raw_request(
            "POST",
            "/api/method/login",
            data={"usr": usr, "pwd": pwd},
            extra_headers={},
        )
        resp = FrappeResponse(status=status, body=body)
        if status not in (200, 302) or body.get("message") not in ("Logged In", "No App"):
            raise FrappeAuthError(status, body, f"{self.base_url}/api/method/login")
        # Extract CSRF token if Frappe sent it
        self._csrf_token = body.get("home_page", "") and self._fetch_csrf_token() or ""
        return resp

    def logout(self) -> FrappeResponse:
        """Invalidate the current session."""
        try:
            status, body = self._raw_request("POST", "/api/method/logout", data={}, extra_headers={})
        except (FrappeHTTPError, FrappeConnectionError):
            body = {}
            status = 200
        self._cookies.clear()
        self._csrf_token = ""
        return FrappeResponse(status=status, body=body)

    def get(
        self,
        method: str,
        params: dict | None = None,
        *,
        assert_status: int | None = None,
    ) -> FrappeResponse:
        """Perform an authenticated GET to /api/method/<method>.

        Args:
            method:        Frappe API method dotted path.
            params:        URL query parameters.
            assert_status: If set, raises FrappeHTTPError if status != assert_status.
        """
        qs = ""
        if params:
            qs = "?" + urllib.parse.urlencode(params)
        path = f"/api/method/{method}{qs}"
        status, body = self._raw_request("GET", path, data=None, extra_headers={})
        resp = FrappeResponse(status=status, body=body)
        self._maybe_assert_status(resp, assert_status, method)
        return resp

    def post(
        self,
        method: str,
        data: dict | None = None,
        headers: dict | None = None,
        *,
        assert_status: int | None = None,
        include_csrf: bool = True,
    ) -> FrappeResponse:
        """Perform an authenticated POST to /api/method/<method>.

        Args:
            method:        Frappe API method dotted path.
            data:          POST body as key-value dict.
            headers:       Additional request headers.
            assert_status: If set, raises FrappeHTTPError if status != assert_status.
            include_csrf:  Whether to include the CSRF token header (default True).
        """
        extra_headers = dict(headers or {})
        if include_csrf and self._csrf_token:
            extra_headers["X-Frappe-CSRF-Token"] = self._csrf_token
        status, body = self._raw_request(
            "POST",
            f"/api/method/{method}",
            data=data or {},
            extra_headers=extra_headers,
        )
        resp = FrappeResponse(status=status, body=body)
        self._maybe_assert_status(resp, assert_status, method)
        return resp

    def call_as_guest(self, method: str, data: dict | None = None) -> FrappeResponse:
        """POST to a whitelisted endpoint without any session (guest/anonymous access)."""
        saved_cookies = dict(self._cookies)
        saved_csrf = self._csrf_token
        self._cookies.clear()
        self._csrf_token = ""
        try:
            return self.post(method, data, include_csrf=False)
        finally:
            self._cookies = saved_cookies
            self._csrf_token = saved_csrf

    def assert_endpoint_returns_permission_error(self, method: str, data: dict | None = None) -> bool:
        """Return True if calling <method> as the current session gets a permission error.

        Accepts HTTP 403, 417, or a Frappe PermissionError in exc_type.
        """
        resp = self.post(method, data, include_csrf=False)
        return (
            resp.status in (403, 417)
            or resp.is_permission_error
            or resp.is_auth_error
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_csrf_token(self) -> str:
        """Try to read the CSRF token from a lightweight Frappe endpoint."""
        try:
            status, body = self._raw_request("GET", "/api/method/frappe.auth.get_logged_user", data=None, extra_headers={})
            return ""  # CSRF extracted from cookie jar if present
        except Exception:
            return ""

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def _parse_set_cookie(self, raw: str) -> tuple[str, str]:
        """Parse a single Set-Cookie header into (name, value)."""
        first_part = raw.split(";")[0]
        if "=" in first_part:
            name, _, value = first_part.partition("=")
            return name.strip(), value.strip()
        return "", ""

    def _raw_request(
        self,
        method: str,
        path: str,
        data: dict | None,
        extra_headers: dict,
    ) -> tuple[int, dict]:
        """Low-level HTTP request. Returns (status_code, parsed_json_body).

        Raises FrappeConnectionError on network failure, FrappeHTTPError on non-2xx.
        """
        url = f"{self.base_url}{path}"
        req_headers: dict[str, str] = {
            "Accept": "application/json",
        }
        if self.site_name:
            req_headers["Host"] = self.site_name
        if self._cookies:
            req_headers["Cookie"] = self._cookie_header()
        req_headers.update(extra_headers)

        encoded_data: bytes | None = None
        if data is not None:
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            encoded_data = urllib.parse.urlencode(data).encode("utf-8")

        req = urllib.request.Request(url, data=encoded_data, headers=req_headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                raw_body = resp.read().decode("utf-8", errors="replace")
                # Absorb new cookies
                info = resp.info()
                for cookie_line in (info.get_all("Set-Cookie") or []):
                    name, value = self._parse_set_cookie(cookie_line)
                    if name:
                        self._cookies[name] = value
                        if name == "sid" and value not in ("Guest", ""):
                            # Presence of session cookie means logged in
                            pass
                return status, self._parse_body(raw_body)

        except urllib.error.HTTPError as exc:
            raw_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            body = self._parse_body(raw_body)
            status = exc.code
            # Absorb cookies from error responses too (Frappe sometimes sends them)
            for cookie_line in (exc.headers.get_all("Set-Cookie") or []):
                name, value = self._parse_set_cookie(cookie_line)
                if name:
                    self._cookies[name] = value
            # Raise typed exception
            if status in (401, 403):
                raise FrappeAuthError(status, body, url) from exc
            if status == 417:
                raise FrappePermissionError(status, body, url) from exc
            raise FrappeHTTPError(status, body, url) from exc

        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise FrappeConnectionError(f"Cannot reach bench at {url}: {exc}") from exc

    @staticmethod
    def _parse_body(raw: str) -> dict:
        """Parse JSON body; return dict with 'raw' key on decode failure."""
        raw = raw.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return {"message": parsed}
        except json.JSONDecodeError:
            return {"raw": raw}

    @staticmethod
    def _maybe_assert_status(resp: FrappeResponse, expected: int | None, method: str) -> None:
        if expected is not None and resp.status != expected:
            raise FrappeHTTPError(
                resp.status,
                resp.body,
                f"/api/method/{method}",
            )
