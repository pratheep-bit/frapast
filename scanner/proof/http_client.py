from __future__ import annotations

import urllib.request
import urllib.parse
import json


class FrappeHTTPClient:
	"""Lightweight HTTP RPC client for testing whitelisted Frappe endpoints."""

	def __init__(self, base_url: str = "http://localhost:8000") -> None:
		self.base_url = base_url.rstrip("/")
		self.cookie_jar: dict[str, str] = {}

	def post(self, method: str, data: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
		url = f"{self.base_url}/api/method/{method}"
		encoded_data = urllib.parse.urlencode(data or {}).encode("utf-8")
		req_headers = {"Content-Type": "application/x-www-form-urlencoded"}
		if headers:
			req_headers.update(headers)

		if self.cookie_jar:
			cookie_header = "; ".join(f"{k}={v}" for k, v in self.cookie_jar.items())
			req_headers["Cookie"] = cookie_header

		req = urllib.request.Request(url, data=encoded_data, headers=req_headers, method="POST")
		try:
			with urllib.request.urlopen(req, timeout=10) as resp:
				status = resp.status
				body = resp.read().decode("utf-8")
				headers_out = resp.info()
				if "Set-Cookie" in headers_out:
					for cookie in headers_out.get_all("Set-Cookie"):
						parts = cookie.split(";")[0].split("=", 1)
						if len(parts) == 2:
							self.cookie_jar[parts[0].strip()] = parts[1].strip()
				try:
					json_resp = json.loads(body)
				except Exception:
					json_resp = {"raw": body}
				return status, json_resp
		except Exception as exc:
			return 500, {"error": str(exc)}
