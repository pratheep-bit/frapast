"""scanner/web/server.py — Frapast localhost web dashboard.

Serves a single-page HTML dashboard on http://localhost:7777.
Uses stdlib only: http.server + threading + json.
No Flask, no FastAPI — zero extra dependencies.

Features:
  GET  /            → HTML dashboard (index.html inlined)
  GET  /api/findings → All candidates as JSON
  GET  /api/stats    → Proof summary stats
  POST /api/prove    → Trigger proof for top N findings
  GET  /api/stream   → Server-Sent Events — live proof progress

Usage:
    from scanner.web.server import start_server
    start_server(repo=Path("."), candidates=[...])
"""
from __future__ import annotations

import json
import queue
import threading
import time
import webbrowser
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PORT = 7777
_STATIC_DIR = Path(__file__).parent / "static"

# Shared mutable state — guarded by _lock
_lock = threading.Lock()
_state: dict = {
    "repo": "",
    "candidates": [],
    "summary": {
        "total": 0, "proven": 0, "refuted": 0, "skipped": 0, "errors": 0,
        "proven_findings": [],
    },
    "running": False,
}

# SSE event queue — each item is a string (SSE line) or None (close)
_sse_queue: queue.Queue = queue.Queue()


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default logging
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_html()
        elif path == "/api/findings":
            self._serve_json({"candidates": _state["candidates"], "repo": _state["repo"]})
        elif path == "/api/stats":
            self._serve_json({**_state["summary"], "repo": _state["repo"]})
        elif path == "/api/snippet":
            self._serve_snippet(query)
        elif path == "/api/stream":
            self._serve_sse()
        else:
            self._404()

    def _serve_snippet(self, query: dict):
        rel_file = query.get("file", [""])[0]
        line_str = query.get("line", ["1"])[0]
        before_str = query.get("before", ["2"])[0]
        after_str = query.get("after", ["3"])[0]

        try:
            target_line = int(line_str)
            before = int(before_str)
            after = int(after_str)
        except ValueError:
            self._serve_json({"error": "Invalid line number", "lines": []})
            return

        repo_root = Path(_state.get("repo", ""))
        file_path = Path(rel_file)
        if not file_path.is_absolute():
            file_path = repo_root / file_path

        if not file_path.is_file():
            file_path = Path.cwd() / rel_file

        if not file_path.is_file():
            self._serve_json({"error": "File not found", "lines": []})
            return

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            all_lines = content.splitlines()
        except Exception as e:
            self._serve_json({"error": str(e), "lines": []})
            return

        start_line = max(1, target_line - before)
        end_line = min(len(all_lines), target_line + after)

        res_lines = []
        for lnum in range(start_line, end_line + 1):
            idx = lnum - 1
            code_str = all_lines[idx] if 0 <= idx < len(all_lines) else ""
            res_lines.append({
                "num": lnum,
                "code": code_str,
                "is_error": (lnum == target_line)
            })

        self._serve_json({
            "file": rel_file,
            "line": target_line,
            "start_line": start_line,
            "end_line": end_line,
            "lines": res_lines,
        })

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/prove":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            count = data.get("count", 10)
            self._trigger_proof(count)
            self._serve_json({"status": "started", "count": count})
        else:
            self._404()

    # ------------------------------------------------------------------
    # Serving helpers
    # ------------------------------------------------------------------

    def _serve_html(self):
        html_path = _STATIC_DIR / "index.html"
        if html_path.is_file():
            html = html_path.read_bytes()
        else:
            html = b"<h1>Dashboard not found</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _serve_json(self, data: dict):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            while True:
                try:
                    event = _sse_queue.get(timeout=30)
                except queue.Empty:
                    # Keep-alive ping
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                if event is None:
                    break
                self.wfile.write(f"data: {event}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _404(self):
        self.send_response(404)
        self.end_headers()

    # ------------------------------------------------------------------
    # Proof trigger (runs in background thread)
    # ------------------------------------------------------------------

    def _trigger_proof(self, count):
        with _lock:
            if _state["running"]:
                return  # already running
            _state["running"] = True

        def _worker():
            try:
                _run_proof_in_background(count)
            finally:
                with _lock:
                    _state["running"] = False
                _sse_queue.put(json.dumps({"type": "done", "summary": _state["summary"]}))

        threading.Thread(target=_worker, daemon=True).start()


# ---------------------------------------------------------------------------
# Background proof worker
# ---------------------------------------------------------------------------


def _run_proof_in_background(count: int | str) -> None:
    """Run proof pipeline, sending SSE events for each result."""
    from scanner.ui.results import candidate_score
    from scanner.ui.flow import run_proof_pipeline
    from scanner.proof.models import ProofStatus

    candidates = _state["candidates"]
    repo = Path(_state["repo"])

    sorted_cands = sorted(candidates, key=candidate_score, reverse=True)
    if isinstance(count, int):
        slice_ = sorted_cands[:count]
    else:
        slice_ = sorted_cands

    total = len(slice_)
    proven = refuted = skipped = errors = 0
    proven_findings: list[dict] = []

    from scanner.proof.orchestrator import ProofOrchestrator
    from scanner.proof.models import ProofStatus
    from scanner.cli import _finding_id, _candidate_repo_id
    from dataclasses import replace as dc_replace

    orchestrator = ProofOrchestrator(workspace_root=repo)

    for idx, c in enumerate(slice_, 1):
        rule_id = c.get("rule_id", "")
        func = c.get("function", "")
        loc_hash = str(c.get("code_location_hash", ""))
        crid = _candidate_repo_id(c, "local")
        fid = _finding_id(c, crid)
        c["id"] = fid

        res = orchestrator.prove_candidate(fid, candidate_data=c)
        if loc_hash:
            res = dc_replace(res, code_location_hash=loc_hash)

        status_val = getattr(res.status, "value", str(res.status))
        c["proof_status"] = status_val

        if res.status == ProofStatus.PASSED:
            c["proof_tier"] = res.proof_tier
            c["status"] = "proven"
            proven += 1
            proven_findings.append(c)
        elif res.status == ProofStatus.FAILED:
            refuted += 1
        elif res.status == ProofStatus.SKIPPED:
            skipped += 1
        else:
            errors += 1

        # Emit SSE event for this finding
        event = {
            "type": "progress",
            "index": idx,
            "total": total,
            "finding_id": fid,
            "rule_id": rule_id,
            "function": func,
            "file": c.get("file", ""),
            "line": c.get("line", ""),
            "status": status_val,
            "tier": c.get("proof_tier", 0),
        }
        _sse_queue.put(json.dumps(event))

    # Update global state
    with _lock:
        _state["summary"] = {
            "total": total,
            "proven": proven,
            "refuted": refuted,
            "skipped": skipped,
            "errors": errors,
            "proven_findings": proven_findings,
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def start_server(
    repo: Path,
    candidates: list[dict],
    *,
    bench_url: str = "",
    bench_user: str = "",
    bench_password: str = "",
    bench_site: str = "",
    port: int = PORT,
    open_browser: bool = True,
) -> None:
    """Start the web dashboard server (blocking until Ctrl-C)."""
    with _lock:
        _state["repo"] = str(repo)
        _state["candidates"] = candidates

    server = HTTPServer(("localhost", port), _Handler)
    url = f"http://localhost:{port}"

    from scanner.ui.theme import console
    console.print(f"\n[bold cyan]🌐 Web dashboard running at[/bold cyan] [underline]{url}[/underline]")
    console.print("[muted]Press Ctrl+C to stop the server.[/muted]\n")

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[muted]Web server stopped.[/muted]")
        server.server_close()
