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
import sys
import threading
import time
import webbrowser
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath

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
    "scan_running": False,
    "bench_url": "",
    "bench_user": "Administrator",
    "bench_password": "admin",
    "bench_site": "",
}

# Per-client SSE broadcast registry
_sse_clients: set[queue.Queue] = set()
_sse_clients_lock = threading.Lock()


def _broadcast_sse(event: dict) -> None:
    payload = json.dumps(event, default=str)
    with _sse_clients_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.discard(q)


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default logging
        pass

    def _is_trusted_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        return origin in (f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_html()
        elif not path.startswith("/api/") and (_STATIC_DIR / path.lstrip("/")).is_file():
            self._serve_static_file(path.lstrip("/"))
        elif path == "/api/findings":
            with _lock:
                snapshot_candidates = [dict(c) for c in _state["candidates"]]
                snapshot_repo = _state["repo"]
            self._serve_json({"candidates": snapshot_candidates, "repo": snapshot_repo})
        elif path == "/api/stats":
            with _lock:
                snapshot_summary = dict(_state["summary"])
                snapshot_repo = _state["repo"]
                snapshot_scan_running = _state["scan_running"]
            self._serve_json({**snapshot_summary, "repo": snapshot_repo, "scan_running": snapshot_scan_running})
        elif path == "/api/snippet":
            self._serve_snippet(query)
        elif path == "/api/stream":
            self._serve_sse()
        elif path == "/api/bench/check":
            self._serve_bench_check()
        elif path == "/api/bench/config":
            with _lock:
                self._serve_json({
                    "bench_url": _state.get("bench_url", ""),
                    "bench_user": _state.get("bench_user", "Administrator"),
                    "bench_site": _state.get("bench_site", ""),
                    "repo": _state.get("repo", ""),
                })
        elif path == "/api/report":
            self._serve_report()
        elif path == "/api/export/json":
            self._serve_export_json()
        elif path == "/api/export/sarif":
            self._serve_export_sarif()
        else:
            self._404()

    def _serve_snippet(self, query: dict):
        rel_file = query.get("file", [""])[0]
        line_str = query.get("line", ["1"])[0]
        before_str = query.get("before", ["2"])[0]
        after_str = query.get("after", ["3"])[0]

        try:
            target_line = int(line_str)
            before = max(0, min(int(before_str), 50))
            after = max(0, min(int(after_str), 50))
        except ValueError:
            self._serve_json({"error": "Invalid line number", "lines": []})
            return

        if target_line < 1:
            self._serve_json({"error": "Invalid line number", "lines": []})
            return

        repo_root = Path(_state.get("repo", ""))
        file_path = _resolve_file_path(repo_root, rel_file)

        if not file_path:
            self._serve_json({
                "error": f"Could not confidently resolve {rel_file} within the scanned repo",
                "lines": [],
            })
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
        if not self._is_trusted_origin():
            self._serve_json({"error": "Cross-origin requests are not allowed."}, status=403)
            return

        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if path == "/api/prove":
            raw_count = data.get("count", 10)
            if raw_count == "all":
                count: int | str = "all"
            else:
                try:
                    count = int(raw_count)
                except (TypeError, ValueError):
                    self._serve_json({"error": "count must be a positive integer or 'all'"}, status=400)
                    return
                if count < 1:
                    self._serve_json({"error": "count must be a positive integer or 'all'"}, status=400)
                    return

            started = self._trigger_proof(count)
            if started:
                self._serve_json({"status": "started", "count": count})
            else:
                self._serve_json({"status": "already_running"})

        elif path == "/api/bench/config":
            with _lock:
                if "bench_url" in data:
                    _state["bench_url"] = str(data["bench_url"]).strip()
                if "bench_port" in data and data["bench_port"]:
                    try:
                        _state["bench_url"] = f"http://localhost:{int(data['bench_port'])}"
                    except (TypeError, ValueError):
                        pass
                if "bench_user" in data:
                    _state["bench_user"] = str(data["bench_user"]).strip()
                if "bench_password" in data:
                    _state["bench_password"] = str(data["bench_password"]).strip()
                if "bench_site" in data:
                    _state["bench_site"] = str(data["bench_site"]).strip()
            self._serve_json({"status": "saved"})

        elif path == "/api/scan":
            repo_path = str(data.get("repo_path", "")).strip()
            if not repo_path:
                self._serve_json({"error": "repo_path is required"}, status=400)
                return
            target = Path(repo_path)
            if not target.exists():
                self._serve_json({"error": f"Path '{repo_path}' does not exist"}, status=400)
                return
            with _lock:
                if _state["scan_running"]:
                    self._serve_json({"status": "already_running"})
                    return
                _state["scan_running"] = True

            def _scan_worker():
                try:
                    _run_scan_in_background(target)
                finally:
                    with _lock:
                        _state["scan_running"] = False
                    _broadcast_sse({"type": "scan_done", "repo": str(target)})

            threading.Thread(target=_scan_worker, daemon=True).start()
            self._serve_json({"status": "started", "repo": str(target)})

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

    def _serve_static_file(self, rel_path: str):
        target_path = (_STATIC_DIR / rel_path).resolve()
        try:
            target_path.relative_to(_STATIC_DIR.resolve())
        except ValueError:
            self._404()
            return

        if not target_path.is_file():
            self._404()
            return

        ext = target_path.suffix.lower()
        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".json": "application/json",
            ".png": "image/png",
            ".ico": "image/x-icon",
        }
        content_type = mime_types.get(ext, "application/octet-stream")
        content = target_path.read_bytes()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_json(self, data: dict, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Restrict to same-origin rather than wildcard so that a malicious tab
        # open in the same browser cannot silently fetch and exfiltrate findings.
        self.send_header("Access-Control-Allow-Origin", f"http://localhost:{PORT}")
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self):
        # EventSource can't set custom request headers, but the browser still
        # sends a real Origin header on the underlying request — the same one
        # _is_trusted_origin() already checks for POST. A wildcard ACAO opts
        # every origin out of CORS, letting any tab open in the same browser
        # read live scan results via a localhost-CORS / DNS-rebinding attack.
        # Origin-gate it the same way POST already is.
        if not self._is_trusted_origin():
            self.send_response(403)
            self.end_headers()
            return
        origin = self.headers.get("Origin") or f"http://localhost:{PORT}"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()

        client_q: queue.Queue = queue.Queue(maxsize=200)
        with _sse_clients_lock:
            _sse_clients.add(client_q)

        try:
            while True:
                try:
                    payload = client_q.get(timeout=30)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                if payload is None:
                    break
                self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _sse_clients_lock:
                _sse_clients.discard(client_q)

    def _404(self):
        self.send_response(404)
        self.end_headers()

    def _serve_bench_check(self):
        from scanner.proof.bench_runner import diagnose_bench
        with _lock:
            bench_url = _state.get("bench_url", "")
            bench_site = _state.get("bench_site", "")
            bench_user = _state.get("bench_user", "Administrator")
            bench_password = _state.get("bench_password", "admin")
        try:
            report = diagnose_bench(
                base_url=bench_url,
                username=bench_user,
                password=bench_password,
                site_name=bench_site,
            )
            self._serve_json(report)
        except Exception as exc:
            self._serve_json({"error": str(exc)}, status=500)

    def _serve_report(self):
        try:
            from scanner.reporting import render_track_record
            text = render_track_record("findings")
            self._serve_json({"report": text})
        except Exception as exc:
            self._serve_json({"error": str(exc)}, status=500)

    def _serve_export_json(self):
        with _lock:
            data = [dict(c) for c in _state["candidates"]]
        body = json.dumps(data, default=str, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="frapast-findings.json"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_export_sarif(self):
        try:
            from scanner.reporting.sarif import candidates_to_sarif
            with _lock:
                candidates = [dict(c) for c in _state["candidates"]]
                repo = _state.get("repo", ".")
            sarif_doc = candidates_to_sarif(candidates, repo_root=repo)
            body = json.dumps(sarif_doc, default=str, indent=2).encode("utf-8")
        except Exception as exc:
            body = json.dumps({"error": str(exc)}, default=str).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="frapast-findings.sarif"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # Proof trigger (runs in background thread)
    # ------------------------------------------------------------------

    def _trigger_proof(self, count) -> bool:
        with _lock:
            if _state["running"]:
                return False
            _state["running"] = True

        def _worker():
            try:
                _run_proof_in_background(count)
            finally:
                with _lock:
                    _state["running"] = False
                _broadcast_sse({"type": "done", "summary": _state["summary"]})

        threading.Thread(target=_worker, daemon=True).start()
        return True


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------


def _run_scan_in_background(repo: Path) -> None:
    """Run a full static scan in background, updating _state and broadcasting SSE events."""
    try:
        from scanner.python import load as load_python
        from scanner.schema import load as load_schema
        from scanner.hooks import load as load_hooks
        from scanner.rules import execute_rules

        _broadcast_sse({"type": "scan_start", "repo": str(repo)})

        python_index = load_python(repo)
        schema_index = load_schema(repo)
        hooks_index = load_hooks(repo)

        candidates = execute_rules(
            python_index=python_index,
            schema_index=schema_index,
            hooks_index=hooks_index,
        )

        with _lock:
            _state["repo"] = str(repo.resolve())
            _state["candidates"] = candidates
            _state["summary"] = {
                "total": len(candidates),
                "proven": 0,
                "refuted": 0,
                "skipped": 0,
                "errors": 0,
                "proven_findings": [],
            }
            _state["running"] = False

        _broadcast_sse({
            "type": "scan_progress",
            "count": len(candidates),
            "repo": str(repo),
        })

    except Exception as exc:
        _broadcast_sse({"type": "scan_error", "error": str(exc)})


# ---------------------------------------------------------------------------
# Background proof worker
# ---------------------------------------------------------------------------


def _run_proof_in_background(count: int | str) -> None:
    """Run proof pipeline, sending SSE events for each result."""
    from scanner.ui.results import candidate_score
    from scanner.proof.orchestrator import ProofOrchestrator
    from scanner.proof.models import ProofStatus
    from scanner.cli import _finding_id, _candidate_repo_id
    from dataclasses import replace as dc_replace

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

    orchestrator = ProofOrchestrator(
        workspace_root=repo,
        bench_url=_state.get("bench_url", ""),
        bench_user=_state.get("bench_user", ""),
        bench_password=_state.get("bench_password", ""),
        bench_site_name=_state.get("bench_site", ""),
    )

    for idx, c in enumerate(slice_, 1):
        rule_id = c.get("rule_id", "")
        func = c.get("function", "")
        loc_hash = str(c.get("code_location_hash", ""))
        crid = _candidate_repo_id(c, "local")
        fid = _finding_id(c, crid)

        status_val = "error"
        updates: dict = {"id": fid}
        try:
            res = orchestrator.prove_candidate(fid, candidate_data={**c, "id": fid})
            if loc_hash:
                res = dc_replace(res, code_location_hash=loc_hash)

            status_val = getattr(res.status, "value", str(res.status))
            updates["proof_status"] = status_val

            if res.status == ProofStatus.PASSED:
                updates.update(proof_tier=res.proof_tier, status="proven", proof_status="proven")
                proven += 1
            elif res.status == ProofStatus.FAILED:
                updates.update(status="refuted", proof_status="refuted")
                refuted += 1
            elif res.status == ProofStatus.SKIPPED:
                updates.update(status="skipped", proof_status="skipped")
                skipped += 1
            else:
                updates["status"] = status_val
                errors += 1
        except Exception as e:
            updates.update(status="error", proof_status="error", proof_error=str(e))
            errors += 1

        # Apply every field for this candidate as one atomic step under the
        # same lock the reader uses, so /api/findings never sees this dict
        # mid-update or racing a key insertion.
        with _lock:
            c.update(updates)
            if updates.get("status") == "proven":
                proven_findings.append(c)

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
        with _lock:
            _state["summary"] = {
                "total": total,
                "proven": proven,
                "refuted": refuted,
                "skipped": skipped,
                "errors": errors,
                "proven_findings": proven_findings,
            }
        _broadcast_sse(event)

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


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """Subclass of ThreadingHTTPServer that suppresses harmless client disconnects."""

    def handle_error(self, request: object, client_address: object) -> None:
        _, exc, _ = sys.exc_info()
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


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
    """Start local web server on PORT in background thread, then open browser."""
    with _lock:
        _state["repo"] = str(repo.resolve())
        _state["candidates"] = candidates
        _state["bench_url"] = bench_url
        _state["bench_user"] = bench_user
        _state["bench_password"] = bench_password
        _state["bench_site"] = bench_site
        _state["summary"] = {
            "total": len(candidates), "proven": 0, "refuted": 0, "skipped": 0, "errors": 0,
            "proven_findings": [],
        }
        _state["running"] = False

    server = None
    for try_port in range(port, port + 10):
        try:
            server = QuietThreadingHTTPServer(("127.0.0.1", try_port), _Handler)
            port = try_port
            break
        except OSError:
            continue

    if server is None:
        print(f"\n❌ Could not start dashboard on ports {port}-{port+9}: All addresses in use.")
        print("   Stop existing instances or free the port.\n")
        return

    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://localhost:{port}"
    print(f"\n🌐 Web dashboard running at {url}")
    print("Press Ctrl+C to stop the server.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            # Silently ignore failures — headless / SSH / container environments
            # have no display and webbrowser.open raises OSError or spawns a
            # subprocess that immediately fails. The server is still running;
            # the user can navigate to the URL manually.
            pass

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping web dashboard server...")
        server.shutdown()


def _resolve_file_path(repo_root: Path, rel_file: str) -> Path | None:
    if not rel_file:
        return None

    try:
        repo_root_resolved = repo_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return None

    def _within_repo(candidate: Path) -> Path | None:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if resolved == repo_root_resolved or repo_root_resolved in resolved.parents:
            return resolved
        return None

    p = Path(rel_file)

    # Reject absolute input outright — a finding's "file" should always be
    # repo-relative. Absolute paths are never trusted from the client.
    # Check both POSIX and Windows absolute formats regardless of runner OS.
    if p.is_absolute() or PureWindowsPath(rel_file).is_absolute() or rel_file.startswith(("/", "\\")):
        return None

    # 1. Direct join with repo_root
    cand = _within_repo(repo_root / p)
    if cand:
        return cand

    # 2. Strip leading path components (handles findings recorded with
    #    a differing prefix, e.g. "app/scanner/x.py" vs "scanner/x.py")
    parts = p.parts
    for i in range(1, len(parts)):
        sub = Path(*parts[i:])
        cand = _within_repo(repo_root / sub)
        if cand:
            return cand

    # 3. Search by filename within repo_root only — require the match to
    #    be unambiguous. If multiple files share the basename, refuse to
    #    guess; the caller must be told rather than silently shown the
    #    wrong file.
    fname = p.name
    if fname:
        candidates = [
            m for m in repo_root_resolved.rglob(fname)
            if m.is_file() and _within_repo(m)
        ]
        exact_suffix = [m for m in candidates if str(m).endswith(rel_file)]
        if len(exact_suffix) == 1:
            return exact_suffix[0]
        if len(exact_suffix) == 0 and len(candidates) == 1:
            return candidates[0]
        # 0 matches, or ambiguous (>1) matches — both are "can't resolve
        # confidently" cases, not "pick one and hope."
        return None

    return None
