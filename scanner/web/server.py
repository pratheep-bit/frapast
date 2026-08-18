"""scanner/web/server.py — Frapast localhost web dashboard.

Serves a single-page HTML dashboard on http://localhost:7777.
Uses stdlib only: http.server + threading + json + sqlite3.
No Flask, no FastAPI — zero extra dependencies.

Features:
  GET  /                            → HTML dashboard (index.html)
  GET  /api/scans                   → List all past scans with stats
  GET  /api/findings                → Candidates for latest (or ?scan_id=) scan
  GET  /api/findings/<id>/proof     → Full proof detail for one finding
  GET  /api/stats                   → Proof summary stats for latest scan
  POST /api/prove                   → Trigger proof for selected / top-N findings
  POST /api/scan                    → Trigger a background scan
  GET  /api/stream                  → Server-Sent Events — live proof progress
  GET  /api/snippet                 → Source code excerpt around a line
  GET  /api/bench/check             → Test bench connectivity
  GET  /api/bench/config            → Read persisted bench config
  POST /api/bench/config            → Save bench config to SQLite
  GET  /api/report                  → Markdown compliance report
  GET  /api/export/json             → Download findings as JSON
  GET  /api/export/sarif            → Download findings as SARIF
  GET  /api/browse                  → Browse local filesystem

Usage:
    from scanner.web.server import start_server
    start_server(repo=Path("."), candidates=[])
"""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
import uuid
import webbrowser
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath

# Import DB layer — init() is called from start_server() and the /api/scan handler
from scanner.web import db as _db

PORT = 7777
_STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# In-memory runtime-only state (scan/proof progress that doesn't need to survive restart)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state: dict = {
    "running": False,         # proof worker active
    "scan_running": False,    # scan worker active
    "current_scan_id": None,  # scan_id of the most recently triggered scan
    "summary": {              # live tally during a proof run (refreshed from DB on done)
        "total": 0, "proven": 0, "refuted": 0, "skipped": 0, "errors": 0,
        "proven_findings": [],
    },
    # Bench config — loaded from DB on startup, kept in memory for fast reads
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
        try:
            parsed = urllib.parse.urlparse(origin)
            return parsed.hostname in ("localhost", "127.0.0.1", "::1")
        except Exception:
            return False

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_html()
        elif not path.startswith("/api/") and (_STATIC_DIR / path.lstrip("/")).is_file():
            self._serve_static_file(path.lstrip("/"))
        elif path == "/api/scans":
            self._serve_json({"scans": _db.list_scans()})
        elif path == "/api/findings":
            self._serve_findings(query)
        elif path.startswith("/api/findings/") and path.endswith("/proof"):
            finding_id = path[len("/api/findings/"):-len("/proof")]
            self._serve_proof_detail(finding_id)
        elif path == "/api/stats":
            self._serve_stats()
        elif path == "/api/snippet":
            self._serve_snippet(query)
        elif path == "/api/stream":
            self._serve_sse()
        elif path == "/api/bench/check":
            self._serve_bench_check()
        elif path == "/api/bench/config":
            with _lock:
                self._serve_json({
                    "bench_url":  _state.get("bench_url", ""),
                    "bench_user": _state.get("bench_user", "Administrator"),
                    "bench_site": _state.get("bench_site", ""),
                    "repo":       _db.get_latest_scan_id() or "",
                })
        elif path == "/api/report":
            self._serve_report()
        elif path == "/api/export/json":
            self._serve_export_json()
        elif path == "/api/export/sarif":
            self._serve_export_sarif()
        elif path == "/api/browse":
            self._serve_browse(query)
        else:
            self._404()

    def _serve_findings(self, query: dict) -> None:
        scan_id = query.get("scan_id", [None])[0]
        if not scan_id:
            with _lock:
                scan_id = _state.get("current_scan_id")
            if not scan_id:
                scan_id = _db.get_latest_scan_id()
        if not scan_id:
            self._serve_json({"candidates": [], "repo": "", "scan_id": None})
            return
        candidates = _db.get_findings(scan_id)
        # Inject id field if missing (finding_id is the canonical key in DB)
        for c in candidates:
            if not c.get("id"):
                c["id"] = c.get("finding_id", "")
        scans = _db.list_scans()
        repo = next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), "")
        self._serve_json({"candidates": candidates, "repo": repo, "scan_id": scan_id})

    def _serve_proof_detail(self, finding_id: str) -> None:
        finding = _db.get_finding_by_id(finding_id)
        if finding is None:
            self._serve_json({"error": f"Finding '{finding_id}' not found."}, status=404)
            return
        proof = _db.get_proof_result(finding_id)
        if proof is None:
            # No proof has been run yet — return a structured empty response
            status = finding.get("proof_status") or finding.get("status") or "candidate"
            proof = {
                "finding_id":       finding_id,
                "proof_status":     status,
                "proof_tier":       finding.get("proof_tier", 0),
                "exit_code":        None,
                "stdout":           "",
                "stderr":           "",
                "reproducer_path":  "",
                "reproducer_source": "",
                "error_message":    None,
                "duration_seconds": None,
                "proved_at":        None,
                "skip_reason":      "No proof has been run for this finding yet."
                                    if status == "candidate" else None,
            }
        else:
            proof = dict(proof)
            # Annotate skipped findings with a human-readable reason
            if proof.get("proof_status") == "skipped" or (
                    proof.get("exit_code") is None and not proof.get("stdout")):
                err = proof.get("error_message") or ""
                if "no bench configured" in err.lower():
                    proof["skip_reason"] = (
                        "Tier 2 HTTP proof skipped: no Frappe bench is configured. "
                        "Enter the bench URL in the Bench Configuration panel and re-run."
                    )
                elif "no reproducer" in err.lower():
                    proof["skip_reason"] = (
                        "No reproducer strategy is implemented for this rule yet "
                        "(proof_tier=0 / SKIP). The finding is a static candidate only."
                    )
                else:
                    proof["skip_reason"] = err or "Proof was skipped."
            else:
                proof["skip_reason"] = None
        self._serve_json(proof)

    def _serve_stats(self) -> None:
        with _lock:
            scan_id = _state.get("current_scan_id")
            scan_running = _state.get("scan_running", False)
            running = _state.get("running", False)
            live_summary = dict(_state.get("summary", {}))
        if not scan_id:
            scan_id = _db.get_latest_scan_id()
        if scan_id:
            db_stats = _db.get_scan_stats(scan_id)
        else:
            db_stats = {"total": 0, "proven": 0, "refuted": 0, "skipped": 0, "candidate": 0, "errors": 0}
        # During an active proof run, the in-memory live_summary is more current
        stats = db_stats if not running else {
            "total":     live_summary.get("total", db_stats["total"]),
            "proven":    live_summary.get("proven", db_stats["proven"]),
            "refuted":   live_summary.get("refuted", db_stats["refuted"]),
            "skipped":   live_summary.get("skipped", db_stats["skipped"]),
            "errors":    live_summary.get("errors", db_stats.get("errors", 0)),
            "candidate": db_stats.get("candidate", 0),
        }
        scans = _db.list_scans()
        repo = next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), "")
        self._serve_json({**stats, "repo": repo, "scan_running": scan_running, "scan_id": scan_id})

    # Hard cap on request bodies.
    MAX_BODY_BYTES = 5 * 1024 * 1024

    def _read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        length = max(0, length)
        if length > self.MAX_BODY_BYTES:
            raise ValueError(f"Request body too large ({length} bytes, max {self.MAX_BODY_BYTES}).")
        body = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(body)
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def do_POST(self):
        if not self._is_trusted_origin():
            self._serve_json({"error": "Cross-origin requests are not allowed."}, status=403)
            return

        path = self.path.split("?")[0]
        try:
            data = self._read_json_body()
        except ValueError as exc:
            self._serve_json({"error": str(exc)}, status=413)
            return

        if path == "/api/prove":
            self._handle_prove_request(data)

        elif path == "/api/bench/config":
            cfg = {}
            with _lock:
                if "bench_url" in data:
                    _state["bench_url"] = cfg["bench_url"] = str(data["bench_url"]).strip()
                if "bench_port" in data and data["bench_port"]:
                    try:
                        url = f"http://localhost:{int(data['bench_port'])}"
                        _state["bench_url"] = cfg["bench_url"] = url
                    except (TypeError, ValueError):
                        pass
                if "bench_user" in data:
                    _state["bench_user"] = cfg["bench_user"] = str(data["bench_user"]).strip()
                if "bench_password" in data:
                    _state["bench_password"] = cfg["bench_password"] = str(data["bench_password"]).strip()
                if "bench_site" in data:
                    _state["bench_site"] = cfg["bench_site"] = str(data["bench_site"]).strip()
            _db.save_bench_config(cfg)
            self._serve_json({"status": "saved"})

        elif path == "/api/scan":
            repo_path = str(data.get("repo_path", "")).strip()
            if not repo_path:
                self._serve_json({"error": "repo_path is required"}, status=400)
                return
            target = Path(repo_path).expanduser().resolve()

            home = Path.home().resolve()
            home_root = Path("/home").resolve() if Path("/home").exists() else home
            users_root = Path("/Users").resolve() if Path("/Users").exists() else home
            tmp_root = Path("/tmp").resolve()
            allowed_roots = [home, home_root, users_root, tmp_root]

            # Security containment: prevent scanning arbitrary system directories outside user workspace/tmp
            is_allowed = any(target == r or r in target.parents for r in allowed_roots)
            if not is_allowed:
                self._serve_json({"error": f"Path '{repo_path}' is outside allowed workspace roots"}, status=403)
                return

            if not target.exists():
                self._serve_json({"error": f"Path '{repo_path}' does not exist"}, status=400)
                return
            if not target.is_dir():
                self._serve_json({"error": f"Path '{repo_path}' is not a directory"}, status=400)
                return

            with _lock:
                if _state["scan_running"]:
                    self._serve_json({"status": "already_running"})
                    return
                if _state["running"]:
                    self._serve_json(
                        {"error": "A proof run is in progress. Wait for it to finish before scanning."},
                        status=409,
                    )
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
            self._serve_json({"status": "scanning", "repo": str(target)})

        elif path == "/api/fix/preview":
            self._handle_fix_preview(data)

        elif path == "/api/fix/apply":
            self._handle_fix_apply(data)

        else:
            self._404()

    # ------------------------------------------------------------------
    # Serving helpers
    # ------------------------------------------------------------------

    def _serve_html(self):
        html_path = _STATIC_DIR / "index.html"
        html = html_path.read_bytes() if html_path.is_file() else b"<h1>Dashboard not found</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
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
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(content)

    def _serve_json(self, data: dict | list, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin")
        if origin and self._is_trusted_origin():
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            actual_port = self.server.server_address[1] if hasattr(self, "server") and self.server else PORT
            self.send_header("Access-Control-Allow-Origin", f"http://localhost:{actual_port}")
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self):
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

    _report_cache: dict = {"time": 0.0, "text": ""}

    def _serve_report(self):
        try:
            scan_id = _db.get_latest_scan_id()
            candidates: list[dict] = _db.get_findings(scan_id) if scan_id else []
            repo = ""
            if scan_id:
                scans = _db.list_scans()
                repo = next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), "")

            if not repo and not candidates:
                self._serve_json({
                    "report": (
                        "# Security Track-Record Report\n\n"
                        "No target repository has been scanned yet.\n\n"
                        "Select a target directory in the dashboard and click **Scan** to generate a report."
                    )
                })
                return

            now = time.time()
            cache_time = _Handler._report_cache["time"]
            cache_text = _Handler._report_cache["text"]

            if now - cache_time > 10.0 or not cache_text:
                from scanner.reporting import render_track_record
                new_text = render_track_record("findings")

                if candidates and ("| candidate | 0 |" in new_text or "| proven | 0 |" in new_text):
                    stats = _db.get_scan_stats(scan_id)
                    repo_name = Path(repo).name if repo else "Scanned Repo"
                    new_text = (
                        f"# Security Track-Record Report for {repo_name}\n\n"
                        f"## Evidence Status\n\n"
                        f"Static candidates are internal-only Tier 0 records.\n\n"
                        f"| Status | Count |\n"
                        f"| --- | ---: |\n"
                        f"| candidate | {stats['candidate']} |\n"
                        f"| proven | {stats['proven']} |\n"
                        f"| false_positive | 0 |\n"
                        f"| patched | 0 |\n\n"
                        f"## Target Summary\n\n"
                        f"Scanned repository path: `{repo}`\n\n"
                        f"Total candidate findings detected: **{stats['total']}**\n"
                    )

                _Handler._report_cache["text"] = new_text
                _Handler._report_cache["time"] = now
                cache_text = new_text

            self._serve_json({"report": cache_text})
        except Exception as exc:
            self._serve_json({"error": str(exc)}, status=500)

    def _serve_export_json(self):
        scan_id = _db.get_latest_scan_id()
        data = _db.get_findings(scan_id) if scan_id else []
        body = json.dumps(data, default=str, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="frapast-findings.json"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_export_sarif(self):
        try:
            from scanner.reporting.sarif import export_sarif
            scan_id = _db.get_latest_scan_id()
            candidates = _db.get_findings(scan_id) if scan_id else []
            scans = _db.list_scans()
            repo = Path(next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), "."))
            sarif_str = export_sarif(candidates, repo_path=repo)
            body = sarif_str.encode("utf-8")
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

        scan_id = _db.get_latest_scan_id()
        scans = _db.list_scans()
        repo_root = Path(
            next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), "")
            if scan_id else ""
        )

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
            res_lines.append({"num": lnum, "code": code_str, "is_error": (lnum == target_line)})

        self._serve_json({
            "file": rel_file,
            "line": target_line,
            "start_line": start_line,
            "end_line": end_line,
            "lines": res_lines,
        })

    def _serve_browse(self, query: dict):
        try:
            raw_path = query.get("path", [""])[0].strip()
            if not raw_path:
                raw_path = "/Users"

            target = Path(raw_path).expanduser().resolve()
            home = Path.home().resolve()
            home_root = Path("/home").resolve() if Path("/home").exists() else home
            users_root = Path("/Users").resolve() if Path("/Users").exists() else home
            allowed_roots = [home, home_root, users_root]

            # Security containment: prevent browsing outside user home/workspace roots (e.g. /etc, /var)
            is_allowed = any(target == r or r in target.parents for r in allowed_roots)
            if not is_allowed or not target.exists() or not target.is_dir():
                target = home

            subdirs = []
            try:
                for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                    try:
                        if item.name.startswith((".", "__")) or item.name in ("node_modules", "venv", "env", "build", "dist"):
                            continue
                        if item.is_dir():
                            has_hooks = (item / "hooks.py").is_file() or (item / "pyproject.toml").is_file()
                            subdirs.append({"name": item.name, "path": str(item), "is_app": has_hooks})
                    except Exception:
                        continue
            except Exception:
                pass

            quick_locations = []
            for c in [home, home / "Documents", home / "Documents" / "erpnext", home / "frappe-bench" / "apps"]:
                try:
                    if c.exists():
                        quick_locations.append({
                            "name": f"~/{c.relative_to(home)}" if home in c.parents or c == home else str(c),
                            "path": str(c),
                        })
                except Exception:
                    pass

            parent_is_allowed = any(target.parent == r or r in target.parent.parents for r in allowed_roots)
            parent_path = str(target.parent) if (parent_is_allowed and target.parent != target) else None
            self._serve_json({
                "current_path": str(target),
                "parent_path": parent_path,
                "subdirs": subdirs,
                "quick_locations": quick_locations,
            })
        except Exception as exc:
            self._serve_json({"error": str(exc), "current_path": str(Path.home()), "subdirs": [], "quick_locations": []})

    # ------------------------------------------------------------------
    # Proof trigger (runs in background thread)
    # ------------------------------------------------------------------

    MAX_SELECTION_ITEMS = 5000

    def _handle_prove_request(self, data: dict) -> None:
        raw_ids = data.get("finding_ids")
        raw_locators = data.get("finding_locators")
        ids = [str(i) for i in raw_ids] if isinstance(raw_ids, list) else []
        locators = [loc for loc in raw_locators if isinstance(loc, dict)] if isinstance(raw_locators, list) else []

        selection_intent = "finding_ids" in data or "finding_locators" in data
        has_selection = bool(ids) or bool(locators)

        if selection_intent and not has_selection:
            self._serve_json({"error": "No valid findings were selected. Refresh and try again."}, status=400)
            return

        if has_selection:
            if len(ids) + len(locators) > self.MAX_SELECTION_ITEMS:
                self._serve_json({"error": f"Too many findings selected (max {self.MAX_SELECTION_ITEMS})."}, status=400)
                return
            spec = {"ids": ids, "locators": locators}
            requested = len(ids) + len(locators)
        else:
            raw_count = data.get("count", 10)
            if raw_count == "all":
                spec = "all"
                requested = "all"
            else:
                try:
                    n = int(raw_count)
                except (TypeError, ValueError):
                    self._serve_json({"error": "count must be a positive integer or 'all'"}, status=400)
                    return
                if n < 1:
                    self._serve_json({"error": "count must be a positive integer or 'all'"}, status=400)
                    return
                spec = n
                requested = n

        started, reason = self._trigger_proof(spec)
        if started:
            self._serve_json({"status": "started", "count": requested})
        elif reason == "scan_running":
            self._serve_json({"error": "A scan is in progress. Wait for it to finish before proving."}, status=409)
        else:
            self._serve_json({"status": "already_running"})

    def _trigger_proof(self, spec) -> tuple[bool, str | None]:
        with _lock:
            if _state["running"]:
                return False, "already_running"
            if _state["scan_running"]:
                return False, "scan_running"
            _state["running"] = True

        def _worker():
            try:
                _run_proof_in_background(spec)
            finally:
                with _lock:
                    _state["running"] = False
                _broadcast_sse({"type": "done", "summary": _state["summary"]})

        threading.Thread(target=_worker, daemon=True).start()
        return True, None

    def _handle_fix_preview(self, data: dict) -> None:
        from scanner.autofix import FixEngine

        scan_id = _state.get("current_scan_id") or _db.get_latest_scan_id()
        if not scan_id:
            self._serve_json({"error": "No active scan found"}, status=400)
            return

        scans = _db.list_scans()
        repo_str = next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), ".")
        repo = Path(repo_str)

        finding_id = str(data.get("finding_id", "")).strip()
        finding_data = data.get("finding_data")
        if not finding_data and finding_id:
            finding_data = _db.get_finding_by_id(finding_id)

        if not finding_data:
            self._serve_json({"has_fix": False, "error": "Finding not found"})
            return

        fix_engine = FixEngine(repo)
        patch = fix_engine.generate_patch(finding_data)
        if patch is None:
            self._serve_json({"has_fix": False, "diff": "", "description": "No automated patch available for this rule yet."})
            return

        self._serve_json({
            "has_fix": True,
            "diff": patch.diff,
            "description": patch.description,
            "start_line": patch.start_line,
            "end_line": patch.end_line,
        })

    def _handle_fix_apply(self, data: dict) -> None:
        from scanner.autofix import FixEngine

        scan_id = _state.get("current_scan_id") or _db.get_latest_scan_id()
        if not scan_id:
            self._serve_json({"error": "No active scan found"}, status=400)
            return

        scans = _db.list_scans()
        repo_str = next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), ".")
        repo = Path(repo_str)

        finding_id = str(data.get("finding_id", "")).strip()
        finding_data = data.get("finding_data")
        if not finding_data and finding_id:
            finding_data = _db.get_finding_by_id(finding_id)

        if not finding_data:
            self._serve_json({"success": False, "error": "Finding not found"}, status=400)
            return

        fix_engine = FixEngine(repo)
        patch = fix_engine.generate_patch(finding_data)
        if patch is None:
            self._serve_json({"success": False, "error": "No patch available for this finding"}, status=400)
            return

        ok = fix_engine.apply_patch(patch)
        if ok:
            self._serve_json({"success": True, "message": f"Successfully applied fix to {patch.file_path.name}"})
        else:
            self._serve_json({"success": False, "error": "Failed to write patch to disk"}, status=500)


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------


def _run_scan_in_background(repo: Path) -> None:
    """Run a full static scan in background, writing to DB and broadcasting SSE events."""
    scan_id = str(uuid.uuid4())
    try:
        from scanner.python import load as load_python
        from scanner.schema import load as load_schema
        from scanner.hooks import load as load_hooks
        from scanner.rules import execute_rules
        from dataclasses import asdict
        from scanner.severity import score_candidates
        from scanner.cli import _finding_id, _candidate_repo_id

        _broadcast_sse({"type": "scan_start", "repo": str(repo), "scan_id": scan_id})
        _db.create_scan(scan_id, str(repo.resolve()))

        with _lock:
            _state["current_scan_id"] = scan_id

        python_index = load_python(repo)
        schema_index = load_schema(repo)
        hooks_index = load_hooks(repo)

        raw_candidates = execute_rules(
            schema=schema_index,
            hooks=hooks_index,
            python=python_index,
        )

        guest_endpoints = {
            e.function for e in getattr(python_index, "whitelisted_endpoints", []) if getattr(e, "allow_guest", False)
        }
        scored = score_candidates(raw_candidates, guest_endpoints=guest_endpoints)

        candidates = []
        for c, score in scored:
            cd = asdict(c) if hasattr(c, "__dataclass_fields__") else dict(c)
            cd["severity"] = score.__dict__
            # Generate stable finding_id matching CLI convention
            crid = _candidate_repo_id(cd, "local")
            fid = _finding_id(cd, crid)
            cd["id"] = fid
            candidates.append(cd)

        # Persist to DB
        _db.upsert_findings(scan_id, candidates)
        _db.finish_scan(scan_id, status="done")

        with _lock:
            _state["summary"] = {
                "total": len(candidates),
                "proven": 0, "refuted": 0, "skipped": 0, "errors": 0,
                "proven_findings": [],
            }

        _broadcast_sse({
            "type": "scan_progress",
            "count": len(candidates),
            "repo": str(repo),
            "scan_id": scan_id,
        })

    except Exception as exc:
        _db.finish_scan(scan_id, status="error")
        _broadcast_sse({"type": "scan_error", "error": str(exc)})


# ---------------------------------------------------------------------------
# Background proof worker
# ---------------------------------------------------------------------------


def _candidate_locator(c: dict) -> tuple[str, str, str, str]:
    return (str(c.get("file", "")), str(c.get("line", "")), str(c.get("rule_id", "")), str(c.get("function", "")))


def _select_candidates(candidates: list[dict], spec) -> list[dict]:
    from scanner.ui.results import candidate_score

    if isinstance(spec, dict):
        wanted_ids = {str(i) for i in spec.get("ids", []) if i is not None and str(i) != ""}
        wanted_locators = {
            (str(loc.get("file", "")), str(loc.get("line", "")), str(loc.get("rule_id", "")), str(loc.get("function", "")))
            for loc in spec.get("locators", [])
        }
        selected: list[dict] = []
        seen_keys: set = set()
        for c in candidates:
            cid = c.get("id") or c.get("finding_id")
            cid_str = str(cid) if cid is not None and cid != "" else None
            matches = (cid_str is not None and cid_str in wanted_ids) or (_candidate_locator(c) in wanted_locators)
            if not matches:
                continue
            dedupe_key = cid_str if cid_str is not None else _candidate_locator(c)
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            selected.append(c)
        return selected

    sorted_cands = sorted(candidates, key=candidate_score, reverse=True)
    if isinstance(spec, int):
        return sorted_cands[:spec]
    return sorted_cands  # "all"


def _run_proof_in_background(spec) -> None:
    """Run proof pipeline, persisting results to DB and sending SSE events."""
    from scanner.proof.orchestrator import ProofOrchestrator
    from scanner.proof.models import ProofStatus
    from scanner.cli import _finding_id, _candidate_repo_id
    from dataclasses import replace as dc_replace

    with _lock:
        scan_id = _state.get("current_scan_id")
        bench_url = _state.get("bench_url", "")
        bench_user = _state.get("bench_user", "")
        bench_password = _state.get("bench_password", "")
        bench_site = _state.get("bench_site", "")

    if not scan_id:
        scan_id = _db.get_latest_scan_id()
    if not scan_id:
        _broadcast_sse({"type": "error", "message": "No scan results to prove — run a scan first."})
        return

    candidates = _db.get_findings(scan_id)
    scans = _db.list_scans()
    repo_str = next((s["repo_path"] for s in scans if s["scan_id"] == scan_id), ".")
    repo = Path(repo_str)

    slice_ = _select_candidates(candidates, spec)
    total = len(slice_)
    proven = refuted = skipped = errors = 0
    proven_findings: list[dict] = []

    if total == 0:
        with _lock:
            _state["summary"] = {
                "total": 0, "proven": 0, "refuted": 0, "skipped": 0, "errors": 0,
                "proven_findings": [],
            }
        _broadcast_sse({"type": "error", "message": "No matching candidates to prove."})
        return

    orchestrator = ProofOrchestrator(
        workspace_root=repo,
        bench_url=bench_url,
        bench_user=bench_user,
        bench_password=bench_password,
        bench_site_name=bench_site,
    )

    for idx, c in enumerate(slice_, 1):
        rule_id = c.get("rule_id", "")
        func = c.get("function", "")
        fid = c.get("id") or c.get("finding_id") or ""

        status_val = "error"
        try:
            res = orchestrator.prove_candidate(fid, candidate_data=c)
            loc_hash = str(c.get("code_location_hash", ""))
            if loc_hash:
                res = dc_replace(res, code_location_hash=loc_hash)

            status_val = getattr(res.status, "value", str(res.status))

            if res.status == ProofStatus.PASSED:
                proof_status = "proven"
                proof_tier = res.proof_tier
                status_val = "proven"
                proven += 1
                proven_findings.append({**c, "id": fid, "status": "proven", "proof_tier": proof_tier})
            elif res.status == ProofStatus.FAILED:
                proof_status = "refuted"
                status_val = "refuted"
                proof_tier = res.proof_tier
                refuted += 1
            elif res.status == ProofStatus.SKIPPED:
                proof_status = "skipped"
                status_val = "skipped"
                proof_tier = res.proof_tier
                skipped += 1
            else:
                proof_status = status_val
                proof_tier = res.proof_tier
                errors += 1

            # Read reproducer source from disk (if path available)
            reproducer_source = ""
            if res.reproducer_path:
                try:
                    reproducer_source = Path(res.reproducer_path).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

            # Persist proof result to DB
            _db.upsert_proof_result(
                fid,
                exit_code=res.exit_code,
                stdout=res.stdout or "",
                stderr=res.stderr or "",
                reproducer_path=res.reproducer_path or "",
                reproducer_source=reproducer_source,
                error_message=res.error_message,
                duration_seconds=res.duration_seconds,
                proof_status=proof_status,
                proof_tier=proof_tier,
            )
            # Update finding status in DB
            _db.update_finding_status(fid, status_val, proof_status, proof_tier)

        except Exception as e:
            proof_status = "error"
            proof_tier = 0
            errors += 1
            _db.upsert_proof_result(
                fid,
                exit_code=None,
                stdout="",
                stderr=str(e),
                reproducer_path="",
                reproducer_source="",
                error_message=str(e),
                duration_seconds=0.0,
                proof_status="error",
                proof_tier=0,
            )

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
            "tier": proof_tier if "proof_tier" in dir() else 0,
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
    """ThreadingHTTPServer that suppresses harmless client disconnects."""

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
    data_dir: Path | None = None,
) -> None:
    """Start local web server on PORT in background thread, then open browser."""
    # Determine persistent data directory.
    # IMPORTANT: use the user's home dir, NOT CWD.  CWD changes depending on
    # where you type `frapast dashboard` — using CWD meant scanning from two
    # different shell sessions produced two separate, invisible databases.
    # ~/.frapast is constant regardless of working directory.
    if data_dir is None:
        data_dir = Path.home() / ".frapast"
    _db.init(data_dir)

    # Load persisted bench config into memory (command-line args take precedence)
    persisted = _db.load_bench_config()
    with _lock:
        _state["bench_url"] = bench_url or persisted.get("bench_url", "")
        _state["bench_user"] = bench_user or persisted.get("bench_user", "Administrator")
        _state["bench_password"] = bench_password or persisted.get("bench_password", "admin")
        _state["bench_site"] = bench_site or persisted.get("bench_site", "")
        _state["running"] = False
        _state["scan_running"] = False

    # If the caller already ran a scan (CLI path), pre-load those results
    if candidates:
        scan_id = str(uuid.uuid4())
        _db.create_scan(scan_id, str(repo.resolve()) if str(repo) and str(repo) != "." else "")
        from scanner.cli import _finding_id, _candidate_repo_id
        for c in candidates:
            if not c.get("id"):
                crid = _candidate_repo_id(c, "local")
                c["id"] = _finding_id(c, crid)
        _db.upsert_findings(scan_id, candidates)
        _db.finish_scan(scan_id, status="done")
        with _lock:
            _state["current_scan_id"] = scan_id
            _state["summary"] = {
                "total": len(candidates), "proven": 0, "refuted": 0, "skipped": 0, "errors": 0,
                "proven_findings": [],
            }
    else:
        # Restore most recent completed scan from DB on launch
        latest = _db.get_latest_scan_id()
        with _lock:
            _state["current_scan_id"] = latest

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
        return

    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    url = f"http://localhost:{port}"
    import platform
    from scanner.ui.theme import console

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

    console.print(r"""[bold cyan]
 ______                        _____ _______ 
|  ____|                /\    / ____|__   __|
| |__ _ __ __ _ _ __   /  \  | (___    | |   
|  __| '__/ _` | '_ \ / /\ \  \___ \   | |   
| |  | | | (_| | |_) / ____ \ ____) |  | |   
|_|  |_|  \__,_| .__/_/    \_\_____/   |_|   
               | |                           
               |_|                           [/bold cyan]""")
    console.print()
    console.print("  [bold white]frapAST Security Engine[/bold white] — [dim]v1.2.0 (Public Beta)[/dim]")
    console.print("  [dim]Enterprise SAST & DAST Platform for Frappe / ERPNext[/dim]\n")
    console.print("[dim]┌──────────────────────────────────────────────────────────────────┐[/dim]")
    console.print(f"[dim]│[/dim]   [bold white]Local Dashboard[/bold white]   [bold green]● ONLINE[/bold green]   [underline blue]{url}[/underline blue]             [dim]│[/dim]")
    console.print(f"[dim]│[/dim]   [bold white]Network Host[/bold white]      [bold green]● READY[/bold green]    [underline blue]http://127.0.0.1:{port}[/underline blue]             [dim]│[/dim]")
    console.print("[dim]└──────────────────────────────────────────────────────────────────┘[/dim]\n")
    console.print(f"  [dim]Environment  :[/dim] [white]{os_info} | Python {py_ver}[/white]")
    console.print(f"  [dim]Persistence  :[/dim] [white]{data_dir / 'frapast_web.db'}[/white]")
    console.print(f"  [dim]Security     :[/dim] [white]Origin-gated localhost bridge[/white]\n")
    console.print("  [dim]Press [bold white]Ctrl+C[/bold white] to stop the dashboard server.[/dim]\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n  [dim]Gracefully shutting down dashboard server...[/dim]")
        server.shutdown()
        console.print("  [bold green]✓ Dashboard server stopped cleanly.[/bold green]\n")


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

    if p.is_absolute() or PureWindowsPath(rel_file).is_absolute() or rel_file.startswith(("/", "\\")):
        return None

    cand = _within_repo(repo_root / p)
    if cand:
        return cand

    parts = p.parts
    for i in range(1, len(parts)):
        sub = Path(*parts[i:])
        cand = _within_repo(repo_root / sub)
        if cand:
            return cand

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
        return None

    return None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="frapAST Web Dashboard")
    parser.add_argument("repo_path", nargs="?", default=".", help="Repository path to scan")
    parser.add_argument("--port", type=int, default=7777, help="Port to listen on (default 7777)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()
    start_server(Path(args.repo_path), [], port=args.port, open_browser=not args.no_browser)