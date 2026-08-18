"""scanner/web/db.py — SQLite persistence layer for the frapAST web dashboard.

Schema
------
scans          — one row per scan session
findings       — one row per candidate (FK → scans)
proof_results  — one row per completed proof attempt (FK → findings)
bench_config   — single key/value store for bench connection settings

All writes are wrapped in transactions.  Reads return plain dicts so the
rest of the server code stays JSON-serialisable without extra models.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_db_path: Path | None = None
_local = threading.local()     # one connection per thread (SQLite requirement)
_init_lock = threading.Lock()
_initialized = False


def init(data_dir: Path) -> None:
    """Call once on startup to set the DB path and create tables."""
    global _db_path, _initialized
    with _init_lock:
        if _initialized:
            return
        data_dir.mkdir(parents=True, exist_ok=True)
        _db_path = data_dir / "frapast_web.db"
        _apply_schema(_connect())
        _initialized = True


def _connect() -> sqlite3.Connection:
    """Return a thread-local connection, creating one if needed."""
    if _db_path is None:
        raise RuntimeError("db.init() has not been called")
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(str(_db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def _apply_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id     TEXT PRIMARY KEY,
            repo_path   TEXT NOT NULL,
            started_at  REAL NOT NULL,
            finished_at REAL,
            status      TEXT NOT NULL DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id          TEXT PRIMARY KEY,
            scan_id             TEXT NOT NULL REFERENCES scans(scan_id),
            rule_id             TEXT NOT NULL,
            rule_version        TEXT,
            taxonomy_id         TEXT,
            file                TEXT,
            line                INTEGER,
            function            TEXT,
            code_location_hash  TEXT,
            evidence            TEXT,
            description         TEXT,
            remediation         TEXT,
            proof_recipe        TEXT,
            proof_tier          INTEGER,
            status              TEXT,
            proof_status        TEXT,
            fix_confidence      TEXT,
            target_arg          TEXT,
            severity_score      REAL,
            severity_json       TEXT,
            created_at          REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

        CREATE TABLE IF NOT EXISTS proof_results (
            finding_id        TEXT PRIMARY KEY REFERENCES findings(finding_id),
            exit_code         INTEGER,
            stdout            TEXT,
            stderr            TEXT,
            reproducer_path   TEXT,
            reproducer_source TEXT,
            error_message     TEXT,
            duration_seconds  REAL,
            proof_status      TEXT,
            proof_tier        INTEGER,
            proved_at         REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bench_config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Scan operations
# ---------------------------------------------------------------------------

def create_scan(scan_id: str, repo_path: str) -> None:
    conn = _connect()
    conn.execute(
        "INSERT OR REPLACE INTO scans (scan_id, repo_path, started_at, status)"
        " VALUES (?, ?, ?, 'running')",
        (scan_id, repo_path, time.time()),
    )
    conn.commit()


def finish_scan(scan_id: str, status: str = "done") -> None:
    conn = _connect()
    conn.execute(
        "UPDATE scans SET finished_at=?, status=? WHERE scan_id=?",
        (time.time(), status, scan_id),
    )
    conn.commit()


def list_scans() -> list[dict]:
    conn = _connect()
    rows = conn.execute("""
        SELECT s.scan_id, s.repo_path, s.started_at, s.finished_at, s.status,
               COUNT(f.finding_id)                              AS finding_count,
               SUM(f.status = 'proven')                        AS proven_count,
               SUM(f.status = 'refuted')                       AS refuted_count,
               SUM(f.status = 'skipped')                       AS skipped_count,
               SUM(f.status = 'candidate')                     AS candidate_count
        FROM scans s
        LEFT JOIN findings f ON f.scan_id = s.scan_id
        GROUP BY s.scan_id
        ORDER BY s.started_at DESC
    """).fetchall()
    return [dict(r) for r in rows]


def get_latest_scan_id() -> str | None:
    conn = _connect()
    row = conn.execute(
        "SELECT scan_id FROM scans WHERE status='done' ORDER BY finished_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        # fall back to any scan including running ones
        row = conn.execute(
            "SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    return row["scan_id"] if row else None


# ---------------------------------------------------------------------------
# Finding operations
# ---------------------------------------------------------------------------

def upsert_findings(scan_id: str, candidates: list[dict]) -> None:
    """Bulk-insert/replace all findings for a scan."""
    conn = _connect()
    now = time.time()
    conn.executemany(
        """INSERT OR REPLACE INTO findings
           (finding_id, scan_id, rule_id, rule_version, taxonomy_id,
            file, line, function, code_location_hash,
            evidence, description, remediation, proof_recipe,
            proof_tier, status, proof_status, fix_confidence, target_arg,
            severity_score, severity_json, created_at)
           VALUES
           (:finding_id, :scan_id, :rule_id, :rule_version, :taxonomy_id,
            :file, :line, :function, :code_location_hash,
            :evidence, :description, :remediation, :proof_recipe,
            :proof_tier, :status, :proof_status, :fix_confidence, :target_arg,
            :severity_score, :severity_json, :created_at)""",
        [_flatten_finding(c, scan_id, now) for c in candidates],
    )
    conn.commit()


def _flatten_finding(c: dict, scan_id: str, now: float) -> dict:
    sev = c.get("severity") or {}
    return {
        "finding_id":         c.get("id") or "",
        "scan_id":            scan_id,
        "rule_id":            c.get("rule_id") or "",
        "rule_version":       c.get("rule_version"),
        "taxonomy_id":        c.get("taxonomy_id"),
        "file":               c.get("file") or "",
        "line":               c.get("line"),
        "function":           c.get("function") or "",
        "code_location_hash": c.get("code_location_hash"),
        "evidence":           c.get("evidence"),
        "description":        c.get("description"),
        "remediation":        c.get("remediation"),
        "proof_recipe":       c.get("proof_recipe"),
        "proof_tier":         c.get("proof_tier"),
        "status":             c.get("status") or "candidate",
        "proof_status":       c.get("proof_status"),
        "fix_confidence":     c.get("fix_confidence"),
        "target_arg":         c.get("target_arg"),
        "severity_score":     sev.get("score") if isinstance(sev, dict) else None,
        "severity_json":      json.dumps(sev) if sev else None,
        "created_at":         now,
    }


def get_findings(scan_id: str) -> list[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY rowid ASC",
        (scan_id,),
    ).fetchall()
    return [_inflate_finding(dict(r)) for r in rows]


def _inflate_finding(r: dict) -> dict:
    sev = {}
    if r.get("severity_json"):
        try:
            sev = json.loads(r["severity_json"])
        except Exception:
            pass
    r.pop("severity_json", None)
    r["severity"] = sev
    return r


def update_finding_status(finding_id: str, status: str, proof_status: str, proof_tier: int) -> None:
    conn = _connect()
    conn.execute(
        "UPDATE findings SET status=?, proof_status=?, proof_tier=? WHERE finding_id=?",
        (status, proof_status, proof_tier, finding_id),
    )
    conn.commit()


def get_finding_by_id(finding_id: str) -> dict | None:
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM findings WHERE finding_id=?", (finding_id,)
    ).fetchone()
    if row is None:
        return None
    return _inflate_finding(dict(row))


# ---------------------------------------------------------------------------
# Proof result operations
# ---------------------------------------------------------------------------

def upsert_proof_result(
    finding_id: str,
    *,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    reproducer_path: str,
    reproducer_source: str,
    error_message: str | None,
    duration_seconds: float,
    proof_status: str,
    proof_tier: int,
) -> None:
    conn = _connect()
    conn.execute(
        """INSERT OR REPLACE INTO proof_results
           (finding_id, exit_code, stdout, stderr, reproducer_path, reproducer_source,
            error_message, duration_seconds, proof_status, proof_tier, proved_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (finding_id, exit_code, stdout, stderr, reproducer_path, reproducer_source,
         error_message, duration_seconds, proof_status, proof_tier, time.time()),
    )
    conn.commit()


def get_proof_result(finding_id: str) -> dict | None:
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM proof_results WHERE finding_id=?", (finding_id,)
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Bench config persistence
# ---------------------------------------------------------------------------

_BENCH_KEYS = ("bench_url", "bench_user", "bench_password", "bench_site")


def save_bench_config(cfg: dict) -> None:
    conn = _connect()
    for k in _BENCH_KEYS:
        if k in cfg:
            conn.execute(
                "INSERT OR REPLACE INTO bench_config (key, value) VALUES (?, ?)",
                (k, str(cfg[k])),
            )
    conn.commit()


def load_bench_config() -> dict:
    conn = _connect()
    rows = conn.execute(
        "SELECT key, value FROM bench_config WHERE key IN (?, ?, ?, ?)",
        _BENCH_KEYS,
    ).fetchall()
    result = {k: "" for k in _BENCH_KEYS}
    for row in rows:
        result[row["key"]] = row["value"]
    return result


# ---------------------------------------------------------------------------
# Stats helper
# ---------------------------------------------------------------------------

def get_scan_stats(scan_id: str) -> dict:
    conn = _connect()
    row = conn.execute("""
        SELECT
            COUNT(*)                    AS total,
            SUM(status='proven')        AS proven,
            SUM(status='refuted')       AS refuted,
            SUM(status='skipped')       AS skipped,
            SUM(status='candidate')     AS candidate,
            SUM(status='error')         AS errors
        FROM findings WHERE scan_id=?
    """, (scan_id,)).fetchone()
    return {
        "total":     row["total"]     or 0,
        "proven":    row["proven"]    or 0,
        "refuted":   row["refuted"]   or 0,
        "skipped":   row["skipped"]   or 0,
        "candidate": row["candidate"] or 0,
        "errors":    row["errors"]    or 0,
    }
