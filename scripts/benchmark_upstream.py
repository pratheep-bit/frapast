#!/usr/bin/env python3
"""scripts/benchmark_upstream.py — Phase 4 Upstream Monorepo Benchmark

Executes frapAST against full local checkouts of frappe/frappe and frappe/erpnext.
Measures:
  1. Execution time across indexing, call-graph construction, rule execution, and scoring.
  2. Memory footprint (peak RSS and delta memory).
  3. Findings breakdown by rule family, severity, and phase.
  4. False-positive / True-positive rate characterization on large production codebases.
"""

from __future__ import annotations

import gc
import json
import os
import resource
import sys
import time
import tracemalloc
from collections import Counter, defaultdict
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.callgraph import build_call_graph
from scanner.hooks import load as load_hooks
from scanner.python import load as load_python
from scanner.python.engine import discover_python_files
from scanner.rules.engine import (
    ALL_RULES,
    Candidate,
    _RuleCache,
    _deduplicate,
    _filter_suppressed_candidates,
    _rule_cache_var,
)
from scanner.schema import load as load_schema
from scanner.severity import score_candidates


def get_current_rss_mb() -> float:
    # On macOS, ru_maxrss is in bytes; on Linux, in kilobytes
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return raw / (1024 * 1024)
    return raw / 1024


def count_loc_and_files(repo_path: Path, files: list) -> tuple[int, int]:
    total_loc = 0
    for f in files:
        p = f.path if hasattr(f, "path") else Path(f)
        try:
            with open(p, "rb") as fp:
                total_loc += sum(1 for _ in fp)
        except Exception:
            pass
    return len(files), total_loc


def benchmark_repository(repo_name: str, repo_path: Path) -> dict:
    print(f"\n{'='*70}\nBenchmarking Repository: {repo_name} ({repo_path})\n{'='*70}")
    gc.collect()
    start_rss = get_current_rss_mb()
    t_global_start = time.perf_counter()

    # 1. File Discovery
    t0 = time.perf_counter()
    python_files = discover_python_files(repo_path)
    t_discovery = time.perf_counter() - t0
    num_files, total_loc = count_loc_and_files(repo_path, python_files)
    print(f"[{repo_name}] Discovered {num_files:,} Python files ({total_loc:,} LOC) in {t_discovery:.3f}s")

    # 2. Schema Indexing
    t0 = time.perf_counter()
    schema = load_schema(repo_path)
    t_schema = time.perf_counter() - t0
    rss_after_schema = get_current_rss_mb()
    doctype_count = len(getattr(schema, "doctypes", {}))
    print(f"[{repo_name}] Schema index loaded: {doctype_count} DocTypes in {t_schema:.3f}s (RSS: {rss_after_schema:.1f} MB)")

    # 3. Hooks Indexing
    t0 = time.perf_counter()
    hooks = load_hooks(repo_path)
    t_hooks = time.perf_counter() - t0
    rss_after_hooks = get_current_rss_mb()
    hook_count = len(getattr(hooks, "fixtures", []))
    print(f"[{repo_name}] Hook index loaded in {t_hooks:.3f}s (RSS: {rss_after_hooks:.1f} MB)")

    # 4. Python AST Indexing
    t0 = time.perf_counter()
    python = load_python(repo_path, progress_callback=None, files=python_files)
    t_python = time.perf_counter() - t0
    rss_after_python = get_current_rss_mb()
    endpoint_count = len(getattr(python, "whitelisted_endpoints", []))
    calls_count = len(getattr(python, "calls", []))
    mutations_count = len(getattr(python, "mutations", []))
    print(f"[{repo_name}] Python AST indexed in {t_python:.3f}s: {endpoint_count} whitelisted endpoints, {calls_count:,} calls, {mutations_count:,} mutations (RSS: {rss_after_python:.1f} MB)")

    # 5. Call Graph Construction
    t0 = time.perf_counter()
    call_graph = build_call_graph(python)
    t_cg = time.perf_counter() - t0
    rss_after_cg = get_current_rss_mb()
    edge_count = len(getattr(call_graph, "edges", []))
    print(f"[{repo_name}] Call Graph constructed in {t_cg:.3f}s: {edge_count:,} edges (RSS: {rss_after_cg:.1f} MB)")

    # 6. Rule Evaluation (Measuring per-rule execution time)
    token = _rule_cache_var.set(_RuleCache())
    raw_candidates: list[Candidate] = []
    rule_timing: dict[str, dict] = {}

    t_rules_start = time.perf_counter()
    for rule in ALL_RULES:
        r_name = getattr(rule, "__name__", repr(rule))
        t_r0 = time.perf_counter()
        try:
            findings = rule(schema, hooks, python, call_graph)
        except Exception as exc:
            findings = []
            print(f"  Warning: rule {r_name} failed: {exc}")
        t_r_elapsed = time.perf_counter() - t_r0
        raw_candidates.extend(findings)
        rule_timing[r_name] = {
            "elapsed_ms": round(t_r_elapsed * 1000, 2),
            "findings_count": len(findings),
        }
    _rule_cache_var.reset(token)
    t_rules = time.perf_counter() - t_rules_start

    # Suppression & Deduplication
    t0 = time.perf_counter()
    filtered_candidates = _filter_suppressed_candidates(raw_candidates, python)
    candidates = _deduplicate(filtered_candidates)
    t_suppression = time.perf_counter() - t0

    # 7. Severity Scoring
    t0 = time.perf_counter()
    guest_endpoints = {e.function for e in python.whitelisted_endpoints if e.allow_guest}
    scored = score_candidates(candidates, guest_endpoints=guest_endpoints)
    score_by_key = {
        (c.rule_id, c.file, c.line, c.code_location_hash): score for c, score in scored
    }
    t_scoring = time.perf_counter() - t0

    t_global_total = time.perf_counter() - t_global_start
    peak_rss = get_current_rss_mb()

    # Finding Categorization
    by_rule = Counter(c.rule_id for c in candidates)
    by_severity = Counter()
    by_family = Counter()

    phase1_rule_ids = {
        "FR-SSTI-001", "FR-ARCH-001", "FR-UPLOAD-001", "FR-REDIR-001",
        "FR-SECRET-001", "FR-MASSASSIGN-001"
    }
    phase2_rule_ids = {"FR-XSS-001", "FR-XSS-002", "FR-XSS-003"}
    
    phase1_findings = []
    phase2_findings = []
    test_file_findings = 0
    app_file_findings = 0

    for c in candidates:
        key = (c.rule_id, c.file, c.line, c.code_location_hash)
        score = score_by_key.get(key)
        sev_label = getattr(score, "severity_label", "Unknown") if score else "Unknown"
        by_severity[sev_label] += 1
        
        family = c.rule_id.split("-")[1] if "-" in c.rule_id else "OTHER"
        by_family[family] += 1

        is_test = any(part in c.file.lower() for part in ["/test", "tests/", "fixture"])
        if is_test:
            test_file_findings += 1
        else:
            app_file_findings += 1

        if c.rule_id in phase1_rule_ids:
            phase1_findings.append({
                "rule_id": c.rule_id,
                "file": c.file,
                "line": c.line,
                "evidence": c.evidence,
                "severity": sev_label,
            })
        elif c.rule_id in phase2_rule_ids:
            phase2_findings.append({
                "rule_id": c.rule_id,
                "file": c.file,
                "line": c.line,
                "evidence": c.evidence,
                "severity": sev_label,
            })

    throughput_fps = num_files / t_global_total if t_global_total > 0 else 0
    throughput_loc = total_loc / t_global_total if t_global_total > 0 else 0

    print(f"\n[{repo_name}] RESULTS SUMMARY:")
    print(f"  Total Wall Time     : {t_global_total:.2f}s")
    print(f"  Throughput          : {throughput_fps:.1f} files/sec ({throughput_loc:,.0f} LOC/sec)")
    print(f"  Peak RSS Memory     : {peak_rss:.1f} MB (Delta: {peak_rss - start_rss:.1f} MB)")
    print(f"  Total Candidates    : {len(candidates)} (Production: {app_file_findings}, Test code: {test_file_findings})")
    print(f"  Severity Breakdown  : {dict(by_severity)}")
    print(f"  Family Breakdown    : {dict(by_family.most_common(8))}")
    print(f"  Phase 1 Findings    : {len(phase1_findings)}")
    print(f"  Phase 2 Findings    : {len(phase2_findings)}")

    return {
        "repo_name": repo_name,
        "repo_path": str(repo_path),
        "num_files": num_files,
        "total_loc": total_loc,
        "timing": {
            "discovery_s": round(t_discovery, 3),
            "schema_s": round(t_schema, 3),
            "hooks_s": round(t_hooks, 3),
            "python_ast_s": round(t_python, 3),
            "call_graph_s": round(t_cg, 3),
            "rules_evaluation_s": round(t_rules, 3),
            "suppression_s": round(t_suppression, 3),
            "scoring_s": round(t_scoring, 3),
            "total_wall_s": round(t_global_total, 3),
        },
        "throughput": {
            "files_per_second": round(throughput_fps, 1),
            "loc_per_second": round(throughput_loc, 1),
        },
        "memory": {
            "start_rss_mb": round(start_rss, 1),
            "peak_rss_mb": round(peak_rss, 1),
            "delta_rss_mb": round(peak_rss - start_rss, 1),
        },
        "counts": {
            "total_candidates": len(candidates),
            "app_code_candidates": app_file_findings,
            "test_code_candidates": test_file_findings,
            "by_severity": dict(by_severity),
            "by_family": dict(by_family),
            "by_rule": dict(by_rule.most_common()),
            "phase1_findings_count": len(phase1_findings),
            "phase2_findings_count": len(phase2_findings),
        },
        "phase1_findings": phase1_findings,
        "phase2_findings": phase2_findings,
        "rule_timing": rule_timing,
    }


def main():
    repos = [
        ("frappe/frappe", Path("/Users/pratheepselvam/Documents/frappe")),
        ("frappe/erpnext", Path("/Users/pratheepselvam/Documents/erpnext")),
    ]

    results = []
    total_files = 0
    total_loc = 0
    total_time = 0.0

    for name, path in repos:
        if not path.exists():
            print(f"Error: Path {path} does not exist.")
            continue
        res = benchmark_repository(name, path)
        results.append(res)
        total_files += res["num_files"]
        total_loc += res["total_loc"]
        total_time += res["timing"]["total_wall_s"]

    out_file = PROJECT_ROOT / "phase4_benchmark_results.json"
    with open(out_file, "w") as fp:
        json.dump(results, fp, indent=2)
    print(f"\nSaved detailed benchmark JSON to: {out_file}")

    print("\n" + "="*70)
    print("PHASE 4 AGGREGATE MONOREPO BENCHMARK TOTALS:")
    print("="*70)
    print(f"Total Python Files Scanned  : {total_files:,}")
    print(f"Total Lines of Code Scanned : {total_loc:,} LOC")
    print(f"Combined Scan Wall Time     : {total_time:.2f}s")
    if total_time > 0:
        print(f"Combined Throughput         : {total_files / total_time:.1f} files/sec ({total_loc / total_time:,.0f} LOC/sec)")
    max_peak = max(r["memory"]["peak_rss_mb"] for r in results) if results else 0
    print(f"Peak Resident Memory (RSS)  : {max_peak:.1f} MB")
    print("="*70)


if __name__ == "__main__":
    main()
