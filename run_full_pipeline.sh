#!/usr/bin/env bash
set -euo pipefail

echo "=== Phase 1: Callgraph acceptance test ==="
python -m pytest tests/test_callgraph_dispatch.py -v

echo "=== Phase 2: Full test suite ==="
python -m pytest tests/ -v

echo "=== Phase 3: FP report (pre-proof) ==="
python -m scanner.cli fp-report

echo "=== Phase 4: Benchmark against known CVEs ==="
python benchmark/run_benchmark.py

echo "=== Phase 5: New rule smoke test ==="
grep -rE "FR-XSS-001|FR-CSRF-001|FR-SSRF-001" scanner/rules/*.yaml || \
  echo "WARNING: zero hits for new rule families — see Task 4 acceptance test"

echo "=== Pipeline complete. Review findings/ directory manually before any proof runs. ==="