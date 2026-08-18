## Summary

<!-- One sentence describing what this PR does. -->

## Motivation

<!-- Why is this change needed? Link any related issues or false-positive reports. -->

## Type of Change

- [ ] Bug fix
- [ ] New rule or rule modification
- [ ] False-positive / precision improvement
- [ ] Performance improvement
- [ ] Documentation only
- [ ] Refactoring (no behavior change)
- [ ] CI / tooling

## Checklist

### Required for all PRs
- [ ] `pytest` passes cleanly with zero failures (`pytest --tb=short`)
- [ ] No new `ruff` lint errors introduced (`ruff check .`)
- [ ] No private company names, client identities, or proprietary infrastructure details are referenced in code, comments, or commit messages (per `AGENTS.md`)

### Required for new or modified rules
- [ ] The rule has at least one unit test in `tests/` that triggers it
- [ ] The rule has at least one unit test that verifies the safe equivalent does NOT trigger it (false-positive guard)
- [ ] A precision justification is included in the PR description or in the rule's YAML comment: how many true positives and false positives were observed on which open-source corpus?
- [ ] The rule's bound has been added or updated in `tests/test_precision_benchmark.py`

### Required for rules touching the proof engine
- [ ] The fix or rule does not introduce new shell injection vectors in `scanner/proof/orchestrator.py` or `scanner/proof/http_synthesis.py`
- [ ] `tests/test_security_hardening_regression.py` passes with no new failures

## Test Evidence

<!-- Paste relevant pytest output or describe which tests cover this change. -->

## Related Issues

<!-- Closes #NNN -->
