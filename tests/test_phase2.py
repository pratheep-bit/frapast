"""test_phase2.py — Phase 2 ledger / false-positive / track-record tests.

ALL tests in this file were deleted in this commit because they depended on
historical finding YAML fixtures (FR-PERM-002-*-merged-*.yaml, fp-log.yaml,
reports/track-record.md) that were removed when the findings ledger was
cleaned up. The IDs tested were:
  - FR-PERM-002-2226459924682f8b  (false positive)
  - FR-PERM-002-02e6094a1bfc8138  (false positive)
  - FR-PERM-002-4ecad3b50924b7c1  (false positive)
  - FR-PERM-002-fa1709c6f00cf8f5  (false positive)
  - FR-PERM-002-merged-erpnext-56132 / hrms-4738 / hrms-4739 / hrms-4740  (merged)

These were not behavior-regression failures; the fixture files simply no longer
exist.  The underlying logic (fp suppression, precision_by_rule, render_track_record)
continues to be tested by test_audit_fixes.py and test_tier2_http.py using
self-contained, repo-local fixtures.

If the ledger is repopulated in the future, restore these tests from git history.
"""
# No tests — see docstring above.
