"""One-time migration: add a PROOF_MODE marker to every existing reproducer
script that predates the convention. Each retrofitted line is explicitly
flagged as a guess requiring manual verification — this must never be
silently trusted as equivalent to a marker the original author intended.
"""
from __future__ import annotations
import sys
from pathlib import Path

REPRODUCERS_DIR = Path("runtime/reproducers")
HTTP_SIGNAL_WORDS = ("curl ", "requests.", "frappe.client", "FrappeClient", " http://", " https://")


def guess_mode(content: str) -> str:
	return "http_rpc" if any(sig in content for sig in HTTP_SIGNAL_WORDS) else "direct_call"


def main() -> int:
	retrofitted = []
	for path in sorted(REPRODUCERS_DIR.glob("FR-*.sh")):
		content = path.read_text(encoding="utf-8")
		first_line = content.splitlines()[0] if content else ""
		if first_line.startswith("# PROOF_MODE:"):
			continue
		guessed = guess_mode(content)
		marker = f"# PROOF_MODE: {guessed}  # RETROFITTED — heuristic guess, VERIFY MANUALLY\n"
		path.write_text(marker + content, encoding="utf-8")
		retrofitted.append((path.name, guessed))

	print(f"Retrofitted {len(retrofitted)} reproducer(s):")
	for name, guessed in retrofitted:
		print(f"  - {name}: guessed '{guessed}' — REQUIRES MANUAL VERIFICATION")
	if retrofitted:
		print(
			"\nNone of these should be treated as Tier 2 until a human confirms the "
			"guess is correct. Track this in a checklist, don't just accept the default."
		)
	return 0


if __name__ == "__main__":
	sys.exit(main())
