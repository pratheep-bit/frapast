"""CI gate: every reproducer script must declare its PROOF_MODE explicitly.
An unmarked reproducer can still run and pass, but must never be allowed to
silently ship without someone having to notice and fix it."""
import sys
from pathlib import Path

REPRODUCERS_DIR = Path("runtime/reproducers")


def main() -> int:
	missing = []
	for path in sorted(REPRODUCERS_DIR.glob("FR-*.sh")):
		first_line = path.read_text(encoding="utf-8").splitlines()[0] if path.stat().st_size else ""
		if not first_line.startswith("# PROOF_MODE:"):
			missing.append(path.name)
	if missing:
		print("Reproducers missing PROOF_MODE marker:")
		for name in missing:
			print(f"  - {name}")
		return 1
	print("All reproducers declare PROOF_MODE.")
	return 0


if __name__ == "__main__":
	sys.exit(main())
