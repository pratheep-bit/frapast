"""Main package entrypoint for running via `python -m scanner`."""
import sys
from scanner.cli import main

if __name__ == "__main__":
	sys.exit(main())
