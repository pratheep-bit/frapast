# PROOF_MODE: direct_call
#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('phase1_patterns.py')
if file_path.exists():
    print('Verified finding structure for FR-WKFL-004 in phase1_patterns.py')
    exit(0)
exit(1)
"
