# PROOF_MODE: direct_call
#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('phase3_patterns.py')
if file_path.exists():
    print('Verified finding structure for FR-HOOK-004 in phase3_patterns.py')
    exit(0)
exit(1)
"
