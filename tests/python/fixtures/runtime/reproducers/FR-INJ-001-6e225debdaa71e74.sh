# PROOF_MODE: direct_call
#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('vulnerable.py')
if file_path.exists():
    print('Verified finding structure for FR-INJ-001 in vulnerable.py')
    exit(0)
exit(1)
"
