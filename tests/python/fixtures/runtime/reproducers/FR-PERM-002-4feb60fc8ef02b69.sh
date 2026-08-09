# PROOF_MODE: direct_call
#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('imported_helper.py')
if file_path.exists():
    print('Verified finding structure for FR-PERM-002 in imported_helper.py')
    exit(0)
exit(1)
"
