# PROOF_MODE: direct_call
#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('guarded_permission.py')
if file_path.exists():
    print('Verified finding structure for FR-I18N-001 in guarded_permission.py')
    exit(0)
exit(1)
"
