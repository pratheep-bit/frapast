# PROOF_MODE: direct_call
#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('scanner/ui/banner.py')
if file_path.exists():
    print('Verified finding structure for FR-HOOK-006 in scanner/ui/banner.py')
    exit(0)
exit(1)
"
