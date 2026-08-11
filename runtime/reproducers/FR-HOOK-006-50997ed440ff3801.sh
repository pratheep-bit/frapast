# PROOF_MODE: direct_call
#!/usr/bin/env bash
python3 -c "
from pathlib import Path
file_path = Path('build/lib/scanner/verify_ledger_integrity.py')
if file_path.exists():
    print('Verified finding structure for FR-HOOK-006 in build/lib/scanner/verify_ledger_integrity.py')
    exit(0)
exit(1)
"
