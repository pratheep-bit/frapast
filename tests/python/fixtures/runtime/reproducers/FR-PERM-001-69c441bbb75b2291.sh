#!/usr/bin/env bash
# PROOF_MODE: http_rpc
python3 -c "
import urllib.request
url = 'http://localhost:8000/api/method/ignore_permissions_endpoint'
try:
    req = urllib.request.Request(url, method='POST')
    with urllib.request.urlopen(req, timeout=5) as resp:
        print('HTTP RPC endpoint accessible:', resp.status)
        exit(0)
except Exception as e:
    print('HTTP RPC request status:', e)
    exit(1)
"
