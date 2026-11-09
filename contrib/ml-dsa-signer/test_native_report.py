#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""DATA-only regression: no client-only ELF observation may stand for the signer."""
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding='utf8'))
names = {'wallet-smoke','ipc-smoke','schedule-smoke','pilot-signer','public-client'}
assert set(report['executables']) == names, 'missing per-executable ELF evidence'
for name in names:
    item = report['executables'][name]
    assert item['sha256'] == report['binaries'][name]
    assert 'ELF64' in item['elf'] and 'NEEDED' in item['dynamic']
    assert 'libcrypto.so' not in item['dynamic'] and 'libssl.so' not in item['dynamic']
assert report['pilot_crypto_version'] == report['native']['wallet']['runtime']
assert report['pilot_crypto_version'].startswith('OpenSSL 3.6.5 ')
print(json.dumps({'result':'PASS','individual_executables_checked':len(names)}))
