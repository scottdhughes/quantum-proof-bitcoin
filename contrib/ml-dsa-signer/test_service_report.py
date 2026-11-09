#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Host orchestrator regression; all fixture execution remains contained Linux."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--build-report', type=Path, required=True)
parser.add_argument('--checkout', required=True)
args = parser.parse_args()
report = json.loads(args.build_report.read_text(encoding='utf8'))
report['binaries']['pilot-signer'] = '0' * 64
with tempfile.TemporaryDirectory(prefix='mldsa-public-report-control-') as temporary:
    altered = Path(temporary) / 'public-build-report.json'
    altered.write_text(json.dumps(report), encoding='utf8')
    result = subprocess.run([sys.executable, str(Path(__file__).with_name('run_service_tests.py')),
        '--build-report', str(altered), '--checkout', args.checkout],capture_output=True,timeout=120)
    assert result.returncode != 0, 'orchestrator accepted a false executable digest'
    assert b'service executable digest mismatch' in result.stderr, result.stderr
print(json.dumps({'result':'PASS','false_service_binary_digest_rejected':True}))
optimized = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name('run_service_tests.py')),
    '--build-report', str(args.build_report), '--checkout', args.checkout],capture_output=True,timeout=120)
assert optimized.returncode != 0 and b'optimized Python is not permitted' in optimized.stderr, optimized.stderr
print(json.dumps({'result':'PASS','optimized_python_rejected':True}))
unsafe = subprocess.run(['docker','exec','-i','--user','1000:1000','pqbtc-mldsa-integration-exec-20261022',
    report['service_binaries']['pilot-signer'],'--valueless-pilot','--create','--node-uid','1001',
    '--fee-cap','1000','--socket','/not-opened','--wallet-dir','/not-opened','--spec-file','/not-opened',
    '--operator-fd','0','--operator-out-fd','1'],input=b'',capture_output=True,timeout=15)
assert unsafe.returncode != 0 and unsafe.stdout == b'' and unsafe.stderr == b'MLDSA_PILOT_ERROR 4\n', unsafe.stderr
print(json.dumps({'result':'PASS','standard_operator_descriptors_rejected_before_storage':True}))
