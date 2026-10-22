#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Host orchestration ONLY. Every native/socket/filesystem fixture runs in bounded Linux."""
import argparse
import hashlib
import json
from pathlib import Path
import select
import struct
import subprocess
import sys
import time

if not __debug__:
    raise RuntimeError('optimized Python is not permitted for signer evidence')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--build-report', type=Path, required=True)
parser.add_argument('--checkout', required=True, help='contained source checkout, not host path')
args = parser.parse_args()
container = 'pqbtc-mldsa-integration-exec-20261022'
report = json.loads(args.build_report.read_text(encoding='utf8'))
assert report['result'] == 'PASS' and report['build_retained'] is True
server = report['service_binaries']['pilot-signer']
client = report['service_binaries']['public-client']
assert server.startswith('/tmp/mldsa-service-') and server.endswith('/pilot-signer') and '..' not in server
assert client == str(Path(server).parent / 'public-client')
assert args.checkout.startswith('/tmp/mldsa-') and '..' not in args.checkout
options = report['environment']
fixed = ['--env', 'ASAN_OPTIONS=' + options['ASAN_OPTIONS'], '--env', 'UBSAN_OPTIONS=' + options['UBSAN_OPTIONS'],
         '--env', 'OPENSSL_CONF=/dev/null', '--env', 'OPENSSL_MODULES=/nonexistent', '--env', 'PYTHONDONTWRITEBYTECODE=1']
def command(user, *parts):
    return ['docker','exec','-i','--user',user,*fixed,container,*map(str,parts)]
def invoke(user, *parts):
    value = subprocess.run(command(user,*parts),capture_output=True,timeout=120)
    if value.returncode or value.stderr:
        raise RuntimeError(f'contained fixture failed {parts}: exit={value.returncode}\n{value.stdout!r}\n{value.stderr!r}')
    return value.stdout

image = subprocess.check_output(['docker','inspect','--format',
    '{{.Image}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}',container],text=True,encoding='utf8').strip()
assert image == 'sha256:e62b83e313176eaf87f8fe634bd073fd576f29224e00c40bd6be8232a6cb6feb|none|true|4294967296|4000000000|["ALL"]|["no-new-privileges"]'
def verify_binaries():
    observed = {}
    for name, path in [('pilot-signer',server),('public-client',client)]:
        digest = invoke('1000:1000','python3','-c',
            'import hashlib,pathlib,sys;print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())',path).decode().strip()
        if digest != report['binaries'][name]:
            raise RuntimeError('service executable digest mismatch: ' + name)
        observed[name] = digest
    return observed
binary_hashes = verify_binaries()
spec_file = args.checkout + '/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md'
spec_bytes = invoke('1000:1000','python3','-c','import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())',spec_file)
spec = hashlib.sha256(spec_bytes).hexdigest()
base = invoke('1000:1000','python3','-c',
    'import tempfile,pathlib,os; p=pathlib.Path(tempfile.mkdtemp(prefix="mldsa-svc-"));os.chmod(p,0o750);(p/"wallet").mkdir(mode=0o700);(p/"ipc").mkdir(mode=0o750);print(p)').decode().strip()
assert base.startswith('/tmp/mldsa-svc-') and '/' not in base[len('/tmp/'):]
socket_path = base + '/ipc/signer.sock'
observations = []; processes = []; operator_checkpoints = []
def checkpoint(line):
    fields = line.decode('ascii').strip().split(' ')
    assert len(fields) == 5 and fields[0] == 'MLDSA_WALLET_STATUS_V1', 'missing operator checkpoint'
    assert len(fields[1]) == 32 and all(c in '0123456789abcdef' for c in fields[1])
    value = {'wallet_id':fields[1],'generation':int(fields[2]),'next_receive':int(fields[3]),'next_change':int(fields[4])}
    operator_checkpoints.append(value); return value
def native(scene, *tail, user='1001:1000'):
    result = json.loads(invoke(user,client,socket_path,1000,spec,scene,*tail))
    assert result['result'] == 'PASS'
    observations.append({'scene':scene,**result}); return result

class Running:
    def __init__(self, restore=None):
        flags = ['--valueless-pilot','--socket',socket_path,'--wallet-dir',base+'/wallet','--node-uid','1001',
                 '--fee-cap','1000','--spec-file',spec_file,'--operator-fd','3','--operator-out-fd','4']
        if restore is None: flags += ['--create']
        else:
            identity, receive, change = restore
            flags += ['--restore','--expected-wallet-id',identity,'--min-receive',str(receive),'--min-change',str(change),'--acknowledge-restore-scan-range']
        launcher = 'import os,sys;os.write(1,str(os.getpid()).encode()+bytes([10]));os.dup2(0,3);os.dup2(1,4);os.execv(sys.argv[1],sys.argv[1:])'
        self.process = subprocess.Popen(command('1000:1000','python3','-c',launcher,server,*flags),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        password = b'public-service-fixture' # PUBLIC test phrase, never a user credential.
        self.process.stdin.write(struct.pack('<H',len(password))+password); self.process.stdin.close(); self.process.stdin = None
        assert select.select([self.process.stdout],[],[],15)[0], 'launcher PID deadline'
        self.pid = int(self.process.stdout.readline())
        assert select.select([self.process.stdout],[],[],15)[0], 'operator checkpoint deadline'
        self.initial = checkpoint(self.process.stdout.readline())
        deadline = time.monotonic()+15
        while True:
            probe = subprocess.run(command('1000:1000','test','-S',socket_path),capture_output=True)
            if probe.returncode == 0: break
            if self.process.poll() is not None: raise RuntimeError(f'service startup failed: {self.process.stderr.read()!r}')
            assert time.monotonic()<deadline, 'service startup deadline'
            time.sleep(0.02)
        processes.append(self)
    def stop(self):
        if self.process.poll() is None:
            invoke('1000:1000','python3','-c','import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)',self.pid)
        output,error = self.process.communicate(timeout=15)
        assert self.process.returncode == 0 and error == b'', (self.process.returncode,output,error)
        self.final = checkpoint(output)
        processes.remove(self)
        return self.final

try:
    running = Running()
    invoke('1000:1000','python3','-c','import pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);shutil.copyfile(p/"wallet.dat",p/"retained-before-reservations.dat")',base+'/wallet')
    for role,user in [('unauthorized','1002:1000'),('controls','1001:1000')]:
        result = json.loads(invoke(user,'python3',args.checkout+'/contrib/ml-dsa-signer/service_smoke.py',socket_path,1000,spec,role))
        assert result['result'] == 'PASS'; observations.append(result)
    native('wrong-peer'); native('wrong-spec')
    spent = native('spend'); assert spent['locked']==1 and (spent['next_receive'],spent['next_change'])==(1,1)
    unreadable = subprocess.run(command('1001:1000','test','-r',base+'/wallet/wallet.dat'),capture_output=True)
    assert unreadable.returncode != 0
    retained = running.stop()
    assert spent['wallet_id'] == retained['wallet_id'] and (retained['next_receive'],retained['next_change']) == (1,1)
    running = Running((retained['wallet_id'],retained['next_receive'],retained['next_change']))
    resumed = native('reserve',1); assert resumed['next_receive']==2
    retained = running.stop()
    invoke('1000:1000','python3','-c','import pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);shutil.copyfile(p/"retained-before-reservations.dat",p/"wallet.dat")',base+'/wallet')
    running = Running((retained['wallet_id'],retained['next_receive'],retained['next_change']))
    restored = native('reserve',2); assert restored['next_receive']==3
    running.stop()
finally:
    for running in list(processes): running.stop()

assert verify_binaries() == binary_hashes
print(json.dumps({'result':'PASS','scope':'ISOLATED_REGTEST_SIGNER_SERVICE_NOT_NODE_INTEGRATION',
    'architecture':report['architecture'],'sanitized':report['sanitized'],'compiler':report['compiler'],
    'signer_uid':1000,'node_uid':1001,'unauthorized_uid':1002,'gid':1000,'spec_sha256':spec,
    'state_directory':base,'node_cannot_read_wallet':True,'observations':observations,
    'private_material_transfer':'NOT_IN_PROTOCOL_BY_CONSTRUCTION_NOT_A_MEMORY_SCAN',
    'default_node_linkage':'UNCHANGED_BY_COMPONENT_NO_NODE_EXECUTED','production_admitted':False,
    'executed_binary_hashes_before_and_after':binary_hashes,'build_runtime':report['runtime_before'],
    'operator_checkpoints':operator_checkpoints},indent=2))
