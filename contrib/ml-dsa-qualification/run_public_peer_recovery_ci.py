#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Private, valueless native peer-renewal regression; zero public soak credit.

Use a qualified H or current runtime descriptor. Host control provenance is
recorded separately from native payload provenance. Custody state is retained in
a private temporary directory outside the evidence output, never uploaded.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / 'contrib/ml-dsa-console'), str(HERE)]
import public_controller as controls  # noqa: E402
import public_soak_agent as agent_api  # noqa: E402
import run_public_soak as soak_api  # noqa: E402
from run_assembled_ci import checkout_identity  # noqa: E402

ENDPOINT = '127.0.0.1:23834'
CONTROL = '/var/lib/pqbtc/node/peer-recovery-ci.sock'
CONTROL_FILES = (*soak_api.CONTROL_FILES, 'contrib/ml-dsa-qualification/run_public_soak.py',
                 'contrib/ml-dsa-qualification/run_public_peer_recovery_ci.py',
                 'contrib/ml-dsa-qualification/peer_recovery_proxy.py')
require = soak_api.require


def remaining(deadline):
    require(type(deadline) in (int, float) and math.isfinite(deadline), 'Finite deadline required')
    left = deadline - time.monotonic()
    require(left > 0, 'Private native regression deadline')
    return left


def validate_namespace(name):
    require(type(name) is str and re.fullmatch(r'pqbtc-mldsa-public-recovery-[0-9a-f]{32}', name),
            'Fresh UUID recovery namespace required')
    return name + '-data-v1'


def private_ip(value):
    address = ipaddress.IPv4Address(value)
    require(address.is_private and not (address.is_loopback or address.is_link_local or
            address.is_unspecified or address.is_multicast), 'Private Docker bridge address required')
    return str(address)


def validate_renewal(value, endpoint, transport):
    require(type(value) is dict and value.get('endpoint') == endpoint and value.get('renewed') is True and
            value.get('network_active') is True and value.get('fresh_pong') is True and
            value.get('transport_protocol_type') == transport, 'Native renewal transport or pong missing')
    old, new = value.get('old_peer_ids'), value.get('new_peer_id')
    require(type(old) is list and len(old) == 1 and type(old[0]) is int and old[0] >= 0 and
            type(new) is int and new >= 0 and new not in old, 'Native target peer did not change')
    for label in ('ping_sent', 'pong_received'):
        before, after = value.get(label + '_before'), value.get(label + '_after')
        require(type(before) is int and type(after) is int and 0 <= before < after, 'Native pong counters stale')


def validate_payment(value):
    payment, known = value['payment'], value['known']
    require(payment.get('sender') == 'A' and payment.get('receiver') == 'B' and
            payment.get('recipient_in_mempool') is True and value.get('recipient_observed') is True and
            soak_api.finite(payment.get('settle_seconds')) and 0 < payment['settle_seconds'] <= 60 and
            soak_api.finite(payment.get('recipient_relay_seconds')) and
            10 <= payment['recipient_relay_seconds'] <= payment['settle_seconds'], 'Original payment clock or relay proof failed')
    require(value['counts'] == {'receive': 1, 'send': 1, 'renew_peer': 1}, 'Payment was reissued or renewal not exercised once')
    require(all(soak_api.hex64(known.get(k)) for k in ('txid', 'wtxid', 'raw_transaction_sha256')) and
            known['txid'] == payment['txid'] and soak_api.hex64(payment['block_hash']), 'Known transaction identity missing')
    dropped = value['drop'].get('dropped')
    require(value['drop'].get('armed') is False and value['drop'].get('ever_armed') is True and
            type(dropped) is list and len(dropped) == 1 and dropped[0].get('type') in (1, 5) and
            dropped[0].get('hash') == known['txid' if dropped[0]['type'] == 1 else 'wtxid'], 'Dropped INV does not bind known transaction')
    announcements = value['reannouncements']
    require(type(announcements) is list and 1 <= len(announcements) <= 6 and all(
            row.get('txid') == known['txid'] and row.get('raw_transaction_sha256') == known['raw_transaction_sha256'] and
            row.get('known_in_mempool') is True and row.get('rebroadcast') is True and row.get('reissued_payment') is False
            for row in announcements), 'Reannouncement changed transaction bytes')
    validate_renewal(value['renewal'], ENDPOINT, 'v1')
    require(soak_api.finite(value.get('renewal_elapsed')) and 10 <= value['renewal_elapsed'] < payment['settle_seconds'],
            'Normal ten-second recovery trigger not exercised')
    floors = value['floors']
    require(type(floors) is list and len(floors) >= 3 and all(point == floors[0] for point in floors), 'Recovery changed floors')
    require(set(value['memberships']) == {'A', 'B'} and all(
            row.get('txid') == known['txid'] and row.get('block_hash') == payment['block_hash'] and
            row.get('confirmed') is True and type(row.get('confirmations')) is int and row['confirmations'] >= 1
            for row in value['memberships'].values()), 'Both-node target block membership missing')
    nodes = value['agreement']
    require(set(nodes) == {'A', 'B'} and nodes['A'] == nodes['B'] and nodes['A'].get('tip') == payment['block_hash'] and
            soak_api.hex64(nodes['A'].get('utxo_hash')) and type(nodes['A'].get('height')) is int and
            type(nodes['A'].get('utxo_count')) is int, 'Full native state agreement missing')


# Deliberately omit Env, process argv and logs. Cmd is the fixed sleep supervisor
# declaration required by the production layout validator, never /proc argv.
INSPECT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
           '"HostConfig":{{json .HostConfig}},"Mounts":{{json .Mounts}},'
           '"State":{"Running":{{json .State.Running}},"Pid":{{json .State.Pid}}},'
           '"Config":{"Labels":{{json .Config.Labels}},"Cmd":{{json .Config.Cmd}},"User":{{json .Config.User}}},'
           '"NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}}}}')
MARKER_SCRIPT = '''import json,os,stat
fd=os.open('/var/lib/pqbtc/identity.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
s=os.fstat(fd)
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=1024
raw=os.read(fd,1025);os.close(fd);assert len(raw)<=1024
print(json.dumps(json.loads(raw)))'''


class OwnedNode:
    def __init__(self, controller):
        self.controller, self.manager = controller, controller.manager
        require(self.manager.volume == validate_namespace(self.manager.container), 'Recovery volume namespace mismatch')
        self.container_id = self.volume_id = None
        self.lock = threading.Lock()
        # All legacy manager observations now use the same selected fields.
        self.manager.inspect = self.inspect

    def inspect(self, target=None):
        result = self.manager.run(['inspect', '--format', INSPECT, target or self.manager.container],
                                  check=False, timeout=10)
        if result.returncode:
            require(b'No such object:' in result.stderr or b'No such container:' in result.stderr,
                    'Container liveness could not be determined')
            return None
        require(len(result.stdout) <= 65536, 'Container layout response bound')
        return soak_api.parsed(result.stdout)

    def discover(self):
        row = self.inspect()
        if row is None:
            require(self.container_id is None, 'Retained native container disappeared')
            return None
        self.manager.layout(row)
        identity = row.get('Id')
        require(soak_api.hex64(identity) and row.get('Name') == '/' + self.manager.container and
                self.container_id in (None, identity), 'Immutable owned container changed')
        retained = self.manager._read_json('public-runtime.json')
        require(retained.get('schema') == 'PQBTC-MLDSA44-PUBLIC-RUNTIME-1' and
                retained.get('compatibility') == controls.COMPATIBILITY and
                retained.get('container') == self.manager.container and retained.get('volume') == self.manager.volume and
                retained.get('port') == self.manager.port and retained.get('descriptor') == self.manager.descriptor,
                'Retained public ownership mismatch')
        volume_id = retained.get('volume_id')
        require(type(volume_id) is str and re.fullmatch('[0-9a-f]{32}', volume_id) and volume_id != '0' * 32 and
                self.volume_id in (None, volume_id), 'Retained volume identity changed')
        state = row.get('State', {})
        require(type(state.get('Running')) is bool and type(state.get('Pid')) is int and state['Pid'] >= 0,
                'Native liveness evidence missing')
        if state['Running']:
            result = self.manager.run(['exec', '--user', '1001:1000', identity, 'python3', '-c', MARKER_SCRIPT], timeout=10)
            require(len(result.stdout) <= 1024 and soak_api.parsed(result.stdout) ==
                    {'volume_id': volume_id, 'profile_sha256': controls.PROFILE}, 'Native volume marker mismatch')
        self.container_id, self.volume_id = identity, volume_id
        return row

    def stop(self):
        with self.lock:
            row = self.discover()
            if row is None:
                return {'container': self.manager.container, 'created': False, 'retained': True}
            if row['State']['Running']:
                self.manager.run(['stop', '--time', '5', self.container_id], timeout=20)
            # Bind proof to the full ID; a same-name replacement is never stopped.
            stopped = self.inspect(self.container_id)
            require(stopped is not None, 'Stopped native identity disappeared')
            self.manager.layout(stopped)
            require(stopped['Id'] == self.container_id and stopped['State'] == {'Running': False, 'Pid': 0},
                    'Stopped PID0 proof missing')
            return {'container': self.manager.container, 'container_id': self.container_id,
                    'volume': self.manager.volume, 'volume_id': self.volume_id,
                    'running': False, 'pid': 0, 'retained': True}

    def invoke(self, script, *arguments, deadline):
        require(self.container_id is not None, 'Native API needs captured ownership')
        result = self.manager.run(['exec', '--user', '1001:1000', self.container_id,
                                  'python3', '-B', '-c', script, *arguments], timeout=min(10, remaining(deadline)))
        remaining(deadline)
        require(len(result.stdout) <= 16384, 'Native API public result bound')
        return soak_api.parsed(result.stdout)


HELPER_INSPECT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
                  '"Config":{"Labels":{{json .Config.Labels}},"User":{{json .Config.User}}},'
                  '"HostConfig":{{json .HostConfig}},"Mounts":{{json .Mounts}},'
                  '"State":{"Running":{{json .State.Running}},"Pid":{{json .State.Pid}}}}')


class StartupHelper:
    """One pre-registered invocation of an unchanged product startup script."""
    def __init__(self, invoke, manager, descriptor, arguments, attempt):
        self.invoke, self.container_id, self.proof = invoke, None, None
        self.layout_observed = False
        self.lock = threading.Lock()
        self.name = 'pqbtc-mldsa-recovery-helper-' + uuid.uuid4().hex
        self.image = descriptor['image']
        self.volume = validate_namespace(manager.container)
        require(manager.volume == self.volume, 'Helper volume namespace mismatch')
        image_index = arguments.index(self.image)
        options = arguments[1:image_index]
        common = ['--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL']
        image_options = common + ['--security-opt', 'no-new-privileges', '--memory', '268435456',
                                  '--pids-limit', '64', '--user', '1001:1000']
        init_options = common + ['--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges', '--mount',
                                 'type=volume,source=' + self.volume + ',target=' + controls.DATA + ',volume-nocopy']
        require(options in (image_options, init_options) and arguments[image_index+1:image_index+3] == ['python3', '-c'],
                'Unexpected product startup helper invocation')
        self.kind = 'image_check' if options == image_options else 'volume_init'
        self.memory = 268435456 if self.kind == 'image_check' else 134217728
        # Labels bind the original public product invocation without retaining
        # its script/arguments in receipts or reading a container's raw argv.
        self.labels = {'org.pqbtc.console.build': 'source-1', 'org.pqbtc.recovery.helper': self.kind, 'org.pqbtc.recovery.attempt': attempt,
                       'org.pqbtc.recovery.node': manager.container, 'org.pqbtc.recovery.manifest': descriptor['manifest_sha256'],
                       'org.pqbtc.recovery.invocation': hashlib.sha256(soak_api.canonical(arguments)).hexdigest()}
        additions = ['--name', self.name, '--cpus', '2']
        if self.kind == 'volume_init':
            additions += ['--memory', '134217728', '--pids-limit', '64']
        for key, value in self.labels.items():
            additions += ['--label', key + '=' + value]
        # Keep the production image-check/init script, public operands and all
        # existing containment options byte-for-byte; only add fixture bounds.
        self.arguments = ['run', *additions, *arguments[1:]]

    def inspect(self, target):
        result = self.invoke(['inspect', '--format', HELPER_INSPECT, target], check=False, timeout=5)
        if result.returncode:
            require(b'No such object:' in result.stderr or b'No such container:' in result.stderr,
                    'Startup helper absence could not be proved')
            return None
        require(len(result.stdout) <= 65536, 'Startup helper layout response bound')
        row = soak_api.parsed(result.stdout)
        self.layout(row)
        self.layout_observed = True
        return row

    def layout(self, row):
        host, config = row['HostConfig'], row['Config']
        require(row.get('Name') == '/' + self.name and row.get('Image') == self.image and
                soak_api.hex64(row.get('Id')) and self.container_id in (None, row['Id']) and
                config.get('Labels') == self.labels, 'Startup helper ownership or immutable identity changed')
        require(host.get('NetworkMode') == 'none' and host.get('ReadonlyRootfs') is True and
                host.get('NanoCpus') == 2000000000 and host.get('Memory') == self.memory and host.get('PidsLimit') == 64 and
                host.get('CapDrop') == ['ALL'] and host.get('SecurityOpt') == ['no-new-privileges'] and
                host.get('Privileged') is False and host.get('AutoRemove') is True and
                host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0} and
                host.get('PortBindings') in (None, {}) and host.get('Binds') in (None, []) and host.get('Tmpfs') in (None, {}) and
                host.get('Devices') in (None, []) and host.get('DeviceRequests') in (None, []) and
                host.get('PidMode') == '' and host.get('IpcMode') == 'private', 'Startup helper isolation changed')
        mounts = row.get('Mounts')
        if self.kind == 'image_check':
            require(config.get('User') == '1001:1000' and host.get('CapAdd') in (None, []) and mounts == [],
                    'Image-check helper UID/capabilities/mounts changed')
        else:
            require(config.get('User', '') in ('', '0') and host.get('CapAdd') == ['CHOWN'] and
                    type(mounts) is list and len(mounts) == 1 and mounts[0].get('Type') == 'volume' and
                    mounts[0].get('Name') == self.volume and mounts[0].get('Destination') == controls.DATA and
                    mounts[0].get('RW') is True, 'Volume-init helper UID/capabilities/mount changed')
        state = row.get('State', {})
        require(type(state.get('Running')) is bool and type(state.get('Pid')) is int and state['Pid'] >= 0,
                'Startup helper liveness missing')

    def stop(self):
        with self.lock:
            # Discovery by the never-reused name is needed when docker run lost
            # its response. A captured ID is rechecked and cannot be replaced.
            row = self.inspect(self.name)
            if row is None and self.container_id is not None:
                row = self.inspect(self.container_id)
            if row is not None:
                self.container_id = row['Id']
                if row['State']['Running']:
                    result = self.invoke(['stop', '--time', '1', self.container_id], check=False, timeout=15)
                    require(result.returncode == 0 or b'No such' in result.stderr, 'Startup helper stop failed')
                row = self.inspect(self.container_id)
                if row is not None:
                    require(row['State'] == {'Running': False, 'Pid': 0}, 'Startup helper stopped PID0 proof missing')
            self.proof = {'name': self.name, 'kind': self.kind, 'container_id': self.container_id,
                          'image': self.image, 'memory_bytes': self.memory, 'nano_cpus': 2000000000, 'pids_limit': 64,
                          'ownership_labels': dict(self.labels), 'volume': self.volume if self.kind == 'volume_init' else None,
                          'layout_observed': self.layout_observed,
                          'resource_evidence': 'VALIDATED_LAYOUT' if self.layout_observed else 'REQUESTED_LIMITS_AND_PROVED_ABSENCE',
                          'absence_proved': row is None, 'running': False, 'pid': 0}
            return dict(self.proof)


class StartupHelpers:
    """Fixture-only manager.run adapter; shared across both product nodes."""
    def __init__(self, deadline):
        self.deadline, self.attempt = deadline, uuid.uuid4().hex
        self.records, self.closed = [], False
        self.serial, self.registry_lock = threading.Lock(), threading.Lock()

    def attach(self, manager, descriptor):
        original = manager.run
        def bounded(arguments, **kwargs):
            if not arguments or arguments[0] != 'run':
                return original(arguments, **kwargs)
            acquired = self.serial.acquire(timeout=remaining(self.deadline))
            require(acquired, 'Startup helper serialization deadline')
            try:
                require(not self.closed, 'Startup helpers already shut down')
                # Verify every prior helper is stopped/absent before another
                # product startup invocation may enter Docker.
                for prior in self.records:
                    prior.stop()
                record = StartupHelper(original, manager, descriptor, list(arguments), self.attempt)
                require(record.inspect(record.name) is None, 'Startup helper namespace already exists')
                with self.registry_lock:
                    require(not self.closed, 'Startup helpers already shut down')
                    require(len(self.records) < 4, 'Only four necessary startup helpers are allowed')
                    self.records.append(record)
                try:
                    kwargs['timeout'] = min(kwargs.get('timeout', 90), remaining(self.deadline))
                    require(not self.closed, 'Startup helpers already shut down')
                    return original(record.arguments, **kwargs)
                finally:
                    # Even a failed or timed-out CLI may have created/started
                    # the helper; recover ownership by name, never assume exit.
                    record.stop()
            finally:
                self.serial.release()
        manager.run = bounded

    def stop_all(self):
        with self.registry_lock:
            self.closed = True
            records = tuple(self.records)
        errors = []
        for record in records:
            try:
                record.stop()
            except Exception as error:
                errors.append(type(error).__name__)
        require(not errors, 'Startup helper cleanup ownership or liveness failure')

    def receipts(self):
        with self.registry_lock:
            return [dict(record.proof) if record.proof is not None else
                    {'name': record.name, 'kind': record.kind, 'cleanup_unproved': True} for record in self.records]


class LocalAgent:
    """Only transport adaptation: all actions are dispatched by production Agent."""
    def __init__(self, host, agent, audit):
        self.host, self.agent, self.audit = host, agent, audit

    def call(self, action, params=None, *, timeout=90):
        require(soak_api.finite(timeout) and 0 < timeout <= 300, 'Local agent budget refused')
        deadline = time.monotonic() + timeout
        params = self.audit.before(self.host, action, dict(params or {}), deadline)
        remaining(deadline)
        value = self.agent.act(action, params)
        remaining(deadline)
        self.audit.after(self.host, action, params, value, deadline)
        remaining(deadline)
        return value


NATIVE_SCRIPT = r'''import hashlib,json,re,sys,time
from pathlib import Path
sys.path[:0]=[sys.argv[1]+'/contrib/ml-dsa-console',sys.argv[1]+'/test/functional']
from public_runtime import PublicNode
from test_framework.authproxy import AuthServiceProxy
node=PublicNode('',Path('/var/lib/pqbtc/node/chain'),AuthServiceProxy)
op,arg,transport=sys.argv[2:5];deadline=time.monotonic()+float(sys.argv[5])
def rpc(method,*args):
    left=deadline-time.monotonic();assert left>0
    return getattr(node.rpc(timeout=min(0.5,left)),method)(*args)
if op=='known':
    assert re.fullmatch('[0-9a-f]{64}',arg)
    entry=rpc('getmempoolentry',arg);assert isinstance(entry,dict) and 0<entry['vsize']<=1000000
    raw=rpc('getrawtransaction',arg,False)
    assert isinstance(raw,str) and 2<=len(raw)<=2000000 and len(raw)%2==0 and re.fullmatch('[0-9a-f]+',raw)
    decoded=rpc('decoderawtransaction',raw);assert decoded['txid']==arg
    result={'txid':arg,'wtxid':decoded['hash'],'raw_transaction_sha256':hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
elif op in ('peer','register'):
    assert re.fullmatch(r'[0-9.]+:2383[34]',arg) and transport in ('v1','v2')
    if op=='register':
        registered=rpc('getaddednodeinfo');assert not any(p['addednode']==arg for p in registered)
        rpc('addnode',arg,'add',transport=='v2')
    values=rpc('getpeerinfo');assert isinstance(values,list) and len(values)<=256
    peers=[{'id':p['id'],'addr':p['addr'],'version':p.get('version',0),'relaytxes':p.get('relaytxes',False),
            'transport_protocol_type':p.get('transport_protocol_type')} for p in values if p['addr']==arg]
    result={'endpoint':arg,'peers':peers}
else:
    assert op=='network'
    status=rpc('getnetworkinfo')
    result={'network_active':status['networkactive']}
assert time.monotonic()<deadline
print(json.dumps(result,sort_keys=True))'''


def native(node, operation, argument='', transport='v1', *, deadline):
    return node.invoke(NATIVE_SCRIPT, controls.SOURCE, operation, argument, transport,
                       str(min(3, remaining(deadline))), deadline=deadline)


def floors(nodes):
    result = {}
    for host, node in nodes.items():
        point = node.controller.journal['checkpoint']
        require(type(point) is dict, 'Public checkpoint missing')
        result[host] = {key: point[key] for key in ('wallet_id', 'next_receive', 'next_change')}
    return copy.deepcopy(result)


class PaymentAudit:
    def __init__(self, nodes):
        self.nodes, self.active = nodes, False
        self.txid = self.started = None
        self.data = {'counts': {'receive': 0, 'send': 0, 'renew_peer': 0}, 'floors': [],
                     'memberships': {}, 'reannouncements': [], 'recipient_observed': False}

    def check_floors(self):
        if self.data['floors']:
            require(floors(self.nodes) == self.data['floors'][0], 'Recovery changed public floors')

    def before(self, host, action, params, deadline):
        if not self.active:
            return params
        self.check_floors()
        if action in self.data['counts']:
            expected = 'B' if action == 'receive' else 'A'
            require(host == expected and self.data['counts'][action] == 0, 'Duplicate or misrouted payment mutation')
            self.data['counts'][action] += 1
        if action == 'renew_peer':
            require(self.txid is not None and params.get('endpoint') == ENDPOINT, 'Renewal target not the known payment route')
            self.data['known'] = native(self.nodes['A'], 'known', self.txid, deadline=deadline)
            self.data['renewal_elapsed'] = time.monotonic() - self.started
            self.data['floors'].append(floors(self.nodes))
            # Observation consumes the caller's existing budget, never extends it.
            params['budget_seconds'] = min(params['budget_seconds'], remaining(deadline))
        return params

    def after(self, host, action, params, result, deadline):
        if not self.active:
            return
        value = result['result'] if 'status' in result and isinstance(result.get('result'), dict) else result
        if action == 'send':
            self.txid = value['txid']
            self.started = time.monotonic()
            self.data['floors'].append(floors(self.nodes))
        else:
            self.check_floors()
        if action == 'renew_peer':
            self.data['renewal'] = value
            self.data['floors'].append(floors(self.nodes))
        elif action == 'rebroadcast':
            self.data['reannouncements'].append(value)
            self.data['floors'].append(floors(self.nodes))
        elif action == 'transaction':
            require(value.get('txid') == self.txid, 'Native transaction observation substituted target')
            if host == 'B' and value.get('in_mempool') is True:
                self.data['recipient_observed'] = True
            if 'block_hash' in params:
                self.data['memberships'][host] = value


def validate_acceptance(report):
    validate_payment(report['payment_evidence'])
    v2 = report['v2']
    validate_renewal(v2['renewal'], v2['endpoint'], 'v2')
    require(v2['unrelated_before'] == v2['unrelated_after'] and v2['floors_before'] == v2['floors_after'],
            'V2 control changed unrelated peer or floors')
    off = report['network_off']
    require(off.get('refused') is True and off.get('network_active') is False and off.get('saved_network_active') is False and
            off['floors_before'] == off['floors_after'], 'Network-off control resumed networking or changed floors')
    helpers = report.get('startup_helpers')
    require(type(helpers) is list and len(helpers) == 4 and
            sorted(row.get('kind', '') for row in helpers) == ['image_check', 'image_check', 'volume_init', 'volume_init'] and
            len({row.get('name') for row in helpers}) == 4, 'Four necessary startup helper cleanup receipts required')
    for row in helpers:
        require(type(row.get('name')) is str and re.fullmatch(r'pqbtc-mldsa-recovery-helper-[0-9a-f]{32}', row['name']) and
                row.get('memory_bytes') == (268435456 if row['kind'] == 'image_check' else 134217728) and
                row.get('nano_cpus') == 2000000000 and row.get('pids_limit') == 64 and
                row.get('running') is False and type(row.get('pid')) is int and row['pid'] == 0 and
                type(row.get('absence_proved')) is bool and
                (row['absence_proved'] and row.get('container_id') is None or soak_api.hex64(row.get('container_id'))),
                'Bounded startup helper stopped PID0 or absence proof missing')
    cleanup = report['cleanup']
    require(type(cleanup) is list and len(cleanup) == 2 and all(
            soak_api.hex64(row.get('container_id')) and type(row.get('volume_id')) is str and
            re.fullmatch('[0-9a-f]{32}', row['volume_id']) and row.get('running') is False and
            type(row.get('pid')) is int and row['pid'] == 0 and row.get('retained') is True for row in cleanup) and
            len({row['container_id'] for row in cleanup}) == 2 and len({row['volume_id'] for row in cleanup}) == 2,
            'Two distinct retained native nodes need stopped PID0 proof')
    require(report['proxy_stop'].get('ok') is True and report['proxy_stop'].get('active_connections') == 0 and
            report.get('public_soak_credit_seconds') == 0 and report.get('watchdog_expired') is False and
            report.get('cleanup_errors') == [], 'Cleanup or private-scope acceptance failed')


CONTROL_SCRIPT = r'''import json,os,socket,stat,sys
path=sys.argv[1];s=os.lstat(path)
assert stat.S_ISSOCK(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o600
with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(2);client.connect(path)
    client.sendall(json.dumps({'op':sys.argv[2]}).encode()+b'\n')
    raw=bytearray()
    while not raw.endswith(b'\n') and len(raw)<=16384:
        data=client.recv(min(4096,16385-len(raw)));assert data;raw.extend(data)
    assert len(raw)<=16384
    value=json.loads(raw);assert value.get('ok') is True
    print(json.dumps(value,sort_keys=True))'''


class Proxy:
    def __init__(self, node, upstream):
        self.node, self.upstream, self.process = node, private_ip(upstream), None

    def control(self, operation, deadline):
        require(operation in ('status', 'arm', 'stop'), 'Proxy control refused')
        return self.node.invoke(CONTROL_SCRIPT, CONTROL, operation, deadline=deadline)

    def start(self, deadline):
        source = (HERE / 'peer_recovery_proxy.py').read_bytes()
        require(len(source) <= 32768, 'Proxy source bound')
        self.process = subprocess.Popen(['docker', 'exec', '--interactive', '--user', '1001:1000', self.node.container_id,
                                        'python3', '-B', '-c', 'import sys;exec(compile(sys.stdin.buffer.read(),"<recovery-proxy>","exec"))',
                                        '--control', CONTROL, '--upstream', self.upstream],
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.process.stdin.write(source)
        self.process.stdin.close()
        while True:
            require(self.process.poll() is None, 'Proxy startup failed')
            try:
                return self.control('status', deadline)
            except Exception:
                remaining(deadline)
                time.sleep(.05)

    def stop(self, deadline):
        require(self.process is not None and self.process.poll() is None, 'Proxy exited before clean stop')
        result = self.control('stop', deadline)
        self.process.wait(timeout=min(5, remaining(deadline)))
        require(self.process.returncode == 0 and result['active_connections'] == 0, 'Proxy did not close all connections')
        return result

    def reap(self):
        if self.process is not None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def wait_peer(node, endpoint, transport, deadline):
    while True:
        value = native(node, 'peer', endpoint, transport, deadline=deadline)
        peers = value.get('peers')
        require(type(peers) is list and len(peers) <= 1, 'Ambiguous target native peer')
        if peers:
            peer = peers[0]
            if peer.get('version', 0) > 0 and peer.get('relaytxes') is True and peer.get('transport_protocol_type') == transport:
                return peer
        time.sleep(min(.05, remaining(deadline)))


def check_runtime(descriptor):
    def query(arguments):
        result = subprocess.run(['docker', *arguments], capture_output=True, timeout=20)
        require(result.returncode == 0 and len(result.stdout) <= 4096, 'Native Docker runtime unavailable')
        return soak_api.parsed(result.stdout)
    image = query(['image', 'inspect', '--format', '{"Id":{{json .Id}},"Architecture":{{json .Architecture}},"Os":{{json .Os}}}', descriptor['image']])
    server = query(['info', '--format', '{"Architecture":{{json .Architecture}},"Os":{{json .OSType}}}'])
    normalize = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}
    architecture = normalize.get(descriptor['manifest']['architecture'])
    require(image.get('Id') == descriptor['image'] and image.get('Os') == server.get('Os') == 'linux' and
            normalize.get(image.get('Architecture')) == normalize.get(server.get('Architecture')) == architecture and
            architecture is not None, 'Native image/server architecture mismatch or emulation')
    return {'image': image, 'server': server, 'emulated': False}


def require_fresh(name):
    volume = validate_namespace(name)
    for kind, target in (('container', name), ('volume', volume)):
        result = subprocess.run(['docker', kind, 'inspect', '--format', '{{json .Name}}', target], capture_output=True, timeout=15)
        require(result.returncode != 0 and (b'No such' in result.stderr or b'no such' in result.stderr),
                'Fresh native namespace absent proof missing')


def host_port():
    import socket
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def network_observation(node, deadline):
    script = r'''import json,os,stat,sys
sys.path[:0]=[sys.argv[1]+'/contrib/ml-dsa-console',sys.argv[1]+'/test/functional']
from public_runtime import PeerPolicy,PublicNode
from test_framework.authproxy import AuthServiceProxy
from pathlib import Path
path=Path('/var/lib/pqbtc/node/peer-policy.json')
assert not os.path.lexists(path.with_name('peer-policy.tmp'))
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd)
assert stat.S_ISREG(s.st_mode) and s.st_uid==1001 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4096
raw=os.read(fd,4097);os.close(fd);assert len(raw)<=4096
saved=PeerPolicy.validate(json.loads(raw))
node=PublicNode('',Path('/var/lib/pqbtc/node/chain'),AuthServiceProxy)
print(json.dumps({'network_active':node.rpc(timeout=.5).getnetworkinfo()['networkactive'],
                  'saved_network_active':saved['network_active']}))'''
    return node.invoke(script, controls.SOURCE, deadline=deadline)


def exercise(nodes, report, log, proxy, deadline):
    config = {'hosts': [{'name': 'A', 'role': 'follower'}, {'name': 'B', 'role': 'bootstrap'}]}
    run = soak_api.Soak(config, 'preflight', log, {}, 'PRIVATE_REGRESSION_NO_PUBLIC_CLOCK')
    audit = PaymentAudit(nodes)
    run.agents = {host: LocalAgent(host, agent_api.Agent(node.controller, node.controller.state_dir,
                  time.time() + remaining(deadline)), audit) for host, node in nodes.items()}
    run.action_deadline = deadline
    native(nodes['A'], 'register', ENDPOINT, deadline=deadline)
    run.action('A', 'peer', {'endpoint': ENDPOINT})
    report['v1_before'] = wait_peer(nodes['A'], ENDPOINT, 'v1', deadline)
    run.agree(timeout=min(90, remaining(deadline)))
    for host in ('A', 'B'):
        password = secrets.token_urlsafe(32)
        run.action(host, 'setup', {'password': password})
        del password
        address = run.receive(host)
        run.action(host, 'fund', {'address': address}, timeout=min(240, remaining(deadline)))
        run.agree(timeout=min(90, remaining(deadline)))
        require(run.statuses[host]['wallet']['spendable_sats'] > 105000, 'Mature native TEST funds missing')
    require(run.transaction_peers_connected(), 'Native transaction handshake not ready')
    ready = proxy.control('status', deadline)
    require(ready.get('active_connections') == 1 and ready.get('connections') == 1 and
            ready.get('ever_armed') is False and ready.get('dropped') == [], 'Proxy readiness or drop history invalid')
    proxy.control('arm', deadline)
    audit.active = True
    # This is the actual current workload, including its original 60s deadline.
    try:
        report['payment_evidence'] = audit.data
        audit.data['payment'] = run.payment('A', 'B')
        audit.data['drop'] = proxy.control('status', deadline)
        audit.data['agreement'] = {host: {key: run.statuses[host]['nodes'][0][key]
                                          for key in ('height', 'tip', 'utxo_hash', 'utxo_count')} for host in nodes}
        audit.data['floors'].append(floors(nodes))
        validate_payment(audit.data)
        require(audit.data['renewal']['old_peer_ids'] == [report['v1_before']['id']], 'Recovery did not renew original v1 peer')
    finally:
        audit.active = False
    direct = proxy.upstream + ':23833'
    before = floors(nodes)
    unrelated = wait_peer(nodes['A'], ENDPOINT, 'v1', deadline)
    native(nodes['A'], 'register', direct, 'v2', deadline=deadline)
    run.action('A', 'peer', {'endpoint': direct})
    v2_before = wait_peer(nodes['A'], direct, 'v2', deadline)
    result = run.action('A', 'renew_peer', {'endpoint': direct, 'budget_seconds': min(10, remaining(deadline))}, timeout=10)
    validate_renewal(result, direct, 'v2')
    require(result['old_peer_ids'] == [v2_before['id']], 'V2 native target identity changed before renewal')
    report['v2'] = {'endpoint': direct, 'renewal': result, 'before': v2_before,
                    'unrelated_before': unrelated, 'unrelated_after': wait_peer(nodes['A'], ENDPOINT, 'v1', deadline),
                    'floors_before': before, 'floors_after': floors(nodes)}
    require(report['v2']['unrelated_before'] == report['v2']['unrelated_after'], 'V2 renewal changed unrelated v1 peer')
    run.action('A', 'network', {'active': False})
    before = floors(nodes)
    try:
        run.action('A', 'renew_peer', {'endpoint': ENDPOINT, 'budget_seconds': min(5, remaining(deadline))}, timeout=5)
    except controls.legacy.ConsoleError:
        refused = True
    else:
        refused = False
    report['network_off'] = {'refused': refused, **network_observation(nodes['A'], deadline),
                             'floors_before': before, 'floors_after': floors(nodes)}
    require(refused, 'Deliberate network-off renewal was admitted')
    report['proxy_stop'] = proxy.stop(deadline)


def run(descriptor, output, *, expected_head=None):
    descriptor = controls.source.validate_descriptor(descriptor)
    identity = checkout_identity(ROOT, expected_head)
    if expected_head is not None:
        require(descriptor['manifest']['source_head'] == expected_head and descriptor['manifest']['source_tree'] == identity['tree'],
                'Current-source descriptor does not match host source')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'Evidence output must be new')
    output.mkdir(mode=0o700, parents=True)
    report = {'schema': 'PQBTC-MLDSA44-PUBLIC-PEER-RECOVERY-CI-1', 'result': 'FAIL',
              'scope': 'PRIVATE_TWO_NODE_VALUELESS_TEST_ONLY', 'public_soak_credit_seconds': 0,
              'host_source': identity, 'host_control_sha256': {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                                                            for path in CONTROL_FILES},
              'native_source': {key: descriptor['manifest'][key] for key in ('source_head', 'source_tree', 'architecture')},
              'image': descriptor['image'], 'manifest_sha256': descriptor['manifest_sha256'],
              'native_payload_sha256': descriptor['manifest'].get('sha256', {}),
              'descriptor_sha256': hashlib.sha256(soak_api.canonical(descriptor)).hexdigest(),
              'baseline_red': 'RETAINED_EXTERNAL_L_EVIDENCE_NOT_REPLAYED_OR_NEW_ACCEPTANCE',
              'cleanup': [], 'cleanup_errors': [], 'watchdog_expired': False}
    nodes, controllers, proxy, guard = {}, [], None, None
    deadline = time.monotonic() + 600
    helpers = StartupHelpers(deadline)
    phase, success = 'runtime_preflight', False
    log = soak_api.EventLog(output / 'events.jsonl')

    def stop_all():
        errors = []
        try:
            helpers.stop_all()
        except Exception as error:
            errors.append(type(error).__name__)
        for node in tuple(nodes.values()):
            try:
                node.stop()
            except Exception as error:
                errors.append(type(error).__name__)
        require(not errors, 'Independent cleanup failed')

    try:
        report['runtime'] = check_runtime(descriptor)
        state = Path(tempfile.mkdtemp(prefix='pqbtc-peer-recovery-state-'))
        report['retained_host_state'] = str(state)
        guard = agent_api.DeadlineGuard(time.time() + remaining(deadline), deadline, stop_all)
        guard.start()
        phase = 'fixture_startup'
        for host in ('A', 'B'):
            remaining(deadline)
            name = 'pqbtc-mldsa-public-recovery-' + uuid.uuid4().hex
            require_fresh(name)
            controller = controls.PublicController(state / host, descriptor, container=name, p2p_port=host_port(), bootstrap=host == 'B')
            controllers.append(controller)
            helpers.attach(controller.manager, descriptor)
            node = OwnedNode(controller)
            nodes[host] = node
            controller.action('start')
            row = node.discover()
            require(row is not None and row['State']['Running'], 'Fresh native node failed startup')
            require(controller.journal['checkpoint'] is None, 'Existing custody unexpectedly adopted')
        report['owned_nodes'] = {host: {'container_id': node.container_id, 'volume_id': node.volume_id,
                                       'container': node.manager.container, 'volume': node.manager.volume} for host, node in nodes.items()}
        upstream = private_ip(nodes['B'].discover()['NetworkSettings']['Networks']['bridge']['IPAddress'])
        proxy = Proxy(nodes['A'], upstream)
        proxy.start(time.monotonic() + min(10, remaining(deadline)))
        phase = 'native_payment_and_controls'
        exercise(nodes, report, log, proxy, deadline)
        require(checkout_identity(ROOT, expected_head) == identity, 'Host control checkout changed during regression')
        success = True
    except Exception as error:
        report.update(error_class=type(error).__name__, failed_phase=phase)
    finally:
        try:
            helpers.stop_all()
        except Exception as error:
            report['cleanup_errors'].append({'phase': 'startup_helpers', 'error_class': type(error).__name__})
        # Keep the independent watchdog armed until all close/stop proofs finish.
        for controller in controllers:
            try:
                controller.close()
            except Exception as error:
                report['cleanup_errors'].append({'phase': 'graceful_close', 'error_class': type(error).__name__})
        for node in nodes.values():
            try:
                report['cleanup'].append(node.stop())
            except Exception as error:
                report['cleanup_errors'].append({'phase': 'owned_stop', 'error_class': type(error).__name__})
        if proxy is not None:
            try:
                proxy.reap()
            except Exception as error:
                report['cleanup_errors'].append({'phase': 'proxy_reap', 'error_class': type(error).__name__})
        if guard is not None:
            try:
                guard.cancel()
            except Exception as error:
                report['cleanup_errors'].append({'phase': 'watchdog', 'error_class': type(error).__name__})
            report['watchdog_expired'] = guard.expired
        report['startup_helpers'] = helpers.receipts()
        log.close()
        if success:
            try:
                validate_acceptance(report)
                report['result'] = 'PASS'
            except Exception as error:
                report.update(error_class=type(error).__name__, failed_phase='acceptance')
        soak_api.public_value(report)
        soak_api.write_immutable(output / 'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--descriptor', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expect-head')
    args = parser.parse_args()
    descriptor, raw_hash = soak_api.load_public_json(args.descriptor)
    report = run(descriptor, args.output, expected_head=args.expect_head)
    # The canonical descriptor hash is inside the report; retain the file hash
    # separately because descriptor whitespace is not native payload identity.
    soak_api.write_immutable(args.output / 'descriptor-file.json', {'sha256': raw_hash})
    print(json.dumps({'result': report['result'], 'report': str(args.output / 'report.json'), 'public_soak_credit_seconds': 0}))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
