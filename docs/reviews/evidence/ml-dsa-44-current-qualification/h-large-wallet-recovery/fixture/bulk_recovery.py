#!/usr/bin/env python3
"""Isolated 1450-entry recovery diagnostic; import performs no operations."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time

TASK = Path('/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak')
ROOT = TASK / 'candidate-l/source-clean-7223772e'
HERE = TASK / 'candidate-l/bulk-recovery-fixture-20261117-01'
STATE, EVENTS, RESULT = (HERE / name for name in ('state', 'events.jsonl', 'result.json'))
SOURCE_HEAD = '7223772e76d2d0a0bb7fd1d35e0e16fba61918fd'
SOURCE_TREE = '33b36275b1da7f7fbc27fae00d519206b0f7c16f'
DESCRIPTOR = TASK / 'candidate-h/arm-gcc-runtime.json'
DESCRIPTOR_SHA = 'd9cb075bfc4fdc03911eb7b0d702a622d88230a7801d9228831b2f289d869db2'
IMAGE = 'sha256:87075e6b6c13a805afaa8dcdc72b8e9cb35c78389ed6283949f1cf079b626153'
MANIFEST = 'b9e3a8896f4012fb10fc2eb7fffabb556c1f45d391b69a3a24da5801039bf92a'
ENGINE = '4d2c0ea7-0efe-46b4-9ca7-f8cb3ee300ab'
CONTAINER = 'pqbtc-mldsa-public-bulk-recovery-20261117-01'
VOLUME, PORT = CONTAINER + '-data-v1', 23935
PROFILE = '78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933'
COUNT, WATCHDOG_SECONDS = 1450, 540
ERROR_CLASSES = {'ValueError', 'OSError', 'ConsoleError', 'WalletError', 'TimeoutExpired',
                 'BrokenPipeError', 'RuntimeError', 'KeyboardInterrupt', 'SystemExit'}
CONTROL_HASHES = {
    'contrib/ml-dsa-console/public_controller.py': 'ba175939b711e824678d01405910f2a8e771e73f093efb30936d275cbf2ee2b5',
    'contrib/ml-dsa-console/controller.py': '8619657e00b52e7ad4f14927160a0c7359521f2845b23370cd6e3bc4d7677380',
    'contrib/ml-dsa-console/source_runtime.py': '6f68de1ebeb85aa2d082f9f863c656ec6908b1969aed25e6e434af350ed0bfce',
    'contrib/ml-dsa-qualification/public_soak_agent.py': '84c60ec4873cbe4da97603b64e4e119470bf9a5735dd98099a287ea72f5ce310',
    'contrib/ml-dsa-signer/node_wallet.py': 'ec3a8f16d4d814ae31dfd202a79be3aa2c759b4e9b17359a051a35c22f55ccac',
    'contrib/ml-dsa-console/public_runtime.py': 'c1fd5f565ab1deb6875a8e0c005e75624575456519db6f744f282a87d0e2a348',
}
# Public output only. One authenticated client subprocess per reservation, with
# no retries. This script runs only inside the owned Linux container as UID1001.
BATCH_SCRIPT = r'''
import json,sys
sys.path.insert(0, '/opt/pqbtc-runtime/seed/mldsa-demo-source/contrib/ml-dsa-signer')
from node_wallet import NativeSigner,parse_status
request=json.load(sys.stdin)
signer=NativeSigner('/opt/pqbtc-runtime/seed/mldsa-demo-build/bin/pqbtc-mldsa-client',
                    '/run/pqbtc-ipc/public/signer.sock',1000,network='test')
before=parse_status(signer.call(5))
assert before==request['before'] and before['locked'] is False
floors=[before['next_receive'],before['next_change']]
paths=set(); programs=set(); entries=[]
for branch in request['branches']:
    payload=signer.call(2,bytes([branch]))
    assert type(payload) is bytes and len(payload)==1349 and payload[0]==branch
    index=int.from_bytes(payload[1:5],'little')
    assert index==floors[branch] and (branch,index) not in paths and payload[1317:] not in programs
    paths.add((branch,index)); programs.add(payload[1317:]); floors[branch]+=1
    entries.append({'branch':branch,'index':index,'public_key':payload[5:1317].hex(),'program':payload[1317:].hex()})
after=parse_status(signer.call(5))
assert after==dict(before,next_receive=floors[0],next_change=floors[1])
print(json.dumps({'before':before,'after':after,'entries':entries},separators=(',',':')))
'''
SELECT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
          '"Config":{"Labels":{{json .Config.Labels}}},'
          '"HostConfig":{"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},'
          '"PortBindings":{{json .HostConfig.PortBindings}}},"Mounts":{{json .Mounts}},'
          '"State":{"Running":{{json .State.Running}},"Pid":{{json .State.Pid}}}}')


def require(value, label):
    if not value:
        raise ValueError(label)


def safe_error(error):
    # Never stringify exceptions: subprocess/native errors can contain input.
    name = type(error).__name__
    return {'error_class': name if name in ERROR_CLASSES else 'OTHER_EXCEPTION'}


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(args, *, check=True, timeout=30):
    value = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    require(not check or value.returncode == 0, 'COMMAND_FAILED_OPAQUE')
    require(len(value.stdout) <= 8 * 1024 * 1024, 'COMMAND_OUTPUT_BOUND')
    return value


def preflight(approved):
    require(__debug__ and sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0, 'MAC_HOST_REQUIRED')
    require(re.fullmatch(r'[0-9a-f]{64}', approved) and digest(__file__) == approved, 'HELPER_APPROVAL_HASH')
    require('DOCKER_HOST' not in os.environ and os.environ.get('DOCKER_CONTEXT') in (None, 'desktop-linux'), 'DOCKER_ENV_SCOPE')
    os.environ['DOCKER_CONTEXT'] = 'desktop-linux'  # This helper and its children only.
    info = json.loads(command(['docker', 'info', '--format',
        '{"id":{{json .ID}},"arch":{{json .Architecture}},"cpus":{{json .NCPU}},"memory":{{json .MemTotal}}}']).stdout)
    require(info['id'] == ENGINE and info['arch'] == 'aarch64' and info['cpus'] >= 2 and info['memory'] >= 2**30, 'ENGINE_ID_ARCH_CAPACITY')
    require(not any(os.path.lexists(path) for path in (STATE, EVENTS, RESULT)), 'FRESH_STATE_REQUIRED')
    parent = HERE.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, 'PRIVATE_PARENT_REQUIRED')
    for kind, name in (('container', CONTAINER), ('volume', VOLUME)):
        value = command(['docker', kind, 'inspect', name], check=False)
        require(value.returncode != 0 and (b'No such object:' in value.stderr or b'No such container:' in value.stderr
                or b'no such volume' in value.stderr.lower()), 'FRESH_DOCKER_NAMESPACE_REQUIRED')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', PORT))
    git = ['git', '-C', str(ROOT)]
    actual = tuple(command(git + args).stdout.decode().strip() for args in
                   (['rev-parse', 'HEAD'], ['rev-parse', 'HEAD^{tree}'], ['status', '--porcelain=v1', '--untracked-files=all']))
    require(actual == (SOURCE_HEAD, SOURCE_TREE, ''), 'FROZEN_SOURCE_REQUIRED')
    require(all(digest(ROOT / path) == sha for path, sha in CONTROL_HASHES.items()), 'CONTROL_HASHES')
    require(digest(DESCRIPTOR) == DESCRIPTOR_SHA, 'DESCRIPTOR_HASH')
    descriptor = json.loads(DESCRIPTOR.read_bytes())
    require((descriptor['image'], descriptor['manifest_sha256']) == (IMAGE, MANIFEST), 'DESCRIPTOR_IDENTITY')
    image = json.loads(command(['docker', 'image', 'inspect', '--format',
        '{"image":{{json .Id}},"arch":{{json .Architecture}},"os":{{json .Os}}}', IMAGE]).stdout)
    require(image == {'image': IMAGE, 'arch': 'arm64', 'os': 'linux'}, 'NATIVE_LINUX_IMAGE_REQUIRED')
    return descriptor, info


class Trace:
    def __init__(self, stream):
        self.stream = stream

    def emit(self, event, **fields):
        # Call sites supply static labels and explicitly selected scalar evidence.
        self.stream.write(json.dumps({'utc': utc(), 'event': event, **fields}, sort_keys=True) + '\n')
        self.stream.flush()
        if hasattr(self.stream, 'fileno'):
            try:
                os.fsync(self.stream.fileno())
            except (OSError, ValueError):
                pass


def plan_branches():
    return [1 if index % 2 == 0 else 0 for index in range(COUNT - 1)]


def assemble_manifest(base, batch, validate):
    require(len(base['entries']) == 1 and (base['next_receive'], base['next_change']) == (1, 0), 'INITIAL_MANIFEST')
    before = {'wallet_id': base['wallet_id'], 'next_receive': 1, 'next_change': 0, 'locked': False}
    require(batch['before'] == before and len(batch['entries']) == COUNT - 1, 'BATCH_START_COUNT')
    floors, paths, programs = [1, 0], {(0, 0)}, {base['entries'][0]['program']}
    for branch, entry in zip(plan_branches(), batch['entries'], strict=True):
        require((entry['branch'], entry['index']) == (branch, floors[branch]), 'BATCH_PATH_SEQUENCE')
        require((branch, entry['index']) not in paths and entry['program'] not in programs, 'BATCH_DUPLICATE')
        paths.add((branch, entry['index']))
        programs.add(entry['program'])
        floors[branch] += 1
    require(floors == [725, 725] and batch['after'] == dict(before, next_receive=725, next_change=725), 'BATCH_FINAL_FLOORS')
    value = copy.deepcopy(base)
    value['entries'].extend(batch['entries'])
    value.update(next_receive=725, next_change=725)
    return validate(value)


def instrument_signer(controller, trace):
    original, line = controller._start_signer, controller._line
    observations, checkpoint_waits = [], []

    def measured_line(process, timeout, maximum):
        started = time.monotonic_ns()
        value = line(process, timeout, maximum)
        if timeout == 45:
            elapsed = time.monotonic_ns() - started
            checkpoint_waits.append(elapsed)
            trace.emit('native_checkpoint_received', deadline_seconds=45, elapsed_ns=elapsed)
        return value

    def measured(password, **kwargs):
        entries = kwargs.get('public_entries')
        count = len(entries if entries is not None else (controller.journal['manifest'] or {}).get('entries', []))
        bulk = kwargs.get('retain') is False
        if bulk:
            require(count == COUNT and len(password.encode()) == 43, 'EXACT_BULK_RESTORE_FRAME')
            trace.emit('bulk_restore_started', entries=count, frame_bytes=1956099,
                       operator_frame_deadline_seconds=5, checkpoint_deadline_seconds=45)
        previous_waits = len(checkpoint_waits)
        started = time.monotonic_ns()
        result = original(password, **kwargs)
        if bulk:
            require(len(checkpoint_waits) == previous_waits + 1, 'EXACT_BULK_CHECKPOINT_OBSERVED')
            observation = {'entries': count, 'frame_bytes': 2 + 43 + 4 + count * 1349,
                           'operator_frame_deadline_seconds': 5, 'checkpoint_deadline_seconds': 45,
                           'start_signer_elapsed_ns': time.monotonic_ns() - started,
                           'checkpoint_wait_ns': checkpoint_waits[-1], 'checkpoint_received': True}
            observations.append(observation)
            trace.emit('bulk_restore_authenticated', **observation)
        return result

    controller._line, controller._start_signer = measured_line, measured
    return observations


def validate_owned(value, expected_id=None):
    require(type(value) is dict and value.get('Name') == '/' + CONTAINER and
            re.fullmatch(r'[0-9a-f]{64}', value.get('Id', '')) and
            (expected_id is None or value['Id'] == expected_id), 'CLEANUP_CONTAINER_ID')
    require(value.get('Image') == IMAGE and value.get('Config', {}).get('Labels') == {
        'org.pqbtc.console.schema': 'public-test-1', 'org.pqbtc.console.profile': PROFILE,
        'org.pqbtc.console.build': 'source-1', 'org.pqbtc.console.manifest': MANIFEST}, 'CLEANUP_IMAGE_LABELS')
    require(value.get('HostConfig') == {'ReadonlyRootfs': True, 'PortBindings': {
        '23833/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(PORT)}]}}, 'CLEANUP_PORT_ISOLATION')
    mounts = value.get('Mounts')
    require(type(mounts) is list and len(mounts) == 1 and mounts[0].get('Type') == 'volume' and
            mounts[0].get('Name') == VOLUME and mounts[0].get('Destination') == '/var/lib/pqbtc' and mounts[0].get('RW') is True,
            'CLEANUP_VOLUME')
    require(type(value.get('State', {}).get('Running')) is bool and type(value['State'].get('Pid')) is int, 'CLEANUP_STATE')
    return value['Id']


def stop_owned(controller, agent, identity):
    manager = controller.manager
    require((manager.container, manager.volume, manager.port) == (CONTAINER, VOLUME, PORT), 'CLEANUP_MANAGER_SCOPE')

    def inspect():
        result = manager.run(['inspect', '--format', SELECT, CONTAINER], check=False, timeout=10)
        if result.returncode:
            require(b'No such object:' in result.stderr or b'No such container:' in result.stderr, 'CLEANUP_INSPECT_UNCERTAIN')
            return None
        require(len(result.stdout) <= 1024 * 1024, 'CLEANUP_INSPECT_BOUND')
        value = json.loads(result.stdout)
        validate_owned(value, identity[0])
        return value

    before = inspect()
    if before is None:
        require(identity[0] is None, 'OWNED_INSTANCE_DISAPPEARED')
        return {'backend_stopped': True, 'state': 'ABSENT'}
    if identity[0] is None:
        identity[0] = before['Id']  # Fresh namespace and full immutable ownership bound above.
    volume = json.loads(manager.run(['volume', 'inspect', '--format',
        '{"name":{{json .Name}},"driver":{{json .Driver}},"options":{{json .Options}},"labels":{{json .Labels}}}', VOLUME]).stdout)
    require(volume == {'name': VOLUME, 'driver': 'local', 'options': None, 'labels': {
        'org.pqbtc.console.schema': 'public-test-1', 'org.pqbtc.console.profile': PROFILE}} or
        volume == {'name': VOLUME, 'driver': 'local', 'options': {}, 'labels': {
        'org.pqbtc.console.schema': 'public-test-1', 'org.pqbtc.console.profile': PROFILE}}, 'CLEANUP_VOLUME_LABELS')
    agent.stop_owned_public(manager)
    after = inspect()
    require(after is not None and after['Id'] == before['Id'] and after['State'] == {'Running': False, 'Pid': 0}, 'OWNED_INSTANCE_NOT_STOPPED')
    return {'backend_stopped': True, 'container_id': after['Id'], 'image': IMAGE,
            'pid': 0, 'container_and_volume_retained': True}


def exercise(controller, agent, controls, trace, identity):
    def action(name, params=None):
        started = time.monotonic_ns()
        result = controller.action(name, params or {}, **({'include_status': False} if name == 'transaction' else {}))['result']
        trace.emit('action_completed', action=name, elapsed_ns=time.monotonic_ns() - started)
        return result

    action('start')  # bootstrap=True already mines H1; no second bootstrap.
    identity[0] = validate_owned(json.loads(controller.manager.run(['inspect', '--format', SELECT, CONTAINER]).stdout))
    volume = controller.manager._read_json('public-runtime.json')
    require(volume['container'] == CONTAINER and volume['volume'] == VOLUME and volume['port'] == PORT and
            re.fullmatch(r'[0-9a-f]{32}', volume['volume_id']) and volume['volume_id'] != '0' * 32, 'VOLUME_IDENTITY')
    password = secrets.token_urlsafe(32)
    require(len(password) == 43, 'PASSWORD_GENERATOR_LENGTH')
    observations = instrument_signer(controller, trace)
    action('setup', {'password': password})
    action('receive')
    backup = action('backup')['id']
    action('unlock', {'password': password})
    base = copy.deepcopy(controller.journal['manifest'])
    before = {'wallet_id': base['wallet_id'], 'next_receive': 1, 'next_change': 0, 'locked': False}
    branches = plan_branches()
    for branch in branches:
        controller._intent(branch)
    trace.emit('independent_floors_reserved', next_receive=725, next_change=725, reservations=len(branches))
    started = time.monotonic_ns()
    # No status/actions run concurrently while native addresses are reserved.
    raw = controller._invoke('1001:1000', 'python3', '-c', BATCH_SCRIPT,
                             data=json.dumps({'before': before, 'branches': branches}).encode(), timeout=450)
    require(len(raw) <= 8 * 1024 * 1024, 'BATCH_PUBLIC_OUTPUT_BOUND')
    manifest = assemble_manifest(base, json.loads(raw), controls.validate_manifest)
    controller._retain(manifest=manifest)  # Once; never import into nonempty worker store.
    manifest_sha = hashlib.sha256(controls.canonical(manifest)).hexdigest()
    trace.emit('native_bulk_reservations_retained', entries=COUNT, elapsed_ns=time.monotonic_ns() - started,
               next_receive=725, next_change=725, manifest_sha256=manifest_sha)
    action('lock')
    quarantine = agent.Agent(controller, STATE, time.time() + WATCHDOG_SECONDS).act('quarantine_record', {})
    require(quarantine['selected_record_missing'] is True and quarantine['independent_journal_preserved'] is True and
            (quarantine['next_receive'], quarantine['next_change']) == (725, 725), 'MISSING_RECORD_FLOORS')
    trace.emit('current_record_quarantined', selected_record_missing=True, independent_journal_preserved=True)
    recovered = action('recover', {'backup_id': backup, 'password': password})
    require((recovered['next_receive'], recovered['next_change']) == (725, 725) and
            recovered['wallet_id'] == base['wallet_id'] and recovered['chain_snapshot_restored'] is False, 'RECOVERY_FLOORS')
    require(len(observations) == 1 and observations[0]['frame_bytes'] == 1956099, 'BULK_RECOVERY_OBSERVED')
    address = action('receive')
    require(address['branch'] == 0 and address['index'] == 725, 'POST_RECOVERY_ADDRESS_REUSED')
    action('fund', {'address': address['address']})
    sent = action('send', {'address': address['address'], 'amount_sats': 100000, 'fee_sats': 5000})
    require(sent.get('broadcast') is True and re.fullmatch(r'[0-9a-f]{64}', sent.get('txid', '')), 'SEND_BROADCAST')
    blocks = action('mine', {'blocks': 1})['blocks']
    require(type(blocks) is list and len(blocks) == 1 and re.fullmatch(r'[0-9a-f]{64}', blocks[0]), 'MINED_BLOCK')
    proof = action('transaction', {'txid': sent['txid'], 'block_hash': blocks[0]})
    require(proof.get('txid') == sent['txid'] and proof.get('block_hash') == blocks[0] and proof.get('confirmed') is True and
            type(proof.get('confirmations')) is int and proof['confirmations'] >= 1 and proof.get('in_mempool') is False,
            'EXACT_BLOCK_MEMBERSHIP')
    action('lock')
    point = controller.journal['checkpoint']
    require(point['wallet_id'] == base['wallet_id'] and point['next_receive'] >= 726 and point['next_change'] >= 726, 'FINAL_FLOORS')
    return {'recovery_entries': COUNT, 'bulk_restore': observations[0], 'bulk_manifest_sha256': manifest_sha,
            'volume_id': volume['volume_id'], 'post_recovery_receive_index': 725,
            'final_floors': {key: point[key] for key in ('next_receive', 'next_change')},
            'confirmed_self_payment': {key: proof[key] for key in ('txid', 'block_hash', 'confirmed', 'confirmations', 'in_mempool')}}


def import_controls():
    sys.path.insert(0, str(ROOT / 'contrib/ml-dsa-console'))
    import public_controller
    spec = importlib.util.spec_from_file_location('bulk_soak_agent', ROOT / 'contrib/ml-dsa-qualification/public_soak_agent.py')
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    return public_controller, agent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-owned-bulk-recovery', action='store_true', required=True)
    parser.add_argument('--approved-sha256', required=True)
    args = parser.parse_args(argv)
    descriptor, engine = preflight(args.approved_sha256)
    controls, agent = import_controls()
    controls.source.validate_descriptor(descriptor)
    STATE.mkdir(mode=0o700)
    fd = os.open(EVENTS, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    stream = os.fdopen(fd, 'w')
    trace = Trace(stream)
    identity, controller, guard = [None], None, None
    result = {'schema': 'PQBTC-BULK-RECOVERY-DIAGNOSTIC-1', 'result': 'FAIL', 'source_head': SOURCE_HEAD,
              'helper_sha256': args.approved_sha256, 'descriptor_sha256': DESCRIPTOR_SHA, 'image': IMAGE,
              'engine': engine, 'public_soak_credit_seconds': 0, 'desktop_restart': False}
    try:
        controller = controls.PublicController(STATE, descriptor, container=CONTAINER, p2p_port=PORT, bootstrap=True)
        guard = agent.DeadlineGuard(time.time() + WATCHDOG_SECONDS, time.monotonic() + WATCHDOG_SECONDS,
                                    lambda: stop_owned(controller, agent, identity))
        guard.start()
        trace.emit('diagnostic_started', source_head=SOURCE_HEAD, image=IMAGE, container=CONTAINER)
        result.update(exercise(controller, agent, controls, trace, identity))
        require(not guard.expired, 'WATCHDOG_EXPIRED')
        result['result'] = 'PASS'
    except BaseException as error:
        result.update(safe_error(error))
        trace.emit('diagnostic_failed', **safe_error(error))
    finally:
        if controller is not None:
            try:
                controller.close()
                result['controller_closed_cleanly'] = True
            except BaseException as error:
                result.update(result='FAIL', controller_close_error=safe_error(error))
            try:
                result['cleanup'] = stop_owned(controller, agent, identity)
            except BaseException as error:
                result.update(result='FAIL', cleanup={'backend_stopped': False, **safe_error(error)})
        else:
            result['cleanup'] = {'backend_stopped': True, 'state': 'NO_CONTROLLER'}
        if guard is not None:
            try:
                guard.cancel()
                require(not guard.expired, 'WATCHDOG_EXPIRED')
            except BaseException as error:
                result.update(result='FAIL', watchdog_error=safe_error(error))
        trace.emit('diagnostic_completed', result=result['result'], backend_stopped=result['cleanup']['backend_stopped'])
        stream.close()
        result.update(events_sha256=digest(EVENTS), finished_utc=utc())
        fd = os.open(RESULT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as receipt:
            json.dump(result, receipt, sort_keys=True, indent=2)
            receipt.write('\n')
            receipt.flush()
            os.fsync(receipt.fileno())
    print(json.dumps({'result': result['result'], 'receipt': str(RESULT), 'events': str(EVENTS)}), flush=True)
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'result': 'REFUSED_OR_EARLY_FAILURE', **safe_error(error)}), flush=True)
        raise SystemExit(2) from None
