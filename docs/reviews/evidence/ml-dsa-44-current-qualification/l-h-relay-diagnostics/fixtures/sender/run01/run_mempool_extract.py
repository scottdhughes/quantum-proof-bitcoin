#!/usr/bin/env python3
"""Extract one public signed TEST transaction; never starts an original node."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / 'sender-extraction-20261117-01'
DECODER = HERE / 'mempool_extract.py'
DECODER_SHA = '581ea271483691c0cbeba5f0448ac73b9e6452d1846e3ef04a9c14cd7e491f45'
ENGINE = '4d2c0ea7-0efe-46b4-9ca7-f8cb3ee300ab'
IMAGE = 'sha256:87075e6b6c13a805afaa8dcdc72b8e9cb35c78389ed6283949f1cf079b626153'
SOURCE_ID = '09357eb22afff16e50da4e4b1d4ca94469f3060729d6811bfdc736de3dffa63d'
SOURCE_NAME = 'pqbtc-mldsa-public-soak-r3-l-soak-20261116-01-mac'
SOURCE_VOLUME = SOURCE_NAME + '-data-v1'
NAMES = {'init': 'pqbtc-mldsa-public-relay-extract-init-20261117-01',
         'extract': 'pqbtc-mldsa-public-relay-extract-20261117-01'}
OUTPUT_VOLUME = NAMES['extract'] + '-output-v1'
LABELS = {'org.pqbtc.forensic.fixture': 'sender-mempool-20261117-01',
          'org.pqbtc.forensic.source-container': SOURCE_ID}
TXID = 'f52c9e1538c8f9aa619266c06e5389fa194b724a51a769d0b00de54db6adcb94'
RAW_SHA = 'd9216ce739ace40ebbc309eada41f54317d7f48ec7d009e95480cc9f1bd8e028'
SELECT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
          '"State":{"Running":{{json .State.Running}},"Pid":{{json .State.Pid}}},'
          '"Mounts":{{json .Mounts}},"User":{{json .Config.User}},"Labels":{{json .Config.Labels}},'
          '"NetworkMode":{{json .HostConfig.NetworkMode}},"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},'
          '"CapDrop":{{json .HostConfig.CapDrop}},"CapAdd":{{json .HostConfig.CapAdd}}}')


def require(value, label):
    if not value:
        raise ValueError(label)


def safe_guard(error):
    value = str(error) if type(error) is ValueError else ''
    return value if re.fullmatch('[A-Z0-9_]{1,96}', value) else 'UNCLASSIFIED_FAILURE'


def command(args, *, data=None, timeout=30, check=True, maximum=65536):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    require(not check or result.returncode == 0, 'OPAQUE_COMMAND_FAILURE')
    require(len(result.stdout) <= maximum, 'COMMAND_OUTPUT_BOUND')
    return result


def absent(result, name):
    messages = {f'Error: No such object: {name}', f'Error: No such container: {name}',
                f'Error response from daemon: No such container: {name}',
                f'Error: No such volume: {name}', f'Error response from daemon: get {name}: no such volume'}
    return result.returncode == 1 and result.stdout.strip() in (b'', b'[]') and result.stderr.strip() in {
        text.encode('ascii') for text in messages}


def inspect_aux(identity):
    return json.loads(command(['docker', 'inspect', '--format', SELECT, identity]).stdout)


def mounts(value):
    rows = value.get('Mounts')
    require(type(rows) is list and len(rows) <= 2, 'MOUNT_COUNT')
    return [{key: row.get(key) for key in ('Type', 'Name', 'Destination', 'RW')} for row in rows]


def volume_mount(name, target, writable):
    return {'Type': 'volume', 'Name': name, 'Destination': target, 'RW': writable}


def validate_source(value):
    require(value.get('Id') == SOURCE_ID and value.get('Name') == '/' + SOURCE_NAME and
            value.get('Image') == IMAGE and value.get('State') == {'Running': False, 'Pid': 0}, 'ORIGINAL_STOPPED_IDENTITY')
    require(mounts(value) == [volume_mount(SOURCE_VOLUME, '/var/lib/pqbtc', True)], 'ORIGINAL_VOLUME_IDENTITY')


def validate_aux(value, role, identity):
    require(role in NAMES and re.fullmatch('[0-9a-f]{64}', identity or '') and
            value.get('Id') == identity and value.get('Name') == '/' + NAMES[role] and
            value.get('Image') == IMAGE and value.get('Labels') == LABELS, 'AUX_IMMUTABLE_IDENTITY')
    require(value.get('NetworkMode') == 'none' and value.get('ReadonlyRootfs') is True and
            value.get('CapDrop') == ['ALL'], 'AUX_ISOLATION')
    require(value.get('User') == ('1001:1000' if role == 'extract' else '0:0') and
            value.get('CapAdd') in ((None, []) if role == 'extract' else (['CHOWN'],)), 'AUX_UID_CAPABILITIES')
    expected = ([volume_mount(SOURCE_VOLUME, '/sender', False)] if role == 'extract' else [])
    expected += [volume_mount(OUTPUT_VOLUME, '/out', True)]
    require(sorted(mounts(value), key=lambda row: row['Destination']) ==
            sorted(expected, key=lambda row: row['Destination']), 'AUX_EXACT_READONLY_SOURCE')


def stop_aux(identity, role):
    before = inspect_aux(identity)
    validate_aux(before, role, identity)
    if before['State']['Running']:
        command(['docker', 'stop', '--time', '5', identity], timeout=15)
    after = inspect_aux(identity)
    validate_aux(after, role, identity)
    require(after['State'] == {'Running': False, 'Pid': 0}, 'AUX_STOP_PID_PROOF')
    return {'id': identity, 'role': role, 'stopped': True, 'pid': 0, 'container_retained': True}


def bind_aux(role, identity=None):
    result = command(['docker', 'inspect', '--format', SELECT, NAMES[role]], check=False)
    if absent(result, NAMES[role]):
        require(identity is None, 'OWNED_CONTAINER_DISAPPEARED')
        return None
    require(result.returncode == 0, 'UNCERTAIN_OWNED_INSPECT')
    value = json.loads(result.stdout)
    bound = identity or value.get('Id')
    validate_aux(value, role, bound)
    return bound


def validate_receipt(value):
    require(type(value) is dict and set(value) == {
        'schema', 'result', 'source_file', 'public_volume_marker_verified', 'decoded', 'signed_raw_bytes',
        'artifact', 'no_raw_payload_stdout', 'timestamps_are_saved_metadata_fee_delta_is_not_actual_fee'}, 'PUBLIC_RECEIPT_FIELDS')
    require(value['schema'] == 'PQBTC-L-SENDER-PUBLIC-MEMPOOL-EXTRACTION-1' and value['result'] == 'PASS' and
            value['public_volume_marker_verified'] is True and value['no_raw_payload_stdout'] is True and
            value['timestamps_are_saved_metadata_fee_delta_is_not_actual_fee'] is True, 'PUBLIC_RECEIPT_RESULT')
    decoded = value['decoded']
    require(decoded['txid'] == TXID and decoded['selected_raw_sha256'] == RAW_SHA and
            decoded['version'] in (1, 2) and 1 <= decoded['record_count'] <= 10000 and
            1 <= value['signed_raw_bytes'] <= 4000000 and value['artifact'] == '/out/pending-signed-transaction.raw', 'TARGET_BINDING')
    require(re.fullmatch('[0-9a-f]{64}', value['source_file']['sha256']) and
            8 <= value['source_file']['bytes'] <= 64 * 1024 * 1024, 'SOURCE_FILE_RECEIPT')


def immutable_json(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        require(os.write(fd, raw) == len(raw), 'RECEIPT_WRITE')
        os.fsync(fd)
    finally:
        os.close(fd)


def checked_decoder():
    fd = os.open(DECODER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                info.st_mode & 0o022 == 0 and 0 < info.st_size <= 1024 * 1024, 'DECODER_FILE_GUARD')
        raw = os.read(fd, 1024 * 1024 + 1)
        require(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == DECODER_SHA, 'DECODER_REVIEW_HASH')
        return raw
    finally:
        os.close(fd)


def preflight():
    require(__debug__ and sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0, 'HOST_UID_PLATFORM')
    require('DOCKER_HOST' not in os.environ and os.environ.get('DOCKER_CONTEXT') in (None, 'desktop-linux'), 'DOCKER_ENV_SCOPE')
    os.environ['DOCKER_CONTEXT'] = 'desktop-linux'
    actual = json.loads(command(['docker', 'info', '--format',
        '{"id":{{json .ID}},"arch":{{json .Architecture}}}']).stdout)
    require(actual == {'id': ENGINE, 'arch': 'aarch64'}, 'ENGINE_BINDING')
    require(not os.path.lexists(OUTPUT) and stat.S_IMODE(HERE.lstat().st_mode) == 0o700 and
            HERE.lstat().st_uid == os.getuid(), 'FRESH_PRIVATE_HOST_OUTPUT')
    decoder_bytes = checked_decoder()
    validate_source(inspect_aux(SOURCE_ID))
    for kind, name in [('container', name) for name in NAMES.values()] + [('volume', OUTPUT_VOLUME)]:
        projection = '{{json .Id}}' if kind == 'container' else '{{json .Name}}'
        result = command(['docker', kind, 'inspect', '--format', projection, name], check=False)
        require(absent(result, name), 'FRESH_AUX_NAMESPACE')
    image = json.loads(command(['docker', 'image', 'inspect', '--format',
        '{"image":{{json .Id}},"arch":{{json .Architecture}},"os":{{json .Os}}}', IMAGE]).stdout)
    require(image == {'image': IMAGE, 'arch': 'arm64', 'os': 'linux'}, 'NATIVE_QUALIFIED_IMAGE')
    return decoder_bytes


def create(role):
    args = ['docker', 'create', '--name', NAMES[role], '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--cpus', '2', '--memory', '512m', '--pids-limit', '64',
            '--restart', 'no', '--user', '1001:1000' if role == 'extract' else '0:0']
    for key, value in LABELS.items():
        args += ['--label', key + '=' + value]
    if role == 'extract':
        args += ['--interactive', '--mount', f'type=volume,src={SOURCE_VOLUME},dst=/sender,readonly,volume-nocopy']
    else:
        args += ['--cap-add', 'CHOWN']
    args += ['--mount', f'type=volume,src={OUTPUT_VOLUME},dst=/out,volume-nocopy', '--entrypoint', '/usr/bin/python3',
             IMAGE, '-I', '-B']
    if role == 'init':
        script = ('import os,pathlib,stat;p=pathlib.Path("/out");s=p.lstat();'
                  'assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not any(p.iterdir());'
                  'os.chmod(p,0o700);os.chown(p,1001,1000)')
        args += ['-c', script]
    else:
        args += ['-', '--extract-mounted-sender-mempool']
    result = command(args)
    identity = result.stdout.decode('ascii').strip()
    require(re.fullmatch('[0-9a-f]{64}', identity), 'AUX_CREATED_ID')
    validate_aux(inspect_aux(identity), role, identity)
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.parse_args()
    decoder_bytes = preflight()
    OUTPUT.mkdir(mode=0o700)
    result = {'schema': 'PQBTC-ROOT-SENDER-MEMPOOL-EXTRACTION-1', 'result': 'FAIL',
              'source_container': SOURCE_ID, 'source_volume': SOURCE_VOLUME, 'source_image': IMAGE,
              'engine_id': ENGINE, 'decoder_sha256': DECODER_SHA, 'original_node_started': False,
              'source_mounted_read_only': True, 'public_soak_credit_seconds': 0}
    owned = {}
    try:
        args = ['docker', 'volume', 'create']
        for key, value in LABELS.items():
            args += ['--label', key + '=' + value]
        require(command(args + [OUTPUT_VOLUME]).stdout.decode().strip() == OUTPUT_VOLUME, 'NEW_OUTPUT_VOLUME')
        for role in ('init', 'extract'):
            result['last_stage'] = 'create_' + role
            identity = create(role)
            owned[role] = identity
            result['last_stage'] = 'run_' + role
            args = ['docker', 'start', '--attach'] + (['--interactive'] if role == 'extract' else []) + [identity]
            run = command(args, data=decoder_bytes if role == 'extract' else None, timeout=120, check=False)
            if run.returncode and role == 'extract':
                refusal = json.loads(run.stdout)
                guard = refusal.get('guard')
                if refusal.get('result') == 'REFUSED' and type(guard) is str and re.fullmatch('[A-Z0-9_]{1,96}', guard):
                    result['decoder_guard'] = guard
            require(run.returncode == 0, 'CONTAINED_HELPER_FAILED')
            stopped = inspect_aux(identity)
            validate_aux(stopped, role, identity)
            require(stopped['State'] == {'Running': False, 'Pid': 0}, 'NATURAL_HELPER_STOP')
            if role == 'extract':
                receipt = json.loads(run.stdout)
                validate_receipt(receipt)
                result['extraction'] = receipt
        result['last_stage'] = 'copy_selected_public_transaction'
        validate_source(inspect_aux(SOURCE_ID))
        target = OUTPUT / 'pending-signed-transaction.raw'
        command(['docker', 'cp', owned['extract'] + ':/out/pending-signed-transaction.raw', str(target)])
        info = target.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == result['extraction']['signed_raw_bytes'] and
                hashlib.sha256(target.read_bytes()).hexdigest() == RAW_SHA, 'COPIED_PUBLIC_SIGNED_RAW_BINDING')
        immutable_json(OUTPUT / 'extraction.json', result['extraction'])
        result['result'] = 'PASS'
        result['artifact'] = str(target)
    except BaseException as error:
        result['error'] = 'OPAQUE_EXTRACTION_FAILURE_NO_OPERATION_RETRIED'
        result['guard'] = safe_guard(error)
    finally:
        result['cleanup'] = []
        # A Docker create can succeed before a client timeout. Bind every fresh
        # declared name through its complete layout, even without a returned ID.
        for role in NAMES:
            try:
                identity = bind_aux(role, owned.get(role))
                result['cleanup'].append(stop_aux(identity, role) if identity is not None else
                                         {'role': role, 'container_absent': True, 'stopped': True})
            except BaseException:
                result['result'] = 'FAIL'
                result['cleanup'].append({'role': role, 'stopped': False, 'error': 'OWNED_STOP_PROOF_FAILED'})
        try:
            validate_source(inspect_aux(SOURCE_ID))
            result['original_still_stopped_same_identity'] = True
        except BaseException:
            result['result'] = 'FAIL'
            result['original_still_stopped_same_identity'] = False
        immutable_json(OUTPUT / 'RESULT.json', result)
    print(json.dumps({'result': result['result'], 'receipt': str(OUTPUT / 'RESULT.json')}))
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'result': 'REFUSED', 'error': 'EXTRACTION_PREFLIGHT_REFUSED', 'guard': safe_guard(error)}))
        raise SystemExit(2) from None
