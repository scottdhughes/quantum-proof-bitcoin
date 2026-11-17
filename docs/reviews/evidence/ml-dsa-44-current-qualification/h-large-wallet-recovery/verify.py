#!/usr/bin/env python3
"""Offline verification of selected bulk-recovery evidence; no helper execution."""
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HOST = {'head': '7223772e76d2d0a0bb7fd1d35e0e16fba61918fd',
        'tree': '33b36275b1da7f7fbc27fae00d519206b0f7c16f'}
NATIVE = {'head': '52f26f31e2d8fcf52459f9cb2e9159564395f74a',
          'tree': 'd2e07ad8db149f6d3eac1cb15379d97e1484e2e6',
          'image': 'sha256:87075e6b6c13a805afaa8dcdc72b8e9cb35c78389ed6283949f1cf079b626153'}
MANIFEST = 'b9e3a8896f4012fb10fc2eb7fffabb556c1f45d391b69a3a24da5801039bf92a'
ENGINE = '4d2c0ea7-0efe-46b4-9ca7-f8cb3ee300ab'
ORIGINALS = {
    'receipt/report.json': 'd81f175d7f94b7b85f3b93433c403dacc3c08b83283ceeb0c003d44995245de4',
    'receipt/events.jsonl': 'c75c3701c1a7f19d07328fdbe179a6c100c4d37eaf7e76269943dc166defde9d',
    'fixture/bulk_recovery.py': 'c13df76b388861d7e059de8d894d1e4946128b9b558bda987e6ebd5c2bd45fcb',
    'fixture/test_bulk_recovery.py': 'ce1478c9d2460d08d49177e88364b0e458bffcf25da12fbb9c3887dfc6224181',
    'native/arm-gcc-runtime.json': 'd9cb075bfc4fdc03911eb7b0d702a622d88230a7801d9228831b2f289d869db2',
}
DERIVED = {'.gitattributes', 'README.md', 'verify.py', 'negative-controls.py', 'verification-controls.json'}
MEMBERS = set(ORIGINALS) | DERIVED
MAX_FILE, MAX_TOTAL = 131072, 393216
EVENTS = [('diagnostic_started', None), ('action_completed', 'start'), ('native_checkpoint_received', None),
          ('action_completed', 'setup'), ('action_completed', 'receive'), ('action_completed', 'backup'),
          ('native_checkpoint_received', None), ('action_completed', 'unlock'), ('independent_floors_reserved', None),
          ('native_bulk_reservations_retained', None), ('action_completed', 'lock'), ('current_record_quarantined', None),
          ('bulk_restore_started', None), ('native_checkpoint_received', None), ('bulk_restore_authenticated', None),
          ('action_completed', 'recover'), ('action_completed', 'receive'), ('action_completed', 'fund'),
          ('action_completed', 'send'), ('action_completed', 'mine'), ('action_completed', 'transaction'),
          ('action_completed', 'lock'), ('diagnostic_completed', None)]


def need(value, gate):
    if not value:
        raise ValueError(gate)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'JSON_DUPLICATE_KEY')
        result[key] = value
    return result


def parsed(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def name_ok(name):
    need(type(name) is str and name and not name.startswith('/') and '\\' not in name and '\n' not in name
         and all(item not in ('', '.', '..') for item in name.split('/')), 'SAFE_MEMBER_PATH')
    return name


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(root, name):
    name_ok(name)
    path = root
    for component in name.split('/')[:-1]:
        path /= component
        need(stat.S_ISDIR(path.lstat().st_mode), 'FILE_TYPE')
    path = root / name
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'FILE_TYPE')
    need(info.st_size <= MAX_FILE, 'FILE_SIZE')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(descriptor)) == identity(info), 'FILE_CHANGED')
        chunks, count = [], 0
        while count <= MAX_FILE:
            chunk = os.read(descriptor, min(16384, MAX_FILE + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        need(count <= MAX_FILE, 'FILE_SIZE')
        raw = b''.join(chunks)
        need(len(raw) == info.st_size and identity(os.fstat(descriptor)) == identity(info)
             and identity(path.lstat()) == identity(info), 'FILE_CHANGED')
    finally:
        os.close(descriptor)
    return raw


def hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def timestamp(value):
    need(type(value) is str, 'EVENT_UTC')
    result = datetime.fromisoformat(value)
    need(result.tzinfo == timezone.utc, 'EVENT_UTC')
    return result


def positive_int(value):
    return type(value) is int and value > 0


def verify_native_and_helper(data):
    descriptor = parsed(data['native/arm-gcc-runtime.json'])
    manifest = descriptor.get('manifest', {})
    need(descriptor.get('schema') == 'PQBTC-MLDSA44-SOURCE-RUNTIME-1' and descriptor.get('image') == NATIVE['image']
         and descriptor.get('manifest_sha256') == MANIFEST
         and manifest.get('source_head') == NATIVE['head'] and manifest.get('source_tree') == NATIVE['tree']
         and manifest.get('architecture') == 'aarch64' and manifest.get('compiler') == 'gcc', 'NATIVE_H_BINDING')
    helper = ast.parse(data['fixture/bulk_recovery.py'])
    selected = {'SOURCE_HEAD', 'SOURCE_TREE', 'IMAGE', 'MANIFEST', 'ENGINE', 'DESCRIPTOR_SHA',
                'COUNT', 'WATCHDOG_SECONDS', 'CONTROL_HASHES', 'BATCH_SCRIPT'}
    constants = {}
    for node in helper.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in selected:
            constants[target.id] = ast.literal_eval(node.value)
        if isinstance(target, ast.Tuple) and all(isinstance(item, ast.Name) and item.id in selected for item in target.elts):
            constants.update(zip((item.id for item in target.elts), ast.literal_eval(node.value), strict=True))
    need(constants.get('SOURCE_HEAD') == HOST['head'] and constants.get('SOURCE_TREE') == HOST['tree']
         and constants.get('IMAGE') == NATIVE['image'] and constants.get('MANIFEST') == MANIFEST
         and constants.get('ENGINE') == ENGINE and constants.get('DESCRIPTOR_SHA') == ORIGINALS['native/arm-gcc-runtime.json']
         and constants.get('COUNT') == 1450 and constants.get('WATCHDOG_SECONDS') == 540, 'HELPER_CONSTANTS')
    for path in ('contrib/ml-dsa-console/public_controller.py', 'contrib/ml-dsa-console/public_runtime.py'):
        host_hash = constants.get('CONTROL_HASHES', {}).get(path)
        need(hex64(host_hash) and host_hash == manifest.get('sha256', {}).get('/tmp/mldsa-demo-source/' + path),
             'MATCHING_SELECTED_H_L_CONTROL_HASHES')
    # Parsing creates ASTs only. No historical helper/test AST is executed.
    batch = ast.parse(constants.get('BATCH_SCRIPT', ''))
    native_calls = [node for node in ast.walk(batch) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'call' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'signer']
    need(len(native_calls) == 3, 'SINGLE_NATIVE_RESERVATION_PATH')
    tests = ast.parse(data['fixture/test_bulk_recovery.py'])
    test_names = [node.name for node in ast.walk(tests) if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    need(len(test_names) == 9 and len(set(test_names)) == 9, 'NINE_ORIGINAL_TESTS')


def verify_run(data):
    report = parsed(data['receipt/report.json'])
    need(report.get('schema') == 'PQBTC-BULK-RECOVERY-DIAGNOSTIC-1' and report.get('result') == 'PASS', 'NATIVE_DIAGNOSTIC_PASS')
    need(report.get('source_head') == HOST['head'] and report.get('image') == NATIVE['image'], 'HOST_L_NATIVE_H_SUBJECT')
    need(report.get('helper_sha256') == ORIGINALS['fixture/bulk_recovery.py']
         and report.get('descriptor_sha256') == ORIGINALS['native/arm-gcc-runtime.json'], 'EXECUTED_INPUT_BINDING')
    need(report.get('events_sha256') == sha(data['receipt/events.jsonl']), 'EVENTS_REPORT_BINDING')
    need(report.get('desktop_restart') is False and type(report.get('public_soak_credit_seconds')) is int
         and report['public_soak_credit_seconds'] == 0, 'NO_DESKTOP_OR_SOAK_CREDIT')
    need(report.get('engine', {}).get('id') == ENGINE and report['engine'].get('arch') == 'aarch64', 'ENGINE_ARCH')
    need(report.get('recovery_entries') == 1450 and report.get('post_recovery_receive_index') == 725
         and report.get('final_floors') == {'next_receive': 726, 'next_change': 726}, 'RECOVERY_CAPACITY_AND_FLOORS')
    need(hex64(report.get('bulk_manifest_sha256')) and re.fullmatch('[0-9a-f]{32}', report.get('volume_id', '')),
         'PUBLIC_IDENTITY_AND_MANIFEST')
    restore = report.get('bulk_restore', {})
    need(restore.get('entries') == 1450 and restore.get('frame_bytes') == 2 + 43 + 4 + 1450 * 1349,
         'EXACT_RECOVERY_FRAME')
    need(restore.get('operator_frame_deadline_seconds') == 5 and restore.get('checkpoint_deadline_seconds') == 45
         and restore.get('checkpoint_received') is True, 'UNCHANGED_DECLARED_DEADLINES')
    need(positive_int(restore.get('start_signer_elapsed_ns')) and positive_int(restore.get('checkpoint_wait_ns'))
         and restore['checkpoint_wait_ns'] <= restore['start_signer_elapsed_ns']
         and restore['checkpoint_wait_ns'] < 45 * 10**9, 'OBSERVED_RESTORE_TIMINGS')
    need('operator_input_elapsed_ns' not in restore and 'input_transfer_elapsed_ns' not in restore, 'NO_DIRECT_INPUT_TIMING_CLAIM')
    proof = report.get('confirmed_self_payment', {})
    need(proof.get('confirmed') is True and proof.get('in_mempool') is False
         and positive_int(proof.get('confirmations')) and hex64(proof.get('txid')) and hex64(proof.get('block_hash')),
         'NEW_CONFIRMED_SELF_PAYMENT')
    cleanup = report.get('cleanup', {})
    need(report.get('controller_closed_cleanly') is True and cleanup.get('backend_stopped') is True
         and type(cleanup.get('pid')) is int and cleanup['pid'] == 0 and cleanup.get('container_and_volume_retained') is True
         and cleanup.get('image') == NATIVE['image'] and hex64(cleanup.get('container_id')), 'STOPPED_RETAINED_CLEANUP')
    lines = data['receipt/events.jsonl'].splitlines()
    need(len(lines) == 23 and all(len(line) <= 2048 for line in lines), 'EXACT_EVENT_COUNT')
    events = [parsed(line) for line in lines]
    need([(event.get('event'), event.get('action')) for event in events] == EVENTS, 'EXACT_EVENT_ACTION_ORDER')
    times = [timestamp(event.get('utc')) for event in events]
    need(all(b > a for a, b in zip(times, times[1:])) and timestamp(report.get('finished_utc')) >= times[-1], 'EVENT_TIME_ORDER')
    need(events[0].get('source_head') == HOST['head'] and events[0].get('image') == NATIVE['image']
         and events[0].get('container') == 'pqbtc-mldsa-public-bulk-recovery-20261117-01', 'EVENT_SUBJECT')
    for event in events:
        if event['event'] == 'action_completed':
            need(positive_int(event.get('elapsed_ns')), 'ACTION_TIMING')
    reserved, retained, quarantined = events[8], events[9], events[11]
    need(reserved.get('reservations') == 1449 and reserved.get('next_receive') == reserved.get('next_change') == 725
         and retained.get('entries') == 1450 and retained.get('next_receive') == retained.get('next_change') == 725,
         'BATCH_RESERVATIONS_AND_FLOORS')
    need(retained.get('manifest_sha256') == report['bulk_manifest_sha256'] and positive_int(retained.get('elapsed_ns')),
         'RETAINED_MANIFEST_JOIN')
    need(quarantined.get('selected_record_missing') is True and quarantined.get('independent_journal_preserved') is True,
         'OLD_BACKUP_RECOVERY_PRECONDITION')
    started = {key: value for key, value in events[12].items() if key not in ('utc', 'event')}
    need(started == {key: restore[key] for key in ('entries', 'frame_bytes', 'operator_frame_deadline_seconds',
                                               'checkpoint_deadline_seconds')}, 'RESTORE_START_JOIN')
    authenticated = {key: value for key, value in events[14].items() if key not in ('utc', 'event')}
    need(authenticated == restore, 'AUTHENTICATED_RESTORE_JOIN')
    need(events[13].get('deadline_seconds') == 45 and events[13].get('elapsed_ns') == restore['checkpoint_wait_ns'],
         'CHECKPOINT_OBSERVATION_JOIN')
    need(events[-1].get('result') == 'PASS' and events[-1].get('backend_stopped') is True, 'TERMINAL_EVENT_CLEANUP')


def verify(root):
    root = root.resolve(strict=True)
    expected = MEMBERS | {'SOURCE.json', 'SHA256SUMS'}
    actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if not path.is_dir() or path.is_symlink()}
    need(actual == expected, 'EXACT_PACKET_MEMBERS')
    data = {name: read(root, name) for name in expected}
    need(sum(map(len, data.values())) <= MAX_TOTAL, 'TOTAL_SIZE')
    seal = {}
    for line in data['SHA256SUMS'].decode('ascii').splitlines():
        need(len(line) > 66 and line[64:66] == '  ' and hex64(line[:64]), 'SEAL_FORMAT')
        name = name_ok(line[66:])
        need(name not in seal, 'DUPLICATE_SEAL_MEMBER')
        seal[name] = line[:64]
    need(set(seal) == expected - {'SHA256SUMS'}, 'SEAL_MEMBERS')
    need(all(sha(data[name]) == digest for name, digest in seal.items()), 'SEALED_FILE_HASH')
    source = parsed(data['SOURCE.json'])
    need(source.get('schema') == 'PQBTC-SELECTED-NATIVE-BULK-RECOVERY-PACKET-1'
         and source.get('host_controller_subject') == HOST and source.get('native_subject') == NATIVE, 'PACKET_SUBJECT')
    need(source.get('scope') == 'VALUELESS_EXPERIMENTAL_TEST_RECOVERY_CAPACITY_ONLY'
         and source.get('production_admitted') is False and source.get('human_review_performed') is False
         and source.get('desktop_restart_performed') is False and source.get('operating_system_reboot_performed') is False
         and source.get('direct_input_transfer_timing_claimed') is False
         and type(source.get('public_soak_credit_seconds')) is int and source['public_soak_credit_seconds'] == 0,
         'PACKET_EXCLUSIONS')
    need(source.get('native_capacity_entries') == 1450 and source.get('ordinary_receive_entries') == 1
         and source.get('batched_native_reservations') == 1449 and source.get('full_24_hour_workload_reproduced') is False
         and source.get('public_manifest_payload_included') is False, 'CAPACITY_PREPARATION_SCOPE')
    entries = source.get('files', [])
    need(type(entries) is list and len(entries) == len(MEMBERS)
         and {name_ok(item.get('path')) for item in entries} == MEMBERS, 'SOURCE_MEMBERS')
    for item in entries:
        raw = data[item['path']]
        need(item.get('bytes') == len(raw) and item.get('sha256') == sha(raw), 'SOURCE_FILE_HASH')
        if item['path'] in ORIGINALS:
            origin = item.get('provenance', {})
            need(origin.get('transform') == 'NONE' and origin.get('original_bytes') == len(raw)
                 and origin.get('original_sha256') == sha(raw)
                 and origin.get('original_verified_unchanged_after_copy') is True, 'ORIGINAL_COPY_METADATA')
    verify_run(data)
    verify_native_and_helper(data)
    # Semantic gates precede fixed pins so re-sealed controls exercise both.
    need(all(sha(data[name]) == digest for name, digest in ORIGINALS.items()), 'PINNED_ORIGINAL_BYTES')
    return {'result': 'PASS_SELECTED_NATIVE_BULK_RECOVERY_EVIDENCE', 'files': len(expected),
            'unchanged_original_files': len(ORIGINALS), 'events': 23, 'recovery_entries': 1450,
            'historical_helper_execution': False, 'direct_input_transfer_timing_claimed': False,
            'public_soak_credit_seconds': 0, 'sha256sums_sha256': sha(data['SHA256SUMS'])}


if __name__ == '__main__':
    try:
        need(len(sys.argv) <= 2, 'ARGUMENTS')
        print(json.dumps(verify(Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parent), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, SyntaxError, UnicodeError) as error:
        message = error.args[0] if type(error) is ValueError and error.args and re.fullmatch('[A-Z_]+', str(error.args[0])) else type(error).__name__
        print(json.dumps({'result': 'FAIL', 'gate': message}, sort_keys=True))
        raise SystemExit(1) from None
