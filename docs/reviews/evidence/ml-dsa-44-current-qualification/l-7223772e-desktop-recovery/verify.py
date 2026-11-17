#!/usr/bin/env python3
"""Verify only this selected, public Desktop evidence packet; execute no driver."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HEAD = '7223772e76d2d0a0bb7fd1d35e0e16fba61918fd'
TREE = '33b36275b1da7f7fbc27fae00d519206b0f7c16f'
IMAGE = 'sha256:fc470f630a0eaa679aa49563d13b1a1e1d183528eb4348877c7cbb60b3c0e6f3'
STOP_SHA = 'df2ac6462bbecdc739b5c4242cb79a9a03d06cf146a150d4da125635d19055e9'
MAX_FILE, MAX_TOTAL = 131072, 524288
ORIGINALS = {
    'reports/attempt01.json': '819558b469e3cf8cccb1ecc553f8ad82838ed80071b970d04bd39f845b30a3aa',
    'reports/attempt02.json': 'eb9be86d2d8171cad9df36ca418c09b20a24ce7f9441fcef9816ee903f436d8e',
    'drivers/attempt01.py': '83dce920be57140ddd36d63b27b8b516c559bf0ff058272b973a785bea4baf50',
    'drivers/attempt02.py': '7ec3433ef1dd2849f4451a9003351898bfaa9176549b7eb089f2d472b41d3b7c',
    'driver-review/derivation.json': 'f6afc2adcfb6cd521548098d94dc990d1c216535245c2d74e5070aa0bc31be9a',
    'driver-review/final-review.json': 'c65f2e6d5d9bf677403e3d224e6633b6637e48f1edbabc4ea91d3f546a7432f9',
    'driver-review/driver.diff': '41b53a8882247260cc679ec2aaa3e98ce57e4fa6a01a5f2d565e7c87834303ab',
    'driver-review/test_driver_guards.py': '26c57543fc221bfc27489d56f5a1bffec7f7cb0774673d84e370c03807c1811f',
    'driver-review/test_post_recovery.py': '791c4826ffa7e30fd873498ac9c9488d5eb2fab4c7793efc4e867068e7dc3291',
    'launch/attempt01.json': 'da62d1e81317cc278f382f3123121490ca34c1197dd39f4f94e94ec29d275be2',
    'launch/attempt02.json': 'a54100a804819be8da72f03af1e899aaf1d42d7a6d1ccaf5a1d17792c9baabcb',
    'authorization/owner-order.json': '38be0752428744ad52b23cfb35e285eb88d45d26fef11f24486239b721bdeff3',
    'native/arm-gcc-runtime.json': 'c483f14b416eeb25c90d635a98f872faecda00d57259c5f35130816c2bf0eefb',
}
DERIVED = {'.gitattributes', 'README.md', 'verify.py', 'negative-controls.py',
           'verification-controls.json', 'authorization/musashi-stop-public-projection.json'}
MEMBERS = set(ORIGINALS) | DERIVED
STEPS = [
    'disposable_wallet_funded_sent_confirmed_and_paused',
    'actual_desktop_restart_existing_app_reopened',
    'desktop_stopped_existing_http_app_still_alive',
    'one_click_started_desktop_and_reused_app',
    'cold_desktop_and_new_host_app_one_click_resume',
    'old_backup_recovered_and_new_spend_confirmed',
]


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


def path_name(name):
    need(type(name) is str and name and '\\' not in name and '\n' not in name
         and not name.startswith('/') and all(part not in ('', '.', '..') for part in name.split('/')), 'SAFE_MEMBER_PATH')
    return name


def file_identity(info):
    # Reading may update atime. All other mutation/identity fields stay bound.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(root, name):
    path_name(name)
    path = root
    for component in name.split('/')[:-1]:
        path = path / component
        need(stat.S_ISDIR(path.lstat().st_mode), 'FILE_TYPE')
    path = root / name
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'FILE_TYPE')
    need(info.st_size <= MAX_FILE, 'FILE_SIZE')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(file_identity(os.fstat(descriptor)) == file_identity(info), 'FILE_CHANGED')
        chunks, count = [], 0
        while count <= MAX_FILE:
            chunk = os.read(descriptor, min(16384, MAX_FILE + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        need(count <= MAX_FILE, 'FILE_SIZE')
        raw = b''.join(chunks)
        need(len(raw) == info.st_size and file_identity(os.fstat(descriptor)) == file_identity(info)
             and file_identity(path.lstat()) == file_identity(info), 'FILE_CHANGED')
    finally:
        os.close(descriptor)
    return raw


def hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def confirmation(value, txid=None):
    need(type(value) is dict and value.get('confirmed') is True
         and type(value.get('confirmations')) is int and value['confirmations'] >= 1
         and hex64(value.get('txid')) and hex64(value.get('block_hash'))
         and (txid is None or value['txid'] == txid), 'CONFIRMED_TRANSACTION')
    return value['txid']


def status(value):
    need(type(value) is dict and value.get('ready') is True and value.get('phase') == 'running', 'APP_READY')
    wallet = value.get('wallet', {})
    need(type(wallet.get('locked')) is bool and re.fullmatch('[0-9a-f]{32}', wallet.get('wallet_id', ''))
         and all(type(wallet.get(key)) is int and wallet[key] >= 0 for key in ('next_receive', 'next_change')), 'WALLET_STATUS')
    need(type(value.get('backup_ids')) is list and len(value['backup_ids']) == 1, 'BACKUP_CONTINUITY')
    nodes = value.get('nodes')
    need(type(nodes) is list and len(nodes) == 1 and type(nodes[0].get('height')) is int
         and nodes[0]['height'] > 0 and hex64(nodes[0].get('tip')) and hex64(nodes[0].get('utxo_hash'))
         and type(nodes[0].get('network_active')) is bool, 'CHAIN_STATUS')
    return wallet


def custody(report):
    need(report.get('original_custody_preserved') is True, 'ORIGINAL_CUSTODY')
    before, after = report.get('original_before', {}), report.get('original_after', {})
    need(before.get('identity') == after.get('identity') and before.get('volume') == after.get('volume')
         and before.get('status') == after.get('status') and before.get('status', {}).get('ready') is True, 'ORIGINAL_CUSTODY')
    for key in ('id', 'image', 'mounts', 'name', 'restart'):
        need(before.get('container', {}).get(key) == after.get('container', {}).get(key), 'ORIGINAL_CUSTODY')
    need(before.get('container', {}).get('running') is True and after.get('container', {}).get('running') is True
         and type(after['container'].get('pid')) is int and after['container']['pid'] > 0, 'ORIGINAL_CUSTODY')


def report_common(report):
    need(report.get('schema') == 'PQBTC-L-ACTUAL-DESKTOP-PUBLIC-RECOVERY-1'
         and report.get('scope') == 'ONE_DISPOSABLE_PUBLIC_TEST_WALLET_HOST_APP_AND_REAL_DESKTOP_NOT_PUBLIC_SOAK', 'REPORT_SCOPE')
    need(report.get('source') == {'head': HEAD, 'tree': TREE}, 'REPORT_SOURCE')
    need(report.get('image') == IMAGE, 'REPORT_IMAGE')
    need(type(report.get('public_soak_credit_seconds')) is int and report['public_soak_credit_seconds'] == 0, 'ZERO_PUBLIC_CREDIT')
    need(report.get('app_cleanup') == 'INTENTIONAL_SIGINT_EXIT0', 'APP_CLEANUP')
    cleanup = report.get('backend_cleanup', {})
    need(cleanup.get('backend_stopped') is True and type(cleanup.get('pid')) is int and cleanup['pid'] == 0
         and cleanup.get('volume_retained') is True and cleanup.get('image') == IMAGE
         and hex64(cleanup.get('container_id')), 'BACKEND_CLEANUP')
    custody(report)


def verify_reports(data):
    first, final = parsed(data['reports/attempt01.json']), parsed(data['reports/attempt02.json'])
    for report in (first, final):
        report_common(report)
    need(first.get('result') == 'FAIL' and first.get('error_class') == 'ValueError'
         and first.get('failed_step') == STEPS[4]
         and [event.get('step') for event in first.get('events', [])] == STEPS[:5], 'HISTORICAL_FAILURE')
    need(final.get('result') == 'PASS' and final.get('native_reexecution') == 'ACTUAL_L_QUALIFIED_IMAGE'
         and final.get('secrets_written_to_artifacts') is False, 'COMPLETE_NATIVE_PASS')
    need(final.get('operating_system_reboot_performed') is False, 'NO_OS_REBOOT_CLAIM')
    events = final.get('events', [])
    need([event.get('step') for event in events] == STEPS, 'ORDERED_SIX_STEPS')
    times = [event.get('monotonic_ns') for event in events]
    need(all(type(value) is int for value in times) and all(b > a for a, b in zip(times, times[1:])), 'MONOTONIC_ORDER')
    txid = confirmation(events[0].get('confirmation'), events[0].get('txid'))
    need(events[0].get('container_id') == final['backend_cleanup']['container_id'], 'OWNED_CONTAINER_CONTINUITY')
    baseline = events[0]['status']
    baseline_wallet = status(baseline)
    need(baseline_wallet['locked'] is False and baseline['nodes'][0]['network_active'] is False, 'INITIAL_WALLET_PAUSED')
    need(baseline['nodes'][0]['tip'] == events[0]['confirmation']['block_hash'], 'INITIAL_CHAIN_MEMBERSHIP')
    for index in (1, 3, 4):
        event = events[index]
        confirmation(event.get('confirmation'), txid)
        need(event['confirmation']['block_hash'] == events[0]['confirmation']['block_hash'], 'RESTART_TRANSACTION_MEMBERSHIP')
        wallet = status(event['status'])
        need(wallet == dict(baseline_wallet, locked=True)
             and event['status']['backup_ids'] == baseline['backup_ids'], 'WALLET_BACKUP_CONTINUITY')
        need(event['status']['nodes'] == baseline['nodes'], 'RESTART_CHAIN_CONTINUITY')
    need(events[0].get('app_pid') == events[2].get('app_pid') == events[3].get('app_pid')
         == events[4].get('old_app_pid') and type(events[4].get('new_app_pid')) is int
         and events[4]['new_app_pid'] > 0 and events[4]['new_app_pid'] != events[4]['old_app_pid'], 'COLD_HOST_APP_PROCESS')
    last = events[5]
    new_txid = confirmation(last.get('confirmation'), last.get('txid'))
    need(new_txid != txid, 'NEW_CONFIRMED_SPEND')
    last_wallet = status(last['status'])
    need(last_wallet['wallet_id'] == baseline_wallet['wallet_id'] and last_wallet['locked'] is False
         and all(last_wallet[key] > baseline_wallet[key] for key in ('next_receive', 'next_change')),
         'POST_RECOVERY_COUNTERS')
    need(last['status']['backup_ids'] == baseline['backup_ids'], 'BACKUP_CONTINUITY')
    need(last['status']['nodes'][0]['height'] > baseline['nodes'][0]['height']
         and last['status']['nodes'][0]['tip'] == last['confirmation']['block_hash'], 'FINAL_CHAIN_MEMBERSHIP')
    need(final.get('final_status') == last['status'], 'FINAL_STATUS_CONTINUITY')
    need(first['backend_cleanup']['container_id'] != final['backend_cleanup']['container_id'], 'FRESH_ATTEMPT_NAMESPACE')


def verify_drivers(data):
    old, new = (data['drivers/attempt' + key + '.py'].decode('utf8') for key in ('01', '02'))
    changes = [('desktop-20261116-01', 'desktop-20261117-02', 1), ('18847', '18848', 2), ('23943', '23944', 1),
               ("        action(url, 'unlock', {'password': password})\n        recovered = action(url, 'receive')['result']",
                "        require(status(url)['wallet']['locked'] is False, 'Successful recovery did not unlock the wallet')\n        recovered = action(url, 'receive')['result']", 1)]
    reconstructed = old
    for before, after, count in changes:
        need(reconstructed.count(before) == count, 'EXACT_DRIVER_DIFF')
        reconstructed = reconstructed.replace(before, after)
    need(reconstructed == new, 'EXACT_DRIVER_DIFF')
    trees = [ast.parse(raw) for raw in (old, new)]
    functions = [{node.name: ast.dump(node, include_attributes=False) for node in tree.body
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name != 'main'} for tree in trees]
    need(functions[0] == functions[1] and len(functions[0]) == 14, 'UNCHANGED_DRIVER_GUARDS')
    # Historical drivers are parsed only; no executable code is compiled,
    # imported or executed.
    derivation = parsed(data['driver-review/derivation.json'])
    need(derivation.get('inverse_bytes_exact') is True and derivation.get('original_driver_preserved') is True
         and derivation.get('original_driver_sha256') == ORIGINALS['drivers/attempt01.py']
         and derivation.get('new_driver_sha256') == ORIGINALS['drivers/attempt02.py'], 'DRIVER_DERIVATION')
    review = parsed(data['driver-review/final-review.json'])
    need(review.get('test_count') == 24 and review.get('exact_reversible_diff') is True
         and review.get('source_head') == HEAD and review.get('source_tree') == TREE
         and review.get('source_native_CI_qualification_subject_unchanged') is True
         and review.get('unchanged_non_main_AST_function_count') == 14
         and len(review.get('tests', [])) == 2 and all(item.get('returncode') == 0 for item in review['tests']), 'DRIVER_LOCAL_REVIEW')
    need(review.get('no_actual_Desktop_Docker_HTTP_native_or_remote_execution') is True, 'LOCAL_REVIEW_SCOPE')


def verify_authorization(data):
    owner = parsed(data['authorization/owner-order.json'])
    need(owner.get('human_reply') == 'Stop the 11 and test'
         and owner.get('further_human_confirmation_required_for_this_scoped_test') is False
         and owner.get('stop_receipt_sha256') == STOP_SHA
         and owner.get('eleven_ID_verified_Musashi_containers_stopped_and_data_retained') is True
         and owner.get('operating_system_reboot_performed') is False, 'OWNER_AUTHORIZATION')
    stop = parsed(data['authorization/musashi-stop-public-projection.json'])
    need(stop.get('projection_schema') == 'PQBTC-MUSASHI-STOP-PUBLIC-PROJECTION-1'
         and stop.get('transform') == 'SELECTED_PUBLIC_FIELDS_ONLY'
         and stop.get('original_sha256') == STOP_SHA, 'STOP_PROJECTION_ORIGIN')
    need(all(stop.get(key) is True for key in ('all_images_and_volumes_unchanged', 'all_prior_containers_retained',
         'other_container_running_states_unchanged', 'original_wallet_console_running_ready_same_wallet_id')),
         'MUSASHI_DATA_RETAINED')
    before, after = stop.get('targets_before', []), stop.get('targets_after', [])
    need(len(before) == len(after) == 11 and len({item.get('Id') for item in before}) == 11
         and {item.get('Id') for item in before} == {item.get('Id') for item in after}, 'ELEVEN_BOUND_IDS')
    for item in before:
        need(hex64(item.get('Id')) and item.get('Running') is True and item.get('Created', '').startswith('2026-11-15'), 'MUSASHI_ORIGINAL_STATE')
    for item in after:
        need(item.get('Running') is False and type(item.get('Pid')) is int and item['Pid'] == 0, 'MUSASHI_STOPPED')
    for key, driver in (('01', 'drivers/attempt01.py'), ('02', 'drivers/attempt02.py')):
        launch = parsed(data['launch/attempt' + key + '.json'])
        need(launch.get('driver_sha256') == ORIGINALS[driver]
             and launch.get('owner_authorization_record_sha256') == ORIGINALS['authorization/owner-order.json']
             and launch.get('operating_system_reboot_performed') is False, 'LAUNCH_BINDING')
    launch02 = parsed(data['launch/attempt02.json'])
    need(launch02.get('no_active_public_attempt') is True, 'NO_ACTIVE_SOAK_AT_RESTART')
    need(launch02.get('prior_full_driver_report_FAIL_preserved_sha256') == ORIGINALS['reports/attempt01.json']
         and launch02.get('root24_guard_and_flow_tests_pass') is True, 'LAUNCH_REVIEW_AND_PRIOR_FAILURE')
    descriptor = parsed(data['native/arm-gcc-runtime.json'])
    need(descriptor.get('image') == IMAGE and descriptor.get('manifest', {}).get('source_head') == HEAD
         and descriptor['manifest'].get('source_tree') == TREE and descriptor['manifest'].get('architecture') == 'aarch64',
         'DESCRIPTOR_SOURCE_IMAGE')


def verify(root):
    root = root.resolve(strict=True)
    expected = MEMBERS | {'SOURCE.json', 'SHA256SUMS'}
    actual = set()
    for path in root.rglob('*'):
        if not path.is_dir() or path.is_symlink():
            actual.add(path.relative_to(root).as_posix())
    need(actual == expected, 'EXACT_PACKET_MEMBERS')
    data = {name: read(root, name) for name in expected}
    need(sum(map(len, data.values())) <= MAX_TOTAL, 'TOTAL_SIZE')
    seal = {}
    for line in data['SHA256SUMS'].decode('ascii').splitlines():
        need(len(line) > 66 and line[64:66] == '  ' and hex64(line[:64]), 'SEAL_FORMAT')
        name = path_name(line[66:])
        need(name not in seal, 'DUPLICATE_SEAL_MEMBER')
        seal[name] = line[:64]
    need(set(seal) == expected - {'SHA256SUMS'}, 'SEAL_MEMBERS')
    need(all(sha(data[name]) == digest for name, digest in seal.items()), 'SEALED_FILE_HASH')
    source = parsed(data['SOURCE.json'])
    need(source.get('schema') == 'PQBTC-L-SELECTED-DESKTOP-RECOVERY-PACKET-1'
         and source.get('source_subject') == {'head': HEAD, 'tree': TREE, 'image': IMAGE}, 'PACKET_SUBJECT')
    need(source.get('scope') == 'VALUELESS_EXPERIMENTAL_TEST_DESKTOP_RECOVERY_ONLY'
         and source.get('production_admitted') is False and source.get('human_review_performed') is False
         and source.get('operating_system_reboot_performed') is False
         and type(source.get('public_soak_credit_seconds')) is int and source['public_soak_credit_seconds'] == 0, 'PACKET_EXCLUSIONS')
    entries = source.get('files', [])
    need(type(entries) is list and len(entries) == len(MEMBERS)
         and {path_name(item.get('path')) for item in entries} == MEMBERS, 'SOURCE_MEMBERS')
    for item in entries:
        raw = data[item['path']]
        need(item.get('bytes') == len(raw) and item.get('sha256') == sha(raw), 'SOURCE_FILE_HASH')
        provenance = item.get('provenance', {})
        if item['path'] in ORIGINALS:
            need(provenance.get('transform') == 'NONE' and provenance.get('original_bytes') == len(raw)
                 and provenance.get('original_sha256') == sha(raw)
                 and provenance.get('original_verified_unchanged_after_copy') is True, 'ORIGINAL_COPY_METADATA')
    verify_reports(data)
    verify_drivers(data)
    verify_authorization(data)
    # Run semantic gates before fixed-origin pins, so re-sealed negative controls
    # can exercise those gates independently of ordinary tamper detection.
    need(all(sha(data[name]) == digest for name, digest in ORIGINALS.items()), 'PINNED_ORIGINAL_BYTES')
    return {'result': 'PASS_SELECTED_DESKTOP_EVIDENCE', 'files': len(expected),
            'unchanged_original_files': len(ORIGINALS), 'ordered_native_steps': len(STEPS),
            'operating_system_reboot_performed': False, 'public_soak_credit_seconds': 0,
            'historical_driver_execution': False, 'sha256sums_sha256': sha(data['SHA256SUMS'])}


if __name__ == '__main__':
    try:
        need(len(sys.argv) <= 2, 'ARGUMENTS')
        print(json.dumps(verify(Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parent), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, SyntaxError, UnicodeError) as error:
        # All errors are local, public metadata. Emit only the static gate name.
        message = error.args[0] if type(error) is ValueError and error.args and re.fullmatch('[A-Z_]+', str(error.args[0])) else type(error).__name__
        print(json.dumps({'result': 'FAIL', 'gate': message}, sort_keys=True))
        raise SystemExit(1) from None
