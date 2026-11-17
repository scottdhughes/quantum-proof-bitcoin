#!/usr/bin/env python3
"""Run offline copy/relocation/tamper controls; execute only this packet verifier."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
VERIFIER = ROOT / 'verify.py'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def rebind(root):
    """Re-seal test mutations so semantic rejection is independently exercised."""
    source = json.loads((root / 'SOURCE.json').read_bytes())
    for row in source['files']:
        path = root / row['path']
        if not path.is_file():
            continue
        raw = path.read_bytes()
        row.update(bytes=len(raw), sha256=digest(raw))
        provenance = row.get('provenance', {})
        if provenance.get('transform') == 'NONE':
            provenance.update(original_bytes=len(raw), original_sha256=digest(raw))
    write_json(root / 'SOURCE.json', source)
    members = [row['path'] for row in source['files']] + ['SOURCE.json']
    (root / 'SHA256SUMS').write_text(''.join(
        digest((root / name).read_bytes()) + '  ' + name + '\n' for name in sorted(members)))


def run(root):
    # Always execute the original known verifier, never a copied driver or a
    # possibly modified verifier from a negative-control copy.
    result = subprocess.run([sys.executable, '-I', '-B', str(VERIFIER), str(root)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    if len(result.stdout) > 4096 or len(result.stderr) > 4096:
        raise ValueError('BOUNDED_VERIFIER_OUTPUT')
    return result.returncode, json.loads(result.stdout)


def modify_json(name, mutate):
    def change(root):
        path = root / name
        value = json.loads(path.read_bytes())
        mutate(value)
        write_json(path, value)
        rebind(root)
    return change


def main():
    code, baseline = run(ROOT)
    if code != 0:
        raise ValueError('INITIAL_PACKET_NOT_VALID')
    source = json.loads((ROOT / 'SOURCE.json').read_bytes())
    members = [row['path'] for row in source['files']] + ['SOURCE.json', 'SHA256SUMS']
    original = {name: digest((ROOT / name).read_bytes()) for name in members}
    results = []
    cases = []

    def case(label, gate, name, mutate):
        cases.append((label, gate, modify_json(name, mutate)))

    final = 'reports/attempt02.json'
    case('result_false_pass', 'COMPLETE_NATIVE_PASS', final, lambda x: x.update(result='FAIL'))
    case('source_head', 'REPORT_SOURCE', final, lambda x: x['source'].update(head='0' * 40))
    case('source_image', 'REPORT_IMAGE', final, lambda x: x.update(image='sha256:' + '0' * 64))
    case('os_reboot_claim', 'NO_OS_REBOOT_CLAIM', final, lambda x: x.update(operating_system_reboot_performed=True))
    case('soak_time_claim', 'ZERO_PUBLIC_CREDIT', final, lambda x: x.update(public_soak_credit_seconds=86400))
    case('five_steps_only', 'ORDERED_SIX_STEPS', final, lambda x: x['events'].pop())
    case('confirmation_false', 'CONFIRMED_TRANSACTION', final, lambda x: x['events'][5]['confirmation'].update(confirmed=False))
    case('same_spend_reused', 'NEW_CONFIRMED_SPEND', final,
         lambda x: (x['events'][5].update(txid=x['events'][0]['txid']),
                    x['events'][5]['confirmation'].update(txid=x['events'][0]['txid'])))
    case('restart_wrong_block', 'RESTART_TRANSACTION_MEMBERSHIP', final,
         lambda x: x['events'][1]['confirmation'].update(block_hash='0' * 64))
    case('initial_wrong_tip', 'INITIAL_CHAIN_MEMBERSHIP', final,
         lambda x: x['events'][0]['status']['nodes'][0].update(tip='0' * 64))
    case('wallet_counter_reuse', 'POST_RECOVERY_COUNTERS', final,
         lambda x: x['events'][5]['status']['wallet'].update(next_receive=2))
    case('wallet_identity_changed', 'POST_RECOVERY_COUNTERS', final,
         lambda x: x['events'][5]['status']['wallet'].update(wallet_id='0' * 32))
    case('backup_changed', 'BACKUP_CONTINUITY', final,
         lambda x: x['events'][5]['status'].update(backup_ids=['0' * 32]))
    case('original_wallet_counter_changed', 'ORIGINAL_CUSTODY', final,
         lambda x: x['original_after']['status']['wallet'].update(next_receive=14))
    case('cleanup_pid_alive', 'BACKEND_CLEANUP', final, lambda x: x['backend_cleanup'].update(pid=1))
    case('cleanup_volume_missing', 'BACKEND_CLEANUP', final, lambda x: x['backend_cleanup'].update(volume_retained=False))
    case('same_host_process', 'COLD_HOST_APP_PROCESS', final,
         lambda x: x['events'][4].update(new_app_pid=x['events'][4]['old_app_pid']))
    case('nonmonotonic_event', 'MONOTONIC_ORDER', final,
         lambda x: x['events'][4].update(monotonic_ns=x['events'][3]['monotonic_ns']))
    case('historical_failure_promoted', 'HISTORICAL_FAILURE', 'reports/attempt01.json', lambda x: x.update(result='PASS'))
    case('owner_confirmation_reintroduced', 'OWNER_AUTHORIZATION', 'authorization/owner-order.json',
         lambda x: x.update(further_human_confirmation_required_for_this_scoped_test=True))
    case('only_ten_container_ids', 'ELEVEN_BOUND_IDS', 'authorization/musashi-stop-public-projection.json',
         lambda x: x['targets_after'].pop())
    case('musashi_still_running', 'MUSASHI_STOPPED', 'authorization/musashi-stop-public-projection.json',
         lambda x: x['targets_after'][0].update(Running=True))
    case('launch_driver_unbound', 'LAUNCH_BINDING', 'launch/attempt02.json', lambda x: x.update(driver_sha256='0' * 64))
    case('restart_during_soak', 'NO_ACTIVE_SOAK_AT_RESTART', 'launch/attempt02.json', lambda x: x.update(no_active_public_attempt=False))
    case('descriptor_other_source', 'DESCRIPTOR_SOURCE_IMAGE', 'native/arm-gcc-runtime.json',
         lambda x: x['manifest'].update(source_head='0' * 40))
    case('production_admission_claim', 'PACKET_EXCLUSIONS', 'SOURCE.json', lambda x: x.update(production_admitted=True))

    def driver_change(root):
        path = root / 'drivers/attempt02.py'
        text = path.read_text()
        old = "require(status(url)['wallet']['locked'] is False, 'Successful recovery did not unlock the wallet')"
        if text.count(old) != 1:
            raise ValueError('DRIVER_FIXTURE_NOT_EXACT')
        path.write_text(text.replace(old, old.replace('is False', 'is True')))
        rebind(root)
    cases.append(('extra_driver_behavior', 'EXACT_DRIVER_DIFF', driver_change))

    def raw_tamper(root):
        with (root / final).open('ab') as stream:
            stream.write(b' ')
    cases.append(('unsealed_byte_tamper', 'SEALED_FILE_HASH', raw_tamper))
    cases.append(('unexpected_file', 'EXACT_PACKET_MEMBERS', lambda root: (root / 'unexpected.txt').write_text('public')))

    def symlink(root):
        path = root / final
        path.unlink()
        path.symlink_to('attempt01.json')
    cases.append(('symlink_member', 'FILE_TYPE', symlink))
    cases.append(('oversized_member', 'FILE_SIZE', lambda root: (root / final).write_bytes(b' ' * 131073)))

    def duplicate_seal(root):
        path = root / 'SHA256SUMS'
        path.write_text(path.read_text() + path.read_text().splitlines()[0] + '\n')
    cases.append(('duplicate_seal_member', 'DUPLICATE_SEAL_MEMBER', duplicate_seal))

    def traversal_seal(root):
        path = root / 'SHA256SUMS'
        path.write_text(path.read_text() + '0' * 64 + '  ../outside\n')
    cases.append(('traversal_seal_member', 'SAFE_MEMBER_PATH', traversal_seal))

    with tempfile.TemporaryDirectory(prefix='.negative-controls-', dir=ROOT) as workspace:
        temporary = Path(workspace)

        def copy_to(name):
            destination = temporary / name
            destination.mkdir()
            for member in members:
                path = destination / member
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / member, path)
            return destination

        for name in ('relocated-a', 'relocated with spaces'):
            code, value = run(copy_to(name))
            if code != 0 or value.get('result') != 'PASS_SELECTED_DESKTOP_EVIDENCE':
                raise ValueError('RELOCATED_POSITIVE_FAILED')
            results.append({'case': name, 'expected': 'PASS', 'observed': value['result']})
        for index, (name, gate, mutate) in enumerate(cases):
            destination = copy_to('negative-' + str(index))
            mutate(destination)
            code, value = run(destination)
            if code != 1 or value != {'result': 'FAIL', 'gate': gate}:
                raise ValueError('NEGATIVE_CONTROL_FAILED_' + name + '_' + str(value))
            results.append({'case': name, 'expected_gate': gate, 'observed_gate': value['gate']})
    if original != {name: digest((ROOT / name).read_bytes()) for name in members}:
        raise ValueError('ORIGINAL_PACKET_CHANGED')
    code, after = run(ROOT)
    if code != 0:
        raise ValueError('FINAL_PACKET_NOT_VALID')
    print(json.dumps({'schema': 'PQBTC-DESKTOP-PACKET-OFFLINE-CONTROLS-1', 'result': 'PASS',
                      'relocated_positive_controls': 2, 'gate_specific_negative_controls': len(cases),
                      'original_packet_member_hashes_unchanged': len(members),
                      'runtime_or_historical_driver_execution': False,
                      'controls': results, 'baseline': baseline['result'], 'after': after['result']}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
