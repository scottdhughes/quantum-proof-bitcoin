#!/usr/bin/env python3
"""Exercise only the offline verifier using relocated and altered packet copies."""
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
    source = json.loads((root / 'SOURCE.json').read_bytes())
    for item in source['files']:
        raw = (root / item['path']).read_bytes()
        item.update(bytes=len(raw), sha256=digest(raw))
        origin = item.get('provenance', {})
        if origin.get('transform') == 'NONE':
            origin.update(original_bytes=len(raw), original_sha256=digest(raw))
    write_json(root / 'SOURCE.json', source)
    names = [item['path'] for item in source['files']] + ['SOURCE.json']
    (root / 'SHA256SUMS').write_text(''.join(digest((root / name).read_bytes()) + '  ' + name + '\n' for name in sorted(names)))


def run(root):
    # The executable is the original verifier, never copied/mutated helper code.
    value = subprocess.run([sys.executable, '-I', '-B', str(VERIFIER), str(root)],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    if len(value.stdout) > 4096 or len(value.stderr) > 4096:
        raise ValueError('BOUNDED_VERIFIER_OUTPUT')
    return value.returncode, json.loads(value.stdout)


def json_change(name, mutate):
    def change(root):
        path = root / name
        value = json.loads(path.read_bytes())
        mutate(value)
        write_json(path, value)
        rebind(root)
    return change


def event_change(mutate):
    def change(root):
        path = root / 'receipt/events.jsonl'
        events = [json.loads(line) for line in path.read_bytes().splitlines()]
        mutate(events)
        path.write_text(''.join(json.dumps(value, sort_keys=True) + '\n' for value in events))
        report_path = root / 'receipt/report.json'
        report = json.loads(report_path.read_bytes())
        report['events_sha256'] = digest(path.read_bytes())
        write_json(report_path, report)
        rebind(root)
    return change


def main():
    code, baseline = run(ROOT)
    if code != 0:
        raise ValueError('INITIAL_PACKET_NOT_VALID')
    source = json.loads((ROOT / 'SOURCE.json').read_bytes())
    names = [item['path'] for item in source['files']] + ['SOURCE.json', 'SHA256SUMS']
    before = {name: digest((ROOT / name).read_bytes()) for name in names}
    cases, results = [], []

    def report_case(label, gate, mutate):
        cases.append((label, gate, json_change('receipt/report.json', mutate)))

    report_case('false_pass', 'NATIVE_DIAGNOSTIC_PASS', lambda x: x.update(result='FAIL'))
    report_case('wrong_host_source', 'HOST_L_NATIVE_H_SUBJECT', lambda x: x.update(source_head='0' * 40))
    report_case('wrong_native_image', 'HOST_L_NATIVE_H_SUBJECT', lambda x: x.update(image='sha256:' + '0' * 64))
    report_case('wrong_executed_helper', 'EXECUTED_INPUT_BINDING', lambda x: x.update(helper_sha256='0' * 64))
    report_case('events_unbound', 'EVENTS_REPORT_BINDING', lambda x: x.update(events_sha256='0' * 64))
    report_case('desktop_credit', 'NO_DESKTOP_OR_SOAK_CREDIT', lambda x: x.update(desktop_restart=True))
    report_case('soak_credit', 'NO_DESKTOP_OR_SOAK_CREDIT', lambda x: x.update(public_soak_credit_seconds=86400))
    report_case('wrong_engine_arch', 'ENGINE_ARCH', lambda x: x['engine'].update(arch='x86_64'))
    report_case('only_1449_entries', 'RECOVERY_CAPACITY_AND_FLOORS', lambda x: x.update(recovery_entries=1449))
    report_case('receive_index_reused', 'RECOVERY_CAPACITY_AND_FLOORS', lambda x: x.update(post_recovery_receive_index=724))
    report_case('change_floor_reused', 'RECOVERY_CAPACITY_AND_FLOORS', lambda x: x['final_floors'].update(next_change=725))
    report_case('frame_too_short', 'EXACT_RECOVERY_FRAME', lambda x: x['bulk_restore'].update(frame_bytes=1956098))
    report_case('operator_deadline_relaxed', 'UNCHANGED_DECLARED_DEADLINES', lambda x: x['bulk_restore'].update(operator_frame_deadline_seconds=6))
    report_case('checkpoint_deadline_relaxed', 'UNCHANGED_DECLARED_DEADLINES', lambda x: x['bulk_restore'].update(checkpoint_deadline_seconds=46))
    report_case('checkpoint_not_received', 'UNCHANGED_DECLARED_DEADLINES', lambda x: x['bulk_restore'].update(checkpoint_received=False))
    report_case('negative_observed_time', 'OBSERVED_RESTORE_TIMINGS', lambda x: x['bulk_restore'].update(start_signer_elapsed_ns=-1))
    report_case('checkpoint_longer_than_whole_call', 'OBSERVED_RESTORE_TIMINGS',
                lambda x: x['bulk_restore'].update(checkpoint_wait_ns=x['bulk_restore']['start_signer_elapsed_ns'] + 1))
    report_case('invented_input_transfer_time', 'NO_DIRECT_INPUT_TIMING_CLAIM', lambda x: x['bulk_restore'].update(input_transfer_elapsed_ns=1))
    report_case('unconfirmed_new_spend', 'NEW_CONFIRMED_SELF_PAYMENT', lambda x: x['confirmed_self_payment'].update(confirmed=False))
    report_case('new_spend_still_in_mempool', 'NEW_CONFIRMED_SELF_PAYMENT', lambda x: x['confirmed_self_payment'].update(in_mempool=True))
    report_case('backend_pid_alive', 'STOPPED_RETAINED_CLEANUP', lambda x: x['cleanup'].update(pid=1))
    report_case('volume_not_retained', 'STOPPED_RETAINED_CLEANUP', lambda x: x['cleanup'].update(container_and_volume_retained=False))
    report_case('controller_close_failed', 'STOPPED_RETAINED_CLEANUP', lambda x: x.update(controller_closed_cleanly=False))

    def event_case(label, gate, mutate):
        cases.append((label, gate, event_change(mutate)))

    event_case('event_missing', 'EXACT_EVENT_COUNT', lambda x: x.pop())
    event_case('redundant_post_recovery_unlock', 'EXACT_EVENT_ACTION_ORDER', lambda x: x[16].update(action='unlock'))
    event_case('event_clock_reversed', 'EVENT_TIME_ORDER', lambda x: x[14].update(utc=x[12]['utc']))
    event_case('only_1448_batch_reservations', 'BATCH_RESERVATIONS_AND_FLOORS', lambda x: x[8].update(reservations=1448))
    event_case('retained_manifest_unbound', 'RETAINED_MANIFEST_JOIN', lambda x: x[9].update(manifest_sha256='0' * 64))
    event_case('selected_record_still_present', 'OLD_BACKUP_RECOVERY_PRECONDITION', lambda x: x[11].update(selected_record_missing=False))
    event_case('independent_journal_missing', 'OLD_BACKUP_RECOVERY_PRECONDITION', lambda x: x[11].update(independent_journal_preserved=False))
    event_case('restore_start_frame_changed', 'RESTORE_START_JOIN', lambda x: x[12].update(frame_bytes=1))
    event_case('authenticated_time_changed', 'AUTHENTICATED_RESTORE_JOIN', lambda x: x[14].update(start_signer_elapsed_ns=1))
    event_case('checkpoint_observation_changed', 'CHECKPOINT_OBSERVATION_JOIN', lambda x: x[13].update(elapsed_ns=1))
    event_case('terminal_cleanup_false', 'TERMINAL_EVENT_CLEANUP', lambda x: x[-1].update(backend_stopped=False))
    cases.append(('descriptor_has_L_instead_of_H', 'NATIVE_H_BINDING', json_change('native/arm-gcc-runtime.json',
                  lambda x: x['manifest'].update(source_head='7223772e76d2d0a0bb7fd1d35e0e16fba61918fd'))))
    cases.append(('production_claim', 'PACKET_EXCLUSIONS', json_change('SOURCE.json', lambda x: x.update(production_admitted=True))))
    cases.append(('direct_input_timing_claim', 'PACKET_EXCLUSIONS', json_change('SOURCE.json',
                  lambda x: x.update(direct_input_transfer_timing_claimed=True))))
    cases.append(('complete_workload_claim', 'CAPACITY_PREPARATION_SCOPE', json_change('SOURCE.json',
                  lambda x: x.update(full_24_hour_workload_reproduced=True))))
    cases.append(('all_ordinary_receive_claim', 'CAPACITY_PREPARATION_SCOPE', json_change('SOURCE.json',
                  lambda x: x.update(ordinary_receive_entries=1450))))

    def helper_constant(root):
        path = root / 'fixture/bulk_recovery.py'
        text = path.read_text()
        old = 'COUNT, WATCHDOG_SECONDS = 1450, 540'
        if text.count(old) != 1:
            raise ValueError('HELPER_MUTANT_NOT_EXACT')
        path.write_text(text.replace(old, 'COUNT, WATCHDOG_SECONDS = 1451, 540'))
        rebind(root)
    cases.append(('wrong_helper_capacity', 'HELPER_CONSTANTS', helper_constant))

    def raw_tamper(root):
        with (root / 'receipt/report.json').open('ab') as stream:
            stream.write(b' ')
    cases.append(('unsealed_byte_tamper', 'SEALED_FILE_HASH', raw_tamper))
    cases.append(('unexpected_file', 'EXACT_PACKET_MEMBERS', lambda root: (root / 'unexpected.txt').write_text('public')))

    def symlink(root):
        path = root / 'receipt/report.json'
        path.unlink()
        path.symlink_to('events.jsonl')
    cases.append(('symlink_member', 'FILE_TYPE', symlink))
    cases.append(('oversized_member', 'FILE_SIZE', lambda root: (root / 'receipt/report.json').write_bytes(b' ' * 131073)))

    def duplicate_seal(root):
        path = root / 'SHA256SUMS'
        path.write_text(path.read_text() + path.read_text().splitlines()[0] + '\n')
    cases.append(('duplicate_seal', 'DUPLICATE_SEAL_MEMBER', duplicate_seal))

    with tempfile.TemporaryDirectory(prefix='.negative-controls-', dir=ROOT) as workspace:
        temporary = Path(workspace)

        def copy_to(name):
            destination = temporary / name
            destination.mkdir()
            for member in names:
                path = destination / member
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / member, path)
            return destination

        for name in ('relocated-a', 'relocated with spaces'):
            code, value = run(copy_to(name))
            if code != 0 or value.get('result') != 'PASS_SELECTED_NATIVE_BULK_RECOVERY_EVIDENCE':
                raise ValueError('RELOCATED_POSITIVE_FAILED')
            results.append({'case': name, 'expected': 'PASS', 'observed': value['result']})
        for index, (name, gate, mutate) in enumerate(cases):
            destination = copy_to('negative-' + str(index))
            mutate(destination)
            code, value = run(destination)
            if code != 1 or value != {'result': 'FAIL', 'gate': gate}:
                raise ValueError('NEGATIVE_CONTROL_FAILED_' + name + '_' + str(value))
            results.append({'case': name, 'expected_gate': gate, 'observed_gate': value['gate']})
    if before != {name: digest((ROOT / name).read_bytes()) for name in names}:
        raise ValueError('ORIGINAL_PACKET_CHANGED')
    code, after = run(ROOT)
    if code != 0:
        raise ValueError('FINAL_PACKET_NOT_VALID')
    print(json.dumps({'schema': 'PQBTC-BULK-PACKET-OFFLINE-CONTROLS-1', 'result': 'PASS',
                      'relocated_positive_controls': 2, 'gate_specific_negative_controls': len(cases),
                      'original_packet_member_hashes_unchanged': len(names), 'runtime_or_historical_helper_execution': False,
                      'controls': results, 'baseline': baseline['result'], 'after': after['result']}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
