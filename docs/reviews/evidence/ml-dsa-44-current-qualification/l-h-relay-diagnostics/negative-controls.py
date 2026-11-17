#!/usr/bin/env python3
"""Run only the offline verifier on temporary copies, never historical fixtures."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
VERIFIER = ROOT / 'verify.py'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def rebind(root):
    source = json.loads((root / 'SOURCE.json').read_bytes())
    for row in source['files']:
        raw = (root / row['path']).read_bytes()
        row.update(bytes=len(raw), sha256=sha(raw))
        origin = row.get('provenance', {})
        if origin.get('transform') == 'NONE':
            origin.update(original_bytes=len(raw), original_sha256=sha(raw))
    write_json(root / 'SOURCE.json', source)
    names = [row['path'] for row in source['files']] + ['SOURCE.json']
    (root / 'SHA256SUMS').write_text(''.join(sha((root / name).read_bytes()) + '  ' + name + '\n' for name in sorted(names)))


def change_json(name, mutate):
    def change(root):
        path = root / name
        value = json.loads(path.read_bytes())
        mutate(value)
        write_json(path, value)
        rebind(root)
    return change


def change_trace(mutate):
    def change(root):
        path = root / 'controlled/run02/events.jsonl'
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        mutate(rows)
        path.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows))
        report = root / 'controlled/run02/report.json'
        value = json.loads(report.read_bytes())
        value['trace_sha256'] = sha(path.read_bytes())
        write_json(report, value)
        rebind(root)
    return change


def sender_receipt(mutate):
    def change(root):
        path = root / 'sender/run02/extraction.json'
        value = json.loads(path.read_bytes())
        mutate(value)
        write_json(path, value)
        report = root / 'sender/run02/RESULT.json'
        result = json.loads(report.read_bytes())
        result['extraction'] = value
        write_json(report, result)
        rebind(root)
    return change


def run(root):
    value = subprocess.run([sys.executable, '-I', '-B', str(VERIFIER), str(root)],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    if len(value.stdout) > 8192 or len(value.stderr) > 8192:
        raise ValueError('BOUNDED_VERIFIER_OUTPUT')
    return value.returncode, json.loads(value.stdout)


def main():
    code, baseline = run(ROOT)
    if code != 0:
        raise ValueError('INITIAL_PACKET_NOT_VALID_' + str(baseline))
    source = json.loads((ROOT / 'SOURCE.json').read_bytes())
    names = [row['path'] for row in source['files']] + ['SOURCE.json', 'SHA256SUMS']
    before = {name: sha((ROOT / name).read_bytes()) for name in names}
    cases, outcomes = [], []

    def case(label, gate, name, mutate):
        cases.append((label, gate, change_json(name, mutate)))

    c = 'controlled/run02/report.json'
    case('controlled_first_failure_promoted', 'CONTROLLED_STARTUP_FAILURE_PRESERVED', 'controlled/run01/report.json', lambda x: x.update(result='PASS'))
    case('wrong_controlled_source', 'CONTROLLED_SOURCE_TRACE_BINDING', c, lambda x: x.update(source_head='0' * 40))
    case('wrong_controlled_image', 'CONTROLLED_SOURCE_TRACE_BINDING', c, lambda x: x.update(image='sha256:' + '0' * 64))
    case('two_inventory_drops', 'ONE_MATCHING_MSG_WTX_DROP', c, lambda x: x['baseline']['proxy']['dropped'].append(dict(x['baseline']['proxy']['dropped'][0])))
    case('wrong_dropped_wtxid', 'ONE_MATCHING_MSG_WTX_DROP', c, lambda x: x['baseline']['proxy']['dropped'][0].update(hash='0' * 64))
    case('MSG_TX_instead_of_observed_MSG_WTX', 'ONE_MATCHING_MSG_WTX_DROP', c, lambda x: x['baseline']['proxy']['dropped'][0].update(type=1))
    case('connection_replaced_during_loss', 'ONE_MATCHING_MSG_WTX_DROP', c, lambda x: x['baseline']['proxy'].update(connections=2))
    case('positive_control_budget_relaxed', 'SEPARATE_POSITIVE_CONTROL_BUDGET', c, lambda x: x['positive_control'].update(budget_seconds=120))
    case('same_old_peer_ids_for_control', 'SEPARATE_POSITIVE_CONTROL_BUDGET', c, lambda x: x['positive_control'].update(peer_ids=[0, 0]))
    case('extra_signed_target_payment', 'NO_EXTRA_CONTROLLED_PAYMENTS', c, lambda x: x['action_counts'].update({'0:send': 3}))
    case('controlled_backend_alive', 'CONTROLLED_RETAINED_CLEANUP', c, lambda x: x['retained_containers'][0].update(pid=1))
    case('newline_defect_falsely_claimed', 'NO_NEWLINE_DEFECT_CLAIM', 'controlled/earlier-review-regression.json', lambda x: x['archived_lf_baseline'].update(failures=1))

    def event(rows, name):
        return next(row for row in rows if row['event'] == name)

    def trace_case(label, gate, mutate):
        cases.append((label, gate, change_trace(mutate)))

    trace_case('stale_pong', 'FRESH_SAME_PEER_PONG', lambda x: event(x, 'same_connection_same_known_rebroadcast')['before'][0].update(pong_received_after=64))
    trace_case('ping_for_different_peer', 'FRESH_SAME_PEER_PONG', lambda x: event(x, 'same_connection_same_known_rebroadcast')['after'][0].update(id=1))
    trace_case('rebroadcast_raw_bytes_changed', 'SAME_BYTES_NO_REISSUANCE', lambda x: event(x, 'same_connection_same_known_rebroadcast').update(raw_transaction_sha256='0' * 64))
    trace_case('rebroadcast_reissued', 'SAME_BYTES_NO_REISSUANCE', lambda x: event(x, 'same_connection_same_known_rebroadcast').update(reissued_payment=True))
    trace_case('loss_timer_shortened', 'ORIGINAL_LOSS_BUDGET_EXPIRED', lambda x: event(x, 'original_budget_expired_without_receipt').update(elapsed_seconds=30))
    trace_case('post_budget_recipient_present', 'POST_BUDGET_ABSENCE_AND_FLOORS', lambda x: event(x, 'post_budget_absence_and_fresh_pongs').update(recipient_absent=False))
    trace_case('post_budget_counters_changed', 'POST_BUDGET_ABSENCE_AND_FLOORS', lambda x: event(x, 'post_budget_absence_and_fresh_pongs').update(checkpoints_unchanged=False))
    trace_case('positive_control_other_bytes', 'SAME_BYTES_RECONNECT_CONFIRMATION', lambda x: event(x, 'positive_control_same_bytes_confirmed_after_exact_reconnect')['target'].update(raw_transaction_sha256='0' * 64))

    def socket_mode(root):
        path = root / 'fixtures/controlled/run02/inv_proxy.py'
        text = path.read_text()
        if text.count('os.chmod(path, 0o600)') != 1:
            raise ValueError('EXACT_PROXY_MUTANT_REQUIRED')
        path.write_text(text.replace('os.chmod(path, 0o600)', 'os.chmod(path, 0o700)'))
        rebind(root)
    cases.append(('proxy_socket_mode_regression', 'EXACT_PROXY_SOCKET_MODE_FIX', socket_mode))
    s = 'sender/run02/RESULT.json'
    case('sender_first_failure_promoted', 'SENDER_FIRST_GUARD_FAILURE', 'sender/run01/RESULT.json', lambda x: x.update(result='PASS'))
    case('original_sender_started', 'STOPPED_READONLY_SENDER_SOURCE', s, lambda x: x.update(original_node_started=True))
    case('sender_mount_writable', 'STOPPED_READONLY_SENDER_SOURCE', s, lambda x: x.update(source_mounted_read_only=False))
    case('sender_wrapper_unbound', 'SENDER_EXECUTED_CODE_BINDING', s, lambda x: x.update(wrapper_sha256='0' * 64))
    case('sender_helper_still_running', 'SENDER_HELPERS_STOPPED', s, lambda x: x['cleanup'][0].update(stopped=False))
    cases.append(('wrong_extracted_raw', 'EXACT_PENDING_TRANSACTION_EXTRACTION', sender_receipt(lambda x: x['decoded'].update(selected_raw_sha256='0' * 64))))
    cases.append(('wrong_extracted_size', 'SENDER_RECEIPT_AND_SIZE', sender_receipt(lambda x: x.update(signed_raw_bytes=3877))))
    cases.append(('sender_source_not_rechecked', 'SENDER_SOURCE_FILE_UNCHANGED', sender_receipt(lambda x: x['source_file'].update(same_identity_metadata_and_second_digest=False))))
    r = 'receiver/run03/RESULT.json'
    case('receiver_initializer_failure_promoted', 'RECEIVER_INITIALIZER_FAILURE', 'receiver/run01/remote-result-original.json', lambda x: x.update(result='PASS'))
    case('receiver02_native_verdict_invented', 'RECEIVER_PATH_FAILURE_NO_NATIVE_VERDICT', 'receiver/run02/RESULT.json', lambda x: x.update(native_verdict='ALLOWED'))
    case('nonempty_original_process_lock', 'EXACT_EMPTY_PROCESS_LOCK_METADATA', 'receiver/metadata/RESULT.json', lambda x: x['offending_entry'].update(bytes=1))
    case('native_allowed_false', 'NATIVE_ALLOWED_EXACT_PENDING_BYTES', r, lambda x: x['native_testmempoolaccept_verdict'].update(allowed=False))
    case('receiver_context_changed', 'EXACT_OFFLINE_CONTEXT_UNCHANGED', r, lambda x: x['context_after'].update(height=409))
    case('wrong_native_H_image', 'FROZEN_H_NATIVE_IMAGE', 'receiver/run03/remote-result.json', lambda x: x.update(source_image='sha256:' + '0' * 64))
    case('native_other_signed_bytes', 'NATIVE_VERDICT_RAW_IDENTITY_JOIN', 'receiver/run03/remote-native-admission-receipt.json', lambda x: x.update(bound_raw_sha256='0' * 64))
    case('transaction_admission_claimed', 'NO_NATIVE_ADMISSION_OR_BROADCAST', 'receiver/run03/remote-native-admission-receipt.json', lambda x: x.update(transaction_broadcast_or_admission_not_performed=False))
    case('private_copy_path_added', 'STRICT_PUBLIC_COPY_PATHS', 'receiver/run03/PUBLIC-COPY-MANIFEST.json', lambda x: x['files'][0].update(path='signer/current'))
    case('copy_count_wrong', 'FOURTEEN_PUBLIC_FILE_HASH_MANIFEST', 'receiver/run03/PUBLIC-COPY-MANIFEST.json', lambda x: x.update(file_count=13))
    case('source_hashes_not_rechecked', 'COPIED_SOURCE_HASHES_RECHECKED', 'receiver/run03/remote-copy-receipt.json', lambda x: x.update(source_all_selected_identity_metadata_and_hashes_rechecked=False))
    case('process_lock_not_empty', 'FRESH_CLONE_PROCESS_LOCK', 'receiver/run03/PUBLIC-COPY-MANIFEST.json', lambda x: x['omitted_process_locks'][0].update(bytes=1))
    case('failed_original_receiver_changed', 'ORIGINAL_RECEIVER_UNCHANGED', r, lambda x: x.update(original_failed_receiver_source_e6ff_stopped_unchanged_PID0=False))
    case('clone_not_stopped', 'RECEIVER_CLONE_CLEANUP', r, lambda x: x['cleanup'].update(pid=1))
    case('aggregate_quota_unbounded', 'ACTUAL_NATIVE_AND_AGGREGATE_LIMITS', 'receiver/run03/independent-live-kernel.json', lambda x: x['parent_limits'].update({'cpu.max': 'max 100000'}))
    case('sleep_misidentified_as_native', 'ACTUAL_NATIVE_AND_AGGREGATE_LIMITS', 'receiver/run03/independent-live-kernel.json', lambda x: x['native_process'].update(pid=x['container_kernel']['pid']))
    case('native_bound_to_other_clone', 'ACTUAL_NATIVE_AND_AGGREGATE_LIMITS', 'receiver/run03/independent-live-kernel.json', lambda x: x['container'].update(id='0' * 64))
    case('receiver_executed_helper_unbound', 'EXECUTED_RECEIVER_HELPER_SHA', r, lambda x: x.update(helper_sha256='0' * 64))
    case('live_cause_claimed_proven', 'CAUSAL_AND_CURRENT_FIX_LIMITS', 'SOURCE.json', lambda x: x.update(live_cause_proved=True))
    case('ephemeral_state_claimed_restored', 'CAUSAL_AND_CURRENT_FIX_LIMITS', 'SOURCE.json', lambda x: x.update(original_ephemeral_state_restored=True))
    case('M_qualification_claimed', 'CAUSAL_AND_CURRENT_FIX_LIMITS', 'SOURCE.json', lambda x: x.update(subsequent_M_fix_qualification_claimed=True))
    case('human_review_claimed', 'ZERO_CREDIT_AND_ADMISSION', 'SOURCE.json', lambda x: x.update(human_review_performed=True))
    case('public_time_claimed', 'POSITIVE_CREDIT_REFUSED', 'SOURCE.json', lambda x: x.update(public_24_hour_credit_seconds=86400))
    case('excerpt_hash_mislabeled', 'DERIVED_SUMMARY_REPLAY', 'SUMMARY.json', lambda x: x['receiver']['primary_source_excerpts'][0].update(full_source_file_sha256=x['receiver']['primary_source_excerpts'][0]['selected_excerpt_sha256']))
    case('private_field_added', 'PRIVATE_FIELD_REFUSED', 'SOURCE.json', lambda x: x.update(password='SYNTHETIC_TEST_ONLY'))
    case('referenced_launch_bytes_changed', 'RECEIVER_REFERENCED_JSON_BYTE_CLOSURE', 'receiver/run03/launch-request.json', lambda x: x.update(utc='2026-11-17T07:42:44+00:00'))

    def fixture_bytes(root):
        with (root / 'fixtures/receiver/test_research_receiver_clone.py').open('a') as stream:
            stream.write('\n# Public offline negative-control fixture.\n')
        rebind(root)
    cases.append(('resealed_unused_fixture_bytes_changed', 'PINNED_ORIGINAL_BYTES', fixture_bytes))

    def raw_tamper(root):
        with (root / c).open('ab') as stream:
            stream.write(b' ')
    cases.append(('unsealed_byte_change', 'SEALED_FILE_HASH', raw_tamper))
    cases.append(('unexpected_member', 'EXACT_PACKET_MEMBERS', lambda root: (root / 'unexpected.txt').write_text('public')))

    def symlink(root):
        path = root / c
        path.unlink()
        path.symlink_to('events.jsonl')
    cases.append(('symlink_member', 'SYMLINK_REFUSED', symlink))

    def hardlink(root):
        path = root / c
        path.unlink()
        os.link(root / 'controlled/run01/report.json', path)
    cases.append(('hardlink_member', 'NONREGULAR_OR_HARDLINK_REFUSED', hardlink))

    with tempfile.TemporaryDirectory(prefix='.negative-controls-', dir=ROOT) as work:
        workspace = Path(work)

        def copy_to(name):
            target = workspace / name
            target.mkdir()
            for member in names:
                path = target / member
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / member, path)
            return target

        for name in ('relocated-a', 'relocated with spaces'):
            code, value = run(copy_to(name))
            if code != 0 or value.get('result') != 'VERIFIED_SELECTED_RELAY_DIAGNOSTICS':
                raise ValueError('RELOCATED_POSITIVE_FAILED_' + str(value))
            outcomes.append({'case': name, 'expected': 'VERIFIED', 'observed': value['result']})
        for index, (name, gate, mutate) in enumerate(cases):
            target = copy_to('negative-' + str(index))
            mutate(target)
            code, value = run(target)
            if code != 1 or value != {'result': 'FAIL', 'gate': gate}:
                raise ValueError('NEGATIVE_CONTROL_FAILED_' + name + '_' + str(value))
            outcomes.append({'case': name, 'expected_gate': gate, 'observed_gate': value['gate']})
    if before != {name: sha((ROOT / name).read_bytes()) for name in names}:
        raise ValueError('ORIGINAL_PACKET_CHANGED')
    code, final = run(ROOT)
    if code != 0:
        raise ValueError('FINAL_PACKET_NOT_VALID')
    print(json.dumps({'schema': 'PQBTC-RELAY-DIAGNOSIS-PACKET-OFFLINE-CONTROLS-1', 'result': 'PASS',
                      'relocated_positive_controls': 2, 'gate_specific_negative_controls': len(cases),
                      'original_packet_member_hashes_unchanged': len(names), 'historical_fixture_or_runtime_execution': False,
                      'controls': outcomes, 'baseline': baseline['result'], 'after': final['result']}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
