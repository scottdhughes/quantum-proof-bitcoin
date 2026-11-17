#!/usr/bin/env python3
"""Offline relocation and re-sealed semantic controls; execute only verify.py."""
import gzip
import hashlib
import io
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


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


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
        elif row['path'] == 'events.jsonl.gz':
            origin.update(original_bytes=source['original_events']['bytes'], original_sha256=source['original_events']['sha256'])
    write_json(root / 'SOURCE.json', source)
    names = [row['path'] for row in source['files']] + ['SOURCE.json']
    (root / 'SHA256SUMS').write_text(''.join(sha((root / name).read_bytes()) + '  ' + name + '\n' for name in sorted(names)))


def json_change(name, mutate):
    def change(root):
        path = root / name
        value = json.loads(path.read_bytes())
        mutate(value)
        write_json(path, value)
        # Keep declaration/inventory/review byte joins consistent, so these
        # mutations exercise the chosen semantic gate rather than only hashes.
        if name in ('report.json', 'declaration.json'):
            bind_inventory(root)
        rebind(root)
    return change


def bind_inventory(root):
    report = json.loads((root / 'report.json').read_bytes())
    report['declaration_sha256'] = sha((root / 'declaration.json').read_bytes())
    write_json(root / 'report.json', report)
    expanded = gzip.decompress((root / 'events.jsonl.gz').read_bytes())
    inventory = {'report.json': sha((root / 'report.json').read_bytes()),
                 'declaration.json': sha((root / 'declaration.json').read_bytes()), 'events.jsonl': sha(expanded)}
    write_json(root / 'evidence-sha256.json', inventory)
    review = json.loads((root / 'independent-review.json').read_bytes())
    review.update(source_payload_sha256=inventory, inventory_sha256=sha((root / 'evidence-sha256.json').read_bytes()))
    write_json(root / 'independent-review.json', review)


def events_change(mutate, *, rechain=True, cleanup_report=False):
    def change(root):
        path = root / 'events.jsonl.gz'
        events = [json.loads(line) for line in gzip.decompress(path.read_bytes()).splitlines()]
        mutate(events)
        previous, clocks = '0' * 64, {}
        if rechain:
            for index, event in enumerate(events):
                event.update(sequence=index, previous_sha256=previous)
                event['sha256'] = sha(canonical({key: value for key, value in event.items() if key != 'sha256'}))
                previous = event['sha256']
                if event['kind'] in ('public_clock_started', 'public_clock_completed'):
                    clocks[event['kind']] = {key: event[key] for key in ('utc', 'monotonic_ns', 'data')}
        expanded = b''.join(canonical(event) + b'\n' for event in events)
        buffer = io.BytesIO()
        with gzip.GzipFile(filename='', fileobj=buffer, mode='wb', compresslevel=9, mtime=0) as stream:
            stream.write(expanded)
        path.write_bytes(buffer.getvalue())
        source = json.loads((root / 'SOURCE.json').read_bytes())
        source['original_events'].update(bytes=len(expanded), sha256=sha(expanded))
        if rechain:
            chain = {'count': len(events), 'last_sha256': previous, 'clock_boundaries': clocks}
            source['event_chain'] = chain
            for name in ('report.json', 'independent-review.json'):
                value = json.loads((root / name).read_bytes())
                value['event_chain'] = chain
                if cleanup_report and name == 'report.json':
                    value['cleanup'] = events[-2]['data']['results']
                write_json(root / name, value)
        write_json(root / 'SOURCE.json', source)
        bind_inventory(root)
        rebind(root)
    return change


def run(root):
    result = subprocess.run([sys.executable, '-I', '-B', str(VERIFIER), str(root)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    if len(result.stdout) > 8192 or len(result.stderr) > 8192:
        raise ValueError('BOUNDED_VERIFIER_OUTPUT')
    return result.returncode, json.loads(result.stdout)


def main():
    code, baseline = run(ROOT)
    if code != 0:
        raise ValueError('INITIAL_PACKET_NOT_VALID_' + str(baseline))
    source = json.loads((ROOT / 'SOURCE.json').read_bytes())
    names = [row['path'] for row in source['files']] + ['SOURCE.json', 'SHA256SUMS']
    before = {name: sha((ROOT / name).read_bytes()) for name in names}
    cases, outcomes = [], []

    def case(label, gate, name, mutate):
        cases.append((label, gate, json_change(name, mutate)))

    case('failed_report_promoted', 'FAILED_REPORT_SOURCE_OUTCOME', 'report.json', lambda x: x.update(result='PASS'))
    case('runner_source_changed', 'FAILED_REPORT_SOURCE_OUTCOME', 'report.json', lambda x: x['host_runner_source'].update(head='0' * 40))
    case('preflight_relabel', 'DECLARED_SOURCE_SCOPE_DURATION', 'declaration.json', lambda x: x.update(duration_seconds=900))
    case('profile_changed', 'DECLARED_SOURCE_SCOPE_DURATION', 'declaration.json', lambda x: x.update(profile_sha256='0' * 64))
    case('live_cause_claimed', 'UNKNOWN_CAUSE_LIMITS', 'SOURCE.json', lambda x: x.update(live_failure_cause='PROVEN_STALL'))
    case('zero_peers_claimed', 'UNKNOWN_CAUSE_LIMITS', 'SOURCE.json', lambda x: x.update(zero_peers_proven=True))
    case('later_forensic_result_claimed', 'UNKNOWN_CAUSE_LIMITS', 'SOURCE.json', lambda x: x.update(later_reproducer_or_forensic_conclusions_included=True))
    case('human_review_claimed', 'NO_COMPLETION_CREDIT_OR_ADMISSION', 'SOURCE.json', lambda x: x.update(human_review_performed=True))
    case('resumption_allowed', 'NO_COMPLETION_CREDIT_OR_ADMISSION', 'SOURCE.json', lambda x: x.update(resumption_allowed=True))
    case('partial_time_credited', 'POSITIVE_CREDIT_REFUSED', 'SOURCE.json', lambda x: x.update(public_24_hour_credit_seconds=12180))
    case('full_clock_claimed', 'NO_COMPLETION_CREDIT_OR_ADMISSION', 'SOURCE.json', lambda x: x.update(full_clock_completed=True))
    case('terminal_recovery_claimed', 'NO_COMPLETION_CREDIT_OR_ADMISSION', 'SOURCE.json', lambda x: x.update(terminal_old_backup_recovery_reached=True))
    case('worker_reap_precedes_failure', 'WORKER_EXIT_AFTER_FAILURE', 'research-closeout.json',
         lambda x: x.update(registered_worker_reaped_utc='2026-11-17T05:14:39+00:00'))
    case('research_backend_alive', 'ACTUAL_RESEARCH_STOPPED_PROOF', 'research-closeout.json', lambda x: x['failed_container'].update(pid=1))
    case('research_source_dirty', 'RESEARCH_SOURCE_AND_RESOURCE_LIMITS', 'research-closeout.json', lambda x: x['same_source'].update(status=' M file'))
    case('research_cpu_limit_changed', 'RESEARCH_SOURCE_AND_RESOURCE_LIMITS', 'research-closeout.json', lambda x: x['same_aggregate_limits'].update(**{'cpu.max': 'max 100000'}))
    case('fictitious_remaining_budget', 'DERIVED_TIMELINE_REPLAY', 'failure-timeline.json', lambda x: x.update(recorded_remaining_action_budget_seconds=0.05249))
    case('postbroadcast_checkpoint_claim', 'DERIVED_TIMELINE_REPLAY', 'failure-timeline.json', lambda x: x.update(post_broadcast_checkpoint_invariance_independently_reobserved=True))
    case('unneeded_resealed_original_change', 'PINNED_ORIGINAL_BYTES', 'independent-review.json', lambda x: x.update(observed_boundary='Changed public prose'))
    case('private_field_injection', 'PRIVATE_FIELD_REFUSED', 'SOURCE.json', lambda x: x.update(password='SYNTHETIC_TEST_ONLY'))

    def event_case(label, gate, mutate, **kwargs):
        cases.append((label, gate, events_change(mutate, **kwargs)))

    event_case('hash_chain_tamper', 'EVENT_HASH_SEQUENCE_CLOCK', lambda x: x[100].update(sha256='0' * 64), rechain=False)
    event_case('clock_completed_falsely', 'INCOMPLETE_86400_CLOCK_REQUIRED', lambda x: x[-1].update(kind='public_clock_completed'))
    event_case('normal_slot_miss', 'EXACT_COMPLETED_PAYMENT_SLOT_COUNTS',
               lambda x: next(event for event in x if event['kind'] == 'normal_slot')['data'].update(success=False))
    event_case('completed_wrong_fault', 'ONLY_CRASH_PHASE_COMPLETED',
               lambda x: next(event for event in x if event['kind'] == 'fault_completed')['data'].update(name='partition'))
    event_case('confirmed_receipt_without_relay', 'UNIQUE_PAYMENT_IDENTITY_AND_LATENCY',
               lambda x: next(event for event in x if event['kind'] == 'confirmed_payment')['data'].update(recipient_in_mempool=False))

    def first_payment_mutate(events, mode):
        payment = next(event for event in events if event['kind'] == 'confirmed_payment')
        proof = payment['data']
        for event in events[:payment['sequence']]:
            if event['kind'] != 'action':
                continue
            data = event['data']
            value = data['result']
            result = value['result'] if 'status' in value and type(value.get('result')) is dict else value
            if mode == 'relay' and data['action'] == 'transaction' and data['host'] == proof['receiver'] and result.get('txid') == proof['txid']:
                result['in_mempool'] = False
            elif mode == 'confirmation' and data['action'] == 'transaction' and data['host'] == proof['receiver'] and result.get('confirmed') is True:
                result['block_hash'] = '0' * 64
            elif mode == 'utxo' and data['action'] == 'status' and data['host'] == 'mac' and value['nodes'][0]['tip'] == proof['block_hash']:
                value['nodes'][0]['utxo_hash'] = '0' * 64
    event_case('missing_actual_recipient_relay', 'PAYMENT_NATIVE_PROOF_ORDER', lambda x: first_payment_mutate(x, 'relay'))
    event_case('wrong_receiver_confirmation_block', 'PAYMENT_NATIVE_PROOF_ORDER', lambda x: first_payment_mutate(x, 'confirmation'))
    event_case('full_utxo_disagreement', 'PAYMENT_FULL_UTXO_AGREEMENT', lambda x: first_payment_mutate(x, 'utxo'))
    event_case('pending_recipient_observed', 'PENDING_RECIPIENT_ABSENCE', lambda x: x[23236]['data']['result'].update(in_mempool=True))
    event_case('pending_rebroadcast_new_payment', 'FIVE_SAME_KNOWN_REBROADCASTS', lambda x: x[23388]['data']['result'].update(reissued_payment=True))
    event_case('pending_raw_changed', 'FIVE_SAME_KNOWN_REBROADCASTS', lambda x: x[23388]['data']['result'].update(raw_transaction_sha256='0' * 64))
    event_case('last_peer_zero', 'OBSERVED_TRANSACTION_PEERS', lambda x: x[24074]['data']['result'].update(transaction_peers=0))
    event_case('wrong_pending_transaction', 'PENDING_BROADCAST_IDENTITY', lambda x: x[23234]['data']['result']['result'].update(txid='0' * 64))

    def reissue(events):
        events[23235]['data']['action'] = events[23236]['data']['action'] = 'receive'
    event_case('receive_after_broadcast', 'NO_POST_BROADCAST_REISSUANCE', reissue)
    event_case('research_signer_identity_changed', 'H_RUNTIME_BINARY_IDENTITY',
               lambda x: x[9]['data']['result']['sha256'].update({'/tmp/demo-signer-bin/pilot-signer': '0' * 64}))
    event_case('original_volume_changed', 'TWO_ORIGINAL_VOLUME_IDENTITIES', lambda x: x[5]['data']['identity'].update(volume_id='0' * 32))
    event_case('reported_backend_not_stopped', 'BOTH_REPORTED_BACKENDS_STOPPED',
               lambda x: x[-2]['data']['results']['research']['backend_stop_proofs']['after_exit'].update(backend_stopped=False), cleanup_report=True)

    def gzip_mtime(root):
        path = root / 'events.jsonl.gz'
        value = bytearray(path.read_bytes())
        value[4] = 1
        path.write_bytes(value)
        rebind(root)
    cases.append(('gzip_nondeterministic_header', 'DETERMINISTIC_GZIP_HEADER', gzip_mtime))

    def raw_tamper(root):
        with (root / 'report.json').open('ab') as stream:
            stream.write(b' ')
    cases.append(('unsealed_byte_change', 'SEALED_FILE_HASH', raw_tamper))
    cases.append(('unexpected_member', 'EXACT_PACKET_MEMBERS', lambda root: (root / 'unexpected.txt').write_text('public')))

    def symlink(root):
        path = root / 'report.json'
        path.unlink()
        path.symlink_to('declaration.json')
    cases.append(('symlink_member', 'SYMLINK_REFUSED', symlink))

    def hardlink(root):
        path = root / 'report.json'
        path.unlink()
        os.link(root / 'declaration.json', path)
    cases.append(('hardlink_member', 'NONREGULAR_OR_HARDLINK_REFUSED', hardlink))

    def duplicate_seal(root):
        path = root / 'SHA256SUMS'
        path.write_text(path.read_text() + path.read_text().splitlines()[0] + '\n')
    cases.append(('duplicate_seal', 'SEAL_FORMAT_OR_DUPLICATE', duplicate_seal))

    with tempfile.TemporaryDirectory(prefix='.negative-controls-', dir=ROOT) as work:
        workspace = Path(work)

        def copy_to(name):
            target = workspace / name
            target.mkdir()
            for member in names:
                shutil.copyfile(ROOT / member, target / member)
            return target

        for name in ('relocated-a', 'relocated with spaces'):
            code, value = run(copy_to(name))
            if code != 0 or value.get('result') != 'VERIFIED_FAILED_L_PUBLIC_ATTEMPT':
                raise ValueError('RELOCATED_POSITIVE_FAILED_' + str(value))
            outcomes.append({'case': name, 'expected': 'VERIFIED_FAIL', 'observed': value['result']})
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
    print(json.dumps({'schema': 'PQBTC-L-FAILED-SOAK-PACKET-OFFLINE-CONTROLS-1', 'result': 'PASS',
                      'relocated_positive_controls': 2, 'gate_specific_negative_controls': len(cases),
                      'original_packet_member_hashes_unchanged': len(names), 'historical_driver_or_runtime_execution': False,
                      'controls': outcomes, 'baseline': baseline['result'], 'after': final['result']}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
