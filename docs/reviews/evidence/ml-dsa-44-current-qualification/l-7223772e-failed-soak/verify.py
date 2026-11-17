#!/usr/bin/env python3
"""Offline verification of an immutable failed public attempt; no driver execution."""
import sys

if not __debug__ or not sys.flags.isolated:
    raise SystemExit('Use isolated, nonoptimized Python: python3 -I -B verify.py')

import ast
import collections
import datetime
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

SUBJECT = {'head': '7223772e76d2d0a0bb7fd1d35e0e16fba61918fd',
           'tree': '33b36275b1da7f7fbc27fae00d519206b0f7c16f',
           'driver_sha256': '6668f219acff79a25161d57bf505a3204ab50ef434adbb3487f913f0f913a6d0'}
CONFIG = 'd14f7f2e3217abd4d1858354a9c196746d8afe433b4209ca5664f20e61bd6a89'
PROFILE = '78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933'
SCOPE = 'VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY'
PENDING = 'f52c9e1538c8f9aa619266c06e5389fa194b724a51a769d0b00de54db6adcb94'
PENDING_RAW = 'd9216ce739ace40ebbc309eada41f54317d7f48ec7d009e95480cc9f1bd8e028'
CHAIN = '9a862bbab5586acfd6d4dae26cd16b4f46e8f88da9fffb70c087da88261f1724'
EVENT_BYTES = 11707523
EVENT_SHA = 'c623bf8b542b4ee6c2d1489ae660892e07269732f7e9c326df21dc04a4e34b85'
ORIGINALS = {
    'report.json': '27e7bbaddd26e5225a44394a58be3345214355950e94859afc228c19b9d9aae5',
    'declaration.json': '45bc12ba62feddc2566781138d094982e3a89834c8c99ebdbc3ffa8f2df27595',
    'evidence-sha256.json': '6e00bf96439463fa6c1c766b3b126c0693557cc4a0e2d4c2fb1a3f7c932a31e4',
    'frozen-l-public-soak-driver.py': SUBJECT['driver_sha256'],
    'independent-review.json': '7755bf07de9f99d3d948940b61d011eb855e4ea52aba7f7d09bcfc181b2a0cbf',
    'research-closeout.json': '813a28966030443662501fac095c5a189854a4fad0b6c0e2f517028fe71a6483',
}
DERIVED = {'.gitattributes', 'README.md', 'verify.py', 'negative-controls.py',
           'verification-controls.json', 'failure-timeline.json', 'events.jsonl.gz'}
MEMBERS = set(ORIGINALS) | DERIVED | {'SOURCE.json', 'SHA256SUMS'}
PRIVATE = {'password', 'passphrase', 'secret', 'ciphertext', 'operator_input', 'private_key', 'seed', 'wallet_seed',
           'mnemonic', 'rpcpassword', 'rpcauth', 'access_token', 'refresh_token', 'authorization', 'cookie', 'raw_transaction'}
ERROR = 'Owned agent response deadline; ambiguous operations are not retried'
STOP_IDS = {'mac': '09357eb22afff16e50da4e4b1d4ca94469f3060729d6811bfdc736de3dffa63d',
            'research': 'e6ffad0815e423a2f54088232d6b8940282dfc7be457f7599085925ad27a5666'}


def need(value, gate):
    if not value:
        raise ValueError(gate)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, 'JSON_DUPLICATE_KEY')
        value[key] = item
    return value


def parsed(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON_NONFINITE')))


def public(value):
    if type(value) is dict:
        need(not PRIVATE.intersection(key.lower() for key in value), 'PRIVATE_FIELD_REFUSED')
        for key, item in value.items():
            if 'credit' in key.lower() and type(item) in (int, float, bool):
                need(item == 0, 'POSITIVE_CREDIT_REFUSED')
            public(item)
    elif type(value) is list:
        for item in value:
            public(item)
    elif type(value) is float:
        need(math.isfinite(value), 'JSON_NONFINITE')
    elif type(value) is str:
        need(not re.search(r'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|'
                           r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|'
                           r'(?i:Authorization\s*:\s*(?:Bearer|token)\s+\S+)', value), 'CREDENTIAL_PATTERN_REFUSED')


def parts(name):
    need(type(name) is str and name and '\\' not in name and '\n' not in name, 'SAFE_MEMBER_PATH')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and not {'.', '..'}.intersection(path.parts), 'SAFE_MEMBER_PATH')
    return path.parts


def open_root(value):
    path = Path(value)
    need('..' not in path.parts, 'SAFE_ROOT_PATH')
    if not path.is_absolute():
        path = Path.cwd() / path
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for item in path.parts[1:]:
            child = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def tree(descriptor, prefix=''):
    files, directories = set(), set()
    for entry in os.scandir(descriptor):
        name = prefix + entry.name
        parts(name)
        info = entry.stat(follow_symlinks=False)
        need(not stat.S_ISLNK(info.st_mode), 'SYMLINK_REFUSED')
        if stat.S_ISDIR(info.st_mode):
            directories.add(name)
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                more, nested = tree(child, name + '/')
                files |= more
                directories |= nested
            finally:
                os.close(child)
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'NONREGULAR_OR_HARDLINK_REFUSED')
            files.add(name)
    return files, directories


def read(descriptor, name):
    components = parts(name)
    parent = os.dup(descriptor)
    limit = 8 * 1024 * 1024
    try:
        for component in components[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        child = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(child)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'NONREGULAR_OR_HARDLINK_REFUSED')
            need(before.st_size <= limit, 'FILE_SIZE_BOUND')
            chunks, count = [], 0
            while count <= limit:
                piece = os.read(child, min(65536, limit + 1 - count))
                if not piece:
                    break
                chunks.append(piece)
                count += len(piece)
            after = os.fstat(child)
            keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_gid', 'st_mode', 'st_nlink')
            need(count <= limit and count == before.st_size, 'FILE_SIZE_BOUND')
            need(tuple(getattr(before, key) for key in keys) == tuple(getattr(after, key) for key in keys), 'FILE_CHANGED')
            return b''.join(chunks)
        finally:
            os.close(child)
    finally:
        os.close(parent)


def stamp(value):
    parsed_value = datetime.datetime.fromisoformat(value)
    need(parsed_value.tzinfo is not None and parsed_value.utcoffset().total_seconds() == 0, 'UTC_REQUIRED')
    return parsed_value


def event_chain(raw):
    previous, mono, events, clocks = '0' * 64, -1, [], {}
    for sequence, line in enumerate(raw.splitlines(keepends=True)):
        need(line.endswith(b'\n') and len(line) <= 2 * 1024 * 1024, 'EVENT_LINE_BOUND')
        event = parsed(line)
        public(event)
        need(set(event) == {'sequence', 'utc', 'monotonic_ns', 'kind', 'data', 'previous_sha256', 'sha256'}, 'EVENT_FIELDS')
        need(type(event['sequence']) is int and event['sequence'] == sequence and event['previous_sha256'] == previous
             and type(event['monotonic_ns']) is int and event['monotonic_ns'] >= mono
             and sha(canonical({key: item for key, item in event.items() if key != 'sha256'})) == event['sha256'], 'EVENT_HASH_SEQUENCE_CLOCK')
        stamp(event['utc'])
        previous, mono = event['sha256'], event['monotonic_ns']
        if event['kind'] in ('public_clock_started', 'public_clock_completed'):
            need(event['kind'] not in clocks, 'DUPLICATE_CLOCK_BOUNDARY')
            clocks[event['kind']] = {key: event[key] for key in ('utc', 'monotonic_ns', 'data')}
        events.append(event)
    return events, {'count': len(events), 'last_sha256': previous, 'clock_boundaries': clocks}


def unwrapped(value):
    return value['result'] if 'status' in value and type(value.get('result')) is dict else value


def node_state(value):
    nodes = value.get('nodes', [])
    need(len(nodes) == 1 and value.get('ready') is True, 'PAYMENT_NODE_STATUS')
    return {key: nodes[0].get(key) for key in ('height', 'tip', 'utxo_hash', 'utxo_count')}


def payments_join(events, payments):
    prior, txids = -1, set()
    for payment in payments:
        proof = payment['data']
        need(proof.get('txid') not in txids and re.fullmatch('[0-9a-f]{64}', proof.get('txid', ''))
             and re.fullmatch('[0-9a-f]{64}', proof.get('block_hash', '')) and {proof['sender'], proof['receiver']} == {'mac', 'research'}
             and proof.get('recipient_in_mempool') is True and 0 <= proof['recipient_relay_seconds'] <= proof['settle_seconds'] <= 60,
             'UNIQUE_PAYMENT_IDENTITY_AND_LATENCY')
        txids.add(proof['txid'])
        sends, relays, mines, confirmations, statuses = [], [], [], {}, {}
        for event in events[prior + 1:payment['sequence']]:
            if event['kind'] != 'action':
                continue
            data = event['data']
            result = unwrapped(data['result'])
            action, host = data['action'], data['host']
            if action == 'send':
                need(host == proof['sender'] and result.get('txid') == proof['txid'] and result.get('broadcast') is True, 'PAYMENT_SEND_JOIN')
                sends.append(event['sequence'])
            elif action == 'transaction' and result.get('txid') == proof['txid']:
                if host == proof['receiver'] and result.get('in_mempool') is True:
                    relays.append(event['sequence'])
                if result.get('confirmed') is True and result.get('block_hash') == proof['block_hash']:
                    need(type(result.get('confirmations')) is int and result['confirmations'] >= 1, 'PAYMENT_CONFIRMATION_COUNT')
                    confirmations[host] = event['sequence']
            elif action == 'mine' and proof['block_hash'] in result.get('blocks', []):
                need(host == proof['sender'], 'PAYMENT_MINE_JOIN')
                mines.append(event['sequence'])
            elif action == 'status' and mines:
                state = node_state(data['result'])
                if state['tip'] == proof['block_hash']:
                    statuses[host] = state
            elif action == 'rebroadcast':
                need(result.get('reissued_payment') is False and result.get('known_in_mempool') is True, 'REBROADCAST_NO_REISSUANCE')
        need(len(sends) == len(mines) == 1 and relays and set(confirmations) == {'mac', 'research'}
             and sends[0] < relays[0] < mines[0] < min(confirmations.values()), 'PAYMENT_NATIVE_PROOF_ORDER')
        need(set(statuses) == {'mac', 'research'} and statuses['mac'] == statuses['research']
             and type(statuses['mac']['height']) is int and type(statuses['mac']['utxo_count']) is int
             and re.fullmatch('[0-9a-f]{64}', statuses['mac']['utxo_hash'] or ''), 'PAYMENT_FULL_UTXO_AGREEMENT')
        prior = payment['sequence']
    return len(txids)


def dispatches(events):
    pending, actions, dispatched = None, [], 0
    for event in events:
        if event['kind'] == 'action_dispatched':
            need(pending is None, 'OVERLAPPING_ACTION_DISPATCH')
            pending, dispatched = event, dispatched + 1
        elif event['kind'] == 'action':
            need(pending is not None and all(event['data'][key] == pending['data'][key] for key in ('host', 'action')), 'ACTION_RESPONSE_DISPATCH_JOIN')
            actions.append(event)
            pending = None
        elif event['kind'] == 'attempt_failed':
            need(pending is not None and pending['sequence'] == 24081 and pending['data'] == {'host': 'research', 'action': 'transaction'},
                 'FINAL_PENDING_QUERY')
            pending = None
    need(pending is None and dispatched == 11823 and len(actions) == 11822, 'EXACT_ACTION_COUNTS')
    return actions


def pending_timeline(events, actions, failure, start):
    send = events[23234]
    need(send['kind'] == 'action' and send['data']['host'] == 'mac' and send['data']['action'] == 'send'
         and unwrapped(send['data']['result']).get('txid') == PENDING
         and unwrapped(send['data']['result']).get('broadcast') is True, 'PENDING_BROADCAST_IDENTITY')
    tail = [event for event in actions if send['sequence'] < event['sequence'] < failure['sequence']]
    need(not any(event['data']['action'] in ('send', 'receive') for event in tail), 'NO_POST_BROADCAST_REISSUANCE')
    queries = [event for event in tail if event['data']['host'] == 'research' and event['data']['action'] == 'transaction']
    need(len(queries) == 320 and all(unwrapped(event['data']['result']) ==
         {'block_hash': None, 'confirmations': 0, 'confirmed': False, 'in_mempool': False, 'txid': PENDING} for event in queries),
         'PENDING_RECIPIENT_ABSENCE')
    broadcasts = [event for event in tail if event['data']['action'] == 'rebroadcast']
    need(len(broadcasts) == 5 and all(event['data']['host'] == 'mac' and unwrapped(event['data']['result']) ==
         {'known_in_mempool': True, 'raw_transaction_sha256': PENDING_RAW, 'rebroadcast': True,
          'reissued_payment': False, 'txid': PENDING} for event in broadcasts), 'FIVE_SAME_KNOWN_REBROADCASTS')
    peers = [event for event in actions if 23227 < event['sequence'] < failure['sequence']
             and event['data']['action'] == 'peer_status']
    need(len(peers) == 100 and all(unwrapped(event['data']['result']).get('transaction_peers') == 1
         and unwrapped(event['data']['result']).get('network_active') is True for event in peers), 'OBSERVED_TRANSACTION_PEERS')
    last_peers = {host: next(event for event in reversed(peers) if event['data']['host'] == host) for host in ('mac', 'research')}
    final_dispatch = events[24081]
    need(final_dispatch['kind'] == 'action_dispatched' and final_dispatch['data'] == {'host': 'research', 'action': 'transaction'}, 'FINAL_PENDING_QUERY')
    need(events[23227]['kind'] == 'action_dispatched' and events[23227]['data'] == {'host': 'mac', 'action': 'peer_status'}, 'INITIAL_PAYMENT_READINESS')
    elapsed = {'monotonic_seconds': (failure['monotonic_ns'] - start['monotonic_ns']) / 1e9,
               'wall_seconds': (stamp(failure['utc']) - stamp(start['utc'])).total_seconds()}
    need(elapsed == {'monotonic_seconds': 12180.020856708, 'wall_seconds': 12180.08274}, 'EXACT_PARTIAL_FAILURE_CLOCK')
    return {'schema': 'PQBTC-L-FAILED-SOAK-DERIVED-TIMELINE-1', 'result': 'FAIL', 'live_failure_cause': 'UNKNOWN',
            'public_clock_started_utc': start['utc'], 'failure_utc': failure['utc'], 'partial_clock_to_failure': elapsed,
            'pending_txid': PENDING, 'pending_raw_transaction_sha256': PENDING_RAW,
            'broadcast': {key: send[key] for key in ('sequence', 'utc')}, 'recipient_absent_completed_queries': len(queries),
            'last_completed_recipient_query': {key: queries[-1][key] for key in ('sequence', 'utc')},
            'same_known_rebroadcasts': [{key: event[key] for key in ('sequence', 'utc')} for event in broadcasts],
            'peer_status_scope': 'FIRST_PAYMENT_READINESS_THROUGH_FAILURE', 'peer_status_observations': len(peers),
            'peer_status_observations_after_broadcast': sum(event['sequence'] > send['sequence'] for event in peers),
            'last_peer_status': {host: {'sequence': event['sequence'], 'utc': event['utc'],
                                      **{key: unwrapped(event['data']['result'])[key] for key in ('peers', 'transaction_peers', 'network_active')}}
                                 for host, event in last_peers.items()},
            'final_dispatched_query': {key: final_dispatch[key] for key in ('sequence', 'utc')},
            'dispatch_to_failure_seconds': (failure['monotonic_ns'] - final_dispatch['monotonic_ns']) / 1e9,
            'recorded_remaining_action_budget_seconds': None, 'exact_payment_deadline_recorded': False,
            'post_broadcast_checkpoint_invariance_independently_reobserved': False,
            'agent_stall_proven': False, 'zero_peers_proven': False, 'public_soak_credit_seconds': 0}


def declared_context(declaration, events, actions):
    need(declaration.get('host_runner_source') == SUBJECT and declaration.get('configuration_sha256') == CONFIG
         and declaration.get('schema') == 'PQBTC-MLDSA44-PUBLIC-SOAK-DECLARATION-1' and declaration.get('mode') == 'soak'
         and declaration.get('duration_seconds') == 86400 and declaration.get('normal_slot_seconds') == 60
         and declaration.get('profile_sha256') == PROFILE and declaration.get('scope') == SCOPE
         and declaration.get('production_admitted') is False, 'DECLARED_SOURCE_SCOPE_DURATION')
    need([phase['name'] for phase in declaration['faults']] ==
         ['crash', 'partition', 'hostile', 'old_backup_missing_record', 'reindex', 'upgrade', 'rollback'], 'DECLARED_SEVEN_PHASES')
    for host in ('mac', 'research'):
        audit = declaration['host_execution_audit'][host]
        need(audit['source_head'] == SUBJECT['head'] and audit['source_tree'] == SUBJECT['tree'] and audit['clean'] is True,
             'CLEAN_HOST_CONTROL_SOURCE')
        need(all(declaration['initial_namespace_absence'][host].values()), 'FRESH_DECLARED_NAMESPACES')
    identities = [event for event in actions if event['data']['action'] == 'identity']
    need(len(identities) == 3, 'THREE_H_RUNTIME_IDENTITY_CHECKS')
    hosts = {host['name']: host for host in declaration['hosts']}
    for event in identities:
        host = event['data']['host']
        value = unwrapped(event['data']['result'])
        version = hosts[host]['versions']['a']
        need(value.get('source_head') == version['source_head'] and value.get('source_tree') == version['source_tree']
             and value.get('image') == version['image'] and value.get('architecture') == version['architecture']
             and value['sha256']['/tmp/mldsa-demo-build/bin/pqbtcd'] == version['node_sha256']
             and value['sha256']['/tmp/demo-signer-bin/pilot-signer'] == version['signer_sha256'], 'H_RUNTIME_BINARY_IDENTITY')
    bound = [event['data'] for event in events if event['kind'] == 'initial_volume_bound']
    need(len(bound) == 2 and {row['host']: row['identity'] for row in bound} == declaration['original_volume_identities'],
         'TWO_ORIGINAL_VOLUME_IDENTITIES')


def cleanup_join(report, review, closeout, events, failure):
    need(report.get('cleanup_ok') is True and events[-1]['kind'] == 'attempt_completed'
         and events[-1]['data'] == {'cleanup_ok': True, 'result': 'FAIL'}, 'TERMINAL_FAILED_CLEANUP')
    cleanup = events[-2]
    need(cleanup['kind'] == 'cleanup' and cleanup['data']['errors'] == [] and cleanup['data']['results'] == report['cleanup'], 'CLEANUP_EVENT_REPORT_JOIN')
    for host, identity in STOP_IDS.items():
        value = report['cleanup'][host]
        stop = value['backend_stop_proofs']['after_exit']
        need(value['exit_code'] == 0 and value['stderr_bytes'] == 0 and stop['backend_stopped'] is True
             and stop['state'] == 'STOPPED' and stop['last_id'] == identity and identity in stop['stopped_ids'], 'BOTH_REPORTED_BACKENDS_STOPPED')
    need(review.get('recorded_cleanup_ok') is True and review.get('recorded_both_owned_backends_STOPPED') is True, 'REVIEW_CLEANUP_JOIN')
    need(closeout.get('result') == 'PASS_ACTUAL_OWNED_RESEARCH_FAILURE_CLEANUP_VERIFIED'
         and closeout.get('failed_attempt_result') == 'FAIL' and closeout.get('failed_attempt_error') == ERROR
         and closeout.get('failed_at_utc') == failure['utc'] and closeout.get('public_soak_elapsed_credit_seconds') == 0,
         'RESEARCH_CLOSEOUT_FAILURE_BINDING')
    container = closeout.get('failed_container', {})
    need(container.get('id') == STOP_IDS['research'] and container.get('running') is False and container.get('pid') == 0
         and closeout.get('exact_agent_worker_tracer_gone_units_collected') is True
         and all(not value['running'] for value in closeout['same_engines'].values()), 'ACTUAL_RESEARCH_STOPPED_PROOF')
    need(closeout['same_source'] == {'head': SUBJECT['head'], 'tree': SUBJECT['tree'], 'status': ''}
         and closeout['same_aggregate_limits'] == {'cgroup.freeze': '0', 'cpu.max': '200000 100000',
                                                'memory.max': '4294967296', 'pids.max': '2048'}, 'RESEARCH_SOURCE_AND_RESOURCE_LIMITS')
    need(closeout.get('registered_worker_exit_code') == 0
         and (stamp(closeout['registered_worker_reaped_utc']) - stamp(failure['utc'])).total_seconds()
         == closeout.get('reap_seconds_after_terminal_failure') == 2.270638, 'WORKER_EXIT_AFTER_FAILURE')


def replay(raw, source):
    report, declaration, inventory, review, closeout = [parsed(raw[name]) for name in
        ('report.json', 'declaration.json', 'evidence-sha256.json', 'independent-review.json', 'research-closeout.json')]
    need(report.get('host_runner_source') == SUBJECT and report.get('configuration_sha256') == CONFIG
         and report.get('result') == 'FAIL' and report.get('mode') == 'soak' and report.get('scope') == SCOPE
         and report.get('production_admitted') is False and report.get('error') == ERROR and report.get('error_class') == 'ValueError',
         'FAILED_REPORT_SOURCE_OUTCOME')
    compressed = raw['events.jsonl.gz']
    need(compressed[:4] == b'\x1f\x8b\x08\x00' and compressed[4:8] == b'\0' * 4 and compressed[8] == 2, 'DETERMINISTIC_GZIP_HEADER')
    expected = source['original_events']
    need(type(expected.get('bytes')) is int and 0 < expected['bytes'] <= 32 * 1024 * 1024, 'EXPANDED_EVENT_BOUND')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        event_bytes = stream.read(expected['bytes'] + 1)
        need(len(event_bytes) == expected['bytes'] and not stream.read(1), 'EXPANDED_EVENT_SIZE')
    need(sha(event_bytes) == expected['sha256'], 'LOSSLESS_EVENT_PROVENANCE')
    actual_inventory = {'report.json': sha(raw['report.json']), 'declaration.json': sha(raw['declaration.json']), 'events.jsonl': sha(event_bytes)}
    need(inventory == actual_inventory and report['declaration_sha256'] == inventory['declaration.json'], 'ORIGINAL_INVENTORY_BINDING')
    events, chain = event_chain(event_bytes)
    need(chain == report['event_chain'] == review['event_chain'], 'REPORT_REVIEW_EVENT_CHAIN_JOIN')
    need(len(events) == 24085, 'EXACT_24085_EVENTS')
    need(set(chain['clock_boundaries']) == {'public_clock_started'}, 'INCOMPLETE_86400_CLOCK_REQUIRED')
    start = next(event for event in events if event['kind'] == 'public_clock_started')
    failures = [event for event in events if event['kind'] == 'attempt_failed']
    need(len(failures) == 1 and failures[0]['data'] == {'detail': ERROR, 'error_class': 'ValueError'}, 'SINGLE_ORIGINAL_FAILURE')
    failure = failures[0]
    need(start['utc'] == '2026-11-17T01:51:39.968062+00:00' and failure['utc'] == '2026-11-17T05:14:40.050802+00:00'
         and start['data']['duration_seconds'] == 86400, 'EXACT_CLOCK_BOUNDARIES')
    actions = dispatches(events)
    need(not any(event['data']['action'] in ('quarantine_record', 'recover', 'reindex', 'upgrade', 'rollback') for event in actions),
         'UNREACHED_REMAINING_PHASES')
    need(dict(collections.Counter(event['kind'] for event in events)) ==
         {'prelaunch_bound': 1, 'action_dispatched': 11823, 'action': 11822, 'initial_volume_bound': 2,
          'anonymous_public_probe': 23, 'confirmed_payment': 205, 'declaration_bound': 1,
          'public_clock_started': 1, 'normal_slot': 202, 'fault_started': 1, 'fault_completed': 1,
          'attempt_failed': 1, 'cleanup': 1, 'attempt_completed': 1}, 'RECORDED_EVENT_KIND_COUNTS')
    declared_context(declaration, events, actions)
    payments = [event for event in events if event['kind'] == 'confirmed_payment']
    slots = [event['data'] for event in events if event['kind'] == 'normal_slot']
    phases = [event['data'] for event in events if event['kind'] == 'fault_completed']
    need(len(payments) == 205 and len(slots) == 202 and all(row.get('slot') == index and row.get('success') is True
         and 0 <= row['settle_seconds'] <= 60 for index, row in enumerate(slots)), 'EXACT_COMPLETED_PAYMENT_SLOT_COUNTS')
    need(len(phases) == 1 and phases[0].get('name') == 'crash' and phases[0].get('result') == 'PASS'
         and phases[0]['finished_elapsed'] - phases[0]['started_elapsed'] <= 300
         and any(event['data'] == phases[0]['recovery_payment'] for event in payments), 'ONLY_CRASH_PHASE_COMPLETED')
    need(payments_join(events, payments) == 205, 'PAYMENT_PROOF_CLOSURE')
    timeline = pending_timeline(events, actions, failure, start)
    need(review.get('source') == SUBJECT and review.get('public_attempt_result') == 'FAIL'
         and review.get('result') == 'PASS_EVIDENCE_AUDIT_OF_FAILED_SOAK' and review.get('confirmed_payments') == 205
         and review.get('successful_normal_slots') == 202 and review.get('recorded_missed_slots') == 0
         and review.get('partial_clock_to_failure') == timeline['partial_clock_to_failure']
         and review.get('public_clock_completed_event_present') is False
         and review.get('final_after_full_clock_missing_record_recovery_and_confirmed_spend_reached') is False
         and review.get('payments_with_both_host_exact_transaction_membership_and_tip_height_full_UTXO_agreement') == 205,
         'INDEPENDENT_COVERAGE_REVIEW_JOIN')
    need(review.get('source_payload_sha256') == actual_inventory and review.get('inventory_sha256') == sha(raw['evidence-sha256.json']),
         'INDEPENDENT_REVIEW_BYTE_BINDING')
    cleanup_join(report, review, closeout, events, failure)
    ast.parse(raw['frozen-l-public-soak-driver.py'])
    return timeline, chain, event_bytes


def verify(root):
    descriptor = open_root(root)
    try:
        need(tree(descriptor) == (MEMBERS, set()), 'EXACT_PACKET_MEMBERS')
        sums = read(descriptor, 'SHA256SUMS')
        seals = {}
        for line in sums.decode('ascii').splitlines():
            digest, name = line.split('  ', 1)
            parts(name)
            need(re.fullmatch('[0-9a-f]{64}', digest) and name not in seals, 'SEAL_FORMAT_OR_DUPLICATE')
            seals[name] = digest
        need(set(seals) == MEMBERS - {'SHA256SUMS'}, 'SEAL_MEMBERS')
        raw = {name: read(descriptor, name) for name in seals}
        need(all(sha(value) == seals[name] for name, value in raw.items()), 'SEALED_FILE_HASH')
        source = parsed(raw['SOURCE.json'])
        for name, value in raw.items():
            if name.endswith('.json'):
                public(parsed(value))
        need(raw['.gitattributes'] == b'* -text\n', 'BYTE_PRESERVATION_ATTRIBUTES')
        need(source.get('schema') == 'PQBTC-L-SELECTED-FAILED-PUBLIC-SOAK-PACKET-1' and source.get('source_subject') == SUBJECT
             and source.get('scope') == SCOPE and source.get('result') == 'FAIL', 'PACKET_SOURCE_SCOPE_OUTCOME')
        need(source.get('live_failure_cause') == 'UNKNOWN' and source.get('agent_stall_proven') is False
             and source.get('zero_peers_proven') is False and source.get('original_failure_proven_fixed') is False
             and source.get('later_reproducer_or_forensic_conclusions_included') is False
             and source.get('worker_exit_claimed_causal') is False, 'UNKNOWN_CAUSE_LIMITS')
        need(source.get('production_admitted') is False and source.get('human_review_performed') is False
             and source.get('resumption_allowed') is False and source.get('public_24_hour_credit_seconds') == 0
             and source.get('full_clock_completed') is False and source.get('terminal_old_backup_recovery_reached') is False,
             'NO_COMPLETION_CREDIT_OR_ADMISSION')
        rows = source.get('files', [])
        need(type(rows) is list and len(rows) == len(MEMBERS) - 2 and {parts(row['path']) for row in rows} ==
             {parts(name) for name in MEMBERS - {'SOURCE.json', 'SHA256SUMS'}}, 'SOURCE_MEMBER_CLOSURE')
        for row in rows:
            value = raw[row['path']]
            need(row.get('bytes') == len(value) and row.get('sha256') == sha(value), 'SOURCE_PAYLOAD_HASH')
            if row['path'] in ORIGINALS:
                origin = row.get('provenance', {})
                need(origin.get('transform') == 'NONE' and origin.get('original_sha256') == sha(value)
                     and origin.get('original_bytes') == len(value) and origin.get('original_verified_unchanged_after_copy') is True,
                     'UNCHANGED_COPY_PROVENANCE')
            elif row['path'] == 'events.jsonl.gz':
                origin = row.get('provenance', {})
                need(origin.get('transform') == 'DETERMINISTIC_LOSSLESS_GZIP_MTIME0_LEVEL9'
                     and origin.get('original_bytes') == source['original_events']['bytes']
                     and origin.get('original_sha256') == source['original_events']['sha256']
                     and origin.get('original_verified_unchanged_after_copy') is True, 'LOSSLESS_GZIP_PROVENANCE')
        timeline, chain, expanded = replay(raw, source)
        need(parsed(raw['failure-timeline.json']) == timeline, 'DERIVED_TIMELINE_REPLAY')
        need(source.get('event_chain') == chain and source.get('partial_clock_to_failure') == timeline['partial_clock_to_failure'],
             'SOURCE_CHAIN_AND_PARTIAL_CLOCK')
        # Fixed pins follow semantic checks, allowing independently re-sealed
        # controls to test semantic gates as well as byte-tamper detection.
        need(all(sha(raw[name]) == digest for name, digest in ORIGINALS.items())
             and len(expanded) == EVENT_BYTES and sha(expanded) == EVENT_SHA and chain['last_sha256'] == CHAIN,
             'PINNED_ORIGINAL_BYTES')
        need(tree(descriptor) == (MEMBERS, set()) and read(descriptor, 'SHA256SUMS') == sums
             and all(read(descriptor, name) == value for name, value in raw.items()), 'PACKET_CHANGED_DURING_VERIFICATION')
        return {'result': 'VERIFIED_FAILED_L_PUBLIC_ATTEMPT', 'report_result': 'FAIL', 'files': len(MEMBERS),
                'unchanged_original_files': len(ORIGINALS), 'events': len(expanded.splitlines()), 'confirmed_payments': 205,
                'completed_normal_successes': 202, 'normal_misses': 0, 'completed_phases': 1,
                'recipient_absent_queries': 320, 'same_known_rebroadcasts': 5, 'live_failure_cause': 'UNKNOWN',
                'public_24_hour_credit_seconds': 0, 'historical_driver_execution': False,
                'last_sha256': chain['last_sha256'], 'sha256sums_sha256': sha(sums)}
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        need(len(sys.argv) <= 2, 'ARGUMENTS')
        print(json.dumps(verify(sys.argv[1] if len(sys.argv) == 2 else Path(__file__).absolute().parent), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, SyntaxError, UnicodeError, EOFError) as error:
        message = error.args[0] if type(error) is ValueError and error.args and re.fullmatch('[A-Z0-9_]+', str(error.args[0])) else type(error).__name__
        print(json.dumps({'result': 'FAIL', 'gate': message}, sort_keys=True))
        raise SystemExit(1) from None
