#!/usr/bin/env python3
"""Pure offline checks over selected relay diagnostics; execute no fixture code."""
import sys

if not __debug__ or not sys.flags.isolated:
    raise SystemExit('Use python3 -I -B verify.py')

import ast
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

PINS = {
    "controlled/earlier-review-regression.json": "ab56a15001b7b76c8895d96f4bd1e2506e5516653ccee16f3a76be7dc6f465e5",
    "controlled/run01/events.jsonl": "9a70ee01ccf6bd604c412399e830db4082150c4f42e090c0590c386c634bb192",
    "controlled/run01/report.json": "ac0e3383c08e804fe9a4efcaf1404e04dc417d60d18f2c993275715c16491e70",
    "controlled/run02/events.jsonl": "a76285880e68269d3072862685317b8548a287b7dcdfdc964dcb10424f0ea00a",
    "controlled/run02/report.json": "920508efd00ac6367acc301d47ba42728dc51400ce83b6666ab8c335cb7434b5",
    "controlled/startup-regression.json": "cd13067e0ceac2683187929b5202328c71b602629011aa13893c722677c41710",
    "fixtures/controlled/run01/inv_proxy.py": "af679743835efe0295f2a4f939b62fd0a0ece8961cf95e3e6b7530e10e848770",
    "fixtures/controlled/run01/lost_inv.py": "4fb109e28c536aef154f2df686ae02957dc8f16703758e618fd281292da82876",
    "fixtures/controlled/run01/native_rpc.py": "2705349a5aa52ae2e7dc6a8dc875166790db0f79d776cd183f67a118f5046fb7",
    "fixtures/controlled/run01/sha256.json": "451f574a0ee3248a0007ef0c47d82c642906a887f876667910a85721823a5315",
    "fixtures/controlled/run01/test_lost_inv.py": "2cacb89c19d08ce8511da02bdccfb127f40ac606769c91527fc77eb3a0046abd",
    "fixtures/controlled/run02/inv_proxy.py": "bef8af41bb58fa61779e52daeb041ce660bc33e9f32cb55b417fd09d7561c0f7",
    "fixtures/controlled/run02/lost_inv.py": "9da2ad5eb4141b09564e238d0282adc865c9c428c938deb5bd5a1439eaea2075",
    "fixtures/controlled/run02/native_rpc.py": "2705349a5aa52ae2e7dc6a8dc875166790db0f79d776cd183f67a118f5046fb7",
    "fixtures/controlled/run02/test_lost_inv.py": "1ee915c047f73749338b1316a307deaed12d7cce0c73f7c92a1bb062576899e9",
    "fixtures/receiver/preparation04.json": "0ab03f9b882f73264239de5177898c5b6d8b8cdce17452a8f14590036446caf5",
    "fixtures/receiver/run01.py": "b36fc460bddf087f0fe1e7c103665d27ccd5350ae629574e3e1ad4c855fbaaf1",
    "fixtures/receiver/run02.py": "e25dd8b5043adc359245b1894984adb4a006191763ca0d6632992f73e1f52edb",
    "fixtures/receiver/run03.py": "95249ff79b52479d525061cf7557826a897bef0925c1f49c81e92cbd3daaa272",
    "fixtures/receiver/test_research_receiver_clone.py": "ba338417c041c01d9e8e82a2a9cc2196b6fb953c8d7ea02982ac4f4dd85841af",
    "fixtures/sender/mempool_extract.py": "581ea271483691c0cbeba5f0448ac73b9e6452d1846e3ef04a9c14cd7e491f45",
    "fixtures/sender/run01/SHA256.json": "546762e88c56e65a53370a8e40a9242d1d711e34474b6d3af861b43233a6aea9",
    "fixtures/sender/run01/run_mempool_extract.py": "026702a89f58d3ce6e93dd4a508164e31674abf6d50dfeaa6caada22c7f95922",
    "fixtures/sender/run01/test_run_mempool_extract.py": "ed65a1c205cf94fb63952860833a1855454131260e7e39fe44bb0bfe0b882ba6",
    "fixtures/sender/run02/run_mempool_extract.py": "7ad55e2c53e919b95af6a7a3a7c8ee1ce2c2c9a0f8a6e4fc4bd851cb349a22f7",
    "fixtures/sender/run02/test_run_mempool_extract.py": "b0a5b9e4661bffe716ac2e36d58bea786ea62d590307573a1f19e477bb6c0994",
    "fixtures/sender/test_mempool_extract.py": "9071fb8b9f97fb2098dee45f037dc878c0be874c7cb151b859f86ae980ede20c",
    "receiver/metadata/RESULT.json": "ca51924a0e13551742ffba1d50fc8c805f772a2710ed93015a0b8a811318f749",
    "receiver/metadata/independent-final-closeout.json": "9e19ae4a2ba342027ffdc0dbbabdce9e523d4df6c00abfd2a1a78cc58c664842",
    "receiver/metadata/remote02-safe-result.json": "aff5d046f35ffd7f7410c3ef54976b6bbb89fd2cc21a175656da75372733c95f",
    "receiver/run01/independent-live-kernel.json": "a8b1505eb4a35e3c6673574921e0a571f843a012818fb34e28e47947bfd5b8e0",
    "receiver/run01/launch-request.json": "1acc102cd1db4ad3a3f01bd3c6bfd48b95bf14bca6472393227cbb41f2348d3b",
    "receiver/run01/post-failure-readonly-closeout.json": "19cc00d7fba51beb62758012e7dbee826ed5c018a5e83bd55b5fba67eb9e67f9",
    "receiver/run01/remote-result-original.json": "3fa1e5845261abfb6503c420e49fee06b794f36ec67c4439e5dbec69b035c846",
    "receiver/run01/service-exit.json": "e193f6978c094d572d6678818903e2f4a196a15765028e953dad25cf6840622e",
    "receiver/run01/service-safe-stdout.json": "71c38e37ab502cb596bfa9d96c95295b9643ee0312c172b0a486b95d70be971b",
    "receiver/run01/staging.json": "a825454ad735ef635bcd056ff41b4748c3118ad06595292b6aa221250d077c64",
    "receiver/run02/RESULT.json": "83f02004d0625219bf69e79be27af92c313db879451393ec07451a955c0812bc",
    "receiver/run02/closeout-exit.json": "e78d78971b9b2f75a80c5ec7c112d717c2b15c29d73b54fe2024053801f59489",
    "receiver/run02/independent-live-kernel.json": "e2c13aeaa68502e7600628fab3c2839a38dd528834ebfb7d62a6849711f5f29e",
    "receiver/run02/launch-request.json": "6d480f54916353dd5df9714e33dd8f30ca5c4e7acb753542d2af7339589e3d6d",
    "receiver/run02/observer-exit.json": "e78d78971b9b2f75a80c5ec7c112d717c2b15c29d73b54fe2024053801f59489",
    "receiver/run02/post-failure-readonly-closeout.json": "2266a9f9a70a6c397cf36ca1b4527206317738498b12d1b9b94274d6a16b350b",
    "receiver/run02/receipt-collection.json": "4a5d1d97369237c0b5a19c25232ccd3de0b38716e0f4fb0a24a25549a7192e57",
    "receiver/run02/remote-copy-receipt.json": "1754f9ccfffe31475246fcb6dac7085f784b3d004581b8615538a4757b54d40d",
    "receiver/run02/remote-result.json": "a2cb81a2b5106cd23d66e6610e7cd3cad13b4c9b9d85189c35415a0cfb222290",
    "receiver/run02/service-exit.json": "57976a31d19def0989305421f081ab4c860381ecfa6a99392c0cd3425c7ee6f1",
    "receiver/run02/service-safe-stdout.json": "fdfac613f500a6092240c1a342f4c145dc825cd1bd616664f5365be4fca5cdcd",
    "receiver/run02/staging.json": "c5c572561f666e3bc1c136ae05e7c48db17caaed2be89847641b8a3d2f4d8bde",
    "receiver/run03/PUBLIC-COPY-MANIFEST.json": "d5cb01c7c5e97221098d99e9d1c446543f38b930b72ff35c13e933a9f893597e",
    "receiver/run03/RESULT.json": "820bb33ef2b72695e79f0a6cc573a307230a6aec996c56a69e5787e5d0c5bb74",
    "receiver/run03/closeout-exit.json": "abd3f219e1cb38bbcbb7201b94f09e02b2e4b4b48d6ffe2bc6b52bb4755987c0",
    "receiver/run03/independent-live-kernel.json": "54998d5e76c4c64115855db8420f87d5a3518b4b32d99117b3713c83425deac9",
    "receiver/run03/launch-request.json": "e1309aef841ee5a07999a0e2f771727d9033221ef4e6f7e47d430731d8cbd1f5",
    "receiver/run03/observer-exit.json": "e78d78971b9b2f75a80c5ec7c112d717c2b15c29d73b54fe2024053801f59489",
    "receiver/run03/post-pass-readonly-closeout.json": "5df8587c6948444ec9e307d169ac779e5e180a230224c15874f681c38152a2b4",
    "receiver/run03/receipt-collection.json": "902ddb3f412ac6ade4ff7981dfe4abc2621c5a0076afe9312e1acdbf72aa4758",
    "receiver/run03/remote-copy-receipt.json": "deb4b2b9df704075ba6be2b20586f249bfcf2e5eae929d480355ba381e7f28bd",
    "receiver/run03/remote-native-admission-receipt.json": "1a6edf02677efdafbdfab41c523aaf835cca2cf94b247bc00b1eafd244e193be",
    "receiver/run03/remote-result.json": "3d07b406e2a68fca761be26294adf065a36124ed1da1c9e129db95ec4a312b5e",
    "receiver/run03/service-exit.json": "e78d78971b9b2f75a80c5ec7c112d717c2b15c29d73b54fe2024053801f59489",
    "receiver/run03/service-safe-stdout.json": "96b70b665464bb213724350b9714eb4ef4f8620eb8eb779d2bc02e116b704144",
    "receiver/run03/staging.json": "e32028e59001d62f6fc7b7d6266c4c0a9a98d6b17c18e08198edec3b17a07ef7",
    "sender/run01/RESULT.json": "7e29869cde56562b5933626055255c52061c70974c07ed00365ce63047528057",
    "sender/run02/RESULT.json": "6b3c99c1689a1c308edd69174e3515900828b0d5fbb6bdc1ad217ad19170c7c7",
    "sender/run02/extraction.json": "374e26b513064db15e87bc203948f52da54a8dbc5082a46936979f594339c481"
}
HEAD = '7223772e76d2d0a0bb7fd1d35e0e16fba61918fd'
TREE = '33b36275b1da7f7fbc27fae00d519206b0f7c16f'
LIVE_TXID = 'f52c9e1538c8f9aa619266c06e5389fa194b724a51a769d0b00de54db6adcb94'
LIVE_RAW = 'd9216ce739ace40ebbc309eada41f54317d7f48ec7d009e95480cc9f1bd8e028'
MAC_ID = '09357eb22afff16e50da4e4b1d4ca94469f3060729d6811bfdc736de3dffa63d'
RESEARCH_ID = 'e6ffad0815e423a2f54088232d6b8940282dfc7be457f7599085925ad27a5666'
CLONE_ID = 'd4ebbd95442b2484ce676e1b147b25589543aff39355db2a5f4764003f8353cb'
H_IMAGE = 'sha256:b3358bb35d60a5f42c9ce1fe65c26926250c26e99815c3446810a8eb6e730f0a'
PARENT = {'cgroup.freeze': '0', 'cpu.max': '200000 100000', 'memory.max': '4294967296', 'pids.max': '2048'}
NATIVE_LIMITS = dict(PARENT, **{'memory.max': '1073741824', 'pids.max': '256'})
CONTEXT = {'height': 408, 'mempool_size': 0, 'network_active': False, 'peer_count': 0,
           'tip': '54a78dadccd74a664b730f09d436f7272b3fda02081deb9915935b0a5a4ff8be', 'utxo_count': 547,
           'utxo_hash': '5e8dbc2dc2a2a945baf0cd994eaaba8e4f02d6d0701b8b4ac60a9ead44aaac0d'}
DERIVED = {'.gitattributes', 'README.md', 'SUMMARY.json', 'verify.py', 'negative-controls.py', 'verification-controls.json'}
PRIVATE = {'password', 'passphrase', 'secret', 'ciphertext', 'operator_input', 'private_key', 'seed', 'wallet_seed',
           'mnemonic', 'rpcpassword', 'rpcauth', 'access_token', 'refresh_token', 'cookie', 'raw_hex', 'raw_transaction', 'env'}


def need(value, gate):
    if not value:
        raise ValueError(gate)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(rows):
    value = {}
    for key, item in rows:
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
    components, parent = parts(name), os.dup(descriptor)
    try:
        for item in components[:-1]:
            child = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        child = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            start = os.fstat(child)
            need(stat.S_ISREG(start.st_mode) and start.st_nlink == 1 and start.st_size <= 1024 * 1024, 'FILE_TYPE_SIZE')
            chunks, size = [], 0
            while size <= 1024 * 1024:
                value = os.read(child, min(65536, 1024 * 1024 + 1 - size))
                if not value:
                    break
                chunks.append(value)
                size += len(value)
            end = os.fstat(child)
            keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_gid', 'st_mode', 'st_nlink')
            need(size == start.st_size and size <= 1024 * 1024
                 and tuple(getattr(start, key) for key in keys) == tuple(getattr(end, key) for key in keys), 'FILE_CHANGED')
            return b''.join(chunks)
        finally:
            os.close(child)
    finally:
        os.close(parent)


def pong(rows, ids):
    need(type(rows) is list and len(rows) == 2, 'FRESH_PONG_PAIR')
    for row, identity in zip(rows, ids, strict=True):
        need(row.get('id') == identity and all(type(row.get(key)) is int for key in
             ('ping_sent_after', 'ping_sent_before', 'pong_received_after', 'pong_received_before'))
             and row['ping_sent_after'] - row['ping_sent_before'] == 32
             and row['pong_received_after'] - row['pong_received_before'] == 32, 'FRESH_SAME_PEER_PONG')


def controlled(data):
    first, result = (parsed(data['controlled/run' + run + '/report.json']) for run in ('01', '02'))
    for run, report in (('01', first), ('02', result)):
        trace = data['controlled/run' + run + '/events.jsonl']
        rows = [parsed(line) for line in trace.splitlines()]
        need(report.get('schema') == 'PQBTC-LOST-INV-DIAGNOSTIC-1' and report.get('source_head') == HEAD
             and report.get('source_tree') == TREE and report.get('scope') == 'PRIVATE_V1_DIAGNOSTIC_ZERO_PUBLIC_SOAK_CREDIT'
             and report.get('image') == 'sha256:fc470f630a0eaa679aa49563d13b1a1e1d183528eb4348877c7cbb60b3c0e6f3'
             and report.get('trace_sha256') == sha(trace) and report.get('trace_events') == len(rows), 'CONTROLLED_SOURCE_TRACE_BINDING')
        need(all(row.get('stopped') is True and row.get('pid') == 0 and row.get('volume_retained') is True
                 for row in report.get('retained_containers', [])) and len(report['retained_containers']) == 2, 'CONTROLLED_RETAINED_CLEANUP')
    need(first.get('result') == 'FAIL' and first.get('trace_events') == 2
         and first.get('cleanup_errors') == ['PROXY_CLOSE_FAILED'], 'CONTROLLED_STARTUP_FAILURE_PRESERVED')
    need(result.get('result') == 'REPRODUCED_WITH_PASSING_POSITIVE_CONTROL' and result.get('trace_events') == 39
         and result.get('cleanup_errors') == [] and result.get('watchdog_fired') is False
         and result.get('proxy_exit') == {'returncode': 0, 'stopped_cleanly': True}, 'CONTROLLED_REPRODUCTION_RESULT')
    trace = [parsed(line) for line in data['controlled/run02/events.jsonl'].splitlines()]
    need(all(type(row.get('monotonic_ns')) is int for row in trace)
         and all(b['monotonic_ns'] > a['monotonic_ns'] for a, b in zip(trace, trace[1:])), 'HOST_TRACE_ORDER')
    select = lambda name: [row for row in trace if row['event'] == name]
    one = lambda name: select(name)[0] if len(select(name)) == 1 else None
    baseline, control = result['baseline'], result['positive_control']
    need(baseline.get('result') == 'LOSS_REPRODUCED' and baseline.get('budget_seconds') == 60
         and baseline.get('peer_ids') == [0, 0] and baseline.get('reissued_payment') is False, 'BASELINE_LOSS_SCOPE')
    target, proxy = baseline['target'], baseline['proxy']
    need(target.get('txid') != LIVE_TXID and proxy.get('connections') == proxy.get('active_connections') == 1
         and len(proxy.get('dropped', [])) == 1 and proxy['dropped'][0].get('type') == 5
         and proxy['dropped'][0].get('hash') == target.get('wtxid'), 'ONE_MATCHING_MSG_WTX_DROP')
    sent, expired = one('target_broadcast_once'), one('original_budget_expired_without_receipt')
    need(sent is not None and all(sent[key] == target[key] for key in ('txid', 'wtxid', 'raw_transaction_sha256')), 'CONTROLLED_TARGET_BROADCAST')
    repeats = select('same_connection_same_known_rebroadcast')
    need(len(repeats) == 5, 'FIVE_SAME_CONNECTION_REBROADCASTS')
    for index, event in enumerate(repeats, 1):
        need(event.get('ordinal') == index and event.get('txid') == target['txid']
             and event.get('raw_transaction_sha256') == target['raw_transaction_sha256']
             and event.get('known_in_mempool') is True and event.get('rebroadcast') is True
             and event.get('reissued_payment') is False and 0 < event['elapsed_seconds'] < 60, 'SAME_BYTES_NO_REISSUANCE')
        pong(event['before'], [0, 0])
        pong(event['after'], [0, 0])
    need(expired is not None and expired.get('ids') == [0, 0] and expired.get('reannouncements') == 5
         and expired.get('recipient_absent_queries') == 328 and 60 <= expired.get('elapsed_seconds', -1) < 61, 'ORIGINAL_LOSS_BUDGET_EXPIRED')
    readiness, absent = one('fresh_target_readiness_pongs'), one('post_budget_absence_and_fresh_pongs')
    pong(readiness['pings'], [0, 0])
    pong(absent['pings'], [0, 0])
    need(absent.get('recipient_absent') is True and absent.get('checkpoints_unchanged') is True, 'POST_BUDGET_ABSENCE_AND_FLOORS')
    declared, positive = one('positive_control_budget_declared'), one('positive_control_same_bytes_confirmed_after_exact_reconnect')
    need(declared is not None and declared.get('budget_seconds') == 60 and declared.get('old_peer_ids') == [0, 0]
         and declared['monotonic_ns'] > expired['monotonic_ns'] and control.get('result') == 'PASS'
         and control.get('peer_ids') == [1, 1] and control.get('budget_seconds') == 60
         and 0 < control.get('elapsed_seconds', 0) < 60, 'SEPARATE_POSITIVE_CONTROL_BUDGET')
    need(positive is not None and positive.get('target') == target and positive.get('new_peer_ids') == [1, 1]
         and positive.get('block_hash') == control.get('block_hash') and 0 < positive['elapsed_seconds'] < 60, 'SAME_BYTES_RECONNECT_CONFIRMATION')
    pong(positive['fresh_pongs'], [1, 1])
    need(result['action_counts'].get('0:send') == 2 and result['action_counts'].get('0:rebroadcast') == 6, 'NO_EXTRA_CONTROLLED_PAYMENTS')
    old_proxy = data['fixtures/controlled/run01/inv_proxy.py'].decode()
    new_proxy = data['fixtures/controlled/run02/inv_proxy.py'].decode()
    need('os.chmod(path, 0o600)' not in old_proxy and 'os.chmod(path, 0o600)' in new_proxy and 'control.bind(path)\n' in new_proxy
         and new_proxy.index('control.bind(path)') < new_proxy.index('os.chmod(path, 0o600)')
         < new_proxy.index('control_permissions(path)', new_proxy.index('def serve(')), 'EXACT_PROXY_SOCKET_MODE_FIX')
    regression = parsed(data['controlled/earlier-review-regression.json'])
    need(regression.get('archived_lf_baseline') == {'errors': 0, 'failures': 0, 'tests': 2}, 'NO_NEWLINE_DEFECT_CLAIM')
    return {'result': result['result'], 'forced_transport': 'v1', 'dropped_MSG_WTX_items': 1, 'same_connection_rebroadcasts': 5,
            'loss_elapsed_seconds': expired['elapsed_seconds'], 'absent_queries': 328, 'positive_control_report_seconds': control['elapsed_seconds'],
            'positive_control_trace_seconds': positive['elapsed_seconds'], 'live_cause_proved': False}


def sender(data):
    first, result = (parsed(data['sender/run' + run + '/RESULT.json']) for run in ('01', '02'))
    need(first.get('result') == 'FAIL' and first.get('guard') == 'AUX_IMMUTABLE_IDENTITY'
         and first.get('last_stage') == 'create_init' and 'extraction' not in first, 'SENDER_FIRST_GUARD_FAILURE')
    need(result.get('result') == 'PASS' and result.get('source_container') == MAC_ID
         and result.get('original_node_started') is False and result.get('source_mounted_read_only') is True
         and result.get('original_still_stopped_same_identity') is True, 'STOPPED_READONLY_SENDER_SOURCE')
    need(result.get('decoder_sha256') == PINS['fixtures/sender/mempool_extract.py']
         and result.get('wrapper_sha256') == PINS['fixtures/sender/run02/run_mempool_extract.py'], 'SENDER_EXECUTED_CODE_BINDING')
    receipt = parsed(data['sender/run02/extraction.json'])
    need(receipt == result.get('extraction') and receipt.get('signed_raw_bytes') == 3878
         and receipt.get('no_raw_payload_stdout') is True and receipt.get('public_volume_marker_verified') is True, 'SENDER_RECEIPT_AND_SIZE')
    decoded, source = receipt['decoded'], receipt['source_file']
    need(decoded.get('txid') == LIVE_TXID and decoded.get('selected_raw_sha256') == LIVE_RAW
         and decoded.get('version') == 2 and decoded.get('record_count') == 1, 'EXACT_PENDING_TRANSACTION_EXTRACTION')
    need(source.get('bytes') == 3953 and source.get('sha256') == '8d7b058ce175a7cbfd0bd05bb18d3c8e210d6ffe176e442819fa3d668bf93763'
         and source.get('same_identity_metadata_and_second_digest') is True and source.get('mode') == '0600', 'SENDER_SOURCE_FILE_UNCHANGED')
    need(len(result.get('cleanup', [])) == 2 and all(row.get('stopped') is True and row.get('pid') == 0
         and row.get('container_retained') is True for row in result['cleanup']), 'SENDER_HELPERS_STOPPED')
    return {'first_result': 'FAIL_BEFORE_DECODER_READ', 'result': 'PASS', 'txid': LIVE_TXID, 'raw_sha256': LIVE_RAW,
            'raw_bytes': 3878, 'source_file_bytes': 3953, 'raw_payload_local_member': False}


def public_copy_path(path):
    return re.fullmatch(r'mempool\.dat|blocks/(?:blk|rev)\d{5}\.dat|blocks/xor\.dat|'
                        r'(?:blocks/index|chainstate)/(?:\d{6}\.(?:ldb|log)|CURRENT|LOCK|MANIFEST-\d{6})', path) is not None


def receiver(data):
    first = parsed(data['receiver/run01/remote-result-original.json'])
    second = parsed(data['receiver/run02/RESULT.json'])
    need(first.get('result') == 'FAIL' and first.get('guard') == 'BOUNDED_DOCKER_JSON_REQUIRED', 'RECEIVER_INITIALIZER_FAILURE')
    need(second.get('result') == 'FAIL_BEFORE_NATIVE_COPY_PATH_GUARD' and second.get('contained_copy_guard') == 'PUBLIC_PATH_FILE'
         and second.get('native_verdict') == 'NOT_OBTAINED' and second.get('source_payload_copy_completed') is False,
         'RECEIVER_PATH_FAILURE_NO_NATIVE_VERDICT')
    metadata = parsed(data['receiver/metadata/RESULT.json'])
    lock = metadata.get('offending_entry', {})
    need(metadata.get('result') == 'PASS_METADATA_ONLY' and lock == {'basename': '.lock', 'bytes': 0, 'gid': 1000,
         'mode': '0600', 'nlink': 1, 'relative_path': 'blocks/.lock', 'type': 'regular', 'uid': 1001}, 'EXACT_EMPTY_PROCESS_LOCK_METADATA')
    prefix = 'receiver/run03/'
    result, native, remote, copy, manifest, closed, kernel = [parsed(data[prefix + name]) for name in
        ('RESULT.json', 'remote-native-admission-receipt.json', 'remote-result.json', 'remote-copy-receipt.json',
         'PUBLIC-COPY-MANIFEST.json', 'post-pass-readonly-closeout.json', 'independent-live-kernel.json')]
    need(result.get('result') == 'PASS_DIAGNOSTIC' and native.get('result') == remote.get('result') == 'PASS', 'RECEIVER_NATIVE_DIAGNOSTIC_PASS')
    need(remote.get('source_image') == H_IMAGE and remote['original_source_stopped_after'].get('image') == H_IMAGE,
         'FROZEN_H_NATIVE_IMAGE')
    verdict = result.get('native_testmempoolaccept_verdict', {})
    need(verdict.get('allowed') is True and verdict.get('txid') == LIVE_TXID and verdict.get('vsize') == 3125
         and verdict.get('wtxid') == 'eb49dcb75ffea7ad0cf1995c8166f0392ea8df931824aec9a479a4509178b51b', 'NATIVE_ALLOWED_EXACT_PENDING_BYTES')
    need(verdict == native.get('native_verdict') == remote.get('native_verdict') and native.get('bound_txid') == LIVE_TXID
         and native.get('bound_raw_sha256') == LIVE_RAW and result.get('exact_raw_transaction') ==
         {'bytes': 3878, 'sha256': LIVE_RAW, 'txid': LIVE_TXID}, 'NATIVE_VERDICT_RAW_IDENTITY_JOIN')
    need(result.get('context_before') == result.get('context_after') == native.get('context_before')
         == native.get('context_after') == remote.get('context') == CONTEXT, 'EXACT_OFFLINE_CONTEXT_UNCHANGED')
    need(native.get('transaction_broadcast_or_admission_not_performed') is True
         and result.get('test_did_not_admit_or_broadcast_transaction') is True
         and native.get('fresh_rpc_auth_stayed_inside_clone') is True, 'NO_NATIVE_ADMISSION_OR_BROADCAST')
    files = manifest.get('files', [])
    need(len(files) == 14 and all(public_copy_path(row.get('path', '')) for row in files), 'STRICT_PUBLIC_COPY_PATHS')
    need(files == copy.get('files') and manifest.get('file_count') == copy.get('file_count') == 14
         and sum(row['bytes'] for row in files) == manifest.get('selected_bytes') == copy.get('selected_bytes') == 18173046,
         'FOURTEEN_PUBLIC_FILE_HASH_MANIFEST')
    need(copy.get('source_all_selected_identity_metadata_and_hashes_rechecked') is True
         and manifest.get('source_identity_metadata_and_selected_hashes_rechecked') is True, 'COPIED_SOURCE_HASHES_RECHECKED')
    omitted = manifest.get('omitted_process_locks', [])
    need(len(omitted) == 1 and omitted[0]['path'] == 'blocks/.lock' and omitted[0]['bytes'] == 0
         and closed['new_clone_own_process_lock_metadata_only']['inode'] != omitted[0]['identity'][1], 'FRESH_CLONE_PROCESS_LOCK')
    need(result.get('original_failed_receiver_source_e6ff_stopped_unchanged_PID0') is True
         and remote.get('original_source_metadata_unchanged') is True
         and remote.get('original_source_stopped_before') == remote.get('original_source_stopped_after')
         and remote['original_source_stopped_after']['id'] == RESEARCH_ID
         and remote['original_source_stopped_after']['state']['Running'] is False
         and remote['original_source_stopped_after']['state']['Pid'] == 0, 'ORIGINAL_RECEIVER_UNCHANGED')
    stop = result.get('cleanup', {})
    need(stop.get('backend_stopped') is True and stop.get('container_id') == CLONE_ID and stop.get('pid') == 0
         and result.get('temporary_helpers_absent') is True and closed['clone_stopped_PID0']['running'] is False
         and closed['clone_stopped_PID0']['pid'] == 0 and closed['clone_stopped_PID0']['network'] == 'none'
         and closed['clone_stopped_PID0']['readonly'] is True and closed['clone_stopped_PID0']['nano'] == 2000000000
         and closed['clone_stopped_PID0']['memory'] == 1073741824 and closed['clone_stopped_PID0']['pids'] == 256
         and len(closed['temporary_helpers_proven_absent']) == 2, 'RECEIVER_CLONE_CLEANUP')
    need(kernel.get('parent_limits') == result['kernel_live']['parent'] == closed.get('shared_limits') == PARENT
         and kernel['native_process']['limits'] == NATIVE_LIMITS and kernel['native_process']['comm'] == 'pqbtcd'
         and kernel['native_process']['uid'] == 1001 and kernel['native_process']['pid'] != kernel['container_kernel']['pid']
         and kernel['container']['id'] == CLONE_ID and kernel['container']['image'] == H_IMAGE
         and kernel['native_process']['cgroup'] == kernel['container_kernel']['cgroup']
         and kernel['native_process']['cgroup'].endswith('/docker-' + CLONE_ID + '.scope'),
         'ACTUAL_NATIVE_AND_AGGREGATE_LIMITS')
    need(remote == parsed(data[prefix + 'service-safe-stdout.json']), 'REMOTE_AND_SAFE_STDOUT_JSON_EQUAL')
    for run, value in (('02', second), ('03', result)):
        for name, identity in value['files'].items():
            raw = data['receiver/run' + run + '/' + name]
            need(identity == {'bytes': len(raw), 'sha256': sha(raw)}, 'RECEIVER_REFERENCED_JSON_BYTE_CLOSURE')
    collection = parsed(data[prefix + 'receipt-collection.json'])
    for name, local in {'result.json': 'remote-result.json', 'copy-receipt.json': 'remote-copy-receipt.json',
                        'native-admission-receipt.json': 'remote-native-admission-receipt.json'}.items():
        need(collection[name] == {'bytes': len(data[prefix + local]), 'sha256': sha(data[prefix + local])}, 'COLLECTED_RECEIPT_NAME_MAPPING')
    need(result.get('helper_sha256') == PINS['fixtures/receiver/run03.py'] == parsed(data[prefix + 'staging.json'])['helper']['sha256'],
         'EXECUTED_RECEIVER_HELPER_SHA')
    excerpts = [{'file': row['file'], 'line_start': row['line_start'], 'line_end': row['line_end'],
                 'full_source_file_sha256': row['sha256'], 'selected_excerpt_sha256': sha(row['exact_source'].encode())}
                for row in metadata['frozen_H_source']['evidence']]
    return {'first_result': 'FAIL_INITIALIZER', 'second_result': second['result'], 'result': 'PASS_DIAGNOSTIC',
            'native_allowed': True, 'persisted_context': CONTEXT, 'copied_file_count': 14, 'copied_bytes': 18173046,
            'full_datasets_local_members': False, 'live_ephemeral_state_restored': False, 'primary_source_excerpts': excerpts}


def summary(data):
    return {'schema': 'PQBTC-SELECTED-RELAY-DIAGNOSTICS-SUMMARY-1', 'controlled': controlled(data),
            'sender': sender(data), 'receiver': receiver(data), 'original_live_failure_cause': 'UNKNOWN',
            'subsequent_M_fix_qualification_claimed': False, 'public_preflight_credit_seconds': 0, 'public_24_hour_credit_seconds': 0}


def verify(root):
    descriptor = open_root(root)
    expected = set(PINS) | DERIVED | {'SOURCE.json', 'SHA256SUMS'}
    directories = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != '.'}
    try:
        need(tree(descriptor) == (expected, directories), 'EXACT_PACKET_MEMBERS')
        sums = read(descriptor, 'SHA256SUMS')
        seals = {}
        for line in sums.decode('ascii').splitlines():
            digest, name = line.split('  ', 1)
            parts(name)
            need(re.fullmatch('[0-9a-f]{64}', digest) and name not in seals, 'SEAL_FORMAT_OR_DUPLICATE')
            seals[name] = digest
        need(set(seals) == expected - {'SHA256SUMS'}, 'SEAL_MEMBERS')
        data = {name: read(descriptor, name) for name in seals}
        need(sum(map(len, data.values())) <= 4 * 1024 * 1024 and all(sha(raw) == seals[name] for name, raw in data.items()), 'SEALED_FILE_HASH')
        for name, raw in data.items():
            if name.endswith('.json'):
                public(parsed(raw))
            elif name.endswith('.jsonl'):
                for line in raw.splitlines():
                    public(parsed(line))
            elif name.startswith('fixtures/') and name.endswith('.py'):
                ast.parse(raw)
        source = parsed(data['SOURCE.json'])
        need(source.get('schema') == 'PQBTC-SELECTED-RELAY-DIAGNOSIS-PACKET-1' and source.get('host_source') == {'head': HEAD, 'tree': TREE}
             and source.get('scope') == 'VALUELESS_TEST_DIAGNOSTICS_ONLY', 'PACKET_SUBJECT_SCOPE')
        need(source.get('original_live_failure_cause') == 'UNKNOWN' and source.get('live_cause_proved') is False
             and source.get('original_ephemeral_state_restored') is False and source.get('subsequent_M_fix_qualification_claimed') is False,
             'CAUSAL_AND_CURRENT_FIX_LIMITS')
        need(source.get('human_review_performed') is False and source.get('production_admitted') is False
             and source.get('public_preflight_credit_seconds') == source.get('public_24_hour_credit_seconds') == 0,
             'ZERO_CREDIT_AND_ADMISSION')
        rows = source.get('files', [])
        need(len(rows) == len(expected) - 2 and {row['path'] for row in rows} == expected - {'SOURCE.json', 'SHA256SUMS'}, 'SOURCE_MEMBER_CLOSURE')
        for row in rows:
            raw = data[row['path']]
            need(row.get('bytes') == len(raw) and row.get('sha256') == sha(raw), 'SOURCE_PAYLOAD_HASH')
            if row['path'] in PINS:
                origin = row.get('provenance', {})
                need(origin.get('transform') == 'NONE' and origin.get('original_bytes') == len(raw)
                     and origin.get('original_sha256') == sha(raw) and origin.get('original_verified_unchanged_after_copy') is True,
                     'UNCHANGED_ORIGINAL_PROVENANCE')
        result = summary(data)
        need(parsed(data['SUMMARY.json']) == result, 'DERIVED_SUMMARY_REPLAY')
        need(all(sha(data[name]) == digest for name, digest in PINS.items()), 'PINNED_ORIGINAL_BYTES')
        need(tree(descriptor) == (expected, directories) and read(descriptor, 'SHA256SUMS') == sums
             and all(read(descriptor, name) == raw for name, raw in data.items()), 'PACKET_CHANGED_DURING_VERIFICATION')
        return {'result': 'VERIFIED_SELECTED_RELAY_DIAGNOSTICS', 'files': len(expected), 'unchanged_original_files': len(PINS),
                'controlled_loss_reproduced': True, 'separate_reconnect_control': 'PASS', 'persisted_state_native_allowed': True,
                'live_failure_cause': 'UNKNOWN', 'public_preflight_credit_seconds': 0, 'public_24_hour_credit_seconds': 0,
                'subsequent_M_fix_qualification_claimed': False, 'historical_fixture_execution': False, 'sha256sums_sha256': sha(sums)}
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        need(len(sys.argv) <= 2, 'ARGUMENTS')
        print(json.dumps(verify(sys.argv[1] if len(sys.argv) == 2 else Path(__file__).absolute().parent), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, SyntaxError, UnicodeError) as error:
        message = error.args[0] if type(error) is ValueError and error.args and re.fullmatch('[A-Z0-9_]+', str(error.args[0])) else type(error).__name__
        print(json.dumps({'result': 'FAIL', 'gate': message}, sort_keys=True))
        raise SystemExit(1) from None
