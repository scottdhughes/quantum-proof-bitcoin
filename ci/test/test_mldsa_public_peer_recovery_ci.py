#!/usr/bin/env python3
"""Host-only regressions: framing, bounded lifecycle and native receipt gates."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'contrib/ml-dsa-qualification'
sys.path.insert(0, str(HERE))


def module(name):
    path = HERE / (name + '.py')
    assert path.is_file(), 'Missing regression implementation: ' + name
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def frame(command, payload=b''):
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return bytes.fromhex('a7e29cf7') + command.ljust(12, b'\0') + struct.pack('<I', len(payload)) + digest + payload


def renewal(transport='v1'):
    return dict(endpoint='127.0.0.1:23834', renewed=True, network_active=True,
                old_peer_ids=[4], new_peer_id=5, transport_protocol_type=transport,
                fresh_pong=True, ping_sent_before=0, ping_sent_after=8,
                pong_received_before=0, pong_received_after=8)


def evidence():
    point = {'A': {'wallet_id': '11' * 16, 'next_receive': 1, 'next_change': 1},
             'B': {'wallet_id': '22' * 16, 'next_receive': 2, 'next_change': 0}}
    return {'payment': {'sender': 'A', 'receiver': 'B', 'txid': 'aa' * 32, 'block_hash': 'bb' * 32,
                        'settle_seconds': 12, 'recipient_in_mempool': True, 'recipient_relay_seconds': 11},
            'counts': {'receive': 1, 'send': 1, 'renew_peer': 1},
            'known': {'txid': 'aa' * 32, 'wtxid': 'cc' * 32, 'raw_transaction_sha256': 'dd' * 32},
            'drop': {'armed': False, 'ever_armed': True, 'dropped': [{'type': 5, 'hash': 'cc' * 32, 'monotonic_ns': 10}]},
            'reannouncements': [{'txid': 'aa' * 32, 'raw_transaction_sha256': 'dd' * 32,
                                  'known_in_mempool': True, 'rebroadcast': True, 'reissued_payment': False}],
            'renewal': renewal(), 'floors': [point, copy.deepcopy(point), copy.deepcopy(point)],
            'memberships': {h: {'txid': 'aa' * 32, 'block_hash': 'bb' * 32, 'confirmed': True, 'confirmations': 1} for h in ('A', 'B')},
            'agreement': {h: {'height': 101, 'tip': 'bb' * 32, 'utxo_hash': 'ee' * 32, 'utxo_count': 2} for h in ('A', 'B')},
            'recipient_observed': True, 'renewal_elapsed': 10.1}


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.p = module('peer_recovery_proxy')

    def test_fragmented_frames_forward_unchanged_and_reject_corruption(self):
        raw = frame(b'ping', b'12345678') + frame(b'verack')
        parser = self.p.Framer()
        result = []
        for byte in raw:
            result.extend(parser.feed(bytes([byte])))
        self.assertEqual(b''.join(row[2] for row in result), raw)
        for corrupt in (b'xxxx' + raw[4:], raw[:20] + b'xxxx' + raw[24:],
                        frame(b'a\0b'), raw[:16] + struct.pack('<I', 4194305) + raw[20:]):
            with self.subTest(corrupt=corrupt[:24]), self.assertRaises(ValueError):
                self.p.Framer().feed(corrupt)

    def test_inventory_canonical_bounds_and_one_armed_single_tx_drop(self):
        drop = self.p.DropOnce()
        payload = b'\x01' + struct.pack('<I', 5) + bytes.fromhex('ab' * 32)[::-1]
        self.assertTrue(drop.forward('sender_to_receiver', 'inv', payload))
        drop.arm()
        self.assertTrue(drop.forward('receiver_to_sender', 'inv', payload))
        self.assertTrue(drop.forward('sender_to_receiver', 'inv', b'\x02' + payload[1:] * 2))
        self.assertFalse(drop.forward('sender_to_receiver', 'inv', payload))
        self.assertTrue(drop.forward('sender_to_receiver', 'inv', payload))
        self.assertEqual(drop.status()['dropped'][0]['hash'], 'ab' * 32)
        with self.assertRaises(ValueError):
            drop.arm()
        for bad in (b'', b'\xfd\x01\0' + payload[1:], b'\x02' + payload[1:], b'\xff'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.p.inventory(bad)

    def test_control_refuses_duplicates_trailing_data_and_unsafe_socket(self):
        for bad in (b'{"op":"arm","op":"stop"}\n', b'{"op":"stop"}\nX', b'{"op":"other"}\n', b'x' * 513):
            with self.subTest(bad=bad[:50]), self.assertRaises(ValueError):
                self.p.parse_control(bad)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'control')
            with socket.socket(socket.AF_UNIX) as control:
                control.bind(path)
                os.chmod(path, 0o600)
                self.p.control_permissions(path)
                os.chmod(path, 0o666)
                with self.assertRaises(ValueError):
                    self.p.control_permissions(path)

    def test_listener_startup_failure_closes_created_sockets(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen(1)
            created = []
            factory = socket.socket
            def make_socket(*args, **kwargs):
                value = factory(*args, **kwargs)
                created.append(value)
                return value
            with patch.object(self.p.socket, 'socket', side_effect=make_socket):
                with self.assertRaises(OSError):
                    self.p.serve(str(Path(directory) / 'control'), '127.0.0.1', listen_port=occupied.getsockname()[1])
            self.assertTrue(created)
            self.assertTrue(all(sock.fileno() == -1 for sock in created))

    def test_zero_connection_stop_removes_socket(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as port_probe:
            port_probe.bind(('127.0.0.1', 0))
            port = port_probe.getsockname()[1]
            port_probe.close()
            path = str(Path(directory) / 'control')
            errors = []
            def serve():
                try:
                    self.p.serve(path, '127.0.0.1', listen_port=port)
                except Exception as error:
                    errors.append(type(error).__name__)
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            deadline = time.monotonic() + 3
            while not os.path.exists(path) and time.monotonic() < deadline:
                time.sleep(.01)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(path)
                client.sendall(b'{"op":"stop"}\n')
                import json
                result = json.loads(client.recv(4096))
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(result['active_connections'], 0)
            self.assertFalse(os.path.exists(path))


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.h = module('run_public_peer_recovery_ci')

    def test_complete_payment_receipt_and_each_material_failure(self):
        self.h.validate_payment(evidence())
        variants = []
        for key, value in (('settle_seconds', 60.01), ('recipient_in_mempool', False), ('txid', 'ff' * 32)):
            item = evidence()
            item['payment'][key] = value
            variants.append(item)
        for key in ('send', 'receive', 'renew_peer'):
            item = evidence()
            item['counts'][key] = 2
            variants.append(item)
        item = evidence()
        item['drop']['dropped'][0]['hash'] = 'ff' * 32
        variants.append(item)
        item = evidence()
        item['reannouncements'][0]['raw_transaction_sha256'] = 'ff' * 32
        variants.append(item)
        item = evidence()
        item['floors'][1]['A']['next_change'] += 1
        variants.append(item)
        item = evidence()
        item['memberships']['B']['confirmed'] = False
        variants.append(item)
        item = evidence()
        item['agreement']['B']['utxo_hash'] = 'ff' * 32
        variants.append(item)
        item = evidence()
        item['recipient_observed'] = False
        variants.append(item)
        item = evidence()
        item['renewal_elapsed'] = 9
        variants.append(item)
        item = evidence()
        item['renewal']['new_peer_id'] = 4
        variants.append(item)
        item = evidence()
        item['renewal']['pong_received_after'] = 0
        variants.append(item)
        for index, item in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.h.validate_payment(item)

    def test_renewal_requires_expected_transport_endpoint_and_fresh_pong(self):
        value = renewal('v2')
        self.h.validate_renewal(value, '127.0.0.1:23834', 'v2')
        for field, replacement in (('transport_protocol_type', 'v1'), ('endpoint', 'evil:23834'),
                                   ('fresh_pong', False), ('ping_sent_after', 0), ('old_peer_ids', [])):
            item = copy.deepcopy(value)
            item[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.h.validate_renewal(item, '127.0.0.1:23834', 'v2')

    def test_remaining_refuses_expiry_nonfinite_and_boolean(self):
        with patch.object(self.h.time, 'monotonic', return_value=20):
            self.assertEqual(self.h.remaining(23), 3)
            for value in (20, 19, float('nan'), float('inf'), True):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.h.remaining(value)

    def test_namespace_and_private_destination_refuse_unowned_routes(self):
        name = 'pqbtc-mldsa-public-recovery-' + 'a' * 32
        self.assertEqual(self.h.validate_namespace(name), name + '-data-v1')
        for bad in ('pqbtc-mldsa-public', name + '-extra', 'user-wallet', name.upper()):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.h.validate_namespace(bad)
        self.assertEqual(self.h.private_ip('172.17.0.2'), '172.17.0.2')
        for bad in ('8.8.8.8', '0.0.0.0', '127.0.0.1', '169.254.1.1', '172.17.0.2;id'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.h.private_ip(bad)


class HarnessBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.h = module('run_public_peer_recovery_ci')

    def test_actual_soak_payment_through_actual_agent_and_local_adapter(self):
        from types import SimpleNamespace
        h = self.h
        clock = [100.0]
        shared = {'relayed': False, 'renewed': False, 'mined': False}
        points = evidence()['floors'][0]
        class Controller:
            def __init__(self, host):
                self.host = host
                self.journal = {'checkpoint': dict(points[host])}
            def status(self):
                return {'wallet': dict(self.journal['checkpoint']),
                        'nodes': [{'height': 101, 'tip': 'bb' * 32, 'utxo_hash': 'ee' * 32, 'utxo_count': 2, 'peers': 1}]}
            def action(self, action, params, include_status=True):
                if action == 'peer_status':
                    result = {'network_active': True, 'transaction_peers': 1,
                              'declared_endpoints': ['127.0.0.1:23834'], 'connected_endpoints': ['127.0.0.1:23834']}
                elif action == 'receive':
                    index = self.journal['checkpoint']['next_receive']
                    self.journal['checkpoint']['next_receive'] += 1
                    result = {'address': 'tq1test-only', 'branch': 0, 'index': index}
                elif action == 'send':
                    self.journal['checkpoint']['next_change'] += 1
                    result = {'broadcast': True, 'txid': 'aa' * 32}
                elif action == 'renew_peer':
                    shared['renewed'] = True
                    result = renewal()
                elif action == 'rebroadcast':
                    shared['relayed'] = shared['renewed']
                    result = evidence()['reannouncements'][0]
                elif action == 'mine':
                    if not shared['relayed']:
                        raise AssertionError('Mining before receiver relay')
                    shared['mined'] = True
                    result = {'blocks': ['bb' * 32]}
                elif action == 'transaction':
                    result = (evidence()['memberships']['A'] if 'block_hash' in params else
                              {'txid': 'aa' * 32, 'in_mempool': shared['relayed']})
                else:
                    raise AssertionError('Unexpected action')
                return {'result': result, **({'status': self.status()} if include_status else {})}
        nodes = {host: SimpleNamespace(controller=Controller(host)) for host in ('A', 'B')}
        audit = h.PaymentAudit(nodes)
        config = {'hosts': [{'name': 'A', 'role': 'follower'}, {'name': 'B', 'role': 'bootstrap'}]}
        log = SimpleNamespace(append=lambda *_args: None)
        run = h.soak_api.Soak(config, 'preflight', log, {}, 'private')
        with patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(h.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
             patch.object(h, 'native', return_value=evidence()['known']):
            with tempfile.TemporaryDirectory() as directory:
                run.agents = {host: h.LocalAgent(host, h.agent_api.Agent(node.controller, directory, time.time()+60), audit)
                              for host, node in nodes.items()}
                run.statuses_now()
                audit.active = True
                audit.data['payment'] = run.payment('A', 'B')
                audit.data['drop'] = evidence()['drop']
                audit.data['agreement'] = evidence()['agreement']
                h.validate_payment(audit.data)
        self.assertTrue(shared['mined'])
        self.assertEqual(audit.data['counts'], {'send': 1, 'receive': 1, 'renew_peer': 1})
        self.assertLess(audit.data['payment']['settle_seconds'], 60)

    def test_native_observer_returns_only_bound_hashes_and_rejects_substitution(self):
        import contextlib
        import io
        import json
        from types import SimpleNamespace
        raw = '010203'
        class RPC:
            def getmempoolentry(self, txid):
                return {'vsize': 3}
            def getrawtransaction(self, txid, verbose):
                return raw
            def decoderawtransaction(self, payload):
                return {'txid': 'aa' * 32, 'hash': 'cc' * 32}
        rpc = RPC()
        class Node:
            def __init__(self, *_args):
                pass
            def rpc(self, **_kwargs):
                return rpc
        replacements = {'public_runtime': SimpleNamespace(PublicNode=Node),
                        'test_framework.authproxy': SimpleNamespace(AuthServiceProxy=None)}
        args = ['native', '/fixture', 'known', 'aa' * 32, 'v1', '3']
        with patch.dict(sys.modules, replacements), patch.object(sys, 'argv', args), patch.object(sys, 'path', list(sys.path)):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exec(compile(self.h.NATIVE_SCRIPT, '<native-test>', 'exec'), {})
            value = json.loads(output.getvalue())
            self.assertEqual(set(value), {'txid', 'wtxid', 'raw_transaction_sha256'})
            self.assertEqual(value['raw_transaction_sha256'], hashlib.sha256(bytes.fromhex(raw)).hexdigest())
            rpc.decoderawtransaction = lambda payload: {'txid': 'bb' * 32, 'hash': 'cc' * 32}
            with self.assertRaises(AssertionError), contextlib.redirect_stdout(io.StringIO()):
                exec(compile(self.h.NATIVE_SCRIPT, '<native-test>', 'exec'), {})

    def test_runtime_preflight_failure_is_retained_as_fail_without_cleanup_claim(self):
        import json
        descriptor = {'image': 'sha256:' + 'a' * 64, 'manifest_sha256': 'b' * 64,
                      'manifest': {'source_head': 'c' * 40, 'source_tree': 'd' * 40, 'architecture': 'x86_64'}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(self.h.controls.source, 'validate_descriptor', return_value=descriptor), \
                patch.object(self.h, 'checkout_identity', return_value={'head': 'e' * 40, 'tree': 'f' * 40}), \
                patch.object(self.h, 'check_runtime', side_effect=ValueError('private diagnostic must not leak')):
            output = Path(directory) / 'evidence'
            result = self.h.run(descriptor, output)
            retained = json.loads((output / 'report.json').read_text())
            self.assertEqual(result['result'], 'FAIL')
            self.assertEqual(retained['result'], 'FAIL')
            self.assertEqual(retained['failed_phase'], 'runtime_preflight')
            self.assertEqual(retained['error_class'], 'ValueError')
            self.assertEqual(retained['cleanup'], [])
            self.assertTrue(retained.get('failure_sites'))
            self.assertTrue(all(set(row) == {'file', 'function', 'line'} for row in retained['failure_sites']))
            self.assertNotIn('private diagnostic', json.dumps(retained))
            self.assertEqual(retained['public_soak_credit_seconds'], 0)
            with self.assertRaises(ValueError):
                self.h.run(descriptor, output)

    def test_adapter_preserves_timeout_and_refuses_late_result(self):
        class Agent:
            def act(self, action, params):
                return {'network_active': False}
        class Audit:
            def before(self, host, action, params, deadline):
                return params
            def after(self, host, action, params, result, deadline):
                return None
        adapter = self.h.LocalAgent('A', Agent(), Audit())
        with patch.object(self.h.time, 'monotonic', side_effect=[1, 1, 3]):
            with self.assertRaises(ValueError):
                adapter.call('peer_status', timeout=1)
        with patch.object(self.h.time, 'monotonic', return_value=1):
            self.assertEqual(adapter.call('peer_status', timeout=2), {'network_active': False})
        for timeout in (0, -1, float('nan'), True):
            with self.assertRaises(ValueError):
                adapter.call('peer_status', timeout=timeout)

    def test_cleanup_requires_full_layout_and_stable_identity_before_stop(self):
        import json
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            name = 'pqbtc-mldsa-public-recovery-' + 'a' * 32
            manager = self.h.controls.PublicManager(Path(directory), container=name, p2p_port=23933)
            manager.descriptor = {'image': 'sha256:' + 'c' * 64, 'manifest_sha256': 'd' * 64}
            row = {'Id': 'a' * 64, 'Name': '/' + name, 'Image': manager.descriptor['image'],
                   'State': {'Running': True, 'Pid': 42},
                   'Config': {'Labels': manager.container_labels(), 'Cmd': ['sleep', 'infinity'], 'User': ''},
                   'HostConfig': {'ReadonlyRootfs': True, 'NetworkMode': 'bridge', 'Memory': 1073741824,
                                  'NanoCpus': 2000000000, 'PidsLimit': 256, 'CapDrop': ['ALL'], 'CapAdd': [],
                                  'SecurityOpt': ['no-new-privileges'], 'Privileged': False, 'Tmpfs': self.h.controls.TMPFS,
                                  'RestartPolicy': {'Name': 'unless-stopped'},
                                  'PortBindings': {'23833/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '23933'}]}},
                   'Mounts': [{'Type': 'volume', 'Name': manager.volume, 'Destination': '/var/lib/pqbtc', 'RW': True}]}
            marker = {'volume_id': 'e' * 32, 'profile_sha256': self.h.controls.PROFILE}
            manager._write_json('public-runtime.json', {'schema': 'PQBTC-MLDSA44-PUBLIC-RUNTIME-1',
                'compatibility': self.h.controls.COMPATIBILITY, 'container': name, 'volume': manager.volume,
                'volume_id': marker['volume_id'], 'port': 23933, 'descriptor': manager.descriptor})
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                if args[0] == 'stop':
                    self.assertEqual(args[-1], 'a' * 64)
                    row['State'] = {'Running': False, 'Pid': 0}
                result = marker if args[0] == 'exec' else row
                return SimpleNamespace(returncode=0, stdout=json.dumps(result).encode(), stderr=b'')
            manager.run = run
            owned = self.h.OwnedNode(SimpleNamespace(manager=manager))
            # Unknown post-create ID must be discovered through the full layout.
            row['HostConfig']['Memory'] = 1
            with self.assertRaises(Exception):
                owned.stop()
            self.assertFalse(any(call[0] == 'stop' for call in calls))
            row['HostConfig']['Memory'] = 1073741824
            owned.discover()
            row['Id'] = 'b' * 64
            with self.assertRaises(Exception):
                owned.stop()
            self.assertFalse(any(call[0] == 'stop' for call in calls))
            row['Id'] = 'a' * 64
            result = owned.stop()
            self.assertEqual(result['container_id'], 'a' * 64)
            self.assertEqual(result['pid'], 0)
            self.assertFalse(result['running'])
            self.assertEqual(result['volume_id'], 'e' * 32)

    def test_audit_rejects_second_issuance_and_changed_recovery_floor(self):
        from types import SimpleNamespace
        nodes = {host: SimpleNamespace(controller=SimpleNamespace(journal={'checkpoint': point}))
                 for host, point in evidence()['floors'][0].items()}
        audit = self.h.PaymentAudit(nodes)
        audit.active = True
        audit.before('B', 'receive', {}, time.monotonic() + 3)
        with self.assertRaises(ValueError):
            audit.before('B', 'receive', {}, time.monotonic() + 3)
        audit = self.h.PaymentAudit(nodes)
        audit.active = True
        audit.before('A', 'send', {}, time.monotonic() + 3)
        audit.after('A', 'send', {}, {'result': {'txid': 'aa' * 32}, 'status': {}}, time.monotonic() + 3)
        nodes['A'].controller.journal['checkpoint']['next_change'] += 1
        with self.assertRaises(ValueError):
            audit.before('B', 'transaction', {'txid': 'aa' * 32}, time.monotonic() + 3)

    def test_failure_report_cannot_claim_pass_without_two_stopped_nodes(self):
        value = {'payment_evidence': evidence(), 'v2': {'renewal': renewal('v2'), 'endpoint': '127.0.0.1:23834',
                 'unrelated_before': {'id': 5}, 'unrelated_after': {'id': 5}, 'floors_before': {}, 'floors_after': {}},
                 'network_off': {'refused': True, 'network_active': False, 'saved_network_active': False,
                                 'floors_before': {}, 'floors_after': {}},
                 'cleanup': [{'container_id': c * 64, 'volume_id': c * 32, 'running': False, 'pid': 0, 'retained': True}
                             for c in ('a', 'b')], 'proxy_stop': {'ok': True, 'active_connections': 0},
                 'public_soak_credit_seconds': 0, 'watchdog_expired': False, 'cleanup_errors': [],
                 'startup_helpers': [{'name': 'pqbtc-mldsa-recovery-helper-'+format(index, '032x'),
                                      'kind': kind, 'container_id': None, 'absence_proved': True, 'launch_state': 'START_ACKNOWLEDGED',
                                      'running': False, 'pid': 0, 'memory_bytes': memory,
                                      'nano_cpus': 2000000000, 'pids_limit': 64}
                                     for index, (kind, memory) in enumerate((('image_check', 268435456),
                                        ('volume_init', 134217728), ('image_check', 268435456), ('volume_init', 134217728)))]}
        self.h.validate_acceptance(value)
        for field, replacement in (('cleanup', value['cleanup'][:1]), ('public_soak_credit_seconds', 1),
                                   ('watchdog_expired', True), ('cleanup_errors', ['ValueError']), ('startup_helpers', [])):
            broken = copy.deepcopy(value)
            broken[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.h.validate_acceptance(broken)
        unresolved = copy.deepcopy(value)
        unresolved['startup_helpers'][0]['launch_state'] = 'CREATE_UNRESOLVED'
        with self.assertRaises(ValueError):
            self.h.validate_acceptance(unresolved)
        for field in ('pid', 'running'):
            broken = copy.deepcopy(value)
            broken['cleanup'][0][field] = 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.h.validate_acceptance(broken)

    def test_proxy_connected_stop_closes_both_sockets(self):
        p = module('peer_recovery_proxy')
        with tempfile.TemporaryDirectory() as directory, socket.socket() as upstream, socket.socket() as port_probe:
            upstream.bind(('127.0.0.1', 0))
            upstream.listen(1)
            upstream.settimeout(3)
            upstream_address = upstream.getsockname()
            port_probe.bind(('127.0.0.1', 0))
            port = port_probe.getsockname()[1]
            port_probe.close()
            original_connect = socket.create_connection
            def connect(address, **kwargs):
                return original_connect(upstream_address, **kwargs)
            path = str(Path(directory) / 'control')
            errors = []
            def serve():
                try:
                    p.serve(path, '127.0.0.1', listen_port=port)
                except Exception as error:
                    errors.append(type(error).__name__)
            with patch.object(p.socket, 'create_connection', side_effect=connect):
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                deadline = time.monotonic() + 3
                while not os.path.exists(path) and time.monotonic() < deadline:
                    time.sleep(.01)
                with socket.socket() as client:
                    client.settimeout(3)
                    client.connect(('127.0.0.1', port))
                    target, _ = upstream.accept()
                    with target, socket.socket(socket.AF_UNIX) as control:
                        target.settimeout(3)
                        client.sendall(frame(b'verack'))
                        self.assertEqual(target.recv(24), frame(b'verack'))
                        control.settimeout(3)
                        control.connect(path)
                        control.sendall(b'{"op":"stop"}\n')
                        import json
                        self.assertEqual(json.loads(control.recv(4096))['active_connections'], 0)
                        self.assertEqual(client.recv(1), b'')
                        self.assertEqual(target.recv(1), b'')
                thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertFalse(os.path.exists(path))


class StartupHelperTests(unittest.TestCase):
    def setUp(self):
        self.h = module('run_public_peer_recovery_ci')
        self.assertTrue(hasattr(self.h, 'StartupHelpers'), 'Startup helpers must be owned before Docker run')

    def fixture(self, directory, kind, *, lose_response=False, corrupt=None):
        import json
        from types import SimpleNamespace
        h = self.h
        name = 'pqbtc-mldsa-public-recovery-' + 'a' * 32
        manager = h.controls.PublicManager(Path(directory), container=name, p2p_port=23933)
        descriptor = {'image': 'sha256:' + 'b' * 64, 'manifest_sha256': 'c' * 64}
        state = {'row': None, 'calls': [], 'launch': None, 'registered_before_run': False, 'pause': lambda: None, 'output': b'product-result',
                 'before_dispatch': lambda _args: None, 'delay_create': False, 'start_count': 0}
        helpers = h.StartupHelpers(time.monotonic() + 60)
        def original(args, **kwargs):
            state['calls'].append(list(args))
            state['before_dispatch'](args)
            if args[0] in ('run', 'create'):
                state['launch'] = list(args)
                state['registered_before_run'] = len(helpers.records) == 1
                labels = {'org.pqbtc.console.build': 'source-1', **dict(args[i+1].split('=', 1) for i, value in enumerate(args) if value == '--label')}
                helper_name = args[args.index('--name')+1]
                host = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'NanoCpus': 2000000000,
                        'Memory': int(args[args.index('--memory')+1]), 'PidsLimit': int(args[args.index('--pids-limit')+1]),
                        'CapDrop': ['ALL'], 'CapAdd': ['CHOWN'] if kind == 'volume_init' else None,
                        'SecurityOpt': ['no-new-privileges'], 'Privileged': False, 'AutoRemove': True,
                        'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'PortBindings': {},
                        'Binds': None, 'Tmpfs': None, 'Devices': [], 'DeviceRequests': None,
                        'PidMode': '', 'IpcMode': 'private'}
                row = {'Id': 'd' * 64, 'Name': '/' + helper_name, 'Image': descriptor['image'],
                       'Config': {'Labels': labels, 'User': '1001:1000' if kind == 'image_check' else ''},
                       'HostConfig': host, 'State': {'Running': args[0] == 'run', 'Pid': 111 if args[0] == 'run' else 0},
                       'Mounts': ([] if kind == 'image_check' else [{'Type': 'volume', 'Name': manager.volume,
                                   'Destination': '/var/lib/pqbtc', 'RW': True}])}
                if corrupt:
                    corrupt(row)
                state['created_row'] = copy.deepcopy(row)
                if state['delay_create']:
                    state['pending_creation'] = row
                    raise h.controls.legacy.ConsoleError('simulated timeout before daemon create becomes visible')
                state['row'] = row
                if args[0] == 'create':
                    return SimpleNamespace(returncode=0, stdout=(row['Id']+'\n').encode(), stderr=b'')
                state['pause']()
                if lose_response:
                    raise h.controls.legacy.ConsoleError('simulated Docker timeout after creation')
                state['row'] = None
                return SimpleNamespace(returncode=0, stdout=state['output'], stderr=b'')
            if args[0] == 'start':
                self.assertEqual(args, ['start', '--attach', 'd'*64])
                if state['row'] is None or state['row']['Id'] != args[-1]:
                    raise h.controls.legacy.ConsoleError('start target has been removed')
                state['start_count'] += 1
                state['row']['State'] = {'Running': True, 'Pid': 111}
                state['pause']()
                if lose_response:
                    raise h.controls.legacy.ConsoleError('simulated ambiguous start response')
                state['row'] = None  # --rm completed before attached response.
                return SimpleNamespace(returncode=0, stdout=state['output'], stderr=b'')
            if args[0] in ('stop', 'rm') and state.get('missing_on') == args[0]:
                state['row'] = None
                return SimpleNamespace(returncode=1, stdout=b'',
                    stderr=('error response from daemon: no such container: '+args[-1]+'\n').encode())
            if args[0] == 'stop' and state['row'] is not None:
                self.assertEqual(args[-1], 'd' * 64)
                state['row']['State'] = {'Running': False, 'Pid': 0}
            if args[0] == 'rm':
                self.assertEqual(args, ['rm', '--force', 'd'*64])
                state['row'] = None
                return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            row = state['row']
            if row is None:
                return SimpleNamespace(returncode=1, stdout=b'\n', stderr=('error: no such object: '+args[-1]+'\n').encode())
            return SimpleNamespace(returncode=0, stdout=json.dumps(row).encode(), stderr=b'')
        manager.run = original
        helpers.attach(manager, descriptor)
        args = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL']
        if kind == 'image_check':
            args += ['--security-opt', 'no-new-privileges', '--memory', '268435456', '--pids-limit', '64', '--user', '1001:1000']
        else:
            args += ['--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges', '--mount',
                     'type=volume,source='+manager.volume+',target=/var/lib/pqbtc,volume-nocopy']
        args += [descriptor['image'], 'python3', '-c', 'unchanged product script', 'public-argument']
        return helpers, manager, args, state

    def test_helpers_are_registered_bounded_and_preserve_product_arguments(self):
        for kind, memory in (('image_check', '268435456'), ('volume_init', '134217728')):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                helpers, manager, args, state = self.fixture(directory, kind)
                result = manager.run(args)
                self.assertEqual(result.stdout, b'product-result')
                self.assertTrue(state['registered_before_run'])
                launch = state['launch']
                self.assertEqual(launch[launch.index('--memory')+1], memory)
                self.assertEqual(launch[launch.index('--cpus')+1], '2')
                self.assertEqual(launch[launch.index('--pids-limit')+1], '64')
                image_index = launch.index('sha256:' + 'b'*64)
                self.assertEqual(launch[image_index:], args[args.index('sha256:' + 'b'*64):])
                self.assertEqual(helpers.receipts()[0]['absence_proved'], True)
                self.assertFalse(any(call[0] == 'stop' for call in state['calls']))

    def test_lost_run_response_discovers_full_identity_and_proves_pid_zero(self):
        for kind in ('image_check', 'volume_init'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                helpers, manager, args, state = self.fixture(directory, kind, lose_response=True)
                with self.assertRaises(self.h.controls.legacy.ConsoleError):
                    manager.run(args)
                row = helpers.receipts()[0]
                self.assertEqual(row['container_id'], 'd' * 64)
                self.assertEqual(row['pid'], 0)
                self.assertIs(row['running'], False)
                self.assertEqual(len([call for call in state['calls'] if call[0] == 'stop']), 1)

    def test_lost_response_with_changed_layout_never_stops_unowned_helper(self):
        for corrupt in (lambda row: row['HostConfig'].update(Memory=1),
                        lambda row: row['Config'].update(User='wrong'),
                        lambda row: row['Config'].update(Labels={}),
                        lambda row: row['Mounts'].append({'Type': 'bind', 'Destination': '/etc'})):
            with tempfile.TemporaryDirectory() as directory:
                helpers, manager, args, state = self.fixture(directory, 'image_check', lose_response=True, corrupt=corrupt)
                with self.assertRaises(Exception):
                    manager.run(args)
                self.assertFalse(any(call[0] == 'stop' for call in state['calls']))
                with self.assertRaises(Exception):
                    helpers.stop_all()

    def test_product_image_checker_still_executes_and_validates_its_result(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'image_check')
            descriptor = {'image': 'sha256:'+'b'*64, 'manifest_sha256': 'c'*64,
                'manifest': {'checks': {name: 'PASS' for name in ('native_integration', 'signer', 'mldsa44_node_tests',
                                                               'mldsa44_public_tests', 'mldsa44_resource_tests')},
                             'sha256': {'/tmp/mldsa-demo-source/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md': self.h.controls.wallet.SPEC}}}
            state['output'] = json.dumps(descriptor['manifest']).encode()
            with patch.object(self.h.controls.source, 'validate_descriptor', return_value=descriptor):
                self.assertEqual(manager.image_check(descriptor), descriptor)
                state['output'] = b'{}'
                with self.assertRaises(self.h.controls.legacy.ConsoleError):
                    manager.image_check(descriptor)
            self.assertEqual(len(helpers.receipts()), 2)

    def test_watchdog_cleans_helper_while_run_is_blocked_and_serializes_launches(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'volume_init', lose_response=True)
            entered, release = threading.Event(), threading.Event()
            errors = []
            def pause():
                entered.set()
                if not release.wait(3):
                    raise AssertionError('Test did not release Docker run')
            state['pause'] = pause
            def launch():
                try:
                    manager.run(args)
                except Exception as error:
                    errors.append(type(error).__name__)
            first = threading.Thread(target=launch)
            second = threading.Thread(target=launch)
            first.start()
            self.assertTrue(entered.wait(3))
            second.start()
            helpers.stop_all()
            self.assertIsNone(state['row'])
            release.set()
            first.join(3)
            second.join(3)
            self.assertFalse(first.is_alive() or second.is_alive())
            self.assertEqual(len([call for call in state['calls'] if call[0] in ('run', 'create')]), 1)
            self.assertEqual(len(errors), 2)
            self.assertEqual(helpers.receipts()[0]['pid'], 0)

    def test_helper_identity_replacement_is_never_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'image_check', lose_response=True)
            with self.assertRaises(self.h.controls.legacy.ConsoleError):
                manager.run(args)
            stopped_count = len([call for call in state['calls'] if call[0] in ('stop', 'rm')])
            state['row'] = copy.deepcopy(state['created_row'])
            state['row']['Id'] = 'e' * 64
            state['row']['State'] = {'Running': True, 'Pid': 222}
            with self.assertRaises(ValueError):
                helpers.stop_all()
            self.assertEqual(len([call for call in state['calls'] if call[0] in ('stop', 'rm')]), stopped_count)

    def test_more_than_four_startup_helpers_is_refused_before_docker_run(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'image_check')
            for _ in range(4):
                manager.run(args)
            with self.assertRaises(ValueError):
                manager.run(args)
            self.assertEqual(len([call for call in state['calls'] if call[0] in ('run', 'create')]), 4)

    def test_watchdog_between_launch_gate_and_create_dispatch_cannot_claim_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'volume_init')
            entered, release = threading.Event(), threading.Event()
            errors = []
            def before_dispatch(command):
                if command[0] in ('create', 'run'):
                    entered.set()
                    if not release.wait(3):
                        raise AssertionError('test did not release dispatch')
            state['before_dispatch'] = before_dispatch
            def launch():
                try:
                    manager.run(args)
                except Exception as error:
                    errors.append(type(error).__name__)
            thread = threading.Thread(target=launch)
            thread.start()
            self.assertTrue(entered.wait(3))
            try:
                with self.assertRaises(ValueError):
                    helpers.stop_all()
                receipt = helpers.receipts()[0]
                self.assertIs(receipt.get('cleanup_unproved'), True)
                self.assertIsNot(receipt.get('absence_proved'), True)
            finally:
                release.set()
                thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertTrue(errors)
            self.assertEqual(state['start_count'], 0)
            self.assertEqual(state['row']['State'], {'Running': False, 'Pid': 0})
            helpers.stop_all()
            self.assertFalse(helpers.receipts()[0]['absence_proved'])

    def test_delayed_create_after_timeout_remains_unresolved_and_can_never_start(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'image_check')
            state['delay_create'] = True
            with self.assertRaises(Exception):
                manager.run(args)
            with self.assertRaises(ValueError):
                helpers.stop_all()
            receipt = helpers.receipts()[0]
            self.assertEqual(receipt.get('launch_state'), 'CREATE_UNRESOLVED')
            self.assertIs(receipt.get('cleanup_unproved'), True)
            self.assertIsNot(receipt.get('absence_proved'), True)
            # Model daemon completion after the CLI timed out and an absence
            # scan returned. create is deliberately incapable of starting it.
            state['row'] = state['pending_creation']
            self.assertEqual(state['row']['State'], {'Running': False, 'Pid': 0})
            self.assertEqual(state['start_count'], 0)
            helpers.stop_all()
            self.assertFalse(helpers.receipts()[0]['running'])
            self.assertEqual(helpers.receipts()[0]['pid'], 0)
            self.assertEqual(state['start_count'], 0)

    def test_watchdog_after_validated_create_prevents_start_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'image_check')
            fired = []
            def before_dispatch(command):
                if command[0] == 'inspect' and command[-1] == 'd'*64 and not fired:
                    fired.append(True)
                    helpers.stop_all()
            state['before_dispatch'] = before_dispatch
            with self.assertRaises(ValueError):
                manager.run(args)
            self.assertEqual(fired, [True])
            self.assertFalse(any(call[0] == 'start' for call in state['calls']))
            self.assertEqual(state['row']['State'], {'Running': False, 'Pid': 0})

    def test_ambiguous_start_with_changed_layout_refuses_stop_and_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'image_check', lose_response=True)
            def changed():
                state['row']['HostConfig']['Memory'] = 1
            state['pause'] = changed
            with self.assertRaises(ValueError):
                manager.run(args)
            self.assertEqual(state['start_count'], 1)
            self.assertFalse(any(call[0] in ('stop', 'rm') for call in state['calls']))
            with self.assertRaises(ValueError):
                helpers.stop_all()

    def test_watchdog_after_start_gate_fences_id_before_delayed_start(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'volume_init')
            fired = []
            def before_dispatch(command):
                if command[0] == 'start':
                    helpers.stop_all()
                    fired.append(True)
                    self.assertIsNone(state['row'])
            state['before_dispatch'] = before_dispatch
            with self.assertRaises(self.h.controls.legacy.ConsoleError):
                manager.run(args)
            self.assertEqual(fired, [True])
            self.assertEqual(state['start_count'], 0)
            self.assertEqual([call for call in state['calls'] if call[0] == 'rm'], [['rm', '--force', 'd'*64]])
            self.assertIs(helpers.receipts()[0]['absence_proved'], True)

    def test_lowercase_absence_during_stop_or_remove_fence_is_verified(self):
        for operation in ('stop', 'rm'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                helpers, manager, args, state = self.fixture(directory, 'image_check', lose_response=True)
                state['missing_on'] = operation
                with self.assertRaises(self.h.controls.legacy.ConsoleError):
                    manager.run(args)
                self.assertTrue(helpers.receipts()[0]['absence_proved'])
                self.assertEqual(helpers.receipts()[0]['container_id'], 'd'*64)

    def test_terminal_watchdog_prevents_any_later_helper_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            helpers, manager, args, state = self.fixture(directory, 'volume_init')
            helpers.stop_all()
            with self.assertRaises(ValueError):
                manager.run(args)
            self.assertIsNone(state['launch'])


class ProxyReplacementTests(unittest.TestCase):
    def test_listener_before_old_eof_forwards_replacement_and_rejects_third(self):
        import selectors
        p = module('peer_recovery_proxy')
        real_selector = selectors.DefaultSelector
        arm, blocked, release = threading.Event(), threading.Event(), threading.Event()
        order, errors = [], []
        class OrderedSelector:
            def __init__(self):
                self.delegate = real_selector()
            def __getattr__(self, name):
                return getattr(self.delegate, name)
            def select(self, timeout):
                if arm.is_set() and not blocked.is_set():
                    blocked.set()
                    if not release.wait(3):
                        raise AssertionError('test did not release selector')
                    events = self.delegate.select(timeout)
                    events.sort(key=lambda event: event[0].data != 'listen')
                    order.extend('listen' if key.data == 'listen' else 'peer' for key, _ in events)
                    return events
                return self.delegate.select(timeout)
        with tempfile.TemporaryDirectory() as directory, socket.socket() as upstream, socket.socket() as probe:
            upstream.bind(('127.0.0.1', 0))
            upstream.listen(2)
            upstream.settimeout(3)
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
            probe.close()
            address = upstream.getsockname()
            connector = socket.create_connection
            path = str(Path(directory) / 'control')
            def serve():
                try:
                    p.serve(path, '127.0.0.1', listen_port=port)
                except Exception as error:
                    errors.append(str(error))
            with patch.object(p.selectors, 'DefaultSelector', OrderedSelector), \
                    patch.object(p.socket, 'create_connection', side_effect=lambda *_args, **kwargs: connector(address, **kwargs)):
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                deadline = time.monotonic()+3
                while not os.path.exists(path) and time.monotonic() < deadline:
                    time.sleep(.01)
                with socket.socket() as first, socket.socket() as second, socket.socket() as third:
                    first.settimeout(3)
                    second.settimeout(3)
                    first.connect(('127.0.0.1', port))
                    target, _ = upstream.accept()
                    with target:
                        target.settimeout(3)
                        first.sendall(frame(b'verack'))
                        self.assertEqual(target.recv(24), frame(b'verack'))
                        arm.set()
                        self.assertTrue(blocked.wait(3))
                        first.shutdown(socket.SHUT_RDWR)
                        first.close()
                        second.connect(('127.0.0.1', port))
                        second.sendall(frame(b'ping', b'12345678'))
                        release.set()
                        replacement, _ = upstream.accept()
                        with replacement:
                            replacement.settimeout(3)
                            self.assertEqual(replacement.recv(32), frame(b'ping', b'12345678'))
                            self.assertTrue(thread.is_alive())
                            self.assertEqual(errors, [])
                            self.assertEqual(order[0], 'listen')
                            self.assertIn('peer', order[1:])
                            third.connect(('127.0.0.1', port))
                            thread.join(3)
                            self.assertFalse(thread.is_alive())
                            self.assertEqual(second.recv(1), b'')
            release.set()
            thread.join(3)
            self.assertEqual(errors, ['PROXY_EXTRA_CONNECTION'])
            self.assertFalse(os.path.exists(path))


class AbsenceAndFailureSiteTests(unittest.TestCase):
    def setUp(self):
        self.h = module('run_public_peer_recovery_ci')

    def test_exact_docker_absence_forms_bind_target_and_refuse_other_errors(self):
        from types import SimpleNamespace
        self.assertTrue(hasattr(self.h, 'docker_absent'))
        target = 'pqbtc-mldsa-public-recovery-' + '0'*32
        for prefix in ('error: no such object: ', 'Error: No such object: ',
                       'Error response from daemon: No such container: '):
            result = SimpleNamespace(returncode=1, stdout=b'\n', stderr=(prefix+target+'\n').encode())
            self.assertTrue(self.h.docker_absent(result, target))
        volume = target + '-data-v1'
        result = SimpleNamespace(returncode=1, stdout=b'',
            stderr=('Error response from daemon: get '+volume+': no such volume\n').encode())
        self.assertTrue(self.h.docker_absent(result, volume, 'volume'))
        self.assertFalse(self.h.docker_absent(result, volume, 'container'))
        for stderr in (b'permission denied', b'Cannot connect to the Docker daemon', b'template parsing error',
                       ('error: no such object: '+target+'-other\n').encode(),
                       ('permission denied; no such object: '+target).encode(),
                       ('error: no such object: '+target+'\npermission denied\n').encode()):
            result = SimpleNamespace(returncode=1, stdout=b'', stderr=stderr)
            self.assertFalse(self.h.docker_absent(result, target))
        for rc, stdout in ((0, b''), (125, b''), (1, b'{}')):
            self.assertFalse(self.h.docker_absent(SimpleNamespace(returncode=rc, stdout=stdout,
                stderr=('error: no such object: '+target).encode()), target))

    def test_owned_node_accepts_actual_lowercase_missing_object(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            name = 'pqbtc-mldsa-public-recovery-' + '0'*32
            manager = self.h.controls.PublicManager(Path(directory), container=name)
            manager.run = lambda args, **kwargs: SimpleNamespace(returncode=1, stdout=b'\n',
                stderr=('error: no such object: '+args[-1]+'\n').encode())
            node = self.h.OwnedNode(SimpleNamespace(manager=manager))
            self.assertIsNone(node.inspect())
            self.assertEqual(node.stop(), {'container': name, 'created': False, 'retained': True})

    def test_failure_sites_emit_only_fixed_project_locations_and_are_bounded(self):
        import json
        self.assertTrue(hasattr(self.h, 'failure_sites'))
        allowed = str(HERE / 'run_public_peer_recovery_ci.py')
        scope = {}
        source = '\n'.join('def frame%d():\n    %s' % (i, 'frame%d()' % (i+1) if i < 39 else
                            'raise ValueError("PRIVATE_ARGUMENT_DO_NOT_EMIT")') for i in range(40))
        exec(compile(source, allowed, 'exec'), scope)
        outside = {}
        exec(compile('def outside(callback):\n    callback()', '/private/not-a-project/secret.py', 'exec'), outside)
        try:
            outside['outside'](scope['frame0'])
        except ValueError as error:
            sites = self.h.failure_sites(error)
        self.assertEqual(len(sites), 8)
        self.assertTrue(all(set(row) == {'file', 'function', 'line'} and
            row['file'] == 'contrib/ml-dsa-qualification/run_public_peer_recovery_ci.py' and
            type(row['line']) is int and row['line'] > 0 for row in sites))
        rendered = json.dumps(sites)
        self.assertNotIn('PRIVATE_ARGUMENT', rendered)
        self.assertNotIn('/private/', rendered)
        scope['frame39'].__code__ = scope['frame39'].__code__.replace(co_name='unsafe / function name')
        try:
            scope['frame39']()
        except ValueError as error:
            self.assertEqual(self.h.failure_sites(error), [])


if __name__ == '__main__':
    unittest.main()
