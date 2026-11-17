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
                 'public_soak_credit_seconds': 0, 'watchdog_expired': False, 'cleanup_errors': []}
        self.h.validate_acceptance(value)
        for field, replacement in (('cleanup', value['cleanup'][:1]), ('public_soak_credit_seconds', 1),
                                   ('watchdog_expired', True), ('cleanup_errors', ['ValueError'])):
            broken = copy.deepcopy(value)
            broken[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.h.validate_acceptance(broken)
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


if __name__ == '__main__':
    unittest.main()
