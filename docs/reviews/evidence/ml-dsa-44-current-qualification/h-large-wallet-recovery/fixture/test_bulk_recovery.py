"""No-runtime protocol, count, redaction, and owned-cleanup checks."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bulk_fixture', Path(__file__).with_name('bulk_recovery.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def payload(branch, index):
    program = (branch * 10000 + index + 1).to_bytes(32, 'little')
    return bytes([branch]) + index.to_bytes(4, 'little') + b'P' * 1312 + program


class FakeSigner:
    fail_at = None
    calls = []

    def __init__(self, binary, socket, uid, network):
        self.floors = [1, 0]
        self.calls.clear()
        if not (binary.endswith('/bin/pqbtc-mldsa-client') and socket.endswith('/public/signer.sock')
                and uid == 1000 and network == 'test'):
            raise ValueError('WRONG_NATIVE_API')

    def call(self, kind, body=b''):
        self.calls.append((kind, body))
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            raise RuntimeError('SENSITIVE AMBIGUOUS NATIVE FAILURE')
        if kind == 5:
            return {'wallet_id': 'ab' * 16, 'next_receive': self.floors[0], 'next_change': self.floors[1], 'locked': False}
        branch = body[0]
        value = payload(branch, self.floors[branch])
        self.floors[branch] += 1
        return value


def batch():
    before = {'wallet_id': 'ab' * 16, 'next_receive': 1, 'next_change': 0, 'locked': False}
    module = types.ModuleType('node_wallet')
    module.NativeSigner, module.parse_status = FakeSigner, lambda value: value
    output = io.StringIO()
    with patch.dict(sys.modules, node_wallet=module), patch.object(sys, 'stdin', io.StringIO(json.dumps({
        'before': before, 'branches': h.plan_branches()}))), patch.object(sys, 'stdout', output), patch.object(sys, 'path', list(sys.path)):
        exec(compile(h.BATCH_SCRIPT, '<contained-batch-fixture>', 'exec'), {})
    return json.loads(output.getvalue())


def owned():
    return {'Name': '/' + h.CONTAINER, 'Id': 'a' * 64, 'Image': h.IMAGE,
            'Config': {'Labels': {'org.pqbtc.console.schema': 'public-test-1', 'org.pqbtc.console.profile': h.PROFILE,
                                 'org.pqbtc.console.build': 'source-1', 'org.pqbtc.console.manifest': h.MANIFEST}},
            'HostConfig': {'ReadonlyRootfs': True, 'PortBindings': {'23833/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(h.PORT)}]}},
            'Mounts': [{'Type': 'volume', 'Name': h.VOLUME, 'Destination': '/var/lib/pqbtc', 'RW': True}],
            'State': {'Running': True, 'Pid': 12}}


class FixtureTests(unittest.TestCase):
    def setUp(self):
        FakeSigner.fail_at = None

    def test_exact_bulk_native_protocol_and_sizes(self):
        result = batch()
        self.assertEqual(len(result['entries']), 1449)
        self.assertEqual((result['after']['next_receive'], result['after']['next_change']), (725, 725))
        self.assertEqual(len(FakeSigner.calls), 1451)
        self.assertEqual(FakeSigner.calls[0], (5, b''))
        self.assertEqual(FakeSigner.calls[-1], (5, b''))
        self.assertEqual(len(payload(0, 0)), 1349)
        self.assertEqual(2 + 43 + 4 + h.COUNT * len(payload(0, 0)), 1956099)

    def test_ambiguous_reservation_is_never_retried(self):
        FakeSigner.fail_at = 8
        with self.assertRaisesRegex(RuntimeError, 'AMBIGUOUS'):
            batch()
        self.assertEqual(len(FakeSigner.calls), 8)

    def test_assembly_rejects_missing_duplicate_wrong_path_or_floor(self):
        result = batch()
        first = payload(0, 0)
        base = {'wallet_id': 'ab' * 16, 'next_receive': 1, 'next_change': 0,
                'entries': [{'branch': 0, 'index': 0, 'public_key': first[5:1317].hex(), 'program': first[1317:].hex()}]}
        manifest = h.assemble_manifest(base, result, lambda x: x)
        self.assertEqual(len(manifest['entries']), 1450)
        self.assertEqual(len(base['entries']), 1)
        for mutate in [lambda x: x['entries'].pop(),
                       lambda x: x['entries'][1].update(program=x['entries'][0]['program']),
                       lambda x: x['entries'][0].update(index=1),
                       lambda x: x['after'].update(next_receive=724)]:
            changed = copy.deepcopy(result)
            mutate(changed)
            with self.assertRaises(ValueError):
                h.assemble_manifest(base, changed, lambda x: x)

    def test_exception_redaction_including_dynamic_class_and_subprocess(self):
        secret = 'NEVER EMIT PASSWORD OR PUBLIC KEYS'
        values = [RuntimeError(secret), subprocess.CalledProcessError(1, secret, output=secret, stderr=secret),
                  type(secret, (Exception,), {})(secret)]
        text = json.dumps([h.safe_error(error) for error in values])
        self.assertNotIn(secret, text)
        self.assertNotIn('cmd', text)

    def test_cleanup_rejects_wrong_container_image_labels_mount_port_and_id(self):
        value = owned()
        self.assertEqual(h.validate_owned(value, 'a' * 64), 'a' * 64)
        changes = [lambda x: x.update(Name='/pqbtc-mldsa-local'), lambda x: x.update(Image='other'),
                   lambda x: x['Config']['Labels'].update({'org.pqbtc.console.manifest': 'other'}),
                   lambda x: x['Mounts'][0].update(Name='original-wallet-volume'),
                   lambda x: x['HostConfig']['PortBindings']['23833/tcp'][0].update(HostPort='23833'),
                   lambda x: x.update(Id='b' * 64)]
        for mutate in changes:
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.assertRaises(ValueError):
                h.validate_owned(changed, 'a' * 64)

    def test_guarded_cleanup_stops_only_bound_identity_and_proves_pid_zero(self):
        value, calls = owned(), []
        volume = {'name': h.VOLUME, 'driver': 'local', 'options': None, 'labels': {
            'org.pqbtc.console.schema': 'public-test-1', 'org.pqbtc.console.profile': h.PROFILE}}

        def run(args, **kwargs):
            calls.append(args)
            result = volume if args[0] == 'volume' else value
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(result).encode(), stderr=b'')

        manager = types.SimpleNamespace(container=h.CONTAINER, volume=h.VOLUME, port=h.PORT, run=run)

        def stop(actual):
            self.assertIs(actual, manager)
            value['State'] = {'Running': False, 'Pid': 0}

        agent = types.SimpleNamespace(stop_owned_public=stop)
        result = h.stop_owned(types.SimpleNamespace(manager=manager), agent, ['a' * 64])
        self.assertTrue(result['backend_stopped'])
        self.assertEqual(result['pid'], 0)
        self.assertTrue(all(arg[0] in ('inspect', 'volume') for arg in calls))
        value['Id'] = 'b' * 64
        with self.assertRaises(ValueError):
            h.stop_owned(types.SimpleNamespace(manager=manager), agent, ['a' * 64])

    def test_instrumentation_preserves_exact_checkpoint_timeout(self):
        stream = io.StringIO()
        calls = []
        controller = types.SimpleNamespace(journal={'manifest': {'entries': []}})
        controller._line = lambda process, timeout, maximum: calls.append((timeout, maximum)) or b'checkpoint'

        def start(password, **kwargs):
            self.assertEqual(password, 'S' * 43)
            controller._line(None, 45, 512)
            return {'next_receive': 725, 'next_change': 725}

        controller._start_signer = start
        observations = h.instrument_signer(controller, h.Trace(stream))
        controller._start_signer('S' * 43, retain=False, public_entries=[{}] * 1450)
        self.assertEqual(calls, [(45, 512)])
        self.assertEqual(observations[0]['frame_bytes'], 1956099)
        self.assertNotIn('S' * 43, stream.getvalue())
        self.assertIn('native_checkpoint_received', stream.getvalue())

    def test_real_public_manifest_validator_and_canonical_size_without_native(self):
        with patch.object(sys, 'path', list(sys.path)):
            spec = importlib.util.spec_from_file_location('bulk_public_only_wallet',
                h.ROOT / 'contrib/ml-dsa-signer/node_wallet.py')
            wallet = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(wallet)
            entries = []
            for branch in (0, 1):
                for index in range(725):
                    public_key = bytes([branch]) + index.to_bytes(4, 'little') + b'P' * 1307
                    entries.append({'branch': branch, 'index': index, 'public_key': public_key.hex(),
                                    'program': wallet.protocol.key_commitment('test', public_key).hex()})
            manifest = {'schema': wallet.SCHEMA, 'spec_sha256': wallet.SPEC,
                        'network_binding': wallet.protocol.binding('test').hex(), 'wallet_id': 'ab' * 16,
                        'next_receive': 725, 'next_change': 725, 'entries': entries}
            self.assertEqual(wallet.validate_manifest(manifest, network='test'), manifest)
            size = len(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode())
            self.assertLess(size, 4 * 1024 * 1024)
            self.assertLess(2 * size + 65536, 20 * 1024 * 1024)
            manifest['entries'][0]['program'] = '00' * 32
            with self.assertRaises(ValueError):
                wallet.validate_manifest(manifest, network='test')

    def test_complete_control_sequence_requires_quarantine_before_bulk_recover(self):
        events = []
        first = payload(0, 0)
        base = {'wallet_id': 'ab' * 16, 'next_receive': 1, 'next_change': 0,
                'entries': [{'branch': 0, 'index': 0, 'public_key': first[5:1317].hex(), 'program': first[1317:].hex()}]}
        controller = types.SimpleNamespace(journal={'manifest': copy.deepcopy(base),
            'checkpoint': {'wallet_id': 'ab' * 16, 'next_receive': 1, 'next_change': 0}})
        manager = types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(stdout=json.dumps(owned()).encode()),
            _read_json=lambda *a: {'container': h.CONTAINER, 'volume': h.VOLUME, 'port': h.PORT, 'volume_id': 'c' * 32})
        controller.manager = manager

        def action(name, params, **kwargs):
            events.append(name)
            result = {}
            if name == 'receive':
                index = 725 if 'recover' in events else 0
                result = {'branch': 0, 'index': index, 'address': 'PUBLIC_TEST_ADDRESS'}
                controller.journal['checkpoint']['next_receive'] = index + 1
            elif name == 'backup':
                self.assertEqual(len(controller.journal['manifest']['entries']), 1)
                result = {'id': 'd' * 32}
            elif name == 'recover':
                self.assertEqual(events[-2], 'quarantine')
                self.assertEqual(params['backup_id'], 'd' * 32)
                self.assertEqual(len(controller.journal['manifest']['entries']), 1450)
                result = dict(controller.journal['checkpoint'], chain_snapshot_restored=False)
            elif name == 'send':
                controller.journal['checkpoint']['next_change'] += 1
                result = {'broadcast': True, 'txid': 'e' * 64}
            elif name == 'mine':
                result = {'blocks': ['f' * 64]}
            elif name == 'transaction':
                result = {'txid': 'e' * 64, 'block_hash': 'f' * 64, 'confirmed': True,
                          'confirmations': 1, 'in_mempool': False}
            return {'result': result}

        def intent(branch):
            field = 'next_receive' if branch == 0 else 'next_change'
            controller.journal['checkpoint'][field] += 1

        def invoke(*args, **kwargs):
            self.assertEqual(args[:2], ('1001:1000', 'python3'))
            self.assertEqual(controller.journal['checkpoint']['next_receive'], 725)
            self.assertEqual(controller.journal['checkpoint']['next_change'], 725)
            return json.dumps(batch()).encode()

        def retain(manifest):
            controller.journal['manifest'] = manifest

        def quarantine(name, params):
            self.assertEqual((name, params), ('quarantine_record', {}))
            self.assertEqual(events[-1], 'lock')
            events.append('quarantine')
            return {'selected_record_missing': True, 'independent_journal_preserved': True,
                    'next_receive': 725, 'next_change': 725}

        controller.action, controller._intent, controller._invoke, controller._retain = action, intent, invoke, retain
        agent = types.SimpleNamespace(Agent=lambda *a: types.SimpleNamespace(act=quarantine))
        controls = types.SimpleNamespace(validate_manifest=lambda x: x,
                                        canonical=lambda x: json.dumps(x, sort_keys=True).encode())
        with patch.object(h, 'instrument_signer', return_value=[{'frame_bytes': 1956099}]):
            result = h.exercise(controller, agent, controls, h.Trace(io.StringIO()), [None])
        self.assertEqual(events, ['start', 'setup', 'receive', 'backup', 'unlock', 'lock', 'quarantine',
                                  'recover', 'receive', 'fund', 'send', 'mine', 'transaction', 'lock'])
        self.assertEqual(result['recovery_entries'], 1450)
        self.assertTrue(result['confirmed_self_payment']['confirmed'])


if __name__ == '__main__':
    unittest.main()
