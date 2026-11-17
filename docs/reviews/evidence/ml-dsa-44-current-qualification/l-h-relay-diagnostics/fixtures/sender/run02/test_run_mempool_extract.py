"""No-runtime ownership, read-only-source and cleanup regression controls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sender_wrapper', Path(__file__).with_name('run_mempool_extract.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def mount(name, target, writable):
    return {'Type': 'volume', 'Name': name, 'Destination': target, 'RW': writable}


def source():
    return {'Id': h.SOURCE_ID, 'Name': '/' + h.SOURCE_NAME, 'Image': h.IMAGE,
            'State': {'Running': False, 'Pid': 0},
            'Mounts': [mount(h.SOURCE_VOLUME, '/var/lib/pqbtc', True)]}


def auxiliary(role='extract', running=False):
    return {'Id': 'a' * 64, 'Name': '/' + h.NAMES[role], 'Image': h.IMAGE,
            'State': {'Running': running, 'Pid': 12 if running else 0},
            'User': '1001:1000' if role == 'extract' else '0:0',
            'Labels': h.LABELS, 'NetworkMode': 'none', 'ReadonlyRootfs': True,
            'CapDrop': ['ALL'], 'CapAdd': None if role == 'extract' else ['CHOWN'],
            'Mounts': ([mount(h.SOURCE_VOLUME, '/sender', False)] if role == 'extract' else []) +
                      [mount(h.OUTPUT_VOLUME, '/out', True)]}


class OwnershipTests(unittest.TestCase):
    def test_source_accepts_only_exact_stopped_original(self):
        h.validate_source(source())
        for mutate in [lambda x: x.update(Id='b' * 64), lambda x: x.update(Image='other'),
                       lambda x: x['State'].update(Running=True, Pid=123),
                       lambda x: x['Mounts'][0].update(Name='original-user-wallet'),
                       lambda x: x['Mounts'].append(mount('other', '/other', False))]:
            value = source()
            mutate(value)
            with self.assertRaises(ValueError):
                h.validate_source(value)

    def test_extract_requires_node_uid_and_read_only_exact_source(self):
        h.validate_aux(auxiliary(), 'extract', 'a' * 64)
        for mutate in [lambda x: x.update(User='0:0'), lambda x: x.update(NetworkMode='bridge'),
                       lambda x: x.update(ReadonlyRootfs=False), lambda x: x.update(CapAdd=['DAC_OVERRIDE']),
                       lambda x: x['Mounts'][0].update(RW=True),
                       lambda x: x['Mounts'][0].update(Name='other'),
                       lambda x: x.update(Id='b' * 64), lambda x: x.update(Labels={})]:
            value = auxiliary()
            mutate(value)
            with self.assertRaises(ValueError):
                h.validate_aux(value, 'extract', 'a' * 64)

    def test_chown_initializer_cannot_mount_original_source(self):
        h.validate_aux(auxiliary('init'), 'init', 'a' * 64)
        value = auxiliary('init')
        value['Mounts'].append(mount(h.SOURCE_VOLUME, '/sender', False))
        with self.assertRaises(ValueError):
            h.validate_aux(value, 'init', 'a' * 64)

    def test_cleanup_checks_identity_before_stopping_and_proves_pid_zero(self):
        current = auxiliary(running=True)
        calls = []

        def command(args, **kwargs):
            calls.append(args)
            current['State'] = {'Running': False, 'Pid': 0}
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

        with patch.object(h, 'inspect_aux', side_effect=lambda identity: copy.deepcopy(current)), patch.object(h, 'command', command):
            result = h.stop_aux('a' * 64, 'extract')
        self.assertTrue(result['stopped'])
        self.assertEqual(calls, [['docker', 'stop', '--time', '5', 'a' * 64]])
        current['Id'] = 'b' * 64
        calls.clear()
        with patch.object(h, 'inspect_aux', return_value=current), patch.object(h, 'command', command):
            with self.assertRaises(ValueError):
                h.stop_aux('a' * 64, 'extract')
        self.assertEqual(calls, [])

    def test_probe_error_is_not_absence(self):
        self.assertTrue(h.absent(SimpleNamespace(returncode=1, stdout=b'', stderr=b'Error: No such object: owned\n'), 'owned'))
        self.assertFalse(h.absent(SimpleNamespace(returncode=1, stdout=b'', stderr=b'Cannot connect to Docker daemon'), 'owned'))
        self.assertFalse(h.absent(SimpleNamespace(returncode=0, stdout=b'[]', stderr=b''), 'owned'))
        self.assertTrue(h.absent(SimpleNamespace(returncode=1, stdout=b'\n', stderr=b'error: no such object: owned\n'), 'owned'))

    def test_actual_docker_chown_capability_serialization(self):
        value = auxiliary('init')
        value['CapAdd'] = ['CAP_CHOWN']
        h.validate_aux(value, 'init', 'a' * 64)

    def test_partial_create_binds_only_full_owned_layout(self):
        value = auxiliary(running=True)
        with patch.object(h, 'command', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())):
            self.assertEqual(h.bind_aux('extract'), 'a' * 64)
        value['Mounts'][0]['RW'] = True
        with patch.object(h, 'command', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())):
            with self.assertRaises(ValueError):
                h.bind_aux('extract')

    def test_known_container_identity_cannot_be_replaced_at_cleanup(self):
        value = auxiliary()
        value['Id'] = 'b' * 64
        with patch.object(h, 'command', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())):
            with self.assertRaises(ValueError):
                h.bind_aux('extract', 'a' * 64)

    def test_cached_decoder_bytes_are_verified_and_changed_input_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'decoder.py'
            data = b'# harmless public diagnostic code\n'
            path.write_bytes(data)
            os.chmod(path, 0o600)
            with patch.object(h, 'DECODER', path), patch.object(h, 'DECODER_SHA', h.hashlib.sha256(data).hexdigest()):
                checked = h.checked_decoder()
                path.write_bytes(b'# changed\n')
                self.assertEqual(checked, data)
                with self.assertRaises(ValueError):
                    h.checked_decoder()

    def test_receipt_rejects_wrong_transaction_and_payload_stdout(self):
        value = {'schema': 'PQBTC-L-SENDER-PUBLIC-MEMPOOL-EXTRACTION-1', 'result': 'PASS',
                 'source_file': {'sha256': 'a' * 64, 'bytes': 4000}, 'public_volume_marker_verified': True,
                 'decoded': {'txid': h.TXID, 'selected_raw_sha256': h.RAW_SHA, 'record_count': 1, 'version': 2},
                 'signed_raw_bytes': 3900, 'artifact': '/out/pending-signed-transaction.raw',
                 'no_raw_payload_stdout': True, 'timestamps_are_saved_metadata_fee_delta_is_not_actual_fee': True}
        h.validate_receipt(value)
        for mutate in [lambda x: x['decoded'].update(txid='b' * 64),
                       lambda x: x['decoded'].update(selected_raw_sha256='b' * 64),
                       lambda x: x.update(raw_hex='SENSITIVE'), lambda x: x.update(no_raw_payload_stdout=False)]:
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.assertRaises(ValueError):
                h.validate_receipt(changed)


if __name__ == '__main__':
    unittest.main()
