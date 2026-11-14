#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Public archive and strict transport boundary tests; no native execution."""
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys

import deploy_payloads
import install_payload
import export_state


class DeploymentTests(unittest.TestCase):
    def test_refuse_unsafe_archive_members(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("c/../../escape", tarfile.REGTYPE),
                           ("a3/file", tarfile.REGTYPE), ("c/link", tarfile.SYMTYPE), ("c/fifo", tarfile.FIFOTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with tarfile.open(root / "bad.tar", "w") as archive:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = "/etc/passwd"
                    archive.addfile(item)
                with self.assertRaises(ValueError):
                    install_payload.extract(root / "bad.tar", root / "out", "c")
                self.assertFalse((root / "escape").exists())

    def test_regular_archive_and_duplicate_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with tarfile.open(root / "good.tar", "w") as archive:
                item = tarfile.TarInfo("c/data")
                item.size = 4
                archive.addfile(item, io.BytesIO(b"DATA"))
            install_payload.extract(root / "good.tar", root / "out", "c")
            self.assertEqual((root / "out/c/data").read_bytes(), b"DATA")
            with tarfile.open(root / "duplicate.tar", "w") as archive:
                item = tarfile.TarInfo("c/data")
                archive.addfile(item)
                archive.addfile(item)
            with self.assertRaises(ValueError):
                install_payload.extract(root / "duplicate.tar", root / "twice", "c")

    def test_provider_pinned_ssh_and_shell_quoting(self):
        transport = {"kind": "ssh", "hostkey_source": "AUTHENTICATED_PROVIDER_EXEC_PUBLIC_KEY_ONLY",
                     "argv": ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                              "-o", "ForwardAgent=no", "-o", "UserKnownHostsFile=/owned/hosts", "root@203.0.113.1"]}
        result = deploy_payloads.ssh_command(transport, ["python3", "-c", "print('literal; $HOME')"])
        self.assertEqual(result[:-1], transport["argv"])
        self.assertIn("'", result[-1])
        changed = {**transport, "argv": [v for v in transport["argv"] if v != "StrictHostKeyChecking=yes"]}
        with self.assertRaises(ValueError):
            deploy_payloads.ssh_command(changed, ["true"])
        with self.assertRaises(ValueError):
            deploy_payloads.ssh_command({**transport, "hostkey_source": "TOFU"}, ["true"])

    def test_installed_marker_replay_checks_actual_bytes_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with tarfile.open(root / 'payload.tar', 'w') as archive:
                item = tarfile.TarInfo('c/data')
                item.size = 4
                archive.addfile(item, io.BytesIO(b'DATA'))
            install_payload.extract(root / 'payload.tar', root / 'installed', 'c')
            target = root / 'installed/c'
            install_payload.verify_installed(root / 'payload.tar', target, 'c', owner=os.geteuid())
            data = target / 'data'
            data.chmod(0o644)
            data.write_bytes(b'EVIL')
            with self.assertRaises(ValueError):
                install_payload.verify_installed(root / 'payload.tar', target, 'c', owner=os.geteuid())
            link = root / 'linked'
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                install_payload.verify_installed(root / 'payload.tar', link, 'c', owner=os.geteuid())

    def test_live_registry_refuses_state_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'native-processes.json'
            path.write_text(json.dumps({'namespace': 'pqbtc-runpod-test', 'groups': []}))
            path.chmod(0o600)
            self.assertIn('native-processes.json', export_state.quiescent_inventory(root, owner=os.geteuid()))
            path.write_text(json.dumps({'namespace': 'pqbtc-runpod-test', 'groups': [{'pid': 123}]}))
            with self.assertRaises(ValueError):
                export_state.quiescent_inventory(root, owner=os.geteuid())
            self.assertIn('--exclude=.cookie*', export_state.tar_command(root))

    def test_bounded_upload_stdin_and_output_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public-data'
            path.write_bytes(b'PUBLIC CODE DATA')
            result = deploy_payloads.bounded([sys.executable, '-c',
                                              'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                                             stdin_path=path, limit=100)
            self.assertEqual(result.stdout, path.read_text())
            with self.assertRaises(ValueError):
                deploy_payloads.bounded([sys.executable, '-c', 'import os;os.write(1,b"x"*4096)'], limit=1024)
            with self.assertRaises(ValueError):
                deploy_payloads.bounded([sys.executable, '-c', 'import os;os.write(2,b"diagnostic")'],
                                        limit=1024, fail_on_stderr=True)

    def test_binary_stream_preserves_non_utf8_and_enforces_write_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'binary'
            script = Path(deploy_payloads.HERE) / 'bounded_stream.py'
            command = [sys.executable, '-B', str(script), '--output', str(path), '--maximum', '1024', '--',
                       sys.executable, '-c', 'import os;os.write(1,bytes([255,0,13,10])*100)']
            result = deploy_payloads.bounded(command, limit=4096)
            self.assertEqual(json.loads(result.stdout)['bytes'], 400)
            self.assertEqual(path.read_bytes(), bytes([255,0,13,10])*100)
            path = root / 'overflow'
            command = [sys.executable, '-B', str(script), '--output', str(path), '--maximum', '1024', '--',
                       sys.executable, '-c', 'import os;os.write(1,b"X"*4096)']
            with self.assertRaises(ValueError):
                deploy_payloads.bounded(command, limit=4096)
            self.assertLessEqual(path.stat().st_size, 1024)


if __name__ == "__main__":
    unittest.main()
