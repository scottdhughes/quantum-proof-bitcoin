#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""DATA-only archive tests; real role switching is qualified separately on Linux."""
import hashlib
import os
from pathlib import Path
import socket
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

import export_state as export


class ExportTests(unittest.TestCase):
    def archive(self, root, target, **options):
        with mock.patch.object(export, 'ALLOWED_IDS', frozenset((os.geteuid(), os.getegid()))):
            return export.build_archive(root, target, **options)

    def test_regular_tree_preserves_bytes_owner_modes_and_excludes_cookies(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / 'state'
            root.mkdir(mode=0o755)
            branch = root / 'private'
            branch.mkdir(mode=0o700)
            data = branch / 'selected-record'
            raw = bytes((255, 0, 13, 10)) * 10
            data.write_bytes(raw)
            data.chmod(0o600)
            (branch / '.cookie.tmp').write_bytes(b'EXCLUDED PUBLIC COOKIE FIXTURE')
            target = parent / 'state.tar'
            result = self.archive(root, target)
            self.assertEqual(result['bytes'], target.stat().st_size)
            self.assertEqual(result['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_bytes()[257:263], b'ustar\0')
            with tarfile.open(target) as archive:
                self.assertEqual(archive.getnames(), ['.', './private', './private/selected-record'])
                member = archive.getmember('./private/selected-record')
                self.assertEqual((member.uid, member.gid, member.mode), (os.geteuid(), os.getegid(), 0o600))
                self.assertEqual(archive.getmember('./private').mode, 0o700)
                self.assertEqual(archive.extractfile(member).read(), raw)

    def test_symlinks_hardlinks_and_special_files_are_refused(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / 'state'
                root.mkdir()
                data = root / 'data'
                data.write_bytes(b'PUBLIC DATA')
                if kind == 'symlink':
                    (root / 'link').symlink_to(data)
                elif kind == 'hardlink':
                    os.link(data, root / 'link')
                else:
                    os.mkfifo(root / 'pipe')
                with self.assertRaises(ValueError):
                    self.archive(root, parent / 'out.tar')

    def test_only_scoped_socket_names_and_cookie_entries_are_skipped(self):
        for name, allowed in (('signer.sock', True), ('unexpected-socket', False)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / 'state'
                root.mkdir()
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(str(root / name))
                    if allowed:
                        self.archive(root, parent / 'out.tar')
                        with tarfile.open(parent / 'out.tar') as archive:
                            self.assertEqual(archive.getnames(), ['.'])
                    else:
                        with self.assertRaises(ValueError):
                            self.archive(root, parent / 'out.tar')

    def test_paths_destination_and_complete_tar_headers_are_bounded(self):
        for kind in ('unsafe-name', 'inside-source', 'byte-limit', 'member-limit'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / 'state'
                root.mkdir()
                (root / ('bad\nname' if kind == 'unsafe-name' else 'data')).write_bytes(b'X' * 1024)
                target = root / 'out.tar' if kind == 'inside-source' else parent / 'out.tar'
                options = {'maximum': 1024} if kind == 'byte-limit' else {'max_members': 1} if kind == 'member-limit' else {}
                with self.assertRaises(ValueError):
                    self.archive(root, target, **options)
                if kind == 'byte-limit':
                    self.assertLessEqual(target.stat().st_size, 1024)

    def test_mixed_uid_behind_private_parent_is_refused_without_switch(self):
        private = type('Metadata', (), {'st_uid': 1000, 'st_gid': 1000, 'st_mode': stat.S_IFDIR | 0o700})()
        public = type('Metadata', (), {'st_uid': 0, 'st_gid': 0, 'st_mode': stat.S_IFDIR | 0o755})()
        export.require_traversal(1000, 1000, [public, private])
        for uid in (0, 1001):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                export.require_traversal(uid, 1000, [public, private])

    def test_effective_ids_restore_root_even_when_reading_raises(self):
        calls = []
        with mock.patch.object(export.os, 'geteuid', return_value=0), mock.patch.object(export.os, 'getegid', return_value=0), \
             mock.patch.object(export.os, 'getgroups', return_value=[0]), \
             mock.patch.object(export.os, 'setgroups', side_effect=lambda value: calls.append(('groups', value))), \
             mock.patch.object(export.os, 'setegid', side_effect=lambda value: calls.append(('gid', value))), \
             mock.patch.object(export.os, 'seteuid', side_effect=lambda value: calls.append(('uid', value))):
            with self.assertRaisesRegex(RuntimeError, 'DATA failure'):
                with export.owner_identity(1000, 1000):
                    raise RuntimeError('DATA failure')
        self.assertEqual(calls, [('groups', []), ('gid', 1000), ('uid', 1000), ('uid', 0), ('gid', 0), ('groups', [0])])


if __name__ == '__main__':
    unittest.main()
