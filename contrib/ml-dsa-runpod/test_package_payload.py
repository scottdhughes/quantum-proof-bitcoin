#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""DATA tests for payload provenance and archive traversal/tamper refusal."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import package_payload as pack


class PayloadTests(unittest.TestCase):
    def fixture(self, root):
        runtime = root / "runtime"
        seed = runtime / "seed/mldsa-demo-build/bin"
        seed.mkdir(parents=True)
        binary = seed / "pqbtcd"
        binary.write_bytes(b"DATA fixture only; not a native binary\n")
        binary.chmod(0o755)
        h = pack.digest(binary)
        head, tree = pack.VERSIONS["c"]
        manifest = {"schema": "PQBTC-MLDSA44-SOURCE-BUILD-1", "source_head": head, "source_tree": tree,
                    "architecture": "x86_64", "compiler": "gcc", "sha256": {"/tmp/mldsa-demo-build/bin/pqbtcd": h}}
        raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        (runtime / "manifest.json").write_bytes(raw)
        descriptor = {"schema": "PQBTC-MLDSA44-SOURCE-RUNTIME-1", "image": "sha256:" + "a" * 64,
                      "manifest": manifest, "manifest_sha256": hashlib.sha256(raw).hexdigest()}
        identity = {"head": head, "tree": tree, "sha256": manifest["sha256"]}
        report = {"schema": "PQBTC-MLDSA44-NATIVE-QUALIFICATION-1", "result": "PASS",
                  "source": {"head": head, "tree": tree}, "image": descriptor["image"],
                  "checks": dict.fromkeys(pack.GATES, "PASS"), "architecture": "x86_64", "emulated": False,
                  "identity_before": identity, "identity_after": identity, "cleanup": "REMOVED",
                  "manifest_sha256": descriptor["manifest_sha256"]}
        for name, data in (("build.json", descriptor), ("report.json", report)):
            (root / name).write_text(json.dumps(data))
        return runtime, descriptor, report, raw

    def test_qualification_identity_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            _, descriptor, report, raw = self.fixture(Path(directory))
            pack.validate_provenance("c", descriptor, report, raw)
            mutations = [lambda r: r.update(emulated=True), lambda r: r.update(identity_before=None, identity_after=None),
                         lambda r: r.update(cleanup="FAILED"), lambda r: r.update(image="sha256:" + "b" * 64),
                         lambda r: r["checks"].pop("signer-normal"),
                         lambda r: r["identity_after"].update(tree="b" * 40)]
            for mutate in mutations:
                candidate = copy.deepcopy(report)
                mutate(candidate)
                with self.assertRaises(ValueError):
                    pack.validate_provenance("c", descriptor, candidate, raw)
            with self.assertRaises(ValueError):
                pack.validate_provenance("a3", descriptor, report, raw)

    def test_package_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, _, _, _ = self.fixture(root)
            value = pack.package("c", runtime, root / "build.json", root / "report.json", root / "export")
            self.assertIn("seed/mldsa-demo-build/bin/pqbtcd", value["files"])
            with tarfile.open(root / "export/c-payload.tar.gz") as archive:
                members = archive.getmembers()
                self.assertTrue(all(m.uid == 0 and m.gid == 0 and not m.mode & 0o222 for m in members))
                self.assertIn("c/descriptor.json", archive.getnames())
            binary = runtime / "seed/mldsa-demo-build/bin/pqbtcd"
            binary.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                pack.package("c", runtime, root / "build.json", root / "report.json", root / "changed")

    def test_local_arm_rehearsal_requires_explicit_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            _, descriptor, report, _ = self.fixture(Path(directory))
            descriptor["manifest"]["architecture"] = "aarch64"
            raw = (json.dumps(descriptor["manifest"], sort_keys=True) + "\n").encode()
            descriptor["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
            report.update(architecture="aarch64", manifest_sha256=descriptor["manifest_sha256"])
            with self.assertRaises(ValueError):
                pack.validate_provenance("c", descriptor, report, raw)
            pack.validate_provenance("c", descriptor, report, raw, expected_architecture="aarch64")

    def test_archive_rejects_escape_duplicate_link_and_special(self):
        cases = [("../escape", None), ("/absolute", None), ("seed/link", tarfile.SYMTYPE),
                 ("seed/hard", tarfile.LNKTYPE), ("seed/fifo", tarfile.FIFOTYPE)]
        for name, kind in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with tarfile.open(root / "bad.tar", "w") as archive:
                    item = tarfile.TarInfo(name)
                    if kind:
                        item.type = kind
                        item.linkname = "elsewhere"
                    archive.addfile(item)
                with self.assertRaises(ValueError):
                    pack.extract_regular(root / "bad.tar", root / "out")
                self.assertFalse((root / "escape").exists())

    def test_regular_archive_extracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with tarfile.open(root / "ok.tar", "w") as archive:
                item = tarfile.TarInfo("seed/mldsa-demo-build/bin/pqbtcd")
                item.size, item.mode = 4, 0o755
                archive.addfile(item, io.BytesIO(b"DATA"))
            pack.extract_regular(root / "ok.tar", root / "out")
            self.assertEqual((root / "out/seed/mldsa-demo-build/bin/pqbtcd").read_bytes(), b"DATA")


if __name__ == "__main__":
    unittest.main()
