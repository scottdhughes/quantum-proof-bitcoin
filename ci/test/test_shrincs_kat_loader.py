"""Regression tests for the authenticated committed SHRINCS KAT loader."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOADER_PATH = REPO_ROOT / "contrib" / "shrincs-ref" / "kat_loader.py"
VECTOR_DIR = REPO_ROOT / "contrib" / "shrincs-ref" / "vectors"
SPEC = importlib.util.spec_from_file_location("shrincs_kat_loader", LOADER_PATH)
assert SPEC is not None and SPEC.loader is not None
LOADER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOADER)


class ShrincsKatLoaderTests(unittest.TestCase):
    def test_committed_corpora_load(self) -> None:
        manifest = LOADER.load_manifest(VECTOR_DIR / "manifest.json")
        stateful_raw, stateful = LOADER.load_corpus("stateful", VECTOR_DIR, manifest)
        stateless_raw, stateless = LOADER.load_corpus("stateless", VECTOR_DIR, manifest)
        self.assertEqual(len(stateful_raw), 12581)
        self.assertEqual(len(stateless_raw), 24566)
        self.assertEqual(len(stateful["vectors"]), 7)
        self.assertEqual(len(stateless["vectors"]), 2)

    def test_unknown_corpus_is_rejected(self) -> None:
        with self.assertRaisesRegex(LOADER.KatError, "unknown KAT corpus"):
            LOADER.load_corpus("unknown", VECTOR_DIR)

    def test_unsafe_part_name_is_rejected(self) -> None:
        manifest = json.loads((VECTOR_DIR / "manifest.json").read_text(encoding="utf-8"))
        manifest["corpora"]["stateful"]["parts"][0] = "../escape"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(LOADER.KatError, "unsafe or unexpected"):
                LOADER.load_manifest(path)

    def test_part_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copy_dir = Path(directory)
            for path in VECTOR_DIR.iterdir():
                if path.is_file():
                    shutil.copyfile(path, copy_dir / path.name)
            part = copy_dir / "stateful-vectors.json.gz.b64.part00"
            text = part.read_text(encoding="ascii")
            replacement = "A" if text[0] != "A" else "B"
            part.write_text(replacement + text[1:], encoding="ascii")
            manifest = LOADER.load_manifest(copy_dir / "manifest.json")
            with self.assertRaisesRegex(LOADER.KatError, "base64 digest drifted"):
                LOADER.load_corpus("stateful", copy_dir, manifest)

    def test_vector_digest_helper_rejects_invalid_hex(self) -> None:
        with self.assertRaisesRegex(LOADER.KatError, "invalid hexadecimal"):
            LOADER.decode_hex("zz", "field")


if __name__ == "__main__":
    unittest.main()
