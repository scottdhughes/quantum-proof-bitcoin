#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import json
from pathlib import Path
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
SOURCE_MANIFEST = ENGINEERING_DIR / "vendor" / "mldsa-native" / "SOURCE.json"
ADMISSION = ENGINEERING_DIR / "backend_admission.json"
PROTOTYPE_DOCUMENT = REPO_ROOT / "docs" / "ML_DSA_44_WRAPPER_PROTOTYPE.md"
FUZZ_MANIFEST = ENGINEERING_DIR / "verifier_fuzz_corpus.json"


class MlDsaWrapperPrototypeTest(unittest.TestCase):
    def test_source_capsule_is_exact_portable_pin(self):
        manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf8"))
        self.assertEqual(manifest["tag"], "v1.0.0-beta2")
        self.assertEqual(
            manifest["commit"], "9b0ee84f4cf399043eca59eca4e5f8531ca1d61b"
        )
        self.assertEqual(len(manifest["files"]), 34)
        self.assertEqual(
            manifest["capsule_hash"]["value"],
            "2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb",
        )
        self.assertEqual(
            manifest["upstream_git_archive_tar_sha256"],
            "4fd08a772d0a142863593471f0c26e239bac8babc8e2a960e072f06ee89ff30b",
        )
        self.assertFalse(any("/native/" in path for path in manifest["files"]))
        self.assertFalse(any(path.endswith(".S") for path in manifest["files"]))

    def test_build_contract_is_frozen(self):
        config = (ENGINEERING_DIR / "pqbtc_mldsa44_config.h").read_text(
            encoding="utf8"
        )
        for required in (
            "#define MLD_CONFIG_PARAMETER_SET 44",
            "#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static",
            "#define MLD_CONFIG_INTERNAL_API_QUALIFIER static",
            "#define MLD_CONFIG_NO_SUPERCOP",
            "#define MLD_CONFIG_NO_ASM",
            "#define MLD_CONFIG_MAX_SIGNING_ATTEMPTS 814",
            "#define MLD_CONFIG_CUSTOM_RANDOMBYTES",
            "#define MLD_CONFIG_CUSTOM_ZEROIZE",
        ):
            self.assertIn(required, config)

    def test_production_header_has_no_test_or_randomizer_control(self):
        header = (ENGINEERING_DIR / "pqbtc_mldsa44.h").read_text(encoding="utf8")
        self.assertIn("pqbtc_mldsa44_sign_hedged", header)
        self.assertIn("pqbtc_mldsa44_verify_strict", header)
        self.assertNotIn("test_", header)
        self.assertNotIn("fixed_randomizer", header)
        self.assertNotIn("entropy_callback", header)

    def test_production_hold_and_isolation_remain_explicit(self):
        admission = json.loads(ADMISSION.read_text(encoding="utf8"))
        self.assertEqual(admission["decision"]["production_backend"], "NONE")
        self.assertTrue(admission["decision"]["release_hold"])
        evidence = admission["admitted_prototype"]["implementation_evidence"]
        self.assertFalse(evidence["node_linkage"])
        self.assertFalse(evidence["wallet_linkage"])
        self.assertFalse(evidence["consensus_linkage"])
        document = PROTOTYPE_DOCUMENT.read_text(encoding="utf8")
        self.assertIn("ISOLATED_PROTOTYPE_IMPLEMENTED - RELEASE_HOLD", document)
        self.assertIn("backend remains `NONE`", document)
        self.assertIn("Issues `#181` and `#184` through `#190` remain open", document)

    def test_wrapper_build_and_behavior(self):
        subprocess.run(
            [sys.executable, str(ENGINEERING_DIR / "run_wrapper_tests.py")],
            cwd=REPO_ROOT,
            check=True,
        )

    def test_verifier_fuzz_corpus_is_frozen(self):
        manifest = json.loads(FUZZ_MANIFEST.read_text(encoding="utf8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["frame_version"], 1)
        self.assertEqual(manifest["fuzz_limits"]["frame_bytes"], 8096)
        self.assertEqual(manifest["generated_corpus"]["total_cases"], 207)
        self.assertEqual(manifest["generated_corpus"]["unique_frames"], 202)
        self.assertEqual(
            manifest["generated_corpus"]["source_counts"],
            {"project": 27, "wycheproof": 180},
        )
        subprocess.run(
            [
                sys.executable,
                str(ENGINEERING_DIR / "run_verifier_fuzz.py"),
                "--manifest-only",
            ],
            cwd=REPO_ROOT,
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
