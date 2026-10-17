"""Exercise the complete layered public-labnet materialization sequence."""

import hashlib
import configparser
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
INPUTS = (
    "src/chainparams.cpp",
    "src/chainparamsbase.cpp",
    "src/kernel/chainparams.cpp",
    "src/kernel/chainparams.h",
    "src/consensus/params.h",
    "src/validation.cpp",
    "src/script/shrincs_tx_v0.cpp",
    "src/script/shrincs_tx_v0.h",
    "src/script/interpreter.cpp",
    "src/test/CMakeLists.txt",
    "src/test/shrincs_tx_v0_tests.cpp",
    "src/test/shrincs_tx_v0_signed_seam_tests.cpp",
    "contrib/shrincs-tx/tx_model.py",
    "contrib/shrincs-labnet/labnet.py",
    "contrib/shrincs-labnet/test_labnet.py",
    "contrib/shrincs-labnet/manifest.json",
    "test/functional/feature_shrincs_regtest.py",
    "test/functional/test_framework/address.py",
    "ci/test/test_shrincs_tx_cpp_component.py",
    "contrib/devtools/normalize_shrincslab_materializer.py",
    "contrib/devtools/apply_shrincslab_public_profile.py",
    "contrib/devtools/apply_shrincslab_chain_domain.py",
)


class ShrincsLabMaterializerTests(unittest.TestCase):
    def test_profile_and_domain_sequence_is_repeatable_without_losing_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in INPUTS:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO_ROOT / name, destination)

            def run_script(name):
                result = subprocess.run(
                    [sys.executable, str(root / "contrib" / "devtools" / name)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            def snapshot():
                return {
                    str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in root.rglob("*") if path.is_file()
                }

            run_script("normalize_shrincslab_materializer.py")
            run_script("apply_shrincslab_public_profile.py")
            run_script("apply_shrincslab_chain_domain.py")
            first = snapshot()
            run_script("apply_shrincslab_public_profile.py")
            run_script("apply_shrincslab_chain_domain.py")
            self.assertEqual(snapshot(), first)
            policy = "contrib/shrincs-labnet/Dockerfile.shrincslab.dockerignore"
            self.assertTrue((root / policy).is_file(), "materializer must preserve the source-only image context")
            self.assertEqual((root / policy).read_bytes(), (REPO_ROOT / policy).read_bytes())

            manifest = json.loads((root / "contrib/shrincs-labnet/manifest.json").read_text())
            self.assertFalse(manifest["consensus_activation"]["ordinary_regtest"])
            self.assertTrue(manifest["consensus_activation"]["shrincslab"])
            self.assertEqual(
                manifest["shrincs"]["chain_domain"]["sha256"],
                "db0e425cda8dcebc9e64203d2a5dfde2e954954f3dc95b8b9807590103d07652",
            )
            config = configparser.ConfigParser()
            config.read_string("[global]\n" + (root / "contrib/shrincs-labnet/shrincslab.conf.example").read_text())
            self.assertEqual(config["global"]["regtest"], "1")
            self.assertEqual(config["global"]["shrincslab"], "1")
            for key, value in (
                ("port", "29333"), ("rpcport", "29332"),
                ("bind", "0.0.0.0:29333"), ("rpcbind", "127.0.0.1"),
                ("rpcallowip", "127.0.0.1"),
            ):
                with self.subTest(setting=key):
                    self.assertNotIn(key, config["global"])
                    self.assertEqual(config["regtest"][key], value)
            spec = importlib.util.spec_from_file_location(
                "materialized_shrincs_guards", root / "ci/test/test_shrincs_tx_cpp_component.py"
            )
            assert spec is not None and spec.loader is not None
            guards = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(guards)
            guard = guards.ShrincsTxCppComponentTests()
            guard.test_activation_defaults_off_and_is_assigned_only_in_regtest()
            guard.test_labnet_base_directory_and_rpc_identity()
            guard.test_validation_flags_follow_consensus_scope()

    @unittest.skipUnless(shutil.which("docker"), "Docker is required for the real context regression")
    def test_docker_context_excludes_host_build_and_private_state(self):
        available = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"],
            capture_output=True, text=True, check=False, timeout=15,
        )
        if available.returncode or available.stdout.strip() != "linux":
            self.skipTest("a Linux Docker daemon is required for the real context regression")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "context"
            source = {
                "CMakeLists.txt": "source-cmake\n",
                "COPYING": "source-license\n",
                "cmake/module/check.cmake": "source-module\n",
                "src/check.cpp": "source-native\n",
                "share/check.txt": "source-share\n",
                "test/CMakeLists.txt": "source-test\n",
                "doc/CMakeLists.txt": "source-doc\n",
                "contrib/filter-lcov.py": "source-coverage\n",
                "contrib/devtools/split-debug.sh.in": "source-linux-debug-template\n",
            }
            contamination = (
                "build/CMakeCache.txt", "build-other/CMakeCache.txt",
                ".git/config", ".shrincs-labnet/signer.sqlite3",
                ".env", "untracked-state/signer.sqlite3",
                "src/__pycache__/check.pyc",
            )
            for name, content in {
                **source, **dict.fromkeys(contamination, "synthetic-not-source\n"),
            }.items():
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content)
            dockerfile = root / "contrib/shrincs-labnet/Dockerfile.shrincslab"
            dockerfile.parent.mkdir(parents=True)
            dockerfile.write_text("FROM scratch\nCOPY . /\n")
            policy = REPO_ROOT / "contrib/shrincs-labnet/Dockerfile.shrincslab.dockerignore"
            if policy.is_file():
                shutil.copy2(policy, dockerfile.with_name(dockerfile.name + ".dockerignore"))
            output = Path(temporary) / "export"
            result = subprocess.run(
                ["docker", "build", "--progress=plain", "--no-cache", "--file", str(dockerfile),
                 "--output", f"type=local,dest={output}", str(root)],
                capture_output=True, text=True, check=False, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name, content in source.items():
                with self.subTest(source=name):
                    self.assertTrue((output / name).is_file(), f"required source missing from image context: {name}")
                    self.assertEqual((output / name).read_text(), content)
            for name in contamination:
                with self.subTest(excluded=name):
                    self.assertFalse((output / name).exists(), f"host-only file entered image context: {name}")
