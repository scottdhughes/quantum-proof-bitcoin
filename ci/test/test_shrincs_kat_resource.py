"""Unit tests for SHRINCS KAT locks, resource bounds, and fuzz framing."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
REF_DIR = REPO_ROOT / "contrib" / "shrincs-ref"


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, REF_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CHECK_KATS = load_module("shrincs_check_kats", "check_kats.py")
RESOURCE = load_module("shrincs_resource_model", "resource_model.py")
STACK = load_module("shrincs_stack_usage", "collect_stack_usage.py")
FUZZ = load_module("shrincs_fuzz_corpus", "build_fuzz_corpus.py")
sys.modules.setdefault("resource_model", RESOURCE)
sys.modules.setdefault("check_kats", CHECK_KATS)
MEASURE = load_module("shrincs_measure_resources", "measure_resources.py")
GENERATOR = load_module("shrincs_resource_vectors", "generate_resource_vectors.py")


class ShrincsKatResourceTests(unittest.TestCase):
    def test_committed_kat_lock_is_valid(self) -> None:
        lock = CHECK_KATS.load_lock()
        self.assertEqual(lock["corpora"]["stateful"]["vector_count"], 7)
        self.assertEqual(lock["corpora"]["stateless"]["vector_count"], 2)
        self.assertEqual(lock["resource_vectors"]["vector_count"], 2)
        self.assertEqual(lock["resource_vectors"]["signature_lengths"], [4618, 5776])

    def test_kat_lock_digest_tamper_is_rejected(self) -> None:
        lock = copy.deepcopy(CHECK_KATS.load_lock())
        lock["corpora"]["stateful"]["sha256"] = "z" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(CHECK_KATS.KatError, "locked SHA-256 is invalid"):
                CHECK_KATS.load_lock(path)

    def test_resource_lock_tamper_is_rejected(self) -> None:
        lock = copy.deepcopy(CHECK_KATS.load_lock())
        lock["resource_vectors"]["vector_names"].reverse()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(CHECK_KATS.KatError, "vector-name lock drifted"):
                CHECK_KATS.load_lock(path)

    def test_well_formed_replacement_lock_cannot_authorize_new_bytes(self) -> None:
        for kind in ("stateful", "stateless", "resource"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                lock = copy.deepcopy(CHECK_KATS.load_lock())
                entry = lock["resource_vectors"] if kind == "resource" else lock["corpora"][kind]
                entry["sha256"] = "ab" * 32
                path = Path(directory) / "lock.json"
                path.write_text(json.dumps(lock), encoding="utf-8")
                with self.assertRaises(CHECK_KATS.KatError):
                    CHECK_KATS.load_lock(path)

    def test_one_shot_sha256_padding_boundaries(self) -> None:
        self.assertEqual(RESOURCE.sha256_compressions(0), 1)
        self.assertEqual(RESOURCE.sha256_compressions(55), 1)
        self.assertEqual(RESOURCE.sha256_compressions(56), 2)
        self.assertEqual(RESOURCE.sha256_compressions(63), 2)
        self.assertEqual(RESOURCE.sha256_compressions(64), 2)

    def test_wots_tw_exact_step_envelope(self) -> None:
        envelope = RESOURCE.wots_tw_step_envelope()
        self.assertEqual(envelope.minimum, 45)
        self.assertEqual(envelope.maximum, 510)
        maximizers = [
            checksum
            for checksum in range(481)
            if RESOURCE.wots_tw_verify_steps_from_checksum(checksum) == envelope.maximum
        ]
        self.assertEqual(maximizers, [480])

    def test_global_compression_bounds(self) -> None:
        self.assertEqual(RESOURCE.stateful_global_maximum(), 1074)
        self.assertEqual(RESOURCE.stateless_global_maximum(), 5601)

    def test_stateful_length_depth_mapping(self) -> None:
        self.assertEqual(RESOURCE.stateful_signature_depth(554), 1)
        self.assertEqual(RESOURCE.stateful_signature_depth(4618), 255)
        with self.assertRaisesRegex(ValueError, "non-canonical"):
            RESOURCE.stateful_signature_depth(555)

    def test_stack_usage_line_parser(self) -> None:
        entry = STACK.parse_line("file.c:10:2:verify\t992\tstatic\n", Path("x.su"))
        self.assertEqual(entry["frame_bytes"], 992)
        self.assertEqual(entry["qualifier"], "static")

    def test_dynamic_stack_records_cannot_pass_static_ceiling(self) -> None:
        for qualifier in ("dynamic", "dynamic,bounded", "unknown"):
            with self.subTest(qualifier=qualifier):
                with self.assertRaises(STACK.StackUsageError):
                    STACK.parse_line(f"file.c:10:2:verify\t32\t{qualifier}\n", Path("x.su"))

    def test_incomplete_stack_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "partial.su").write_text("x.c:1:1:unrelated\t8\tstatic\n")
            with self.assertRaises(STACK.StackUsageError):
                STACK.collect(Path(directory))

    def vector(self, name: str, signature_bytes: int) -> dict[str, str]:
        return {
            "name": name,
            "public_key": (b"p" * 48).hex(),
            "signature": (b"s" * signature_bytes).hex(),
            "message": (b"m" * 32).hex(),
            "context": b"ctx".hex(),
        }

    def test_fuzz_encoding_has_exact_length_header(self) -> None:
        encoded = FUZZ.encode(b"p" * 48, b"s" * 554, b"m" * 32, b"ctx")
        self.assertEqual(encoded[0], 48)
        self.assertEqual(int.from_bytes(encoded[1:3], "big"), 554)
        self.assertEqual(int.from_bytes(encoded[3:5], "big"), 32)
        self.assertEqual(int.from_bytes(encoded[5:7], "big"), 3)
        self.assertEqual(len(encoded), 7 + 48 + 554 + 32 + 3)

    def test_fuzz_seed_builder_includes_both_modes(self) -> None:
        cases = FUZZ.build([self.vector("stateful", 554)], [self.vector("stateless", 5776)])
        self.assertGreaterEqual(len(cases), 20)
        self.assertTrue(any(name.startswith("valid-stateful") for name in cases))
        self.assertTrue(any(name.startswith("valid-stateless") for name in cases))

    def test_seed_cli_includes_maximum_envelope_valid_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resource = [dict(self.vector("max-stateful", 4618), message=bytes(4096).hex(), context=bytes(255).hex()),
                        dict(self.vector("max-stateless", 5776), message=bytes(4096).hex(), context=bytes(255).hex())]
            groups = {"stateful": [self.vector("stateful", 554)], "stateless": [self.vector("stateless", 5776)],
                      "resource": resource}
            arguments = []
            for kind, vectors in groups.items():
                path = root / f"{kind}.json"
                path.write_text(json.dumps({"vectors": vectors}))
                arguments += [f"--{kind}", str(path)]
            completed = subprocess.run([sys.executable, str(REF_DIR / "build_fuzz_corpus.py"), *arguments,
                                        "--output-dir", str(root / "out"), "--json"], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            encoded = {path.read_bytes() for path in (root / "out").iterdir()}
            for vector in resource:
                self.assertIn(FUZZ.encode(bytes.fromhex(vector["public_key"]), bytes.fromhex(vector["signature"]),
                                          bytes(4096), bytes(255)), encoded)

    def test_seed_builder_preserves_nonempty_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind, length in (("stateful", 554), ("stateless", 5776)):
                (root / f"{kind}.json").write_text(json.dumps({"vectors": [self.vector(kind, length)]}))
            output = root / "output"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_bytes(b"unrelated data")
            with mock.patch.object(sys, "argv", ["build_fuzz_corpus.py", "--stateful", str(root / "stateful.json"),
                                                "--stateless", str(root / "stateless.json"), "--output-dir", str(output)]):
                try:
                    FUZZ.main()
                except FUZZ.FuzzCorpusError:
                    pass
            self.assertTrue(sentinel.is_file(), "existing output data was deleted")
            self.assertEqual(sentinel.read_bytes(), b"unrelated data")
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_generator_loader_preserves_source_semantics_without_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fixture.py"
            source.write_text("VALUE: int = 7\n")
            with mock.patch.object(sys, "dont_write_bytecode", False):
                module = GENERATOR.load_module(source, "resource_fixture")
            self.assertIs(module.__annotations__["VALUE"], int)
            self.assertFalse((source.parent / "__pycache__").exists())

    def test_generator_rejects_unfrozen_manifest_before_source_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "draft"
            (repo / "impl").mkdir(parents=True)
            marker = root / "executed"
            (repo / "impl" / "shrincs.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n")
            env = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
            def git(*args):
                return subprocess.run(["git", "-C", str(repo), *args], env=env, check=True,
                                      text=True, capture_output=True).stdout.strip()
            git("init", "-q")
            git("add", "impl/shrincs.py")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                "commit", "-qm", "fixture")
            manifest = json.loads((REPO_ROOT / "contrib/shrincs/manifest.json").read_text())
            manifest["upstream"]["draft_specification"]["commit"] = git("rev-parse", "HEAD")
            manifest["release_hold"] = False
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest))
            with mock.patch.object(sys, "argv", ["generate_resource_vectors.py", "--shrincs-bip", str(repo),
                                                "--manifest", str(path), "--output", str(root / "vectors.json")]):
                try:
                    GENERATOR.main()
                except Exception:
                    pass
            self.assertFalse(marker.exists(), "unfrozen source executed before policy validation")

    def test_workflow_hash_manifest_covers_every_data_member(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/shrincs-kat-resource-fuzz.yml").read_text()
        start = workflow.index("          sha256sum \\")
        stop = workflow.index("\n\n", start)
        command = "\n".join(line[10:] for line in workflow[start:stop].splitlines())
        names = {"stateful-vectors.json", "stateless-vectors.json", "resource-vectors.json",
                 "resource-report.json", "resource-model.json", "stack-usage.json"}
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "build/evidence"
            evidence.mkdir(parents=True)
            for name in names:
                (evidence / name).write_text(name)
            subprocess.run(["bash", "-o", "pipefail", "-c", command], cwd=directory, check=True, capture_output=True)
            covered = {Path(line.split(maxsplit=1)[1]).name
                       for line in (evidence / "evidence-sha256.txt").read_text().splitlines()}
            self.assertEqual(covered, names)


@unittest.skipUnless(shutil.which("cc"), "native compiler required")
class ShrincsResourceNativeStatusTests(unittest.TestCase):
    def compile(self, root: Path, *, driver: bool = False, status: int = 7, marker: Path | None = None) -> Path:
        source = root / "stub.c"
        source.write_text(f"""#include <stddef.h>
#include <stdint.h>
int pqbtc_shrincs_verify(const void *p,size_t a,const void *s,size_t b,const void *m,size_t c,const void *x,size_t d)
{{(void)p;(void)a;(void)s;(void)b;(void)m;(void)c;(void)x;(void)d;return {status};}}
void pqbtc_shrincs_resource_reset_sha256(void){{}}
void pqbtc_shrincs_resource_reset_allocations(void){{}}
uint64_t pqbtc_shrincs_resource_sha256_calls(void){{return 0;}}
uint64_t pqbtc_shrincs_resource_sha256_compressions(void){{return 0;}}
uint64_t pqbtc_shrincs_resource_malloc_calls(void){{return 0;}}
uint64_t pqbtc_shrincs_resource_free_calls(void){{return 0;}}
uint64_t pqbtc_shrincs_resource_malloc_bytes(void){{return 0;}}
size_t pqbtc_shrincs_resource_max_malloc_request(void){{return 0;}}
""")
        if marker is not None:
            with source.open("a") as handle:
                handle.write("#include <stdio.h>\nstatic void __attribute__((constructor)) stamp(void){"
                             f"FILE*f=fopen({json.dumps(str(marker))},\"w\");"
                             "if(f){fputs(\"loaded\",f);fclose(f);}}\n")
        output = root / ("driver" if driver else "stub.so")
        flags = ["-std=c99", "-Wall", "-Wextra", "-Werror"]
        if driver:
            harness = root / "main.c"
            harness.write_text("#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput(const uint8_t*,size_t);\n"
                               "int main(void){uint8_t d[609]={48,2,42,0,0,0,0};return LLVMFuzzerTestOneInput(d,sizeof(d));}\n")
            flags += [str(REF_DIR / "fuzz_full_verify.c"), str(harness)]
        else:
            flags += ["-fPIC", "-shared"]
        subprocess.run(["cc", *flags, str(source), "-o", str(output)], check=True, capture_output=True)
        return output

    def test_measurement_rejects_noncanonical_native_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            library = self.compile(Path(directory))
            verifier = MEASURE.InstrumentedVerifier(library)
            with self.assertRaises(MEASURE.ResourceError):
                verifier.call(b"p" * 48, bytes(554), b"", b"")

    def test_fuzz_driver_rejects_noncanonical_native_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = self.compile(Path(directory), driver=True)
            completed = subprocess.run([str(executable)], capture_output=True)
            self.assertNotEqual(completed.returncode, 0, "fuzz driver silently ignored native error status")

    def test_resource_corpus_drift_rejects_before_loading_native_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "loaded"
            library = self.compile(root, marker=marker)
            for kind in ("stateful", "stateless", "resource"):
                (root / f"{kind}.json").write_text("{}")
            with mock.patch.object(sys, "argv", ["measure_resources.py", "--library", str(library),
                                                "--stateful-kats", str(root / "stateful.json"),
                                                "--stateless-kats", str(root / "stateless.json"),
                                                "--resource-vectors", str(root / "resource.json")]):
                try:
                    MEASURE.main()
                except ValueError:
                    pass
            self.assertFalse(marker.exists(), "native constructor executed before corpus identity validation")


if __name__ == "__main__":
    unittest.main()
