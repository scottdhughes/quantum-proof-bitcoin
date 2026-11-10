#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Current-source host orchestration: real nodes/signers stay in offline Linux.

PUBLIC test phrase only. Never supply a real wallet, passphrase or network here.
The qualification caller owns disposal after collecting evidence. No historical
image allowlist is used: the requested image, clean source and binary receipts
are joined explicitly, with the same offline process isolation.
"""
if not __debug__:
    raise RuntimeError("optimized Python is not permitted for demo evidence")
import argparse
import hashlib
import json
from pathlib import Path
import select
import struct
import subprocess
import time

from run_native_qualification import inspect_runtime, validate_native_identity, validate_runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--expect-image", required=True)
    parser.add_argument("--expect-architecture", required=True)
    parser.add_argument("--source", default="/tmp/mldsa-demo-source")
    parser.add_argument("--build", default="/tmp/mldsa-demo-build")
    parser.add_argument("--expect-head", required=True, help="exact clean contained source commit")
    args = parser.parse_args()
    for path in (args.source, args.build):
        assert path.startswith("/tmp/mldsa-") and ".." not in path and "\n" not in path
    assert args.container.startswith("pqbtc-native-"), "qualification namespace required"
    runtime = inspect_runtime(args.container)
    validate_runtime(runtime, args.expect_image)

    def command(user, *parts):
        return ["docker", "exec", "-i", "--user", user, "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--env", "OPENSSL_CONF=/dev/null", "--env", "OPENSSL_MODULES=/nonexistent",
                "--env", "GIT_CONFIG_COUNT=1", "--env", "GIT_CONFIG_KEY_0=safe.directory",
                "--env", "GIT_CONFIG_VALUE_0=" + args.source, args.container, *map(str, parts)]

    timeout_factor = 1

    def invoke(user, *parts):
        result = subprocess.run(command(user, *parts), capture_output=True, timeout=120 * timeout_factor)
        if result.returncode or result.stderr:
            raise RuntimeError(f"contained demo helper failed: {result.returncode} {result.stderr!r}")
        return result.stdout

    architecture = invoke("1001:1000", "uname", "-m").decode().strip()
    vm_architecture = subprocess.check_output(["docker", "info", "--format", "{{.Architecture}}"], text=True, encoding="utf8").strip()
    validate_native_identity(args.expect_architecture, architecture, vm_architecture, architecture)
    emulated_x86 = False
    qualified_head = args.expect_head
    assert len(qualified_head) == 40 and all(c in "0123456789abcdef" for c in qualified_head)
    server = "/tmp/demo-signer-bin/pilot-signer"

    def identity():
        # DATA reads/Git only, inside Linux; never inspect the wallet directory.
        script = ('import hashlib,json,pathlib,subprocess,sys;source=pathlib.Path(sys.argv[1]);'
            'git=["git","-c","safe.directory="+str(source),"-C",source];'
            'head=subprocess.check_output(git+["rev-parse","HEAD"],text=True,encoding="utf8").strip();'
            'assert head==sys.argv[2];assert not subprocess.check_output(git+["status","--porcelain"]);'
            'paths=[pathlib.Path(p) for p in sys.argv[3:]];'
            'print(json.dumps({"source_head":head,"worktree":"clean","sha256":{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}))')
        return json.loads(invoke("1001:1000", "python3", "-c", script, args.source, qualified_head,
            args.build + "/bin/pqbtcd", args.build + "/bin/pqbtc-mldsa-client", server,
            args.source + "/contrib/ml-dsa-qualification/run_spend_restore.py", args.source + "/contrib/ml-dsa-signer/node_wallet.py",
            args.source + "/test/functional/feature_mldsa44_demo.py", args.source + "/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md"))

    before = identity()
    assert before["sha256"][args.source + "/contrib/ml-dsa-qualification/run_spend_restore.py"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps({"binary_source_binding_before": before}), flush=True)
    validation = invoke("1001:1000", "python3", args.source + "/test/functional/feature_mldsa44_demo.py",
        "--binary", args.build + "/bin/pqbtcd", "--validation-only", "--timeout-factor", timeout_factor)
    assert b'MLDSA_DEMO_VALIDATION_TERMINAL_EXIT_0\n' in validation
    print(validation.decode("utf8"), end="", flush=True)
    base = invoke("1000:1000", "python3", "-c",
        'import os,pathlib,tempfile;p=pathlib.Path(tempfile.mkdtemp(prefix="mldsa-node-svc-"));os.chmod(p,0o750);'
        '[(p/n).mkdir(mode=m) for n,m in (("wallet",0o700),("backup",0o700),("ipc",0o750))];print(p)').decode().strip()
    assert base.startswith("/tmp/mldsa-node-svc-") and "/" not in base[5:]
    socket = base + "/ipc/signer.sock"
    print(json.dumps({"runtime": runtime, "architecture": architecture, "docker_vm_architecture": vm_architecture,
                      "x86_cpu_emulated": emulated_x86, "timeout_factor": timeout_factor, "retained_signer_directory": base}), flush=True)

    def checkpoint(raw):
        fields = raw.decode("ascii").strip().split(" ")
        assert len(fields) == 5 and fields[0] == "MLDSA_WALLET_STATUS_V1"
        assert len(fields[1]) == 32 and all(c in "0123456789abcdef" for c in fields[1])
        return {"wallet_id": fields[1], "generation": int(fields[2]), "next_receive": int(fields[3]), "next_change": int(fields[4])}

    class Signer:
        def __init__(self, restore=None):
            wallet_dir = base + ("/wallet" if restore is None else "/wallet-restored")
            flags = ["--valueless-pilot", "--socket", socket, "--wallet-dir", wallet_dir, "--node-uid", "1001",
                     "--fee-cap", "20000", "--spec-file", args.source + "/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md",
                     "--operator-fd", "3", "--operator-out-fd", "4"]
            if restore is None:
                flags += ["--create"]
            else:
                flags += ["--restore", "--expected-wallet-id", restore["wallet_id"],
                          "--min-receive", str(restore["next_receive"]), "--min-change", str(restore["next_change"]),
                          "--acknowledge-restore-scan-range"]
            launcher = 'import os,sys;os.write(1,str(os.getpid()).encode()+b"\\n");os.dup2(0,3);os.dup2(1,4);os.execv(sys.argv[1],sys.argv[1:])'
            self.process = subprocess.Popen(command("1000:1000", "python3", "-c", launcher, server, *flags),
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            password = b"public-two-node-demo-fixture"
            self.process.stdin.write(struct.pack("<H", len(password)) + password)
            self.process.stdin.close()
            self.process.stdin = None
            assert select.select([self.process.stdout], [], [], 15 * timeout_factor)[0], "signer PID deadline"
            self.pid = int(self.process.stdout.readline())
            assert select.select([self.process.stdout], [], [], 15 * timeout_factor)[0], "signer checkpoint deadline"
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("signer startup: " + repr(self.process.stderr.read()))
            self.initial = checkpoint(line)
            deadline = time.monotonic() + 15 * timeout_factor
            while subprocess.run(command("1000:1000", "test", "-S", socket), capture_output=True).returncode:
                assert self.process.poll() is None and time.monotonic() < deadline, "signer socket deadline"
                time.sleep(0.02)

        def stop(self):
            if self.process.poll() is None:
                invoke("1000:1000", "python3", "-c", 'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)', self.pid)
            output, error = self.process.communicate(timeout=15)
            assert self.process.returncode == 0 and not error, (self.process.returncode, error)
            self.final = checkpoint(output)
            print(json.dumps({"operator_checkpoint": self.final}), flush=True)

    signer, demo = None, None
    restored, result_seen, terminal_seen = False, False, False
    try:
        signer = Signer()
        # Deliberately retain an encrypted record from BEFORE address issuance.
        invoke("1000:1000", "python3", "-c",
            'import os,pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);assert (p/"wallet/wallet.dat").stat().st_size==167;'
            'shutil.copyfile(p/"wallet/wallet.dat",p/"backup/old-wallet.dat");os.chmod(p/"backup/old-wallet.dat",0o600)', base)
        isolation = invoke("1001:1000", "python3", "-c",
            'import os,sys\ntry:\n fd=os.open(sys.argv[1]+"/wallet/wallet.dat",os.O_RDONLY)\n'
            'except PermissionError:\n print("NODE_CANNOT_OPEN_SIGNER_RECORD")\n'
            'else:\n os.close(fd);raise AssertionError("node opened signer record")', base)
        assert isolation == b"NODE_CANNOT_OPEN_SIGNER_RECORD\n"
        print(isolation.decode("ascii").strip(), flush=True)
        demo = subprocess.Popen(command("1001:1000", "python3", args.source + "/test/functional/feature_mldsa44_demo.py",
            "--binary", args.build + "/bin/pqbtcd", "--spend-restore", "--client", args.build + "/bin/pqbtc-mldsa-client",
            "--socket", socket, "--signer-uid", "1000", "--timeout-factor", timeout_factor), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        deadline = time.monotonic() + 180 * timeout_factor
        while True:
            assert time.monotonic() < deadline, "two-node demo deadline"
            if not select.select([demo.stdout], [], [], 1)[0]:
                if demo.poll() is not None:
                    break
                continue
            line = demo.stdout.readline()
            if not line:
                break
            print(line.decode("utf8").rstrip(), flush=True)
            if line == b"MLDSA_DEMO_SPEND_RESTORE_TERMINAL_EXIT_0\n":
                terminal_seen = True
            if line.startswith(b"{"):
                event = json.loads(line)
                if event.get("result") == "PASS":
                    assert event["scope"] == "ACTUAL_TWO_NODE_SIGNER_SPEND_ENCRYPTED_OLD_RECORD_RESTORE"
                    assert event["actual_nodes"] == 2 and event["restored_inputs"] == 2 and event["restored_receive_index"] == 2
                    result_seen = True
                if event.get("event") == "RESTORE_REQUIRED":
                    assert not restored
                    manifest = event["public_manifest"]
                    signer.stop()
                    assert signer.final["wallet_id"] == manifest["wallet_id"]
                    for field in ("next_receive", "next_change"):
                        assert signer.final[field] == manifest[field]
                    invoke("1000:1000", "python3", "-c",
                        'import os,pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);(p/"wallet-restored").mkdir(mode=0o700);'
                        'shutil.copyfile(p/"backup/old-wallet.dat",p/"wallet-restored/wallet.dat");os.chmod(p/"wallet-restored/wallet.dat",0o600)', base)
                    signer = Signer(manifest)
                    assert signer.initial["wallet_id"] == manifest["wallet_id"]
                    demo.stdin.write(b"RESTORED\n")
                    demo.stdin.flush()
                    restored = True
        output, error = demo.communicate(timeout=20)
        if output:
            print(output.decode("utf8"), end="", flush=True)
        if demo.returncode != 0 or error:
            raise RuntimeError(f"actual node demo failed exit={demo.returncode}: {error.decode('utf8')}")
        assert restored and result_seen and terminal_seen, "encrypted restore result/terminal marker incomplete"
    finally:
        if demo and demo.poll() is None:
            demo.terminate()
            demo.wait(timeout=20)
        if signer and signer.process.poll() is None:
            signer.stop()
    after = identity()
    assert after == before, "source or executable changed during actual demo"
    print(json.dumps({"binary_source_binding_after": after}), flush=True)
    print("MLDSA_CURRENT_SOURCE_SPEND_RESTORE_TERMINAL_EXIT_0", flush=True)


if __name__ == "__main__":
    main()
