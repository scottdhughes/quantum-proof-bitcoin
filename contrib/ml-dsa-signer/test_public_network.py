#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Contained Linux root harness; actual native signer/client use distinct UIDs."""
if not __debug__:
    raise RuntimeError("optimized Python is not permitted for signer evidence")
import argparse
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "contrib/ml-dsa-production-contract"))
import ipc_v1
import protocol_v1 as protocol


def check(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signer", required=True)
    parser.add_argument("--client", required=True)
    args = parser.parse_args()
    check(sys.platform.startswith("linux") and os.geteuid() == 0, "contained root harness required")
    spec_file = ROOT / "docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md"
    spec = "c7993d7f2ae72623cf3b9e2f45c021885f610ef3169dbf176e0c2dd1a619d126"
    # Public automated fixture only; operator-selected secrets use the same FD channel.
    password = b"public-network-fixture"
    observations = []
    recovery_observations = []
    environment = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                   "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"}

    def invoke(command, body=b"", user=1001):
        return subprocess.run(command, input=body, capture_output=True, timeout=15,
                              user=user, group=1000, extra_groups=[], env=environment)

    def client(socket, kind, body=b"", network=None, expected=0):
        command = [args.client, "--valueless-demo", str(socket), "1000", spec, str(kind)]
        if network is not None:
            command += ["--network", network]
        result = invoke(command, body.hex().encode() + b"\n")
        if expected:
            check(result.returncode == 1 and result.stderr == f"MLDSA_CLIENT_ERROR {expected}\n".encode()
                  and result.stdout == b"", "native client wrong-network refusal")
            return None
        check(result.returncode == 0 and result.stderr == b"", "native client failure: " + repr(result.stderr))
        response = json.loads(result.stdout)
        check(response["status"] == 0, "native service refused: " + str(response["status"]))
        return bytes.fromhex(response["payload"])

    def recovery_cases(wallet, ipc, address, identity, network):
        socket = ipc / "signer.sock"

        def restore(frame=None, expected=None, reserve=False, minimum=4):
            before = (wallet / "wallet.dat").read_bytes()
            check(not socket.exists(), "restore fixture still has an active signer")
            input_read, input_write = os.pipe()
            output_read, output_write = os.pipe()
            command = [args.signer, "--valueless-pilot", "--restore", "--socket", str(socket),
                       "--wallet-dir", str(wallet), "--node-uid", "1001", "--fee-cap", "1000",
                       "--spec-file", str(spec_file), "--operator-fd", str(input_read),
                       "--operator-out-fd", str(output_write), "--expected-wallet-id", identity.hex(),
                       "--min-receive", str(minimum), "--min-change", "0", "--acknowledge-restore-scan-range"]
            if network == "test":
                command += ["--network", "test"]
            if frame is not None:
                command += ["--recovery-public-input"]
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, pass_fds=(input_read, output_write),
                                       user=1000, group=1000, extra_groups=[], env=environment)
            os.close(input_read)
            os.close(output_write)
            try:
                os.write(input_write, struct.pack("<H", len(password)) + password + (frame or b""))
                os.close(input_write)
                if expected is not None:
                    stdout, stderr = process.communicate(timeout=10)
                    check(process.returncode == 1 and stderr == f"MLDSA_PILOT_ERROR {expected}\n".encode() and not stdout,
                          "native recovery refusal mismatch: " + repr(stderr))
                    check(os.read(output_read, 4096) == b"" and not socket.exists(), "failed recovery published custody")
                    check((wallet / "wallet.dat").read_bytes() == before, "failed recovery replaced selected record")
                    return
                check(select.select([output_read], [], [], 15)[0], "recovery checkpoint timed out")
                checkpoint = os.read(output_read, 4096).split()
                check(len(checkpoint) == 5 and checkpoint[0] == b"MLDSA_WALLET_STATUS_V1" and
                      checkpoint[1].decode() == identity.hex() and int(checkpoint[3]) == minimum,
                      "valid retained public entry did not unlock: " + repr(checkpoint))
                deadline = time.monotonic() + 10
                while not socket.exists():
                    check(process.poll() is None and time.monotonic() < deadline, "recovery socket startup failure")
                    time.sleep(0.02)
                status = client(socket, 5, network=network)
                check(int.from_bytes(status[17:21], "little") == minimum, "recovered receive floor differs")
                if reserve:
                    next_address = client(socket, 2, b"\0", network=network)
                    check(int.from_bytes(next_address[1:5], "little") == minimum, "restore reused an address below retained floor")
                client(socket, 4, network=network)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=15)
                os.close(output_read)
            check(process.returncode == 0 and not stdout and not stderr, "recovery signer stop failed")

        if network == "regtest":
            restore(minimum=1)  # Exact historical password-only FD form.
            recovery_observations.append({"network": network, "legacy_password_only_restore": True})
            return
        valid = struct.pack("<I", 1) + address
        restore(valid)
        # Published valid ML-DSA key from an unrelated fixture root, with its
        # correct TEST commitment, injected at an unissued path below the floor.
        fixture_key = bytes.fromhex(json.loads((ROOT / "src/test/data/mldsa44_node.json").read_text())["public_key"])
        gap_entry = b"\0" + struct.pack("<I", 2) + fixture_key + protocol.key_commitment("test", fixture_key)
        same_program_gap = address[:1] + struct.pack("<I", 2) + address[5:]
        restore(struct.pack("<I", 1) + gap_entry, expected=4)
        invalid = [struct.pack("<I", 4097), b"\x01\0", valid[:-1], valid + b"x",
                   struct.pack("<I", 1) + b"\x02" + address[1:],
                   struct.pack("<I", 1) + address[:1] + struct.pack("<I", 4) + address[5:],
                   struct.pack("<I", 1) + address[:1] + struct.pack("<I", 2**31) + address[5:],
                   struct.pack("<I", 2) + address + address,
                   struct.pack("<I", 2) + address + address[:-1] + bytes([address[-1] ^ 1]),
                   struct.pack("<I", 2) + address + same_program_gap]
        for frame in invalid:
            restore(frame, expected=9)
        restore(bytes(4))  # Empty retained manifests also have a finite count frame.
        restore(valid, reserve=True)
        recovery_observations.append({"network": network, "valid_retained_entry": True,
            "wrong_root_gap_entry_refused": True, "grammar_refusals": len(invalid), "failed_record_unchanged": True,
            "restored_next_reserved_index": 4})

    with tempfile.TemporaryDirectory(prefix="mldsa-network-") as temporary:
        base = Path(temporary)
        base.chmod(0o755)
        fake_spec = base / "fake-contract.md"
        fake_spec.write_text("PUBLIC deliberately wrong contract fixture\n")
        rejected_wallet = base / "rejected-wallet"
        rejected_wallet.mkdir(mode=0o700)
        os.chown(rejected_wallet, 1000, 1000)
        input_read, input_write = os.pipe()
        output_read, output_write = os.pipe()
        os.close(input_write)  # No operator input is needed to refuse the wrong file.
        try:
            rejected = subprocess.run([args.signer, "--valueless-pilot", "--network", "test", "--create",
                "--socket", str(base / "absent.sock"), "--wallet-dir", str(rejected_wallet), "--node-uid", "1001",
                "--fee-cap", "1000", "--spec-file", str(fake_spec), "--operator-fd", str(input_read),
                "--operator-out-fd", str(output_write)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL, pass_fds=(input_read, output_write), timeout=5,
                user=1000, group=1000, extra_groups=[], env=environment)
            check(rejected.returncode == 1 and rejected.stderr == b"MLDSA_PILOT_ERROR 3\n" and not rejected.stdout,
                  "TEST launcher did not refuse actual wrong spec-file bytes before operator input: " + repr(rejected.stderr))
            check(not list(rejected_wallet.iterdir()) and not (base / "absent.sock").exists(),
                  "wrong TEST spec created custody/address state")
        finally:
            for descriptor in (input_read, output_read, output_write):
                os.close(descriptor)
        input_read, input_write = os.pipe()
        output_read, output_write = os.pipe()
        os.write(input_write, struct.pack("<H", len(password)) + password + bytes(4))
        os.close(input_write)
        try:
            rejected = subprocess.run([args.signer, "--valueless-pilot", "--network", "test", "--create",
                "--recovery-public-input", "--socket", str(base / "absent.sock"), "--wallet-dir", str(rejected_wallet),
                "--node-uid", "1001", "--fee-cap", "1000", "--spec-file", str(spec_file), "--operator-fd", str(input_read),
                "--operator-out-fd", str(output_write)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL, pass_fds=(input_read, output_write), timeout=5,
                user=1000, group=1000, extra_groups=[], env=environment)
            check(rejected.returncode == 1 and rejected.stderr == b"MLDSA_PILOT_ERROR 9\n" and not rejected.stdout,
                  "recovery public input was permitted with create")
            os.close(output_write)
            output_write = None
            check(not list(rejected_wallet.iterdir()) and os.read(output_read, 4096) == b"",
                  "create with recovery-only flag published custody")
        finally:
            for descriptor in (input_read, output_read, output_write):
                if descriptor is not None:
                    os.close(descriptor)
        for network in ("regtest", "test"):
            state = base / network
            state.mkdir(mode=0o755)
            wallet, ipc = state / "wallet", state / "ipc"
            wallet.mkdir(mode=0o700)
            ipc.mkdir(mode=0o750)
            for path in (wallet, ipc):
                os.chown(path, 1000, 1000)
            socket = ipc / "signer.sock"
            read_fd, write_fd = os.pipe()
            checkpoint_read, checkpoint_write = os.pipe()
            command = [args.signer, "--valueless-pilot", "--create", "--socket", str(socket), "--wallet-dir", str(wallet),
                       "--node-uid", "1001", "--fee-cap", "1000", "--spec-file", str(spec_file),
                       "--operator-fd", str(read_fd), "--operator-out-fd", str(checkpoint_write)]
            if network == "test":
                command += ["--network", network]
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, pass_fds=(read_fd, checkpoint_write),
                                       user=1000, group=1000, extra_groups=[], env=environment)
            os.close(read_fd)
            os.close(checkpoint_write)
            try:
                os.write(write_fd, struct.pack("<H", len(password)) + password)
                os.close(write_fd)
                check(select.select([checkpoint_read], [], [], 15)[0], "operator checkpoint timed out")
                initial = os.read(checkpoint_read, 4096)
                check(initial.startswith(b"MLDSA_WALLET_STATUS_V1 "), "native signer startup: " + repr(initial))
                deadline = time.monotonic() + 10
                while not socket.exists():
                    check(process.poll() is None and time.monotonic() < deadline, "native socket startup failure")
                    time.sleep(0.02)
                status = client(socket, 5, network=network)
                identity = status[1:17]
                opposite = "regtest" if network == "test" else "test"
                client(socket, 2, b"\0", network=opposite, expected=3)
                after_wrong = client(socket, 5, network=network)
                check(after_wrong == status, "wrong-network HELLO changed address floors")
                # No option remains the original regtest wire binding.
                client(socket, 5, expected=3 if network == "test" else 0)
                address = client(socket, 2, b"\0", network=network)
                key, program = address[5:1317], address[1317:]
                check(address[:5] == bytes(5) and program == protocol.key_commitment(network, key), "address binding")
                model = {"version": 2, "lock_time": 0,
                         "inputs": [{"prev_txid": "11" * 32, "prev_index": 0, "sequence": 4294967294,
                                     "amount": 100000, "script_pubkey": "5220" + program.hex()}],
                         "outputs": [{"amount": 99000, "script_pubkey": "5220" + program.hex()}]}
                witness = client(socket, 3, ipc_v1.encode_sign_request(identity, model, [(0, 0)]), network=network)
                check(len(witness) == 3733 and witness[0] == 1 and witness[-1312:] == key, "real signing response")
                # Exercise the Python command bridge against the actual native client.
                adapter = ("import sys;sys.path.insert(0,sys.argv[1]);import node_wallet;"
                           "s=node_wallet.NativeSigner(sys.argv[2],sys.argv[3],1000,network=sys.argv[4]);"
                           "print(s.call(5).hex())")
                result = invoke([sys.executable, "-c", adapter, str(ROOT / "contrib/ml-dsa-signer"),
                                 args.client, str(socket), network])
                check(result.returncode == 0 and not result.stderr, "Python/native network bridge refused")
                check(bytes.fromhex(result.stdout.decode())[17:21] == b"\x01\0\0\0", "bridge retained floor")
                observations.append({"network": network, "next_receive": 1, "wrong_network_refused": True,
                                     "native_signature_returned": True, "python_native_bridge": True})
                client(socket, 4, network=network)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=15)
                os.close(checkpoint_read)
            check(process.returncode == 0 and stdout == b"" and stderr == b"", "native signer stop failed")
            recovery_cases(wallet, ipc, address, identity, network)
        for network in ("main", "unknown"):
            result = invoke([args.signer, "--valueless-pilot", "--crypto-version", "--network", network], user=1000)
            check(result.returncode == 1 and result.stderr == b"MLDSA_PILOT_ERROR 7\n" and not result.stdout,
                  "signer unsupported network was not refused before operator input")
    print(json.dumps({"result": "PASS", "scope": "NATIVE_TEST_REGTEST_NETWORK_PLUMBING_NOT_NODE_ACTIVATION",
                      "observations": observations, "recovery": recovery_observations}))


if __name__ == "__main__":
    main()
