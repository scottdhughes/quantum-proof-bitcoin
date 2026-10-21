#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Data readers on import; prove_runtime executes only in contained Linux."""

import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

HERE = Path(__file__).resolve().parent
WRAPS = (
    "getentropy",
    "prctl",
    "setrlimit",
    "getrlimit",
    "sysconf",
    "mmap",
    "mprotect",
    "syscall",
    "madvise",
    "munmap",
)
SCENARIOS = {
    "uninitialized": 5,
    "public-only-verify": 5,
    "healthy-init": 6,
    "fork-before-init": 5,
    **{
        "init-fail-" + name: 5
        for name in ("setrlimit", "prctl-set", "prctl-get", "getrlimit")
    },
    **{
        "allocation-fail-" + name: 6
        for name in ("pagesize", "mmap", "mprotect", "mlock", "dontdump", "dontfork")
    },
    "mapping": 13,
    "entropy-error": 5,
    "whole-body-alias": 8,
    "policy-drift": 9,
    "unmap-failure": 7,
    "page-layout": 8,
    "guards": 10,
    "generation-signing-repeat": 7,
    "signing-generation-repeat": 9,
    "concurrent-duplicate": 7,
    "fork-live": 23,
    "memlock-limit": 7,
}
EXTRA_SCENARIOS = {"entropy-boundaries": 11, "consumed-samples": 10, "unsupported": 6}
CONTROL_MARKERS = {
    "lock": ("mapping", "(flags & 9U) == 9U"),
    "dontdump": ("mapping", "(flags & 2U) == 2U"),
    "dontfork": ("fork-live", "mincore(key, 1, vector) == -1 && errno == ENOMEM"),
    "origin": ("fork-live", "pqbtc_mldsa44_key_runtime_init() == -13"),
    "wipe": ("mapping", "zero_releases == 1 && nonzero_releases == 0"),
}
FIELDS = {
    "schema",
    "scenario",
    "checks",
    "result",
    "core_zero",
    "dump_zero",
    "map_flags",
    "entropy_calls",
    "keypair_entries",
    "signature_entries",
    "randomized_entries",
    "zero_releases",
    "nonzero_releases",
}
RELEASES = {
    "mapping": 1,
    "entropy-error": 1,
    "whole-body-alias": 1,
    "policy-drift": 1,
    "unmap-failure": 2,
    "guards": 1,
    "generation-signing-repeat": 2,
    "signing-generation-repeat": 3,
    "concurrent-duplicate": 2,
    "fork-live": 1,
    "entropy-boundaries": 2,
    "consumed-samples": 4,
    "memlock-limit": 1,
    **{"allocation-fail-" + name: 1 for name in ("mlock", "dontdump", "dontfork")},
}
ENTROPY_CALLS = {
    "entropy-error": 1,
    "generation-signing-repeat": 4,
    "signing-generation-repeat": 5,
    "concurrent-duplicate": 2,
    "fork-live": 2,
    "entropy-boundaries": 3,
}


class HarnessError(RuntimeError):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError("duplicate runtime observation field")
        result[key] = value
    return result


def runtime_result(text):
    try:
        data = json.loads(text, object_pairs_hook=_object)
    except (ValueError, TypeError) as error:
        raise HarnessError("invalid runtime observation JSON") from error
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise HarnessError("incomplete/extra runtime observation fields")
    name = data["scenario"]
    expected = {**SCENARIOS, **EXTRA_SCENARIOS}
    if type(name) is not str or name not in expected:
        raise HarnessError("unknown runtime scenario")
    if (
        type(data["schema"]) is not int
        or data["schema"] != 2
        or data["result"] != "PASS"
    ):
        raise HarnessError("wrong runtime observation schema/result")
    for field in FIELDS - {"schema", "scenario", "result", "core_zero", "dump_zero"}:
        if type(data[field]) is not int or data[field] < (
            -1 if field == "map_flags" else 0
        ):
            raise HarnessError("wrong runtime count type/range")
    if type(data["core_zero"]) is not bool or type(data["dump_zero"]) is not bool:
        raise HarnessError("wrong policy observation type")
    if data["checks"] != expected[name] or data["nonzero_releases"] != 0:
        raise HarnessError("incomplete checks or nonzero owned release")
    if data["zero_releases"] != RELEASES.get(name, 0):
        raise HarnessError("wrong owned release count")
    if data["entropy_calls"] != ENTROPY_CALLS.get(name, 0):
        raise HarnessError("wrong OS adapter call count")
    if name not in {
        "uninitialized",
        "public-only-verify",
        "unsupported",
        "page-layout",
    } and not name.startswith("init-fail-"):
        if not data["core_zero"] or not data["dump_zero"]:
            raise HarnessError("required process policy not observed")
    if data["map_flags"] != (15 if name == "mapping" else -1):
        raise HarnessError("required locked/dump/fork mapping flags not observed")
    entries = tuple(
        data[key]
        for key in ("keypair_entries", "signature_entries", "randomized_entries")
    )
    if entries != ((1, 1, 2) if name == "entropy-boundaries" else (0, 0, 0)):
        raise HarnessError("wrong actual function-entry observations")
    return data


def require_runtime_control(kind, returncode, stderr):
    if kind not in CONTROL_MARKERS:
        raise HarnessError("unknown runtime control")
    scenario, marker = CONTROL_MARKERS[kind]
    expected = "FAIL runtime " + scenario + ": " + marker + "\n"
    if kind in {"dontfork", "origin"}:
        expected += (
            "FAIL runtime fork-live: WIFEXITED(status) && WEXITSTATUS(status) == 0 && summary.failures == 0\n"
        )
    if returncode != 1 or stderr != expected:
        raise HarnessError(
            "runtime control lacked its exact behavioral failure: " + kind
        )


def require_scenarios(observations):
    if not isinstance(observations, dict) or set(observations) != set(SCENARIOS):
        raise HarnessError("incomplete/extra runtime scenario set")
    for name, observation in observations.items():
        if runtime_result(json.dumps(observation))["scenario"] != name:
            raise HarnessError("runtime observation filed under wrong scenario")


def require_profiles(proof):
    profiles = {
        "O2",
        "O3",
        "LTO",
        "asan-ubsan",
        "entries-normal",
        "entries-asan-ubsan",
        "consumed-normal",
        "consumed-asan-ubsan",
        "unsupported-normal",
        "unsupported-asan-ubsan",
    }
    if not isinstance(proof, dict) or set(proof) != {
        "schema",
        "profiles",
        "controls",
        "disassembly",
    }:
        raise HarnessError("incomplete runtime proof inventory")
    if (
        proof["schema"] != 2
        or type(proof["profiles"]) is not dict
        or set(proof["profiles"]) != profiles
    ):
        raise HarnessError("missing/extra runtime build profile")
    for name, data in proof["profiles"].items():
        if name in {"O2", "O3", "LTO", "asan-ubsan"}:
            if not isinstance(data, dict) or not data.get("flags"):
                raise HarnessError("missing profile compiler flags")
            require_scenarios(data.get("observations"))
        else:
            if name.startswith("unsupported-"):
                if (
                    not isinstance(data, dict)
                    or set(data) != {"observation", "fixture_runtime_sha256"}
                    or not re.fullmatch(r"[0-9a-f]{64}", data["fixture_runtime_sha256"])
                ):
                    raise HarnessError("missing unsupported-branch fixture identity")
                data = data["observation"]
            expected = (
                "entropy-boundaries"
                if name.startswith("entries-")
                else name.split("-", 1)[0]
            )
            expected = "consumed-samples" if expected == "consumed" else expected
            if runtime_result(json.dumps(data))["scenario"] != expected:
                raise HarnessError("wrong supplemental runtime scenario")
    if type(proof["controls"]) is not dict or set(proof["controls"]) != set(
        CONTROL_MARKERS
    ):
        raise HarnessError("missing/extra compiled runtime control")
    for name, data in proof["controls"].items():
        if (
            data.get("result") != "REJECTED"
            or data.get("scenario") != CONTROL_MARKERS[name][0]
            or not re.fullmatch(r"[0-9a-f]{64}", data.get("mutated_runtime_sha256", ""))
        ):
            raise HarnessError("incomplete compiled runtime control observation")
    if set(proof["disassembly"]) != {
        "owned-release-" + mode + ".asm" for mode in ("O2", "O3", "LTO")
    }:
        raise HarnessError("missing/extra optimized disassembly")
    for text in proof["disassembly"].values():
        if not isinstance(text, str) or "<pqbtc_mldsa44_key_destroy>:" not in text:
            raise HarnessError("missing optimized release entry")


def prove_runtime(compiler, build, run):
    """run(argv, env=None, expected_status=0) returns its retained raw record."""
    version = run([compiler, "--version"])["stdout"].splitlines()[0]
    clang = "clang" in version.lower()
    common = [
        compiler,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-unknown-pragmas",
        "-pthread",
        "-I" + str(HERE),
        "-I" + str(HERE.parent / "ml-dsa-engineering"),
    ]
    wraps = ["-Wl," + ",".join("--wrap=" + name for name in WRAPS)]
    sanitizer = [
        "-O1",
        "-g",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-sanitize-recover=all",
    ]
    env = {
        "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }
    lto = ["-O3", "-flto"]
    if clang:
        lto += ["-fuse-ld=" + ("lld" if shutil.which("ld.lld") else "gold")]
    profiles = {"O2": ["-O2"], "O3": ["-O3"], "LTO": lto, "asan-ubsan": sanitizer}
    result = {"schema": 2, "profiles": {}, "controls": {}, "disassembly": {}}
    for name, flags in profiles.items():
        exe = build / ("runtime-" + name)
        command = [*common, *flags, HERE / "key_runtime_probe.c", *wraps, "-o", exe]
        run(command)
        observations = {}
        for scenario in SCENARIOS:
            raw = run([exe, scenario], env=env)
            if raw["stderr"]:
                raise HarnessError("unexpected runtime diagnostic: " + scenario)
            observations[scenario] = runtime_result(raw["stdout"])
        require_scenarios(observations)
        result["profiles"][name] = {"flags": flags, "observations": observations}
        if name != "asan-ubsan":
            # Code addresses in selected disassembly, not runtime pointer dumps.
            symbols = run(["nm", "--defined-only", exe])["stdout"]
            names = sorted(
                {
                    line.split()[-1]
                    for line in symbols.splitlines()
                    if line.split()
                    and re.fullmatch(
                        r"(?:pqbtc_mldsa44_key_destroy|pqbtc_mldsa44_zeroize|DestroyAllocation)(?:[.$][A-Za-z0-9_.$]+)?",
                        line.split()[-1],
                    )
                }
            )
            if "pqbtc_mldsa44_key_destroy" not in names:
                raise HarnessError(
                    "optimized release entry absent from symbol inventory"
                )
            text = "".join(
                run(["objdump", "-d", "--disassemble=" + symbol, exe])["stdout"]
                for symbol in names
            )
            if any(("<" + symbol + ">:") not in text for symbol in names):
                raise HarnessError("missing selected release disassembly")
            member = "owned-release-" + name + ".asm"
            result["disassembly"][member] = text
            result["profiles"][name]["release_symbols"] = names

    for name, extra in (("normal", ["-O0"]), ("asan-ubsan", sanitizer)):
        exe = build / ("runtime-entries-" + name)
        run(
            [
                *common,
                *extra,
                "-finstrument-functions",
                "-fno-inline",
                HERE / "key_runtime_probe.c",
                *wraps,
                "-o",
                exe,
            ]
        )
        result["profiles"]["entries-" + name] = runtime_result(
            run([exe, "entropy-boundaries"], env=env)["stdout"]
        )
        exe = build / ("runtime-consumed-" + name)
        run(
            [
                *common,
                *extra,
                "-DPQBTC_MLDSA44_TESTING=1",
                HERE / "key_runtime_probe.c",
                *wraps,
                "-o",
                exe,
            ]
        )
        result["profiles"]["consumed-" + name] = runtime_result(
            run([exe, "consumed-samples"], env=env)["stdout"]
        )

    # Select only the owned unit's existing fallback in a temporary copy.
    # Undefining Linux globally would trip the held entropy platform #error.
    # No foreign platform build/qualification is claimed by this fixture.
    original_key = (HERE / "key_lifecycle.c").read_text(encoding="utf8")
    original_runtime = (HERE / "key_runtime.c").read_text(encoding="utf8")
    guard = "#if defined(__linux__)"
    if original_runtime.count(guard) != 1:
        raise HarnessError("ambiguous owned unsupported-branch selection")
    branch_directory = build / "unsupported-branch"
    branch_directory.mkdir()
    (branch_directory / "key_lifecycle.c").write_text(original_key, encoding="utf8")
    fallback_runtime = original_runtime.replace(
        guard, "#if 0 /* test fixture: select owned unsupported branch */"
    )
    (branch_directory / "key_runtime.c").write_text(fallback_runtime, encoding="utf8")
    unsupported = build / "unsupported.c"
    unsupported.write_text(
        r"""
#include "key_lifecycle.h"
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/resource.h>
static unsigned checks, entropy_calls;
int __wrap_getentropy(void* p, size_t n) { (void)p; (void)n; ++entropy_calls; errno=EIO; return -1; }
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL unsupported: %s\n",#c); return 1; } } while (0)
int main(void) {
    struct pqbtc_mldsa44_key* key=NULL;
    const uint8_t seed[32]={1}, signature[2420]={0}, public_key[1312]={0};
    struct rlimit core;
    CHECK(pqbtc_mldsa44_key_runtime_init()==-14);
    CHECK(pqbtc_mldsa44_key_generate(&key)==-14);
    CHECK(pqbtc_mldsa44_key_import_seed(&key,seed,32)==-14);
    CHECK(key==NULL);
    CHECK(entropy_calls==0);
    CHECK(pqbtc_mldsa44_key_verify_strict(signature,2420,public_key,1312,NULL,0,NULL,0)==-9);
    printf("{\"schema\":2,\"scenario\":\"unsupported\",\"checks\":%u,\"result\":\"PASS\","
        "\"core_zero\":%s,\"dump_zero\":%s,\"map_flags\":-1,\"entropy_calls\":%u,"
        "\"keypair_entries\":0,\"signature_entries\":0,\"randomized_entries\":0,"
        "\"zero_releases\":0,\"nonzero_releases\":0}\n", checks,
        getrlimit(RLIMIT_CORE,&core)==0 && core.rlim_cur==0 && core.rlim_max==0 ? "true":"false",
        prctl(PR_GET_DUMPABLE,0UL,0UL,0UL,0UL)==0 ? "true":"false",entropy_calls);
    return 0;
}
""",
        encoding="utf8",
    )
    for name, extra in (("normal", ["-O2"]), ("asan-ubsan", sanitizer)):
        exe = build / ("runtime-unsupported-" + name)
        run(
            [
                *common,
                *extra,
                branch_directory / "key_lifecycle.c",
                unsupported,
                "-Wl,--wrap=getentropy",
                "-o",
                exe,
            ]
        )
        result["profiles"]["unsupported-" + name] = {
            "observation": runtime_result(run([exe], env=env)["stdout"]),
            "fixture_runtime_sha256": hashlib.sha256(
                fallback_runtime.encode()
            ).hexdigest(),
        }

    mutations = {
        "lock": ("syscall(SYS_mlock, body, body_size) != 0", "0"),
        "dontdump": ("madvise(body, body_size, MADV_DONTDUMP) != 0", "0"),
        "dontfork": ("madvise(body, body_size, MADV_DONTFORK) != 0", "0"),
        "origin": ("g_key_origin_pid != 0 && getpid() == g_key_origin_pid", "1"),
        "wipe": (
            "pqbtc_mldsa44_zeroize(key, body_size);",
            "(void)body_size; /* test-only omitted owned-body wipe */",
        ),
    }
    for kind, (needle, replacement) in mutations.items():
        if original_runtime.count(needle) != 1:
            raise HarnessError("ambiguous scoped runtime control: " + kind)
        directory = build / ("control-" + kind)
        directory.mkdir()
        (directory / "key_lifecycle.c").write_text(original_key, encoding="utf8")
        mutated = original_runtime.replace(needle, replacement)
        (directory / "key_runtime.c").write_text(mutated, encoding="utf8")
        source = directory / "key_runtime_probe.c"
        source.write_bytes((HERE / "key_runtime_probe.c").read_bytes())
        exe = directory / "control"
        run([*common, "-O2", source, *wraps, "-o", exe])
        scenario = CONTROL_MARKERS[kind][0]
        raw = run([exe, scenario], env=env, expected_status=1)
        require_runtime_control(kind, raw["returncode"], raw["stderr"])
        if raw["stdout"]:
            raise HarnessError("failed runtime control emitted success output")
        result["controls"][kind] = {
            "result": "REJECTED",
            "scenario": scenario,
            "mutated_runtime_sha256": hashlib.sha256(mutated.encode()).hexdigest(),
        }
    require_profiles(result)
    return result


if __name__ == "__main__":
    print(
        "Use run_key_lifecycle_tests.py for the complete source-bound native proof",
        file=sys.stderr,
    )
    raise SystemExit(2)
