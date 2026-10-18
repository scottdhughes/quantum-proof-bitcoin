"""Reproduce libshrincs WOTS+C compatibility with the pinned SHRINCS draft."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "contrib" / "shrincs" / "manifest.json"
KAT_FIELDS = (
    "sk_seed",
    "pk_seed",
    "adrs",
    "msg",
    "counter",
    "digits",
    "h_grind",
    "sig",
    "pk",
)
DEFINE_RE = re.compile(r"^#define\s+([A-Z0-9_]+)\s+([0-9]+)(?:\s|/|$)", re.MULTILINE)
KAT_SOURCE_RE = re.compile(r"^# Generated .* @ ([0-9a-f]+)$", re.MULTILINE)


class CompatibilityError(ValueError):
    """Raised when a pinned WOTS+C compatibility invariant is violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompatibilityError(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    # Execute source rather than a cached bytecode file, without dirtying the checkout.
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def git_output(path: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", "--no-optional-locks", "-C", str(path), *args],
        check=True,
        capture_output=True,
    )
    return result.stdout


def git_head(path: Path) -> str:
    return git_output(path, "rev-parse", "HEAD").decode().strip()


def validate_checkout(path: Path) -> None:
    root = Path(git_output(path, "rev-parse", "--show-toplevel").decode().strip())
    require(path.resolve() == root.resolve(), "input must be the checkout root")
    for entry in git_output(path, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        relative = Path(raw_name.decode())
        require(kind == b"blob" and mode in (b"100644", b"100755"),
                f"unsupported non-regular source: {relative}")
        source = path
        for part in relative.parts:
            source = source / part
            require(not source.is_symlink(), f"expected regular source: {relative}")
        require(source.is_file(), f"tracked source is missing: {relative}")
        data = source.read_bytes()
        blob = b"blob " + str(len(data)).encode() + b"\0" + data
        actual_id = hashlib.sha1(blob, usedforsecurity=False).hexdigest().encode()
        require(actual_id == object_id, f"tracked source differs from pinned tree: {relative}")
    require(not git_output(path, "diff", "--cached", "--name-only", "HEAD", "--"),
            "staged changes differ from pinned source")
    # No exclusions: ignored files can also shadow imports, headers, or build inputs.
    require(not git_output(path, "ls-files", "--others", "-z", "--"),
            "untracked files in pinned source checkout")


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "manifest root must be an object")
    policy = load_module(REPO_ROOT / "contrib" / "shrincs" / "check_manifest.py",
                         "pqbtc_shrincs_manifest_policy")
    try:
        policy.validate_manifest(data)
    except policy.ManifestError as exc:
        raise CompatibilityError(str(exc)) from exc
    return data


def parse_kat_text(text: str) -> dict[str, dict[str, str | int]]:
    """Parse libshrincs' line-oriented WOTS+C KAT file."""
    cases: dict[str, dict[str, str | int]] = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        if "sk_seed =" not in block:
            continue
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        require(lines and lines[0].startswith("# "), "KAT case is missing a name comment")
        name = lines[0][2:].strip()
        require(name and name not in cases, f"duplicate or empty KAT case name: {name!r}")
        fields: dict[str, str | int] = {}
        for line in lines[1:]:
            require(" = " in line, f"malformed KAT line in {name}: {line!r}")
            key, value = line.split(" = ", 1)
            require(key in KAT_FIELDS, f"unknown KAT field {key!r} in {name}")
            require(key not in fields, f"duplicate KAT field {key!r} in {name}")
            if key == "counter":
                try:
                    fields[key] = int(value, 10)
                except ValueError as exc:
                    raise CompatibilityError(f"invalid decimal counter in {name}") from exc
            else:
                require(len(value) % 2 == 0, f"odd-length hex field {key!r} in {name}")
                try:
                    bytes.fromhex(value)
                except ValueError as exc:
                    raise CompatibilityError(f"invalid hex field {key!r} in {name}") from exc
                fields[key] = value.lower()
        require(set(fields) == set(KAT_FIELDS), f"KAT case {name} has incomplete fields")
        cases[name] = fields
    require(cases, "KAT file contains no cases")
    return cases


def parse_kat(path: Path) -> tuple[dict[str, dict[str, str | int]], str]:
    text = path.read_text(encoding="utf-8")
    match = KAT_SOURCE_RE.search(text)
    require(match is not None, "KAT source commit marker is missing")
    return parse_kat_text(text), match.group(1)


def parse_header_defines(path: Path) -> dict[str, int]:
    return {name: int(value) for name, value in DEFINE_RE.findall(path.read_text(encoding="utf-8"))}


def validate_constants(reference: ModuleType, defines: dict[str, int]) -> None:
    expected_reference = {
        "WOTS_C_CHAIN_BITS": 4,
        "WOTS_C_CHAIN_COUNT": 32,
        "WOTS_C_CONSTANT_SUM": 240,
        "WOTS_C_CHAINS_SIZE": 512,
    }
    for name, expected in expected_reference.items():
        require(getattr(reference, name, None) == expected, f"pinned draft constant {name} drifted")

    expected_c = {
        "SHRINCS_WOTS_SK_SEED_BYTES": 16,
        "SHRINCS_WOTS_PK_SEED_BYTES": 16,
        "SHRINCS_WOTS_MSG_BYTES": 32,
        "SHRINCS_WOTS_PK_BYTES": 16,
        "SHRINCS_WOTS_SIG_BYTES": 514,
        "SHRINCS_WOTS_ADDR_BYTES": 22,
    }
    for name, expected in expected_c.items():
        require(defines.get(name) == expected, f"libshrincs constant {name} drifted")


def compare_field(name: str, key: str, actual: bytes | int, expected: str | int) -> None:
    if isinstance(actual, bytes):
        require(isinstance(expected, str), f"{name}.{key} expected field type drifted")
        actual_value: str | int = actual.hex()
    else:
        actual_value = actual
    require(actual_value == expected, f"{name}.{key} differs from pinned libshrincs KAT")


def recompute_cases(
    reference: ModuleType,
    generator: ModuleType,
    kat_cases: dict[str, dict[str, str | int]],
) -> int:
    generated_inputs: Iterable[tuple[str, bytes, bytes, bytes, bytes]] = generator.cases()
    seen: set[str] = set()
    for name, sk_seed, pk_seed, adrs, msg in generated_inputs:
        require(name in kat_cases, f"generator case {name!r} is absent from committed KAT")
        require(name not in seen, f"generator emitted duplicate case {name!r}")
        seen.add(name)
        case = kat_cases[name]

        compare_field(name, "sk_seed", sk_seed, case["sk_seed"])
        compare_field(name, "pk_seed", pk_seed, case["pk_seed"])
        compare_field(name, "adrs", adrs, case["adrs"])
        compare_field(name, "msg", msg, case["msg"])

        height, index = adrs[0], int.from_bytes(adrs[1:9], "big")
        # Historical KATs use the legacy zero-structure PRF context. A depth-zero
        # full key has no usable stateful leaf: this is NOT current signing parity.
        grinded = reference.wots_c_grind_to_constant_sum(pk_seed, msg, height, index)
        require(grinded is not None, f"{name}: current draft failed to find a grinding counter")
        counter, indexes = grinded
        require(sum(indexes) == reference.WOTS_C_CONSTANT_SUM, f"{name}: non-constant-sum mapping")

        grind_addr = reference.WotsCGrind(height, index)
        h_grind = reference.H_grind(pk_seed, grind_addr, msg, counter)
        signature = reference.wots_c_sign(msg, sk_seed, pk_seed, height, index, False, 0)
        require(signature is not None, f"{name}: current draft signing failed")
        public_key = reference.wots_c_pubkey_gen(sk_seed, pk_seed, height, index, False, 0)
        recovered = reference.wots_c_pubkey_from_sig(signature, msg, pk_seed, height, index)
        require(recovered == public_key, f"{name}: current draft failed its own WOTS+C round trip")

        compare_field(name, "counter", counter, case["counter"])
        compare_field(name, "digits", bytes(indexes), case["digits"])
        compare_field(name, "h_grind", h_grind, case["h_grind"])
        compare_field(name, "sig", signature, case["sig"])
        compare_field(name, "pk", public_key, case["pk"])

    require(seen == set(kat_cases), "committed KAT and generator case sets differ")
    return len(seen)


def validate_reference_semantics(reference: ModuleType) -> int:
    """Check the current model against independent byte-level expectations."""
    randomizer, seed, root, message = b"B" * 16, b"$" * 16, bytes(16), b"v1-message"
    leaf = bytes.fromhex("fe0000000000000001")
    inner = hashlib.sha256(randomizer + seed + root + leaf + message).digest()
    expected = hashlib.sha256(randomizer + seed + inner + leaf).digest()
    require(reference.H_msg_sf(randomizer, seed, root, 254, 1, message) == expected,
            "v1 stateful message-hash ordering drifted")
    require((reference.SHRINCS_SF_SIGNATURE_SIZE_MIN, reference.SHRINCS_SF_SIGNATURE_SIZE_MAX,
             reference.SHRINCS_SL_SIGNATURE_SIZE) == (548, 4619, 5777), "v1 envelope bounds drifted")
    prefix = bytes.fromhex("070102030405060708")
    h, index = 7, 0x0102030405060708
    a, b, c = 0x11121314, 0x21222324, 0x31323334
    word = lambda value: value.to_bytes(4, "big")
    zero = bytes(4)
    addresses = (
        (reference.WotsTwHash(h, index, a, b, c), 0, word(a) + word(b) + word(c)),
        (reference.WotsTwPrf(h, index, a, b), 5, word(a) + word(b) + zero),
        (reference.WotsTwPk(h, index, a), 1, word(a) + zero + zero),
        (reference.XmssTree(h, index, b, c), 2, zero + word(b) + word(c)),
        (reference.ForsTree(h, index, a, b, c), 3, word(a) + word(b) + word(c)),
        (reference.ForsRoots(h, index, a), 4, word(a) + zero + zero),
        (reference.ForsPrf(h, index, a, c), 6, word(a) + zero + word(c)),
        (reference.WotsCHash(h, index, b, c), 16, zero + word(b) + word(c)),
        (reference.WotsCPrf(h, index, False, 0x92, b), 21, bytes.fromhex("00920000") + word(b) + zero),
        (reference.WotsCPrf(h, index, True, 0x92, b), 21, bytes.fromhex("01920000") + word(b) + zero),
        (reference.WotsCPk(h, index), 17, zero * 3),
        (reference.WotsCGrind(h, index), 22, zero * 3),
        (reference.FxmssTree(h, index), 18, zero * 3),
    )
    for address, kind, payload in addresses:
        require(address.to_bytes() == prefix + bytes([kind]) + payload,
                f"typed address serialization drifted: {type(address).__name__}")
    for structure, state, expected_position in (
        (bytes([0, 4]), 4, (0, 251)), (bytes([0, 4]), 5, None),
        (bytes([1, 3]), 7, (7, 252)), (bytes([1, 3]), 8, None),
        (bytes([0, 0]), 0, None), (bytes([1, 0]), 0, None),
        (bytes([2, 3]), 0, None),
    ):
        require(reference.shrincs_sf_leaf_select(structure, state) == expected_position,
                "state selection boundary drifted")
    return 2 + len(addresses) + 7


def current_recovery_cases(reference: ModuleType, generator: ModuleType, library: Path) -> int:
    """Qualify recovery only; the native signer is not current-structure compatible."""
    native = ctypes.CDLL(str(library.resolve()))
    recover = native.shrincs_wots_pubkey_from_sig
    recover.argtypes = [ctypes.c_void_p] * 5
    recover.restype = ctypes.c_int
    count = 0
    for number, (name, sk_seed, pk_seed, _address, message) in enumerate(generator.cases()):
        depth, balanced = 1 + number // 2, bool(number % 2)
        height, index = 255 - depth, 1
        signature = reference.wots_c_sign(message, sk_seed, pk_seed, height, index, balanced, depth)
        require(signature is not None, f"{name}: current-profile signing failed")
        expected = reference.wots_c_pubkey_gen(sk_seed, pk_seed, height, index, balanced, depth)
        output = (ctypes.c_uint8 * 16)()
        address = (ctypes.c_uint8 * 22).from_buffer_copy(
            bytes([height]) + index.to_bytes(8, "big") + bytes(13))
        require(recover(output, signature, message, pk_seed, address) == 0,
                f"{name}: native recovery rejected current-profile signature")
        require(bytes(output) == expected, f"{name}: current-profile recovery mismatch")
        # Same prefix/seeds but different structure must not derive the same key.
        other = reference.wots_c_pubkey_gen(sk_seed, pk_seed, height, index, not balanced, depth)
        require(expected != other, f"{name}: tree shape was not bound to derivation")
        count += 1
    require(count == 8, "incomplete current-profile recovery campaign")
    return count


def validate_paths(manifest: dict[str, Any], libshrincs: Path, shrincs_bip: Path) -> tuple[str, str]:
    upstream = manifest.get("upstream")
    require(isinstance(upstream, dict), "manifest upstream object is missing")
    draft = upstream.get("draft_specification")
    lib = upstream.get("libshrincs_wotsc")
    require(isinstance(draft, dict), "draft_specification manifest entry is missing")
    require(isinstance(lib, dict), "libshrincs_wotsc manifest entry is missing")

    expected_draft = str(draft.get("commit", ""))
    expected_lib = str(lib.get("commit", ""))
    actual_draft = git_head(shrincs_bip)
    actual_lib = git_head(libshrincs)
    require(actual_draft == expected_draft, "shrincs-bip checkout does not match manifest pin")
    require(actual_lib == expected_lib, "libshrincs checkout does not match manifest pin")
    validate_checkout(shrincs_bip)
    validate_checkout(libshrincs)
    return expected_draft, expected_lib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--libshrincs", type=Path, required=True)
    parser.add_argument("--shrincs-bip", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    draft_commit, lib_commit = validate_paths(manifest, args.libshrincs, args.shrincs_bip)

    reference_path = args.shrincs_bip / "impl" / "shrincs.py"
    generator_path = args.libshrincs / "test" / "wots" / "gen_vectors.py"
    kat_path = args.libshrincs / "test" / "wots" / "vectors" / "wotsc.kat"
    header_path = args.libshrincs / "include" / "wots.h"
    for path in (reference_path, generator_path, kat_path, header_path):
        require(path.is_file(), f"required file is missing: {path}")

    reference = load_module(reference_path, "pqbtc_pinned_shrincs_reference")
    generator = load_module(generator_path, "pqbtc_pinned_libshrincs_vectors")
    validate_constants(reference, parse_header_defines(header_path))
    kat_cases, kat_source = parse_kat(kat_path)

    lib_entry = manifest["upstream"]["libshrincs_wotsc"]
    expected_kat_source = str(lib_entry.get("kat_source_commit", ""))
    require(expected_kat_source.startswith(kat_source), "committed KAT source marker differs from manifest")
    case_count = recompute_cases(reference, generator, kat_cases)
    semantics = validate_reference_semantics(reference)
    current_cases = current_recovery_cases(reference, generator, args.library)

    result = {
        "component": "WOTS+C",
        "draft_commit": draft_commit,
        "libshrincs_commit": lib_commit,
        "kat_source_commit": expected_kat_source,
        "cases": case_count,
        "historical_zero_structure_keygen_sign_cases": case_count,
        "current_recovery_cases": current_cases,
        "current_keygen_sign_compatible": False,
        "reference_semantic_checks": semantics,
        "signature_bytes": 514,
        "public_key_bytes": 16,
        "result": "PASS",
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "libshrincs WOTS+C compatibility: PASS "
            f"(cases={case_count}, signature_bytes=514, public_key_bytes=16)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
