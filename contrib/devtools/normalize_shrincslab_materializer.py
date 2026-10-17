#!/usr/bin/env python3
"""Idempotent corrections for the layered public-labnet materializers."""

from pathlib import Path

path = Path(__file__).with_name("apply_shrincslab_public_profile.py")
text = path.read_text(encoding="utf-8")

old_native = '''def patch_native_tests() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["new_test"] = write("src/test/shrincslab_chainparams_tests.cpp", chainparams_test_source())
    changes["cmake"] = replace_all(
        "src/test/CMakeLists.txt",
        "  shrincs_tx_v0_signed_seam_tests.cpp\\n",
        "  shrincs_tx_v0_signed_seam_tests.cpp\\n  shrincslab_chainparams_tests.cpp\\n",
        minimum=2,
    )
    return changes
'''
new_native = '''def patch_native_tests() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["new_test"] = write("src/test/shrincslab_chainparams_tests.cpp", chainparams_test_source())

    cmake_path = ROOT / "src/test/CMakeLists.txt"
    original = cmake_path.read_text(encoding="utf-8")
    anchor = "  shrincs_tx_v0_signed_seam_tests.cpp\\n"
    entry = "  shrincslab_chainparams_tests.cpp\\n"
    lines = original.splitlines(keepends=True)
    normalized: list[str] = []
    index = 0
    anchors = 0
    while index < len(lines):
        line = lines[index]
        normalized.append(line)
        index += 1
        if line != anchor:
            continue
        anchors += 1
        while index < len(lines) and lines[index] == entry:
            index += 1
        normalized.append(entry)
    if anchors < 1:
        raise RuntimeError(f"expected the PQ-first test-list anchor, found {anchors}")
    updated = "".join(normalized)
    changes["cmake"] = updated != original
    if updated != original:
        cmake_path.write_text(updated, encoding="utf-8")
    return changes
'''
if old_native in text:
    text = text.replace(old_native, new_native, 1)
elif new_native not in text:
    strict = '''    if anchors < 2:\n        raise RuntimeError(f"expected both full and PQ-first test-list anchors, found {anchors}")\n'''
    relaxed = '''    if anchors < 1:\n        raise RuntimeError(f"expected the PQ-first test-list anchor, found {anchors}")\n'''
    if strict in text:
        text = text.replace(strict, relaxed, 1)
    elif relaxed not in text:
        raise SystemExit("materializer patch_native_tests anchor not found")

old_naming = '''def patch_shrincs_naming() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["header"] = replace_once(
        "src/script/shrincs_tx_v0.h",
        "/** Fixed chain identifier for the private regtest/devnet activation. */\\nuint256 RegtestChainId();\\n",
        "/** Frozen chain identifier retained for signed-vector compatibility. */\\nuint256 RegtestChainId();\\n\\n"
        "/** Chain identifier used by the explicitly selected SHRINCS labnet. */\\nuint256 ShrincsLabChainId();\\n",
    )
    changes["source"] = replace_once(
        "src/script/shrincs_tx_v0.cpp",
        "uint256 RegtestChainId()\\n{\\n    HashWriter writer;\\n    writer.write(std::as_bytes(std::span<const char>{\\n        REGTEST_CHAIN_ID_LABEL.data(), REGTEST_CHAIN_ID_LABEL.size()}));\\n    return writer.GetSHA256();\\n}\\n",
        "uint256 RegtestChainId()\\n{\\n    HashWriter writer;\\n    writer.write(std::as_bytes(std::span<const char>{\\n        REGTEST_CHAIN_ID_LABEL.data(), REGTEST_CHAIN_ID_LABEL.size()}));\\n    return writer.GetSHA256();\\n}\\n\\n"
        "uint256 ShrincsLabChainId()\\n{\\n    return RegtestChainId();\\n}\\n",
    )
    changes["interpreter"] = replace_once(
        "src/script/interpreter.cpp",
        "        shrincs_tx_v0::RegtestChainId())};\\n",
        "        shrincs_tx_v0::ShrincsLabChainId())};\\n",
    )
    return changes
'''
new_naming = '''def patch_shrincs_naming() -> dict[str, bool]:
    changes: dict[str, bool] = {}

    header_path = ROOT / "src/script/shrincs_tx_v0.h"
    header = header_path.read_text(encoding="utf-8")
    if "uint256 ShrincsLabChainId();" in header:
        changes["header"] = False
    else:
        old = "/** Fixed chain identifier for the private regtest/devnet activation. */\\nuint256 RegtestChainId();\\n"
        new = "/** Frozen chain identifier retained for signed-vector compatibility. */\\nuint256 RegtestChainId();\\n\\n/** Chain identifier used by the explicitly selected SHRINCS labnet. */\\nuint256 ShrincsLabChainId();\\n"
        if old not in header:
            raise RuntimeError("SHRINCS header naming anchor not found")
        header_path.write_text(header.replace(old, new, 1), encoding="utf-8")
        changes["header"] = True

    source_path = ROOT / "src/script/shrincs_tx_v0.cpp"
    source = source_path.read_text(encoding="utf-8")
    if "uint256 ShrincsLabChainId()" in source:
        changes["source"] = False
    else:
        old = "uint256 RegtestChainId()\\n{\\n    HashWriter writer;\\n    writer.write(std::as_bytes(std::span<const char>{\\n        REGTEST_CHAIN_ID_LABEL.data(), REGTEST_CHAIN_ID_LABEL.size()}));\\n    return writer.GetSHA256();\\n}\\n"
        new = old + "\\nuint256 ShrincsLabChainId()\\n{\\n    return RegtestChainId();\\n}\\n"
        if old not in source:
            raise RuntimeError("SHRINCS source naming anchor not found")
        source_path.write_text(source.replace(old, new, 1), encoding="utf-8")
        changes["source"] = True

    changes["interpreter"] = replace_once(
        "src/script/interpreter.cpp",
        "        shrincs_tx_v0::RegtestChainId())};\\n",
        "        shrincs_tx_v0::ShrincsLabChainId())};\\n",
    )
    return changes
'''
if old_naming in text:
    text = text.replace(old_naming, new_naming, 1)
elif new_naming not in text:
    raise SystemExit("materializer patch_shrincs_naming anchor not found")

old_functional = '''    changes["functional_args"] = replace_once(
        "test/functional/feature_shrincs_regtest.py",
        '        self.extra_args = [["-acceptnonstdtxn=1"]]\\n',
        '        self.extra_args = [["-shrincslab", "-acceptnonstdtxn=1"]]\\n',
    )
'''
new_functional = '''    changes["functional_args"] = replace_once(
        "test/functional/feature_shrincs_regtest.py",
        '        self.extra_args = [["-acceptnonstdtxn=1"]]\\n',
        '        self.extra_args = [["-shrincslab", "-acceptnonstdtxn=1"]]\\n'
        '        # Keep regtest-shaped config, but read cookies and logs from\\n'
        '        # the node-selected, isolated shrincslab/ network directory.\\n'
        '        self.extra_init = [{"chain": "shrincslab"}]\\n',
    )
'''
if old_functional in text:
    text = text.replace(old_functional, new_functional, 1)
elif new_functional not in text:
    raise SystemExit("materializer functional-harness anchor not found")

path.write_text(text, encoding="utf-8")
