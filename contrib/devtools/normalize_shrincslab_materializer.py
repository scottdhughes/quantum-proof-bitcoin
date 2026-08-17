#!/usr/bin/env python3
"""One-time, idempotent correction for the public-labnet materializer."""

from pathlib import Path

path = Path(__file__).with_name("apply_shrincslab_public_profile.py")
text = path.read_text(encoding="utf-8")
old = '''def patch_native_tests() -> dict[str, bool]:
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
new = '''def patch_native_tests() -> dict[str, bool]:
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
    if anchors < 2:
        raise RuntimeError(f"expected both full and PQ-first test-list anchors, found {anchors}")
    updated = "".join(normalized)
    changes["cmake"] = updated != original
    if updated != original:
        cmake_path.write_text(updated, encoding="utf-8")
    return changes
'''
if old in text:
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
elif new not in text:
    raise SystemExit("materializer patch_native_tests anchor not found")
