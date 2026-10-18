"""Collect and enforce static stack-frame measurements from GCC .su files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

REQUIRED_FUNCTIONS = {
    "pqbtc_shrincs_verify", "pqbtc_shrincs_stateful_verify", "pqbtc_shrincs_stateless_verify",
    "shrincs_sha256", "shrincs_sha256_real", "__wrap_malloc", "__wrap_free",
}
REQUIRED_UNITS = {
    "full_verify", "stateful_verify", "stateless_verify", "sha256_counting",
    "alloc_counting", "wots", "thash", "util", "sha256_real",
}

class StackUsageError(ValueError):
    """Raised when stack-usage evidence is malformed or exceeds the limit."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StackUsageError(message)


def parse_line(line: str, source: Path) -> dict[str, Any]:
    fields = line.rstrip("\n").split("\t")
    require(len(fields) == 3, f"malformed stack-usage line in {source}: {line!r}")
    require(fields[2] == "static", f"non-static stack usage in {source}: {line!r}")
    location = fields[0]
    try:
        frame_bytes = int(fields[1])
    except ValueError as exc:
        raise StackUsageError(f"invalid stack size in {source}: {fields[1]!r}") from exc
    require(frame_bytes >= 0, f"negative stack size in {source}")
    return {
        "location": location,
        "frame_bytes": frame_bytes,
        "qualifier": fields[2],
        "source": str(source),
    }


def normalize_function(name: str) -> str:
    # GCC .su drops numeric clone IDs that remain in the object symbol table.
    # Retain the clone kind; never merge an ordinary function with its clone.
    return re.sub(r"(\.(?:constprop|isra|part))\.\d+(?=\.|$)", r"\1", name)


def inventory(directory: Path, suffix: str) -> dict[str, Path]:
    paths = sorted(directory.rglob(f"*{suffix}"))
    require(all(path.is_file() and not path.is_symlink() for path in paths), "non-regular evidence input")
    require(len(paths) == len(REQUIRED_UNITS) and {path.stem for path in paths} == REQUIRED_UNITS,
            f"incomplete or unexpected {suffix} translation-unit inventory")
    return {path.stem: path for path in paths}


def collect_evidence(directory: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    units: dict[str, Any] = {}
    records = inventory(directory, ".su")
    objects = inventory(directory, ".o")
    for unit, path in records.items():
        unit_entries = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                entry = parse_line(line, path)
                entry["unit"] = unit
                unit_entries.append(entry)
        require(unit_entries, f"empty stack-usage translation unit: {unit}")
        try:
            result = subprocess.run(["nm", "--defined-only", "--format=posix", str(objects[unit])],
                                    check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise StackUsageError(f"cannot inventory object functions: {unit}") from exc
        symbols = []
        for line in result.stdout.splitlines():
            fields = line.split()
            require(len(fields) >= 3, f"malformed nm record: {unit}: {line!r}")
            if fields[1] in {"t", "T", "w", "W"}:
                symbols.append(fields[0])
        functions = [normalize_function(name) for name in symbols]
        measured = [normalize_function(entry["location"].rsplit(":", 1)[-1]) for entry in unit_entries]
        require(functions and len(set(functions)) == len(functions) and len(set(measured)) == len(measured),
                f"empty or ambiguous function inventory: {unit}")
        require(set(functions) == set(measured), f"object/stack function inventory mismatch: {unit}")
        units[unit] = {
            "object_sha256": hashlib.sha256(objects[unit].read_bytes()).hexdigest(),
            "stack_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "object_functions": sorted(symbols),
        }
        entries.extend(unit_entries)
    functions = {entry["location"].rsplit(":", 1)[-1] for entry in entries}
    require(REQUIRED_FUNCTIONS <= functions,
            f"missing required stack records: {sorted(REQUIRED_FUNCTIONS - functions)}")
    return entries, units


def collect(directory: Path) -> list[dict[str, Any]]:
    return collect_evidence(directory)[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=4096)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    require(args.limit > 0, "stack limit must be positive")

    entries, units = collect_evidence(args.directory)
    entries.sort(key=lambda entry: (-entry["frame_bytes"], entry["location"]))
    maximum = entries[0]
    require(
        maximum["frame_bytes"] <= args.limit,
        f"maximum static frame {maximum['frame_bytes']} exceeds limit {args.limit}: {maximum['location']}",
    )
    result: dict[str, Any] = {
        "result": "PASS",
        "limit_bytes": args.limit,
        "function_count": len(entries),
        "maximum": maximum,
        "top": entries[:20],
        "records": entries,
        "units": units,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps({
            "result": "PASS",
            "limit_bytes": args.limit,
            "function_count": len(entries),
            "maximum_frame_bytes": maximum["frame_bytes"],
            "maximum_location": maximum["location"],
        }, sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
