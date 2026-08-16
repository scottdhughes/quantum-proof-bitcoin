"""Collect and enforce static stack-frame measurements from GCC .su files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class StackUsageError(ValueError):
    """Raised when stack-usage evidence is malformed or exceeds the limit."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StackUsageError(message)


def parse_line(line: str, source: Path) -> dict[str, Any]:
    fields = line.rstrip("\n").split("\t")
    require(len(fields) >= 3, f"malformed stack-usage line in {source}: {line!r}")
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


def collect(directory: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    paths = sorted(directory.rglob("*.su"))
    require(paths, f"no .su files found under {directory}")
    for path in paths:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                entries.append(parse_line(line, path))
    require(entries, "stack-usage files contained no function records")
    return entries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=4096)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    require(args.limit > 0, "stack limit must be positive")

    entries = collect(args.directory)
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
