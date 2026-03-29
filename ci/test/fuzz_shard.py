#!/usr/bin/env python3
# Copyright (c) 2026-present The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

from __future__ import annotations

import argparse
import logging
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Optional


SYMBOLIZER_PATH = os.environ.get("LLVM_SYMBOLIZER_PATH", "/usr/bin/llvm-symbolizer")


def fuzz_env(*, target: str, source_dir: Path) -> dict[str, str]:
    return os.environ | {
        "FUZZ": target,
        "UBSAN_OPTIONS": f"suppressions={source_dir}/test/sanitizer_suppressions/ubsan:print_stacktrace=1:halt_on_error=1:report_error_type=1",
        "UBSAN_SYMBOLIZER_PATH": SYMBOLIZER_PATH,
        "ASAN_OPTIONS": "detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1",
        "ASAN_SYMBOLIZER_PATH": SYMBOLIZER_PATH,
        "MSAN_SYMBOLIZER_PATH": SYMBOLIZER_PATH,
    }


def list_targets(*, fuzz_bin: Path, source_dir: Path) -> list[str]:
    output = subprocess.run(
        [str(fuzz_bin)],
        env={"PRINT_ALL_FUZZ_TARGETS_AND_ABORT": "", **fuzz_env(target="", source_dir=source_dir)},
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.splitlines()
    return sorted(output)


def shard_targets(targets: Iterable[str], shard_index: int, shard_count: int) -> list[str]:
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    if shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard_index must be within shard_count")
    sorted_targets = sorted(targets)
    return [target for idx, target in enumerate(sorted_targets) if idx % shard_count == shard_index]


def using_libfuzzer(*, fuzz_bin: Path, source_dir: Path, sample_target: str) -> bool:
    help_output = subprocess.run(
        [str(fuzz_bin), "-help=1"],
        env=fuzz_env(target=sample_target, source_dir=source_dir),
        check=False,
        stderr=subprocess.PIPE,
        text=True,
    ).stderr
    return "libFuzzer" in help_output


def run_targets(*, fuzz_bin: Path, source_dir: Path, corpus_dir: Path, targets: list[str], par: int, empty_min_time: Optional[int]) -> None:
    if not targets:
        raise ValueError("no fuzz targets selected for shard")

    is_libfuzzer = using_libfuzzer(fuzz_bin=fuzz_bin, source_dir=source_dir, sample_target=targets[0])
    stats: list[tuple[str, str]] = []

    def job(target: str) -> tuple[str, subprocess.CompletedProcess[str]]:
        target_corpus = corpus_dir / target
        target_corpus.mkdir(parents=True, exist_ok=True)
        args = [str(fuzz_bin)]
        empty_dir = not any(target_corpus.iterdir())
        if is_libfuzzer:
            if empty_min_time and empty_dir:
                args.append(f"-max_total_time={empty_min_time}")
            else:
                args.extend(["-runs=1", str(target_corpus)])
        else:
            args.append(str(target_corpus))
        result = subprocess.run(
            args,
            env=fuzz_env(target=target, source_dir=source_dir),
            stderr=subprocess.PIPE,
            text=True,
        )
        return target, result

    with ThreadPoolExecutor(max_workers=par) as pool:
        futures = [pool.submit(job, target) for target in targets]
        for future in as_completed(futures):
            target, result = future.result()
            logging.debug("Run %s\n%s", target, result.stderr)
            try:
                result.check_returncode()
            except subprocess.CalledProcessError:
                if result.stderr:
                    logging.error(result.stderr)
                raise
            if is_libfuzzer:
                done_lines = [line for line in result.stderr.splitlines() if "DONE" in line]
                if len(done_lines) != 1:
                    raise RuntimeError(f"expected one libFuzzer DONE line for target {target}")
                stats.append((target, done_lines[0]))

    if is_libfuzzer:
        print("Summary:")
        width = max(len(target) for target, _ in stats)
        for target, stat in sorted(stats):
            print(f"{target.ljust(width + 1)}{stat}")


def main() -> int:
    parser = argparse.ArgumentParser(description="List or run a deterministic shard of fuzz targets.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--fuzz-bin", required=True)
    common.add_argument("--source-dir", required=True)
    common.add_argument("--shard-index", type=int, required=True)
    common.add_argument("--shard-count", type=int, required=True)

    list_parser = subparsers.add_parser("list", parents=[common])
    list_parser.add_argument("--format", choices=("lines", "space"), default="lines")

    run_parser = subparsers.add_parser("run", parents=[common])
    run_parser.add_argument("--corpus-dir", required=True)
    run_parser.add_argument("--par", type=int, default=4)
    run_parser.add_argument("--empty-min-time", type=int)
    run_parser.add_argument("--loglevel", default="INFO")

    args = parser.parse_args()
    fuzz_bin = Path(args.fuzz_bin)
    source_dir = Path(args.source_dir)
    targets = shard_targets(
        list_targets(fuzz_bin=fuzz_bin, source_dir=source_dir),
        shard_index=args.shard_index,
        shard_count=args.shard_count,
    )

    if args.command == "list":
        if args.format == "space":
            print(" ".join(targets))
        else:
            print("\n".join(targets))
        return 0

    logging.basicConfig(
        format="%(message)s",
        level=int(args.loglevel) if str(args.loglevel).isdigit() else str(args.loglevel).upper(),
    )
    run_targets(
        fuzz_bin=fuzz_bin,
        source_dir=source_dir,
        corpus_dir=Path(args.corpus_dir),
        targets=targets,
        par=args.par,
        empty_min_time=args.empty_min_time,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
