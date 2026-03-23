#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpers for optional machine-readable PQBTC ops/SLO summaries."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time


class PQBTCSLORecorder:
    """Writes a one-shot JSON summary when PQBTC_SLO_SUMMARY_FILE is set."""

    def __init__(self, scenario: str):
        self._path = os.environ.get("PQBTC_SLO_SUMMARY_FILE")
        self._start = time.monotonic()
        self._summary = {
            "scenario": scenario,
            "pass": False,
            "duration_s": 0.0,
            "mempool_before_restart": None,
            "mempool_after_restart": None,
            "reorg_result": "not-run",
            "crash_assert_hang": False,
            "notes": "",
        }

    def update(self, **kwargs) -> None:
        self._summary.update(kwargs)

    def add_note(self, note: str) -> None:
        note = note.strip()
        if not note:
            return
        if self._summary["notes"]:
            self._summary["notes"] = f"{self._summary['notes']}; {note}"
        else:
            self._summary["notes"] = note

    def _write(self) -> None:
        if not self._path:
            return
        self._summary["duration_s"] = round(time.monotonic() - self._start, 3)
        path = Path(self._path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def success(self) -> None:
        self._summary["pass"] = True
        self._summary["crash_assert_hang"] = False
        self._write()

    def failure(self, note: str) -> None:
        self._summary["pass"] = False
        self._summary["crash_assert_hang"] = True
        self.add_note(note)
        self._write()
