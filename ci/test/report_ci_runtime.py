#!/usr/bin/env python3
# Copyright (c) 2026-present The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_BUDGET_PATH = Path(__file__).with_name("ci_runtime_budget.json")


def load_json_stream(path: Optional[str]) -> dict[str, Any]:
    if path:
        with open(path, encoding="utf8") as fh:
            return json.load(fh)
    return json.load(sys.stdin)


def load_budget(path: str) -> dict[str, Any]:
    with open(path, encoding="utf8") as fh:
        return json.load(fh)


def infer_workflow_name(run_data: dict[str, Any]) -> Optional[str]:
    for key in ("workflowName", "name"):
        value = run_data.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.strptime(value, TIME_FORMAT)


def completed_job_windows(run_data: dict[str, Any]) -> list[tuple[datetime, datetime, str]]:
    jobs = []
    for job in run_data.get("jobs", []):
        started = parse_timestamp(job.get("startedAt"))
        completed = parse_timestamp(job.get("completedAt"))
        if not started or not completed:
            continue
        jobs.append((started, completed, job.get("name", "<unnamed>")))
    if not jobs:
        raise ValueError("run data did not contain any completed jobs")
    return jobs


def compute_wall_clock_minutes(run_data: dict[str, Any]) -> float:
    jobs = completed_job_windows(run_data)
    started = min(start for start, _, _ in jobs)
    completed = max(end for _, end, _ in jobs)
    return (completed - started).total_seconds() / 60.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Report workflow wall-clock runtime against checked-in CI budgets.")
    parser.add_argument("--workflow", help="Workflow name to evaluate, for example 'CI'. If omitted, infer from JSON when possible.")
    parser.add_argument("--input", help="Saved gh run view JSON file. Reads stdin when omitted.")
    parser.add_argument("--budget", default=str(DEFAULT_BUDGET_PATH), help="Path to ci_runtime_budget.json.")
    args = parser.parse_args()

    run_data = load_json_stream(args.input)
    budget_data = load_budget(args.budget)
    workflow = args.workflow or infer_workflow_name(run_data)
    if not workflow:
        raise SystemExit("workflow name is required via --workflow when the JSON does not include one")

    workflow_budget = budget_data["workflows"].get(workflow)
    if workflow_budget is None:
        raise SystemExit(f"no runtime budget defined for workflow '{workflow}'")

    wall_clock_minutes = compute_wall_clock_minutes(run_data)
    budget_minutes = float(workflow_budget["wall_clock_minutes_max"])
    passed = wall_clock_minutes < budget_minutes
    status = "PASS" if passed else "FAIL"

    print(f"workflow={workflow}")
    print(f"wall_clock_definition={budget_data['wall_clock_definition']}")
    print(f"wall_clock_minutes={wall_clock_minutes:.2f}")
    print(f"budget_minutes_max={budget_minutes:.2f}")
    print(f"status={status}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
