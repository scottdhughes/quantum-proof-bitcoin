#!/usr/bin/env python3
"""
Gatekeeper — PQBTC Freeze-Gate Enforcement

Enforces the docs-first invariant (I3): frozen specs must exist on the base
branch (origin/main) before consensus-critical code can be modified.

Usage:
    python3 gatekeeper.py --rules gatekeeper.yaml --base origin/main --head HEAD

Exit codes:
    0 — All gates pass
    1 — Gate violation detected
    2 — Configuration or runtime error
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import]
except ImportError:
    print("ERROR: pyyaml required. Install with: pip3 install pyyaml", file=sys.stderr)
    sys.exit(2)


def git_diff_files(base: str, head: str) -> list[str]:
    """Get list of files changed between base and head."""
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]


def git_show_file(ref: str, path: str) -> str | None:
    """Get file contents at a specific git ref. Returns None if file doesn't exist."""
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


def git_ls_tree(ref: str, path: str) -> list[str]:
    """List files in a directory at a specific git ref."""
    try:
        result = subprocess.run(
            ["git", "ls-tree", "--name-only", ref, path + "/"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    except subprocess.CalledProcessError:
        return []


def path_matches_patterns(path: str, patterns: list[str]) -> bool:
    """Check if path matches any of the glob patterns."""
    for pattern in patterns:
        # Handle ** for recursive matching
        if "**" in pattern:
            # Convert ** glob to regex
            regex_pattern = pattern.replace(".", r"\.").replace("**", ".*").replace("*", "[^/]*")
            if re.match(regex_pattern, path):
                return True
        elif fnmatch.fnmatch(path, pattern):
            return True
    return False


def check_file_requirement(
    req: dict[str, Any], base_ref: str, head_ref: str
) -> tuple[bool, str]:
    """Check a file requirement. Returns (passed, error_message)."""
    where = req.get("where", "base")
    ref = base_ref if where == "base" else head_ref

    file_path = req.get("file")
    if file_path:
        content = git_show_file(ref, file_path)
        if content is None:
            return False, f"File '{file_path}' not found on {where} branch ({ref})"

        # Check required substrings
        contains = req.get("contains", [])
        for substring in contains:
            if substring not in content:
                return False, f"File '{file_path}' on {where} branch missing required content: '{substring}'"

        return True, ""

    return True, ""


def check_directory_requirement(
    req: dict[str, Any], base_ref: str, head_ref: str
) -> tuple[bool, str]:
    """Check a directory requirement. Returns (passed, error_message)."""
    where = req.get("where", "base")
    ref = base_ref if where == "base" else head_ref

    directory = req.get("directory")
    if directory:
        files = git_ls_tree(ref, directory)
        min_files = req.get("min_files", 1)
        if len(files) < min_files:
            return False, f"Directory '{directory}' on {where} branch has {len(files)} files (requires >= {min_files})"
        return True, ""

    return True, ""


def is_frozen_doc(content: str) -> bool:
    """
    Check if a document is marked as frozen.
    The FROZEN header must appear as a proper heading in the first 30 lines,
    not just mentioned in passing (e.g., as an example).
    """
    lines = content.split('\n')[:30]
    for line in lines:
        stripped = line.strip()
        # Must be a proper markdown heading, not inline text
        if stripped == "## Status: FROZEN":
            return True
    return False


def check_frozen_doc_contract(
    content: str, file_path: str, contract: dict[str, Any]
) -> list[str]:
    """
    Check that a frozen doc meets the contract requirements.
    Returns list of violations.
    """
    violations: list[str] = []

    if not is_frozen_doc(content):
        return []  # Not a frozen doc, skip contract checking

    # Check required headers
    required_headers = contract.get("required_headers", [])
    for header in required_headers:
        if header not in content:
            violations.append(f"Frozen doc '{file_path}' missing required header: '{header}'")

    # Check forbidden tokens
    forbidden = contract.get("forbidden_tokens", [])
    for token in forbidden:
        # Use word boundary matching to avoid false positives
        if re.search(rf'\b{re.escape(token)}\b', content):
            violations.append(f"Frozen doc '{file_path}' contains forbidden token: '{token}'")

    return violations


def run_gatekeeper(rules_path: str, base_ref: str, head_ref: str) -> int:
    """
    Run gatekeeper checks.

    Returns:
        0 if all checks pass
        1 if any check fails
        2 if configuration error
    """
    # Load rules
    try:
        with open(rules_path, encoding="utf-8") as rules_file:
            config = yaml.safe_load(rules_file)
    except Exception as exc:
        print(f"ERROR: Failed to load rules from {rules_path}: {exc}", file=sys.stderr)
        return 2

    rules = config.get("rules", [])
    frozen_contract = config.get("frozen_doc_contract", {})

    # Get changed files
    try:
        changed_files = git_diff_files(base_ref, head_ref)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: Failed to get changed files: {exc}", file=sys.stderr)
        return 2

    if not changed_files:
        print("No files changed.")
        return 0

    print(f"Changed files ({len(changed_files)}):")
    for fname in changed_files[:10]:
        print(f"  - {fname}")
    if len(changed_files) > 10:
        print(f"  ... and {len(changed_files) - 10} more")
    print()

    # Track all violations
    all_violations: list[str] = []

    # Check each rule
    for rule in rules:
        rule_name = rule.get("name", "unnamed rule")
        patterns = rule.get("paths", [])
        requirements = rule.get("requires", [])

        # Find changed files matching this rule's patterns
        matching_files = [fname for fname in changed_files if path_matches_patterns(fname, patterns)]

        if not matching_files:
            continue

        print(f"Rule: {rule_name}")
        print(f"  Triggered by: {matching_files[:3]}{'...' if len(matching_files) > 3 else ''}")

        rule_violations: list[str] = []

        # Check all requirements
        for req in requirements:
            if "file" in req:
                passed, error = check_file_requirement(req, base_ref, head_ref)
                if not passed:
                    rule_violations.append(error)
            elif "directory" in req:
                passed, error = check_directory_requirement(req, base_ref, head_ref)
                if not passed:
                    rule_violations.append(error)

        if rule_violations:
            print("  FAILED:")
            for violation in rule_violations:
                print(f"    - {violation}")
            all_violations.extend(rule_violations)
        else:
            print("  PASSED")
        print()

    # Check frozen doc contract for any frozen docs in the PR
    if frozen_contract:
        for file_path in changed_files:
            if file_path.startswith("docs/") and file_path.endswith(".md"):
                content = git_show_file(head_ref, file_path)
                if content and is_frozen_doc(content):
                    violations = check_frozen_doc_contract(content, file_path, frozen_contract)
                    if violations:
                        print(f"Frozen doc contract violations in {file_path}:")
                        for violation in violations:
                            print(f"  - {violation}")
                        all_violations.extend(violations)
                        print()

    # Final result
    if all_violations:
        print("=" * 60)
        print("GATEKEEPER FAILED")
        print("=" * 60)
        print(f"\n{len(all_violations)} violation(s) detected.\n")
        print("Required artifacts must exist on the base branch (origin/main)")
        print("with '## Status: FROZEN' header BEFORE code changes can land.")
        print("\nTo fix: Land the required spec/doc PR first, then rebase this PR.")
        return 1

    print("=" * 60)
    print("GATEKEEPER PASSED")
    print("=" * 60)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PQBTC Gatekeeper — Freeze-gate enforcement"
    )
    parser.add_argument(
        "--rules",
        required=True,
        help="Path to gatekeeper.yaml rules file",
    )
    parser.add_argument(
        "--base",
        required=True,
        help="Base ref to check against (e.g., origin/main)",
    )
    parser.add_argument(
        "--head",
        default="HEAD",
        help="Head ref to check (default: HEAD)",
    )

    args = parser.parse_args()

    # Ensure we're in a git repository
    if not Path(".git").exists() and not Path("../.git").exists():
        print("ERROR: Must be run from within a git repository", file=sys.stderr)
        sys.exit(2)

    sys.exit(run_gatekeeper(args.rules, args.base, args.head))


if __name__ == "__main__":
    main()
