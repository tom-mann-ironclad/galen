#!/usr/bin/env python3
"""Enforce the checked-in mutation-testing ratchet."""

import argparse
import json
import sys
from pathlib import Path


MINIMUM_SCORE_PERCENT = 84.5
MAXIMUM_TIMEOUTS = 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "outcomes",
        nargs="*",
        type=Path,
        default=[Path("mutants.out/outcomes.json")],
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def aggregate(paths: list[Path]) -> dict:
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if not reports:
        raise ValueError("no mutation reports were provided")

    outcomes = {
        "outcomes": [item for report in reports for item in report.get("outcomes", [])],
        "total_mutants": sum(int(report["total_mutants"]) for report in reports),
        "missed": sum(int(report["missed"]) for report in reports),
        "caught": sum(int(report["caught"]) for report in reports),
        "timeout": sum(int(report["timeout"]) for report in reports),
        "unviable": sum(int(report["unviable"]) for report in reports),
        "success": sum(int(report.get("success", 0)) for report in reports),
    }
    return outcomes


def main() -> int:
    args = parse_args()
    outcomes = aggregate(args.outcomes)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(outcomes, indent=2) + "\n", encoding="utf-8")

    caught = int(outcomes["caught"])
    missed = int(outcomes["missed"])
    timeouts = int(outcomes["timeout"])
    viable = caught + missed + timeouts
    if viable == 0:
        print("Mutation score unavailable: no viable mutants were tested", file=sys.stderr)
        return 1

    score = caught * 100.0 / viable
    print(
        f"Mutation score: {score:.2f}% "
        f"({caught} caught, {missed} missed, {timeouts} timed out, "
        f"{outcomes['unviable']} unviable)"
    )
    print(
        f"Required score: {MINIMUM_SCORE_PERCENT:.2f}%; "
        f"maximum timeouts: {MAXIMUM_TIMEOUTS}"
    )

    failed = False
    if score < MINIMUM_SCORE_PERCENT:
        print("Mutation score fell below the checked-in ratchet", file=sys.stderr)
        failed = True
    if timeouts > MAXIMUM_TIMEOUTS:
        print("Mutation timeouts exceeded the checked-in limit", file=sys.stderr)
        failed = True

    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
