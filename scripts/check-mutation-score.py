#!/usr/bin/env python3
"""Enforce the checked-in mutation-testing ratchet."""

import json
import sys
from pathlib import Path


MINIMUM_SCORE_PERCENT = 84.5
MAXIMUM_TIMEOUTS = 1


def main() -> int:
    outcomes_path = Path(sys.argv[1] if len(sys.argv) > 1 else "mutants.out/outcomes.json")
    outcomes = json.loads(outcomes_path.read_text(encoding="utf-8"))

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
