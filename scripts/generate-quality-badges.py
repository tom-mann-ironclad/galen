#!/usr/bin/env python3
"""Generate Shields endpoint payloads from nightly quality reports."""

import argparse
import json
import re
from pathlib import Path


def badge(label: str, value: float, threshold: float) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "label": label,
        "message": f"{value:.1f}%",
        "color": "brightgreen" if value >= threshold else "red",
        "cacheSeconds": 3600,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutation", type=Path, required=True)
    parser.add_argument("--coverage-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    mutation = json.loads(args.mutation.read_text(encoding="utf-8"))
    caught = int(mutation["caught"])
    viable = caught + int(mutation["missed"]) + int(mutation["timeout"])
    if viable == 0:
        raise ValueError("mutation report contains no viable mutants")
    mutation_score = caught * 100.0 / viable

    coverage_log = args.coverage_log.read_text(encoding="utf-8")
    coverage_matches = re.findall(r"([0-9]+(?:\.[0-9]+)?)% coverage", coverage_log)
    if not coverage_matches:
        raise ValueError("coverage percentage not found in Tarpaulin output")
    coverage = float(coverage_matches[-1])

    args.output.mkdir(parents=True, exist_ok=True)
    payloads = {
        "mutation.json": badge("mutation score", mutation_score, 84.5),
        "coverage.json": badge("coverage", coverage, 81.5),
    }
    for filename, payload in payloads.items():
        (args.output / filename).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
