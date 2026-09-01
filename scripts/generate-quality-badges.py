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


def benchmark_badge(benchmark_path: Path | None) -> dict[str, object]:
    """Build the ClamAV wall-time comparison badge from run-benchmark.sh's output.

    Falls back to an explicit "no data yet" badge rather than omitting the
    file: nightly.yaml syncs dist/ to Cloudflare R2 with --delete, so a
    missing badge file here would delete the previous run's badge from R2
    and 404 the shields.io endpoint instead of degrading gracefully.
    """
    if benchmark_path is None or not benchmark_path.exists():
        return {
            "schemaVersion": 1,
            "label": "vs clamav",
            "message": "no data yet",
            "color": "lightgrey",
            "cacheSeconds": 3600,
        }

    data = json.loads(benchmark_path.read_text(encoding="utf-8"))
    galen_seconds = float(data["galen"]["wall_seconds"])
    clamav_seconds = float(data["clamav"]["wall_seconds"])
    if galen_seconds <= 0:
        raise ValueError("benchmark report has a non-positive galen wall_seconds")

    ratio = clamav_seconds / galen_seconds
    if ratio >= 1:
        message = f"{ratio:.1f}x faster than clamav"
        color = "brightgreen"
    else:
        message = f"{1 / ratio:.1f}x slower than clamav"
        color = "red"

    return {
        "schemaVersion": 1,
        "label": "wall time",
        "message": message,
        "color": color,
        "cacheSeconds": 3600,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutation", type=Path, required=True)
    parser.add_argument("--coverage-log", type=Path, required=True)
    parser.add_argument("--benchmark", type=Path, required=False, default=None)
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
        "benchmark.json": benchmark_badge(args.benchmark),
    }
    for filename, payload in payloads.items():
        (args.output / filename).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
