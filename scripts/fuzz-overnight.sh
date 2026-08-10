#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPOSITORY_ROOT"

SECONDS_PER_TARGET="${GALEN_FUZZ_SECONDS_PER_TARGET:-10800}"
MAX_INPUT_BYTES="${GALEN_FUZZ_MAX_INPUT_BYTES:-1048576}"
RSS_LIMIT_MB="${GALEN_FUZZ_RSS_LIMIT_MB:-2048}"
INPUT_TIMEOUT_SECONDS="${GALEN_FUZZ_INPUT_TIMEOUT_SECONDS:-10}"
RESULTS_DIR="${GALEN_FUZZ_RESULTS_DIR:-fuzz-results}"
TARGETS=(fuzz_zip fuzz_tar fuzz_gzip)

if [[ ! "$SECONDS_PER_TARGET" =~ ^[1-9][0-9]*$ ]]; then
  echo "GALEN_FUZZ_SECONDS_PER_TARGET must be a positive integer" >&2
  exit 2
fi

if ! rustup toolchain list | grep -q '^nightly'; then
  echo "Nightly Rust is required. Install it with: rustup toolchain install nightly" >&2
  exit 2
fi

if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
  echo "cargo-fuzz is required. Install it with: cargo install cargo-fuzz --locked" >&2
  exit 2
fi

mkdir -p "$RESULTS_DIR"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
FAILED_TARGETS=()

echo "Running ${#TARGETS[@]} fuzz targets sequentially for ${SECONDS_PER_TARGET}s each."
echo "Logs will be written beneath $RESULTS_DIR."

for target in "${TARGETS[@]}"; do
  log_path="$RESULTS_DIR/${target}-${RUN_ID}.log"
  echo "Starting $target; log: $log_path"

  cargo +nightly fuzz run "$target" -- \
    "-max_total_time=$SECONDS_PER_TARGET" \
    "-max_len=$MAX_INPUT_BYTES" \
    "-timeout=$INPUT_TIMEOUT_SECONDS" \
    "-rss_limit_mb=$RSS_LIMIT_MB" \
    -print_final_stats=1 \
    2>&1 | tee "$log_path"
  fuzz_exit=${PIPESTATUS[0]}

  if (( fuzz_exit != 0 )); then
    FAILED_TARGETS+=("$target")
    echo "$target exited with status $fuzz_exit; continuing with the remaining targets." >&2
  fi
done

if (( ${#FAILED_TARGETS[@]} > 0 )); then
  echo "Fuzzing failures: ${FAILED_TARGETS[*]}" >&2
  echo "Inspect fuzz/artifacts/<target>/ and the corresponding logs." >&2
  exit 1
fi

echo "All overnight fuzz runs completed without a reported failure."
