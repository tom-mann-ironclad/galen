#!/usr/bin/env bash
set -euo pipefail

# Runs Galen and ClamAV over the same corpus, wrapped in `/usr/bin/time -v`,
# and emits a JSON result plus a markdown summary table. This automates the
# comparison that previously lived only as a one-off manual measurement
# (see README.md "Benchmarks" and TODO.md "Add reproducible benchmark
# fixtures and baseline results").
#
# This is intentionally observability-only: it does not fail the build on a
# performance regression. GitHub-hosted runners are shared and noisy enough
# that hard-gating on wall-clock time before a stable baseline exists would
# produce false alarms.

usage() {
    cat >&2 <<'EOF'
usage: run-benchmark.sh \
    --galen-bin <path> \
    --database <path> \
    --yara-cache <path> \
    --corpus <path> \
    --out-dir <path> \
    [--clamav-bin <path>]
EOF
    exit 1
}

GALEN_BIN=""
DATABASE=""
YARA_CACHE=""
CORPUS=""
OUT_DIR=""
CLAMAV_BIN="clamscan"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --galen-bin) GALEN_BIN="$2"; shift 2 ;;
        --database) DATABASE="$2"; shift 2 ;;
        --yara-cache) YARA_CACHE="$2"; shift 2 ;;
        --corpus) CORPUS="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --clamav-bin) CLAMAV_BIN="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[[ -z "$GALEN_BIN" || -z "$DATABASE" || -z "$YARA_CACHE" || -z "$CORPUS" || -z "$OUT_DIR" ]] && usage

log() {
    printf '[bench] %s\n' "$*"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

require_cmd /usr/bin/time
require_cmd "$CLAMAV_BIN"
require_cmd awk
require_cmd find
require_cmd du

mkdir -p "$OUT_DIR"

# Converts a GNU `time -v` "Elapsed (wall clock) time" value, which is
# formatted as either m:ss.cc or h:mm:ss, into seconds.
wall_clock_to_seconds() {
    local raw="$1" h=0 m s
    case "$raw" in
        *:*:*) IFS=: read -r h m s <<< "$raw" ;;
        *:*) IFS=: read -r m s <<< "$raw" ;;
    esac
    awk -v h="$h" -v m="$m" -v s="$s" 'BEGIN { printf "%.3f", (h * 3600) + (m * 60) + s }'
}

extract_field() {
    local log="$1" label="$2"
    grep -F "$label" "$log" | head -n 1 | awk -F': ' '{print $NF}'
}

log "corpus: $CORPUS"
file_count="$(find "$CORPUS" -type f | wc -l)"
total_bytes="$(du -sb "$CORPUS" | awk '{print $1}')"
log "corpus files: $file_count, total bytes: $total_bytes"

log "running galen scan"
galen_exit=0
/usr/bin/time -v -o "$OUT_DIR/galen-time.log" \
    "$GALEN_BIN" scan "$CORPUS" \
    --database "$DATABASE" \
    --yara-cache "$YARA_CACHE" \
    --output json \
    > "$OUT_DIR/galen-output.json" || galen_exit=$?
log "galen exit code: $galen_exit"

log "running clamscan"
clamav_exit=0
/usr/bin/time -v -o "$OUT_DIR/clamav-time.log" \
    "$CLAMAV_BIN" --recursive --no-summary "$CORPUS" \
    > "$OUT_DIR/clamav-output.log" || clamav_exit=$?
log "clamscan exit code: $clamav_exit"

galen_wall_raw="$(extract_field "$OUT_DIR/galen-time.log" 'Elapsed (wall clock) time')"
galen_wall="$(wall_clock_to_seconds "$galen_wall_raw")"
galen_rss_kb="$(extract_field "$OUT_DIR/galen-time.log" 'Maximum resident set size')"
galen_minor_faults="$(extract_field "$OUT_DIR/galen-time.log" 'Minor (reclaiming a frame) page faults')"
galen_involuntary="$(extract_field "$OUT_DIR/galen-time.log" 'Involuntary context switches')"

clamav_wall_raw="$(extract_field "$OUT_DIR/clamav-time.log" 'Elapsed (wall clock) time')"
clamav_wall="$(wall_clock_to_seconds "$clamav_wall_raw")"
clamav_rss_kb="$(extract_field "$OUT_DIR/clamav-time.log" 'Maximum resident set size')"
clamav_minor_faults="$(extract_field "$OUT_DIR/clamav-time.log" 'Minor (reclaiming a frame) page faults')"
clamav_involuntary="$(extract_field "$OUT_DIR/clamav-time.log" 'Involuntary context switches')"

galen_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
galen_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
clamav_version="$("$CLAMAV_BIN" --version 2>/dev/null | head -n 1)"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

result_json="$OUT_DIR/benchmark.json"
cat > "$result_json" <<EOF
{
  "timestamp": "$timestamp",
  "corpus": {
    "file_count": $file_count,
    "total_bytes": $total_bytes
  },
  "galen": {
    "version": "$galen_version",
    "commit": "$galen_sha",
    "exit_code": $galen_exit,
    "wall_seconds": $galen_wall,
    "max_rss_kb": $galen_rss_kb,
    "minor_page_faults": $galen_minor_faults,
    "involuntary_context_switches": $galen_involuntary
  },
  "clamav": {
    "version": "$clamav_version",
    "exit_code": $clamav_exit,
    "wall_seconds": $clamav_wall,
    "max_rss_kb": $clamav_rss_kb,
    "minor_page_faults": $clamav_minor_faults,
    "involuntary_context_switches": $clamav_involuntary
  }
}
EOF
log "wrote $result_json"

summary_md="$OUT_DIR/benchmark-summary.md"
{
    printf '| Scanner | Files | Wall time | Max RSS | Minor page faults | Involuntary context switches |\n'
    printf '| ------- | ----: | --------: | ------: | -----------------: | ----------------------------: |\n'
    printf '| Galen   | %s | %ss | %s MB | %s | %s |\n' \
        "$file_count" "$galen_wall" "$((galen_rss_kb / 1024))" "$galen_minor_faults" "$galen_involuntary"
    printf '| ClamAV  | %s | %ss | %s MB | %s | %s |\n' \
        "$file_count" "$clamav_wall" "$((clamav_rss_kb / 1024))" "$clamav_minor_faults" "$clamav_involuntary"
} > "$summary_md"
log "wrote $summary_md"
cat "$summary_md"
