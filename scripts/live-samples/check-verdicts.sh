#!/usr/bin/env bash
set -euo pipefail

# Cross-references live malware samples fetched by fetch-live-samples.sh
# against galen's own `--output json` scan report, and reports how many of
# today's real, currently-circulating Malware Bazaar samples galen actually
# flagged as malicious. See TODO.md: "Live sample testing in CI".
#
# Intentionally observability-only for now: this script exits non-zero on a
# miss or a failed scan so the step is visible in the Actions UI, but the
# `live-sample-testing` job in nightly.yaml sets continue-on-error so a
# Malware Bazaar hiccup or a genuine miss doesn't block nightly publication
# until a baseline is established (see the ClamAV benchmark job for the same
# reasoning).
#
# Matching a sample to its detection record is done by exact path equality
# against galen's JSON `path` field, which is why fetch-live-samples.sh and
# this script must both be given the *same absolute* samples directory.
#
# An optional ClamAV comparison (--clamav-log) is purely informational, the
# same way README.md's "Benchmarks" section frames the ClamAV performance
# comparison: it never affects this script's exit code. Only galen's own
# misses do.

usage() {
    cat >&2 <<'EOF'
usage: check-verdicts.sh --manifest <path> --scan-json <path> --out-dir <path>
                          [--clamav-log <path>]

--clamav-log points at the raw output of:
  clamscan --recursive --no-summary <samples-dir>
EOF
    exit 1
}

MANIFEST=""
SCAN_JSON=""
OUT_DIR=""
CLAMAV_LOG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --scan-json) SCAN_JSON="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --clamav-log) CLAMAV_LOG="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[[ -z "$MANIFEST" || -z "$SCAN_JSON" || -z "$OUT_DIR" ]] && usage

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}
require_cmd jq

mkdir -p "$OUT_DIR"
results_json="$OUT_DIR/live-sample-results.json"
summary_md="$OUT_DIR/live-sample-summary.md"

sample_count="$(jq 'length' "$MANIFEST")"

if [[ "$sample_count" -eq 0 ]]; then
    {
        printf '### Live sample testing\n\n'
        printf 'No live samples were available this run (Malware Bazaar returned nothing new, or every download failed).\n'
    } > "$summary_md"
    printf '[]\n' > "$results_json"
    cat "$summary_md"
    exit 0
fi

status="$(jq -r '.status // "error"' "$SCAN_JSON" 2>/dev/null || echo "error")"
if [[ "$status" != "ok" ]]; then
    {
        printf '### Live sample testing\n\n'
        printf 'galen scan failed against the live-sample batch: `%s`\n' \
            "$(jq -r '.error.message // "unknown error"' "$SCAN_JSON" 2>/dev/null || echo "unknown error")"
    } > "$summary_md"
    printf '[]\n' > "$results_json"
    cat "$summary_md"
    exit 1
fi

# Turns ClamAV's "<path>: <status>" text output into JSON. Each scanned file
# produces one line ending in "OK" or "<signature name> FOUND"; paths are
# not expected to contain ": " themselves.
clamav_run=false
clamav_results="$OUT_DIR/.clamav-results.json"
if [[ -n "$CLAMAV_LOG" && -f "$CLAMAV_LOG" ]]; then
    clamav_run=true
    clamav_entries="$OUT_DIR/.clamav-entries.jsonl"
    : > "$clamav_entries"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        path="${line%: *}"
        status="${line##*: }"
        if [[ "$status" == *FOUND ]]; then
            jq -n --arg path "$path" --arg signature "${status% FOUND}" \
                '{path: $path, signature: $signature, detected: true}'
        else
            jq -n --arg path "$path" \
                '{path: $path, signature: null, detected: false}'
        fi
    done < "$CLAMAV_LOG" > "$clamav_entries"
    jq -s '.' "$clamav_entries" > "$clamav_results"
    rm -f "$clamav_entries"
else
    printf '[]\n' > "$clamav_results"
fi

jq -n \
    --slurpfile manifest "$MANIFEST" \
    --slurpfile scan "$SCAN_JSON" \
    --slurpfile clamav "$clamav_results" \
    --argjson clamav_run "$clamav_run" \
    '
    ($scan[0].visible_detections // []) as $detections
    | ($clamav[0] // []) as $clamav_detections
    | $manifest[0] | map(
        . as $sample
        | ($detections | map(select(.path == $sample.path)) | first) as $detection
        | ($clamav_detections | map(select(.path == $sample.path)) | first) as $clam
        | {
            sha256: $sample.sha256,
            family: $sample.family,
            path: $sample.path,
            galen_verdict: ($detection.verdict // "not_detected"),
            galen_detected: (($detection.verdict // "") == "malicious"),
            clamav_signature: (if $clamav_run then ($clam.signature // null) else null end),
            clamav_detected: (if $clamav_run then ($clam.detected // false) else null end)
        }
      )
    ' > "$results_json"
rm -f "$clamav_results"

total="$(jq 'length' "$results_json")"
galen_detected="$(jq '[.[] | select(.galen_detected)] | length' "$results_json")"
missed_json="$(jq '[.[] | select(.galen_detected | not)]' "$results_json")"
missed_count="$(jq 'length' <<< "$missed_json")"

{
    printf '### Live sample testing\n\n'
    printf 'Galen: %s/%s currently-circulating Malware Bazaar samples flagged malicious.\n' \
        "$galen_detected" "$total"

    if [[ "$clamav_run" == "true" ]]; then
        clamav_detected="$(jq '[.[] | select(.clamav_detected == true)] | length' "$results_json")"
        printf 'ClamAV: %s/%s flagged malicious (comparison only; does not affect this job'"'"'s result).\n\n' \
            "$clamav_detected" "$total"
        printf '| SHA-256 | Family | Galen | ClamAV |\n| --- | --- | --- | --- |\n'
        jq -r '.[] | "| \(.sha256) | \(.family) | \(.galen_verdict) | \(if .clamav_detected then "FOUND (\(.clamav_signature))" else "clean" end) |"' \
            "$results_json"
        printf '\n'
    elif [[ "$missed_count" -gt 0 ]]; then
        printf '\nMissed samples:\n\n'
        printf '| SHA-256 | Family | Verdict |\n| --- | --- | --- |\n'
        jq -r '.[] | "| \(.sha256) | \(.family) | \(.galen_verdict) |"' <<< "$missed_json"
        printf '\n'
    fi
} > "$summary_md"

cat "$summary_md"

if [[ "$missed_count" -gt 0 ]]; then
    exit 1
fi
