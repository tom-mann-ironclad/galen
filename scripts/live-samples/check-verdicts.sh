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

usage() {
    cat >&2 <<'EOF'
usage: check-verdicts.sh --manifest <path> --scan-json <path> --out-dir <path>
EOF
    exit 1
}

MANIFEST=""
SCAN_JSON=""
OUT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --scan-json) SCAN_JSON="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
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

jq -n \
    --slurpfile manifest "$MANIFEST" \
    --slurpfile scan "$SCAN_JSON" \
    '
    ($scan[0].visible_detections // []) as $detections
    | $manifest[0] | map(
        . as $sample
        | ($detections | map(select(.path == $sample.path)) | first) as $detection
        | {
            sha256: $sample.sha256,
            family: $sample.family,
            path: $sample.path,
            verdict: ($detection.verdict // "not_detected"),
            detected: (($detection.verdict // "") == "malicious")
        }
      )
    ' > "$results_json"

total="$(jq 'length' "$results_json")"
detected="$(jq '[.[] | select(.detected)] | length' "$results_json")"
missed_json="$(jq '[.[] | select(.detected | not)]' "$results_json")"
missed_count="$(jq 'length' <<< "$missed_json")"

{
    printf '### Live sample testing\n\n'
    printf '%s/%s currently-circulating Malware Bazaar samples were flagged malicious.\n\n' \
        "$detected" "$total"
    if [[ "$missed_count" -gt 0 ]]; then
        printf 'Missed samples:\n\n'
        printf '| SHA-256 | Family | Verdict |\n| --- | --- | --- |\n'
        jq -r '.[] | "| \(.sha256) | \(.family) | \(.verdict) |"' <<< "$missed_json"
        printf '\n'
    fi
} > "$summary_md"

cat "$summary_md"

if [[ "$missed_count" -gt 0 ]]; then
    exit 1
fi
