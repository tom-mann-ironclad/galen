#!/usr/bin/env bash
set -euo pipefail

# Downloads a small batch of real, currently-circulating malware samples from
# Malware Bazaar for live-sample testing in CI (see TODO.md: "Live sample
# testing in CI"). Unlike the synthetic/EICAR corpus under corpus/ and
# test_files/, this exercises galen's full pipeline - signature sync, real
# archive/file parsing, hash lookup, and heuristics - against genuinely
# malicious, unpredictable real-world files.
#
# Downloaded samples are extracted with their executable bit stripped and
# must never be committed, cached, or uploaded as a build artifact. Only the
# resulting manifest (hashes and families, not file contents) and galen's
# scan verdicts should leave the runner - see check-verdicts.sh and
# nightly.yaml's `live-sample-testing` job, which deletes OUT_DIR once
# scanning is done.

usage() {
    cat >&2 <<'EOF'
usage: fetch-live-samples.sh --out-dir <path> [--count <n>]

Reads the Malware Bazaar auth key from GALEN_AUTH_KEY.
EOF
    exit 1
}

AUTH_KEY="${GALEN_AUTH_KEY:-}"
OUT_DIR=""
COUNT=15

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --count) COUNT="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[[ -z "$AUTH_KEY" || -z "$OUT_DIR" ]] && usage

log() {
    printf '[live-samples] %s\n' "$*" >&2
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

require_cmd curl
require_cmd jq
require_cmd unzip

MB_API="https://mb-api.abuse.ch/api/v1/"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/samples"
# Downstream consumers (galen scan, check-verdicts.sh) match paths from this
# manifest byte-for-byte against galen's own JSON output, so OUT_DIR must be
# absolute before anything is written under it.
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
manifest="$OUT_DIR/manifest.json"
manifest_entries="$OUT_DIR/.manifest-entries.jsonl"
: > "$manifest_entries"

log "requesting recent sample metadata"
# selector=time (last 60 minutes), not a fixed count: on 2026-09-01, every
# get_file attempt against selector=100's top-100 candidates returned
# HTTP 200 with a response that wasn't a valid password-protected zip (no
# downloadable sample). Temporary fix: only request the freshest window,
# on the theory that very recently submitted samples are more likely to
# still be downloadable than older entries in a fixed-count "recent" list.
# Revisit if this recurs - selector=time can also return zero candidates.
recent_json="$(curl -sS --fail-with-body -X POST "$MB_API" \
    -H "Auth-Key: $AUTH_KEY" \
    -d "query=get_recent&selector=time")"

status="$(jq -r '.query_status // "error"' <<< "$recent_json")"
if [[ "$status" != "ok" ]]; then
    log "Malware Bazaar get_recent returned status: $status"
    printf '[]\n' > "$manifest"
    exit 0
fi

mapfile -t candidates < <(jq -r '.data[].sha256_hash' <<< "$recent_json")
log "considering ${#candidates[@]} recent samples, downloading up to ${COUNT}"

downloaded=0
for hash in "${candidates[@]}"; do
    [[ "$downloaded" -ge "$COUNT" ]] && break

    zip_path="$OUT_DIR/${hash}.zip"
    http_code="$(curl -sS -o "$zip_path" -w '%{http_code}' -X POST "$MB_API" \
        -H "Auth-Key: $AUTH_KEY" \
        -d "query=get_file&sha256_hash=${hash}")"

    if [[ "$http_code" != "200" ]] || ! unzip -tq -P infected "$zip_path" >/dev/null 2>&1; then
        log "skipping ${hash}: sample unavailable (http ${http_code})"
        rm -f "$zip_path"
        continue
    fi

    dest="$OUT_DIR/samples/${hash}"
    mkdir -p "$dest"
    unzip -q -P infected -o "$zip_path" -d "$dest"
    rm -f "$zip_path"

    # Never let a downloaded live sample be accidentally executed.
    find "$dest" -type f -exec chmod -x {} +

    sample_file="$(find "$dest" -type f | head -n 1)"
    if [[ -z "$sample_file" ]]; then
        log "skipping ${hash}: archive contained no files"
        rm -rf "$dest"
        continue
    fi

    family="$(jq -r --arg h "$hash" \
        '.data[] | select(.sha256_hash == $h) | (.family // "unknown")' \
        <<< "$recent_json" | head -n 1)"

    jq -n --arg hash "$hash" --arg path "$sample_file" --arg family "$family" \
        '{sha256: $hash, path: $path, family: $family}' >> "$manifest_entries"

    downloaded=$((downloaded + 1))
done

jq -s '.' "$manifest_entries" > "$manifest"
rm -f "$manifest_entries"

log "downloaded ${downloaded} live samples into ${OUT_DIR}/samples (manifest: ${manifest})"
