#!/usr/bin/env bash
set -euo pipefail

# Builds the ClamAV-comparison benchmark corpus by shallow-fetching each
# pinned commit listed in corpus-manifest.txt. Produces a directory of real,
# mixed-language source and binary files without depending on any single
# machine's home directory (see TODO.md: "Add reproducible benchmark
# fixtures and baseline results").

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/corpus-manifest.txt"
OUT_DIR="${1:-bench-corpus}"

# shellcheck source=../corpus/lib.sh
source "$SCRIPT_DIR/../corpus/lib.sh"

require_cmd git
require_cmd mkdir
require_cmd rm

log() {
    printf '[bench-corpus] %s\n' "$*"
}

log "preparing corpus at: $OUT_DIR"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

while read -r url sha subdir; do
    # Skip blank lines and comments.
    [[ -z "$url" || "$url" == \#* ]] && continue

    target="$OUT_DIR/$subdir"
    log "fetching $subdir @ $sha"
    mkdir -p "$target"
    git -C "$target" init -q
    git -C "$target" remote add origin "$url"
    git -C "$target" fetch --depth 1 origin "$sha"
    git -C "$target" checkout -q FETCH_HEAD

    # Drop VCS metadata: we want the realistic mixed files a scanner would
    # encounter on disk, not git's own packed object store.
    rm -rf "$target/.git"
done < "$MANIFEST"

file_count="$(find "$OUT_DIR" -type f | wc -l)"
log "done: $file_count files"
