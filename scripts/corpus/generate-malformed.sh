#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

mkdir -p \
  "$OUT_DIR/malformed/zip" \
  "$OUT_DIR/malformed/tar" \
  "$OUT_DIR/malformed/gzip"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/good_zip"
printf 'this zip will be truncated\n' > "$TMP/good_zip/file.txt"
make_zip_from_dir "$TMP/good_zip" "$TMP/good.zip"
head -c 24 "$TMP/good.zip" > "$OUT_DIR/malformed/zip/truncated.zip"

head -c 256 /dev/urandom > "$OUT_DIR/malformed/zip/random_bytes.zip"

mkdir -p "$TMP/good_tar"
printf 'this tar will be truncated\n' > "$TMP/good_tar/file.txt"
make_tar_from_dir "$TMP/good_tar" "$TMP/good.tar"
head -c 128 "$TMP/good.tar" > "$OUT_DIR/malformed/tar/truncated.tar"

printf 'this file has a .gz extension but is not gzip data\n' > "$OUT_DIR/malformed/gzip/not_really_gzip.gz"

printf 'this gzip file will be truncated\n' | gzip -n > "$TMP/good.gz"
head -c 10 "$TMP/good.gz" > "$OUT_DIR/malformed/gzip/truncated.gz"

append_manifest "$OUT_DIR" "40-malformed" <<'EOF'

[[group]]
id = "malformed"
root = "malformed"
mode = "per-file"

[group.expect]
must_not_panic = true
allow_outcomes = ["Clean", "Skipped", "Suspicious"]
EOF
