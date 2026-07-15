#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

mkdir -p \
  "$OUT_DIR/stress/recursion" \
  "$OUT_DIR/stress/many_entries" \
  "$OUT_DIR/stress/decompression_limits"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Deep recursion: zip containing zip containing zip.
mkdir -p "$TMP/level0"
eicar_string > "$TMP/level0/eicar.com"
make_zip_from_dir "$TMP/level0" "$TMP/level0.zip"

previous="$TMP/level0.zip"

for depth in $(seq 1 20); do
    level_dir="$TMP/level${depth}"
    mkdir -p "$level_dir"
    cp "$previous" "$level_dir/level$((depth - 1)).zip"
    make_zip_from_dir "$level_dir" "$TMP/level${depth}.zip"
    previous="$TMP/level${depth}.zip"
done

cp "$previous" "$OUT_DIR/stress/recursion/deep_recursion.zip"

# Many entries, controlled size.
many_dir="$TMP/many_entries"
mkdir -p "$many_dir"

for i in $(seq -w 0 249); do
    printf 'clean tiny file %s\n' "$i" > "$many_dir/file_${i}.txt"
done

make_zip_from_dir "$many_dir" "$OUT_DIR/stress/many_entries/many_small_files.zip"

# High compression ratio, controlled.
ratio_dir="$TMP/high_ratio"
mkdir -p "$ratio_dir"
head -c 1048576 /dev/zero > "$ratio_dir/one_megabyte_of_zeroes.bin"
make_zip_from_dir "$ratio_dir" "$OUT_DIR/stress/decompression_limits/high_ratio_controlled.zip"

bomb_dir="$TMP/controlled_bomb"
mkdir -p "$bomb_dir"
truncate -s $((256 * 1024 * 1024)) "$bomb_dir/two_hundred_fifty_six_megabytes_of_zeroes.bin"
make_zip_from_dir "$bomb_dir" "$OUT_DIR/stress/decompression_limits/zip_bomb_controlled.zip"

# Deep recursion with a large compressed payload at the innermost level.
deep_large_dir="$TMP/deep_large_level0"
mkdir -p "$deep_large_dir"
truncate -s $((256 * 1024 * 1024)) "$deep_large_dir/two_hundred_fifty_six_megabytes_of_zeroes.bin"
make_zip_from_dir "$deep_large_dir" "$TMP/deep_large_level0.zip"

previous="$TMP/deep_large_level0.zip"

for depth in $(seq 1 20); do
    level_dir="$TMP/deep_large_level${depth}"
    mkdir -p "$level_dir"
    cp "$previous" "$level_dir/level$((depth - 1)).zip"
    make_zip_from_dir "$level_dir" "$TMP/deep_large_level${depth}.zip"
    previous="$TMP/deep_large_level${depth}.zip"
done

cp "$previous" "$OUT_DIR/stress/recursion/deep_large_recursion.zip"

# Path traversal names. Do not extract these to disk in tests.
traversal_zip="$OUT_DIR/stress/decompression_limits/path_traversal_names.zip"
traversal_zip_abs="$(abs_path "$traversal_zip")"
mkdir -p "$(dirname "$traversal_zip_abs")"

(
    cd "$TMP"
    printf 'path traversal name fixture\n' > outside.txt
    zip -q -X "$traversal_zip_abs" outside.txt
)

# Add special filenames using zip's stdin mode where supported.
# If this becomes too fiddly, generate this fixture from Rust instead.
printf 'absolute path name fixture\n' > "$TMP/absolute_path.txt"

append_manifest "$OUT_DIR" "50-stress" <<'EOF'

[[group]]
id = "stress"
root = "stress"
mode = "per-case"

[group.expect]
must_not_panic = true
allow_outcomes = ["Skipped", "Clean", "Suspicious", "Malicious"]

[[case]]
id = "deep-recursion-limit"
path = "stress/recursion/deep_recursion.zip"

[case.expect]
outcome = "Skipped"
skip_reason = "maximum recursion reached"

[[case]]
id = "controlled-zip-bomb"
path = "stress/decompression_limits/zip_bomb_controlled.zip"

[case.expect]
outcome = "Skipped"
skip_reason = "maximum decompressed size reached"

[[case]]
id = "deep-large-recursion-limit"
path = "stress/recursion/deep_large_recursion.zip"

[case.expect]
outcome = "Skipped"
skip_reason = "maximum recursion reached"
EOF
