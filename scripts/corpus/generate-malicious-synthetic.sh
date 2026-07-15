#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

ROOT="$OUT_DIR/malicious/synthetic/eicar"
mkdir -p "$ROOT"

eicar_string > "$ROOT/eicar.com"
eicar_string > "$ROOT/eicar.txt"
printf '\n' >> "$ROOT/eicar.txt"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/eicar"
cp "$ROOT/eicar.com" "$TMP/eicar/eicar.com"

make_zip_from_dir "$TMP/eicar" "$ROOT/eicar.zip"
make_tar_from_dir "$TMP/eicar" "$ROOT/eicar.tar"
make_tar_gz_from_dir "$TMP/eicar" "$ROOT/eicar.tar.gz"

append_manifest "$OUT_DIR" "20-malicious-synthetic" <<'EOF'

[[group]]
id = "synthetic-malicious"
root = "malicious/synthetic"
mode = "per-file"

[group.expect]
verdict = "Malicious"
require_detection = true
allow_skipped = false
EOF
