#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-corpus}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

require_cmd bash
require_cmd mkdir
require_cmd cat
require_cmd printf
require_cmd chmod
require_cmd tar
require_cmd gzip
require_cmd zip
require_cmd mktemp
require_cmd truncate
require_cmd head

log "generating corpus at: $OUT_DIR"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/.manifest.d"

cat > "$OUT_DIR/manifest.toml" <<'EOF'
[suite]
name = "galen-regression-corpus"
schema_version = 1
generated_by = "scripts/corpus/generate.sh"

EOF

"$SCRIPT_DIR/generate-clean.sh" "$OUT_DIR"
"$SCRIPT_DIR/generate-suspicious.sh" "$OUT_DIR"
"$SCRIPT_DIR/generate-malicious-synthetic.sh" "$OUT_DIR"
"$SCRIPT_DIR/generate-archives.sh" "$OUT_DIR"
"$SCRIPT_DIR/generate-malformed.sh" "$OUT_DIR"
"$SCRIPT_DIR/generate-stress.sh" "$OUT_DIR"

cat "$OUT_DIR"/.manifest.d/*.toml >> "$OUT_DIR/manifest.toml"
rm -rf "$OUT_DIR/.manifest.d"

log "done"
log "warning: EICAR fixtures may be quarantined by security products"
