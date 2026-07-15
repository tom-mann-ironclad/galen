#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

mkdir -p \
  "$OUT_DIR/clean/text" \
  "$OUT_DIR/clean/scripts" \
  "$OUT_DIR/clean/elf"

write_file "$OUT_DIR/clean/text/plain_text.txt" <<'EOF'
This is a clean plain text file used as a Galen corpus control.
EOF

write_file "$OUT_DIR/clean/text/readme.md" <<'EOF'
# Clean Corpus Control

This file should not trigger malware detections.
It exists to help measure false positives.
EOF

write_executable "$OUT_DIR/clean/scripts/backup_rotation.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "Rotating application logs..."
find ./logs -type f -name '*.log' -mtime +14 -print
EOF

write_executable "$OUT_DIR/clean/scripts/deploy_static_site.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "Building static site"
echo "Copying files to staging directory"
EOF

write_executable "$OUT_DIR/clean/scripts/log_cleanup.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "Cleaning temporary logs"
rm -f ./tmp/*.log 2>/dev/null || true
EOF

# ELF-like clean control. Not a valid executable, just a binary-looking file.
{
    printf '\177ELF'
    head -c 128 /dev/zero
    printf 'hello world\n'
} > "$OUT_DIR/clean/elf/hello_world_elf_like.bin"

append_manifest "$OUT_DIR" "00-clean" <<'EOF'

[[group]]
id = "clean"
root = "clean"
mode = "aggregate"

[group.expect]
max_malicious = 0
max_likely_malicious = 0
max_suspicious_rate = 0.02
EOF
