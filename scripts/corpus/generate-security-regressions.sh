#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

SECURITY_DIR="$OUT_DIR/security_regressions"
mkdir -p \
  "$SECURITY_DIR/verdict_suppression" \
  "$SECURITY_DIR/symlinks" \
  "$SECURITY_DIR/zip_limits"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The archive container matches both regression rules and is malicious. Its
# child matches only one rule and is suspicious, so it must not suppress the
# stronger container verdict.
printf 'GALEN_WEAKER_CHILD_MARKER\n' > "$TMP/weaker-child.bin"
verdict_zip="$(abs_path "$SECURITY_DIR/verdict_suppression/malicious_container_weaker_child.zip")"
(
    cd "$TMP"
    printf 'GALEN_CONTAINER_ONLY_MARKER\n' | zip -q -X -z "$verdict_zip" weaker-child.bin
)

# A static symlink cannot reproduce the timing of a TOCTOU replacement, but it
# exercises the corpus-visible no-follow contract used by the atomic open.
printf 'GALEN_CONTAINER_ONLY_MARKER\n' > "$SECURITY_DIR/symlinks/malicious-target.bin"
ln -s malicious-target.bin "$SECURITY_DIR/symlinks/malicious-link.bin"

# A compact hostile ZIP footer declaring 10,001 entries. The scanner must
# reject this count before asking the ZIP library to parse a central directory.
printf 'PK\003\004placeholderPK\005\006\000\000\000\000\021\047\021\047\000\000\000\000\000\000\000\000\000\000' \
  > "$SECURITY_DIR/zip_limits/declared_10001_entries.zip"

append_manifest "$OUT_DIR" "60-security-regressions" <<'EOF'

[[group]]
id = "security-regressions"
root = "security_regressions"
mode = "per-case"

[group.expect]
must_not_panic = true

[[case]]
id = "verdict-suppression-preserves-malicious-container"
path = "security_regressions/verdict_suppression/malicious_container_weaker_child.zip"

[case.expect]
verdict = "Malicious"
visible_path = "security_regressions/verdict_suppression/malicious_container_weaker_child.zip"

[[case]]
id = "symlink-no-follow"
path = "security_regressions/symlinks/malicious-link.bin"

[case.expect]
outcome = "Skipped"
skip_reason = "file_is_symlink"

[[case]]
id = "zip-entry-count-preflight"
path = "security_regressions/zip_limits/declared_10001_entries.zip"

[case.expect]
outcome = "Skipped"
skip_reason = "maximum_archive_entries_reached"
archive_entries_scanned = 0
EOF
