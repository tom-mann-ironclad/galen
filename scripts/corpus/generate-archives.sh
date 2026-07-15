#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

mkdir -p \
  "$OUT_DIR/archives/clean" \
  "$OUT_DIR/archives/malicious" \
  "$OUT_DIR/archives/suspicious" \
  "$OUT_DIR/archives/mixed"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Clean archives
mkdir -p "$TMP/clean/docs" "$TMP/clean/scripts"
printf 'clean zip archive fixture\n' > "$TMP/clean/readme.txt"
printf '# Clean archive fixture\n' > "$TMP/clean/docs/info.md"
printf '#!/usr/bin/env bash\necho clean\n' > "$TMP/clean/scripts/hello.sh"

make_zip_from_dir "$TMP/clean" "$OUT_DIR/archives/clean/clean_zip.zip"
make_tar_from_dir "$TMP/clean" "$OUT_DIR/archives/clean/clean_tar.tar"
make_tar_gz_from_dir "$TMP/clean" "$OUT_DIR/archives/clean/clean_tar_gz.tar.gz"

# EICAR payload dir
mkdir -p "$TMP/eicar"
eicar_string > "$TMP/eicar/eicar.com"

make_zip_from_dir "$TMP/eicar" "$OUT_DIR/archives/malicious/eicar_zip.zip"
make_tar_from_dir "$TMP/eicar" "$OUT_DIR/archives/malicious/eicar_tar.tar"
make_tar_gz_from_dir "$TMP/eicar" "$OUT_DIR/archives/malicious/eicar_tar_gz.tar.gz"

# zip inside zip
mkdir -p "$TMP/nested_zip_inner"
eicar_string > "$TMP/nested_zip_inner/eicar.com"
make_zip_from_dir "$TMP/nested_zip_inner" "$TMP/eicar_inner.zip"

mkdir -p "$TMP/zip_inside_zip/inner"
cp "$TMP/eicar_inner.zip" "$TMP/zip_inside_zip/inner/eicar.zip"
make_zip_from_dir "$TMP/zip_inside_zip" "$OUT_DIR/archives/malicious/eicar_zip_inside_zip.zip"

# zip inside tar
mkdir -p "$TMP/zip_inside_tar/inner"
cp "$TMP/eicar_inner.zip" "$TMP/zip_inside_tar/inner/eicar.zip"
make_tar_from_dir "$TMP/zip_inside_tar" "$OUT_DIR/archives/malicious/eicar_zip_inside_tar.tar"

# zip inside tar.gz
make_tar_gz_from_dir "$TMP/zip_inside_tar" "$OUT_DIR/archives/malicious/eicar_zip_inside_tar_gz.tar.gz"

# tar.gz inside zip
mkdir -p "$TMP/tgz_inner"
eicar_string > "$TMP/tgz_inner/eicar.com"
make_tar_gz_from_dir "$TMP/tgz_inner" "$TMP/eicar_inner.tar.gz"

mkdir -p "$TMP/tgz_inside_zip/inner"
cp "$TMP/eicar_inner.tar.gz" "$TMP/tgz_inside_zip/inner/eicar.tar.gz"
make_zip_from_dir "$TMP/tgz_inside_zip" "$OUT_DIR/archives/malicious/eicar_tar_gz_inside_zip.zip"

# Suspicious archives
mkdir -p "$TMP/suspicious_shell"
cp "$OUT_DIR/suspicious/shell/curl_pipe_sh_echo_only.sh" "$TMP/suspicious_shell/"
make_zip_from_dir "$TMP/suspicious_shell" "$OUT_DIR/archives/suspicious/suspicious_shell_zip.zip"

mkdir -p "$TMP/suspicious_python"
cp "$OUT_DIR/suspicious/python/subprocess_echo.py" "$TMP/suspicious_python/"
make_tar_gz_from_dir "$TMP/suspicious_python" "$OUT_DIR/archives/suspicious/suspicious_python_tar_gz.tar.gz"

# Mixed archives
mkdir -p "$TMP/mixed/clean" "$TMP/mixed/suspicious" "$TMP/mixed/malicious"
printf 'clean file in mixed archive\n' > "$TMP/mixed/clean/readme.txt"
cp "$OUT_DIR/suspicious/shell/curl_pipe_sh_echo_only.sh" "$TMP/mixed/suspicious/"
eicar_string > "$TMP/mixed/malicious/eicar.com"

make_zip_from_dir "$TMP/mixed" "$OUT_DIR/archives/mixed/clean_suspicious_and_eicar.zip"
make_tar_gz_from_dir "$TMP/mixed" "$OUT_DIR/archives/mixed/clean_suspicious_and_eicar.tar.gz"

append_manifest "$OUT_DIR" "30-archives" <<'EOF'

[[group]]
id = "archive-clean"
root = "archives/clean"
mode = "aggregate"

[group.expect]
max_malicious = 0
max_likely_malicious = 0

[[group]]
id = "archive-malicious"
root = "archives/malicious"
mode = "per-file"

[group.expect]
verdict = "Malicious"
require_detection = true
require_inner_path = true

[[group]]
id = "archive-suspicious"
root = "archives/suspicious"
mode = "per-file"

[group.expect]
allow_verdicts = ["Clean", "Suspicious"]
max_verdict = "Suspicious"

[[group]]
id = "archive-mixed"
root = "archives/mixed"
mode = "per-file"

[group.expect]
verdict = "Malicious"
require_detection = true
require_inner_path = true

[[case]]
id = "eicar-zip-inside-tar-gz"
path = "archives/malicious/eicar_zip_inside_tar_gz.tar.gz"

[case.expect]
verdict = "Malicious"
inner_match_contains = "!/eicar.com"

[[case]]
id = "eicar-tar-gz-inside-zip"
path = "archives/malicious/eicar_tar_gz_inside_zip.zip"

[case.expect]
verdict = "Malicious"
inner_match_contains = "!/eicar.com"
EOF
