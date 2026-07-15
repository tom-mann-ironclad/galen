#!/usr/bin/env bash

log() {
    printf '[corpus] %s\n' "$*"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

write_file() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path"
}

write_executable() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path"
    chmod +x "$path"
}

append_manifest() {
    local out_dir="$1"
    local name="$2"
    mkdir -p "$out_dir/.manifest.d"
    cat > "$out_dir/.manifest.d/$name.toml"
}

eicar_string() {
    printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
}

abs_path() {
    local path="$1"

    case "$path" in
        /*)
            printf '%s\n' "$path"
            ;;
        *)
            printf '%s/%s\n' "$PWD" "$path"
            ;;
    esac
}

make_zip_from_dir() {
    local source_dir="$1"
    local output_zip="$2"
    local output_zip_abs

    output_zip_abs="$(abs_path "$output_zip")"
    mkdir -p "$(dirname "$output_zip_abs")"

    (
        cd "$source_dir"
        zip -q -X -r "$output_zip_abs" .
    )
}

make_tar_from_dir() {
    local source_dir="$1"
    local output_tar="$2"
    local output_tar_abs

    output_tar_abs="$(abs_path "$output_tar")"
    mkdir -p "$(dirname "$output_tar_abs")"

    (
        cd "$source_dir"
        tar --sort=name \
            --owner=0 \
            --group=0 \
            --numeric-owner \
            --mtime='UTC 2024-01-01' \
            -cf "$output_tar_abs" .
    )
}

make_tar_gz_from_dir() {
    local source_dir="$1"
    local output_tgz="$2"
    local output_tgz_abs
    local tmp_tar

    output_tgz_abs="$(abs_path "$output_tgz")"
    mkdir -p "$(dirname "$output_tgz_abs")"

    tmp_tar="$(mktemp)"

    (
        cd "$source_dir"
        tar --sort=name \
            --owner=0 \
            --group=0 \
            --numeric-owner \
            --mtime='UTC 2024-01-01' \
            -cf "$tmp_tar" .
    )

    gzip -n -c "$tmp_tar" > "$output_tgz_abs"
    rm -f "$tmp_tar"
}
