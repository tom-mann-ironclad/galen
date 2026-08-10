#!/usr/bin/env bash

set -euo pipefail

BASE_REF="${1:-origin/main}"
SCHEMA_PATH="schemas/scan-report-v1.schema.json"

if ! git cat-file -e "${BASE_REF}:${SCHEMA_PATH}" 2>/dev/null; then
    echo "No ${SCHEMA_PATH} exists at ${BASE_REF}; there is no previous JSON contract to check."
    exit 0
fi

COMPAT_DIR="$(mktemp -d)"
trap 'rm -rf -- "$COMPAT_DIR"' EXIT
COMPAT_SCHEMA="${COMPAT_DIR}/scan-report-v1.schema.json"
git show "${BASE_REF}:${SCHEMA_PATH}" > "$COMPAT_SCHEMA"

echo "Validating current golden JSON output against ${SCHEMA_PATH} from ${BASE_REF}..."
GALEN_JSON_SCHEMA_PATH="$COMPAT_SCHEMA" \
    cargo test --locked --test json_schema golden_json_reports_match_the_v1_schema
