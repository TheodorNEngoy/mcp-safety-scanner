#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET_PATH="${INPUT_PATH:-.}"
FORMAT="${INPUT_FORMAT:-github}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
SARIF_OUTPUT="${INPUT_SARIF_OUTPUT:-mcp-safety-scan.sarif}"

cd "$ROOT"

if [[ "$FORMAT" == "sarif" ]]; then
  node "$ROOT/src/cli.js" "$TARGET_PATH" --format=sarif --fail-on="$FAIL_ON" > "$SARIF_OUTPUT"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "sarif_file=$SARIF_OUTPUT" >> "$GITHUB_OUTPUT"
  fi
else
  node "$ROOT/src/cli.js" "$TARGET_PATH" --format="$FORMAT" --fail-on="$FAIL_ON"
fi

