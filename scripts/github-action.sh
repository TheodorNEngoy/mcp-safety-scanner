#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET_PATH="${INPUT_PATH:-.}"
BASELINE="${INPUT_BASELINE:-}"
IGNORE_DIRS_RAW="${INPUT_IGNORE_DIRS:-}"
FILES_FROM_RAW="${INPUT_FILES_FROM:-}"
INCLUDE_TESTS_RAW="${INPUT_INCLUDE_TESTS:-false}"
FORMAT="${INPUT_FORMAT:-github}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
SARIF_OUTPUT="${INPUT_SARIF_OUTPUT:-mcp-safety-scan.sarif}"

# Interpret relative paths as relative to the checked-out repository, not the action repo.
WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
if [[ "${TARGET_PATH}" != /* ]]; then
  TARGET_PATH="${WORKSPACE}/${TARGET_PATH}"
fi
if [[ "${SARIF_OUTPUT}" != /* ]]; then
  SARIF_OUTPUT="${WORKSPACE}/${SARIF_OUTPUT}"
fi

if [[ -n "${BASELINE}" && "${BASELINE}" != /* ]]; then
  BASELINE="${WORKSPACE}/${BASELINE}"
fi

FILES_FROM=""
if [[ -n "${FILES_FROM_RAW}" ]]; then
  FILES_FROM="${FILES_FROM_RAW}"
  if [[ "${FILES_FROM}" != /* ]]; then
    FILES_FROM="${WORKSPACE}/${FILES_FROM}"
  fi
fi

cd "$ROOT"

IGNORE_ARGS=()
if [[ -n "${IGNORE_DIRS_RAW}" ]]; then
  IFS=',' read -ra _IGNORE_PARTS <<< "${IGNORE_DIRS_RAW}"
  for p in "${_IGNORE_PARTS[@]}"; do
    p="$(echo "$p" | tr -d '\r' | xargs || true)"
    if [[ -n "${p}" ]]; then
      IGNORE_ARGS+=("--ignore-dir=${p}")
    fi
  done
fi

FILES_FROM_ARGS=()
if [[ -n "${FILES_FROM}" ]]; then
  FILES_FROM_ARGS+=("--files-from=${FILES_FROM}")
fi

INCLUDE_TESTS_ARGS=()
if [[ "${INCLUDE_TESTS_RAW}" == "true" || "${INCLUDE_TESTS_RAW}" == "True" || "${INCLUDE_TESTS_RAW}" == "TRUE" ]]; then
  INCLUDE_TESTS_ARGS+=("--include-tests")
fi

if [[ "$FORMAT" == "sarif" ]]; then
  if [[ -n "${BASELINE}" ]]; then
    node "$ROOT/src/cli.js" "$TARGET_PATH" --format=sarif --fail-on="$FAIL_ON" --baseline="$BASELINE" "${IGNORE_ARGS[@]}" "${FILES_FROM_ARGS[@]}" "${INCLUDE_TESTS_ARGS[@]}" > "$SARIF_OUTPUT"
  else
    node "$ROOT/src/cli.js" "$TARGET_PATH" --format=sarif --fail-on="$FAIL_ON" "${IGNORE_ARGS[@]}" "${FILES_FROM_ARGS[@]}" "${INCLUDE_TESTS_ARGS[@]}" > "$SARIF_OUTPUT"
  fi
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "sarif_file=$SARIF_OUTPUT" >> "$GITHUB_OUTPUT"
  fi
else
  if [[ -n "${BASELINE}" ]]; then
    node "$ROOT/src/cli.js" "$TARGET_PATH" --format="$FORMAT" --fail-on="$FAIL_ON" --baseline="$BASELINE" "${IGNORE_ARGS[@]}" "${FILES_FROM_ARGS[@]}" "${INCLUDE_TESTS_ARGS[@]}"
  else
    node "$ROOT/src/cli.js" "$TARGET_PATH" --format="$FORMAT" --fail-on="$FAIL_ON" "${IGNORE_ARGS[@]}" "${FILES_FROM_ARGS[@]}" "${INCLUDE_TESTS_ARGS[@]}"
  fi
fi
