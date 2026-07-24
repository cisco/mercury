#!/bin/bash
set -euo pipefail

lcov --extract build/Coverage/coverage_data/filtered.info '*/src/libmerc/*' \
  --ignore-errors unused,unused -o cur.libmerc.info
summary=$(lcov --summary cur.libmerc.info 2>&1)
printf '%s\n' "$summary"

{
  echo "### libmerc coverage"
  echo '```'
  printf '%s\n' "$summary" | grep -E '(lines|functions)\.\.'
  echo '```'
} >> "$GITHUB_STEP_SUMMARY"
