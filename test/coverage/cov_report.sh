#!/bin/bash
# Report libmerc coverage in 3 ways (but do not gate pass/fail):
#
#   1. Human-readable summary of absolute coverage ($GITHUB_STEP_SUMMARY)
#   2. Export percentages + baseline id for coverage-gate ($GITHUB_OUTPUT)
#   3. Differential coverage, when a distinct baseline exists:
#      a. Human-readable summary ($GITHUB_STEP_SUMMARY)
#      b. build/Coverage/coverage_report_diff/   differential HTML (genhtml)
#
# NOT produced here: build/Coverage/coverage_report/ (`make test-coverage` on HEAD)

set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(cd "$here/../.." && pwd)}

# Inputs
cur_info=build/Coverage/cur.libmerc.info     # always present
base_info=build/Coverage/base.libmerc.info   # absent on the na path
HEAD_SHA=${HEAD_SHA:-$(git rev-parse HEAD)}
BASE_REF=${BASE_REF:-dev}
BASE_SHA=${BASE_SHA-$(git merge-base "$HEAD_SHA" "$BASE_REF")}  # == HEAD_SHA on na

# Outputs
COV_TLA_OUT=${COV_TLA_OUT:-build/Coverage/cov-tla.json}
GITHUB_STEP_SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/stdout}
GITHUB_OUTPUT=${GITHUB_OUTPUT:-/dev/stdout}

# Computes precise line-coverage %: sum(LH)/sum(LF) from the .info tracefile.
# LH="lines hit" and LF="lines found".  Better than lcov's 1-decimal %-summary.
line_pct() { awk -F: '/^LH:/{h+=$2} /^LF:/{f+=$2} END{print f?100*h/f:0}' "$1"; }

# Absolute coverage, human-readable summary
CUR_PCT=$(line_pct "$cur_info")
{ echo "### libmerc coverage"; echo '```';
  lcov --summary "$cur_info" 2>&1 | grep -E '(lines|functions)\.\.'; echo '```';
} >> "$GITHUB_STEP_SUMMARY"

# Differential coverage, when possible
if [ "$BASE_SHA" = "$HEAD_SHA" ]; then
  { echo "### libmerc differential coverage"; echo;
    echo "**SKIPPED**: baseline is HEAD or no baseline to compare";
  } >> "$GITHUB_STEP_SUMMARY"
  BASE_PCT=""   # empty string explicitly signals na
else
  [ -f "$base_info" ] || { echo "missing $base_info (baseline expected)" >&2; exit 1; }
  git diff --src-prefix="$GITHUB_WORKSPACE/" --dst-prefix="$GITHUB_WORKSPACE/" \
    "$BASE_SHA..$HEAD_SHA" -- 'src/libmerc/*' > build/Coverage/patch.diff
  BASE_PCT=$(line_pct "$base_info")

  # Export so child cov_criteria.sh (invoked by genhtml) writes where we read.
  export COV_TLA_OUT
  tla=$COV_TLA_OUT
  rm -f "$tla"
  genhtml \
    --baseline-file "$base_info" \
    --diff-file build/Coverage/patch.diff \
    --criteria-script "$here/cov_criteria.sh" \
    --ignore-errors path,path,unused,unused,unmapped,unmapped,empty,empty \
    -o build/Coverage/coverage_report_diff \
    "$cur_info"

  [ -f "$tla" ] || echo '{}' > "$tla"   # genhtml may emit no criteria JSON
  python3 "$here/cov_diff_report.py" "$tla" \
    --cur-pct "$CUR_PCT" --base-pct "$BASE_PCT" \
    --base-sha "$BASE_SHA" --base-ref "$BASE_REF" >> "$GITHUB_STEP_SUMMARY"
fi

{ echo "cur_pct=$CUR_PCT"; echo "base_pct=$BASE_PCT";
  echo "base_sha=$BASE_SHA"; echo "base_ref=$BASE_REF";
} >> "$GITHUB_OUTPUT"
