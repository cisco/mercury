#!/bin/bash
# Slice a libmerc-only lcov tracefile out of a Coverage build's filtered.info.
#
# Usage: cov_extract.sh [--rewrite OLD NEW] <filtered.info> <out.info>
#
# Use --rewrite OLD NEW to fix path prefixes for genhtml's --diff-file when
# baseline and HEAD differ. For example, --rewrite /ws/base/ /ws/ turns
#   SF:/ws/base/src/libmerc/tls.c  ->  SF:/ws/src/libmerc/tls.c

set -euo pipefail

sub=()
if [ "${1:-}" = "--rewrite" ]; then
  old_re=$(printf '%s' "$2" | sed 's/[^A-Za-z0-9]/\\&/g') # escape regex metachars
  new_re=$(printf '%s' "$3" | sed 's/[/\\$@]/\\&/g') # and perl-replacement specials
  sub=(--substitute "s/^${old_re}/${new_re}/")
  shift 3
fi
in=${1:?usage: cov_extract.sh [--rewrite OLD NEW] <filtered.info> <out.info>}
out=${2:?usage: cov_extract.sh [--rewrite OLD NEW] <filtered.info> <out.info>}

mkdir -p "$(dirname "$out")"
lcov --extract "$in" '*/src/libmerc/*' --ignore-errors unused,unused,inconsistent,inconsistent \
  "${sub[@]}" -o "$out"
lcov --ignore-errors inconsistent,inconsistent --summary "$out" 2>&1   # log some diagnostic output
