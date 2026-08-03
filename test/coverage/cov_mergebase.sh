#!/bin/bash
# Resolve the merge-base (common ancestor) of HEAD against the baseline branch.
# Baseline branch is the PR target $GITHUB_BASE_REF, or dev if not a PR.
#
# Outputs:
# - GITHUB_OUTPUT: head_sha, base_sha
# - GITHUB_ENV: HEAD_SHA, BASE_SHA, BASE_REF

set -euo pipefail

base_ref=${GITHUB_BASE_REF:-dev}     # PR target, else dev (push/WIP)
head_sha=$(git rev-parse HEAD)
base_sha=$(git merge-base "origin/$base_ref" HEAD)

{ echo "head_sha=$head_sha"; echo "base_sha=$base_sha"; } >> "${GITHUB_OUTPUT:-/dev/stdout}"
{ echo "HEAD_SHA=$head_sha"; echo "BASE_SHA=$base_sha"; echo "BASE_REF=$base_ref"; } >> "${GITHUB_ENV:-/dev/stdout}"

if [ "$base_sha" != "$head_sha" ]; then
  echo "target branch: $base_ref | merge-base: $(git rev-parse --short "$base_sha")"
else
  echo "target branch: $base_ref | merge-base == HEAD (na/skipped)"
fi
