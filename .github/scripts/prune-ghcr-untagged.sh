#!/usr/bin/env bash
#
# prune-ghcr-untagged.sh — delete untagged versions of a GHCR container
# package, while preserving any digest referenced by a tagged manifest list
# (e.g. per-platform child manifests of a multi-arch image, or buildx
# attestation manifests).
#
# Usage:
#   prune-ghcr-untagged.sh <package-name>
#
# Environment:
#   GH_TOKEN                 GitHub token with packages:write (required)
#   GITHUB_REPOSITORY_OWNER  Org/user that owns the package. Set automatically
#                            by GitHub Actions as a default environment
#                            variable; must be provided when running locally.
#   MIN_AGE_DAYS             Minimum age before an untagged version is
#                            eligible for deletion. Default: 7
#   MAX_DELETES              Maximum number of versions to delete in one run.
#                            Default: 50
#   DRY_RUN                  If "1"/"true", log what would be deleted without
#                            actually deleting. Default: 0
#   RETRY_MAX                Retries per DELETE on 429/5xx (e.g. 504 from the
#                            GHCR gateway). Default: 3
#   RETRY_BASE_DELAY         Base seconds for exponential backoff between
#                            retries (delay = base * 2^attempt). Default: 2
#
# Requires: gh, jq, docker (with prior `docker login ghcr.io`), bash 4+.

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
  echo "error: bash >= 4 required (found ${BASH_VERSION}); on macOS install via Homebrew" >&2
  exit 1
fi

PKG="${1:?package name required}"
OWNER="${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER must be set}"
MIN_AGE_DAYS="${MIN_AGE_DAYS:-7}"
MAX_DELETES="${MAX_DELETES:-50}"
DRY_RUN="${DRY_RUN:-0}"

case "${DRY_RUN,,}" in
  1|true|yes) DRY_RUN=1 ;;
  *)          DRY_RUN=0 ;;
esac

echo "== Cleanup ghcr.io/${OWNER}/${PKG} =="
echo "min_age_days=${MIN_AGE_DAYS} max_deletes=${MAX_DELETES} dry_run=${DRY_RUN}"

###############################################################################
# 1. Fetch all versions (paginated). The org and user endpoints differ;
#    try org first, fall back to user, and remember which one worked so
#    we can reuse it for DELETE calls.
###############################################################################
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
versions_json="${tmp}/versions.json"

# `jq -c '.[]'` emits one compact (single-line) JSON object per version,
# which the line-based counts and read loops below depend on.
OWNER_KIND=orgs
if ! gh api --paginate \
      "/orgs/${OWNER}/packages/container/${PKG}/versions" 2>/dev/null \
      | jq -c '.[]' >"${versions_json}"; then
  OWNER_KIND=users
  gh api --paginate \
      "/users/${OWNER}/packages/container/${PKG}/versions" \
      | jq -c '.[]' >"${versions_json}"
fi

total=$(wc -l <"${versions_json}" | tr -d ' ')
tagged=$(jq -s '[.[] | select(.metadata.container.tags | length > 0)] | length' \
            "${versions_json}")
untagged=$(( total - tagged ))
echo "Fetched ${total} versions (${tagged} tagged, ${untagged} untagged)"


###############################################################################
# 2. Build the protected-digest set:
#      - every tagged version's own digest, plus
#      - every child manifest referenced by a tagged manifest list.
#    `name` on a container package version is the manifest digest
#    (e.g. "sha256:abc...").
###############################################################################
protected="${tmp}/protected"

jq -r 'select(.metadata.container.tags | length > 0) | .name' \
    "${versions_json}" >"${protected}"

while read -r digest; do
  [[ -z "${digest}" ]] && continue
  # Fail-closed: a manifest list whose children we can't enumerate must not
  # let those children become deletion candidates.
  if ! children="$(docker manifest inspect \
                     "ghcr.io/${OWNER}/${PKG}@${digest}" \
                   | jq -r '.manifests[]?.digest // empty')"; then
    echo "error: failed to inspect ${digest}; aborting to avoid orphaning children" >&2
    exit 1
  fi
  if [[ -n "${children}" ]]; then
    printf '%s\n' "${children}" >>"${protected}"
  fi
done < <(jq -r 'select(.metadata.container.tags | length > 0) | .name' \
              "${versions_json}")

sort -u -o "${protected}" "${protected}"
protected_count=$(wc -l <"${protected}" | tr -d ' ')
echo "Protected digests: ${protected_count}"

###############################################################################
# 3. Compute deletion candidates: untagged AND not protected AND old enough.
###############################################################################
cutoff="$(date -u -d "${MIN_AGE_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ \
          2>/dev/null \
        || date -u -v"-${MIN_AGE_DAYS}d" +%Y-%m-%dT%H:%M:%SZ)"

candidates="${tmp}/candidates"
filtered="${tmp}/filtered"

# Build the candidate list: "<id> <digest> <updated_at>" per line, oldest
# first. The format is what the delete loop below reads (and prints in its
# per-item log lines). Anti-join on column 2 (digest) so we match the
# digest field exactly, not as a substring; FILENAME guards against an empty
# `protected` file (no tagged versions) being mistaken for the candidates.
jq -r --arg cutoff "${cutoff}" '
    select(.metadata.container.tags | length == 0)
    | select(.updated_at < $cutoff)
    | "\(.id) \(.name) \(.updated_at)"
  ' "${versions_json}" \
  | sort -k3,3 >"${filtered}"
awk -v pf="${protected}" '
    FILENAME == pf { protected[$0] = 1; next }
    !protected[$2]
  ' "${protected}" "${filtered}" >"${candidates}"

candidate_count=$(wc -l <"${candidates}" | tr -d ' ')
echo "Deletion candidates (untagged, not protected, >${MIN_AGE_DAYS}d old):" \
     "${candidate_count}"

if (( candidate_count > MAX_DELETES )); then
  echo "Capped to MAX_DELETES=${MAX_DELETES}"
  head -n "${MAX_DELETES}" "${candidates}" >"${candidates}.capped"
  mv "${candidates}.capped" "${candidates}"
fi

to_delete=$(wc -l <"${candidates}" | tr -d ' ')
if (( to_delete == 0 )); then
  echo "Nothing to delete."
  exit 0
fi

###############################################################################
# 4. Delete (or pretend to).
###############################################################################
RETRY_MAX="${RETRY_MAX:-3}"
RETRY_BASE_DELAY="${RETRY_BASE_DELAY:-2}"

# delete_version <id> -> echoes final HTTP status. Retries 429/5xx with
# exponential backoff; GHCR's gateway sometimes returns 504 even when the
# delete succeeded, so the retry's 404 is treated as success by the caller.
delete_version() {
  local id="$1"
  local resp="${tmp}/resp"
  local attempt=0 status delay
  while :; do
    gh api -X DELETE --include \
        "/${OWNER_KIND}/${OWNER}/packages/container/${PKG}/versions/${id}" \
        >"${resp}" || true
    status=$(awk 'NR==1 {print $2; exit}' "${resp}")
    case "${status}" in
      429|5*)
        if (( attempt >= RETRY_MAX )); then
          echo "${status}"
          return 0
        fi
        delay=$(( RETRY_BASE_DELAY * (1 << attempt) ))
        echo "  retry id=${id} status=${status} attempt=$((attempt+1))/${RETRY_MAX} sleep=${delay}s" >&2
        sleep "${delay}"
        attempt=$(( attempt + 1 )) ;;
      *)
        echo "${status}"
        return 0 ;;
    esac
  done
}

if (( DRY_RUN == 1 )); then
  echo "[DRY] Would delete ${to_delete} versions..."
else
  echo "Deleting ${to_delete} versions..."
fi
deleted=0
errors=0
while read -r id digest updated_at; do
  if (( DRY_RUN == 1 )); then
    echo "[DRY] would delete id=${id} digest=${digest} updated=${updated_at}"
    deleted=$(( deleted + 1 ))
    continue
  fi
  http_status="$(delete_version "${id}")"
  case "${http_status}" in
    2*|404)
      # 404: concurrent deletion, or a retry whose predecessor succeeded server-side.
      echo "[del] id=${id} digest=${digest} updated=${updated_at} status=${http_status}"
      deleted=$(( deleted + 1 )) ;;
    *)
      echo "[err] id=${id} digest=${digest} status=${http_status}" >&2
      errors=$(( errors + 1 )) ;;
  esac
done <"${candidates}"

if (( DRY_RUN == 1 )); then
  echo "[DRY] ${deleted}/${to_delete} would be deleted"
else
  echo "[OK] ${deleted}/${to_delete} deleted, ${errors} errors"
fi
exit $(( errors > 0 ? 1 : 0 ))
