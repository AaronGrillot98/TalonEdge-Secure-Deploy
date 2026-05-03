#!/usr/bin/env bash
# Re-resolve every "uses: <owner>/<repo>@<tag>" reference in .github/workflows/
# to the corresponding commit SHA. Idempotent — already-pinned SHAs are skipped.
#
# Requires: gh, sed, grep. Run from the repo root.
#
# Usage:
#   ./scripts/pin-actions.sh           # update workflows in place
#   ./scripts/pin-actions.sh --check   # exit non-zero if any tag is unpinned
set -euo pipefail

mode="${1:-update}"
exit_code=0

mapfile -t refs < <(
  grep -rEho 'uses:[[:space:]]+[A-Za-z0-9_./-]+@[A-Za-z0-9_./-]+' .github/workflows \
  | sed -E 's/^uses:[[:space:]]+//' \
  | sort -u
)

for ref in "${refs[@]}"; do
  action="${ref%@*}"
  ver="${ref##*@}"
  # Already a 40-char hex SHA? Skip.
  if [[ "$ver" =~ ^[0-9a-f]{40}$ ]]; then
    continue
  fi

  sha=$(gh api "repos/${action}/git/refs/tags/${ver}" --jq '.object.sha' 2>/dev/null \
        || gh api "repos/${action}/commits/${ver}" --jq '.sha' 2>/dev/null \
        || true)

  if [[ -z "$sha" ]]; then
    echo "WARN: could not resolve ${action}@${ver}" >&2
    exit_code=1
    continue
  fi

  if [[ "$mode" == "--check" ]]; then
    echo "UNPINNED: ${action}@${ver} -> ${sha}"
    exit_code=1
  else
    echo "Pinning ${action}@${ver} -> ${sha} # ${ver}"
    # Use a sentinel | as the sed delimiter since refs can contain /.
    grep -rl "uses: ${action}@${ver}" .github/workflows | while read -r f; do
      sed -i.bak "s|uses: ${action}@${ver}\$|uses: ${action}@${sha} # ${ver}|g" "$f"
      rm -f "${f}.bak"
    done
  fi
done

exit $exit_code
