#!/usr/bin/env bash
set -euo pipefail

# Deletes GitHub Actions caches that no job can usefully restore any more:
#   - caches saved under a pull request that is no longer open, since only that
#     pull request could restore them;
#   - on each remaining ref, every cache but the newest of its scope. The scope
#     is the key before its first 64-hex file hash (or trailing commit SHA):
#     Go build caches end in the commit SHA, so each push leaves the previous
#     snapshot behind, and a changed build script or go.sum changes the hash so
#     older entries never match restore-keys again. Restores pick the newest.
# Set DRY_RUN=1 to print what would be deleted.
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set, e.g. owner/name}"

caches=$(gh api --paginate "repos/$repo/actions/caches?per_page=100" --jq '.actions_caches[]' | jq -s .)
open_prs=$(gh pr list --repo "$repo" --state open --limit 1000 --json number --jq '[.[].number | tostring]')

# One line per cache to delete: id, size in bytes, reason, ref, key.
plan=$(jq -r --argjson open "$open_prs" '
  def pr: (.ref | capture("^refs/pull/(?<n>[0-9]+)/") | .n) // null;
  (map(select(pr != null and (pr as $n | $open | index($n) | not)))
    | map(. + {reason: "closed-pr"})) as $closed
  | ($closed | map(.id)) as $closed_ids
  | (map(select(.id as $id | $closed_ids | index($id) | not))
    | group_by([.ref, (.key | sub("-[0-9a-f]{64}(-.*)?$"; "") | sub("-[0-9a-f]{40}$"; ""))])
    | map(sort_by(.created_at) | .[:-1][] | . + {reason: "superseded"})) as $old
  | ($closed + $old)[]
  | [.id, .size_in_bytes, .reason, .ref, .key] | @tsv
' <<< "$caches")

if [[ -z "$plan" ]]; then
  echo "No caches to delete."
  exit 0
fi

total=0
count=0
while IFS=$'\t' read -r id size reason ref key; do
  total=$((total + size))
  count=$((count + 1))
  printf '%-10s %8d MiB  %s  %s\n' "$reason" $((size / 1048576)) "$ref" "$key"
  if [[ "${DRY_RUN:-}" != 1 ]]; then
    # A concurrent run or GitHub's own eviction may already have removed it.
    gh api --method DELETE "repos/$repo/actions/caches/$id" --silent || true
  fi
done <<< "$plan"
verb=Deleted
if [[ "${DRY_RUN:-}" == 1 ]]; then verb="Would delete"; fi
echo "$verb $count caches, $((total / 1048576)) MiB."
