#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Fails if any non-merge commit in BASE..HEAD lacks a "Signed-off-by:" trailer
# matching its author (Developer Certificate of Origin, https://developercertificate.org).
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base-sha> <head-sha>" >&2
  exit 2
fi

base=$1
head=$2
failed=0

while read -r sha; do
  [[ -z "$sha" ]] && continue
  author="$(git log -1 --format='%an <%ae>' "$sha")"
  if git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -qxF "$author"; then
    echo "ok      $(git log -1 --format='%h %s' "$sha")"
  else
    echo "MISSING $(git log -1 --format='%h %s' "$sha") — expected 'Signed-off-by: $author'"
    failed=1
  fi
done < <(git rev-list --no-merges "$base..$head")

if [[ $failed -ne 0 ]]; then
  cat >&2 <<'MSG'

Some commits are missing a DCO sign-off. Fix with:
  git rebase --signoff <base-branch> && git push --force-with-lease
MSG
  exit 1
fi
