#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Enforces the per-directory license split on Go files: pkg/ is Apache-2.0,
# everything else AGPL-3.0-only. (golangci-lint's goheader only checks that a
# valid SPDX header is present, not which one.)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
failed=0

while IFS= read -r -d '' file; do
  case "$file" in
    internal/proto/*) continue ;; # generated
    pkg/*) want="Apache-2.0" ;;
    *) want="AGPL-3.0-only" ;;
  esac
  if [[ "$(head -n1 "$file")" != "// SPDX-License-Identifier: $want" ]]; then
    echo "$file: first line must be '// SPDX-License-Identifier: $want'" >&2
    failed=1
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- '*.go')

exit "$failed"
