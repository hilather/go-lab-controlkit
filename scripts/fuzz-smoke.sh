#!/usr/bin/env bash
# Fuzz smoke: runs every native Go fuzz target in the module for FUZZTIME
# (default 10s). CI runs this as the required "fuzz smoke" check.
set -euo pipefail

GO=${GO:-go}
FUZZTIME=${FUZZTIME:-10s}

cd "$(git rev-parse --show-toplevel)"

count=0
while IFS= read -r file; do
	dir=$(dirname "$file")
	while IFS= read -r name; do
		echo "fuzz smoke: ./$dir $name for $FUZZTIME"
		"$GO" test "./$dir" -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" -count=1
		count=$((count + 1))
	done < <(sed -nE 's/^func (Fuzz[A-Za-z0-9_]*)\([^)]*\*testing\.F\).*/\1/p' "$file")
done < <(git ls-files -- '*_test.go')

echo "fuzz smoke: $count target(s) run"
