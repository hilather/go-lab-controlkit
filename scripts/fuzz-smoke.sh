#!/usr/bin/env bash
# Fuzz smoke: runs every native Go fuzz target in the module for FUZZTIME
# (default 10s). CI runs this as the required "fuzz smoke" check.
set -euo pipefail

GO=${GO:-go}
FUZZTIME=${FUZZTIME:-10s}

cd "$(git rev-parse --show-toplevel)"

# Required names: FuzzAuthorization, FuzzOrigin, FuzzCheck.
# fuzzlist parses Go source, so a signature split across lines still counts,
# and a missing required name fails the run. Zero targets also fail.
if ! targets=$("$GO" run ./scripts/fuzzlist); then
	exit 1
fi
if [ -z "$targets" ]; then
	echo "fuzz smoke: no fuzz targets" >&2
	exit 1
fi

count=0
while IFS=$'\t' read -r dir name; do
	[ -n "$name" ] || continue
	echo "fuzz smoke: ./$dir $name for $FUZZTIME"
	"$GO" test "./$dir" -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" -count=1
	count=$((count + 1))
done <<< "$targets"

if [ "$count" -eq 0 ]; then
	echo "fuzz smoke: no fuzz targets" >&2
	exit 1
fi
echo "fuzz smoke: $count target(s) run"
