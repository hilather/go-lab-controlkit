#!/usr/bin/env bash
# Fuzz smoke: runs every native Go fuzz target in the module for FUZZTIME
# execs (default 200000x). CI runs this as the required "fuzz smoke" check.
#
# A duration -fuzztime can fail a clean run with a bare
# "context deadline exceeded" (issue golang/go#75804, unfixed in go1.26.9;
# fix golang/go#79199). A count sets no deadline. Go back to a duration
# once the Go version CI pins carries that fix.
#
# The outer timeout is the per-target hang bound. go test's -timeout does
# not cover the fuzz phase. A single exec that blocks is already a crash:
# the fuzz worker panics after 10s. The outer timeout covers a coordinator,
# minimization, or process stall, and compile time. GOMAXPROCS/-parallel
# are untouched on purpose.
set -euo pipefail

GO=${GO:-go}
FUZZTIME=${FUZZTIME:-200000x}
FUZZMINIMIZETIME=${FUZZMINIMIZETIME:-5s}
FUZZTIMEOUT=${FUZZTIMEOUT:-5m}

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
	# go test's -timeout is kept but bounds nothing here: with -run '^$'
	# and -fuzz, the seeds and fuzzing both run after its alarm stops.
	# The outer timeout is the bound.
	rc=0
	timeout --kill-after=30s "$FUZZTIMEOUT" "$GO" test "./$dir" \
		-run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" \
		-fuzzminimizetime "$FUZZMINIMIZETIME" \
		-timeout "$FUZZTIMEOUT" -count=1 || rc=$?
	if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
		echo "fuzz smoke: ./$dir $name did not finish $FUZZTIME execs within $FUZZTIMEOUT (timed out or killed, rc=$rc)" >&2
		exit 1
	elif [ "$rc" -ne 0 ]; then
		exit "$rc"
	fi
	count=$((count + 1))
done <<< "$targets"

if [ "$count" -eq 0 ]; then
	echo "fuzz smoke: no fuzz targets" >&2
	exit 1
fi
echo "fuzz smoke: $count target(s) run"
