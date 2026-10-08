#!/usr/bin/env bash
# go.mod hygiene for go-lab-controlkit. CI runs this as the required
# "replace/go.work check". It fails when:
#   - go.mod has a replace directive;
#   - a go.work or go.work.sum file is committed anywhere in the tree;
#   - go.mod has a require entry (the kit uses only the standard library);
#   - go.mod has a toolchain line, or its go line is not "go 1.26";
#   - any go.mod other than ./go.mod is tracked or present (except under .git).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail=0
problem() {
	echo "check-gomod: $*" >&2
	fail=1
}

if grep -nE '^[[:space:]]*replace([[:space:]]|\(|$)' go.mod; then
	problem "go.mod must not contain a replace directive"
fi

work_files=$(git ls-files | grep -E '(^|/)go\.work(\.sum)?$' || true)
if [ -n "$work_files" ]; then
	echo "$work_files"
	problem "go.work and go.work.sum must not be committed"
fi

if grep -nE '^[[:space:]]*require([[:space:]]|\(|$)' go.mod; then
	problem "go.mod must not require any module (standard library only)"
fi

if grep -nE '^[[:space:]]*toolchain([[:space:]]|$)' go.mod; then
	problem "go.mod must not have a toolchain line"
fi

if ! grep -qxE 'go 1\.26' go.mod; then
	grep -nE '^[[:space:]]*go[[:space:]]' go.mod || true
	problem "go.mod must declare exactly \"go 1.26\""
fi

tracked=$(git ls-files | grep -E '(^|/)go\.mod$' | grep -vx 'go.mod' || true)
if [ -n "$tracked" ]; then
	echo "$tracked"
	problem "a go.mod other than ./go.mod is tracked"
fi

while IFS= read -r extra; do
	[ -n "$extra" ] || continue
	echo "$extra"
	problem "a go.mod other than ./go.mod is present: $extra"
done < <(find . -name go.mod -not -path './go.mod' -not -path './.git/*')

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "check-gomod: ok"
