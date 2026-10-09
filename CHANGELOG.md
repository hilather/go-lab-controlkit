# Changelog

All notable changes are recorded here. This file is curated; it is not a raw
commit log.

## Unreleased

### Added

- CI runs on `v*` tag pushes as well as on pull requests and `main`. The
  concurrency group uses `github.ref`, so a tag run does not cancel a `main`
  run.
- Release workflow (`.github/workflows/release.yml`) and
  `scripts/release-gate`. The gate matches the tag push's own CI run:
  workflow `ci.yml`, event `push`, `headSha` the peeled commit, `headBranch`
  the tag name, newest run only. Required jobs are the CI job names. The
  tagged commit must contain `docs/releases/<tag>.md` (a Markdown heading
  that includes the tag; a fenced copy does not count) and a `## <tag>` line
  in `CHANGELOG.md`. There is no image and no GitHub Release. `apidiff`
  stays a required check from `v1.0.0`, not in this workflow.
- Repository setup: Apache-2.0 license, README with the consumer pin matrix
  and option ledger, SECURITY.md, CODEOWNERS, and CI (`go vet`,
  `go test -race ./...`, fuzz smoke, `govulncheck`, and a `replace`/`go.work`
  check) on Go 1.26.9.
- `kerr`: error kinds a facade maps onto its own wire code.
- `authn`: token loading, verifier, stdio pin, secret wiping, and reload.
- `scope`: principal table and capability gate.
- `session`: session table, CSRF compare, cookie helpers, and revocation wake.
- `origin`: Origin allow-list policy.
- `audit`: bounded ring, fanout, redaction, and the denial flood guard.
- `idem`: bounded LRU and FIFO idempotency cache.
- `ratelimit`: capped per-key buckets and a per-call global bucket.
- `mcpstrict`: duplicate JSON keys, typed subtrees, and open fields.
- `kittest`: conformance suites that take injected drivers.
- Fuzz smoke parses Go source for `Fuzz` functions, including a signature
  split across lines, and fails if `FuzzAuthorization`, `FuzzOrigin`, or
  `FuzzCheck` is missing.
- `check-gomod` fails when any `go.mod` other than the root `./go.mod` is
  tracked or present.
