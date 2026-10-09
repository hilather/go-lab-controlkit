# go-lab-controlkit

Shared management-plane primitives for the go-lab repos: management token
loading and verification, scope and capability checks, sessions, origin and
CSRF checks, audit, idempotency and rate limiting.

Six go-lab repos each carry their own copy of this code today and patch it
separately. controlkit owns it once, so a fix lands in one place and reaches
every repo through a version bump. Each consumer keeps thin facades in its own
`internal/auth`, `internal/audit` and related packages, and keeps its own
request flow (authentication order, scope checks, CSRF) and wire codes.

Module path: `github.com/hilather/go-lab-controlkit`

## Status

The v0.1.0 packages have landed. Nothing is tagged. The release workflow
gates a `v*` tag and does not publish an image, a binary, or a GitHub
Release. The release-prep pull request adds `docs/releases/v0.1.0.md` and
folds the changelog before Helm tags `v0.1.0`. Muse never tags.

## Packages

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

## Rules

- Standard library only. `go.mod` has no `require` entries, so controlkit adds
  no transitive requirements and cannot raise a consumer's dependency versions.
- `go.mod` declares `go 1.26` with no `toolchain` line.
- No package imports a consumer package. Each consumer maps controlkit errors
  to its own error codes and converts its own spec types into controlkit
  config.
- No constructor invents a default. A zero value in a config struct is a
  constructor error, unless the field's comment names what zero means.
- `main` never carries a `replace` directive or a committed `go.work`.

## Consumer pin matrix

The controlkit tag each consumer pins on its `main`. Consumers pin an exact
tag, never a pseudo-version. The release-prep PR updates this table.

| Consumer | controlkit tag on `main` | PR-1 (adopt, no behavior change) | PR-2 (deltas) | Last bump PR |
|---|---|---|---|---|
| [go-lab-ntp](https://github.com/hilather/go-lab-ntp) | none | not started | not started | none |
| [go-lab-netconf](https://github.com/hilather/go-lab-netconf) | none | not started | not started | none |
| [go-lab-snmp](https://github.com/hilather/go-lab-snmp) | none | not started | not started | none |
| [go-lab-maildev](https://github.com/hilather/go-lab-maildev) | none | not started | not started | none |
| [go-lab-syslog](https://github.com/hilather/go-lab-syslog) | none | not started | not started | none |
| [go-lab-dns](https://github.com/hilather/go-lab-dns) | none | not started | not started | none |

## Option ledger

Each per-repo option is classified as product semantics (kept) or accidental
divergence (converged, with a milestone). The options marked `*` must be
resolved or explicitly owned before `v1.0.0`. Package and option names are
the v0.1.0 layout (`capgate` is `scope.Gate`). Milestones (M), deltas
(C, P) and decisions (Q) refer to that plan.

| Option | Values today | Class | Resolution and milestone |
|---|---|---|---|
| `scope.Gate.Unmapped` = Allow `*` | dns, ntp, netconf, maildev, syslog (snmp: Forbid) | accidental, security-relevant | Resolved: each PR-2's P4 commit sets Forbid. The option is deleted before v1.0.0 (M7). |
| `scope.Gate.FirstCapOnly` `*` | all six (`caps[0]`) | accidental, security-relevant | Resolved: P4 checks every capability. The option is deleted at M7. |
| `ratelimit` `MaxKeys` 0 `*` | uncapped in dns, ntp REST, snmp, maildev | accidental, security-relevant | Resolved: there is no such value in the kit (constructor error). P6 moves the uncapped limiters in PR-2. |
| nil-verifier administrator `*` | maildev (REST, MCP, compat), dns | accidental, security-relevant | Resolved: the kit never offers it, and P5 deletes the facade copies in PR-2. |
| `authn.FileOpts.Harden` = false `*` | all six, in PR-1 | transitional: keeps PR-1 zero-change (3.2) | Resolved: each consumer's C3a commit sets true, and the option is removed before v1.0.0 (M7). |
| `authn.MinSecretBytes` 0 `*` | dns | accidental, security-relevant | Owned by dns before v1.0.0: the P8 warning plus a kittest pin. Token floor enforcement: deferred, warn-only in B (Q8). |
| `authn.Duplicates` = FirstMatchWins `*` | dns | accidental | Owned by dns before v1.0.0: a kittest pin and a ledger entry. Converging would reject dns configs that boot today, which needs its own decision. |
| `authn.Accept` (zero-token predicate) | ntp, netconf: refuse; snmp, maildev, syslog: none | product today | Kept in B. P9 (Q11, an open decision) is the post-migration convergence. |
| `FileOpts.Line`, `Resolve`, `SkipMissing`; `DNSBundle`; dns identity defaults | per repo | product (documented file formats and path rules) | Kept. |
| `authn.LocalhostIsLoopback` | ntp, maildev: true; dns: false | accidental | Owned per repo. It only matters in dev-loopback mode. Revisit after M7. |
| netconf relative-ref resolution: `LoadFile`'s validator joins the bootstrap directory, while the compile and the loader use the path as given (3.9, Resolvers) | netconf | accidental | Kept in B (v5.3 item 5): Prepare records both paths, and each renderer keeps its verdict. Converging changes behavior and needs its own decision after M7. |
| `scope.Table` fields; dns `Evaluator`; `CapAuthorizer`/`ToolExtra` | per repo | product (role models; dns change policy) | Kept. |
| `session.Config` (TTL, idle, cap, `AtCap`, `IDShape`, `CSRFCompare`), cookie and header names | five vs dns | product (dns console design, `docs/08`) | Kept. |
| `origin.Policy`: `Match` exact (dns), `HostParse` `DNSParse` (dns pairs it with `ExactCaseSensitive`), `ListUnionsLoopback` false (syslog), `LocalhostFold` | per repo | accidental | Owned per repo in B. Converge after M7 in its own plan. |
| `origin.Policy.Sentinels` | maildev (ADR 0008) | product | Kept. |
| kerr mapping (origin code; `unauthenticated` vs `unauthorized`) | per repo | product (wire codes) | Kept. |
| `ratelimit.Ctor` zero/negative/burst meanings | per repo | accidental, kept for config compatibility | Owned per repo. Converge after M7. |
| `ratelimit.Live` (`SetRate`) | ntp | product | Kept. |
| `idem.Eviction` FIFOByInsert | syslog | accidental | Owned by syslog. Converge after M7. |
| `audit.Redactor` key sets | per repo | product now | Unify after M7 (section 11). |
| `audit` `DeniedShare` 0.5, `DeniedGuard` 1/s burst 10 | all six (C2) | committed | Kept. |
| `audit.Redactor` modes | `PEM` true: ntp, snmp, netconf; false: dns, maildev. `BearerPrefix` true: dns, maildev; false: ntp, snmp, netconf. `ColonLines`: dns only. `Path` and `Value`: ntp, snmp, netconf, maildev, dns. syslog has no audit redactor (zero `Redactor`) | accidental | Owned per repo. Unify after M7 with the key sets (section 11). |
| `scope.Gate.UnknownResource` | ntp, snmp, netconf, maildev, syslog: `ResourceMissNotFound`; dns: zero (follow `Unmapped`) | accidental, security-relevant | Owned per repo. Converge after M7. A looser value admits an unknown resource. |
| `scope.Table.AllowUnknownRoleExplicit` | dns: true; ntp, snmp, netconf, maildev, syslog: false | accidental, security-relevant | Owned per repo. Converge after M7. A looser value keeps an unknown role when explicit scopes are set. |
| `audit.RingOptions` `NewID` / `GetID` | `aud-<seq>`: dns, ntp, snmp, netconf, maildev. syslog: a caller-supplied id, otherwise a ULID-like id | accidental | Owned per repo. Converge after M7. |
| `audit.RingOptions` `DefaultList` / `MaxList` | 100/100: dns, ntp, snmp, netconf, maildev. syslog: 0/0 (uncapped list) | accidental | Owned per repo. Converge after M7. |
| stdio unauthenticated wire code (`kittest.StdioRotationDriver.Code`) | `unauthenticated`: ntp, snmp, maildev, dns; `unauthorized`: netconf, syslog | product (wire codes) | Kept. |
| backward clock | `ratelimit.Keyed` always refills (ntp, snmp management, maildev). dns's limiter, and the query limiters in dns, ntp, and snmp's data plane, refill only when elapsed > 0. `ratelimit.Global` skips a negative elapsed and still clamps and updates last; syslog's global bucket always adds elapsed*rps. Production uses monotonic `time.Now`, so there is no production difference | recorded only | No option. The difference shows only with a non-monotonic injected clock. |
| bad-credential text | kit and dns bad token: `invalid token` (dns missing credential: `authentication required`). ntp, snmp, netconf, maildev, and syslog bad token: `authentication required` | product (facade-mapped text) | Each facade maps the text. Each consumer's wrapper message tests cover the bad-token case (plan 3.1), in M1 and each later migration. |
| `authn.FileOpts.TrimRef` | snmp, dns: true; ntp, netconf, maildev, syslog: false (the ref is read as written) | accidental, security-relevant | Owned per repo. Converge after M7. A looser value admits a padded ref. |
| `authn.Config.RejectBlankTokens` | dns: true (a whitespace-only token is `empty token`); ntp, snmp, netconf, maildev, syslog: false | accidental, security-relevant | Owned per repo. Converge after M7. A looser value admits a whitespace-only token. |
| `origin.Policy.ZonedLoopback` | dns: true (`netip` accepts zones); ntp, snmp, netconf, maildev, syslog: false (`net.ParseIP` rejects zones) | accidental, security-relevant | Owned per repo. Converge after M7. A looser value admits a zoned loopback origin. |

## Versioning and releases

- SemVer tags `vMAJOR.MINOR.PATCH`, starting at `v0.1.0`. A pre-release is
  `vMAJOR.MINOR.PATCH-PRE` (for example `v0.1.0-rc.1`). The release workflow
  accepts only tags that match
  `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`.
- In v0 a minor release may break the API. At most one API-breaking minor is in
  flight at a time: every migrated consumer bumps to it before the next
  breaking minor is tagged. Non-breaking patches are not limited.
- `v1.0.0` is cut after every consumer has migrated and the starred option
  ledger rows are resolved or owned. Strict SemVer applies from then on, and an
  `apidiff` (or `gorelease`) check becomes a required CI check. It is not part
  of the v0 gate.
- Tags are never moved or deleted. A bad release gets a `retract` directive in
  `go.mod` and a new patch tag. Proxy tags are permanent.
- Security fixes ship as a patch tag. On the day it is tagged, every consumer
  that pins an affected version gets a bump PR.
- Helm tags. Muse never tags or merges.
- A release starts as a release-prep pull request. That PR adds
  `docs/releases/vX.Y.Z.md` and folds `CHANGELOG.md` so the tag has a line
  `## vX.Y.Z`. `## Unreleased` alone is not enough. Ilya reviews. Helm
  squash-merges and pushes the tag.
- Pushing a `v*` tag runs CI (`.github/workflows/ci.yml`) and the release
  workflow (`.github/workflows/release.yml`). controlkit is a library, so the
  release workflow is a gate only. It does not publish an image, a binary, or
  a GitHub Release. `workflow_dispatch` re-runs the gate for one tag and
  publishes nothing. The ref input has to be a tag of the shape above.
- The gate matches the CI run of that tag push: workflow `ci.yml`, event
  `push`, `headSha` equal to the peeled commit
  (`git rev-parse refs/tags/<tag>^{commit}`), and `headBranch` equal to the
  tag name. An annotated tag's object SHA is not the commit. It waits while
  that run is missing or not completed, then requires the newest matching
  run (highest `databaseId`) to have these jobs green, by exact name:
  `go vet`, `go test -race ./...`, `fuzz smoke`, `govulncheck`,
  `replace/go.work check`. A green run on `main` for the same commit does
  not count.
- `docs/releases/<tag>.md` must exist at the tagged commit and contain a
  Markdown heading that includes the tag (for example `# v0.1.0`).
  `CHANGELOG.md` must contain a line whose text is `## ` plus the tag.

## Contributing

Changes land on `main` through pull requests. Branch protection on `main`:

- Required checks: `go vet`, `go test -race ./...`, `fuzz smoke`, `govulncheck`, `replace/go.work check`.
- `strict: false`. A pull request need not be up to date with `main`.
- `enforce_admins: true`.
- A pull request is required for every change, with 0 required approving reviews.
- No force push and no branch deletion.

The merge gate: Keystone posts a COMMENT review with LGTM, and Helm squash-merges only when the `commit_id` of Keystone's latest LGTM COMMENT review equals the pull request head SHA. A push after the LGTM needs a new one. Muse never merges or tags.

CI pins Go 1.26.8. The `go vet` job also runs gofmt and `go build ./...`. Run the same checks locally with `make ci`.

CI runs on pull requests, on pushes to `main`, and on `v*` tag pushes. A tag
run and a `main` run do not cancel each other: the concurrency group uses
`github.ref` (`refs/heads/main` versus `refs/tags/vX.Y.Z`).

The release workflow is `.github/workflows/release.yml`. It is the tag gate
in Versioning and releases. Helm pushes the tag after the release-prep pull
request. Muse never tags. `apidiff` is a required check from `v1.0.0`.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately; do not open
a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE).
