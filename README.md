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

The v0.1.0 pull request has landed the packages. Nothing is tagged. The
release workflow lands in the release-prep pull request, before the first
tag.

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
- `kittest`: conformance suites that take injected drivers. `DuplicateKeyNoEffect` checks that a later duplicate key leaves no observable validator effect.

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
| `authn.MinSecretBytes` 0 `*` | dns | accidental, security-relevant | Decided by Matt (2026-10-08, Q8). B keeps P8's warning and a kittest pin; it does not refuse short tokens. A separate dns PR outside B makes the examples/main-lab README generate tokens of at least 32 bytes now. dns's next minor release enforces the floor (refuses tokens shorter than 32 bytes), with a deprecation note in its CHANGELOG. |
| `authn.Duplicates` = FirstMatchWins `*` | dns | accidental | Owned by dns before v1.0.0: a kittest pin and a ledger entry. Converging would reject dns configs that boot today, which needs its own decision. |
| `authn.Accept` (zero-token predicate) | ntp, netconf: refuse; snmp: refuse from its B PR-2 (P9); maildev, syslog: none | product (snmp converges in B) | Decided by Matt (2026-10-08, Q11/P9). snmp, ntp and netconf refuse a zero-token bearer config at boot and at reset, in each repo's B PRs (C3a for reset, boot unchanged). snmp's `TestReloadAuthDropsEmptyTokens` flips to a refusal. maildev and syslog are exempt and keep `Accept` unset. |
| `FileOpts.Line`, `Resolve`, `SkipMissing`; `DNSBundle`; dns identity defaults | per repo | product (documented file formats and path rules) | Kept. |
| `authn.LocalhostIsLoopback` | ntp, maildev: true; dns: false | accidental | Owned per repo. It only matters in dev-loopback mode. Revisit after M7. |
| dns bearer-profile loopback administrator (not a kit option) | dns | accidental, security-relevant | Decided by Matt (2026-10-08). A standalone dns PR outside B removes it: under the bearer profile, a loopback request without a bearer is no longer administrator. `dev-loopback-unauth` is unchanged and health stays unauthenticated. B keeps dns identity unchanged, and the kit never offers it. |
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

- SemVer tags `vMAJOR.MINOR.PATCH`, starting at `v0.1.0`.
- In v0 a minor release may break the API. At most one API-breaking minor is in
  flight at a time: every migrated consumer bumps to it before the next
  breaking minor is tagged. Non-breaking patches are not limited.
- `v1.0.0` is cut after every consumer has migrated and the starred option
  ledger rows are resolved or owned. Strict SemVer applies from then on, and an
  `apidiff` check becomes a required CI check.
- Tags are never moved or deleted. A bad release gets a `retract` directive in
  `go.mod` and a new patch tag.
- Security fixes ship as a patch tag. On the day it is tagged, every consumer
  that pins an affected version gets a bump PR.

## Contributing

Changes land on `main` through pull requests. Branch protection on `main`:

- Required checks: `go vet`, `go test -race ./...`, `fuzz smoke`, `govulncheck`, `replace/go.work check`.
- `strict: false`. A pull request need not be up to date with `main`.
- `enforce_admins: true`.
- A pull request is required for every change, with 0 required approving reviews.
- No force push and no branch deletion.

The merge gate: Keystone posts a COMMENT review with LGTM, and Helm squash-merges only when the `commit_id` of Keystone's latest LGTM COMMENT review equals the pull request head SHA. A push after the LGTM needs a new one. Muse never merges or tags.

CI pins Go 1.26.8. The `go vet` job also runs gofmt and `go build ./...`. Run the same checks locally with `make ci`.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately; do not open
a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE).
