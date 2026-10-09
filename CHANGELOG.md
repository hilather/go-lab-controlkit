# Changelog

All notable changes are recorded here. This file is curated; it is not a raw
commit log.

## Unreleased

### Changed

- `mcpstrict`: Check's allocation is linear in the input. No shape grows
  faster than linearly. The 8× + 256 KiB bound is only deep and flat inputs
  that are not wide objects (measured at most about 3.5×). A wide object is
  about 20×, from the duplicate-key map and the decoded key strings.
  `Spec.Typed` decodes the input once with `encoding/json`, about 43× for a
  flat array of numbers and about 31× for a wide object, the same decode the
  MCP SDK pays. A Typed `*` walk over every array element measured about 71×
  under the race detector and is still linear. `TestCheckAllocBound` pins the
  wide object at 28× + 256 KiB and the Typed decode at 60× + 256 KiB, and
  fails if doubling the input multiplies allocations by more than 2.6×.
  Measured 2026-10-08 on Go 1.26.8.
- Option ledger: `authn.MinSecretBytes` stays a warning in B (dns enforces
  the 32-byte floor in a later minor, and a dns PR outside B generates
  tokens of at least 32 bytes now). snmp refuses a zero-token bearer with
  ntp and netconf; maildev and syslog keep `Accept` unset. The dns
  bearer-profile loopback administrator is not a kit option and is removed
  by a standalone dns PR.

### Added

- Repository setup: Apache-2.0 license, README with the consumer pin matrix
  and option ledger, SECURITY.md, CODEOWNERS, and CI (`go vet`,
  `go test -race ./...`, fuzz smoke, `govulncheck`, and a `replace`/`go.work`
  check) on Go 1.26.8.
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
