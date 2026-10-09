# Changelog

All notable changes are recorded here. This file is curated; it is not a raw
commit log.

## Unreleased

### Changed

- `mcpstrict`: Check's allocation is linear in the input. No shape grows
  faster than linearly. The 8× + 256 KiB bound covers three fixtures, each
  at most about 3.5×: a nested array, a single-key deep object, and a flat
  array of zeros. A wide object is about 20×, from the duplicate-key map
  and the decoded key strings. A flat array of small two-key objects is
  about 41×, because each object allocates that map, and is pinned at
  58× + 256 KiB. A root Typed decode is about 43× for a flat array of
  numbers and about 31× for a wide object, the same `encoding/json` decode
  the MCP SDK pays. A Typed `/*` walk over every element of a flat array
  is about 66× to 71× and is pinned at 99× + 256 KiB. The same walk over
  a wide object's keys is about 34× and uses the 60× root-Typed limit.
  The doubling check fails above 2.6×. The size matrix grew by at most
  about 2.02×. The committed -race probe, 64 KiB to 128 KiB, grew 2.10×
  for a root Typed decode and 2.06× for a flat Typed `/*` walk. Measured
  2026-10-08 on Go 1.26.8; the two-key array on Go 1.26.9.
- Option ledger: `authn.MinSecretBytes` follows the Q8 timeline. A dns
  PR outside B now generates tokens of at least 32 bytes. dns's next
  minor, outside B, refuses shorter tokens. B follows dns `main` at M6:
  if that minor has landed, the facade sets `MinSecretBytes` to 32 and
  P8 is omitted; only if M6 ships first does B keep P8's warning. B
  never loosens a floor dns `main` already enforces. snmp, ntp, and
  netconf refuse a zero-token bearer at boot when management binds or a
  stdio pin is built, and at reset through a control adapter. A reset
  with no adapter runs no predicate. maildev and syslog keep `Accept`
  unset. The dns bearer-profile loopback administrator is not a kit
  option and is removed by a standalone dns PR.

### Added

- `kittest.DuplicateKeyNoEffect` appends a later copy of the first root key,
  requires the duplicate-key error, requires the caller's snapshot to stay
  unchanged, and requires Check not to modify the caller's document or the
  duplicate document. Consumers run it in their C4 commit. PR-1 only lists
  the validators.
- `kittest.ResetZeroTokens` adds `ZeroSNMPRefuse` (snmp from its B PR-2
  C3a commit, P9: a zero-token bearer reset through a control adapter is
  refused before the swap) and `ZeroNetconfFailClosed` (netconf PR-1: the
  reset succeeds and the post-swap reload fail-closes, so the old bearer
  and cookie stop working). `ZeroSNMP` stays snmp PR-1, today's success
  that drops old bearers. `ZeroNetconf` stays netconf from its C3a commit.
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
