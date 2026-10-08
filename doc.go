// Package controlkit is the root of the go-lab management-plane kit.
//
// The kit holds the security-critical management-plane primitives that the
// go-lab repos share: management token loading and verification, scope and
// capability checks, sessions, origin and CSRF checks, audit, idempotency and
// rate limiting. Each consumer imports the sub-packages through thin facades in
// its own internal packages. This root package exports nothing.
//
// The packages are:
//
//   - kerr: error kinds a facade maps onto its own wire code.
//   - authn: token loading, verifier, stdio pin, secret wiping, and reload.
//   - scope: principal table and capability gate.
//   - session: session table, CSRF compare, cookie helpers, and revocation wake.
//   - origin: Origin allow-list policy.
//   - audit: bounded ring, fanout, redaction, and the denial flood guard.
//   - idem: bounded LRU and FIFO idempotency cache.
//   - ratelimit: capped per-key buckets and a per-call global bucket.
//   - mcpstrict: duplicate JSON keys, typed subtrees, and open fields.
//   - kittest: conformance suites that take injected drivers.
//
// Rules for every package in this module:
//   - Only the Go standard library is imported, so go.mod has no require
//     entries and the kit never raises a consumer's dependency versions.
//   - No package imports a consumer package.
//   - A zero value in a config struct is a constructor error, unless the
//     field's comment names what zero means.
package controlkit
