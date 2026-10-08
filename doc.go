// Package controlkit is the root of the go-lab management-plane kit.
//
// The kit holds the security-critical management-plane primitives that the
// go-lab repos share: management token loading and verification, scope and
// capability checks, sessions, origin and CSRF checks, audit, idempotency and
// rate limiting. Each consumer imports the sub-packages through thin facades in
// its own internal packages. This root package exports nothing.
//
// Rules for every package in this module:
//   - Only the Go standard library is imported, so go.mod has no require
//     entries and the kit never raises a consumer's dependency versions.
//   - No package imports a consumer package.
//   - A zero value in a config struct is a constructor error, unless the
//     field's comment names what zero means.
//
// The sub-packages arrive with v0.1.0.
package controlkit
