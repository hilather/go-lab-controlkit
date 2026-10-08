# Security Policy

## Scope

go-lab-controlkit holds the management-plane security primitives that the
go-lab repos share: management token loading and verification, scope and
capability checks, sessions, origin and CSRF checks, audit, idempotency and
rate limiting. A bug here can affect every consumer at once, so reports about
authentication bypass, scope or capability confusion, session fixation,
origin or CSRF bypass, timing leaks, secret or token leaks (including through
audit rows), and unbounded memory or blocking in the token-file reader or the
limiters are all in scope.

## Reporting vulnerabilities

Report security vulnerabilities through [GitHub private vulnerability reporting](https://github.com/hilather/go-lab-controlkit/security/advisories/new) on [`hilather/go-lab-controlkit`](https://github.com/hilather/go-lab-controlkit). Do not file vulnerabilities in the public issue tracker before coordinated disclosure.

Include, when possible: the affected version or commit, the consumer and its
configuration, a minimal reproduction, and the impact. Do not attach live
tokens or token files.

## Supported versions

| Version | Supported |
|---|---|
| Latest `v0.x` minor (once tagged) | Yes |
| Unreleased `main` | Best-effort until `v0.1.0` |
| Older minors, forks or modified copies | No |

## How fixes ship

A fix ships as a patch tag. On the day it is tagged, every consumer that pins
an affected version gets a bump PR, followed by that consumer's normal
release. Tags are never moved or deleted; a bad release is retracted in
`go.mod` and replaced by a new patch tag.
