// Package kittest holds the conformance suites consumers run against
// their own wiring. The suites take injected drivers. This package does
// not import an MCP SDK.
//
// DuplicateKeyNoEffect is for a consumer's PR-1. It feeds mcpstrict a
// document that repeats a root key and checks that the caller's snapshot
// is unchanged after Check rejects it.
package kittest

import (
	"context"
	"encoding/json"
	"time"
)

// ToolResult is one MCP or stdio tool call observed by a driver.
type ToolResult struct {
	Code       string
	Scopes     []string
	HandlerRan bool
}

// StdioRotationDriver is the mcp-stdio pin a StdioRotation run drives.
// Code is the repo's unauthenticated wire code. ntp, snmp, maildev, and
// dns use "unauthenticated". netconf and syslog use "unauthorized".
// StartupScopes is the scope set a mapped call sees before demotion.
// DemotedScopes is the scope set after the demotion reset. It must drop
// at least one startup scope and keep at least one.
// Reset steps are demote, rotate, remove, restore, and reject.
// reject must fail and leave the pin unchanged.
// Loopback reports the maildev dev-loopback pin. ok false means this
// wiring has no such pin and the arm is skipped. step is before or after.
type StdioRotationDriver interface {
	Code() string
	StartupScopes() []string
	DemotedScopes() []string
	Call(ctx context.Context, tool string) ToolResult
	Reset(ctx context.Context, step string) error
	Loopback(ctx context.Context, step string) (ToolResult, bool)
}

// ResetView is the observable state around a refused reset.
type ResetView struct {
	Revision     string
	SideEffects  int
	Listeners    []string
	BearerWorks  bool
	SessionWorks bool
}

// ResetFailureDriver observes a reset whose secret file cannot be used.
// Code is the repo's failure code: validation_failed or bootstrap_invalid.
// Reset kinds are missing, unreadable, and short.
type ResetFailureDriver interface {
	Code() string
	Observe(ctx context.Context) ResetView
	Reset(ctx context.Context, kind string) (code string, err error)
}

// ZeroTokenShape names one repo's zero-token reset.
type ZeroTokenShape string

const (
	ZeroNTPBearer   ZeroTokenShape = "ntp-bearer"
	ZeroNTPLoopback ZeroTokenShape = "ntp-loopback"
	// ZeroNetconf is netconf from its C3a commit. A zero-token bearer
	// reset through a control adapter is refused before the swap. The
	// old bearer and cookie still work and the revision is unchanged.
	ZeroNetconf ZeroTokenShape = "netconf"
	// ZeroNetconfFailClosed is netconf PR-1, today's behavior. The reset
	// succeeds. The adapter's post-swap reload calls failClosedAuth, which
	// installs an empty verifier and clears sessions, so the old bearer
	// and cookie stop working and the revision changes.
	ZeroNetconfFailClosed ZeroTokenShape = "netconf-fail-closed"
	// ZeroSNMP is snmp PR-1, today's success that drops old bearers. A
	// zero-token bearer reset succeeds, the old bearer and cookie stop
	// working, and the revision changes.
	ZeroSNMP ZeroTokenShape = "snmp"
	// ZeroSNMPRefuse is snmp from its B PR-2 C3a commit (P9, decided by
	// Matt 2026-10-08). A zero-token bearer reset through a control
	// adapter is refused before the swap. The old bearer and cookie
	// still work and the revision is unchanged.
	ZeroSNMPRefuse      ZeroTokenShape = "snmp-refuse"
	ZeroMaildevBearer   ZeroTokenShape = "maildev-bearer"
	ZeroMaildevBasic    ZeroTokenShape = "maildev-basic"
	ZeroMaildevLoopback ZeroTokenShape = "maildev-loopback"
)

// ZeroTokenResult is what Apply observed. An empty Code is success.
type ZeroTokenResult struct {
	Code              string
	OldBearerWorks    bool
	OldCookieWorks    bool
	RevisionUnchanged bool
}

// ZeroTokenDriver applies a zero-token spec for each shape it owns.
type ZeroTokenDriver interface {
	Shapes() []ZeroTokenShape
	Apply(ctx context.Context, shape ZeroTokenShape) ZeroTokenResult
}

// ApplyDriver is an apply that must not open a secret file.
// MakeUnreadable and MakeMissing run after a successful start.
// Apply returns success, which is HTTP 200 in the driver's terms, and
// the number of secret-file opens during that apply. Apply does not run
// Prepare. That is P2: rotation happens on reset or restart.
// FailureText is today's reset-failure message once the secret file is
// missing. It is the same role as RebindDriver.FailureText and
// BootDriver.BoundMessage. Reset is the reset after the missing-file
// apply. It fails, and its message equals FailureText.
type ApplyDriver interface {
	MakeUnreadable(ctx context.Context)
	MakeMissing(ctx context.Context)
	Apply(ctx context.Context) (ok bool, opens int)
	BearerWorks(ctx context.Context) bool
	SessionWorks(ctx context.Context) bool
	FailureText() string
	Reset(ctx context.Context) (message string, err error)
}

// LoadOnceDriver counts secret-file opens for one reset.
// Variants are omit-mode, listen-override, management-off, and
// unreadable-between.
// Files is the set of secret files that variant opens.
// Reset returns how many times each path was opened. A file opened twice
// fails the suite even when the total equals the size of Files.
type LoadOnceDriver interface {
	Variants() []string
	Files(variant string) []string
	Reset(ctx context.Context, variant string) (opens map[string]int, ok bool)
}

// RaceResult is one Prepare race case.
type RaceResult struct {
	Code         string
	Discarded    bool
	Reads        int
	CommittedNew bool
	Field        string
}

// PrepareRaceDriver runs the two spec-race cases.
// FailureCode is validation_failed or bootstrap_invalid.
type PrepareRaceDriver interface {
	FailureCode() string
	Case(ctx context.Context, n int) RaceResult
}

// BootResult is one boot attempt.
// Opens is the open count for each secret path. Nil and an empty map
// both mean nothing was opened.
type BootResult struct {
	Booted      bool
	DataPlaneOK bool
	Opens       map[string]int
	Message     string
}

// BootDriver boots with management off or bound.
// arm is off or bound. files is absent, short, or mode000.
// Files is the set that arm must open exactly once. The off arm returns
// nil when management-off opens nothing. It returns the pin's token files
// when that boot builds a stdio pin and therefore Prepares; only those
// files may be opened, once each. The bound arm returns every secret file
// that boot opens, including token files and maildev's password file.
// BoundMessage is the consumer's characterization of the bound-arm failure
// for that files shape. The suite compares Boot's Message to it byte for byte.
type BootDriver interface {
	Files(arm, files string) []string
	BoundMessage(files string) string
	Boot(ctx context.Context, arm, files string) BootResult
}

// StreamKind selects the credential that opened a stream.
type StreamKind string

const (
	StreamBearer StreamKind = "bearer"
	StreamCookie StreamKind = "cookie"
)

// StreamEnd is how a stream finished after one trigger.
type StreamEnd struct {
	Ended        bool
	WroteAfter   bool
	WithinBudget bool
	Rechecked    bool
}

// StreamDriver runs the revocation matrix.
// trigger is demote, remove-bearer, delete, delete-other, evict, or keep-scope.
type StreamDriver interface {
	Run(ctx context.Context, kind StreamKind, trigger string) StreamEnd
	MCPGet(ctx context.Context) int
	LazyExpiry(ctx context.Context) (idleEnded, absoluteEnded bool)
}

// RebindVariant selects a ManagementRebindOverAPI case.
// The set is experimental and may change before v1.0.0.
type RebindVariant string

const (
	RebindMove   RebindVariant = "move"
	RebindOff    RebindVariant = "off"
	RebindTaken  RebindVariant = "taken"
	RebindSame   RebindVariant = "same"
	RebindRefuse RebindVariant = "refuse"
	RebindKeep   RebindVariant = "keep"
)

// RebindObs is the observation after one rebind attempt.
type RebindObs struct {
	Elapsed         time.Duration
	Code            string
	NewServes       bool
	OldRefuses      bool
	ResponseIntact  bool
	RevisionChanged bool
	OldStillServes  bool
}

// RebindDriver runs one experimental rebind variant against a real listener.
// FailureText is today's error for a failing variant and empty on success.
// Syslog's address change (RebindRefuse) is "validation_failed".
type RebindDriver interface {
	Variant() RebindVariant
	FailureText() string
	Run(ctx context.Context) RebindObs
}

// CatalogDriver lists the tools a server registered and how a call ends.
// Call and CallUnmapped return ok or forbidden.
type CatalogDriver interface {
	Registered(ctx context.Context) []string
	InCatalog(name string) bool
	Call(ctx context.Context, name string) string
	CallUnmapped(ctx context.Context) string
}

// IdentityOrder is the order REST and MCP bind the shared verifier.
type IdentityOrder string

const (
	OrderProduction IdentityOrder = "production"
	OrderReverse    IdentityOrder = "reverse"
)

// IdentityDriver logs in, demotes, and reports whether the cookie survived.
type IdentityDriver interface {
	Boot(ctx context.Context, order IdentityOrder)
	Login(ctx context.Context) (cookie string)
	Demote(ctx context.Context)
	CookieWorks(ctx context.Context, cookie string) bool
}

// AuditFields is the transport, capability, and code on one denial row.
type AuditFields struct {
	Transport  string
	Capability string
	Code       string
}

// DenialObs is one denied call.
// Rows is how many denial rows that call wrote.
// Row is the recorded row, read back from the audit log.
type DenialObs struct {
	Status int
	Rows   int
	Row    AuditFields
}

// DeniedAuditDriver counts denial rows with the guard not suppressing.
// The Want methods are the expected row. The Deny methods return the
// row that was actually recorded.
type DeniedAuditDriver interface {
	Routes(ctx context.Context) []string
	Tools(ctx context.Context) []string
	WantRoute(route string) AuditFields
	WantTool(tool string) AuditFields
	WantBadBearer() AuditFields
	WantStaleCookie() AuditFields
	WantCSRF() AuditFields
	DenyRoute(ctx context.Context, route string) DenialObs
	DenyTool(ctx context.Context, tool string) DenialObs
	BadBearer(ctx context.Context) DenialObs
	StaleCookie(ctx context.Context) DenialObs
	CSRFMiss(ctx context.Context) DenialObs
}

// FloodDriver floods one denial key and reports an OK row that must survive.
type FloodDriver interface {
	Flood(ctx context.Context, n int) (admitted int, suppressed uint64, okSurvived bool)
}

// StrictDriver calls tools with gap payloads and valid payloads.
// Call returns invalid when Check rejects the arguments.
// revision is the snapshot revision after the call.
type StrictDriver interface {
	Tools(ctx context.Context) []string
	GapPayloads(name string) []json.RawMessage
	ValidPayloads(name string) []json.RawMessage
	Call(ctx context.Context, name string, args json.RawMessage) (code string, revision string)
	Revision(ctx context.Context) string
}
