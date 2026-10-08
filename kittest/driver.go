// Package kittest holds the conformance suites consumers run against
// their own wiring. The suites take injected drivers. This package does
// not import an MCP SDK.
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
// Reset steps are demote, rotate, remove, restore, and reject.
// reject must fail and leave the pin unchanged.
// Loopback reports the maildev dev-loopback pin. ok false means this
// wiring has no such pin and the arm is skipped. step is before or after.
type StdioRotationDriver interface {
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
	ZeroNTPBearer       ZeroTokenShape = "ntp-bearer"
	ZeroNTPLoopback     ZeroTokenShape = "ntp-loopback"
	ZeroNetconf         ZeroTokenShape = "netconf"
	ZeroSNMP            ZeroTokenShape = "snmp"
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
type ApplyDriver interface {
	MakeUnreadable(ctx context.Context)
	Apply(ctx context.Context) (ok bool, opens int)
	BearerWorks(ctx context.Context) bool
	SessionWorks(ctx context.Context) bool
}

// LoadOnceDriver counts secret-file reads for one reset.
// Variants are omit-mode, listen-override, management-off, and
// unreadable-between.
type LoadOnceDriver interface {
	Variants() []string
	Reset(ctx context.Context, variant string) (reads int, ok bool)
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
type BootResult struct {
	Booted      bool
	DataPlaneOK bool
	SecretOpens int
	Message     string
}

// BootDriver boots with management off or bound.
// arm is off or bound. files is absent, short, or mode000.
type BootDriver interface {
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
type RebindDriver interface {
	Variant() RebindVariant
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

// DeniedAuditDriver counts denial rows with the guard not suppressing.
// Status is the HTTP status. rows is how many denial rows that call wrote.
type DeniedAuditDriver interface {
	Routes(ctx context.Context) []string
	Tools(ctx context.Context) []string
	DenyRoute(ctx context.Context, route string) (status int, rows int)
	DenyTool(ctx context.Context, tool string) (status int, rows int)
	BadBearer(ctx context.Context) (status int, rows int)
	StaleCookie(ctx context.Context) (status int, rows int)
	CSRFMiss(ctx context.Context) (status int, rows int)
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
