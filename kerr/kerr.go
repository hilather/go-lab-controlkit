// Package kerr holds the error kinds the management-plane kit returns.
// Each consumer maps a kind onto its own wire code and sentence. The kit
// does not format user-visible text beyond the Msg a caller stored.
package kerr

import "errors"

// Kind classifies a kit error. The zero Kind is unset and is not a result.
type Kind int

const (
	// Unauthenticated means the caller did not present acceptable credentials.
	Unauthenticated Kind = iota + 1
	// Forbidden means the caller was known but not allowed.
	Forbidden
	// OriginNotAllowed means the Origin header failed the policy.
	OriginNotAllowed
	// CSRFInvalid means a cookie mutation failed the CSRF check.
	CSRFInvalid
	// RateLimited means a limiter or a full session table refused the call.
	RateLimited
	// Invalid means the input or the loaded configuration is not usable.
	Invalid
	// Unavailable means a dependency needed for the operation was unavailable.
	Unavailable
	// Internal means the kit hit a bug or an impossible state.
	Internal
)

// String returns the stable lower-case name of the kind.
func (k Kind) String() string {
	switch k {
	case Unauthenticated:
		return "unauthenticated"
	case Forbidden:
		return "forbidden"
	case OriginNotAllowed:
		return "origin_not_allowed"
	case CSRFInvalid:
		return "csrf_invalid"
	case RateLimited:
		return "rate_limited"
	case Invalid:
		return "invalid"
	case Unavailable:
		return "unavailable"
	case Internal:
		return "internal"
	default:
		return "unset"
	}
}

// Violation is one field error a facade renders onto its own wire shape.
type Violation struct {
	Path    string
	Code    string
	Message string
}

// Error is a kit error. Msg is the sentence a facade chose, or a stable
// kit sentence where the plan pins one. Facades may ignore Msg and render
// from Kind and Violations.
type Error struct {
	Kind       Kind
	Msg        string
	Violations []Violation
}

// Error returns Msg.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Msg
}

// New returns an error of the given kind.
func New(kind Kind, msg string) *Error {
	return &Error{Kind: kind, Msg: msg}
}

// WithViolations returns an error of the given kind with field violations.
func WithViolations(kind Kind, msg string, v []Violation) *Error {
	out := append([]Violation(nil), v...)
	return &Error{Kind: kind, Msg: msg, Violations: out}
}

// KindOf reports the kind of err when err is or wraps an *Error with a set kind.
func KindOf(err error) (Kind, bool) {
	var ke *Error
	if !errors.As(err, &ke) || ke == nil || ke.Kind == 0 {
		return 0, false
	}
	return ke.Kind, true
}
