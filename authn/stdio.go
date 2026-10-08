package authn

import (
	"fmt"
	"log/slog"

	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/scope"
)

// StdioPin is the process actor for mcp-stdio.
// A token pin re-verifies its retained secret against the live material on
// every Resolve. A dev-loopback pin returns the startup principal while the
// verifier generation is unchanged and the mode is still dev-loopback-unauth.
// The secret renders as [redacted].
type StdioPin struct {
	v      *Verifier
	secret Secret
	dev    bool
	gen    uint64
	p      scope.Principal
}

// NewStdioPin authenticates s once and retains a copy. An empty secret or a
// nil verifier is an error. A secret that does not match the live material is
// the authenticator's error.
func NewStdioPin(v *Verifier, s Secret) (*StdioPin, error) {
	if v == nil {
		return nil, kerr.New(kerr.Invalid, "authn: stdio pin requires a verifier")
	}
	if s.Len() == 0 {
		return nil, kerr.New(kerr.Invalid, "authn: stdio pin requires a secret")
	}
	p, err := v.AuthenticateBearer(s.bytes())
	if err != nil {
		return nil, err
	}
	return &StdioPin{v: v, secret: NewSecret(s.bytes()), p: p}, nil
}

// NewDevLoopbackStdio pins p with no secret. It refuses a nil verifier and any
// verifier whose live mode is not dev-loopback-unauth.
func NewDevLoopbackStdio(v *Verifier, p scope.Principal) (*StdioPin, error) {
	if v == nil {
		return nil, kerr.New(kerr.Invalid, "authn: stdio pin requires a verifier")
	}
	if v.Mode() != ModeDevLoopbackUnauth {
		return nil, kerr.New(kerr.Invalid, "authn: dev-loopback stdio requires dev-loopback-unauth")
	}
	return &StdioPin{v: v, dev: true, gen: v.Generation(), p: clonePrincipal(p)}, nil
}

// Resolve returns the live principal.
// A token pin is unauthenticated when the retained secret no longer matches,
// including after a same-id rotation, a removal, or a swap to zero tokens.
// A demotion returns the new scopes. Restoring the old secret restores access.
// A dev-loopback pin is unauthenticated after any identity-changing swap.
func (p *StdioPin) Resolve() (scope.Principal, error) {
	if p == nil || p.v == nil {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	if p.dev {
		if p.v.Mode() != ModeDevLoopbackUnauth || p.v.Generation() != p.gen {
			return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
		}
		return clonePrincipal(p.p), nil
	}
	return p.v.AuthenticateBearer(p.secret.bytes())
}

func (p *StdioPin) String() string { return "[redacted]" }

func (p *StdioPin) GoString() string { return "[redacted]" }

// Format renders every verb as [redacted].
func (p *StdioPin) Format(f fmt.State, _ rune) { fmt.Fprint(f, "[redacted]") }

// MarshalJSON renders a redacted JSON string.
func (p *StdioPin) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// LogValue renders a redacted slog value.
func (p *StdioPin) LogValue() slog.Value { return slog.StringValue("[redacted]") }
