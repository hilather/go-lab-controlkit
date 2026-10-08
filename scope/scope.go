// Package scope evaluates principals and authorizes capabilities.
// The capability gate that the plan called capgate lives here as Gate.
package scope

import (
	"context"
	"slices"

	"github.com/hilather/go-lab-controlkit/audit"
	"github.com/hilather/go-lab-controlkit/kerr"
)

// Principal is the identity a request authenticated as.
type Principal struct {
	ID        string
	Class     string
	Role      string
	Scopes    []string
	Groups    []string
	Transport string
}

// Evaluator expands a principal to the scopes a check consults.
type Evaluator interface {
	Effective(p Principal) []string
	HasScope(p Principal, want string) bool
}

// Table is the evaluator for the template repos.
// EmptyRole, when set, is the role Expand uses for an empty role field.
// An empty EmptyRole leaves an empty role empty.
// ExplicitReplacesRole false means Expand ignores an explicit list and stores
// the role's scopes. True means a non-empty explicit list is stored as given.
// WildcardScope, when non-empty, is a stored scope that satisfies every check.
// An empty WildcardScope means there is no wildcard.
type Table struct {
	Roles                map[string][]string
	EmptyRole            string
	ExplicitReplacesRole bool
	WildcardScope        string
}

// Expand resolves role and explicit scopes the way the template repos do at load.
// An unknown role, or an empty role that does not fill from EmptyRole, is an error.
func (t Table) Expand(role string, explicit []string) (string, []string, error) {
	if role == "" {
		role = t.EmptyRole
	}
	if t.ExplicitReplacesRole && len(explicit) > 0 {
		return role, append([]string(nil), explicit...), nil
	}
	scopes, ok := t.Roles[role]
	if !ok || role == "" {
		return "", nil, kerr.New(kerr.Invalid, "unknown role "+quote(role))
	}
	return role, append([]string(nil), scopes...), nil
}

// Effective returns the scopes a check uses. A principal with a non-empty
// scope list uses that list. Otherwise the role is looked up in the table.
func (t Table) Effective(p Principal) []string {
	if len(p.Scopes) > 0 {
		return append([]string(nil), p.Scopes...)
	}
	if scopes, ok := t.Roles[p.Role]; ok {
		return append([]string(nil), scopes...)
	}
	return nil
}

// HasScope reports whether p holds want. WildcardScope satisfies every want.
func (t Table) HasScope(p Principal, want string) bool {
	for _, s := range t.Effective(p) {
		if s == want || (t.WildcardScope != "" && s == t.WildcardScope) {
			return true
		}
	}
	return false
}

// Authorize allows p only when every required scope is held.
// An empty required list is allowed. A nil evaluator is an internal error.
func Authorize(e Evaluator, p Principal, required []string) error {
	if e == nil {
		return kerr.New(kerr.Internal, "scope evaluator is required")
	}
	for _, want := range required {
		if want == "" {
			continue
		}
		if !e.HasScope(p, want) {
			return kerr.New(kerr.Forbidden, "missing scope "+want)
		}
	}
	return nil
}

func quote(s string) string {
	return `"` + s + `"`
}

// Catalog maps capabilities, tools, and resources to required scopes.
type Catalog interface {
	Required(capID string) (scopes []string, ok bool)
	ToolCaps(tool string) []string
	ResourceCaps(uri string) []string
}

// CapAuthorizer decides whether a principal may use a capability.
type CapAuthorizer func(p Principal, required []string, capID string) error

// UnmappedPolicy is what a gate does with a tool, resource, or capability
// the catalog does not map. The zero value is a constructor error.
type UnmappedPolicy int

const (
	// Allow permits an unmapped tool, resource, or capability.
	Allow UnmappedPolicy = iota + 1
	// Forbid rejects an unmapped tool, resource, or capability.
	Forbid
)

// Gate authorizes capabilities, tools, and resources.
// Authorize, when nil, means Authorize through Eval.
// ToolExtra, when nil, means no extra per-tool check.
// FirstCapOnly false checks every mapped capability. True checks only the first.
// Denied, when nil, means denials are not recorded.
type Gate struct {
	Eval         Evaluator
	Catalog      Catalog
	Authorize    CapAuthorizer
	ToolExtra    func(p Principal, tool, capID string) error
	Unmapped     UnmappedPolicy
	FirstCapOnly bool
	Denied       audit.DeniedRecorder
}

// NewGate validates g and fills a nil Authorize.
func NewGate(g Gate) (*Gate, error) {
	if g.Eval == nil {
		return nil, kerr.New(kerr.Invalid, "gate evaluator is required")
	}
	if g.Catalog == nil {
		return nil, kerr.New(kerr.Invalid, "gate catalog is required")
	}
	if g.Unmapped != Allow && g.Unmapped != Forbid {
		return nil, kerr.New(kerr.Invalid, "gate unmapped policy is required")
	}
	if g.Authorize == nil {
		eval := g.Eval
		g.Authorize = func(p Principal, required []string, _ string) error {
			return Authorize(eval, p, required)
		}
	}
	return &g, nil
}

// Capability authorizes one capability id.
func (g *Gate) Capability(ctx context.Context, p Principal, transport, capID string) error {
	if g == nil {
		return kerr.New(kerr.Internal, "nil gate")
	}
	req, ok := g.Catalog.Required(capID)
	if !ok {
		return g.unmapped(ctx, p, transport, capID)
	}
	if err := g.Authorize(p, req, capID); err != nil {
		g.record(ctx, p, transport, capID, err)
		return err
	}
	return nil
}

// Tool authorizes the capabilities mapped to tool.
func (g *Gate) Tool(ctx context.Context, p Principal, tool string) error {
	if g == nil {
		return kerr.New(kerr.Internal, "nil gate")
	}
	caps := g.Catalog.ToolCaps(tool)
	if len(caps) == 0 {
		return g.unmapped(ctx, p, transportOf(p), tool)
	}
	if g.FirstCapOnly {
		caps = caps[:1]
	}
	for _, capID := range caps {
		if err := g.Capability(ctx, p, transportOf(p), capID); err != nil {
			return err
		}
		if g.ToolExtra != nil {
			if err := g.ToolExtra(p, tool, capID); err != nil {
				g.record(ctx, p, transportOf(p), capID, err)
				return err
			}
		}
	}
	return nil
}

// Resource authorizes the capabilities mapped to uri.
func (g *Gate) Resource(ctx context.Context, p Principal, uri string) error {
	if g == nil {
		return kerr.New(kerr.Internal, "nil gate")
	}
	caps := g.Catalog.ResourceCaps(uri)
	if len(caps) == 0 {
		return g.unmapped(ctx, p, transportOf(p), uri)
	}
	if g.FirstCapOnly {
		caps = caps[:1]
	}
	for _, capID := range caps {
		if err := g.Capability(ctx, p, transportOf(p), capID); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gate) unmapped(ctx context.Context, p Principal, transport, capID string) error {
	if g.Unmapped == Allow {
		return nil
	}
	err := kerr.New(kerr.Forbidden, "capability is not mapped")
	g.record(ctx, p, transport, capID, err)
	return err
}

func (g *Gate) record(ctx context.Context, p Principal, transport, capID string, err error) {
	if g.Denied == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	code := "forbidden"
	if k, ok := kerr.KindOf(err); ok {
		code = k.String()
	}
	g.Denied.RecordDenied(ctx, audit.DeniedEvent{
		ActorID:    p.ID,
		ActorClass: p.Class,
		Transport:  transport,
		Capability: capID,
		ErrorCode:  code,
	})
}

func transportOf(p Principal) string {
	if p.Transport != "" {
		return p.Transport
	}
	return "mcp"
}

// CloneStrings copies ss. It is used by loaders that store scopes.
func CloneStrings(ss []string) []string {
	return append([]string(nil), ss...)
}

// SameSet reports whether a and b contain the same strings, ignoring order.
func SameSet(a, b []string) bool {
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	slices.Sort(aa)
	slices.Sort(bb)
	return slices.Equal(aa, bb)
}
