package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"sync"

	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/scope"
)

// Request is one authentication attempt. Adapters fill it from the request.
// RemoteAddr is the peer address. X-Forwarded-For is never read.
// AllowBasic is true for REST. MCP leaves it false, so a Basic header is
// refused even when the material has a Basic credential.
type Request struct {
	Authorization string
	RemoteAddr    string
	AllowBasic    bool
}

type hook struct {
	id uint64
	fn func()
}

// Verifier authenticates against a swappable *Material.
// Hooks run synchronously on the caller goroutine after the verifier lock is
// released, and only when the installed material is not Equivalent.
// Identity-change hooks must not call into the application.
type Verifier struct {
	mu       sync.Mutex
	mat      *Material
	gen      uint64
	nextHook uint64
	hooks    []hook
	allowAll bool
}

// NewVerifier installs m. A nil material is an error.
func NewVerifier(m *Material) (*Verifier, error) {
	if m == nil {
		return nil, kerr.New(kerr.Invalid, "authn: verifier requires material")
	}
	return &Verifier{mat: m.clone()}, nil
}

// Empty is a bearer verifier with zero tokens. Every request fails closed.
func Empty() *Verifier {
	m, err := Load(Config{
		Mode:       ModeBearer,
		Source:     Memory(nil),
		Duplicates: RejectDuplicateValue,
	})
	if err != nil {
		panic("authn: Empty: " + err.Error())
	}
	v, err := NewVerifier(m)
	if err != nil {
		panic("authn: Empty: " + err.Error())
	}
	return v
}

// AllowAll returns a verifier that authenticates every request as an
// administrator. It exists for tests only.
func AllowAll() *Verifier {
	return &Verifier{
		allowAll: true,
		mat: &Material{
			mode: ModeBearer,
			loop: scope.Principal{ID: "allow-all", Class: "test", Role: "administrator"},
		},
	}
}

// Authenticate checks r against the live material.
// A missing or malformed credential is "authentication required".
// A credential that does not match is "invalid token".
// Dev-loopback mode with an empty header and a loopback peer returns the
// loopback principal. A presented header is checked as a credential and does
// not fall back to loopback.
func (v *Verifier) Authenticate(r Request) (scope.Principal, error) {
	if v == nil {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	if v.allowAll {
		return scope.Principal{ID: "allow-all", Class: "test", Role: "administrator"}, nil
	}
	m := v.snapshot()
	if m == nil {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	return authenticateMaterial(m, r)
}

// AuthenticateBearer checks a raw token secret against the live material.
// mcp-stdio uses it on every call. The secret is not retained.
func (v *Verifier) AuthenticateBearer(sec []byte) (scope.Principal, error) {
	if v == nil {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	if v.allowAll {
		return scope.Principal{ID: "allow-all", Class: "test", Role: "administrator"}, nil
	}
	m := v.snapshot()
	if m == nil {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	return lookupBearer(m, strings.TrimSpace(string(sec)))
}

// Swap installs next. A nil next does not change the verifier.
// The material is installed, the hook list is copied, and the lock is
// released before any hook runs. Hooks run only when the identities differ.
// Generation increases only then. Hooks run on the caller goroutine.
func (v *Verifier) Swap(next *Material) (changed bool) {
	if v == nil || next == nil || v.allowAll {
		return false
	}
	v.mu.Lock()
	changed = !v.mat.Equivalent(next)
	v.mat = next.clone()
	if changed {
		v.gen++
	}
	fns := make([]func(), len(v.hooks))
	for i, h := range v.hooks {
		fns[i] = h.fn
	}
	v.mu.Unlock()
	if !changed {
		return false
	}
	for _, fn := range fns {
		fn()
	}
	return true
}

// OnIdentityChange registers fn. The returned function removes it.
// A nil verifier or a nil fn returns a no-op unregister.
// Hooks run in registration order, synchronously, after Swap releases its lock.
func (v *Verifier) OnIdentityChange(fn func()) (unregister func()) {
	if v == nil || fn == nil {
		return func() {}
	}
	v.mu.Lock()
	v.nextHook++
	id := v.nextHook
	v.hooks = append(v.hooks, hook{id: id, fn: fn})
	v.mu.Unlock()
	return func() {
		v.mu.Lock()
		defer v.mu.Unlock()
		n := 0
		for _, h := range v.hooks {
			if h.id != id {
				v.hooks[n] = h
				n++
			}
		}
		v.hooks = v.hooks[:n]
	}
}

// Generation is the number of identity-changing swaps. It starts at zero.
func (v *Verifier) Generation() uint64 {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.gen
}

// Mode is the live mode. AllowAll reports bearer.
func (v *Verifier) Mode() Mode {
	if v == nil {
		return 0
	}
	if v.allowAll {
		return ModeBearer
	}
	m := v.snapshot()
	if m == nil {
		return 0
	}
	return m.Mode()
}

// TokenCount is the live bearer count, duplicates included.
func (v *Verifier) TokenCount() int {
	if v == nil || v.allowAll {
		return 0
	}
	m := v.snapshot()
	if m == nil {
		return 0
	}
	return m.TokenCount()
}

// BasicEnabled reports whether the live material has a Basic credential.
func (v *Verifier) BasicEnabled() bool {
	if v == nil || v.allowAll {
		return false
	}
	m := v.snapshot()
	return m.BasicEnabled()
}

func (v *Verifier) snapshot() *Material {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.mat
}

func authenticateMaterial(m *Material, r Request) (scope.Principal, error) {
	scheme, token, err := ParseAuthorization(r.Authorization)
	if err != nil || (scheme == "" && len(token) == 0 && strings.TrimSpace(r.Authorization) != "") {
		zero(token)
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	if scheme == "" {
		zero(token)
		if m.mode == ModeDevLoopbackUnauth && m.loopback(r.RemoteAddr) {
			return clonePrincipal(m.loop), nil
		}
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	defer zero(token)
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		if strings.ContainsAny(string(token), " \t") {
			return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
		}
		return lookupBearer(m, string(token))
	case strings.EqualFold(scheme, "Basic"):
		if !r.AllowBasic || m.basic == nil || m.mode != ModeBearerAndBasic {
			return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
		}
		return lookupBasic(m, string(token))
	default:
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
}

func lookupBearer(m *Material, secret string) (scope.Principal, error) {
	if secret == "" {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	sum := sha256.Sum256([]byte(secret))
	idx := 0
	found := 0
	first := 1
	for i := range m.tokens {
		eq := subtle.ConstantTimeCompare(sum[:], m.tokens[i].digest[:])
		if m.dup == FirstMatchWins {
			take := eq & first
			idx = idx*(1-take) + i*take
			found |= take
			first &= 1 - eq
		} else {
			idx = idx*(1-eq) + i*eq
			found += eq
		}
	}
	ok := 0
	if m.dup == FirstMatchWins {
		ok = found
	} else if found == 1 {
		ok = 1
	}
	if ok != 1 {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "invalid token")
	}
	return m.principalAt(idx), nil
}

func lookupBasic(m *Material, payload string) (scope.Principal, error) {
	user, pass, ok := parseBasic(payload)
	defer zero([]byte(pass))
	wantUser := ""
	var wantPass [32]byte
	idx := -1
	if m.basic != nil {
		wantUser = m.basic.username
		wantPass = m.basic.digest
		idx = m.basic.index
	}
	userSum := sha256.Sum256([]byte(user))
	wantUserSum := sha256.Sum256([]byte(wantUser))
	passSum := sha256.Sum256([]byte(pass))
	userOK := subtle.ConstantTimeCompare(userSum[:], wantUserSum[:])
	passOK := subtle.ConstantTimeCompare(passSum[:], wantPass[:])
	parsed := 0
	if ok {
		parsed = 1
	}
	inRange := 0
	if idx >= 0 && idx < len(m.tokens) {
		inRange = 1
	}
	if parsed != 1 {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "authentication required")
	}
	if userOK != 1 || passOK != 1 || inRange != 1 {
		return scope.Principal{}, kerr.New(kerr.Unauthenticated, "invalid token")
	}
	return m.principalAt(idx), nil
}

func clonePrincipal(p scope.Principal) scope.Principal {
	p.Scopes = append([]string(nil), p.Scopes...)
	p.Groups = append([]string(nil), p.Groups...)
	return p
}
