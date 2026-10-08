// Package session is the process-local UI session table.
// Expired rows stay until the next Lookup, View, ValidCSRF, or Create.
// There is no timer goroutine. OnDelete hooks run after the store lock is
// released, once per removing call. A hook may call back into the store.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"

	"github.com/hilather/go-lab-controlkit/authn"
	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/scope"
)

// AtCap is what Create does when the table is full after the expiry sweep.
// The zero value is a constructor error.
type AtCap int

const (
	// EvictOldest drops the least-recently-seen session and inserts the new one.
	EvictOldest AtCap = iota + 1
	// Reject refuses the insert with RateLimited "session table full".
	Reject
)

// IDShape selects how the cookie and the public id are minted.
// The zero value is a constructor error.
type IDShape int

const (
	// SeparateCookieSecret uses a 32-byte cookie secret and a distinct
	// 16-byte public id. The five template repos use this shape.
	SeparateCookieSecret IDShape = iota + 1
	// SingleID uses one 32-byte id as both the cookie and the public id.
	// dns uses this shape.
	SingleID
)

// CSRFCompare selects the constant-time CSRF check.
// The zero value is a constructor error.
type CSRFCompare int

const (
	// DigestConstantTime compares SHA-256 digests of the stored and presented
	// secrets. The five template repos use this.
	DigestConstantTime CSRFCompare = iota + 1
	// HexOrRawConstantTime decodes both sides as hex when that succeeds and
	// the decoded lengths match, and otherwise compares the raw strings when
	// their lengths match. dns uses this.
	HexOrRawConstantTime
)

// Config sizes one store. Every field is required except Absolute.
// Absolute 0 means there is no absolute cap. A negative Absolute is an error.
type Config struct {
	CookieName  string
	CSRFHeader  string
	Idle        time.Duration
	Absolute    time.Duration
	Max         int
	AtCap       AtCap
	IDShape     IDShape
	CSRFCompare CSRFCompare
}

// Session is the public view of one row. It does not include the cookie
// secret or the CSRF secret.
type Session struct {
	ID         string
	Principal  scope.Principal
	CreatedAt  time.Time
	LastSeen   time.Time
	Generation uint64
}

// Issued is a newly created or rotated session.
type Issued struct {
	Session Session
	Cookie  string
	CSRF    string
}

type record struct {
	public   Session
	csrf     string
	created  time.Time
	lastSeen time.Time
	gen      uint64
}

type delHook struct {
	id uint64
	fn func()
}

// Store is a process-local session table.
type Store struct {
	mu       sync.Mutex
	cfg      Config
	sessions map[string]*record
	now      func() time.Time
	hooks    []delHook
	nextHook uint64
	verifier *authn.Verifier
	unhook   func()
	bindID   uint64
}

// New builds a store. A zero CookieName, CSRFHeader, Idle, Max, AtCap,
// IDShape, or CSRFCompare is an error. Absolute 0 is the documented
// "no absolute cap" value.
func New(cfg Config) (*Store, error) {
	if cfg.CookieName == "" || cfg.CSRFHeader == "" {
		return nil, kerr.New(kerr.Invalid, "session: cookie name and csrf header are required")
	}
	if cfg.Idle <= 0 {
		return nil, kerr.New(kerr.Invalid, "session: idle duration is required")
	}
	if cfg.Absolute < 0 {
		return nil, kerr.New(kerr.Invalid, "session: absolute duration must not be negative")
	}
	if cfg.Max <= 0 {
		return nil, kerr.New(kerr.Invalid, "session: max is required")
	}
	if cfg.AtCap != EvictOldest && cfg.AtCap != Reject {
		return nil, kerr.New(kerr.Invalid, "session: at-cap policy is required")
	}
	if cfg.IDShape != SeparateCookieSecret && cfg.IDShape != SingleID {
		return nil, kerr.New(kerr.Invalid, "session: id shape is required")
	}
	if cfg.CSRFCompare != DigestConstantTime && cfg.CSRFCompare != HexOrRawConstantTime {
		return nil, kerr.New(kerr.Invalid, "session: csrf compare is required")
	}
	return &Store{
		cfg:      cfg,
		sessions: make(map[string]*record),
		now:      time.Now,
	}, nil
}

// CookieName is the configured cookie name.
func (s *Store) CookieName() string {
	if s == nil {
		return ""
	}
	return s.cfg.CookieName
}

// CSRFHeader is the configured CSRF header name.
func (s *Store) CSRFHeader() string {
	if s == nil {
		return ""
	}
	return s.cfg.CSRFHeader
}

// SetNow replaces the clock. Nil restores time.Now.
func (s *Store) SetNow(now func() time.Time) {
	if s == nil {
		return
	}
	if now == nil {
		now = time.Now
	}
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// Create sweeps expired rows, applies the cap policy, and inserts a session.
// A sweep that removes any row fires OnDelete once. An eviction fires it
// once more. Both can run for the same Create.
func (s *Store) Create(p scope.Principal) (Issued, error) {
	if s == nil {
		return Issued{}, kerr.New(kerr.Invalid, "session: store is required")
	}
	cookie, id, csrf, err := s.mint()
	if err != nil {
		return Issued{}, err
	}
	now := s.currentTime()
	gen := s.generation()
	rec := &record{
		public: Session{
			ID:         id,
			Principal:  copyPrincipal(p),
			CreatedAt:  now,
			LastSeen:   now,
			Generation: gen,
		},
		csrf:     csrf,
		created:  now,
		lastSeen: now,
		gen:      gen,
	}
	s.mu.Lock()
	swept := s.sweepLocked(now)
	evicted := false
	if len(s.sessions) >= s.cfg.Max {
		if s.cfg.AtCap == Reject {
			s.mu.Unlock()
			if swept {
				s.notify()
			}
			return Issued{}, kerr.New(kerr.RateLimited, "session table full")
		}
		evicted = s.evictOldestLocked()
	}
	s.sessions[cookie] = rec
	issued := Issued{Session: rec.view(), Cookie: cookie, CSRF: csrf}
	s.mu.Unlock()
	if swept {
		s.notify()
	}
	if evicted {
		s.notify()
	}
	return issued, nil
}

// Lookup returns the session for cookie and slides LastSeen.
// An expired or stale row is deleted. A deletion fires OnDelete once.
func (s *Store) Lookup(cookie string) (Session, bool) {
	if s == nil || cookie == "" {
		return Session{}, false
	}
	now := s.currentTime()
	gen, bound := s.generationBound()
	s.mu.Lock()
	rec, ok := s.sessions[cookie]
	if !ok || s.expired(rec, now) || (bound && rec.gen != gen) {
		if ok {
			delete(s.sessions, cookie)
		}
		s.mu.Unlock()
		if ok {
			s.notify()
		}
		return Session{}, false
	}
	rec.lastSeen = now
	rec.public.LastSeen = now
	out := rec.view()
	s.mu.Unlock()
	return out, true
}

// View returns the session for cookie without sliding LastSeen.
// An expired or stale row is deleted, and that deletion fires OnDelete once.
func (s *Store) View(cookie string) (Session, bool) {
	if s == nil || cookie == "" {
		return Session{}, false
	}
	now := s.currentTime()
	gen, bound := s.generationBound()
	s.mu.Lock()
	rec, ok := s.sessions[cookie]
	if !ok || s.expired(rec, now) || (bound && rec.gen != gen) {
		if ok {
			delete(s.sessions, cookie)
		}
		s.mu.Unlock()
		if ok {
			s.notify()
		}
		return Session{}, false
	}
	out := rec.view()
	s.mu.Unlock()
	return out, true
}

// Delete removes one cookie session. A row that was present fires OnDelete once.
func (s *Store) Delete(cookie string) {
	if s == nil || cookie == "" {
		return
	}
	s.mu.Lock()
	_, ok := s.sessions[cookie]
	delete(s.sessions, cookie)
	s.mu.Unlock()
	if ok {
		s.notify()
	}
}

// Clear drops every session. A non-empty table fires OnDelete once.
func (s *Store) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	n := len(s.sessions)
	s.sessions = make(map[string]*record)
	s.mu.Unlock()
	if n > 0 {
		s.notify()
	}
}

// ValidCSRF reports whether presented matches the cookie's CSRF secret.
// An expired or stale row is deleted and fires OnDelete once. ValidCSRF does
// not slide LastSeen.
func (s *Store) ValidCSRF(cookie, presented string) bool {
	if s == nil || cookie == "" || presented == "" {
		return false
	}
	now := s.currentTime()
	gen, bound := s.generationBound()
	s.mu.Lock()
	rec, ok := s.sessions[cookie]
	if !ok || s.expired(rec, now) || (bound && rec.gen != gen) {
		if ok {
			delete(s.sessions, cookie)
		}
		s.mu.Unlock()
		if ok {
			s.notify()
		}
		return false
	}
	match := s.csrfMatch(rec.csrf, presented)
	s.mu.Unlock()
	return match
}

// Rotate replaces cookie with a new id and CSRF for the same principal.
// It does not consume an extra table slot. An unknown, expired, or stale
// cookie is removed and returns Unauthenticated "session expired".
func (s *Store) Rotate(cookie string) (Issued, error) {
	if s == nil {
		return Issued{}, kerr.New(kerr.Invalid, "session: store is required")
	}
	if cookie == "" {
		return Issued{}, kerr.New(kerr.Unauthenticated, "session expired")
	}
	nextCookie, id, csrf, err := s.mint()
	if err != nil {
		return Issued{}, err
	}
	now := s.currentTime()
	gen, bound := s.generationBound()
	s.mu.Lock()
	old, ok := s.sessions[cookie]
	if !ok || s.expired(old, now) || (bound && old.gen != gen) {
		if ok {
			delete(s.sessions, cookie)
		}
		s.mu.Unlock()
		if ok {
			s.notify()
		}
		return Issued{}, kerr.New(kerr.Unauthenticated, "session expired")
	}
	delete(s.sessions, cookie)
	freshGen := gen
	if !bound {
		freshGen = old.gen
	}
	rec := &record{
		public: Session{
			ID:         id,
			Principal:  copyPrincipal(old.public.Principal),
			CreatedAt:  now,
			LastSeen:   now,
			Generation: freshGen,
		},
		csrf:     csrf,
		created:  now,
		lastSeen: now,
		gen:      freshGen,
	}
	s.sessions[nextCookie] = rec
	issued := Issued{Session: rec.view(), Cookie: nextCookie, CSRF: csrf}
	s.mu.Unlock()
	return issued, nil
}

// MaxAge is the cookie Max-Age in seconds. It is Absolute when Absolute is
// non-zero, and Idle when Absolute is 0.
func (s *Store) MaxAge() int {
	if s == nil {
		return 0
	}
	d := s.cfg.Absolute
	if d == 0 {
		d = s.cfg.Idle
	}
	return int(d.Seconds())
}

// ExpiresAt is the earlier of idle and absolute expiry. Absolute 0 leaves
// only the idle deadline.
func (s *Store) ExpiresAt(sess Session) time.Time {
	if s == nil {
		return time.Time{}
	}
	idle := sess.LastSeen.Add(s.cfg.Idle)
	if s.cfg.Absolute == 0 {
		return idle
	}
	abs := sess.CreatedAt.Add(s.cfg.Absolute)
	if idle.Before(abs) {
		return idle
	}
	return abs
}

// Len is the number of stored rows, including ones not yet noticed as expired.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// OnDelete registers fn, called once per call that removes sessions, after
// the store lock is released. The returned function unregisters it.
// Several hooks may be registered. They run in registration order.
func (s *Store) OnDelete(fn func()) (unregister func()) {
	if s == nil || fn == nil {
		return func() {}
	}
	s.mu.Lock()
	s.nextHook++
	id := s.nextHook
	s.hooks = append(s.hooks, delHook{id: id, fn: fn})
	s.mu.Unlock()
	return func() {
		if s == nil {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		n := 0
		for _, h := range s.hooks {
			if h.id != id {
				s.hooks[n] = h
				n++
			}
		}
		s.hooks = s.hooks[:n]
	}
}

// Bind registers Clear as an identity-change hook and records v.Generation
// on every later Create. Lookup, View, ValidCSRF, and Rotate reject a session
// whose generation is not current, so a missed hook cannot keep a stale row.
// A nil verifier is an error. The returned function removes the hook and the
// generation check.
func (s *Store) Bind(v *authn.Verifier) (unregister func(), err error) {
	if s == nil || v == nil {
		return nil, kerr.New(kerr.Invalid, "session: bind requires a verifier")
	}
	s.mu.Lock()
	prev := s.unhook
	s.bindID++
	id := s.bindID
	s.mu.Unlock()
	if prev != nil {
		prev()
	}
	unhook := v.OnIdentityChange(func() { s.Clear() })
	s.mu.Lock()
	s.verifier = v
	s.unhook = unhook
	s.bindID = id
	s.mu.Unlock()
	return func() {
		unhook()
		s.mu.Lock()
		if s.bindID == id {
			s.verifier = nil
			s.unhook = nil
		}
		s.mu.Unlock()
	}, nil
}

func (s *Store) mint() (cookie, id, csrf string, err error) {
	csrf, err = randomHex(32)
	if err != nil {
		return "", "", "", err
	}
	switch s.cfg.IDShape {
	case SingleID:
		id, err = randomHex(32)
		if err != nil {
			return "", "", "", err
		}
		return id, id, csrf, nil
	default:
		cookie, err = randomHex(32)
		if err != nil {
			return "", "", "", err
		}
		id, err = randomHex(16)
		if err != nil {
			return "", "", "", err
		}
		return cookie, id, csrf, nil
	}
}

func (s *Store) generation() uint64 {
	g, _ := s.generationBound()
	return g
}

func (s *Store) generationBound() (uint64, bool) {
	s.mu.Lock()
	v := s.verifier
	s.mu.Unlock()
	if v == nil {
		return 0, false
	}
	return v.Generation(), true
}

func (s *Store) currentTime() time.Time {
	s.mu.Lock()
	fn := s.now
	s.mu.Unlock()
	if fn == nil {
		return time.Now()
	}
	return fn()
}

func (s *Store) expired(rec *record, now time.Time) bool {
	if now.Sub(rec.lastSeen) > s.cfg.Idle {
		return true
	}
	if s.cfg.Absolute == 0 {
		return false
	}
	return now.Sub(rec.created) > s.cfg.Absolute
}

func (s *Store) sweepLocked(now time.Time) bool {
	removed := false
	for k, rec := range s.sessions {
		if s.expired(rec, now) {
			delete(s.sessions, k)
			removed = true
		}
	}
	return removed
}

func (s *Store) evictOldestLocked() bool {
	var oldest *record
	var key string
	for k, rec := range s.sessions {
		if oldest == nil || rec.lastSeen.Before(oldest.lastSeen) {
			oldest = rec
			key = k
		}
	}
	if key == "" {
		return false
	}
	delete(s.sessions, key)
	return true
}

func (s *Store) notify() {
	s.mu.Lock()
	fns := make([]func(), len(s.hooks))
	for i, h := range s.hooks {
		fns[i] = h.fn
	}
	s.mu.Unlock()
	for _, fn := range fns {
		if fn != nil {
			fn()
		}
	}
}

func (s *Store) csrfMatch(want, got string) bool {
	if s.cfg.CSRFCompare == HexOrRawConstantTime {
		return hexOrRaw(got, want)
	}
	sumG := sha256.Sum256([]byte(got))
	sumW := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(sumG[:], sumW[:]) == 1
}

func hexOrRaw(got, want string) bool {
	gb, errG := hex.DecodeString(got)
	wb, errW := hex.DecodeString(want)
	if errG != nil || errW != nil || len(gb) != len(wb) {
		if len(got) != len(want) {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
	}
	return subtle.ConstantTimeCompare(gb, wb) == 1
}

func (rec *record) view() Session {
	out := rec.public
	out.Principal = copyPrincipal(rec.public.Principal)
	return out
}

func copyPrincipal(p scope.Principal) scope.Principal {
	p.Scopes = append([]string(nil), p.Scopes...)
	p.Groups = append([]string(nil), p.Groups...)
	return p
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", kerr.New(kerr.Internal, "session: entropy unavailable")
	}
	return hex.EncodeToString(b), nil
}
