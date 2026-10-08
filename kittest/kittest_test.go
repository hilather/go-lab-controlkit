package kittest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-controlkit/audit"
	"github.com/hilather/go-lab-controlkit/authn"
	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/mcpstrict"
	"github.com/hilather/go-lab-controlkit/scope"
	"github.com/hilather/go-lab-controlkit/session"
)

const (
	secretA = "0123456789abcdef0123456789abcdef"
	secretB = "abcdef0123456789abcdef0123456789"
	secretC = "fedcba9876543210fedcba9876543210"
)

func TestSuitesReferenceAndSeeded(t *testing.T) {
	cases := []struct {
		name string
		ok   func(t *testing.T)
		bad  func(Testing)
	}{
		{"StdioRotation", func(t *testing.T) { StdioRotation(t, newStdio(t, "")) }, func(tb Testing) { StdioRotation(tb, newStdio(nil, "rotate")) }},
		{"ResetUnreadableSecret", func(t *testing.T) { ResetUnreadableSecret(t, newResetFail(t, false)) }, func(tb Testing) { ResetUnreadableSecret(tb, newResetFail(nil, true)) }},
		{"ResetZeroTokens", func(t *testing.T) { ResetZeroTokens(t, newZero(false)) }, func(tb Testing) { ResetZeroTokens(tb, newZero(true)) }},
		{"ApplyNoSecretRead", func(t *testing.T) { ApplyNoSecretRead(t, newApply(false)) }, func(tb Testing) { ApplyNoSecretRead(tb, newApply(true)) }},
		{"ResetLoadOnce", func(t *testing.T) { ResetLoadOnce(t, newLoadOnce(false)) }, func(tb Testing) { ResetLoadOnce(tb, newLoadOnce(true)) }},
		{"ResetPrepareRace", func(t *testing.T) { ResetPrepareRace(t, newRace(t, false)) }, func(tb Testing) { ResetPrepareRace(tb, newRace(nil, true)) }},
		{"BootManagementOffNoSecretRead", func(t *testing.T) { BootManagementOffNoSecretRead(t, newBoot(t, false)) }, func(tb Testing) { BootManagementOffNoSecretRead(tb, newBoot(nil, true)) }},
		{"StreamRevocation", func(t *testing.T) { StreamRevocation(t, newStream("")) }, func(tb Testing) { StreamRevocation(tb, newStream("delete")) }},
		{"ManagementRebindOverAPI", func(t *testing.T) {
			for _, v := range []RebindVariant{RebindMove, RebindOff, RebindTaken, RebindSame, RebindRefuse, RebindKeep} {
				ManagementRebindOverAPI(t, newRebind(t, v, false))
			}
		}, func(tb Testing) { ManagementRebindOverAPI(tb, newRebind(nil, RebindMove, true)) }},
		{"CatalogCoversTools", func(t *testing.T) { CatalogCoversTools(t, newCatalog(false)) }, func(tb Testing) { CatalogCoversTools(tb, newCatalog(true)) }},
		{"IdentityChangeClearsSessions", func(t *testing.T) { IdentityChangeClearsSessions(t, newIdentity(false)) }, func(tb Testing) { IdentityChangeClearsSessions(tb, newIdentity(true)) }},
		{"DeniedAudited", func(t *testing.T) { DeniedAudited(t, newDenied(false)) }, func(tb Testing) { DeniedAudited(tb, newDenied(true)) }},
		{"DeniedGuardFlood", func(t *testing.T) { DeniedGuardFlood(t, newFlood(false)) }, func(tb Testing) { DeniedGuardFlood(tb, newFlood(true)) }},
		{"MCPStrictInput", func(t *testing.T) { MCPStrictInput(t, newStrict(false)) }, func(tb Testing) { MCPStrictInput(tb, newStrict(true)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ok(t)
			fake := runFake(tc.bad)
			if !fake.failed {
				t.Fatalf("seeded bug did not fail the suite: %v", fake.msgs)
			}
		})
	}
}

type fakeTB struct {
	mu     sync.Mutex
	failed bool
	msgs   []string
}

func (f *fakeTB) Helper() {}
func (f *fakeTB) Errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = true
	f.msgs = append(f.msgs, fmt.Sprintf(format, args...))
}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.Errorf(format, args...)
	runtime.Goexit()
}
func (f *fakeTB) Failed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failed
}
func (f *fakeTB) Logf(string, ...any) {}
func (f *fakeTB) Name() string        { return "fake" }

func runFake(fn func(Testing)) *fakeTB {
	f := &fakeTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	return f
}

func roleTable() scope.Table {
	return scope.Table{Roles: map[string][]string{
		"administrator": {"admin", "read"},
		"operator":      {"read"},
		"viewer":        {"other"},
	}}
}

func matRole(secret, role string) *authn.Material {
	m, err := authn.Load(authn.Config{
		Mode:       authn.ModeBearer,
		Duplicates: authn.RejectDuplicateValue,
		Roles:      roleTable(),
		Source: authn.Memory([]authn.RawToken{{
			ID: "ada", Role: role, Secret: authn.NewSecret([]byte(secret)),
		}}),
	})
	if err != nil {
		panic(err)
	}
	return m
}

func matMode(mode authn.Mode, secret, role string, accept func(*authn.Material) error) *authn.Material {
	var toks []authn.RawToken
	if secret != "" {
		toks = []authn.RawToken{{ID: "ada", Role: role, Secret: authn.NewSecret([]byte(secret))}}
	}
	m, err := authn.Load(authn.Config{
		Mode: mode, Duplicates: authn.RejectDuplicateValue, Roles: roleTable(),
		Source: authn.Memory(toks), Accept: accept,
	})
	if err != nil {
		panic(err)
	}
	return m
}

func mustVer(m *authn.Material) *authn.Verifier {
	v, err := authn.NewVerifier(m)
	if err != nil {
		panic(err)
	}
	return v
}

func mustSess() *session.Store {
	s, err := session.New(session.Config{
		CookieName: "lab_session", CSRFHeader: "X-Lab-CSRF",
		Idle: time.Hour, Absolute: 4 * time.Hour, Max: 8,
		AtCap: session.EvictOldest, IDShape: session.SeparateCookieSecret,
		CSRFCompare: session.DigestConstantTime,
	})
	if err != nil {
		panic(err)
	}
	return s
}

func login(s *session.Store) string {
	iss, err := s.Create(scope.Principal{ID: "ada", Class: "token", Role: "administrator", Scopes: []string{"admin", "read"}})
	if err != nil {
		panic(err)
	}
	return iss.Cookie
}

type stdioRef struct {
	v     *authn.Verifier
	pin   *authn.StdioPin
	loopV *authn.Verifier
	loop  *authn.StdioPin
	step  string
	bug   string
}

func newStdio(t *testing.T, bug string) *stdioRef {
	v := mustVer(matRole(secretA, "administrator"))
	pin, err := authn.NewStdioPin(v, authn.NewSecret([]byte(secretA)))
	if err != nil {
		panic(err)
	}
	lv := mustVer(matMode(authn.ModeDevLoopbackUnauth, "", "", nil))
	lp, err := authn.NewDevLoopbackStdio(lv, scope.Principal{ID: "loop", Class: "loopback", Role: "administrator"})
	if err != nil {
		panic(err)
	}
	_ = t
	return &stdioRef{v: v, pin: pin, loopV: lv, loop: lp, bug: bug}
}

func (d *stdioRef) Call(_ context.Context, tool string) ToolResult {
	if d.bug == "rotate" && d.step == "rotate" {
		return ToolResult{Code: "ok", HandlerRan: true, Scopes: []string{"admin", "read"}}
	}
	p, err := d.pin.Resolve()
	if err != nil {
		return ToolResult{Code: "unauthenticated"}
	}
	if tool == "unmapped" {
		return ToolResult{Code: "ok", HandlerRan: true, Scopes: append([]string(nil), p.Scopes...)}
	}
	return ToolResult{Code: "ok", HandlerRan: true, Scopes: append([]string(nil), p.Scopes...)}
}

func (d *stdioRef) Reset(_ context.Context, step string) error {
	d.step = step
	switch step {
	case "demote":
		d.v.Swap(matRole(secretA, "operator"))
	case "rotate":
		d.v.Swap(matRole(secretB, "administrator"))
	case "remove":
		d.v.Swap(matRole(secretC, "administrator"))
	case "restore":
		d.v.Swap(matRole(secretA, "administrator"))
	case "reject":
		return errors.New("unreadable")
	default:
		return errors.New("unknown step")
	}
	return nil
}

func (d *stdioRef) Loopback(_ context.Context, step string) (ToolResult, bool) {
	if step == "after" {
		d.loopV.Swap(matRole(secretA, "administrator"))
	}
	if _, err := d.loop.Resolve(); err != nil {
		return ToolResult{Code: "unauthenticated"}, true
	}
	return ToolResult{Code: "ok", HandlerRan: true, Scopes: []string{"admin"}}, true
}

type resetFailRef struct {
	v         *authn.Verifier
	s         *session.Store
	cookie    string
	rev       string
	side      int
	listeners []string
	bug       bool
}

func newResetFail(_ *testing.T, bug bool) *resetFailRef {
	v := mustVer(matRole(secretA, "administrator"))
	s := mustSess()
	if _, err := s.Bind(v); err != nil {
		panic(err)
	}
	return &resetFailRef{
		v: v, s: s, cookie: login(s), rev: "rev-1", side: 3,
		listeners: []string{"127.0.0.1:9"}, bug: bug,
	}
}

func (d *resetFailRef) Code() string { return "validation_failed" }

func (d *resetFailRef) Observe(context.Context) ResetView {
	_, err := d.v.AuthenticateBearer([]byte(secretA))
	_, ok := d.s.Lookup(d.cookie)
	return ResetView{
		Revision: d.rev, SideEffects: d.side, Listeners: append([]string(nil), d.listeners...),
		BearerWorks: err == nil, SessionWorks: ok,
	}
}

func (d *resetFailRef) Reset(context.Context, string) (string, error) {
	if d.bug {
		d.v.Swap(matMode(authn.ModeBearer, "", "", nil))
		d.s.Clear()
		d.rev = "rev-2"
		return "", nil
	}
	return d.Code(), nil
}

type zeroRef struct{ bug bool }

func newZero(bug bool) *zeroRef { return &zeroRef{bug: bug} }

func (d *zeroRef) Shapes() []ZeroTokenShape {
	return []ZeroTokenShape{ZeroNTPBearer, ZeroNTPLoopback, ZeroNetconf, ZeroSNMP, ZeroMaildevBearer, ZeroMaildevBasic, ZeroMaildevLoopback}
}

func (d *zeroRef) Apply(_ context.Context, shape ZeroTokenShape) ZeroTokenResult {
	if d.bug && shape == ZeroSNMP {
		return ZeroTokenResult{OldBearerWorks: true, OldCookieWorks: false}
	}
	v := mustVer(matRole(secretA, "administrator"))
	s := mustSess()
	if _, err := s.Bind(v); err != nil {
		panic(err)
	}
	cookie := login(s)
	mode := authn.ModeBearer
	var accept func(*authn.Material) error
	switch shape {
	case ZeroNTPBearer:
		accept = authn.BearerNeedsToken(true)
	case ZeroNTPLoopback:
		mode = authn.ModeDevLoopbackUnauth
		accept = authn.BearerNeedsToken(true)
	case ZeroNetconf:
		accept = authn.BearerNeedsToken(false)
	case ZeroMaildevBasic:
		mode = authn.ModeBearerAndBasic
	case ZeroMaildevLoopback:
		mode = authn.ModeDevLoopbackUnauth
	}
	rev := 1
	st, err := authn.Prepare(authn.Config{
		Mode: mode, Duplicates: authn.RejectDuplicateValue, Roles: roleTable(),
		Source: authn.Memory(nil), Accept: accept,
	})
	if err != nil {
		panic(err)
	}
	if st.Err() != nil {
		_, berr := v.AuthenticateBearer([]byte(secretA))
		_, ok := s.Lookup(cookie)
		return ZeroTokenResult{Code: "validation_failed", OldBearerWorks: berr == nil, OldCookieWorks: ok, RevisionUnchanged: true}
	}
	if st.Commit(v) {
		rev++
	}
	_, berr := v.AuthenticateBearer([]byte(secretA))
	_, ok := s.Lookup(cookie)
	return ZeroTokenResult{OldBearerWorks: berr == nil, OldCookieWorks: ok, RevisionUnchanged: rev == 1}
}

type applyRef struct {
	v      *authn.Verifier
	s      *session.Store
	cookie string
	opens  int
	bug    bool
}

func newApply(bug bool) *applyRef {
	v := mustVer(matRole(secretA, "administrator"))
	s := mustSess()
	return &applyRef{v: v, s: s, cookie: login(s), bug: bug}
}

func (d *applyRef) MakeUnreadable(context.Context) {}
func (d *applyRef) Apply(context.Context) (bool, int) {
	if d.bug {
		d.opens++
	}
	return true, d.opens
}
func (d *applyRef) BearerWorks(context.Context) bool {
	_, err := d.v.AuthenticateBearer([]byte(secretA))
	return err == nil
}
func (d *applyRef) SessionWorks(context.Context) bool {
	_, ok := d.s.Lookup(d.cookie)
	return ok
}

type countSrc struct {
	n     *int
	inner authn.TokenSource
	id    string
	sec   string
}

func (c *countSrc) Read() ([]authn.RawToken, []authn.FileResult, error) {
	*c.n++
	if c.inner != nil {
		return c.inner.Read()
	}
	return []authn.RawToken{{
		ID: c.id, Role: "administrator", Secret: authn.NewSecret([]byte(c.sec)),
	}}, nil, nil
}
func (c *countSrc) Spec() any {
	if c.inner != nil {
		return c.inner.Spec()
	}
	return struct {
		ID  string `json:"id"`
		Sec string `json:"sec"`
	}{c.id, hexOf(c.sec)}
}

func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:8])
}

type loadOnceRef struct{ bug bool }

func newLoadOnce(bug bool) *loadOnceRef { return &loadOnceRef{bug: bug} }

func (d *loadOnceRef) Variants() []string {
	return []string{"omit-mode", "listen-override", "management-off", "unreadable-between"}
}

func (d *loadOnceRef) Reset(_ context.Context, variant string) (int, bool) {
	n := 0
	src := &countSrc{n: &n, id: "ada", sec: secretA}
	cfg := authn.Config{Mode: authn.ModeBearer, Source: src, Duplicates: authn.RejectDuplicateValue, Roles: roleTable()}
	switch variant {
	case "listen-override":
		cfg.Accept = authn.BearerNeedsToken(true)
	case "management-off":
		cfg.ManagementBound = false
	}
	st, err := authn.Prepare(cfg)
	if err != nil || st.Err() != nil {
		return n, false
	}
	if !st.Commit(authn.Empty()) {
		return n, false
	}
	if d.bug && variant == "omit-mode" {
		return n + 1, true
	}
	return n, true
}

type raceRef struct {
	dir string
	bug bool
}

func newRace(t *testing.T, bug bool) *raceRef {
	dir := tdir(t)
	writeFile(filepath.Join(dir, "valid"), secretA+"\n", 0600)
	writeFile(filepath.Join(dir, "short"), "x\n", 0600)
	writeFile(filepath.Join(dir, "other"), secretB+"\n", 0600)
	return &raceRef{dir: dir, bug: bug}
}

func (d *raceRef) FailureCode() string { return "validation_failed" }

func (d *raceRef) Case(_ context.Context, n int) RaceResult {
	opts := authn.FileOpts{Line: authn.FirstNonCommentLine, Resolve: authn.AsGiven}
	reads := 0
	file := filepath.Join(d.dir, "valid")
	staleSrc := &countSrc{n: &reads, inner: authn.PerTokenFiles([]authn.FileToken{{
		ID: "ada", Role: "administrator", SecretFile: file,
	}}, opts)}
	stale, err := authn.Prepare(authn.Config{
		Mode: authn.ModeBearer, Source: staleSrc, Duplicates: authn.RejectDuplicateValue,
		Roles: roleTable(), MinSecretBytes: 32,
	})
	if err != nil || stale.Err() != nil {
		return RaceResult{Code: "prepare", Reads: reads}
	}
	nextName := "short"
	if n == 2 {
		nextName = "other"
	}
	nextSrc := &countSrc{n: &reads, inner: authn.PerTokenFiles([]authn.FileToken{{
		ID: "ada", Role: "administrator", SecretFile: filepath.Join(d.dir, nextName),
	}}, opts)}
	next, err := authn.Prepare(authn.Config{
		Mode: authn.ModeBearer, Source: nextSrc, Duplicates: authn.RejectDuplicateValue,
		Roles: roleTable(), MinSecretBytes: 32,
	})
	if err != nil {
		return RaceResult{Code: "prepare", Reads: reads}
	}
	if d.bug && n == 1 {
		stale.Commit(authn.Empty())
		return RaceResult{Code: d.FailureCode(), Discarded: true, Reads: reads, CommittedNew: true, Field: "tokens[0].secretFile"}
	}
	stale.Discard()
	v := mustVer(matRole(secretA, "administrator"))
	committed := false
	field := ""
	if next.Err() != nil {
		var le *authn.LoadError
		if errors.As(next.Err(), &le) {
			field = le.Field
		}
		return RaceResult{Code: d.FailureCode(), Discarded: true, Reads: reads, Field: field}
	}
	committed = next.Commit(v)
	_, err = v.AuthenticateBearer([]byte(secretB))
	return RaceResult{Discarded: true, Reads: reads, CommittedNew: committed && err == nil, Field: "tokens[0].secretFile"}
}

type bootRef struct {
	dir string
	bug bool
}

func newBoot(t *testing.T, bug bool) *bootRef { return &bootRef{dir: tdir(t), bug: bug} }

func (d *bootRef) Boot(_ context.Context, arm, files string) BootResult {
	if arm == "off" {
		if d.bug {
			return BootResult{Booted: true, DataPlaneOK: true, SecretOpens: 1}
		}
		if !authn.NotChecked().IsNotChecked() {
			return BootResult{Message: "not-checked stage missing"}
		}
		return BootResult{Booted: true, DataPlaneOK: true, SecretOpens: 0}
	}
	path := filepath.Join(d.dir, arm+"-"+files)
	switch files {
	case "short":
		writeFile(path, "short\n", 0600)
	case "mode000":
		writeFile(path, secretA+"\n", 0000)
		if os.Geteuid() == 0 {
			os.Remove(path)
			os.Mkdir(path, 0700)
		}
	}
	reads := 0
	src := &countSrc{n: &reads, inner: authn.PerTokenFiles([]authn.FileToken{{
		ID: "ada", Role: "administrator", SecretFile: path,
	}}, authn.FileOpts{Line: authn.FirstNonCommentLine, Resolve: authn.AsGiven})}
	st, err := authn.Prepare(authn.Config{
		Mode: authn.ModeBearer, Source: src, Duplicates: authn.RejectDuplicateValue,
		Roles: roleTable(), MinSecretBytes: 32, ManagementBound: true,
	})
	if err != nil {
		return BootResult{Message: err.Error(), SecretOpens: reads}
	}
	if st.Err() != nil {
		return BootResult{Message: st.Err().Error(), SecretOpens: reads}
	}
	return BootResult{Booted: true, DataPlaneOK: true, SecretOpens: reads}
}

type streamState struct {
	v      *authn.Verifier
	s      *session.Store
	wake   *authn.Wake
	cookie string
	cur    *time.Time
}

type streamRef struct{ bug string }

func newStream(bug string) *streamRef { return &streamRef{bug: bug} }

func (d *streamRef) boot() *streamState {
	v := mustVer(matRole(secretA, "administrator"))
	s, err := session.New(session.Config{
		CookieName: "lab_session", CSRFHeader: "X-Lab-CSRF",
		Idle: time.Hour, Absolute: 4 * time.Hour, Max: 2,
		AtCap: session.EvictOldest, IDShape: session.SeparateCookieSecret,
		CSRFCompare: session.DigestConstantTime,
	})
	if err != nil {
		panic(err)
	}
	cur := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.SetNow(func() time.Time { return cur })
	if _, err := s.Bind(v); err != nil {
		panic(err)
	}
	w, _, err := session.RevocationWake(v, s)
	if err != nil {
		panic(err)
	}
	iss, err := s.Create(scope.Principal{ID: "ada", Role: "administrator", Scopes: []string{"admin", "read"}})
	if err != nil {
		panic(err)
	}
	return &streamState{v: v, s: s, wake: w, cookie: iss.Cookie, cur: &cur}
}

func (st *streamState) recheck(kind StreamKind) bool {
	if kind == StreamBearer {
		p, err := st.v.AuthenticateBearer([]byte(secretA))
		if err != nil {
			return false
		}
		for _, s := range p.Scopes {
			if s == "read" {
				return true
			}
		}
		return false
	}
	_, ok := st.s.Lookup(st.cookie)
	return ok
}

func (st *streamState) fire(trigger string) {
	switch trigger {
	case "demote":
		st.v.Swap(matRole(secretA, "viewer"))
	case "remove-bearer":
		st.v.Swap(matRole(secretB, "administrator"))
	case "delete":
		st.s.Delete(st.cookie)
	case "delete-other":
		*st.cur = st.cur.Add(time.Minute)
		iss, err := st.s.Create(scope.Principal{ID: "bea", Role: "operator"})
		if err != nil {
			panic(err)
		}
		st.s.Delete(iss.Cookie)
	case "evict":
		*st.cur = st.cur.Add(time.Minute)
		if _, err := st.s.Create(scope.Principal{ID: "bea", Role: "operator"}); err != nil {
			panic(err)
		}
		*st.cur = st.cur.Add(time.Minute)
		if _, err := st.s.Create(scope.Principal{ID: "cy", Role: "operator"}); err != nil {
			panic(err)
		}
	case "keep-scope":
		st.v.Swap(matRole(secretA, "operator"))
	}
}

func (d *streamRef) Run(_ context.Context, kind StreamKind, trigger string) StreamEnd {
	if d.bug == "delete" && kind == StreamCookie && trigger == "delete" {
		return StreamEnd{WithinBudget: true}
	}
	st := d.boot()
	ch := st.wake.Subscribe()
	if !st.recheck(kind) {
		return StreamEnd{}
	}
	start := time.Now()
	st.fire(trigger)
	end := StreamEnd{}
	select {
	case <-ch:
		end.Rechecked = true
		if !st.recheck(kind) {
			end.Ended = true
		}
	case <-time.After(500 * time.Millisecond):
	}
	end.WithinBudget = time.Since(start) < 500*time.Millisecond
	return end
}

func (d *streamRef) MCPGet(context.Context) int { return 405 }

func (d *streamRef) LazyExpiry(context.Context) (bool, bool) {
	idleEnded := expireAfter(time.Hour, 4*time.Hour, time.Hour+time.Nanosecond)
	absEnded := expireAfter(10*time.Hour, time.Hour, time.Hour+time.Nanosecond)
	return idleEnded, absEnded
}

func expireAfter(idle, absolute, jump time.Duration) bool {
	s, err := session.New(session.Config{
		CookieName: "lab_session", CSRFHeader: "X-Lab-CSRF",
		Idle: idle, Absolute: absolute, Max: 4,
		AtCap: session.EvictOldest, IDShape: session.SeparateCookieSecret,
		CSRFCompare: session.DigestConstantTime,
	})
	if err != nil {
		panic(err)
	}
	cur := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	s.SetNow(func() time.Time { return cur })
	iss, err := s.Create(scope.Principal{ID: "ada", Role: "administrator"})
	if err != nil {
		panic(err)
	}
	cur = cur.Add(jump)
	_, ok := s.Lookup(iss.Cookie)
	return !ok
}

type rebindRef struct {
	t       *testing.T
	variant RebindVariant
	bug     bool
}

func newRebind(t *testing.T, v RebindVariant, bug bool) *rebindRef {
	return &rebindRef{t: t, variant: v, bug: bug}
}
func (d *rebindRef) Variant() RebindVariant { return d.variant }

func (d *rebindRef) Run(context.Context) RebindObs {
	if d.bug {
		return RebindObs{Elapsed: 2 * time.Second, NewServes: true, OldRefuses: true, RevisionChanged: true}
	}
	start := time.Now()
	switch d.variant {
	case RebindMove:
		old := serve(d.t, "old")
		neu := serve(d.t, "new")
		stop(old)
		body, ok := getOK(neu.url)
		return RebindObs{Elapsed: time.Since(start), NewServes: ok && body == "new", OldRefuses: refuses(old.addr), RevisionChanged: true}
	case RebindOff:
		ln := serve(d.t, "ok")
		body, ok := getOK(ln.url)
		stop(ln)
		return RebindObs{Elapsed: time.Since(start), ResponseIntact: ok && body == "ok", OldRefuses: refuses(ln.addr)}
	case RebindTaken:
		old := serve(d.t, "old")
		busy, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		d.t.Cleanup(func() { busy.Close() })
		_, err = net.Listen("tcp", busy.Addr().String())
		return RebindObs{Elapsed: time.Since(start), Code: "address in use", OldStillServes: err != nil && getAlive(old.url)}
	case RebindSame:
		old := serve(d.t, "same")
		_, ok := getOK(old.url)
		return RebindObs{Elapsed: time.Since(start), OldStillServes: ok}
	case RebindRefuse:
		old := serve(d.t, "stay")
		_, ok := getOK(old.url)
		return RebindObs{Elapsed: time.Since(start), Code: "validation_failed", OldStillServes: ok}
	default:
		old := serve(d.t, "keep")
		_, ok := getOK(old.url)
		return RebindObs{Elapsed: time.Since(start), OldStillServes: ok}
	}
}

type listener struct {
	url  string
	addr string
	srv  *http.Server
}

func serve(t *testing.T, body string) *listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &listener{url: "http://" + ln.Addr().String(), addr: ln.Addr().String(), srv: srv}
}

func stop(l *listener) { l.srv.Close() }

func getOK(url string) (string, bool) {
	for i := 0; i < 40; i++ {
		resp, err := http.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(b), resp.StatusCode == 200
		}
		time.Sleep(5 * time.Millisecond)
	}
	return "", false
}

func getAlive(url string) bool {
	_, ok := getOK(url)
	return ok
}

func refuses(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return true
	}
	c.Close()
	return false
}

type miniCat struct{}

func (miniCat) Required(id string) ([]string, bool) {
	if id == "read" || id == "write" {
		return []string{id}, true
	}
	return nil, false
}
func (miniCat) ToolCaps(tool string) []string {
	switch tool {
	case "state_get":
		return []string{"read"}
	case "state_apply":
		return []string{"write"}
	default:
		return nil
	}
}
func (miniCat) ResourceCaps(string) []string { return nil }

type catalogRef struct {
	gate *scope.Gate
	bug  bool
}

func newCatalog(bug bool) *catalogRef {
	g, err := scope.NewGate(scope.Gate{
		Eval:     roleTable(),
		Catalog:  miniCat{},
		Unmapped: scope.Forbid,
	})
	if err != nil {
		panic(err)
	}
	return &catalogRef{gate: g, bug: bug}
}

func (d *catalogRef) Registered(context.Context) []string {
	names := []string{"state_get", "state_apply"}
	if d.bug {
		names = append(names, "extra")
	}
	return names
}
func (d *catalogRef) InCatalog(name string) bool {
	return name == "state_get" || name == "state_apply"
}
func (d *catalogRef) Call(context.Context, string) string { return "ok" }
func (d *catalogRef) CallUnmapped(ctx context.Context) string {
	p := scope.Principal{ID: "ada", Role: "administrator", Scopes: []string{"admin", "read"}}
	err := d.gate.Tool(ctx, p, "missing")
	if err == nil {
		return "ok"
	}
	if k, ok := kerr.KindOf(err); ok && k == kerr.Forbidden {
		return "forbidden"
	}
	return err.Error()
}

type idRef struct {
	v   *authn.Verifier
	s   *session.Store
	bug bool
}

func newIdentity(bug bool) *idRef { return &idRef{bug: bug} }

func (d *idRef) Boot(_ context.Context, order IdentityOrder) {
	d.v = mustVer(matRole(secretA, "administrator"))
	d.s = mustSess()
	if d.bug && order == OrderReverse {
		return
	}
	if order == OrderProduction {
		d.s.Bind(d.v)
		d.v.OnIdentityChange(func() {})
	} else {
		d.v.OnIdentityChange(func() {})
		d.s.Bind(d.v)
	}
}
func (d *idRef) Login(context.Context) string { return login(d.s) }
func (d *idRef) Demote(context.Context)       { d.v.Swap(matRole(secretA, "viewer")) }
func (d *idRef) CookieWorks(_ context.Context, cookie string) bool {
	_, ok := d.s.Lookup(cookie)
	return ok
}

type denyRef struct {
	rec   *audit.CountRecorder
	guard *audit.DeniedGuard
	clock time.Time
	bug   bool
}

func newDenied(bug bool) *denyRef {
	rec := &audit.CountRecorder{}
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	g, err := audit.NewDeniedGuard(rec, func() time.Time { return clock })
	if err != nil {
		panic(err)
	}
	return &denyRef{rec: rec, guard: g, clock: clock, bug: bug}
}

func (d *denyRef) bump(code, cap string, status int) (int, int) {
	before := len(d.rec.Events())
	ev := audit.DeniedEvent{Time: d.clock, ActorID: "ada", ActorClass: "token", Transport: "rest", Capability: cap, ErrorCode: code, RemoteKey: "127.0.0.1"}
	d.guard.RecordDenied(context.Background(), ev)
	if d.bug && code == "bad_bearer" {
		d.guard.RecordDenied(context.Background(), ev)
	}
	d.clock = d.clock.Add(time.Second)
	return status, len(d.rec.Events()) - before
}
func (d *denyRef) Routes(context.Context) []string { return []string{"/v1/state", "/v1/audit"} }
func (d *denyRef) Tools(context.Context) []string  { return []string{"state_apply"} }
func (d *denyRef) DenyRoute(_ context.Context, route string) (int, int) {
	return d.bump("forbidden", route, 403)
}
func (d *denyRef) DenyTool(_ context.Context, tool string) (int, int) {
	return d.bump("forbidden", tool, 403)
}
func (d *denyRef) BadBearer(context.Context) (int, int)   { return d.bump("bad_bearer", "", 401) }
func (d *denyRef) StaleCookie(context.Context) (int, int) { return d.bump("session_expired", "", 401) }
func (d *denyRef) CSRFMiss(context.Context) (int, int)    { return d.bump("csrf_invalid", "", 403) }

type floodRow struct {
	ID     string
	Denied bool
}

type floodRef struct{ bug bool }

func newFlood(bug bool) *floodRef { return &floodRef{bug: bug} }

func (d *floodRef) Flood(_ context.Context, n int) (int, uint64, bool) {
	ring, err := audit.NewRing[floodRow](audit.RingOptions[floodRow]{
		Max: 8, DeniedShare: 0.5,
		SetID:    func(e *floodRow, id string) { e.ID = id },
		IsDenied: func(e floodRow) bool { return e.Denied },
	})
	if err != nil {
		panic(err)
	}
	ring.Append(floodRow{})
	rec := &audit.CountRecorder{}
	g, err := audit.NewDeniedGuard(rec, nil)
	if err != nil {
		panic(err)
	}
	admitted := 0
	for i := 0; i < n; i++ {
		ev := audit.DeniedEvent{ActorID: "ada", ErrorCode: "forbidden"}
		if d.bug {
			admitted++
			ring.Append(floodRow{Denied: true})
			continue
		}
		if g.Admit(ev) {
			admitted++
			ring.Append(floodRow{Denied: true})
		}
	}
	okSurvived := false
	for _, row := range ring.List(ring.Len()) {
		if !row.Denied {
			okSurvived = true
		}
	}
	if d.bug {
		return admitted, 0, okSurvived
	}
	return admitted, g.Suppressed(), okSurvived
}

type strictRef struct {
	rev string
	bug bool
}

func newStrict(bug bool) *strictRef { return &strictRef{rev: "rev-1", bug: bug} }

func (d *strictRef) Tools(context.Context) []string  { return []string{"lab_version_get"} }
func (d *strictRef) Revision(context.Context) string { return d.rev }
func (d *strictRef) GapPayloads(string) []json.RawMessage {
	return []json.RawMessage{[]byte(`{"a":1,"a":2}`), []byte(`{"view":{"mode":"rate","minPoll":1}}`)}
}
func (d *strictRef) ValidPayloads(string) []json.RawMessage {
	return []json.RawMessage{[]byte(`{}`), []byte(`{"view":{"mode":"rate","leap":"none"}}`)}
}
func (d *strictRef) Call(_ context.Context, _ string, args json.RawMessage) (string, string) {
	if d.bug {
		return "ok", d.rev
	}
	spec := mcpstrict.Spec{Typed: map[string]mcpstrict.KeySet{
		"/view": {Keys: map[string]bool{"mode": true, "leap": true, "stratum": true, "refid": true}},
	}}
	if err := mcpstrict.Check(args, spec); err != nil {
		return "invalid", d.rev
	}
	return "ok", d.rev
}

func tdir(t *testing.T) string {
	if t == nil {
		dir, err := os.MkdirTemp("", "kittest")
		if err != nil {
			panic(err)
		}
		return dir
	}
	return t.TempDir()
}

func writeFile(path, body string, mode os.FileMode) {
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		panic(err)
	}
	if mode == 0 {
		if err := os.Chmod(path, 0); err != nil {
			panic(err)
		}
	}
}
