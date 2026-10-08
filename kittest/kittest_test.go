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
	"strings"
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
		bad  []func(Testing)
	}{
		{"StdioRotation", func(t *testing.T) { StdioRotation(t, newStdio(t, "")) }, []func(Testing){
			func(tb Testing) { StdioRotation(tb, newStdio(nil, "rotate")) },
			func(tb Testing) { StdioRotation(tb, newStdio(nil, "code")) },
			func(tb Testing) { StdioRotation(tb, newStdio(nil, "loop-code")) },
			func(tb Testing) { StdioRotation(tb, newStdio(nil, "scopes")) },
			func(tb Testing) { StdioRotation(tb, newStdio(nil, "no-drop")) },
		}},
		{"ResetUnreadableSecret", func(t *testing.T) { ResetUnreadableSecret(t, newResetFail(t, false)) }, []func(Testing){
			func(tb Testing) { ResetUnreadableSecret(tb, newResetFail(nil, true)) },
		}},
		{"ResetZeroTokens", func(t *testing.T) { ResetZeroTokens(t, newZero(false)) }, []func(Testing){
			func(tb Testing) { ResetZeroTokens(tb, newZero(true)) },
		}},
		{"ApplyNoSecretRead", func(t *testing.T) { ApplyNoSecretRead(t, newApply(t, "")) }, []func(Testing){
			func(tb Testing) { ApplyNoSecretRead(tb, newApply(nil, "read")) },
			func(tb Testing) { ApplyNoSecretRead(tb, newApply(nil, "reset")) },
			func(tb Testing) { ApplyNoSecretRead(tb, newApply(nil, "missing-open")) },
			func(tb Testing) { ApplyNoSecretRead(tb, newApply(nil, "missing-lockout")) },
		}},
		{"ResetLoadOnce", func(t *testing.T) { ResetLoadOnce(t, newLoadOnce(t, false)) }, []func(Testing){
			func(tb Testing) { ResetLoadOnce(tb, newLoadOnce(nil, true)) },
		}},
		{"ResetPrepareRace", func(t *testing.T) { ResetPrepareRace(t, newRace(t, false)) }, []func(Testing){
			func(tb Testing) { ResetPrepareRace(tb, newRace(nil, true)) },
		}},
		{"BootManagementOffNoSecretRead", func(t *testing.T) {
			BootManagementOffNoSecretRead(t, newBoot(t, bootMulti, ""))
			BootManagementOffNoSecretRead(t, newBoot(t, bootPin, ""))
		}, []func(Testing){
			func(tb Testing) { BootManagementOffNoSecretRead(tb, newBoot(nil, bootMulti, "double")) },
			func(tb Testing) { BootManagementOffNoSecretRead(tb, newBoot(nil, bootMulti, "message")) },
			func(tb Testing) { BootManagementOffNoSecretRead(tb, newBoot(nil, bootPin, "off-zero")) },
		}},
		{"StreamRevocation", func(t *testing.T) {
			StreamRevocation(t, newStream(""))
			StreamRevocation(t, newStream("wrote-open"))
		}, []func(Testing){
			func(tb Testing) { StreamRevocation(tb, newStream("delete")) },
			func(tb Testing) { StreamRevocation(tb, newStream("wrote-end")) },
			func(tb Testing) { StreamRevocation(tb, newStream("stay-ended")) },
		}},
		{"ManagementRebindOverAPI", func(t *testing.T) {
			for _, v := range []RebindVariant{RebindMove, RebindOff, RebindTaken, RebindSame, RebindRefuse, RebindKeep} {
				ManagementRebindOverAPI(t, newRebind(t, v, ""))
			}
		}, []func(Testing){
			func(tb Testing) { ManagementRebindOverAPI(tb, newRebind(nil, RebindMove, "slow")) },
			func(tb Testing) { ManagementRebindOverAPI(tb, newRebind(nil, RebindRefuse, "code")) },
			func(tb Testing) { ManagementRebindOverAPI(tb, newRebind(nil, RebindTaken, "code")) },
		}},
		{"CatalogCoversTools", func(t *testing.T) { CatalogCoversTools(t, newCatalog(false)) }, []func(Testing){
			func(tb Testing) { CatalogCoversTools(tb, newCatalog(true)) },
		}},
		{"IdentityChangeClearsSessions", func(t *testing.T) { IdentityChangeClearsSessions(t, newIdentity(false)) }, []func(Testing){
			func(tb Testing) { IdentityChangeClearsSessions(tb, newIdentity(true)) },
		}},
		{"DeniedAudited", func(t *testing.T) { DeniedAudited(t, newDenied("")) }, []func(Testing){
			func(tb Testing) { DeniedAudited(tb, newDenied("double")) },
			func(tb Testing) { DeniedAudited(tb, newDenied("empty")) },
		}},
		{"DeniedGuardFlood", func(t *testing.T) { DeniedGuardFlood(t, newFlood(false)) }, []func(Testing){
			func(tb Testing) { DeniedGuardFlood(tb, newFlood(true)) },
		}},
		{"MCPStrictInput", func(t *testing.T) { MCPStrictInput(t, newStrict(false)) }, []func(Testing){
			func(tb Testing) { MCPStrictInput(tb, newStrict(true)) },
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ok(t)
			if len(tc.bad) == 0 {
				t.Fatal("no seeded bug")
			}
			for i, bad := range tc.bad {
				fake := runFake(bad)
				if !fake.failed {
					t.Fatalf("seeded bug %d did not fail the suite: %v", i, fake.msgs)
				}
			}
		})
	}
}

// TestApplyNoSecretReadMissingArmSeeded pins the two missing-file checks
// the "read" and "reset" bugs never reach. missing-open reports one open
// only after MakeMissing. missing-lockout drops the bearer and the cookie
// only on that apply. Each message is that check, so a driver caught
// earlier fails this test, and deleting the check leaves the driver green.
func TestApplyNoSecretReadMissingArmSeeded(t *testing.T) {
	open := runFake(func(tb Testing) {
		ApplyNoSecretRead(tb, newApply(nil, "missing-open"))
	})
	if !open.failed || len(open.msgs) != 1 || !strings.Contains(open.msgs[0], "missing apply ok") {
		t.Fatalf("missing-open: failed=%v msgs=%v", open.failed, open.msgs)
	}
	lock := runFake(func(tb Testing) {
		ApplyNoSecretRead(tb, newApply(nil, "missing-lockout"))
	})
	if !lock.failed || len(lock.msgs) != 1 || !strings.Contains(lock.msgs[0], "missing apply locked the admin out") {
		t.Fatalf("missing-lockout: failed=%v msgs=%v", lock.failed, lock.msgs)
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
	return matRoleIn(secret, role, roleTable())
}

func matRoleIn(secret, role string, roles scope.Table) *authn.Material {
	m, err := authn.Load(authn.Config{
		Mode:       authn.ModeBearer,
		Duplicates: authn.RejectDuplicateValue,
		Roles:      roles,
		Source: authn.Memory([]authn.RawToken{{
			ID: "ada", Role: role, Secret: authn.NewSecret([]byte(secret)),
		}}),
	})
	if err != nil {
		panic(err)
	}
	return m
}

// stdioAdminScopes and stdioOperatorScopes are syslog's ids. The reference
// must not use the labels "admin" and "read"; those are not a real table.
func stdioAdminScopes() []string {
	return []string{"syslog.read", "syslog.write", "syslog.admin", "syslog.audit.read"}
}

func stdioOperatorScopes() []string {
	return []string{"syslog.read"}
}

func stdioRoles() scope.Table {
	return scope.Table{Roles: map[string][]string{
		"administrator": stdioAdminScopes(),
		"operator":      stdioOperatorScopes(),
		"viewer":        {"syslog.audit.read"},
	}}
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
	roles := stdioRoles()
	v := mustVer(matRoleIn(secretA, "administrator", roles))
	pin, err := authn.NewStdioPin(v, authn.NewSecret([]byte(secretA)))
	if err != nil {
		panic(err)
	}
	lv := mustVer(matMode(authn.ModeDevLoopbackUnauth, "", "", nil))
	lp, err := authn.NewDevLoopbackStdio(lv, scope.Principal{
		ID: "loop", Class: "loopback", Role: "administrator", Scopes: stdioAdminScopes(),
	})
	if err != nil {
		panic(err)
	}
	_ = t
	return &stdioRef{v: v, pin: pin, loopV: lv, loop: lp, bug: bug}
}

// Code is syslog's wire code. A suite that hardcodes "unauthenticated" fails.
func (d *stdioRef) Code() string { return "unauthorized" }

func (d *stdioRef) StartupScopes() []string { return stdioAdminScopes() }

func (d *stdioRef) DemotedScopes() []string {
	if d.bug == "no-drop" {
		return stdioAdminScopes()
	}
	return stdioOperatorScopes()
}

func (d *stdioRef) Call(_ context.Context, tool string) ToolResult {
	if d.bug == "rotate" && d.step == "rotate" {
		return ToolResult{Code: "ok", HandlerRan: true, Scopes: stdioAdminScopes()}
	}
	if d.bug == "code" && (d.step == "rotate" || d.step == "remove") {
		return ToolResult{Code: "unauthenticated"}
	}
	if d.bug == "scopes" && d.step == "demote" {
		return ToolResult{Code: "ok", HandlerRan: true, Scopes: stdioAdminScopes()}
	}
	p, err := d.pin.Resolve()
	if err != nil {
		return ToolResult{Code: d.Code()}
	}
	if tool == "unmapped" {
		return ToolResult{Code: "ok", HandlerRan: true, Scopes: append([]string(nil), p.Scopes...)}
	}
	return ToolResult{Code: "ok", HandlerRan: true, Scopes: append([]string(nil), p.Scopes...)}
}

func (d *stdioRef) Reset(_ context.Context, step string) error {
	d.step = step
	roles := stdioRoles()
	switch step {
	case "demote":
		d.v.Swap(matRoleIn(secretA, "operator", roles))
	case "rotate":
		d.v.Swap(matRoleIn(secretB, "administrator", roles))
	case "remove":
		d.v.Swap(matRoleIn(secretC, "administrator", roles))
	case "restore":
		d.v.Swap(matRoleIn(secretA, "administrator", roles))
	case "reject":
		return errors.New("unreadable")
	default:
		return errors.New("unknown step")
	}
	return nil
}

func (d *stdioRef) Loopback(_ context.Context, step string) (ToolResult, bool) {
	if step == "after" {
		d.loopV.Swap(matRoleIn(secretA, "administrator", stdioRoles()))
	}
	p, err := d.loop.Resolve()
	if err != nil {
		code := d.Code()
		if d.bug == "loop-code" || d.bug == "code" {
			code = "unauthenticated"
		}
		return ToolResult{Code: code}, true
	}
	return ToolResult{Code: "ok", HandlerRan: true, Scopes: append([]string(nil), p.Scopes...)}, true
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
	path    string
	v       *authn.Verifier
	s       *session.Store
	cookie  string
	bug     string
	failTxt string
	// missing is set by MakeMissing. The missing-arm bugs read it so the
	// unreadable arm still looks like a good apply.
	missing bool
}

func newApply(t *testing.T, bug string) *applyRef {
	dir := tdir(t)
	path := filepath.Join(dir, "token")
	writeFile(path, secretA+"\n", 0600)
	st, err := prepareToken(path)
	if err != nil || st == nil || st.Err() != nil {
		panic(fmt.Sprintf("apply start: %v", stageErr(err, st)))
	}
	v := authn.Empty()
	if !st.Commit(v) {
		panic("apply start commit")
	}
	if _, err = v.AuthenticateBearer([]byte(secretA)); err != nil {
		panic(err)
	}
	s := mustSess()
	if _, err = s.Bind(v); err != nil {
		panic(err)
	}
	return &applyRef{
		path: path, v: v, s: s, cookie: login(s), bug: bug,
		failTxt: missingSecretSentence(path),
	}
}

// MakeUnreadable leaves the file in place so the missing-file arm can
// remove it. Mode 000 is enough for the suite: apply must not open it.
func (d *applyRef) MakeUnreadable(context.Context) {
	if err := os.Chmod(d.path, 0); err != nil {
		panic(err)
	}
}

func (d *applyRef) MakeMissing(context.Context) {
	d.missing = true
	_ = os.Chmod(d.path, 0600)
	if err := os.Remove(d.path); err != nil && !os.IsNotExist(err) {
		panic(err)
	}
}

// Apply does not run Prepare. P2 keeps the loaded bearer. The "read"
// bug opens the secret file on every apply, so the unreadable arm
// catches it. The "missing-open" bug reports no open until the file is
// gone, then reports one. The "missing-lockout" bug is the pre-P2
// failClosedAuth shape: the missing-file apply reports no open, then
// replaces the verifier with Empty and clears the cookie session.
func (d *applyRef) Apply(context.Context) (bool, int) {
	if d.bug == "read" {
		st, err := prepareToken(d.path)
		if err != nil || st == nil {
			return true, 1
		}
		return true, len(opensFrom(st))
	}
	if d.missing && d.bug == "missing-open" {
		return true, 1
	}
	if d.missing && d.bug == "missing-lockout" {
		d.v = authn.Empty()
		d.s.Clear()
	}
	return true, 0
}

func (d *applyRef) BearerWorks(context.Context) bool {
	_, err := d.v.AuthenticateBearer([]byte(secretA))
	return err == nil
}
func (d *applyRef) SessionWorks(context.Context) bool {
	_, ok := d.s.Lookup(d.cookie)
	return ok
}

func (d *applyRef) FailureText() string { return d.failTxt }

// Reset is the reset after the file is gone. The "reset" bug reports
// success, which the missing-file arm must reject.
func (d *applyRef) Reset(context.Context) (string, error) {
	if d.bug == "reset" {
		return "", nil
	}
	st, err := prepareToken(d.path)
	if err != nil {
		return err.Error(), err
	}
	if st == nil || st.Err() == nil {
		return "", nil
	}
	return st.Err().Error(), st.Err()
}

func prepareToken(path string) (*authn.Staged, error) {
	return authn.Prepare(authn.Config{
		Mode: authn.ModeBearer, Duplicates: authn.RejectDuplicateValue,
		Roles: roleTable(), MinSecretBytes: 32,
		Source: authn.PerTokenFiles([]authn.FileToken{{
			ID: "ada", Role: "administrator", SecretFile: path,
		}}, fileOpts()),
	})
}

// missingSecretSentence is the loader's message for path once it is gone.
// It is characterized on a sibling that was never created, then the path
// is substituted, so the expected text is today's Prepare error.
func missingSecretSentence(path string) string {
	ghost := path + ".absent"
	st, err := prepareToken(ghost)
	if err != nil || st == nil || st.Err() == nil {
		panic(fmt.Sprintf("characterize missing %s: %v", ghost, err))
	}
	return strings.ReplaceAll(st.Err().Error(), ghost, path)
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

type loadOnceRef struct {
	files []string
	bug   bool
}

func newLoadOnce(t *testing.T, bug bool) *loadOnceRef {
	dir := tdir(t)
	return &loadOnceRef{files: []string{
		filepath.Join(dir, "token-a"),
		filepath.Join(dir, "token-b"),
	}, bug: bug}
}

func (d *loadOnceRef) Variants() []string {
	return []string{"omit-mode", "listen-override", "management-off", "unreadable-between"}
}

func (d *loadOnceRef) Files(string) []string {
	return append([]string(nil), d.files...)
}

func (d *loadOnceRef) Reset(_ context.Context, variant string) (map[string]int, bool) {
	restoreSecret(d.files[0], secretA+"\n")
	restoreSecret(d.files[1], secretB+"\n")
	opts := authn.FileOpts{Line: authn.FirstNonCommentLine, Resolve: authn.AsGiven}
	src := authn.PerTokenFiles([]authn.FileToken{
		{ID: "ada", Role: "administrator", SecretFile: d.files[0]},
		{ID: "bea", Role: "administrator", SecretFile: d.files[1]},
	}, opts)
	cfg := authn.Config{
		Mode: authn.ModeBearer, Source: src, Duplicates: authn.RejectDuplicateValue,
		Roles: roleTable(), MinSecretBytes: 32,
	}
	switch variant {
	case "listen-override":
		cfg.Accept = authn.BearerNeedsToken(true)
	case "management-off":
		cfg.ManagementBound = false
	}
	st, err := authn.Prepare(cfg)
	opens := opensFrom(st)
	if err != nil || st == nil || st.Err() != nil {
		return opens, false
	}
	if variant == "unreadable-between" {
		for _, p := range d.files {
			if err := sealUnreadable(p); err != nil {
				return opens, false
			}
			if _, rerr := os.ReadFile(p); rerr == nil {
				return opens, false
			}
		}
	}
	v := authn.Empty()
	if !st.Commit(v) {
		return opens, false
	}
	if _, err := v.AuthenticateBearer([]byte(secretA)); err != nil {
		return opens, false
	}
	if _, err := v.AuthenticateBearer([]byte(secretB)); err != nil {
		return opens, false
	}
	if d.bug && variant == "omit-mode" {
		// Total still equals the file count. One file was opened twice.
		opens[d.files[0]] = 2
		opens[d.files[1]] = 0
	}
	return opens, true
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

type bootKind int

const (
	bootMulti bootKind = iota // token files plus a password file; off opens nothing
	bootPin                   // management-off builds a stdio pin and Prepares
)

type bootRef struct {
	dir     string
	kind    bootKind
	bug     string
	pin     string
	tokens  map[string][]string
	pass    map[string]string
	wantMsg map[string]string
}

func newBoot(t *testing.T, kind bootKind, bug string) *bootRef {
	d := &bootRef{
		dir: tdir(t), kind: kind, bug: bug,
		tokens:  map[string][]string{},
		pass:    map[string]string{},
		wantMsg: map[string]string{},
	}
	if kind == bootPin {
		d.pin = filepath.Join(d.dir, "pin-token")
		writeFile(d.pin, secretA+"\n", 0600)
	}
	for _, shape := range []string{"absent", "short", "mode000"} {
		sub := filepath.Join(d.dir, shape)
		if err := os.MkdirAll(sub, 0700); err != nil {
			panic(err)
		}
		a := filepath.Join(sub, "token-a")
		b := filepath.Join(sub, "token-b")
		d.tokens[shape] = []string{a, b}
		switch shape {
		case "short":
			writeFile(a, "short\n", 0600)
			writeFile(b, "tiny\n", 0600)
		case "mode000":
			sealMode000(a, secretA+"\n")
			sealMode000(b, secretB+"\n")
		}
		if kind == bootMulti {
			pw := filepath.Join(sub, "password")
			d.pass[shape] = pw
			switch shape {
			case "short":
				writeFile(pw, secretC+"\n", 0600)
			case "mode000":
				sealMode000(pw, secretC+"\n")
			}
		}
		d.wantMsg[shape] = characterizeBoot(shape, a)
	}
	return d
}

func (d *bootRef) Files(arm, files string) []string {
	if arm == "off" {
		if d.kind == bootPin {
			return []string{d.pin}
		}
		return nil
	}
	out := append([]string(nil), d.tokens[files]...)
	if pw := d.pass[files]; pw != "" {
		out = append(out, pw)
	}
	return out
}

func (d *bootRef) BoundMessage(files string) string { return d.wantMsg[files] }

func (d *bootRef) Boot(_ context.Context, arm, files string) BootResult {
	if arm == "off" {
		if d.kind == bootPin {
			if d.bug == "off-zero" {
				return BootResult{Booted: true, DataPlaneOK: true}
			}
			return d.bootPin()
		}
		if !authn.NotChecked().IsNotChecked() {
			return BootResult{Message: "not-checked stage missing"}
		}
		return BootResult{Booted: true, DataPlaneOK: true}
	}
	res := d.bootBound(files)
	if d.bug == "double" {
		paths := d.Files("bound", files)
		res.Opens = map[string]int{}
		for _, p := range paths {
			res.Opens[p] = 1
		}
		// Two opens of the first file and zero of the second. The total
		// still equals the file count.
		res.Opens[paths[0]] = 2
		res.Opens[paths[1]] = 0
	}
	if d.bug == "message" {
		res.Message = "boot failed"
	}
	return res
}

func (d *bootRef) bootPin() BootResult {
	opts := fileOpts()
	st, err := authn.Prepare(authn.Config{
		Mode: authn.ModeBearer, Duplicates: authn.RejectDuplicateValue,
		Roles: roleTable(), MinSecretBytes: 32, ManagementBound: false,
		Source: authn.PerTokenFiles([]authn.FileToken{{
			ID: "ada", Role: "administrator", SecretFile: d.pin,
		}}, opts),
	})
	opens := opensFrom(st)
	if err != nil || st == nil || st.Err() != nil {
		return BootResult{Message: stageErr(err, st), Opens: opens}
	}
	v := authn.Empty()
	if !st.Commit(v) {
		return BootResult{Message: "pin commit failed", Opens: opens}
	}
	_, aerr := v.AuthenticateBearer([]byte(secretA))
	return BootResult{Booted: true, DataPlaneOK: aerr == nil, Opens: opens}
}

func (d *bootRef) bootBound(files string) BootResult {
	opts := fileOpts()
	entries := make([]authn.FileToken, len(d.tokens[files]))
	for i, p := range d.tokens[files] {
		id := "ada"
		if i > 0 {
			id = "bea"
		}
		entries[i] = authn.FileToken{ID: id, Role: "administrator", SecretFile: p}
	}
	cfg := authn.Config{
		Mode: authn.ModeBearer, Duplicates: authn.RejectDuplicateValue,
		Roles: roleTable(), MinSecretBytes: 32, ManagementBound: true,
		Source: authn.PerTokenFiles(entries, opts),
	}
	if pw := d.pass[files]; pw != "" {
		cfg.Mode = authn.ModeBearerAndBasic
		cfg.Basic = &authn.BasicSpec{Username: "ada", PasswordFile: pw, Opts: opts}
	}
	st, err := authn.Prepare(cfg)
	opens := opensFrom(st)
	if err != nil || st == nil || st.Err() != nil {
		return BootResult{Message: stageErr(err, st), Opens: opens}
	}
	return BootResult{Booted: true, DataPlaneOK: true, Opens: opens}
}

func fileOpts() authn.FileOpts {
	return authn.FileOpts{Line: authn.FirstNonCommentLine, Resolve: authn.AsGiven}
}

func opensFrom(st *authn.Staged) map[string]int {
	if st == nil {
		return nil
	}
	opens := map[string]int{}
	for _, fr := range st.Files() {
		opens[fr.Path]++
	}
	return opens
}

func stageErr(err error, st *authn.Staged) string {
	if err != nil {
		return err.Error()
	}
	if st != nil && st.Err() != nil {
		return st.Err().Error()
	}
	return ""
}

func characterizeBoot(shape, path string) string {
	if shape == "short" {
		return fmt.Sprintf("secretFile %q trimmed contents are shorter than %d bytes", path, 32)
	}
	_, err := os.ReadFile(path)
	if err == nil {
		panic("characterizeBoot: " + path + " was readable")
	}
	return fmt.Sprintf("secretFile %q: %s", path, err.Error())
}

func sealMode000(path, body string) {
	writeFile(path, body, 0000)
	if os.Geteuid() != 0 {
		return
	}
	if err := os.Remove(path); err != nil {
		panic(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		panic(err)
	}
}

// sealUnreadable makes path unreadable between Prepare and Commit.
// Root can read a mode-000 file, so that case removes the file instead.
func sealUnreadable(path string) error {
	if os.Geteuid() == 0 {
		return os.Remove(path)
	}
	return os.Chmod(path, 0)
}

func restoreSecret(path, body string) {
	_ = os.Chmod(path, 0600)
	writeFile(path, body, 0600)
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
	if d.bug == "wrote-open" && !end.Ended {
		end.WroteAfter = true
	}
	if d.bug == "wrote-end" && end.Ended {
		end.WroteAfter = true
	}
	if d.bug == "stay-ended" && !end.Ended {
		end.Ended = true
	}
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
	bug     string
}

func newRebind(t *testing.T, v RebindVariant, bug string) *rebindRef {
	return &rebindRef{t: t, variant: v, bug: bug}
}
func (d *rebindRef) Variant() RebindVariant { return d.variant }

// FailureText is the error the variant must report. Syslog refuses an
// address change with validation_failed. Taken uses today's listen error.
func (d *rebindRef) FailureText() string {
	switch d.variant {
	case RebindTaken:
		return "address in use"
	case RebindRefuse:
		return "validation_failed"
	default:
		return ""
	}
}

func (d *rebindRef) Run(context.Context) RebindObs {
	if d.bug == "slow" {
		return RebindObs{Elapsed: 2 * time.Second, NewServes: true, OldRefuses: true, RevisionChanged: true}
	}
	if d.bug == "code" {
		return RebindObs{Elapsed: time.Millisecond, Code: "nope", OldStillServes: true}
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
	bug   string
}

func newDenied(bug string) *denyRef {
	rec := &audit.CountRecorder{}
	d := &denyRef{
		rec:   rec,
		clock: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		bug:   bug,
	}
	// The guard must read d.clock. A closure over a local copy stays at
	// the start time while bump advances the field.
	g, err := audit.NewDeniedGuard(rec, func() time.Time { return d.clock })
	if err != nil {
		panic(err)
	}
	d.guard = g
	return d
}

// bump records one denial and returns the row read back from the recorder.
func (d *denyRef) bump(transport, code, cap string, status int) DenialObs {
	before := len(d.rec.Events())
	ev := audit.DeniedEvent{
		Time: d.clock, ActorID: "ada", ActorClass: "token",
		Transport: transport, Capability: cap, ErrorCode: code, RemoteKey: "127.0.0.1",
	}
	if d.bug == "empty" && code == "bad_bearer" {
		ev.Transport = ""
		ev.Capability = ""
		ev.ErrorCode = ""
	}
	d.guard.RecordDenied(context.Background(), ev)
	if d.bug == "double" && code == "bad_bearer" {
		d.guard.RecordDenied(context.Background(), ev)
	}
	row := AuditFields{}
	evs := d.rec.Events()
	if len(evs) == before+1 {
		last := evs[len(evs)-1]
		row = AuditFields{Transport: last.Transport, Capability: last.Capability, Code: last.ErrorCode}
	}
	d.clock = d.clock.Add(time.Second)
	return DenialObs{Status: status, Rows: len(evs) - before, Row: row}
}

func (d *denyRef) Routes(context.Context) []string {
	// More denials than the guard's burst of 10. Each call advances the
	// clock the guard reads, so a stuck clock suppresses the later rows.
	return []string{
		"/v1/state", "/v1/audit", "/v1/metrics", "/v1/health",
		"/v1/config", "/v1/listeners", "/v1/tokens", "/v1/sessions",
	}
}
func (d *denyRef) Tools(context.Context) []string { return []string{"state_apply"} }
func (d *denyRef) WantRoute(route string) AuditFields {
	return AuditFields{Transport: "rest", Capability: route, Code: "forbidden"}
}
func (d *denyRef) WantTool(tool string) AuditFields {
	return AuditFields{Transport: "mcp", Capability: tool, Code: "forbidden"}
}
func (d *denyRef) WantBadBearer() AuditFields {
	return AuditFields{Transport: "rest", Capability: "/v1/session", Code: "bad_bearer"}
}
func (d *denyRef) WantStaleCookie() AuditFields {
	return AuditFields{Transport: "rest", Capability: "/v1/state", Code: "session_expired"}
}
func (d *denyRef) WantCSRF() AuditFields {
	return AuditFields{Transport: "rest", Capability: "/v1/state", Code: "csrf_invalid"}
}
func (d *denyRef) DenyRoute(_ context.Context, route string) DenialObs {
	return d.bump("rest", "forbidden", route, 403)
}
func (d *denyRef) DenyTool(_ context.Context, tool string) DenialObs {
	return d.bump("mcp", "forbidden", tool, 403)
}
func (d *denyRef) BadBearer(context.Context) DenialObs {
	return d.bump("rest", "bad_bearer", "/v1/session", 401)
}
func (d *denyRef) StaleCookie(context.Context) DenialObs {
	return d.bump("rest", "session_expired", "/v1/state", 401)
}
func (d *denyRef) CSRFMiss(context.Context) DenialObs {
	return d.bump("rest", "csrf_invalid", "/v1/state", 403)
}

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
