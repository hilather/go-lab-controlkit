package kittest

import (
	"context"
	"time"
)

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// StdioRotation checks a token pin across demotion, rotation, removal,
// restore, and a rejected reset, then the maildev dev-loopback arm when
// the driver has one.
func StdioRotation(t Testing, d StdioRotationDriver) {
	t.Helper()
	ctx := context.Background()
	start := d.Call(ctx, "mapped")
	if start.Code != "ok" || !start.HandlerRan || !has(start.Scopes, "admin") {
		t.Fatalf("startup pin: %+v", start)
	}
	if err := d.Reset(ctx, "demote"); err != nil {
		t.Fatalf("demote: %v", err)
	}
	dem := d.Call(ctx, "mapped")
	if dem.Code != "ok" || !dem.HandlerRan || has(dem.Scopes, "admin") || !has(dem.Scopes, "read") {
		t.Fatalf("demote: %+v", dem)
	}
	if err := d.Reset(ctx, "rotate"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	assertUnauth(t, d, "mapped")
	assertUnauth(t, d, "unmapped")
	if err := d.Reset(ctx, "remove"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	assertUnauth(t, d, "mapped")
	assertUnauth(t, d, "unmapped")
	if err := d.Reset(ctx, "restore"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	back := d.Call(ctx, "mapped")
	if back.Code != "ok" || !back.HandlerRan || !has(back.Scopes, "admin") {
		t.Fatalf("restore: %+v", back)
	}
	if err := d.Reset(ctx, "reject"); err == nil {
		t.Fatalf("rejected reset succeeded")
	}
	still := d.Call(ctx, "mapped")
	if still.Code != "ok" || !still.HandlerRan || !has(still.Scopes, "admin") {
		t.Fatalf("reject changed the pin: %+v", still)
	}
	if res, ok := d.Loopback(ctx, "before"); ok {
		if res.Code != "ok" || !res.HandlerRan {
			t.Fatalf("loopback before: %+v", res)
		}
		after, ok := d.Loopback(ctx, "after")
		if !ok || after.Code != "unauthenticated" || after.HandlerRan {
			t.Fatalf("loopback after: %+v ok %v", after, ok)
		}
	}
}

func assertUnauth(t Testing, d StdioRotationDriver, tool string) {
	t.Helper()
	got := d.Call(context.Background(), tool)
	if got.Code != "unauthenticated" || got.HandlerRan {
		t.Fatalf("%s: %+v", tool, got)
	}
}

// ResetUnreadableSecret checks that a missing, unreadable, or short secret
// refuses the reset and leaves the bearer, the cookie, and the snapshot.
func ResetUnreadableSecret(t Testing, d ResetFailureDriver) {
	t.Helper()
	ctx := context.Background()
	if d.Code() == "" {
		t.Fatalf("failure code is empty")
	}
	for _, kind := range []string{"missing", "unreadable", "short"} {
		before := d.Observe(ctx)
		if !before.BearerWorks || !before.SessionWorks {
			t.Fatalf("%s before: %+v", kind, before)
		}
		code, err := d.Reset(ctx, kind)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if code != d.Code() {
			t.Fatalf("%s code %q want %q", kind, code, d.Code())
		}
		after := d.Observe(ctx)
		if after.Revision != before.Revision || after.SideEffects != before.SideEffects || !sameStrings(after.Listeners, before.Listeners) {
			t.Fatalf("%s snapshot changed: before %+v after %+v", kind, before, after)
		}
		if !after.BearerWorks || !after.SessionWorks {
			t.Fatalf("%s locked the admin out: %+v", kind, after)
		}
	}
}

// ResetZeroTokens checks each shape the driver claims against the repo matrix.
func ResetZeroTokens(t Testing, d ZeroTokenDriver) {
	t.Helper()
	ctx := context.Background()
	want := zeroTokenWant()
	shapes := d.Shapes()
	if len(shapes) == 0 {
		t.Fatalf("no zero-token shapes")
	}
	for _, shape := range shapes {
		exp, ok := want[shape]
		if !ok {
			t.Fatalf("unknown shape %q", shape)
		}
		got := d.Apply(ctx, shape)
		if got != exp {
			t.Fatalf("%s: got %+v want %+v", shape, got, exp)
		}
	}
}

func zeroTokenWant() map[ZeroTokenShape]ZeroTokenResult {
	fail := ZeroTokenResult{Code: "validation_failed", OldBearerWorks: true, OldCookieWorks: true, RevisionUnchanged: true}
	ok := ZeroTokenResult{OldBearerWorks: false, OldCookieWorks: false, RevisionUnchanged: false}
	return map[ZeroTokenShape]ZeroTokenResult{
		ZeroNTPBearer:       fail,
		ZeroNTPLoopback:     ok,
		ZeroNetconf:         fail,
		ZeroSNMP:            ok,
		ZeroMaildevBearer:   ok,
		ZeroMaildevBasic:    ok,
		ZeroMaildevLoopback: ok,
	}
}

// ApplyNoSecretRead checks that an apply opens no secret file and leaves
// the bearer and the cookie usable.
func ApplyNoSecretRead(t Testing, d ApplyDriver) {
	t.Helper()
	ctx := context.Background()
	d.MakeUnreadable(ctx)
	ok, opens := d.Apply(ctx)
	if !ok || opens != 0 {
		t.Fatalf("apply ok %v opens %d", ok, opens)
	}
	if !d.BearerWorks(ctx) || !d.SessionWorks(ctx) {
		t.Fatalf("apply locked the admin out")
	}
}

// ResetLoadOnce checks exactly one secret read per reset variant.
func ResetLoadOnce(t Testing, d LoadOnceDriver) {
	t.Helper()
	ctx := context.Background()
	want := []string{"omit-mode", "listen-override", "management-off", "unreadable-between"}
	if !sameStrings(d.Variants(), want) {
		t.Fatalf("variants %v", d.Variants())
	}
	for _, variant := range want {
		reads, ok := d.Reset(ctx, variant)
		if reads != 1 || !ok {
			t.Fatalf("%s reads %d ok %v", variant, reads, ok)
		}
	}
}

// ResetPrepareRace checks that a spec change between the unlocked Prepare
// and the locked load is compiled, and that the stale stage is discarded.
func ResetPrepareRace(t Testing, d PrepareRaceDriver) {
	t.Helper()
	ctx := context.Background()
	if d.FailureCode() == "" {
		t.Fatalf("failure code is empty")
	}
	a := d.Case(ctx, 1)
	if a.Code != d.FailureCode() || !a.Discarded || a.Reads != 2 || a.CommittedNew || a.Field == "" {
		t.Fatalf("case 1: %+v", a)
	}
	b := d.Case(ctx, 2)
	if b.Code != "" || b.Reads != 2 || !b.CommittedNew {
		t.Fatalf("case 2: %+v", b)
	}
}

// BootManagementOffNoSecretRead checks management-off boots with zero secret
// opens, and management-bound boots fail after one open.
func BootManagementOffNoSecretRead(t Testing, d BootDriver) {
	t.Helper()
	ctx := context.Background()
	for _, files := range []string{"absent", "short", "mode000"} {
		off := d.Boot(ctx, "off", files)
		if !off.Booted || !off.DataPlaneOK || off.SecretOpens != 0 {
			t.Fatalf("off %s: %+v", files, off)
		}
		bound := d.Boot(ctx, "bound", files)
		if bound.Booted || bound.Message == "" || bound.SecretOpens != 1 {
			t.Fatalf("bound %s: %+v", files, bound)
		}
	}
}

// StreamRevocation checks the wake matrix, the lazy-expiry arm, and GET 405.
func StreamRevocation(t Testing, d StreamDriver) {
	t.Helper()
	ctx := context.Background()
	type row struct {
		kind    StreamKind
		trigger string
		end     bool
	}
	matrix := []row{
		{StreamBearer, "demote", true},
		{StreamCookie, "demote", true},
		{StreamBearer, "remove-bearer", true},
		{StreamCookie, "remove-bearer", true},
		{StreamCookie, "delete", true},
		{StreamBearer, "delete-other", false},
		{StreamCookie, "evict", true},
		{StreamBearer, "evict", false},
		{StreamBearer, "keep-scope", false},
	}
	for _, row := range matrix {
		got := d.Run(ctx, row.kind, row.trigger)
		if got.Ended != row.end || got.WroteAfter || !got.WithinBudget || !got.Rechecked {
			t.Fatalf("%s %s: %+v want ended %v", row.kind, row.trigger, got, row.end)
		}
	}
	if d.MCPGet(ctx) != 405 {
		t.Fatalf("GET mcp: %d", d.MCPGet(ctx))
	}
	idle, abs := d.LazyExpiry(ctx)
	if !idle || !abs {
		t.Fatalf("lazy expiry idle %v absolute %v", idle, abs)
	}
}

// ManagementRebindOverAPI checks one rebind variant against a 1s budget.
// EXPERIMENTAL: the driver and the observations may change before v1.0.0.
func ManagementRebindOverAPI(t Testing, d RebindDriver) {
	t.Helper()
	obs := d.Run(context.Background())
	if obs.Elapsed >= time.Second {
		t.Fatalf("%s took %s", d.Variant(), obs.Elapsed)
	}
	switch d.Variant() {
	case RebindMove:
		if obs.Code != "" || !obs.NewServes || !obs.OldRefuses || !obs.RevisionChanged {
			t.Fatalf("move: %+v", obs)
		}
	case RebindOff:
		if obs.Code != "" || !obs.ResponseIntact || !obs.OldRefuses || obs.OldStillServes {
			t.Fatalf("off: %+v", obs)
		}
	case RebindTaken:
		if obs.Code == "" || !obs.OldStillServes || obs.RevisionChanged {
			t.Fatalf("taken: %+v", obs)
		}
	case RebindSame:
		if obs.Code != "" || !obs.OldStillServes {
			t.Fatalf("same: %+v", obs)
		}
	case RebindRefuse:
		if obs.Code == "" || !obs.OldStillServes || obs.RevisionChanged {
			t.Fatalf("refuse: %+v", obs)
		}
	case RebindKeep:
		if obs.Code != "" || !obs.OldStillServes {
			t.Fatalf("keep: %+v", obs)
		}
	default:
		t.Fatalf("unknown variant %q", d.Variant())
	}
}

// CatalogCoversTools checks that every registered tool is in the catalog
// and that an unmapped tool is forbidden.
func CatalogCoversTools(t Testing, d CatalogDriver) {
	t.Helper()
	ctx := context.Background()
	names := d.Registered(ctx)
	if len(names) == 0 {
		t.Fatalf("no tools")
	}
	for _, name := range names {
		if !d.InCatalog(name) {
			t.Fatalf("tool %s is not in the catalog", name)
		}
	}
	if d.CallUnmapped(ctx) != "forbidden" {
		t.Fatalf("unmapped: %s", d.CallUnmapped(ctx))
	}
}

// IdentityChangeClearsSessions checks both bind orders. A demotion kills
// the cookie session in each order.
func IdentityChangeClearsSessions(t Testing, d IdentityDriver) {
	t.Helper()
	ctx := context.Background()
	for _, order := range []IdentityOrder{OrderProduction, OrderReverse} {
		d.Boot(ctx, order)
		cookie := d.Login(ctx)
		if cookie == "" || !d.CookieWorks(ctx, cookie) {
			t.Fatalf("%s login did not stick", order)
		}
		d.Demote(ctx)
		if d.CookieWorks(ctx, cookie) {
			t.Fatalf("%s demotion left the cookie", order)
		}
	}
}

// DeniedAudited checks one denial row per route, tool, bad bearer, stale
// cookie, and CSRF miss.
func DeniedAudited(t Testing, d DeniedAuditDriver) {
	t.Helper()
	ctx := context.Background()
	routes := d.Routes(ctx)
	tools := d.Tools(ctx)
	if len(routes) == 0 || len(tools) == 0 {
		t.Fatalf("no routes or tools")
	}
	for _, route := range routes {
		status, rows := d.DenyRoute(ctx, route)
		if status != 403 || rows != 1 {
			t.Fatalf("route %s status %d rows %d", route, status, rows)
		}
	}
	for _, tool := range tools {
		status, rows := d.DenyTool(ctx, tool)
		if status != 403 || rows != 1 {
			t.Fatalf("tool %s status %d rows %d", tool, status, rows)
		}
	}
	if status, rows := d.BadBearer(ctx); status != 401 || rows != 1 {
		t.Fatalf("bad bearer status %d rows %d", status, rows)
	}
	if status, rows := d.StaleCookie(ctx); status != 401 || rows != 1 {
		t.Fatalf("stale cookie status %d rows %d", status, rows)
	}
	if status, rows := d.CSRFMiss(ctx); status != 403 || rows != 1 {
		t.Fatalf("csrf status %d rows %d", status, rows)
	}
}

// DeniedGuardFlood checks a burst of 10 and that an OK row survives.
func DeniedGuardFlood(t Testing, d FloodDriver) {
	t.Helper()
	admitted, suppressed, okSurvived := d.Flood(context.Background(), 30)
	if admitted != 10 || suppressed != 20 || !okSurvived {
		t.Fatalf("admitted %d suppressed %d ok %v", admitted, suppressed, okSurvived)
	}
}

// MCPStrictInput checks gap payloads are invalid with no revision change,
// and valid payloads are not rejected.
func MCPStrictInput(t Testing, d StrictDriver) {
	t.Helper()
	ctx := context.Background()
	rev := d.Revision(ctx)
	names := d.Tools(ctx)
	if len(names) == 0 || rev == "" {
		t.Fatalf("no tools or revision")
	}
	for _, name := range names {
		gaps := d.GapPayloads(name)
		if len(gaps) == 0 {
			t.Fatalf("%s has no gap payloads", name)
		}
		for _, gap := range gaps {
			code, got := d.Call(ctx, name, gap)
			if code != "invalid" || got != rev {
				t.Fatalf("%s gap code %s rev %s want invalid %s", name, code, got, rev)
			}
		}
		for _, okp := range d.ValidPayloads(name) {
			code, _ := d.Call(ctx, name, okp)
			if code == "invalid" {
				t.Fatalf("%s valid payload rejected", name)
			}
		}
	}
}
