package authn

import (
	"sync"
	"testing"
	"time"
)

func TestSwapFiresHooksRegardlessOfRegistrationOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		m := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one")))
		v := mustVer(t, m)
		var order []string
		var mu sync.Mutex
		reg := func(name string) {
			v.OnIdentityChange(func() {
				mu.Lock()
				order = append(order, name)
				mu.Unlock()
			})
		}
		if reverse {
			reg("b")
			reg("a")
		} else {
			reg("a")
			reg("b")
		}
		next := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "two")))
		if !v.Swap(next) {
			t.Fatal("expected a change")
		}
		want := []string{"a", "b"}
		if reverse {
			want = []string{"b", "a"}
		}
		if len(order) != 2 || order[0] != want[0] || order[1] != want[1] {
			t.Fatalf("reverse %v order %v", reverse, order)
		}
	}
}

func TestSwapNoHookWhenEquivalent(t *testing.T) {
	m := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one", "s1", "s2")))
	v := mustVer(t, m)
	n := 0
	v.OnIdentityChange(func() { n++ })
	again := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one", "s2", "s1")))
	if v.Swap(again) {
		t.Fatal("scope order counted as a change")
	}
	if n != 0 || v.Generation() != 0 {
		t.Fatalf("hooks %d gen %d", n, v.Generation())
	}
	if v.Swap(nil) {
		t.Fatal("nil swap changed the verifier")
	}
}

func TestSwapHookMayCallAuthenticate(t *testing.T) {
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "old"))))
	next := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("b", "viewer", "new")))
	var id string
	var authErr error
	v.OnIdentityChange(func() {
		var p, err = v.Authenticate(authBearer("new"))
		id, authErr = p.ID, err
	})
	if !v.Swap(next) {
		t.Fatal("swap")
	}
	if authErr != nil || id != "b" {
		t.Fatalf("id %s err %v", id, authErr)
	}
}

func TestSwapHookRunsWhileCallerHoldsLock(t *testing.T) {
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "old"))))
	var mu sync.Mutex
	mu.Lock()
	saw := false
	v.OnIdentityChange(func() {
		if mu.TryLock() {
			mu.Unlock()
			t.Error("hook ran without the caller's lock")
			return
		}
		saw = true
	})
	next := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "viewer", "old")))
	if !v.Swap(next) {
		t.Fatal("swap")
	}
	mu.Unlock()
	if !saw {
		t.Fatal("hook did not run")
	}
}

func TestEquivalentIncludesBasicRoleScopes(t *testing.T) {
	base := func(order ...string) *Material {
		t.Helper()
		toks := []RawToken{raw("a", "administrator", "sa", "read", "write"), raw("b", "viewer", "sb", "read")}
		if len(order) == 2 && order[0] == "b" {
			toks = []RawToken{toks[1], toks[0]}
		}
		return mustLoad(t, Config{
			Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
			Source: Memory(toks),
			Basic:  &BasicSpec{Username: "ada", Password: NewSecret([]byte("pw")), TokenRef: "a"},
		})
	}
	same := base()
	reordered := base("b", "a")
	if same.Equivalent(reordered) {
		t.Fatal("basic token index ignored a reorder")
	}
	noBasic := func(scopes ...string) *Material {
		return mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "sa", scopes...)))
	}
	if !noBasic("read", "write").Equivalent(noBasic("write", "read")) {
		t.Fatal("scope order counted")
	}
	if noBasic("read").Equivalent(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "viewer", "sa", "read")))) {
		t.Fatal("role ignored")
	}
	otherPass := mustLoad(t, Config{
		Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
		Source: Memory([]RawToken{raw("a", "administrator", "sa", "read", "write"), raw("b", "viewer", "sb", "read")}),
		Basic:  &BasicSpec{Username: "ada", Password: NewSecret([]byte("other")), TokenRef: "a"},
	})
	if same.Equivalent(otherPass) {
		t.Fatal("password digest ignored")
	}
	otherUser := mustLoad(t, Config{
		Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
		Source: Memory([]RawToken{raw("a", "administrator", "sa", "read", "write"), raw("b", "viewer", "sb", "read")}),
		Basic:  &BasicSpec{Username: "bea", Password: NewSecret([]byte("pw")), TokenRef: "a"},
	})
	if same.Equivalent(otherUser) {
		t.Fatal("username ignored")
	}
}

func TestMaildevTokenReorderIsIdentityChange(t *testing.T) {
	mk := func(first string) *Material {
		t.Helper()
		a := raw("a", "administrator", "sa", "mail.admin")
		b := raw("b", "viewer", "sb", "mail.read")
		toks := []RawToken{a, b}
		if first == "b" {
			toks = []RawToken{b, a}
		}
		return mustLoad(t, Config{
			Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
			Source: Memory(toks),
			Basic:  &BasicSpec{Username: "ada", Password: NewSecret([]byte("pw")), TokenRef: "a"},
		})
	}
	v := mustVer(t, mk("a"))
	n := 0
	v.OnIdentityChange(func() { n++ })
	if !v.Swap(mk("b")) {
		t.Fatal("reorder was equivalent")
	}
	if n != 1 || v.Generation() != 1 {
		t.Fatalf("hooks %d gen %d", n, v.Generation())
	}
}

func TestGenerationBumpsOnlyOnChange(t *testing.T) {
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one"))))
	if v.Generation() != 0 {
		t.Fatalf("start %d", v.Generation())
	}
	same := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one")))
	v.Swap(same)
	if v.Generation() != 0 {
		t.Fatalf("equivalent gen %d", v.Generation())
	}
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "viewer", "one"))))
	if v.Generation() != 1 {
		t.Fatalf("change gen %d", v.Generation())
	}
	unreg := v.OnIdentityChange(func() {})
	unreg()
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("b", "viewer", "two"))))
	if v.Generation() != 2 {
		t.Fatalf("after unregister gen %d", v.Generation())
	}
}

func TestRevocationWakeFiresOnIdentitySwapOnly(t *testing.T) {
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one"))))
	w := NewWake()
	v.OnIdentityChange(w.Signal)
	ch := w.Subscribe()
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one"))))
	select {
	case <-ch:
		t.Fatal("equivalent swap signaled")
	default:
	}
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "viewer", "one"))))
	select {
	case <-ch:
	default:
		t.Fatal("identity swap did not signal")
	}
	fresh := w.Subscribe()
	select {
	case <-fresh:
		t.Fatal("fresh channel was already closed")
	default:
	}
}

func TestWakeSignalNeverBlocks(t *testing.T) {
	w := NewWake()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			w.Signal()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Signal blocked")
	}
}

func TestWakeSubscribeAfterSignalGetsFreshChannel(t *testing.T) {
	w := NewWake()
	first := w.Subscribe()
	w.Signal()
	select {
	case <-first:
	default:
		t.Fatal("signaled channel was not closed")
	}
	second := w.Subscribe()
	if second == nil {
		t.Fatal("nil channel")
	}
	select {
	case <-second:
		t.Fatal("subscriber after signal received the closed channel")
	default:
	}
	w.Signal()
	select {
	case <-second:
	default:
		t.Fatal("second channel did not close")
	}
}

func TestConcurrentAuthenticateSwapResolve(t *testing.T) {
	secret := "concurrent-secret"
	m1 := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("id", "administrator", secret, "a")))
	m2 := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("id", "viewer", secret, "b")))
	v := mustVer(t, m1)
	pin, err := NewStdioPin(v, NewSecret([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	w := NewWake()
	v.OnIdentityChange(w.Signal)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				_, _ = v.Authenticate(authBearer(secret))
				_, _ = pin.Resolve()
				_ = v.Generation()
				_ = w.Subscribe()
				if i%2 == 0 {
					v.Swap(m2)
				} else {
					v.Swap(m1)
				}
			}
		}(i)
	}
	wg.Wait()
	if _, err := v.AuthenticateBearer([]byte(secret)); err != nil {
		t.Fatal(err)
	}
}
