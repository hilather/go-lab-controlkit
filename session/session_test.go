package session

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-controlkit/authn"
	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/scope"
)

func baseCfg() Config {
	return Config{
		CookieName:  "lab_session",
		CSRFHeader:  "X-Lab-CSRF",
		Idle:        time.Hour,
		Absolute:    4 * time.Hour,
		Max:         4,
		AtCap:       EvictOldest,
		IDShape:     SeparateCookieSecret,
		CSRFCompare: DigestConstantTime,
	}
}

func mustStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func princ() scope.Principal {
	return scope.Principal{ID: "ada", Class: "token", Role: "administrator", Scopes: []string{"read", "write"}, Groups: []string{"ops"}}
}

func clock(t *testing.T, s *Store) *time.Time {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cur := now
	s.SetNow(func() time.Time { return cur })
	return &cur
}

func kindIs(err error, k kerr.Kind) bool {
	got, ok := kerr.KindOf(err)
	return ok && got == k
}

func mustMat(t *testing.T, secret string) *authn.Material {
	t.Helper()
	m, err := authn.Load(authn.Config{
		Mode:       authn.ModeBearer,
		Duplicates: authn.RejectDuplicateValue,
		Source: authn.Memory([]authn.RawToken{{
			ID: "ada", Role: "administrator", Secret: authn.NewSecret([]byte(secret)),
		}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustVer(t *testing.T, m *authn.Material) *authn.Verifier {
	t.Helper()
	v, err := authn.NewVerifier(m)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNewRequiresConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil || !kindIs(err, kerr.Invalid) {
		t.Fatalf("zero config: %v", err)
	}
	cfg := baseCfg()
	cfg.Absolute = -time.Second
	if _, err := New(cfg); err == nil {
		t.Fatal("negative absolute accepted")
	}
	cfg = baseCfg()
	cfg.Absolute = 0
	if _, err := New(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSessionIdleAbsoluteAndCap(t *testing.T) {
	s := mustStore(t, baseCfg())
	now := clock(t, s)
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if iss.Session.ID == iss.Cookie {
		t.Fatal("separate cookie secret reused the public id")
	}
	if len(iss.Cookie) != 64 || len(iss.Session.ID) != 32 || len(iss.CSRF) != 64 {
		t.Fatalf("lengths cookie %d id %d csrf %d", len(iss.Cookie), len(iss.Session.ID), len(iss.CSRF))
	}
	wantIdle := iss.Session.LastSeen.Add(time.Hour)
	if got := s.ExpiresAt(iss.Session); !got.Equal(wantIdle) {
		t.Fatalf("idle expires %s want %s", got, wantIdle)
	}
	*now = now.Add(time.Hour)
	if _, ok := s.Lookup(iss.Cookie); !ok {
		t.Fatal("exactly idle was expired")
	}
	*now = now.Add(time.Hour + time.Nanosecond)
	n := 0
	s.OnDelete(func() { n++ })
	if _, ok := s.Lookup(iss.Cookie); ok || n != 1 {
		t.Fatalf("idle ok=%v hooks=%d", ok, n)
	}

	cfg := baseCfg()
	cfg.Idle = 8 * time.Hour
	s = mustStore(t, cfg)
	now = clock(t, s)
	iss, err = s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(4 * time.Hour)
	if _, ok := s.View(iss.Cookie); !ok {
		t.Fatal("exactly absolute was expired")
	}
	*now = now.Add(time.Nanosecond)
	if _, ok := s.View(iss.Cookie); ok {
		t.Fatal("past absolute was accepted")
	}
	wantAbs := iss.Session.CreatedAt.Add(4 * time.Hour)
	if got := s.ExpiresAt(iss.Session); !got.Equal(wantAbs) {
		t.Fatalf("expires %s want %s", got, wantAbs)
	}
	if s.MaxAge() != int((4 * time.Hour).Seconds()) {
		t.Fatalf("max-age %d", s.MaxAge())
	}
}

func TestSessionAbsoluteZero(t *testing.T) {
	cfg := baseCfg()
	cfg.Absolute = 0
	cfg.Idle = 1000 * time.Hour
	s := mustStore(t, cfg)
	now := clock(t, s)
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(100 * time.Hour)
	if _, ok := s.Lookup(iss.Cookie); !ok {
		t.Fatal("absolute 0 expired a live idle session")
	}
	if s.MaxAge() != 0 {
		t.Fatalf("max-age %d", s.MaxAge())
	}
	if !s.ExpiresAt(iss.Session).Equal(iss.Session.LastSeen.Add(cfg.Idle)) {
		t.Fatal("expires-at used an absolute cap")
	}
}

func TestSessionEvictAndReject(t *testing.T) {
	cfg := baseCfg()
	cfg.Max = 2
	s := mustStore(t, cfg)
	now := clock(t, s)
	n := 0
	s.OnDelete(func() { n++ })
	first, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if _, err := s.Create(princ()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	third, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(first.Cookie); ok {
		t.Fatal("oldest session was kept")
	}
	if _, ok := s.Lookup(third.Cookie); !ok {
		t.Fatal("new session missing")
	}
	if n != 1 || s.Len() != 2 {
		t.Fatalf("hooks %d len %d", n, s.Len())
	}

	cfg.AtCap = Reject
	s = mustStore(t, cfg)
	now = clock(t, s)
	a, _ := s.Create(princ())
	b, _ := s.Create(princ())
	_, err = s.Create(princ())
	if err == nil || err.Error() != "session table full" || !kindIs(err, kerr.RateLimited) {
		t.Fatalf("reject: %v", err)
	}
	if _, ok := s.Lookup(a.Cookie); !ok {
		t.Fatal("reject dropped a")
	}
	if _, ok := s.Lookup(b.Cookie); !ok {
		t.Fatal("reject dropped b")
	}
}

func TestSessionRotate(t *testing.T) {
	cfg := baseCfg()
	cfg.IDShape = SingleID
	cfg.CSRFCompare = HexOrRawConstantTime
	s := mustStore(t, cfg)
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if iss.Cookie != iss.Session.ID || len(iss.Cookie) != 64 {
		t.Fatalf("single id cookie %d id %d", len(iss.Cookie), len(iss.Session.ID))
	}
	next, err := s.Rotate(iss.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if next.Cookie == iss.Cookie || next.CSRF == iss.CSRF || next.Session.Principal.ID != "ada" {
		t.Fatalf("rotated %+v", next)
	}
	if s.Len() != 1 {
		t.Fatalf("len %d", s.Len())
	}
	if _, ok := s.Lookup(iss.Cookie); ok {
		t.Fatal("old id still live")
	}
	if _, ok := s.Lookup(next.Cookie); !ok {
		t.Fatal("new id missing")
	}
	if _, err := s.Rotate("missing"); err == nil || err.Error() != "session expired" {
		t.Fatalf("missing rotate: %v", err)
	}
}

func TestCSRFReadBackDoesNotSlide(t *testing.T) {
	s := mustStore(t, baseCfg())
	now := clock(t, s)
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	csrf, ok := s.CSRF(iss.Cookie)
	if !ok || csrf != iss.CSRF {
		t.Fatalf("csrf %q ok=%v", csrf, ok)
	}
	*now = now.Add(30 * time.Minute)
	sess, ok := s.Lookup(iss.Cookie)
	if !ok {
		t.Fatal("lookup")
	}
	csrf, ok = s.CSRF(iss.Cookie)
	if !ok || csrf != iss.CSRF {
		t.Fatal("csrf after lookup")
	}
	got, ok := s.View(iss.Cookie)
	if !ok || !got.LastSeen.Equal(sess.LastSeen) {
		t.Fatal("csrf slid the idle clock")
	}
	*now = sess.LastSeen.Add(time.Hour)
	if _, ok := s.CSRF(iss.Cookie); !ok {
		t.Fatal("exactly idle was expired")
	}
	*now = sess.LastSeen.Add(time.Hour + time.Nanosecond)
	n := 0
	s.OnDelete(func() { n++ })
	if _, ok := s.CSRF(iss.Cookie); ok || n != 1 {
		t.Fatalf("expired csrf ok hooks=%d", n)
	}
	if _, ok := s.CSRF(""); ok {
		t.Fatal("empty cookie")
	}
	if _, ok := s.CSRF("missing"); ok {
		t.Fatal("missing cookie")
	}
	var nilStore *Store
	if _, ok := nilStore.CSRF(iss.Cookie); ok {
		t.Fatal("nil store")
	}

	v := mustVer(t, mustMat(t, "one"))
	s = mustStore(t, baseCfg())
	unreg, err := s.Bind(v)
	if err != nil {
		t.Fatal(err)
	}
	unreg()
	s.mu.Lock()
	s.verifier = v
	s.mu.Unlock()
	iss, err = s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Swap(mustMat(t, "two")) {
		t.Fatal("swap")
	}
	n = 0
	s.OnDelete(func() { n++ })
	if _, ok := s.CSRF(iss.Cookie); ok || n != 1 {
		t.Fatalf("stale csrf ok hooks=%d", n)
	}
}

func TestRotatePreservesAbsoluteCreation(t *testing.T) {
	cfg := baseCfg()
	cfg.Idle = 8 * time.Hour
	s := mustStore(t, cfg)
	now := clock(t, s)
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	created := iss.Session.CreatedAt
	*now = now.Add(3*time.Hour + 30*time.Minute)
	next, err := s.Rotate(iss.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Session.CreatedAt.Equal(created) {
		t.Fatalf("created %s want %s", next.Session.CreatedAt, created)
	}
	if !next.Session.LastSeen.Equal(*now) {
		t.Fatalf("last seen %s want %s", next.Session.LastSeen, *now)
	}
	want := created.Add(4 * time.Hour)
	if got := s.ExpiresAt(next.Session); !got.Equal(want) {
		t.Fatalf("expires %s want %s", got, want)
	}
	*now = created.Add(4*time.Hour + time.Nanosecond)
	if _, ok := s.Lookup(next.Cookie); ok {
		t.Fatal("rotation extended the absolute cap")
	}

	cfg = baseCfg()
	cfg.Absolute = 0
	cfg.IDShape = SingleID
	s = mustStore(t, cfg)
	now = clock(t, s)
	iss, err = s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Minute)
	next, err = s.Rotate(iss.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Session.CreatedAt.Equal(*now) || !next.Session.LastSeen.Equal(*now) {
		t.Fatalf("absolute 0 created %s seen %s now %s", next.Session.CreatedAt, next.Session.LastSeen, *now)
	}
	if !s.ExpiresAt(next.Session).Equal(now.Add(cfg.Idle)) {
		t.Fatal("absolute 0 rotate did not reset the sliding deadline")
	}
	rotated := *now
	*now = iss.Session.CreatedAt.Add(time.Hour + time.Nanosecond)
	if _, ok := s.View(next.Cookie); !ok {
		t.Fatal("absolute 0 rotate kept the original sliding deadline")
	}
	*now = rotated.Add(cfg.Idle + time.Nanosecond)
	if _, ok := s.Lookup(next.Cookie); ok {
		t.Fatal("absolute 0 rotate ignored the new sliding deadline")
	}
}

func TestSessionViewDoesNotSlide(t *testing.T) {
	s := mustStore(t, baseCfg())
	now := clock(t, s)
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Minute)
	if _, ok := s.View(iss.Cookie); !ok {
		t.Fatal("view")
	}
	*now = iss.Session.CreatedAt.Add(time.Hour + time.Nanosecond)
	if _, ok := s.Lookup(iss.Cookie); ok {
		t.Fatal("view slid the idle clock")
	}
}

func TestSessionCSRFCompare(t *testing.T) {
	s := mustStore(t, baseCfg())
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidCSRF(iss.Cookie, iss.CSRF) {
		t.Fatal("digest compare rejected the issued secret")
	}
	if s.ValidCSRF(iss.Cookie, iss.CSRF+"aa") {
		t.Fatal("digest compare accepted a longer secret")
	}
	seen := iss.Session.LastSeen
	if !s.ValidCSRF(iss.Cookie, iss.CSRF) {
		t.Fatal("second compare")
	}
	got, ok := s.View(iss.Cookie)
	if !ok || !got.LastSeen.Equal(seen) {
		t.Fatal("valid csrf slid the session")
	}

	cfg := baseCfg()
	cfg.CSRFCompare = HexOrRawConstantTime
	s = mustStore(t, cfg)
	iss, err = s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidCSRF(iss.Cookie, iss.CSRF) {
		t.Fatal("hex compare")
	}
	if s.ValidCSRF(iss.Cookie, "zzzz") {
		t.Fatal("raw mismatch accepted")
	}
	s.mu.Lock()
	s.sessions[iss.Cookie].csrf = "not-hex!!"
	s.mu.Unlock()
	if !s.ValidCSRF(iss.Cookie, "not-hex!!") {
		t.Fatal("raw equal secrets were rejected")
	}
	if s.ValidCSRF(iss.Cookie, "not-hex!?") {
		t.Fatal("raw unequal secrets matched")
	}
}

func TestSessionBindClearsOnSwap(t *testing.T) {
	v := mustVer(t, mustMat(t, "one"))
	s := mustStore(t, baseCfg())
	if _, err := s.Bind(nil); err == nil {
		t.Fatal("nil verifier bound")
	}
	if _, err := s.Bind(v); err != nil {
		t.Fatal(err)
	}
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if iss.Session.Generation != 0 {
		t.Fatalf("gen %d", iss.Session.Generation)
	}
	if v.Swap(mustMat(t, "one")) {
		t.Fatal("equivalent swap")
	}
	if _, ok := s.Lookup(iss.Cookie); !ok {
		t.Fatal("equivalent swap cleared the session")
	}
	if !v.Swap(mustMat(t, "two")) {
		t.Fatal("swap")
	}
	if _, ok := s.Lookup(iss.Cookie); ok || s.Len() != 0 {
		t.Fatal("identity swap left a session")
	}
}

func TestConcurrentBindDoesNotRewind(t *testing.T) {
	s := mustStore(t, baseCfg())
	v1 := mustVer(t, mustMat(t, "alpha"))
	v2 := mustVer(t, mustMat(t, "bravo"))
	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			v := v1
			if i%2 == 1 {
				v = v2
			}
			if _, err := s.Bind(v); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	s.mu.Lock()
	if s.bindID != n {
		id := s.bindID
		s.mu.Unlock()
		t.Fatalf("bindID %d want %d", id, n)
	}
	live := s.verifier
	s.mu.Unlock()
	if live != v1 && live != v2 {
		t.Fatalf("verifier %p", live)
	}
	other := v1
	if live == v1 {
		other = v2
	}
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if !other.Swap(mustMat(t, "other")) {
		t.Fatal("other swap did not change identity")
	}
	if _, ok := s.Lookup(iss.Cookie); !ok {
		t.Fatal("another verifier's hook cleared the session")
	}
	if !live.Swap(mustMat(t, "live")) {
		t.Fatal("live swap did not change identity")
	}
	if _, ok := s.Lookup(iss.Cookie); ok || s.Len() != 0 {
		t.Fatal("installed verifier did not clear the session")
	}
}

func TestSessionStaleGeneration(t *testing.T) {
	v := mustVer(t, mustMat(t, "one"))
	s := mustStore(t, baseCfg())
	unreg, err := s.Bind(v)
	if err != nil {
		t.Fatal(err)
	}
	unreg()
	s.mu.Lock()
	s.verifier = v
	s.mu.Unlock()
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Swap(mustMat(t, "two")) {
		t.Fatal("swap")
	}
	if s.Len() != 1 {
		t.Fatal("clear hook still ran")
	}
	n := 0
	s.OnDelete(func() { n++ })
	if _, ok := s.Lookup(iss.Cookie); ok || n != 1 {
		t.Fatalf("stale accepted hooks %d", n)
	}
}

func TestOnDeleteOncePerRemoval(t *testing.T) {
	s := mustStore(t, baseCfg())
	now := clock(t, s)
	n := 0
	s.OnDelete(func() { n++ })
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	s.Delete(iss.Cookie)
	s.Delete(iss.Cookie)
	if n != 1 {
		t.Fatalf("delete hooks %d", n)
	}
	s.Clear()
	if n != 1 {
		t.Fatalf("empty clear hooks %d", n)
	}
	iss, _ = s.Create(princ())
	other, _ := s.Create(princ())
	s.Clear()
	if n != 2 || s.Len() != 0 {
		t.Fatalf("clear hooks %d len %d", n, s.Len())
	}
	_ = other

	iss, _ = s.Create(princ())
	*now = now.Add(2 * time.Hour)
	if _, ok := s.View(iss.Cookie); ok {
		t.Fatal("view kept an expired session")
	}
	if n != 3 {
		t.Fatalf("view expiry hooks %d", n)
	}

	iss, _ = s.Create(princ())
	*now = now.Add(2 * time.Hour)
	if s.ValidCSRF(iss.Cookie, iss.CSRF) {
		t.Fatal("csrf kept an expired session")
	}
	if n != 4 {
		t.Fatalf("csrf expiry hooks %d", n)
	}

	iss, _ = s.Create(princ())
	*now = now.Add(2 * time.Hour)
	if _, ok := s.Lookup(iss.Cookie); ok {
		t.Fatal("lookup kept an expired session")
	}
	if n != 5 {
		t.Fatalf("lookup expiry hooks %d", n)
	}

	cfg := baseCfg()
	cfg.Max = 1
	s = mustStore(t, cfg)
	now = clock(t, s)
	n = 0
	s.OnDelete(func() { n++ })
	iss, _ = s.Create(princ())
	*now = now.Add(2 * time.Hour)
	if _, err := s.Create(princ()); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("sweep hooks %d", n)
	}

	s = mustStore(t, cfg)
	now = clock(t, s)
	n = 0
	s.OnDelete(func() { n++ })
	if _, err := s.Create(princ()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if _, err := s.Create(princ()); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("evict hooks %d", n)
	}
}

func TestOnDeleteSweepAndEvictOnce(t *testing.T) {
	cfg := baseCfg()
	cfg.Max = 2
	s := mustStore(t, cfg)
	now := clock(t, s)
	n := 0
	s.OnDelete(func() { n++ })
	oldest, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	newer, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sessions["expired"] = &record{
		public:   Session{ID: "old", CreatedAt: now.Add(-2 * time.Hour), LastSeen: now.Add(-2 * time.Hour)},
		created:  now.Add(-2 * time.Hour),
		lastSeen: now.Add(-2 * time.Hour),
	}
	s.mu.Unlock()
	fresh, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("sweep+evict hooks %d", n)
	}
	if s.Len() != 2 {
		t.Fatalf("len %d", s.Len())
	}
	if _, ok := s.Lookup("expired"); ok {
		t.Fatal("expired row remained")
	}
	if _, ok := s.Lookup(oldest.Cookie); ok {
		t.Fatal("oldest live row was kept")
	}
	if _, ok := s.Lookup(newer.Cookie); !ok {
		t.Fatal("newer live row was evicted")
	}
	if _, ok := s.Lookup(fresh.Cookie); !ok {
		t.Fatal("new row missing")
	}
}

func TestOnDeleteAfterUnlock(t *testing.T) {
	s := mustStore(t, baseCfg())
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	saw := false
	s.OnDelete(func() {
		if _, ok := s.Lookup(other.Cookie); !ok {
			t.Error("hook lookup failed")
		}
		saw = true
	})
	s.Delete(iss.Cookie)
	if !saw {
		t.Fatal("hook did not run")
	}
}

func TestOnDeleteHooksAndUnregister(t *testing.T) {
	s := mustStore(t, baseCfg())
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	var order []int
	drop := s.OnDelete(func() { order = append(order, 1) })
	s.OnDelete(func() { order = append(order, 2) })
	drop()
	s.Delete(iss.Cookie)
	if len(order) != 1 || order[0] != 2 {
		t.Fatalf("order %v", order)
	}
}

func TestSetNow(t *testing.T) {
	s := mustStore(t, baseCfg())
	now := clock(t, s)
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Hour)
	if _, ok := s.Lookup(iss.Cookie); ok {
		t.Fatal("fake clock did not expire")
	}
	s.SetNow(nil)
	live, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(live.Cookie); !ok {
		t.Fatal("time.Now clock rejected a fresh session")
	}
}

func TestRevocationWake(t *testing.T) {
	v := mustVer(t, mustMat(t, "one"))
	s := mustStore(t, baseCfg())
	if _, err := s.Bind(v); err != nil {
		t.Fatal(err)
	}
	w, unreg, err := RevocationWake(v, s)
	if err != nil {
		t.Fatal(err)
	}
	defer unreg()
	iss, err := s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	ch := w.Subscribe()
	if v.Swap(mustMat(t, "one")) {
		t.Fatal("equivalent")
	}
	select {
	case <-ch:
		t.Fatal("equivalent swap signaled")
	default:
	}
	if !v.Swap(mustMat(t, "two")) {
		t.Fatal("swap")
	}
	select {
	case <-ch:
	default:
		t.Fatal("identity swap did not signal")
	}
	if s.Len() != 0 {
		t.Fatal("swap did not clear")
	}
	iss, err = s.Create(princ())
	if err != nil {
		t.Fatal(err)
	}
	ch = w.Subscribe()
	s.Delete(iss.Cookie)
	select {
	case <-ch:
	default:
		t.Fatal("delete did not signal")
	}
	if _, _, err := RevocationWake(nil, s); err == nil {
		t.Fatal("nil verifier accepted")
	}
}

func TestCookieHelpers(t *testing.T) {
	if CookieSecure(nil, false) {
		t.Fatal("nil request was secure")
	}
	if !CookieSecure(nil, true) {
		t.Fatal("force did not win")
	}
	req := &http.Request{TLS: &tls.ConnectionState{}}
	if !CookieSecure(req, false) {
		t.Fatal("tls request was not secure")
	}
	c := SessionCookie("labntp_session", "abc", true, 60)
	if c.Name != "labntp_session" || !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 60 {
		t.Fatalf("cookie %+v", c)
	}
	if !strings.Contains(c.String(), "Max-Age=60") {
		t.Fatalf("positive max-age missing: %s", c.String())
	}
	browser := SessionCookie("labdns_session", "abc", false, 0)
	if browser.MaxAge != 0 || strings.Contains(browser.String(), "Max-Age") {
		t.Fatalf("zero max-age set an attribute: %s", browser.String())
	}
	cleared := ClearCookie("labntp_session", false)
	if cleared.MaxAge != -1 || !cleared.Expires.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("clear %+v", cleared)
	}
	rr := httptest.NewRecorder()
	NoStore(rr)
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("header %q", rr.Header().Get("Cache-Control"))
	}
	s := mustStore(t, baseCfg())
	if s.CookieName() != "lab_session" || s.CSRFHeader() != "X-Lab-CSRF" {
		t.Fatalf("names %s %s", s.CookieName(), s.CSRFHeader())
	}
}
