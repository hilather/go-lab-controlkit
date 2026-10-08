package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

func ctorNTP() Ctor {
	return Ctor{
		DefaultRate:  32,
		DefaultBurst: 64,
		NegativeRate: NegativeRateDisabled,
		ZeroRate:     ZeroRateUseDefault,
		Burst:        BurstDefaultOnZero,
	}
}

func ctorDNSMgmt() Ctor {
	return Ctor{
		DefaultRate:  32,
		DefaultBurst: 64,
		NegativeRate: NegativeRateDisabled,
		ZeroRate:     ZeroRateUseDefault,
		Burst:        BurstDefaultOnNonPositive,
	}
}

func ctorDNSRaw() Ctor {
	c := ctorDNSMgmt()
	c.ZeroRate = ZeroRateDeny
	return c
}

func opts(max int, now func() time.Time) Options {
	return Options{IdleFloor: 30 * time.Second, IdleRefillFactor: 4, MaxKeys: max, Now: now}
}

func TestCtorRows(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	k, err := NewKeyed(0, 0, ctorNTP(), opts(8, clock))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Allow("a") {
		t.Fatal("ntp rate 0 burst 0 should use defaults and allow")
	}

	k, err = NewKeyed(-1, 10, ctorNTP(), opts(8, clock))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if !k.Allow("a") {
			t.Fatal("negative rate disables")
		}
	}
	k.SetRate(1, 1, Live{Rate: BurstDefaultOnNonPositive, Burst: BurstDefaultOnNonPositive})
	if !k.Allow("b") {
		t.Fatal("setRate on a disabled limiter must be a no-op")
	}

	k, err = NewKeyed(0, -5, ctorDNSRaw(), opts(8, clock))
	if err != nil {
		t.Fatal(err)
	}
	if k.Allow("a") {
		t.Fatal("dns raw rate 0 must deny")
	}

	k, err = NewKeyed(0, -1, ctorDNSMgmt(), opts(8, clock))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Allow("a") {
		t.Fatal("dns management rate 0 burst <0 uses defaults")
	}

	k, err = NewKeyed(10, -3, ctorNTP(), opts(8, clock))
	if err != nil {
		t.Fatal(err)
	}
	if k.Allow("a") {
		t.Fatal("ntp burst <0 is stored and denies")
	}

	if _, err = NewKeyed(1, 1, ctorNTP(), Options{IdleFloor: time.Second, IdleRefillFactor: 4, MaxKeys: 0}); err == nil {
		t.Fatal("MaxKeys 0")
	}
	if _, err = NewKeyed(1, 1, ctorNTP(), Options{IdleFloor: time.Second, IdleRefillFactor: 4, MaxKeys: -2}); err == nil {
		t.Fatal("MaxKeys negative")
	}
	if DefaultMaxKeys != 1024 {
		t.Fatal(DefaultMaxKeys)
	}
}

func TestSetRateLive(t *testing.T) {
	var now time.Time
	clock := func() time.Time { return now }
	k, err := NewKeyed(1, 1, ctorNTP(), opts(8, clock))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Allow("a") {
		t.Fatal("first")
	}
	if k.Allow("a") {
		t.Fatal("burst 1 exhausted")
	}
	k.SetRate(0, 0, Live{Rate: BurstDefaultOnNonPositive, Burst: BurstDefaultOnNonPositive})
	now = now.Add(time.Second)
	if !k.Allow("a") {
		t.Fatal("non-positive setRate uses defaults and refills")
	}
}

func TestIdleCutoffFollowsSetRate(t *testing.T) {
	var now time.Time
	clock := func() time.Time { return now }
	// rate 1 / burst 100 => cutoff = max(30s, 4*100/1 s) = 400s, gap = 100s.
	k, err := NewKeyed(1, 100, ctorNTP(), opts(8, clock))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Allow("idle") {
		t.Fatal("seed")
	}
	now = now.Add(100 * time.Second)
	if !k.Allow("other") {
		t.Fatal("other")
	}
	if !k.Contains("idle") {
		t.Fatal("idle key swept inside the long cutoff")
	}
	// Recompute: rate 100 / burst 1 => cutoff = 30s floor, gap = 7.5s.
	// A SetRate that did not take effect would still use the 400s cutoff.
	k.SetRate(100, 1, Live{Rate: BurstDefaultOnNonPositive, Burst: BurstDefaultOnNonPositive})
	now = now.Add(31 * time.Second)
	if !k.Allow("third") {
		t.Fatal("third")
	}
	if k.Contains("idle") {
		t.Fatal("idle key survived past the cutoff recomputed after SetRate")
	}
}

func TestGlobalAllowAt(t *testing.T) {
	var g Global
	var now time.Time
	g.SetNow(func() time.Time { return now })
	allowed := 0
	for i := 0; i < 70; i++ {
		if g.AllowAt(-1, -1) {
			allowed++
		}
	}
	if allowed != 64 {
		t.Fatalf("<=0 uses 64 burst on that call, allowed %d", allowed)
	}
	var g2 Global
	g2.SetNow(func() time.Time { return now })
	if !g2.AllowAt(1, 1) {
		t.Fatal("first")
	}
	if g2.AllowAt(1, 1) {
		t.Fatal("second at the same instant")
	}
	now = now.Add(time.Second)
	if !g2.AllowAt(5, 5) {
		t.Fatal("rate change between calls refills at the new rate")
	}
}

func TestMaxKeysRequired(t *testing.T) {
	if _, err := NewKeyed(1, 1, ctorNTP(), Options{}); err == nil {
		t.Fatal("zero options")
	}
	k, err := NewKeyed(1, 1, ctorNTP(), opts(DefaultMaxKeys, func() time.Time { return time.Time{} }))
	if err != nil {
		t.Fatal(err)
	}
	if k.maxKeys != DefaultMaxKeys {
		t.Fatal(k.maxKeys)
	}
}

func TestDefaultMaxKeys(t *testing.T) {
	if DefaultMaxKeys != 1024 {
		t.Fatal(DefaultMaxKeys)
	}
}

func TestKeyedDeniedKeyStaysMostRecent(t *testing.T) {
	var now time.Time
	k, err := NewKeyed(0.001, 1, ctorNTP(), opts(2, func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Allow("a") || !k.Allow("b") {
		t.Fatal("seed")
	}
	now = now.Add(time.Millisecond)
	if k.Allow("b") {
		t.Fatal("b should be denied once its token is spent")
	}
	now = now.Add(time.Millisecond)
	if !k.Allow("c") {
		t.Fatal("c")
	}
	if k.Contains("a") {
		t.Fatal("the key that went longest without a call was not the victim")
	}
	if !k.Contains("b") || !k.Contains("c") {
		t.Fatal("denied key was evicted")
	}
	now = now.Add(time.Millisecond)
	if k.Allow("b") {
		t.Fatal("b is still present and still empty")
	}
}

func TestKeyedSweepThrottle(t *testing.T) {
	var now time.Time
	// cutoff = max(30s, 4*1/100s) = 30s. gap = max(1s, 7.5s) = 7.5s.
	k, err := NewKeyed(100, 1, ctorNTP(), opts(8, func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Allow("a") {
		t.Fatal("seed")
	}
	if k.SweepCount() != 1 {
		t.Fatalf("first allow sweeps, got %d", k.SweepCount())
	}
	now = now.Add(7*time.Second + 499*time.Millisecond)
	k.Allow("a")
	if k.SweepCount() != 1 {
		t.Fatalf("sweep ran inside the gap: %d", k.SweepCount())
	}
	now = now.Add(2 * time.Millisecond)
	k.Allow("a")
	if k.SweepCount() != 2 {
		t.Fatalf("sweep did not run once the gap elapsed: %d", k.SweepCount())
	}
	// Many calls inside the next gap add no sweeps.
	now = now.Add(time.Second)
	for i := 0; i < 10; i++ {
		k.Allow("a")
	}
	if k.SweepCount() != 2 {
		t.Fatalf("sweep ran more than once per gap: %d", k.SweepCount())
	}
}

func TestKeyed100kDistinctKeys(t *testing.T) {
	var now time.Time
	k, err := NewKeyed(10, 10, ctorNTP(), Options{
		IdleFloor:        time.Hour,
		IdleRefillFactor: 4,
		MaxKeys:          1024,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	const calls = 100000
	const window = 10000
	marks := make([]uint64, 0, calls/window)
	for i := 0; i < calls; i++ {
		now = now.Add(time.Millisecond)
		if !k.Allow(strconv.Itoa(i)) && i < 1024 {
			t.Fatalf("fresh key %d denied", i)
		}
		if k.Len() > 1024 {
			t.Fatalf("len %d after %d", k.Len(), i)
		}
		if (i+1)%window == 0 {
			marks = append(marks, k.Visits())
		}
	}
	if k.Len() > 1024 {
		t.Fatal(k.Len())
	}
	prev := uint64(0)
	var first float64
	for i, m := range marks {
		d := m - prev
		avg := float64(d) / float64(window)
		if avg > 3 {
			t.Fatalf("window %d averaged %f visits per call", i, avg)
		}
		if i == 0 {
			first = float64(d)
		}
		if i == len(marks)-1 && float64(d) > 1.5*first {
			t.Fatalf("last window %d is more than 1.5x the first %f", d, first)
		}
		prev = m
	}
}

func TestRemoteKeyHostOnly(t *testing.T) {
	if got := RemoteKey("192.0.2.10:443"); got != "192.0.2.10" {
		t.Fatal(got)
	}
	if got := RemoteKey("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatal(got)
	}
	if got := RemoteKey("192.0.2.10"); got != "192.0.2.10" {
		t.Fatal(got)
	}
}

func BenchmarkKeyed(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			keys := make([]string, n)
			for i := range keys {
				keys[i] = strconv.Itoa(i)
			}
			k, err := NewKeyed(1e9, 1e9, ctorNTP(), Options{
				IdleFloor:        time.Hour,
				IdleRefillFactor: 4,
				MaxKeys:          n,
			})
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < n; i++ {
				k.Allow(keys[i])
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k.Allow(keys[i%n])
			}
		})
	}
}
