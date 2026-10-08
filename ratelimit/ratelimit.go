// Package ratelimit is the management-plane token bucket.
//
// Keyed is a per-key limiter with a required cap. There is no uncapped mode.
// Global is one bucket whose rate is supplied on each call. It skips a
// backward step; syslog's bucket does not. See Global.
package ratelimit

import (
	"container/list"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// NegativeRateDisabled means a construction rate below zero disables the
// limiter for the process lifetime. Allow then returns true, and SetRate
// does nothing.
type NegMeaning int

const (
	NegativeRateDisabled NegMeaning = iota + 1
)

// ZeroMeaning says what a construction rate of zero means.
type ZeroMeaning int

const (
	// ZeroRateUseDefault stores Ctor.DefaultRate when the construction rate is 0.
	ZeroRateUseDefault ZeroMeaning = iota + 1
	// ZeroRateDeny stores a rate of 0, and Allow then returns false (dns raw limiter).
	ZeroRateDeny
)

// BurstMeaning says which non-positive burst values are replaced with the default.
type BurstMeaning int

const (
	// BurstDefaultOnZero replaces a burst of exactly 0 with the default.
	BurstDefaultOnZero BurstMeaning = iota + 1
	// BurstDefaultOnNonPositive replaces a burst of 0 or below with the default.
	BurstDefaultOnNonPositive
)

// Ctor is the construction policy. Every field is required.
// DefaultRate and DefaultBurst must be positive.
type Ctor struct {
	DefaultRate  float64
	DefaultBurst float64
	NegativeRate NegMeaning
	ZeroRate     ZeroMeaning
	Burst        BurstMeaning
}

// Live is the policy SetRate applies to a later rate update.
// A disabled limiter ignores a valid SetRate. Both fields are required.
// A zero Live, or any field that is not a known BurstMeaning, is an error.
type Live struct {
	Rate  BurstMeaning
	Burst BurstMeaning
}

// DefaultMaxKeys is the cap facades pass when they have no smaller product cap.
const DefaultMaxKeys = 1024

// Options sizes and clocks a Keyed limiter.
// IdleFloor and IdleRefillFactor and MaxKeys are required.
// Now, when nil, means time.Now.
type Options struct {
	IdleFloor        time.Duration
	IdleRefillFactor float64
	MaxKeys          int
	Now              func() time.Time
}

// Keyed is a per-key token bucket.
//
// Allow always refills: it adds elapsed*rate, including a negative elapsed,
// then clamps to the current burst and sets last to now. That is the ntp,
// snmp, and maildev management limiters. dns's limiter refills, clamps, and
// updates last only when elapsed > 0, as do the dns and ntp query limiters
// and snmp's data-plane query limiters. Production uses time.Now, which is
// monotonic, so the difference shows only with a non-monotonic injected clock.
//
// The idle cutoff is max(IdleFloor, IdleRefillFactor*burst/rate), recomputed
// from the current rate and burst at each sweep. The sweep runs at most once
// per max(1s, cutoff/4). At MaxKeys, a new key evicts the least recently seen
// key. Every Allow updates "seen", whether the call is allowed or denied.
// Buckets sit on a list ordered by the last Allow, so eviction and the idle
// walk are O(1) amortized.
type Keyed struct {
	mu       sync.Mutex
	disabled bool
	rate     float64
	burst    float64
	defRate  float64
	defBurst float64
	floor    time.Duration
	factor   float64
	maxKeys  int
	now      func() time.Time

	buckets   map[string]*bucket
	order     *list.List
	lastSweep time.Time
	swept     bool
	visits    uint64
	sweeps    uint64
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
	elem   *list.Element
}

// NewKeyed builds a limiter. MaxKeys of 0 or below is an error.
// A negative construction rate disables the limiter when Ctor.NegativeRate
// is NegativeRateDisabled.
func NewKeyed(rate, burst float64, c Ctor, o Options) (*Keyed, error) {
	if c.DefaultRate <= 0 || c.DefaultBurst <= 0 {
		return nil, errors.New("ratelimit: default rate and burst must be positive")
	}
	if c.NegativeRate != NegativeRateDisabled {
		return nil, errors.New("ratelimit: negative rate meaning is required")
	}
	if c.ZeroRate != ZeroRateUseDefault && c.ZeroRate != ZeroRateDeny {
		return nil, errors.New("ratelimit: zero rate meaning is required")
	}
	if c.Burst != BurstDefaultOnZero && c.Burst != BurstDefaultOnNonPositive {
		return nil, errors.New("ratelimit: burst meaning is required")
	}
	if o.IdleFloor <= 0 {
		return nil, errors.New("ratelimit: idle floor is required")
	}
	if o.IdleRefillFactor <= 0 {
		return nil, errors.New("ratelimit: idle refill factor is required")
	}
	if o.MaxKeys <= 0 {
		return nil, errors.New("ratelimit: MaxKeys must be positive")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	k := &Keyed{
		defRate:  c.DefaultRate,
		defBurst: c.DefaultBurst,
		floor:    o.IdleFloor,
		factor:   o.IdleRefillFactor,
		maxKeys:  o.MaxKeys,
		now:      now,
		buckets:  map[string]*bucket{},
		order:    list.New(),
	}
	if rate < 0 {
		k.disabled = true
		return k, nil
	}
	if rate == 0 {
		if c.ZeroRate == ZeroRateDeny {
			k.rate = 0
		} else {
			k.rate = c.DefaultRate
		}
	} else {
		k.rate = rate
	}
	k.burst = applyBurst(burst, c.Burst, c.DefaultBurst)
	return k, nil
}

func applyBurst(burst float64, meaning BurstMeaning, def float64) float64 {
	switch meaning {
	case BurstDefaultOnNonPositive:
		if burst <= 0 {
			return def
		}
	case BurstDefaultOnZero:
		if burst == 0 {
			return def
		}
	}
	return burst
}

// Allow consumes one token for key when one is available.
// A disabled limiter returns true. A stored rate of 0 returns false.
func (k *Keyed) Allow(key string) bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.disabled {
		return true
	}
	if k.rate <= 0 {
		return false
	}
	now := k.now()
	k.sweepLocked(now)
	b := k.buckets[key]
	if b == nil {
		if len(k.buckets) >= k.maxKeys {
			k.evictFrontLocked()
		}
		b = &bucket{key: key, tokens: k.burst, last: now}
		b.elem = k.order.PushBack(b)
		k.buckets[key] = b
	} else {
		// Always refill: add elapsed*rate even when elapsed is negative, then
		// clamp and set last. A SetRate that lowers burst therefore applies
		// on the next Allow at the same timestamp. dns's limiter refills
		// only when elapsed > 0. See Keyed.
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * k.rate
		if b.tokens > k.burst {
			b.tokens = k.burst
		}
		b.last = now
		k.order.MoveToBack(b.elem)
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// SetRate updates the live rate and burst.
// It returns an error on a nil limiter or when either Live field is not a
// known BurstMeaning. A zero Live used to leave the rate unchanged.
// A disabled limiter ignores a valid update and returns nil.
func (k *Keyed) SetRate(rate, burst float64, l Live) error {
	if k == nil {
		return errors.New("ratelimit: nil limiter")
	}
	if l.Rate != BurstDefaultOnNonPositive && l.Rate != BurstDefaultOnZero {
		return errors.New("ratelimit: live rate meaning is required")
	}
	if l.Burst != BurstDefaultOnNonPositive && l.Burst != BurstDefaultOnZero {
		return errors.New("ratelimit: live burst meaning is required")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.disabled {
		return nil
	}
	k.rate = applyLive(rate, l.Rate, k.defRate)
	k.burst = applyLive(burst, l.Burst, k.defBurst)
	return nil
}

func applyLive(v float64, meaning BurstMeaning, def float64) float64 {
	switch meaning {
	case BurstDefaultOnNonPositive:
		if v <= 0 {
			return def
		}
	case BurstDefaultOnZero:
		if v == 0 {
			return def
		}
	}
	return v
}

// Len is the number of keys currently stored.
func (k *Keyed) Len() int {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}

// Contains reports whether key is stored. It is for tests and operators.
func (k *Keyed) Contains(key string) bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.buckets[key]
	return ok
}

// Visits is the number of buckets examined by idle sweeps and evictions.
// It is exposed for tests. Production callers should ignore it.
func (k *Keyed) Visits() uint64 {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.visits
}

// SweepCount is how many idle sweeps have run. It is exposed for tests.
func (k *Keyed) SweepCount() uint64 {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.sweeps
}

func (k *Keyed) cutoffLocked() time.Duration {
	idle := k.floor
	if k.rate > 0 && k.burst > 0 {
		refill := time.Duration(float64(time.Second) * (k.burst / k.rate) * k.factor)
		if refill > idle {
			idle = refill
		}
	}
	return idle
}

func (k *Keyed) sweepLocked(now time.Time) {
	cut := k.cutoffLocked()
	gap := cut / 4
	if gap < time.Second {
		gap = time.Second
	}
	if k.swept && now.Sub(k.lastSweep) < gap {
		return
	}
	k.swept = true
	k.lastSweep = now
	k.sweeps++
	for k.order.Len() > 0 {
		b := k.order.Front().Value.(*bucket)
		k.visits++
		if now.Sub(b.last) <= cut {
			return
		}
		k.removeLocked(b)
	}
}

func (k *Keyed) evictFrontLocked() {
	if k.order.Len() == 0 {
		return
	}
	b := k.order.Front().Value.(*bucket)
	k.visits++
	k.removeLocked(b)
}

func (k *Keyed) removeLocked(b *bucket) {
	delete(k.buckets, b.key)
	k.order.Remove(b.elem)
}

// Global is one token bucket. It stores no rate. The zero value is usable.
//
// A negative elapsed adds nothing. AllowAt still clamps to that call's
// burst and still sets last to now. syslog's global bucket always adds
// elapsed*rps, including a backward step. Production uses time.Now, which
// is monotonic, so the difference shows only with a non-monotonic injected
// clock.
type Global struct {
	mu      sync.Mutex
	tokens  float64
	last    time.Time
	started bool
	now     func() time.Time
}

// SetNow installs a test clock. Nil restores time.Now.
func (g *Global) SetNow(now func() time.Time) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.now = now
	g.mu.Unlock()
}

// AllowAt consumes one token using the rate and burst of this call.
// A rate of 0 or below uses 32 on this call. A burst of 0 or below uses 64
// on this call. Those substitutions are not stored.
// A negative elapsed adds nothing. The call still clamps and updates last.
// syslog's bucket always adds elapsed*rps. See Global.
func (g *Global) AllowAt(rate, burst float64) bool {
	if g == nil {
		return false
	}
	if rate <= 0 {
		rate = 32
	}
	if burst <= 0 {
		burst = 64
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.now != nil {
		now = g.now()
	}
	if !g.started {
		g.tokens = burst
		g.last = now
		g.started = true
	} else {
		elapsed := now.Sub(g.last).Seconds()
		if elapsed > 0 {
			g.tokens += elapsed * rate
		}
		if g.tokens > burst {
			g.tokens = burst
		}
		g.last = now
	}
	if g.tokens < 1 {
		return false
	}
	g.tokens--
	return true
}

// RemoteKey returns the host of remoteAddr, without a port.
// It never reads X-Forwarded-For. Callers pass the request's RemoteAddr only.
func RemoteKey(remoteAddr string) string {
	s := strings.TrimSpace(remoteAddr)
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}
