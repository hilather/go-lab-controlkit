// Package audit is the management-plane ring, fanout, redaction, and the
// denied-event flood guard.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-controlkit/ratelimit"
)

// RingOptions configures a Ring.
// Max and SetID are required.
// IsDenied, when nil, treats every row as not denied.
// DeniedShare of 0 disables the flood guard. It must be in [0, 1].
type RingOptions[E any] struct {
	Max         int
	SetID       func(*E, string)
	IsDenied    func(E) bool
	DeniedShare float64
}

// Ring is a bounded in-memory log. Append of a denied row evicts the oldest
// denied row first once denied rows fill DeniedShare of the ring, so a denied
// flood cannot evict OK rows.
type Ring[E any] struct {
	mu     sync.Mutex
	max    int
	setID  func(*E, string)
	denied func(E) bool
	share  float64
	rows   []ringRow[E]
	index  map[string]int
}

type ringRow[E any] struct {
	id string
	e  E
}

// NewRing builds a ring.
func NewRing[E any](o RingOptions[E]) (*Ring[E], error) {
	if o.Max <= 0 {
		return nil, errors.New("audit: ring max must be positive")
	}
	if o.SetID == nil {
		return nil, errors.New("audit: SetID is required")
	}
	if o.DeniedShare < 0 || o.DeniedShare > 1 {
		return nil, errors.New("audit: DeniedShare must be in [0, 1]")
	}
	return &Ring[E]{
		max:    o.Max,
		setID:  o.SetID,
		denied: o.IsDenied,
		share:  o.DeniedShare,
		index:  map[string]int{},
	}, nil
}

// Append stores e, assigning an id through SetID, and returns the stored value.
// When the ring is full, a denied row evicts the oldest denied row once denied
// rows have reached DeniedShare of the capacity. Otherwise the oldest row goes.
func (r *Ring[E]) Append(e E) E {
	if r == nil {
		return e
	}
	id := newID()
	r.setID(&e, id)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rows) >= r.max {
		r.evictLocked(e)
	}
	r.index[id] = len(r.rows)
	r.rows = append(r.rows, ringRow[E]{id: id, e: e})
	return e
}

func (r *Ring[E]) evictLocked(incoming E) {
	drop := 0
	if r.share > 0 && r.isDenied(incoming) {
		limit := int(r.share * float64(r.max))
		if r.deniedCount() >= limit {
			if i := r.oldestDenied(); i >= 0 {
				drop = i
			}
		}
	}
	r.removeAt(drop)
}

func (r *Ring[E]) isDenied(e E) bool {
	if r.denied == nil {
		return false
	}
	return r.denied(e)
}

func (r *Ring[E]) deniedCount() int {
	n := 0
	for _, row := range r.rows {
		if r.isDenied(row.e) {
			n++
		}
	}
	return n
}

func (r *Ring[E]) oldestDenied() int {
	for i, row := range r.rows {
		if r.isDenied(row.e) {
			return i
		}
	}
	return -1
}

func (r *Ring[E]) removeAt(i int) {
	if i < 0 || i >= len(r.rows) {
		return
	}
	delete(r.index, r.rows[i].id)
	r.rows = append(r.rows[:i], r.rows[i+1:]...)
	for j := i; j < len(r.rows); j++ {
		r.index[r.rows[j].id] = j
	}
}

// List returns the most recent limit rows, oldest first among them.
// limit <= 0 returns every row, oldest first.
func (r *Ring[E]) List(limit int) []E {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rows := r.rows
	if limit > 0 && len(rows) > limit {
		rows = rows[len(rows)-limit:]
	}
	out := make([]E, len(rows))
	for i, row := range rows {
		out[i] = row.e
	}
	return out
}

// Get returns the row with id.
func (r *Ring[E]) Get(id string) (E, bool) {
	var zero E
	if r == nil {
		return zero, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	i, ok := r.index[id]
	if !ok {
		return zero, false
	}
	return r.rows[i].e, true
}

// Len is the number of stored rows.
func (r *Ring[E]) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rows)
}

// Wipe drops every row and keeps the capacity.
func (r *Ring[E]) Wipe() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.rows = nil
	r.index = map[string]int{}
	r.mu.Unlock()
}

// Resize changes the capacity. Shrinking drops the oldest rows.
// n <= 0 is an error and leaves the ring unchanged.
func (r *Ring[E]) Resize(n int) error {
	if r == nil {
		return errors.New("audit: nil ring")
	}
	if n <= 0 {
		return errors.New("audit: ring max must be positive")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.max = n
	for len(r.rows) > r.max {
		r.removeAt(0)
	}
	return nil
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// Fanout redacts, appends to a ring, and delivers to a best-effort sink.
// A sink error increments DeliveryFailures and does not fail Record.
// redact, when nil, leaves the event unchanged. sink, when nil, is skipped.
type Fanout[E any] struct {
	ring   *Ring[E]
	redact func(E) E
	sink   func(E) error
	fails  atomic.Uint64
}

// NewFanout builds a fanout. ring is required.
func NewFanout[E any](ring *Ring[E], redact func(E) E, sink func(E) error) (*Fanout[E], error) {
	if ring == nil {
		return nil, errors.New("audit: fanout ring is required")
	}
	return &Fanout[E]{ring: ring, redact: redact, sink: sink}, nil
}

// Record redacts e, appends it, and calls the sink. The stored event is returned.
func (f *Fanout[E]) Record(e E) E {
	if f == nil {
		return e
	}
	if f.redact != nil {
		e = f.redact(e)
	}
	e = f.ring.Append(e)
	if f.sink != nil {
		if err := f.sink(e); err != nil {
			f.fails.Add(1)
		}
	}
	return e
}

// DeliveryFailures is how many sink calls have returned an error.
func (f *Fanout[E]) DeliveryFailures() uint64 {
	if f == nil {
		return 0
	}
	return f.fails.Load()
}

// Redactor blanks sensitive map keys, PEM blocks, and Bearer tokens.
// A zero Redactor redacts nothing. Keys nil means no key redaction.
type Redactor struct {
	Keys         map[string]bool
	PEM          bool
	BearerPrefix bool
}

const redacted = "[redacted]"

var (
	pemRE    = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[A-Za-z0-9+/=\s]+-----END [A-Z0-9 ]+-----`)
	bearerRE = regexp.MustCompile(`(?i)Bearer\s+\S+`)
)

// Map returns a deep copy of m with redaction applied.
func (r Redactor) Map(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return r.walk(m).(map[string]any)
}

// JSON redacts a JSON document and returns the canonical encoding of the result.
func (r Redactor) JSON(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(r.walk(v))
}

// String redacts PEM blocks and Bearer tokens in s.
func (r Redactor) String(s string) string {
	return r.redactString(s)
}

func (r Redactor) walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if r.Keys[k] {
				out[k] = redacted
				continue
			}
			out[k] = r.walk(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = r.walk(child)
		}
		return out
	case string:
		return r.redactString(t)
	default:
		return v
	}
}

func (r Redactor) redactString(s string) string {
	if r.PEM {
		s = pemRE.ReplaceAllString(s, redacted)
	}
	if r.BearerPrefix {
		s = bearerRE.ReplaceAllString(s, "Bearer "+redacted)
	}
	return s
}

// DeniedEvent is one authorization denial, before a repo maps it into its own row.
type DeniedEvent struct {
	Time       time.Time
	ActorID    string
	ActorClass string
	Transport  string
	Capability string
	ErrorCode  string
	RemoteKey  string
}

// DeniedRecorder accepts a denial. Implementations must be safe for concurrent use.
type DeniedRecorder interface {
	RecordDenied(ctx context.Context, ev DeniedEvent)
}

// DeniedGuard rate-limits denial recording.
// The bucket key is "actor:"+ActorID when ActorID is set, otherwise "remote:"+RemoteKey.
// The limiter is 1/s with burst 10. Suppressed counts decisions that were not admitted.
// now, when nil, means time.Now.
type DeniedGuard struct {
	next *recorder
	lim  *ratelimit.Keyed
	sup  atomic.Uint64
}

type recorder struct{ DeniedRecorder }

// NewDeniedGuard builds a guard in front of next.
// next nil means admitted events are counted and then dropped.
func NewDeniedGuard(next DeniedRecorder, now func() time.Time) (*DeniedGuard, error) {
	lim, err := ratelimit.NewKeyed(1, 10, ratelimit.Ctor{
		DefaultRate:  1,
		DefaultBurst: 10,
		NegativeRate: ratelimit.NegativeRateDisabled,
		ZeroRate:     ratelimit.ZeroRateUseDefault,
		Burst:        ratelimit.BurstDefaultOnZero,
	}, ratelimit.Options{
		IdleFloor:        30 * time.Second,
		IdleRefillFactor: 4,
		MaxKeys:          ratelimit.DefaultMaxKeys,
		Now:              now,
	})
	if err != nil {
		return nil, err
	}
	g := &DeniedGuard{lim: lim}
	if next != nil {
		g.next = &recorder{next}
	}
	return g, nil
}

// Admit reports whether ev may be recorded. A refusal increments Suppressed.
func (g *DeniedGuard) Admit(ev DeniedEvent) bool {
	if g == nil || g.lim == nil {
		return false
	}
	key := denialKey(ev)
	if g.lim.Allow(key) {
		return true
	}
	g.sup.Add(1)
	return false
}

// Suppressed is how many Admit calls have refused.
func (g *DeniedGuard) Suppressed() uint64 {
	if g == nil {
		return 0
	}
	return g.sup.Load()
}

// RecordDenied records ev when Admit allows it.
func (g *DeniedGuard) RecordDenied(ctx context.Context, ev DeniedEvent) {
	if g == nil || !g.Admit(ev) {
		return
	}
	if g.next != nil && g.next.DeniedRecorder != nil {
		g.next.RecordDenied(ctx, ev)
	}
}

func denialKey(ev DeniedEvent) string {
	if ev.ActorID != "" {
		return "actor:" + ev.ActorID
	}
	return "remote:" + ev.RemoteKey
}

// CountRecorder is a DeniedRecorder that stores events. It is safe for tests
// and for a process that only needs the denial list.
type CountRecorder struct {
	mu  sync.Mutex
	evs []DeniedEvent
}

// RecordDenied appends ev.
func (c *CountRecorder) RecordDenied(_ context.Context, ev DeniedEvent) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.evs = append(c.evs, ev)
	c.mu.Unlock()
}

// Events returns a copy of the recorded denials.
func (c *CountRecorder) Events() []DeniedEvent {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]DeniedEvent(nil), c.evs...)
}

// HasSecret reports whether s contains secret as a raw substring.
// Tests use it to prove redaction. secret empty returns false.
func HasSecret(s, secret string) bool {
	if secret == "" {
		return false
	}
	return strings.Contains(s, secret)
}
