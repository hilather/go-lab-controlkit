// Package audit is the management-plane ring, fanout, redaction, and the
// denied-event flood guard.
package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
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
//
// DefaultList is the page size List uses when limit <= 0.
// Zero means limit <= 0 returns every stored row (syslog's uncapped List).
// The five template rings set 100.
//
// MaxList caps a positive limit. A limit above MaxList is cut to MaxList.
// Zero means a positive limit is not capped (syslog).
// The five template rings set 100, so limit <= 0 and limit > 100 both become 100.
//
// NewID, when non-nil, builds the id for an append that does not already
// carry one. seq is the 1-based count of Append calls on this ring. Wipe does
// not reset it. Nil means a random 32-digit hex id. A crypto/rand failure
// uses a process-wide counter so two fallbacks cannot collide.
//
// GetID, when non-nil, reads an id already stored on e. A non-empty result is
// kept and indexed, and SetID is not called (syslog's caller-supplied id).
// An empty result is replaced with NewID(seq), or the random hex id, passed
// to SetID, then read back with GetID when that is set, so the ring indexes
// the id actually stored. Nil means the ring indexes the id it passed to
// SetID, and SetID must store that id.
type RingOptions[E any] struct {
	Max         int
	SetID       func(*E, string)
	IsDenied    func(E) bool
	DeniedShare float64
	DefaultList int
	MaxList     int
	NewID       func(seq uint64) string
	GetID       func(E) string
}

// Ring is a bounded in-memory log. Append of a denied row evicts the oldest
// denied row first once denied rows fill DeniedShare of the ring, so a denied
// flood cannot evict OK rows.
type Ring[E any] struct {
	mu          sync.Mutex
	max         int
	setID       func(*E, string)
	denied      func(E) bool
	share       float64
	defaultList int
	maxList     int
	newID       func(uint64) string
	getID       func(E) string
	seq         uint64
	rows        []ringRow[E]
	index       map[string]int
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
	if o.DefaultList < 0 || o.MaxList < 0 {
		return nil, errors.New("audit: list limits must not be negative")
	}
	return &Ring[E]{
		max:         o.Max,
		setID:       o.SetID,
		denied:      o.IsDenied,
		share:       o.DeniedShare,
		defaultList: o.DefaultList,
		maxList:     o.MaxList,
		newID:       o.NewID,
		getID:       o.GetID,
		index:       map[string]int{},
	}, nil
}

// Append stores e and returns the stored value.
// An id already stored on e is kept when GetID is set and returns it.
// Otherwise the id comes from NewID, or from a random hex id when NewID is
// nil, and is written with SetID. The ring indexes the id that is stored.
// An empty or colliding id is replaced with a counter id and passed to SetID.
// When the ring is full, a denied row evicts the oldest denied row once denied
// rows have reached DeniedShare of the capacity. Otherwise the oldest row goes.
func (r *Ring[E]) Append(e E) E {
	if r == nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rows) >= r.max {
		r.evictLocked(e)
	}
	r.seq++
	id := ""
	if r.getID != nil {
		id = r.getID(e)
	}
	if id == "" {
		if r.newID != nil {
			id = r.newID(r.seq)
		}
		if id == "" {
			id = newID()
		}
		r.setID(&e, id)
		if r.getID != nil {
			if stored := r.getID(e); stored != "" {
				id = stored
			}
		}
	}
	if id == "" || r.idTaken(id) {
		id = fallbackID()
		for r.idTaken(id) {
			id = fallbackID()
		}
		r.setID(&e, id)
	}
	r.index[id] = len(r.rows)
	r.rows = append(r.rows, ringRow[E]{id: id, e: e})
	return e
}

func (r *Ring[E]) idTaken(id string) bool {
	_, ok := r.index[id]
	return ok
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

// List returns up to limit rows, newest first.
// limit <= 0 uses DefaultList, or every row when DefaultList is 0.
// A positive MaxList cuts a larger limit down to MaxList.
func (r *Ring[E]) List(limit int) []E {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.rows)
	if limit <= 0 {
		if r.defaultList > 0 {
			limit = r.defaultList
		} else {
			limit = n
		}
	}
	if r.maxList > 0 && limit > r.maxList {
		limit = r.maxList
	}
	if limit > n {
		limit = n
	}
	out := make([]E, limit)
	for i := 0; i < limit; i++ {
		out[i] = r.rows[n-1-i].e
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

var fallbackSeq atomic.Uint64

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fallbackID()
	}
	return hex.EncodeToString(b[:])
}

// fallbackID is unique for this process even when two calls share a nanosecond.
func fallbackID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(b[8:], fallbackSeq.Add(1))
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

// Redactor blanks sensitive map keys, PEM text, and bearer reasons.
// A zero Redactor redacts nothing. Keys nil means no key redaction.
//
// Keys are matched case-insensitively. Store lowercase names, which is
// what every repo's secret set does. A mixed-case map entry is not consulted.
//
// PEM, when true, replaces a whole string that contains both "BEGIN " and
// "PRIVATE" (ntp, snmp, netconf), including an encrypted PEM block and a
// non-JSON document. False, the zero value, keeps that text (dns, maildev).
//
// BearerPrefix, when true, replaces a whole string whose trimmed text starts
// with "bearer " (any case) with "[redacted]" (dns, maildev). False, the zero
// value, keeps a bearer reason (ntp, snmp, netconf). It applies to String,
// not to JSON values.
//
// ColonLines, when true, rewrites each line that contains a secret key
// followed by ":" so the text after the first colon is " [redacted]" (dns).
// False, the zero value, leaves those lines unchanged. maildev does not set
// this: its redactText only applies the bearer prefix.
type Redactor struct {
	Keys         map[string]bool
	PEM          bool
	BearerPrefix bool
	ColonLines   bool
}

const redacted = "[redacted]"

// Map returns a deep copy of m with key and PEM redaction applied.
// BearerPrefix and ColonLines are not applied to map values. Numbers are
// left as the caller decoded them.
func (r Redactor) Map(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return r.walk(m).(map[string]any)
}

// JSON redacts a JSON document and returns the encoding of the result.
// Numbers are decoded with UseNumber, so a literal such as 1.0 or an
// integer above 2^53 is preserved. Empty input and JSON null are returned
// trimmed and unchanged. A decode error returns the trimmed input and a nil
// error, unless PEM is set and the input contains a private key, in which
// case the result is the JSON string "[redacted]".
func (r Redactor) JSON(b []byte) ([]byte, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return b, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		if r.PEM && containsPrivateKey(string(b)) {
			return []byte(`"` + redacted + `"`), nil
		}
		return b, nil
	}
	out, err := json.Marshal(r.walk(v))
	if err != nil {
		return b, nil
	}
	return out, nil
}

// String redacts s the way the repos redact a reason or ticket.
// PEM, when set, replaces the whole string. BearerPrefix, when set,
// replaces the whole string when it starts with "bearer ". ColonLines,
// when set, blanks secret lines. The zero value returns s unchanged.
func (r Redactor) String(s string) string {
	if s == "" {
		return s
	}
	if r.BearerPrefix && strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "bearer ") {
		return redacted
	}
	if r.PEM && containsPrivateKey(s) {
		return redacted
	}
	if r.ColonLines && len(r.Keys) > 0 {
		return r.blankColonLines(s)
	}
	return s
}

// Path reports whether path names a secret field: it equals a key in Keys,
// or it ends in "."+key or "/"+key, compared case-insensitively.
// Every template repo uses this on a diff entry's path and then replaces
// both sides with the JSON string "[redacted]". A nil Keys reports false.
func (r Redactor) Path(path string) bool {
	if len(r.Keys) == 0 || path == "" {
		return false
	}
	p := strings.ToLower(path)
	for key, ok := range r.Keys {
		if !ok {
			continue
		}
		if p == key || strings.HasSuffix(p, "."+key) || strings.HasSuffix(p, "/"+key) {
			return true
		}
	}
	return false
}

// Value redacts one JSON value the way JSON does, then replaces it with the
// JSON string "[redacted]" when Path(path) is true.
func (r Redactor) Value(path string, b []byte) ([]byte, error) {
	if r.Path(path) {
		return []byte(`"` + redacted + `"`), nil
	}
	return r.JSON(b)
}

func (r Redactor) walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if r.secretKey(k) {
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
		if r.PEM && containsPrivateKey(t) {
			return redacted
		}
		return t
	default:
		return v
	}
}

func (r Redactor) secretKey(k string) bool {
	if len(r.Keys) == 0 {
		return false
	}
	return r.Keys[strings.ToLower(k)]
}

func (r Redactor) blankColonLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for key, ok := range r.Keys {
			if !ok {
				continue
			}
			if strings.Contains(lower, key+":") {
				if idx := strings.Index(line, ":"); idx >= 0 {
					lines[i] = line[:idx+1] + " " + redacted
					break
				}
			}
		}
	}
	return strings.Join(lines, "\n")
}

func containsPrivateKey(s string) bool {
	return strings.Contains(s, "BEGIN ") && strings.Contains(s, "PRIVATE")
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
