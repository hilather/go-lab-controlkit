// Package idem is a bounded idempotency cache.
// Fingerprint fields, the "key required" rule, and forgetting a key on a
// revision conflict stay in the consumer. Keys are not scoped by actor.
package idem

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// Eviction selects which stored record is dropped when the cache is full.
// The zero value is a constructor error.
type Eviction int

const (
	// LRU drops the record whose Lookup or Store is oldest.
	// A replay moves the record to the front. dns, ntp, snmp, netconf
	// and maildev use this.
	LRU Eviction = iota + 1
	// FIFOByInsert drops the record with the smallest insert sequence.
	// A replay does not move it. syslog uses this.
	FIFOByInsert
)

// ErrConflict is a replay whose fingerprint does not match the stored one.
// Facades map it onto their wire code. netconf uses validation_failed.
var ErrConflict = kerr.New(kerr.Invalid, "idempotency conflict")

type entry[V any] struct {
	key string
	fp  string
	val V
}

// Cache stores completed idempotent results.
type Cache[V any] struct {
	max int
	ev  Eviction
	ll  *list.List
	idx map[string]*list.Element
}

// New builds a cache. max must be positive. ev must be LRU or FIFOByInsert.
func New[V any](max int, ev Eviction) (*Cache[V], error) {
	if max <= 0 {
		return nil, kerr.New(kerr.Invalid, "idem: max is required")
	}
	if ev != LRU && ev != FIFOByInsert {
		return nil, kerr.New(kerr.Invalid, "idem: eviction policy is required")
	}
	return &Cache[V]{
		max: max,
		ev:  ev,
		ll:  list.New(),
		idx: make(map[string]*list.Element),
	}, nil
}

// Lookup returns the stored value when key and fp both match.
// A matching key with a different fingerprint returns ErrConflict.
// A missing key returns the zero value and hit false.
// An LRU hit moves the record to the front. A FIFO hit does not.
func (c *Cache[V]) Lookup(key, fp string) (V, bool, error) {
	var zero V
	if c == nil {
		return zero, false, kerr.New(kerr.Invalid, "idem: cache is required")
	}
	el := c.idx[key]
	if el == nil {
		return zero, false, nil
	}
	ent := el.Value.(*entry[V])
	if ent.fp != fp {
		return zero, false, ErrConflict
	}
	if c.ev == LRU {
		c.ll.MoveToFront(el)
	}
	return ent.val, true, nil
}

// Store inserts or replaces key. When the cache is over max, LRU drops the
// back of the recency list and FIFOByInsert drops the oldest insert.
func (c *Cache[V]) Store(key, fp string, v V) {
	if c == nil {
		return
	}
	if el := c.idx[key]; el != nil {
		ent := el.Value.(*entry[V])
		ent.fp = fp
		ent.val = v
		if c.ev == LRU {
			c.ll.MoveToFront(el)
		}
		return
	}
	el := c.ll.PushBack(&entry[V]{key: key, fp: fp, val: v})
	if c.ev == LRU {
		c.ll.MoveToFront(el)
	}
	c.idx[key] = el
	if c.ll.Len() > c.max {
		c.drop(c.victim())
	}
}

// Evict removes key when it is present.
func (c *Cache[V]) Evict(key string) {
	if c == nil {
		return
	}
	if el := c.idx[key]; el != nil {
		c.drop(el)
	}
}

// Clear drops every record.
func (c *Cache[V]) Clear() {
	if c == nil {
		return
	}
	c.ll.Init()
	c.idx = make(map[string]*list.Element)
}

// Len is the number of stored records.
func (c *Cache[V]) Len() int {
	if c == nil {
		return 0
	}
	return c.ll.Len()
}

func (c *Cache[V]) victim() *list.Element {
	if c.ev == LRU {
		return c.ll.Back()
	}
	return c.ll.Front()
}

func (c *Cache[V]) drop(el *list.Element) {
	if el == nil {
		return
	}
	ent := el.Value.(*entry[V])
	delete(c.idx, ent.key)
	c.ll.Remove(el)
}

// Fingerprint is the hex SHA-256 of the canonical JSON of parts.
// encoding/json sorts object keys. The parts are one JSON array, in order.
// A value that cannot be encoded as JSON returns an error.
func Fingerprint(parts ...any) (string, error) {
	raw, err := json.Marshal(parts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
