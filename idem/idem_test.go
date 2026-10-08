package idem

import (
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
)

func TestNewRequiresMaxAndEviction(t *testing.T) {
	if _, err := New[int](0, LRU); err == nil || !kindIs(err, kerr.Invalid) {
		t.Fatalf("zero max: %v", err)
	}
	if _, err := New[int](-1, LRU); err == nil {
		t.Fatal("negative max accepted")
	}
	if _, err := New[int](2, 0); err == nil {
		t.Fatal("zero eviction accepted")
	}
}

func TestLRUReplayMovesToFront(t *testing.T) {
	c := mustCache[string](t, 2, LRU)
	c.Store("a", "fa", "va")
	c.Store("b", "fb", "vb")
	if _, hit, err := c.Lookup("a", "fa"); err != nil || !hit {
		t.Fatalf("replay a: hit %v err %v", hit, err)
	}
	c.Store("c", "fc", "vc")
	if _, hit, _ := c.Lookup("b", "fb"); hit {
		t.Fatal("lru evicted the replayed key")
	}
	if v, hit, err := c.Lookup("a", "fa"); err != nil || !hit || v != "va" {
		t.Fatalf("a after eviction: %q hit %v err %v", v, hit, err)
	}
	if _, hit, _ := c.Lookup("c", "fc"); !hit {
		t.Fatal("newest key was evicted")
	}
}

func TestFIFOByInsertReplayDoesNotBump(t *testing.T) {
	c := mustCache[string](t, 2, FIFOByInsert)
	c.Store("a", "fa", "va")
	c.Store("b", "fb", "vb")
	if _, hit, err := c.Lookup("a", "fa"); err != nil || !hit {
		t.Fatalf("replay: hit %v err %v", hit, err)
	}
	c.Store("c", "fc", "vc")
	if _, hit, _ := c.Lookup("a", "fa"); hit {
		t.Fatal("fifo kept the oldest insert")
	}
	if _, hit, _ := c.Lookup("b", "fb"); !hit {
		t.Fatal("fifo evicted a newer insert")
	}
	if c.Len() != 2 {
		t.Fatalf("len %d", c.Len())
	}
}

func TestLookupConflict(t *testing.T) {
	c := mustCache[int](t, 2, LRU)
	c.Store("k", "fp", 7)
	v, hit, err := c.Lookup("k", "other")
	if err != ErrConflict || hit || v != 0 || !kindIs(err, kerr.Invalid) {
		t.Fatalf("conflict v %d hit %v err %v", v, hit, err)
	}
	if err.Error() != "idempotency conflict" {
		t.Fatal(err)
	}
	v, hit, err = c.Lookup("missing", "fp")
	if err != nil || hit || v != 0 {
		t.Fatalf("miss v %d hit %v err %v", v, hit, err)
	}
	if _, hit, err := c.Lookup("k", "fp"); err != nil || !hit {
		t.Fatal("conflict removed the record")
	}
}

func TestClearAndEvict(t *testing.T) {
	c := mustCache[int](t, 4, FIFOByInsert)
	c.Store("a", "fa", 1)
	c.Store("b", "fb", 2)
	c.Evict("a")
	if _, hit, _ := c.Lookup("a", "fa"); hit {
		t.Fatal("evict left a")
	}
	if _, hit, _ := c.Lookup("b", "fb"); !hit {
		t.Fatal("evict removed b")
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("len %d", c.Len())
	}
	if _, hit, _ := c.Lookup("b", "fb"); hit {
		t.Fatal("clear left b")
	}
}

func TestFingerprintCanonical(t *testing.T) {
	a, err := Fingerprint(map[string]any{"b": 1, "a": "x"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Fingerprint(map[string]any{"a": "x", "b": 1}, "op")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("map order changed the digest %s %s", a, b)
	}
	c, err := Fingerprint("op", map[string]any{"a": "x", "b": 1})
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("part order was ignored")
	}
	if _, err := Fingerprint(func() {}); err == nil {
		t.Fatal("function fingerprinted")
	}
	empty, err := Fingerprint()
	if err != nil || empty == "" {
		t.Fatal(err)
	}
}

func mustCache[V any](t *testing.T, max int, ev Eviction) *Cache[V] {
	t.Helper()
	c, err := New[V](max, ev)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func kindIs(err error, k kerr.Kind) bool {
	got, ok := kerr.KindOf(err)
	return ok && got == k
}
