package mcpstrict

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
)

func FuzzCheck(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"view":{"mode":"rate","minPoll":1}}`))
	f.Add([]byte(" "))
	f.Add([]byte(`{"\ud800\u0041":1,"\ufffdA":1}`))
	f.Add([]byte(`{"\ud800\u0041":1,"\ufffd":1}`))
	f.Add([]byte(`{"\ud800":1,"\ufffd":1}`))
	f.Add([]byte(`{"\uD800\uDC00":1,"\ufffd":1}`))
	f.Add([]byte("{\"a\xff\":1,\"a\\uFFFD\":1}"))
	f.Add([]byte("{\"a\xff\":1}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		spec := Spec{
			Typed: map[string]KeySet{
				"/view": {Keys: map[string]bool{"mode": true, "leap": true}},
			},
			Open: map[string]func(json.RawMessage) error{
				"/state": func(msg json.RawMessage) error {
					if len(msg) > 0 && msg[0] == 'n' {
						return errors.New("null state")
					}
					return nil
				},
			},
		}
		_ = Check(raw, spec)
		err := Check(raw, Spec{})
		dup, parsed := jsonKeyCollision(raw)
		if !parsed {
			return
		}
		got := err != nil && strings.Contains(err.Error(), "duplicate key")
		if got != dup {
			t.Fatalf("duplicate check=%v oracle=%v raw=%q", err, dup, raw)
		}
		// Byte bound for the no-spec call only. Spec.Typed is not covered:
		// a Typed /* walk over a flat array measured about 66× to 71×.
		// testing.AllocsPerRun pins GOMAXPROCS to 1 and samples around a
		// warm-up so a process-wide TotalAlloc delta is not mixed with
		// other fuzz workers. A raw ReadMemStats inside the fuzz function
		// is noisy under -race and when workers run together, so tiny
		// inputs are skipped: fixed overhead dominates k*len there. A
		// wide object with Spec{} measured about 20× (duplicate-key map
		// and key strings) and stayed linear. The pair-array shape, a
		// flat array of small two-key objects, measured about 41.15× and
		// is pinned by pairAllocLimit at 58× + 256 KiB. 58× plus 1 MiB
		// covers that shape, and still fails the old depth copy
		// (hundreds of times the input).
		if len(raw) >= fuzzAllocMin {
			avg := bytesPerRun(1, func() { _ = Check(raw, Spec{}) })
			limit := float64(fuzzAllocMul*len(raw) + fuzzAllocSlack)
			if avg > limit {
				t.Fatalf("Check allocated %.0f bytes for %d-byte input; limit %.0f", avg, len(raw), limit)
			}
		}
	})
}

// fuzzAllocMin skips the bound on tiny inputs. fuzzAllocMul and
// fuzzAllocSlack bound TotalAlloc for one Spec{} Check. They do not
// bound a non-empty Spec.Typed. A wide Spec{} object is about 20×.
// The pair-array shape, a flat array of small two-key objects, is
// about 41.15× and stays under 58×.
const (
	fuzzAllocMin   = 2048
	fuzzAllocMul   = 58
	fuzzAllocSlack = 1 << 20
)

// bytesPerRun measures average bytes allocated by fn, the way
// testing.AllocsPerRun measures mallocs: one P, a warm-up call, then
// a TotalAlloc delta. runs is the number of measured calls.
func bytesPerRun(runs int, fn func()) float64 {
	if runs < 1 {
		runs = 1
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	fn()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	before := m.TotalAlloc
	for i := 0; i < runs; i++ {
		fn()
	}
	runtime.ReadMemStats(&m)
	return float64(m.TotalAlloc-before) / float64(runs)
}
