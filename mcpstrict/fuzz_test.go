package mcpstrict

import (
	"encoding/json"
	"errors"
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
	})
}
