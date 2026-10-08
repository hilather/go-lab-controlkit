package mcpstrict

import (
	"encoding/json"
	"errors"
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
	})
}
