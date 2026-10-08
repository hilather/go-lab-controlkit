package mcpstrict

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
)

func TestCheckAcceptsEmpty(t *testing.T) {
	spec := Spec{}
	for _, raw := range []json.RawMessage{nil, {}, []byte("{}"), []byte("null"), []byte("  \n\t ")} {
		if err := Check(raw, spec); err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
	}
}

func TestCheckRejectsDuplicateKeys(t *testing.T) {
	err := Check([]byte(`{"a":1,"a":2}`), Spec{})
	if !kindIs(err, kerr.Invalid) || !strings.Contains(err.Error(), `duplicate key "a"`) {
		t.Fatal(err)
	}
	err = Check([]byte(`{"a":{"b":1,"b":2}}`), Spec{})
	if err == nil || !strings.Contains(err.Error(), `duplicate key "b" at /a`) {
		t.Fatal(err)
	}
	err = Check([]byte(`{"a":1,"\u0061":2}`), Spec{})
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatal(err)
	}
	called := false
	spec := Spec{
		Typed: map[string]KeySet{"": {Keys: map[string]bool{"a": true}}},
		Open: map[string]func(json.RawMessage) error{
			"": func(json.RawMessage) error { called = true; return errors.New("open") },
		},
	}
	err = Check([]byte(`{"a":1,"a":2,"extra":1}`), spec)
	if err == nil || !strings.Contains(err.Error(), "duplicate") || called {
		t.Fatalf("err %v called %v", err, called)
	}
}

func TestCheckTypedViewSpecAndSizeKeys(t *testing.T) {
	viewKeys := map[string]bool{
		"mode": true, "offset": true, "absolute": true, "freezeAt": true,
		"rate": true, "epoch": true, "leap": true, "stratum": true,
		"refid": true, "precision": true, "rootDelay": true, "rootDispersion": true,
		"jitter": true, "minpoll": true, "maxpoll": true,
	}
	storeKeys := map[string]bool{
		"maxMessages": true, "maxBytes": true, "MaxBytes": true, "fullPolicy": true,
	}
	spec := Spec{Typed: map[string]KeySet{
		"/view":               {Keys: viewKeys},
		"/operations/*/store": {Keys: storeKeys},
	}}
	// Omitted minpoll/rate stay valid: Check does not enforce required.
	view := []byte(`{"view":{"mode":"rate","leap":"none","stratum":2,"refid":"LOCL"}}`)
	if err := Check(view, spec); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`{"view":{"mode":"rate","minPoll":16}}`)
	err := Check(bad, spec)
	if err == nil || !strings.Contains(err.Error(), `unknown key "minPoll" at /view`) {
		t.Fatal(err)
	}
	mail := []byte(`{"operations":[{"op":"replaceStoreCaps","store":{"maxMessages":1000,"MaxBytes":1024,"fullPolicy":"reject"}}]}`)
	if err := Check(mail, spec); err != nil {
		t.Fatal(err)
	}
	unknown := []byte(`{"operations":[{"store":{"maxMessages":1,"nope":true}}]}`)
	err = Check(unknown, spec)
	if err == nil || !strings.Contains(err.Error(), `unknown key "nope"`) {
		t.Fatal(err)
	}
	if err := Check([]byte(`{}`), spec); err != nil {
		t.Fatal(err)
	}
}

func TestCheckOpenValidator(t *testing.T) {
	spec := Spec{Open: map[string]func(json.RawMessage) error{
		"/state": func(raw json.RawMessage) error {
			if len(raw) == 0 || raw[0] != '{' {
				return errors.New("state must be an object")
			}
			return nil
		},
	}}
	if err := Check([]byte(`{"state":{"x":1}}`), spec); err != nil {
		t.Fatal(err)
	}
	err := Check([]byte(`{"state":1}`), spec)
	if err == nil || !kindIs(err, kerr.Invalid) || !strings.Contains(err.Error(), "state must be an object") {
		t.Fatal(err)
	}
	if err := Check([]byte(`{"other":1}`), spec); err != nil {
		t.Fatal(err)
	}
}

func TestCheckNestingDepth(t *testing.T) {
	if err := Check(nestedArrays(10000), Spec{}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{10001, 1000000} {
		err := Check(nestedArrays(n), Spec{})
		if err == nil || !kindIs(err, kerr.Invalid) || !strings.Contains(err.Error(), "mcpstrict: invalid json") {
			t.Fatalf("depth %d: %v", n, err)
		}
	}
}

func nestedArrays(n int) json.RawMessage {
	b := make([]byte, 0, n*2)
	for i := 0; i < n; i++ {
		b = append(b, '[')
	}
	for i := 0; i < n; i++ {
		b = append(b, ']')
	}
	return b
}

func kindIs(err error, k kerr.Kind) bool {
	got, ok := kerr.KindOf(err)
	return ok && got == k
}
