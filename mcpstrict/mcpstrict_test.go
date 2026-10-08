package mcpstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

func TestCheckStringDecodeMatchesEncodingJSON(t *testing.T) {
	// An unpaired surrogate does not consume the following \uXXXX.
	// "\ud800\u0041" and "\ufffdA" are one key. "\ud800\u0041" and "\ufffd" are two.
	dup := []byte(`{"\ud800\u0041":1,"\ufffdA":1}`)
	err := Check(dup, Spec{})
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatal(err)
	}
	if err := Check([]byte(`{"\ud800\u0041":1,"\ufffd":1}`), Spec{}); err != nil {
		t.Fatal(err)
	}
	lone := []byte(`{"\ud800":1,"\ufffd":1}`)
	err = Check(lone, Spec{})
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatal(err)
	}
	if err := Check([]byte(`{"\uD800\uDC00":1,"\ufffd":1}`), Spec{}); err != nil {
		t.Fatal(err)
	}
	// Invalid UTF-8 is coerced to U+FFFD, so it collides with \uFFFD and is not invalid json.
	raw := []byte("{\"a\xff\":1,\"a\\uFFFD\":1}")
	err = Check(raw, Spec{})
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatal(err)
	}
	if err := Check([]byte("{\"a\xff\":1}"), Spec{}); err != nil {
		t.Fatalf("invalid utf-8 rejected: %v", err)
	}
	for _, raw := range [][]byte{
		dup, lone, raw,
		[]byte(`{"\ud800\u0041":1,"\ufffd":1}`),
		[]byte(`{"\uD800\uDC00":1,"\ufffd":1}`),
		[]byte("{\"a\xff\":1}"),
		[]byte(`{"a":1,"\u0061":2}`),
	} {
		want, parsed := jsonKeyCollision(raw)
		if !parsed {
			t.Fatalf("oracle rejected %q", raw)
		}
		err := Check(raw, Spec{})
		got := err != nil && strings.Contains(err.Error(), "duplicate key")
		if got != want {
			t.Fatalf("raw %q check %v oracle dup %v", raw, err, want)
		}
	}
}

// jsonKeyCollision reports whether decoding object keys with encoding/json
// yields a collision. parsed is false when encoding/json rejects the input.
func jsonKeyCollision(raw []byte) (dup bool, parsed bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dup, ok := walkJSONValue(dec)
	if !ok {
		return false, false
	}
	if dup {
		return true, true
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return false, false
	}
	return false, true
}

func walkJSONValue(dec *json.Decoder) (bool, bool) {
	tok, err := dec.Token()
	if err != nil {
		return false, false
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return false, true
	}
	switch d {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return false, false
			}
			key, isStr := kt.(string)
			if !isStr {
				return false, false
			}
			if _, exists := seen[key]; exists {
				return true, true
			}
			seen[key] = struct{}{}
			dup, ok := walkJSONValue(dec)
			if !ok || dup {
				return dup, ok
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return false, false
		}
		return false, true
	case '[':
		for dec.More() {
			dup, ok := walkJSONValue(dec)
			if !ok || dup {
				return dup, ok
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return false, false
		}
		return false, true
	default:
		return false, false
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
