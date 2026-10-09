package mcpstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
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
	// Same star count: the allowed set is the intersection. Fewer stars wins
	// over a wider star pattern.
	both := Spec{Typed: map[string]KeySet{
		"/x/*": {Keys: map[string]bool{"keep": true, "other": true}},
		"/*/y": {Keys: map[string]bool{"keep": true, "drop": true}},
	}}
	if err := Check([]byte(`{"x":{"y":{"keep":1}}}`), both); err != nil {
		t.Fatal(err)
	}
	err = Check([]byte(`{"x":{"y":{"keep":1,"drop":2}}}`), both)
	if err == nil || !strings.Contains(err.Error(), `unknown key "drop" at /x/y`) {
		t.Fatal(err)
	}
	fewer := Spec{Typed: map[string]KeySet{
		"/x/*": {Keys: map[string]bool{"y": true}},
		"/*/*": {Keys: map[string]bool{"y": true, "z": true}},
	}}
	err = Check([]byte(`{"x":{"y":{"y":1,"z":2}}}`), fewer)
	if err == nil || !strings.Contains(err.Error(), `unknown key "z" at /x/y`) {
		t.Fatal(err)
	}
}

func TestCheckOpenValidator(t *testing.T) {
	want := errors.New("state must be an object")
	spec := Spec{Open: map[string]func(json.RawMessage) error{
		"/state": func(raw json.RawMessage) error {
			if len(raw) == 0 || raw[0] != '{' {
				return want
			}
			return nil
		},
	}}
	if err := Check([]byte(`{"state":{"x":1}}`), spec); err != nil {
		t.Fatal(err)
	}
	err := Check([]byte(`{"state":1}`), spec)
	if err == nil || !kindIs(err, kerr.Invalid) {
		t.Fatal(err)
	}
	if err.Error() != "mcpstrict: invalid value at /state" {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "state must be an object") {
		t.Fatalf("validator text in sentence: %v", err)
	}
	if !errors.Is(err, want) || errors.Unwrap(err) != want {
		t.Fatalf("validator error not retained: %v", err)
	}
	if err := Check([]byte(`{"other":1}`), spec); err != nil {
		t.Fatal(err)
	}
}

func TestCheckOpenStablePathOnly(t *testing.T) {
	aErr := errors.New("secret-a")
	zErr := errors.New("secret-z")
	spec := Spec{Open: map[string]func(json.RawMessage) error{
		"/z": func(json.RawMessage) error { return zErr },
		"/a": func(json.RawMessage) error { return aErr },
	}}
	raw := []byte(`{"z":1,"a":1}`)
	for i := 0; i < 20; i++ {
		err := Check(raw, spec)
		if err == nil || err.Error() != "mcpstrict: invalid value at /a" {
			t.Fatalf("call %d: %v", i, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal(err)
		}
		if !errors.Is(err, aErr) || !kindIs(err, kerr.Invalid) {
			t.Fatal(err)
		}
	}
	star := Spec{Open: map[string]func(json.RawMessage) error{
		"/items/*": func(json.RawMessage) error { return errors.New("nope") },
	}}
	err := Check([]byte(`{"items":{"z":1,"a":2}}`), star)
	if err == nil || err.Error() != "mcpstrict: invalid value at /items/a" {
		t.Fatal(err)
	}
}

func TestCheckOpenLexicographicMinimum(t *testing.T) {
	starErr := errors.New("star")
	aErr := errors.New("akey")
	// "/*" < "/a". Under "/*", "/10" < "/2" < "/a". The minimum failing
	// pair is ("/*", "/10") even though "/2" and "/a" appear first.
	spec := Spec{Open: map[string]func(json.RawMessage) error{
		"/*": func(m json.RawMessage) error {
			if bytes.Equal(m, []byte("2")) || bytes.Equal(m, []byte("10")) {
				return starErr
			}
			return nil
		},
		"/a": func(json.RawMessage) error { return aErr },
	}}
	raw := []byte(`{"2":2,"a":1,"0":0,"10":10}`)
	err := Check(raw, spec)
	if err == nil || err.Error() != "mcpstrict: invalid value at /10" {
		t.Fatal(err)
	}
	if !errors.Is(err, starErr) || errors.Is(err, aErr) || !kindIs(err, kerr.Invalid) {
		t.Fatal(err)
	}
	if errors.Unwrap(err) != starErr {
		t.Fatal(err)
	}

	// Array indexes use the same path order: "/10" < "/2".
	arrSpec := Spec{Open: map[string]func(json.RawMessage) error{
		"/*": spec.Open["/*"],
	}}
	err = Check([]byte(`[0,1,2,3,4,5,6,7,8,9,10]`), arrSpec)
	if err == nil || err.Error() != "mcpstrict: invalid value at /10" || !errors.Is(err, starErr) {
		t.Fatal(err)
	}

	// A later smaller pattern beats a failure already held for "/a".
	later := Spec{Open: map[string]func(json.RawMessage) error{
		"/*": func(m json.RawMessage) error {
			if bytes.Equal(m, []byte("2")) {
				return starErr
			}
			return nil
		},
		"/a": func(json.RawMessage) error { return aErr },
	}}
	err = Check([]byte(`{"a":1,"b":2}`), later)
	if err == nil || err.Error() != "mcpstrict: invalid value at /b" || !errors.Is(err, starErr) {
		t.Fatal(err)
	}

	// The empty pattern sorts before every other pattern.
	rootErr := errors.New("root")
	both := Spec{Open: map[string]func(json.RawMessage) error{
		"":   func(m json.RawMessage) error { return rootErr },
		"/a": func(json.RawMessage) error { return aErr },
	}}
	err = Check([]byte(`{"a":1}`), both)
	if err == nil || err.Error() != "mcpstrict: invalid value at /" || !errors.Is(err, rootErr) || errors.Is(err, aErr) {
		t.Fatal(err)
	}
}

func TestCheckOpenPrecedenceAndRootNull(t *testing.T) {
	openErr := errors.New("open")
	called := 0
	spec := Spec{Open: map[string]func(json.RawMessage) error{
		"/a": func(m json.RawMessage) error {
			called++
			if string(m) != "1" {
				t.Fatalf("raw %s", m)
			}
			return openErr
		},
	}}
	err := Check([]byte(`{"a":1,"b":2,"b":3}`), spec)
	if err == nil || !strings.Contains(err.Error(), `duplicate key "b"`) || errors.Is(err, openErr) || called != 1 {
		t.Fatalf("err %v called %d", err, called)
	}
	// A duplicate before the open value is found first. The validator does not run.
	called = 0
	err = Check([]byte(`{"b":1,"b":2,"a":1}`), spec)
	if err == nil || !strings.Contains(err.Error(), `duplicate key "b"`) || called != 0 {
		t.Fatalf("err %v called %d", err, called)
	}

	called = 0
	typed := Spec{
		Typed: map[string]KeySet{"/view": {Keys: map[string]bool{"mode": true}}},
		Open: map[string]func(json.RawMessage) error{
			"/state": func(m json.RawMessage) error {
				called++
				if string(m) != "1" || cap(m) != len(m) {
					t.Fatalf("raw %q cap %d", m, cap(m))
				}
				return openErr
			},
		},
	}
	err = Check([]byte(`{"state":1,"view":{"minPoll":1}}`), typed)
	if err == nil || !strings.Contains(err.Error(), `unknown key "minPoll"`) || errors.Is(err, openErr) || called != 1 {
		t.Fatalf("err %v called %d", err, called)
	}

	called = 0
	err = Check([]byte(`{"a":1,"b":1e9999}`), spec)
	if err == nil || err.Error() != "mcpstrict: invalid json" || errors.Is(err, openErr) || called != 1 {
		t.Fatalf("err %v called %d", err, called)
	}
	err = Check([]byte(`{"a":1} true`), spec)
	if err == nil || err.Error() != "mcpstrict: trailing data" || errors.Is(err, openErr) {
		t.Fatal(err)
	}

	rootCalled := false
	root := Spec{Open: map[string]func(json.RawMessage) error{
		"": func(json.RawMessage) error { rootCalled = true; return openErr },
	}}
	for _, raw := range []string{`null`, `  null`, `null  `} {
		rootCalled = false
		if err := Check([]byte(raw), root); err != nil || rootCalled {
			t.Fatalf("%q err %v called %v", raw, err, rootCalled)
		}
	}
}

func TestCheckOpenRawSlice(t *testing.T) {
	raw := []byte(`{"state": {"x":1}, "n": 2}`)
	var kept json.RawMessage
	spec := Spec{Open: map[string]func(json.RawMessage) error{
		"/state": func(m json.RawMessage) error {
			kept = m
			return nil
		},
		"/n": func(m json.RawMessage) error {
			if string(m) != "2" || cap(m) != 1 {
				t.Fatalf("n %q cap %d", m, cap(m))
			}
			return nil
		},
	}}
	if err := Check(raw, spec); err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"x":1}`)
	off := bytes.Index(raw, want)
	if off < 0 || string(kept) != string(want) || cap(kept) != len(kept) {
		t.Fatalf("kept %q cap %d", kept, cap(kept))
	}
	raw[off] = 'X'
	if kept[0] != 'X' {
		t.Fatal("validator slice does not alias the input")
	}
	raw[off] = '{'
}

func TestCheckOpenWideMask(t *testing.T) {
	// 64 patterns: the last sorted one sits on bit 63.
	if err := checkLastPattern(t, 63); err != nil {
		t.Fatal(err)
	}
	// 65 patterns: the last sorted one sits in the second mask word.
	if err := checkLastPattern(t, 64); err != nil {
		t.Fatal(err)
	}

	// A sibling must not keep the previous child's live bits.
	stale := errors.New("stale")
	open := map[string]func(json.RawMessage) error{}
	for i := 0; i < 63; i++ {
		open[fmt.Sprintf("/e%04d/y", i)] = func(json.RawMessage) error { return stale }
	}
	open["/d0000/x"] = func(m json.RawMessage) error {
		if string(m) != "1" {
			t.Fatalf("stale raw %s", m)
		}
		return nil
	}
	zErr := errors.New("z")
	open["/z/b"] = func(m json.RawMessage) error {
		if string(m) != "2" || cap(m) != len(m) {
			t.Fatalf("z raw %q cap %d", m, cap(m))
		}
		return zErr
	}
	if len(open) <= 64 {
		t.Fatalf("patterns %d", len(open))
	}
	err := Check([]byte(`{"d0000":{"x":1},"z":{"b":2}}`), Spec{Open: open})
	if err == nil || err.Error() != "mcpstrict: invalid value at /z/b" || !errors.Is(err, zErr) || errors.Is(err, stale) {
		t.Fatal(err)
	}
}

// TestCheckOpenSiblingMaskClear checks that childMask zeros every word
// of the scratch mask siblings share. "/a/*" is live under "a"; without
// that clear the star validator also runs on /b/x. The wide subtest puts
// /a/* in the second mask word, so clearing only the first word fails.
func TestCheckOpenSiblingMaskClear(t *testing.T) {
	t.Run("one-word", func(t *testing.T) {
		checkStarNotCalledOnSibling(t, 0)
	})
	// 64 patterns sort before /a/*, so its bit is in the second mask word.
	// Zeroing only the first word would still call /a/* for /b/x.
	t.Run("wide", func(t *testing.T) {
		checkStarNotCalledOnSibling(t, 64)
	})
}

func checkStarNotCalledOnSibling(t *testing.T, dummies int) {
	t.Helper()
	var star []string
	bx := 0
	open := make(map[string]func(json.RawMessage) error, dummies+2)
	for i := 0; i < dummies; i++ {
		open[fmt.Sprintf("/0%04d/y", i)] = func(json.RawMessage) error {
			return errors.New("dummy pattern matched")
		}
	}
	open["/a/*"] = func(m json.RawMessage) error {
		star = append(star, string(m))
		return nil
	}
	open["/b/x"] = func(m json.RawMessage) error {
		bx++
		if string(m) != "2" {
			t.Errorf("/b/x raw %s", m)
		}
		return nil
	}
	before := 0
	for pattern := range open {
		if pattern < "/a/*" {
			before++
		}
	}
	if before != dummies {
		t.Fatalf("%d patterns sort before /a/*, want %d", before, dummies)
	}
	if dummies >= 64 && len(open) <= 64 {
		t.Fatalf("patterns %d", len(open))
	}
	err := Check([]byte(`{"a":{"x":1},"b":{"x":2}}`), Spec{Open: open})
	if err != nil {
		t.Fatal(err)
	}
	if len(star) != 1 || star[0] != "1" {
		t.Fatalf("/a/* calls %q, want only the value at /a/x", star)
	}
	if bx != 1 {
		t.Fatalf("/b/x calls %d", bx)
	}
}

func TestCheckDocReusedPathBuffer(t *testing.T) {
	doc := strings.Join(strings.Fields(funcDoc(t, "mcpstrict.go", "Check")), " ")
	for _, phrase := range []string{
		"Values are never copied",
		"One reused path buffer is updated for error locations and is not retained per node",
		"A path string is materialized only for a kept Open failure or an error",
	} {
		if !strings.Contains(doc, phrase) {
			t.Fatalf("Check doc missing %q:\n%s", phrase, doc)
		}
	}
	if strings.Contains(doc, "without path strings") {
		t.Fatalf("Check doc still says an unreachable subtree has no path strings:\n%s", doc)
	}
}

func funcDoc(t *testing.T, filename, name string) string {
	t.Helper()
	src, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	i := strings.Index(text, "func "+name+"(")
	if i < 0 {
		t.Fatalf("func %s not found", name)
	}
	lines := strings.Split(text[:i], "\n")
	var rev []string
	for n := len(lines) - 1; n >= 0; n-- {
		line := strings.TrimSpace(lines[n])
		if line == "" {
			if len(rev) > 0 {
				break
			}
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		rev = append(rev, strings.TrimSpace(strings.TrimPrefix(line, "//")))
	}
	if len(rev) == 0 {
		t.Fatalf("func %s has no doc comment", name)
	}
	parts := make([]string, len(rev))
	for n := range rev {
		parts[n] = rev[len(rev)-1-n]
	}
	return strings.Join(parts, "\n")
}

func checkLastPattern(t *testing.T, dummies int) error {
	t.Helper()
	want := errors.New("last")
	open := make(map[string]func(json.RawMessage) error, dummies+1)
	noop := func(json.RawMessage) error { return nil }
	for i := 0; i < dummies; i++ {
		open[fmt.Sprintf("/d%04d", i)] = noop
	}
	open["/z"] = func(m json.RawMessage) error {
		if string(m) != "1" || cap(m) != len(m) {
			return fmt.Errorf("raw %q cap %d", m, cap(m))
		}
		return want
	}
	err := Check([]byte(`{"z":1}`), Spec{Open: open})
	if err == nil || err.Error() != "mcpstrict: invalid value at /z" || !errors.Is(err, want) {
		if err == nil {
			return errors.New("missing open error for last pattern")
		}
		return fmt.Errorf("%v", err)
	}
	return nil
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
	// A leaf inside the 10000th container is valid JSON. One more container is not.
	cases := []struct {
		name string
		raw  json.RawMessage
		ok   bool
	}{
		{name: "arrays-10000", raw: nestedWithLeaf('[', ']', 10000, "0"), ok: true},
		{name: "arrays-10001", raw: nestedWithLeaf('[', ']', 10001, "0"), ok: false},
		{name: "objects-10000", raw: nestedObjects(10000, "1"), ok: true},
		{name: "objects-10001", raw: nestedObjects(10001, "1"), ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			uerr := json.Unmarshal(tc.raw, &v)
			err := Check(tc.raw, Spec{})
			if tc.ok {
				if uerr != nil {
					t.Fatalf("unmarshal: %v", uerr)
				}
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if uerr == nil {
				t.Fatal("unmarshal accepted a container past the encoding/json limit")
			}
			if err == nil || !kindIs(err, kerr.Invalid) || !strings.Contains(err.Error(), "mcpstrict: invalid json") {
				t.Fatalf("check: %v", err)
			}
		})
	}
}

func nestedWithLeaf(open, close byte, n int, leaf string) json.RawMessage {
	b := make([]byte, 0, n*2+len(leaf))
	for i := 0; i < n; i++ {
		b = append(b, open)
	}
	b = append(b, leaf...)
	for i := 0; i < n; i++ {
		b = append(b, close)
	}
	return b
}

func nestedObjects(n int, leaf string) json.RawMessage {
	const open = `{"a":`
	b := make([]byte, 0, n*len(open)+len(leaf)+n)
	for i := 0; i < n; i++ {
		b = append(b, open...)
	}
	b = append(b, leaf...)
	for i := 0; i < n; i++ {
		b = append(b, '}')
	}
	return b
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

// allocSlack is fixed overhead on top of a linear term: pattern compile
// and the path buffer (it doubles up to the longest pointer). Open
// matching does not copy a value per match. A flat "*" pattern calls the
// validator once per element and keeps at most one failure.
//
// Check's allocation is linear in the input. No shape measured on
// 2026-10-08 grew faster than linearly. From about 0.25 MiB to 2 MiB,
// doubling the input multiplied TotalAlloc by about 1.97× to 2.02×.
// The committed -race probe is smaller: 64 KiB to 128 KiB grew 2.10×
// for a root Typed decode and 2.06× for a flat Typed "/*" walk. The
// doubling check fails above 2.6×. allocLimit's 8× covers three
// fixtures, each at most about 3.5×: a nested array, a single-key deep
// object, and a flat array of zeros. A flat array of two-key objects
// is about 41× and uses pairAllocLimit. Wide objects and Spec.Typed
// have their own limits. 8× still fails the pre-fix Check, which
// allocated hundreds of times the input (KS-B1, KS-B1b).
const allocSlack = 256 << 10

// allocLimit bounds three fixtures: a nested array (deep-array/empty
// and deep-array/open), a single-key deep object (deep-object/empty,
// deep-object/open, and deep-object/open-levels), and a flat array of
// zeros (flat-array/empty, flat-array/open, flat-array/star, and
// flat-array/star-wide). Each measured at most about 3.5×. It does not
// cover a wide object, a Typed spec, or a flat array of two-key objects.
func allocLimit(n int) uint64 {
	return uint64(8*n) + allocSlack
}

const wideAllocMul = 28

// wideAllocLimit bounds a wide object of many short keys ("k0000000":0,
// ...) for Spec{} (wide-object/empty), one shallow Open match
// (wide-object/open, "/k0000000"), and Open "/*" (wide-object/star).
// On 2026-10-08 that shape allocated 19.59× the input without -race and
// 20.20× with -race, from 256 KiB through 2 MiB. The cost is one
// duplicate-key map for the whole object plus one decoded string per
// key. The ratio was flat. Doubling the input doubled TotalAlloc,
// including the 64 KiB to 128 KiB -race probe (2.00× for this shape).
// 28× is 1.4× that 20.20× worst ratio, rounded (1.39× headroom). The
// limit is linear in the input. Slack is allocSlack. A flat array of
// two-key objects is a map per object and uses pairAllocLimit. Typed
// specs use typedAllocLimit or typedStarAllocLimit.
func wideAllocLimit(n int) uint64 {
	return uint64(wideAllocMul*n) + allocSlack
}

const pairAllocMul = 58

// pairAllocLimit bounds a flat array of small two-key objects
// ({"a":0,"b":0}, ...) for Spec{} (pair-array/empty) and for Open "/*"
// (pair-array/star). On 2026-10-08, Go 1.26.9, that shape allocated
// 41.14× the input from 64 KiB through 2 MiB, with and without -race.
// The worst ratio was 41.15× (Open "/*", -race, 64 KiB). The cost is
// the duplicate-key map parseObject allocates on the second key of
// every object, plus one decoded string per key. "/*" added about 200
// bytes, not a copy per element. Doubling growth was 2.00×, including
// the 64 KiB to 128 KiB -race probe. 58× is 1.4× the 41.15× worst
// ratio, rounded (1.41× headroom). Slack is allocSlack. The 8×
// fixtures are a nested array, a single-key deep object, and a flat
// array of zeros. This shape is none of those.
func pairAllocLimit(n int) uint64 {
	return uint64(pairAllocMul*n) + allocSlack
}

const typedAllocMul = 60

// typedAllocLimit bounds a root Typed entry and a Typed "/*" walk over
// the keys of a wide object. The fixtures are typed/flat-array (root
// Typed on a flat array of numbers), typed/wide-object (root Typed on
// a wide object), and wide/typed-star (Typed "/*", the filterTyped
// path). On 2026-10-08 a non-empty Typed map decoded the input once
// with encoding/json, the same decode as before and as the MCP SDK. A
// flat array of numbers with a root Typed entry was about 43× (43.07×,
// the same with -race). A wide object with a root Typed entry was about
// 31× (31.44× under -race, 30.21× without), the decode on top of the
// duplicate-key map. A Typed "/*" walk over that wide object's keys was
// about 33.3× without -race and 34.52× with it (wide/typed-star in the
// 2026-10-08 table). That walk is above wideAllocLimit and under this
// limit. Root Typed returns before the child walk, so it does not pin
// filterTyped. The flat array's Typed "/*" walk is filterTypedIndex,
// about 71×, and uses typedStarAllocLimit. The pinned root shapes
// stayed linear on the 0.25 MiB to 2 MiB matrix (doubling growth about
// 1.97× to 2.00×). The committed -race probe, 64 KiB to 128 KiB, grew
// 2.10× for the flat root Typed decode. 60× is 1.4× the flat 43.07×,
// rounded (1.39× headroom). That is the higher of the pinned root
// shapes, so the wide object and its Typed "/*" walk use this limit
// too. The limit is linear in the input. Slack is allocSlack.
func typedAllocLimit(n int) uint64 {
	return uint64(typedAllocMul*n) + allocSlack
}

const typedStarAllocMul = 99

// typedStarAllocLimit bounds a Typed "/*" walk over every element of a
// flat array of numbers (flat/typed-star, filterTypedIndex). It does
// not cover a wide object's Typed "/*" walk (wide/typed-star,
// filterTyped, typedAllocLimit) or a flat array of two-key objects
// (pairAllocLimit). On 2026-10-08 that walk allocated 65.84× to 66.53×
// the input without -race and 69.97× to 71.06× with -race, from about
// 256 KiB through 2 MiB. The worst ratio is 71.06×. The extra over the
// root decode is one filtered pattern slice per element. On that
// matrix, doubling the input multiplied TotalAlloc by 1.98× to 2.02×.
// The committed -race probe, 64 KiB to 128 KiB, grew 2.06×. The walk
// is linear. The check fails above 2.6×. 99× is 1.4× that 71.06×,
// rounded (1.39× headroom). Slack is allocSlack.
func typedStarAllocLimit(n int) uint64 {
	return uint64(typedStarAllocMul*n) + allocSlack
}

// allocProbe is the smaller wide, pair, and typed input. The doubling
// check uses twice that. Without -race the larger input is about 1 MiB.
// A 2 MiB partner is not in the test: a typed decode of 2 MiB takes
// several seconds a sample. Under -race the probe is 64 KiB (larger
// input about 128 KiB). A 256 KiB typed pair took about 9 s under -race
// on 2026-10-08, and the ratio had already flattened by 256 KiB (20.20×
// wide, 43.04× flat Typed, 31.43× wide Typed, 34.52× wide Typed "/*",
// 65.97× flat Typed "/*" without -race and 71.04× with it). The two-key
// array was 41.14× from 64 KiB up, on Go 1.26.9. These cases use this
// same probe.
func allocProbe() int {
	if checkAllocRace() {
		return 64 << 10
	}
	return 512 << 10
}

func TestCheckAllocBound(t *testing.T) {
	deepArray := nestedArrays(9999)
	deepObj := deepObjectLongKeys(900, 1000)
	flat := flatZeroArray(1_000_000)
	if len(deepArray) != 19998 || len(deepObj) != 904501 || len(flat) != 999999 {
		t.Fatalf("shapes %d %d %d", len(deepArray), len(deepObj), len(flat))
	}
	noop := func(json.RawMessage) error { return nil }
	cases := []struct {
		name    string
		raw     []byte
		pat     string
		wantRaw string
	}{
		{name: "deep-array/empty", raw: deepArray},
		{name: "deep-array/open", raw: deepArray, pat: "/0", wantRaw: string(deepArray[1 : len(deepArray)-1])},
		{name: "deep-object/empty", raw: deepObj},
		{name: "deep-object/open", raw: deepObj, pat: "/*", wantRaw: string(deepObj[1004 : len(deepObj)-1])},
		{name: "flat-array/empty", raw: flat},
		{name: "flat-array/open", raw: flat, pat: "/0", wantRaw: "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := Spec{}
			if tc.pat != "" {
				var got []byte
				var calls int
				spec = Spec{Open: map[string]func(json.RawMessage) error{
					tc.pat: func(m json.RawMessage) error {
						calls++
						got = append([]byte(nil), m...)
						return nil
					},
				}}
				if err := Check(tc.raw, spec); err != nil {
					t.Fatal(err)
				}
				if calls != 1 || string(got) != tc.wantRaw {
					t.Fatalf("calls %d got %d bytes", calls, len(got))
				}
				spec = Spec{Open: map[string]func(json.RawMessage) error{tc.pat: noop}}
			} else if err := Check(tc.raw, Spec{}); err != nil {
				t.Fatal(err)
			}
			n := allocatedBytes(func() { _ = Check(tc.raw, spec) })
			limit := allocLimit(len(tc.raw))
			t.Logf("allocated %d limit %d input %d ratio %.2f", n, limit, len(tc.raw), float64(n)/float64(len(tc.raw)))
			if n > limit {
				t.Fatalf("allocated %d bytes, limit %d, input %d", n, limit, len(tc.raw))
			}
		})
	}

	// Every element matches "/*". The validator returns nil and allocates
	// nothing, so a retained raw per match would blow the bound.
	t.Run("flat-array/star", func(t *testing.T) {
		wantCalls := bytes.Count(flat, []byte("0"))
		calls := 0
		spec := Spec{Open: map[string]func(json.RawMessage) error{
			"/*": func(m json.RawMessage) error {
				calls++
				if len(m) != 1 || m[0] != '0' || cap(m) != len(m) {
					t.Fatalf("raw %q cap %d len %d", m, cap(m), len(m))
				}
				return nil
			},
		}}
		if err := Check(flat, spec); err != nil {
			t.Fatal(err)
		}
		if calls != wantCalls {
			t.Fatalf("calls %d want %d", calls, wantCalls)
		}
		measureOpenAlloc(t, flat, Spec{Open: map[string]func(json.RawMessage) error{"/*": noop}})
	})

	// More than 64 patterns takes the multi-word mask. A fresh []int per
	// element would exceed the bound on this array.
	t.Run("flat-array/star-wide", func(t *testing.T) {
		open := map[string]func(json.RawMessage) error{"/*": noop}
		for i := 0; i < 64; i++ {
			open[fmt.Sprintf("/nope/%d", i)] = noop
		}
		if len(open) != 65 {
			t.Fatalf("patterns %d", len(open))
		}
		measureOpenAlloc(t, flat, Spec{Open: open})
	})

	// Star patterns that match at many depths of the long-key object.
	// One pattern per level, not one raw copy per level.
	t.Run("deep-object/open-levels", func(t *testing.T) {
		const levels = 64
		calls := make([]int, levels)
		open := make(map[string]func(json.RawMessage) error, levels)
		for d := 1; d <= levels; d++ {
			d := d
			open[starPattern(d)] = func(m json.RawMessage) error {
				calls[d-1]++
				if len(m) == 0 || m[0] != '{' || cap(m) != len(m) {
					t.Fatalf("depth %d len %d cap %d", d, len(m), cap(m))
				}
				return nil
			}
		}
		if err := Check(deepObj, Spec{Open: open}); err != nil {
			t.Fatal(err)
		}
		for d, n := range calls {
			if n != 1 {
				t.Fatalf("depth %d calls %d", d+1, n)
			}
		}
		measure := make(map[string]func(json.RawMessage) error, levels)
		for d := 1; d <= levels; d++ {
			measure[starPattern(d)] = noop
		}
		measureOpenAlloc(t, deepObj, Spec{Open: measure})
	})

	// Wide objects, two-key object arrays, and Spec.Typed exceed
	// allocLimit and have their own linear limits. Each subtest measures
	// n and about 2n so a super-linear regression fails even when one
	// size stays under the multiplier. Growth above 2.6× fails. On the
	// 0.25 MiB to 2 MiB matrix, measured growth was at most about 2.02×.
	// The committed -race probe, 64 KiB to 128 KiB, grew 2.10× for a
	// root Typed decode and 2.06× for a flat Typed "/*" walk.
	probe := allocProbe()
	wideSmall, wideSmallKeys := wideZeroObject(probe)
	wideLarge, wideLargeKeys := wideZeroObject(probe * 2)
	flatSmall := flatZeroArray(probe)
	flatLarge := flatZeroArray(probe * 2)
	if len(wideLarge) < len(wideSmall)*19/10 || len(flatLarge) < len(flatSmall)*19/10 {
		t.Fatalf("probe sizes wide %d %d flat %d %d", len(wideSmall), len(wideLarge), len(flatSmall), len(flatLarge))
	}

	t.Run("wide-object/empty", func(t *testing.T) {
		measureAllocPair(t, wideSmall, wideLarge, Spec{}, wideAllocLimit)
	})
	t.Run("wide-object/open", func(t *testing.T) {
		const pat = "/k0000000"
		var got []byte
		var calls int
		spec := Spec{Open: map[string]func(json.RawMessage) error{
			pat: func(m json.RawMessage) error {
				calls++
				got = append([]byte(nil), m...)
				return nil
			},
		}}
		if err := Check(wideSmall, spec); err != nil {
			t.Fatal(err)
		}
		if calls != 1 || string(got) != "0" {
			t.Fatalf("calls %d got %q", calls, got)
		}
		measureAllocPair(t, wideSmall, wideLarge, Spec{Open: map[string]func(json.RawMessage) error{pat: noop}}, wideAllocLimit)
	})
	t.Run("wide-object/star", func(t *testing.T) {
		calls := 0
		spec := Spec{Open: map[string]func(json.RawMessage) error{
			"/*": func(m json.RawMessage) error {
				calls++
				if len(m) != 1 || m[0] != '0' || cap(m) != len(m) {
					t.Fatalf("raw %q cap %d len %d", m, cap(m), len(m))
				}
				return nil
			},
		}}
		if err := Check(wideSmall, spec); err != nil {
			t.Fatal(err)
		}
		if calls != wideSmallKeys {
			t.Fatalf("calls %d want %d", calls, wideSmallKeys)
		}
		measureAllocPair(t, wideSmall, wideLarge, Spec{Open: map[string]func(json.RawMessage) error{"/*": noop}}, wideAllocLimit)
	})
	// A root Typed entry forces one encoding/json decode of the whole
	// document. The flat array's elements are numbers, so the key set
	// does not reject them. The wide object's ratio is lower (the object
	// decode plus the duplicate-key map) and still above wideAllocLimit,
	// so it has this limit too. The key set allows every key of the
	// larger object; absent keys are allowed, so the smaller object passes.
	typedFlat := Spec{Typed: map[string]KeySet{"": {Keys: map[string]bool{"unused": true}}}}
	typedWide := wideTypedSpec(wideLargeKeys)
	t.Run("typed/flat-array", func(t *testing.T) {
		measureAllocPair(t, flatSmall, flatLarge, typedFlat, typedAllocLimit)
	})
	t.Run("typed/wide-object", func(t *testing.T) {
		measureAllocPair(t, wideSmall, wideLarge, typedWide, typedAllocLimit)
	})
	// A Typed "/*" walks every element of the flat array. The elements
	// are numbers, so the key set does not reject them. The cost above
	// the root decode is one filtered pattern slice per element.
	// typedAllocLimit (60×) does not cover it. The same probe as the
	// other typed cases keeps the -race run to a few seconds.
	typedStar := Spec{Typed: map[string]KeySet{"/*": {Keys: map[string]bool{"unused": true}}}}
	t.Run("flat/typed-star", func(t *testing.T) {
		measureAllocPair(t, flatSmall, flatLarge, typedStar, typedStarAllocLimit)
	})

	// Each object has two keys, so parseObject allocates a duplicate-key
	// map per element. That is outside the three allocLimit fixtures.
	// Open "/*" visits each object and must not copy it.
	pairSmall, pairSmallN := twoKeyObjectArray(probe)
	pairLarge, pairLargeN := twoKeyObjectArray(probe * 2)
	t.Run("pair-array/empty", func(t *testing.T) {
		measureAllocPair(t, pairSmall, pairLarge, Spec{}, pairAllocLimit)
	})
	t.Run("pair-array/star", func(t *testing.T) {
		calls := 0
		spec := Spec{Open: map[string]func(json.RawMessage) error{
			"/*": func(m json.RawMessage) error {
				calls++
				if string(m) != `{"a":0,"b":0}` || cap(m) != len(m) {
					t.Fatalf("raw %q cap %d len %d", m, cap(m), len(m))
				}
				return nil
			},
		}}
		if err := Check(pairSmall, spec); err != nil {
			t.Fatal(err)
		}
		if calls != pairSmallN {
			t.Fatalf("calls %d want %d", calls, pairSmallN)
		}
		if pairLargeN < pairSmallN*19/10 {
			t.Fatalf("objects %d %d", pairSmallN, pairLargeN)
		}
		measureAllocPair(t, pairSmall, pairLarge, Spec{Open: map[string]func(json.RawMessage) error{"/*": noop}}, pairAllocLimit)
	})

	// Typed "/*" on a wide object calls filterTyped once per key. Root
	// Typed returns before that walk. flat/typed-star calls
	// filterTypedIndex instead. The values are numbers, so the key set
	// does not reject them. About 34.5× under -race: above wideAllocLimit
	// and under typedAllocLimit.
	typedWideStar := Spec{Typed: map[string]KeySet{"/*": {Keys: map[string]bool{"unused": true}}}}
	t.Run("wide/typed-star", func(t *testing.T) {
		measureAllocPair(t, wideSmall, wideLarge, typedWideStar, typedAllocLimit)
	})
}

func measureOpenAlloc(t *testing.T, raw []byte, spec Spec) {
	t.Helper()
	n := allocatedBytes(func() { _ = Check(raw, spec) })
	limit := allocLimit(len(raw))
	t.Logf("allocated %d limit %d input %d ratio %.2f", n, limit, len(raw), float64(n)/float64(len(raw)))
	if n > limit {
		t.Fatalf("allocated %d bytes, limit %d, input %d", n, limit, len(raw))
	}
}

// measureAllocPair bounds both sizes and fails if doubling the input
// multiplies TotalAlloc by more than 2.6. On 2026-10-08 the 0.25 MiB to
// 2 MiB matrix grew by about 1.97× to 2.02×. The committed -race probe,
// 64 KiB to 128 KiB, grew 2.10× for a root Typed decode and 2.06× for a
// flat Typed "/*" walk. A flat array of two-key objects grew 2.00× at
// those same probe sizes.
func measureAllocPair(t *testing.T, small, large []byte, spec Spec, limit func(int) uint64) {
	t.Helper()
	n1 := measureOneAlloc(t, small, spec, limit)
	n2 := measureOneAlloc(t, large, spec, limit)
	if len(large) < len(small)*19/10 || len(large) > len(small)*21/10 {
		t.Fatalf("input %d -> %d is not about double", len(small), len(large))
	}
	if n1 == 0 || n2*10 > n1*26 {
		t.Fatalf("doubling alloc %d -> %d input %d -> %d", n1, n2, len(small), len(large))
	}
	t.Logf("doubling input %d -> %d alloc %d -> %d growth %.2f", len(small), len(large), n1, n2, float64(n2)/float64(n1))
}

func measureOneAlloc(t *testing.T, raw []byte, spec Spec, limit func(int) uint64) uint64 {
	t.Helper()
	if err := Check(raw, spec); err != nil {
		t.Fatal(err)
	}
	n := allocatedBytes(func() { _ = Check(raw, spec) })
	lim := limit(len(raw))
	t.Logf("allocated %d limit %d input %d ratio %.2f", n, lim, len(raw), float64(n)/float64(len(raw)))
	if n > lim {
		t.Fatalf("allocated %d bytes, limit %d, input %d", n, lim, len(raw))
	}
	return n
}

func starPattern(depth int) string {
	b := make([]byte, 0, depth*2)
	for i := 0; i < depth; i++ {
		b = append(b, '/', '*')
	}
	return string(b)
}

func TestCheckPointerEscape(t *testing.T) {
	raw := []byte(`{"~":{"/":1}}`)
	var got json.RawMessage
	spec := Spec{Open: map[string]func(json.RawMessage) error{
		"/~0/~1": func(m json.RawMessage) error {
			got = append(json.RawMessage(nil), m...)
			return nil
		},
	}}
	if err := Check(raw, spec); err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Fatalf("got %s", got)
	}
	esc := errors.New("escaped")
	err := Check([]byte(`{"~":{"/":1}}`), Spec{Open: map[string]func(json.RawMessage) error{
		"/~0/~1": func(json.RawMessage) error { return esc },
	}})
	if err == nil || err.Error() != "mcpstrict: invalid value at /~0/~1" || !errors.Is(err, esc) {
		t.Fatal(err)
	}
	err = Check([]byte(`{"a/b":1,"a/b":2}`), Spec{})
	if err == nil || !strings.Contains(err.Error(), `duplicate key "a/b" at /`) {
		t.Fatal(err)
	}
	err = Check([]byte(`{"a":{"b/c":1,"b/c":2}}`), Spec{})
	if err == nil || !strings.Contains(err.Error(), `duplicate key "b/c" at /a`) {
		t.Fatal(err)
	}
}

func TestCheckNumberRangeAndOrder(t *testing.T) {
	for _, raw := range []string{`1e9999`, `1e309`, `1.8e308`, `2e308`, `[1e9999]`, `{"a":1e9999}`} {
		err := Check([]byte(raw), Spec{})
		if err == nil || err.Error() != "mcpstrict: invalid json" {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{`1e308`, `1e-9999`, `0e9999`, `0.0e9999`, `1.7976931348623157e308`} {
		if err := Check([]byte(raw), Spec{}); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	err := Check([]byte(`{"a":1e9999,"a":1}`), Spec{})
	if err == nil || !strings.Contains(err.Error(), `duplicate key "a"`) {
		t.Fatal(err)
	}
	called := false
	spec := Spec{
		Typed: map[string]KeySet{"/view": {Keys: map[string]bool{"mode": true}}},
		Open: map[string]func(json.RawMessage) error{
			"": func(json.RawMessage) error { called = true; return errors.New("open") },
		},
	}
	err = Check([]byte(`1e9999`), spec)
	if err == nil || err.Error() != "mcpstrict: invalid json" || called {
		t.Fatalf("err %v called %v", err, called)
	}
	called = false
	err = Check([]byte(`{"view":{"minPoll":1}}`), spec)
	if err == nil || !strings.Contains(err.Error(), `unknown key "minPoll"`) || called {
		t.Fatalf("err %v called %v", err, called)
	}
}

func allocatedBytes(fn func()) uint64 {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	fn()
	runtime.GC()
	prev := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prev)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func deepObjectLongKeys(depth, keyLen int) []byte {
	key := strings.Repeat("k", keyLen)
	open := `{"` + key + `":`
	b := make([]byte, 0, depth*len(open)+1+depth)
	for i := 0; i < depth; i++ {
		b = append(b, open...)
	}
	b = append(b, '0')
	for i := 0; i < depth; i++ {
		b = append(b, '}')
	}
	return b
}

func wideZeroObject(target int) ([]byte, int) {
	b := make([]byte, 0, target+16)
	b = append(b, '{')
	keys := 0
	for {
		if keys > 0 {
			b = append(b, ',')
		}
		b = append(b, '"', 'k')
		var buf [7]byte
		n := keys
		for d := 6; d >= 0; d-- {
			buf[d] = byte('0' + n%10)
			n /= 10
		}
		b = append(b, buf[:]...)
		b = append(b, '"', ':', '0')
		keys++
		if len(b) >= target-1 {
			break
		}
	}
	b = append(b, '}')
	return b, keys
}

func wideTypedSpec(keys int) Spec {
	set := make(map[string]bool, keys)
	for i := 0; i < keys; i++ {
		set[fmt.Sprintf("k%07d", i)] = true
	}
	return Spec{Typed: map[string]KeySet{"": {Keys: set}}}
}

func twoKeyObjectArray(target int) ([]byte, int) {
	const elem = `{"a":0,"b":0}`
	if target < len(elem)+2 {
		return []byte(`[` + elem + `]`), 1
	}
	// n objects: '[' + elem + (',' + elem) * (n-1) + ']'.
	n := (target - 1) / (len(elem) + 1)
	if n < 1 {
		n = 1
	}
	b := make([]byte, 0, n*(len(elem)+1)+2)
	b = append(b, '[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, elem...)
	}
	b = append(b, ']')
	return b, n
}

func flatZeroArray(n int) []byte {
	if n < 2 {
		return []byte("[]")
	}
	b := make([]byte, 0, n)
	b = append(b, '[')
	for len(b) < n-1 {
		if len(b) > 1 {
			b = append(b, ',')
		}
		b = append(b, '0')
	}
	if len(b) > n-1 {
		b = b[:n-1]
		if len(b) > 0 && b[len(b)-1] == ',' {
			b = b[:len(b)-1]
		}
	}
	b = append(b, ']')
	return b
}
