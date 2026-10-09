package kittest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/mcpstrict"
)

// DuplicateKeyNoEffect checks that a later duplicate root key fails
// mcpstrict.Check and leaves the caller's observable state unchanged.
// doc is a JSON object that passes Check with spec. snapshot reports
// that state: a log line, a metric, an audit row. The helper appends a
// second copy of the first root key, requires the duplicate-key error,
// and requires snapshot to return the same string before and after that
// call. A nested Open validator runs when its value ends, which can be
// before Check reports the later duplicate, so the snapshot still has to
// match. The root validator does not run once a duplicate key fails the parse.
func DuplicateKeyNoEffect(t Testing, spec mcpstrict.Spec, doc json.RawMessage, snapshot func() string) {
	t.Helper()
	if err := mcpstrict.Check(doc, spec); err != nil {
		t.Fatalf("document: %v", err)
	}
	dup, err := withLaterDuplicateKey(doc)
	if err != nil {
		t.Fatalf("duplicate document: %v", err)
	}
	before := snapshot()
	err = mcpstrict.Check(dup, spec)
	if !isDuplicateKey(err) {
		t.Fatalf("duplicate key: %v", err)
	}
	if after := snapshot(); before != after {
		t.Fatalf("snapshot changed from %q to %q", before, after)
	}
}

func isDuplicateKey(err error) bool {
	kind, ok := kerr.KindOf(err)
	return ok && kind == kerr.Invalid && strings.Contains(err.Error(), "duplicate key")
}

func withLaterDuplicateKey(doc json.RawMessage) (json.RawMessage, error) {
	raw := bytes.TrimSpace(doc)
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return nil, errors.New("document is not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("document is not a JSON object")
	}
	tok, err = dec.Token()
	if err != nil {
		return nil, err
	}
	key, ok := tok.(string)
	if !ok {
		return nil, errors.New("document has no root key to duplicate")
	}
	quoted, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	extra := append(append([]byte{','}, quoted...), ':', '0')
	out := make([]byte, 0, len(raw)+len(extra))
	out = append(out, raw[:len(raw)-1]...)
	out = append(out, extra...)
	out = append(out, '}')
	return out, nil
}
