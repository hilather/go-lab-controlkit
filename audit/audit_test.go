package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type row struct {
	ID     string
	Result string
	Name   string
}

func setID(e *row, id string) { e.ID = id }

func isDenied(e row) bool { return e.Result == "denied" }

func TestRingBoundsOrder(t *testing.T) {
	r, err := NewRing[row](RingOptions[row]{Max: 3, SetID: setID})
	if err != nil {
		t.Fatal(err)
	}
	a := r.Append(row{Result: "ok", Name: "a"})
	b := r.Append(row{Result: "ok", Name: "b"})
	r.Append(row{Result: "ok", Name: "c"})
	r.Append(row{Result: "ok", Name: "d"})
	if r.Len() != 3 {
		t.Fatal(r.Len())
	}
	got := r.List(0)
	if len(got) != 3 || got[0].Name != "b" || got[2].Name != "d" {
		t.Fatalf("order %+v", got)
	}
	if _, ok := r.Get(a.ID); ok {
		t.Fatal("oldest id survived")
	}
	if found, ok := r.Get(b.ID); !ok || found.Name != "b" {
		t.Fatal("missing b")
	}
	recent := r.List(1)
	if len(recent) != 1 || recent[0].Name != "d" {
		t.Fatalf("recent %+v", recent)
	}
}

func TestRingWipeResize(t *testing.T) {
	r, err := NewRing[row](RingOptions[row]{Max: 4, SetID: setID})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c", "d"} {
		r.Append(row{Name: name, Result: "ok"})
	}
	if err := r.Resize(2); err != nil {
		t.Fatal(err)
	}
	got := r.List(0)
	if len(got) != 2 || got[0].Name != "c" || got[1].Name != "d" {
		t.Fatalf("resize %+v", got)
	}
	if err := r.Resize(0); err == nil {
		t.Fatal("resize 0")
	}
	r.Wipe()
	if r.Len() != 0 || len(r.List(0)) != 0 {
		t.Fatal("wipe")
	}
	if _, err := NewRing[row](RingOptions[row]{Max: 0, SetID: setID}); err == nil {
		t.Fatal("max 0")
	}
}

func TestFanoutBestEffort(t *testing.T) {
	r, err := NewRing[row](RingOptions[row]{Max: 4, SetID: setID})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFanout(r, func(e row) row {
		e.Name = "redacted"
		return e
	}, func(row) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	stored := f.Record(row{Name: "secret", Result: "ok"})
	if stored.Name != "redacted" {
		t.Fatal(stored.Name)
	}
	if f.DeliveryFailures() != 0 || r.Len() != 1 {
		t.Fatalf("fails %d len %d", f.DeliveryFailures(), r.Len())
	}
}

func TestDeliveryFailures(t *testing.T) {
	r, err := NewRing[row](RingOptions[row]{Max: 2, SetID: setID})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFanout[row](r, nil, func(row) error { return errors.New("down") })
	if err != nil {
		t.Fatal(err)
	}
	f.Record(row{Name: "a", Result: "ok"})
	f.Record(row{Name: "b", Result: "ok"})
	if f.DeliveryFailures() != 2 {
		t.Fatal(f.DeliveryFailures())
	}
	if r.Len() != 2 {
		t.Fatal("sink failure dropped the row")
	}
}

func TestRedaction(t *testing.T) {
	secret := "super-secret-value"
	pem := "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----"
	rd := Redactor{Keys: map[string]bool{"token": true, "password": true}, PEM: true, BearerPrefix: true}
	out := rd.Map(map[string]any{
		"token":    secret,
		"password": secret,
		"note":     "Bearer " + secret + " and " + pem,
		"nested":   map[string]any{"token": secret},
	})
	blob := mustJSON(t, out)
	if strings.Contains(blob, secret) || strings.Contains(blob, "BEGIN PRIVATE") {
		t.Fatalf("secret survived: %s", blob)
	}
	if !strings.Contains(blob, "[redacted]") || !strings.Contains(blob, "Bearer [redacted]") {
		t.Fatalf("redaction marker missing: %s", blob)
	}
	js, err := rd.JSON([]byte(`{"token":"` + secret + `","note":"Bearer ` + secret + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), secret) {
		t.Fatal(string(js))
	}
}

func TestDeniedFloodGuard(t *testing.T) {
	r, err := NewRing[row](RingOptions[row]{
		Max:         4,
		SetID:       setID,
		IsDenied:    isDenied,
		DeniedShare: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Append(row{Result: "ok", Name: "apply"})
	r.Append(row{Result: "ok", Name: "reset"})
	r.Append(row{Result: "denied", Name: "d1"})
	r.Append(row{Result: "denied", Name: "d2"})
	for i := 0; i < 20; i++ {
		r.Append(row{Result: "denied", Name: "flood"})
	}
	var okNames []string
	for _, e := range r.List(0) {
		if e.Result == "ok" {
			okNames = append(okNames, e.Name)
		}
	}
	if len(okNames) != 2 || okNames[0] != "apply" || okNames[1] != "reset" {
		t.Fatalf("ok rows = %v", okNames)
	}

	var now time.Time
	rec := &CountRecorder{}
	g, err := NewDeniedGuard(rec, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ev := DeniedEvent{ActorID: "alice", ErrorCode: "forbidden"}
	for i := 0; i < 10; i++ {
		if !g.Admit(ev) {
			t.Fatalf("burst admit %d", i)
		}
	}
	if g.Admit(ev) {
		t.Fatal("11th admit")
	}
	if g.Suppressed() != 1 {
		t.Fatal(g.Suppressed())
	}
	for i := 0; i < 5; i++ {
		g.RecordDenied(context.Background(), ev)
	}
	if g.Suppressed() != 6 {
		t.Fatal(g.Suppressed())
	}
	if len(rec.Events()) != 0 {
		t.Fatal("refused events were recorded")
	}
	now = now.Add(time.Second)
	g.RecordDenied(context.Background(), ev)
	if len(rec.Events()) != 1 {
		t.Fatalf("refill recorded %d", len(rec.Events()))
	}
	other := ev
	other.ActorID = ""
	other.RemoteKey = "203.0.113.5"
	if !g.Admit(other) {
		t.Fatal("a different key shares the flooded bucket")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
