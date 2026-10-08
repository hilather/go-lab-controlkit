package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
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
	if len(got) != 3 || got[0].Name != "d" || got[2].Name != "b" {
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

func TestRingListPageClamp(t *testing.T) {
	r, err := NewRing[row](RingOptions[row]{Max: 8, SetID: setID, DefaultList: 100, MaxList: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		r.Append(row{Name: name})
	}
	// maildev List(0) is newest-first and clamped, not the whole ring when it is longer than 100.
	got := r.List(0)
	if len(got) != 3 || got[0].Name != "c" || got[2].Name != "a" {
		t.Fatalf("short page %+v", got)
	}
	if len(r.List(1)) != 1 || r.List(1)[0].Name != "c" {
		t.Fatal(r.List(1))
	}
	wide, err := NewRing[row](RingOptions[row]{Max: 150, SetID: setID, DefaultList: 100, MaxList: 100})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		wide.Append(row{Name: "n"})
	}
	if len(wide.List(0)) != 100 || len(wide.List(1000)) != 100 || len(wide.List(2)) != 2 {
		t.Fatalf("clamp 0=%d 1000=%d 2=%d", len(wide.List(0)), len(wide.List(1000)), len(wide.List(2)))
	}
	// syslog leaves both limits at zero: List(0) returns every row, newest first.
	open, err := NewRing[row](RingOptions[row]{Max: 150, SetID: setID})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		open.Append(row{Name: "n"})
	}
	all := open.List(0)
	if len(all) != 120 {
		t.Fatalf("uncapped %d", len(all))
	}
	if _, err := NewRing[row](RingOptions[row]{Max: 1, SetID: setID, DefaultList: -1}); err == nil {
		t.Fatal("negative DefaultList")
	}
}

func TestRingIDSchemes(t *testing.T) {
	aud, err := NewRing[row](RingOptions[row]{
		Max:         4,
		SetID:       setID,
		DefaultList: 100,
		MaxList:     100,
		NewID: func(seq uint64) string {
			return "aud-" + strconv.FormatUint(seq, 10)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e1 := aud.Append(row{Name: "one"})
	e2 := aud.Append(row{Name: "two"})
	e3 := aud.Append(row{Name: "three"})
	if e1.ID != "aud-1" || e2.ID != "aud-2" || e3.ID != "aud-3" {
		t.Fatalf("ids %s %s %s", e1.ID, e2.ID, e3.ID)
	}
	listed := aud.List(0)
	if len(listed) != 3 || listed[0].ID != "aud-3" {
		t.Fatalf("list %+v", listed)
	}
	got, ok := aud.Get("aud-2")
	if !ok || got.Name != "two" {
		t.Fatalf("get %+v %v", got, ok)
	}
	aud.Wipe()
	e4 := aud.Append(row{Name: "four"})
	if e4.ID != "aud-4" {
		t.Fatalf("wipe does not reset seq, got %s", e4.ID)
	}

	// syslog keeps a caller-supplied id and otherwise asks NewID (a ULID in the facade).
	sys, err := NewRing[row](RingOptions[row]{
		Max:   4,
		SetID: setID,
		GetID: func(e row) string { return e.ID },
		NewID: func(seq uint64) string { return "ulid-" + strconv.FormatUint(seq, 10) },
	})
	if err != nil {
		t.Fatal(err)
	}
	kept := sys.Append(row{ID: "caller-1", Name: "kept"})
	if kept.ID != "caller-1" {
		t.Fatal(kept.ID)
	}
	if found, ok := sys.Get("caller-1"); !ok || found.Name != "kept" {
		t.Fatal(found, ok)
	}
	gen := sys.Append(row{Name: "gen"})
	if gen.ID != "ulid-2" {
		t.Fatalf("generated %s", gen.ID)
	}
	if _, ok := sys.Get("ulid-2"); !ok {
		t.Fatal("generated id was not indexed")
	}

	// SetID rewrites the id. The ring indexes what GetID reads back.
	rewritten, err := NewRing[row](RingOptions[row]{
		Max: 2,
		SetID: func(e *row, id string) {
			e.ID = "id-" + id
		},
		GetID: func(e row) string { return e.ID },
		NewID: func(seq uint64) string { return strconv.FormatUint(seq, 10) },
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := rewritten.Append(row{Name: "r"})
	if stored.ID != "id-1" {
		t.Fatal(stored.ID)
	}
	if _, ok := rewritten.Get("id-1"); !ok {
		t.Fatal("rewritten id missed")
	}
	if _, ok := rewritten.Get("1"); ok {
		t.Fatal("indexed the pre-SetID string")
	}

	// A repeated caller id must not collapse two rows onto one index entry.
	clash, err := NewRing[row](RingOptions[row]{
		Max:   4,
		SetID: setID,
		GetID: func(e row) string { return e.ID },
	})
	if err != nil {
		t.Fatal(err)
	}
	first := clash.Append(row{ID: "same", Name: "first"})
	second := clash.Append(row{ID: "same", Name: "second"})
	if first.ID != "same" || second.ID == "same" || second.ID == "" {
		t.Fatalf("clash %q %q", first.ID, second.ID)
	}
	if got, ok := clash.Get("same"); !ok || got.Name != "first" {
		t.Fatal(got, ok)
	}
	if got, ok := clash.Get(second.ID); !ok || got.Name != "second" {
		t.Fatal(got, ok)
	}
	if clash.Len() != 2 {
		t.Fatal(clash.Len())
	}

	a := fallbackID()
	b := fallbackID()
	if a == b || len(a) != 32 {
		t.Fatalf("fallback %q %q", a, b)
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
	if len(got) != 2 || got[0].Name != "d" || got[1].Name != "c" {
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
	if !strings.Contains(blob, "[redacted]") {
		t.Fatalf("redaction marker missing: %s", blob)
	}
	js, err := rd.JSON([]byte(`{"token":"` + secret + `","note":"kept"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), secret) {
		t.Fatal(string(js))
	}
	// BearerPrefix applies to String, not to a JSON string value.
	kept, err := rd.JSON([]byte(`{"note":"Bearer ` + secret + `"}`))
	if err != nil || !strings.Contains(string(kept), secret) {
		t.Fatalf("json bearer value %s %v", kept, err)
	}
	// BearerPrefix replaces the whole reason. It does not leave a "Bearer " prefix.
	if got := rd.String("Bearer " + secret); got != "[redacted]" {
		t.Fatalf("bearer reason %q", got)
	}
}

func TestRedactorPortsRepoCases(t *testing.T) {
	const marker = "[redacted]"
	dnsKeys := map[string]bool{
		"secret": true, "secretref": true, "token": true, "password": true,
		"authorization": true, "bearer": true, "credential": true, "credentials": true,
		"apikey": true, "api_key": true,
	}
	basePEM := map[string]bool{
		"secret": true, "secretref": true, "secretfile": true, "token": true, "password": true,
		"authorization": true, "bearer": true, "credential": true, "credentials": true,
		"apikey": true, "api_key": true, "privatekey": true, "private_key": true, "cookie": true,
	}
	snmpKeys := copyKeys(basePEM)
	snmpKeys["community"] = true
	netconfKeys := copyKeys(basePEM)
	netconfKeys["passwordfile"] = true
	netconfKeys["authorizedkeysfile"] = true
	netconfKeys["hostkeyfile"] = true

	dns := Redactor{Keys: dnsKeys, BearerPrefix: true, ColonLines: true}
	if got := dns.String("Bearer super-secret"); got != marker {
		t.Fatalf("dns bearer %q", got)
	}
	if got := dns.String("token: hunter2"); got != "token: "+marker {
		t.Fatalf("dns token line %q", got)
	}
	if got := dns.String("password: hunter2\nkeep"); got != "password: "+marker+"\nkeep" {
		t.Fatalf("dns password line %q", got)
	}
	// maildev shares the bearer prefix and does not blank token: lines.
	mail := Redactor{Keys: dnsKeys, BearerPrefix: true}
	if got := mail.String("Bearer hunter2"); got != marker {
		t.Fatalf("maildev bearer %q", got)
	}
	if got := mail.String("token: hunter2"); got != "token: hunter2" {
		t.Fatalf("maildev kept the token line, got %q", got)
	}
	after, err := dns.Value("spec.management.auth", []byte(`{"secretRef":"/run/secrets/token"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "/run/secrets/token") || !strings.Contains(string(after), marker) {
		t.Fatalf("dns secretRef leaked: %s", after)
	}

	encrypted := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nMIIE\n-----END RSA PRIVATE KEY-----"
	for name, keys := range map[string]map[string]bool{"ntp": basePEM, "snmp": snmpKeys, "netconf": netconfKeys} {
		rd := Redactor{Keys: keys, PEM: true}
		if got := rd.String(encrypted); got != marker {
			t.Fatalf("%s encrypted pem %q", name, got)
		}
		raw, err := rd.JSON([]byte(encrypted))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `"`+marker+`"` {
			t.Fatalf("%s non-json pem %s", name, raw)
		}
		js, err := rd.JSON([]byte(`{"note":"` + strings.ReplaceAll(encrypted, "\n", `\n`) + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(js), "BEGIN ") || strings.Contains(string(js), "DEK-Info") {
			t.Fatalf("%s json pem leaked: %s", name, js)
		}
	}

	ntp := Redactor{Keys: basePEM, PEM: true}
	got, err := ntp.Value("spec.auth.tokens[0].secretFile", []byte(`"/run/secrets/b"`))
	if err != nil || string(got) != `"`+marker+`"` {
		t.Fatalf("ntp secretFile path %s %v", got, err)
	}
	snmp := Redactor{Keys: snmpKeys, PEM: true}
	got, err = snmp.Value("spec.users[0]", []byte(`{"name":"alice","secretFile":"/run/secrets/b"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "/run/secrets/b") || !strings.Contains(string(got), marker) {
		t.Fatalf("snmp secretFile key leaked: %s", got)
	}
	if !strings.Contains(string(got), "alice") {
		t.Fatalf("snmp kept name: %s", got)
	}
	nc := Redactor{Keys: netconfKeys, PEM: true}
	got, err = nc.Value("spec.users[0].passwordFile", []byte(`"/run/secrets/bob"`))
	if err != nil || string(got) != `"`+marker+`"` {
		t.Fatalf("netconf passwordFile %s %v", got, err)
	}
	mailPath, err := mail.Value("spec.smtp.auth.password", []byte(`"new"`))
	if err != nil || string(mailPath) != `"`+marker+`"` {
		t.Fatalf("maildev password path %s %v", mailPath, err)
	}

	// Case-folded keys: Token / secretFile / passwordFile must not survive.
	folded, err := nc.JSON([]byte(`{"Token":"t","passwordFile":"p","secretFile":"s","ok":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(folded), `"t"`) || strings.Contains(string(folded), `"p"`) || strings.Contains(string(folded), `"s"`) {
		t.Fatalf("mixed-case keys leaked: %s", folded)
	}

	// UseNumber keeps 1.0 and an integer past the float64 mantissa.
	nums, err := dns.JSON([]byte(`{"n":1.0,"big":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nums), "1.0") || !strings.Contains(string(nums), "9007199254740993") {
		t.Fatalf("numbers rewritten: %s", nums)
	}
	plain, err := dns.JSON([]byte("not-json"))
	if err != nil || string(plain) != "not-json" {
		t.Fatalf("dns non-json %q %v", plain, err)
	}
}

func copyKeys(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestDeniedShareSmallMax(t *testing.T) {
	r, err := NewRing[row](RingOptions[row]{
		Max: 1, SetID: setID, IsDenied: isDenied, DeniedShare: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	okRow := r.Append(row{Result: "ok", Name: "apply"})
	dropped := r.Append(row{Result: "denied", Name: "d"})
	if r.Len() != 1 || dropped.ID != "" {
		t.Fatalf("len %d dropped %+v", r.Len(), dropped)
	}
	if found, ok := r.Get(okRow.ID); !ok || found.Name != "apply" {
		t.Fatal("ok row evicted", found, ok)
	}
	r.Wipe()
	first := r.Append(row{Result: "denied", Name: "d1"})
	second := r.Append(row{Result: "denied", Name: "d2"})
	if r.Len() != 1 || second.ID == "" {
		t.Fatalf("recycle len %d id %q", r.Len(), second.ID)
	}
	if _, ok := r.Get(first.ID); ok {
		t.Fatal("old denial kept")
	}
	if found, ok := r.Get(second.ID); !ok || found.Name != "d2" {
		t.Fatal(found, ok)
	}

	two, err := NewRing[row](RingOptions[row]{
		Max: 2, SetID: setID, IsDenied: isDenied, DeniedShare: 0.25,
	})
	if err != nil {
		t.Fatal(err)
	}
	a := two.Append(row{Result: "ok", Name: "a"})
	b := two.Append(row{Result: "ok", Name: "b"})
	if miss := two.Append(row{Result: "denied", Name: "d"}); miss.ID != "" || two.Len() != 2 {
		t.Fatalf("fractional share stored a denial by evicting ok: %+v len %d", miss, two.Len())
	}
	if _, ok := two.Get(a.ID); !ok {
		t.Fatal("a evicted")
	}
	if _, ok := two.Get(b.ID); !ok {
		t.Fatal("b evicted")
	}

	// Before the quota is a whole number of rows, a denial still evicts the oldest OK row.
	wide, err := NewRing[row](RingOptions[row]{
		Max: 4, SetID: setID, IsDenied: isDenied, DeniedShare: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldest := wide.Append(row{Result: "ok", Name: "oldest"})
	wide.Append(row{Result: "ok", Name: "b"})
	wide.Append(row{Result: "ok", Name: "c"})
	wide.Append(row{Result: "ok", Name: "d"})
	admitted := wide.Append(row{Result: "denied", Name: "d1"})
	if wide.Len() != 4 || admitted.ID == "" {
		t.Fatalf("len %d admitted %+v", wide.Len(), admitted)
	}
	if _, ok := wide.Get(oldest.ID); ok {
		t.Fatal("pre-quota denial did not evict the oldest ok row")
	}
	if _, ok := wide.Get(admitted.ID); !ok {
		t.Fatal("denial was not stored")
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
	if len(okNames) != 2 || okNames[0] != "reset" || okNames[1] != "apply" {
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
