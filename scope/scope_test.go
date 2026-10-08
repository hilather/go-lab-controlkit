package scope

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-controlkit/audit"
	"github.com/hilather/go-lab-controlkit/kerr"
)

func templateTable(explicit bool) Table {
	return Table{
		Roles: map[string][]string{
			"administrator": {"admin", "read", "write"},
			"operator":      {"read", "write"},
			"viewer":        {"read"},
		},
		EmptyRole:            "administrator",
		ExplicitReplacesRole: explicit,
		WildcardScope:        "admin",
	}
}

func TestTableMatrices(t *testing.T) {
	roleOnly := templateTable(false)
	role, scopes, err := roleOnly.Expand("viewer", []string{"write"})
	if err != nil || role != "viewer" || !SameSet(scopes, []string{"read"}) {
		t.Fatalf("role-only expand %s %v %v", role, scopes, err)
	}
	role, scopes, err = roleOnly.Expand("", nil)
	if err != nil || role != "administrator" || !SameSet(scopes, []string{"admin", "read", "write"}) {
		t.Fatalf("empty role %s %v %v", role, scopes, err)
	}
	if _, _, err = roleOnly.Expand("nope", nil); err == nil {
		t.Fatal("unknown role")
	}

	explicit := templateTable(true)
	role, scopes, err = explicit.Expand("viewer", []string{"write"})
	if err != nil || role != "viewer" || !SameSet(scopes, []string{"write"}) {
		t.Fatalf("explicit expand %s %v %v", role, scopes, err)
	}
	role, scopes, err = explicit.Expand("", []string{"write"})
	if err != nil || role != "administrator" || !SameSet(scopes, []string{"write"}) {
		t.Fatalf("empty role explicit %s %v %v", role, scopes, err)
	}
	if _, _, err = explicit.Expand("nope", []string{"read"}); err == nil {
		t.Fatal("unknown role with explicit scopes")
	}
	explicit.AllowUnknownRoleExplicit = true
	role, scopes, err = explicit.Expand("nope", []string{"read"})
	if err != nil || role != "nope" || !SameSet(scopes, []string{"read"}) {
		t.Fatalf("dns unknown role %s %v %v", role, scopes, err)
	}
	if _, _, err = explicit.Expand("nope", nil); err == nil {
		t.Fatal("dns flag allowed an unknown role without explicit scopes")
	}

	scopes = []string{"write"}
	p := Principal{Role: "viewer", Scopes: scopes}
	if err := Authorize(explicit, p, []string{"write"}); err != nil {
		t.Fatal(err)
	}
	if err := Authorize(explicit, p, nil); err != nil {
		t.Fatal("empty required")
	}
	if err := Authorize(explicit, p, []string{"read"}); !kindIs(err, kerr.Forbidden) {
		t.Fatal(err)
	}
	admin := Principal{Role: "administrator", Scopes: []string{"admin"}}
	if !explicit.HasScope(admin, "anything") {
		t.Fatal("wildcard")
	}
	if !explicit.HasScope(Principal{}, "") || !explicit.HasScope(admin, "") {
		t.Fatal("empty want was not held")
	}
	if explicit.HasScope(Principal{}, "read") {
		t.Fatal("empty principal held read")
	}
	if err := Authorize(nil, p, []string{"write"}); err == nil {
		t.Fatal("nil evaluator")
	}
}

type cat struct {
	req  map[string][]string
	tool map[string][]string
	res  map[string][]string
}

func (c cat) Required(id string) ([]string, bool) {
	s, ok := c.req[id]
	return s, ok
}
func (c cat) ToolCaps(tool string) []string    { return c.tool[tool] }
func (c cat) ResourceCaps(uri string) []string { return c.res[uri] }

func gate(t *testing.T, unmapped UnmappedPolicy, first bool, extra func(Principal, string, string) error) (*Gate, *audit.CountRecorder) {
	t.Helper()
	rec := &audit.CountRecorder{}
	g, err := NewGate(Gate{
		Eval: templateTable(true),
		Catalog: cat{
			req: map[string][]string{
				"read.cap":  {"read"},
				"write.cap": {"write"},
			},
			tool: map[string][]string{
				"mapped": {"read.cap", "write.cap"},
			},
			res: map[string][]string{
				"lab://item": {"read.cap"},
			},
		},
		Unmapped:     unmapped,
		FirstCapOnly: first,
		ToolExtra:    extra,
		Denied:       rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, rec
}

func TestUnmappedAllowAndForbid(t *testing.T) {
	viewer := Principal{ID: "v", Class: "token", Role: "viewer", Scopes: []string{"read"}, Transport: "mcp"}
	allow, _ := gate(t, Allow, false, nil)
	if err := allow.Tool(context.Background(), viewer, "missing"); err != nil {
		t.Fatal(err)
	}
	forbid, rec := gate(t, Forbid, false, nil)
	err := forbid.Tool(context.Background(), viewer, "missing")
	if !kindIs(err, kerr.Forbidden) {
		t.Fatal(err)
	}
	evs := rec.Events()
	if len(evs) != 1 || evs[0].ActorID != "v" || evs[0].Transport != "mcp" || evs[0].ErrorCode != "forbidden" {
		t.Fatalf("%+v", evs)
	}
	if _, err := NewGate(Gate{}); err == nil {
		t.Fatal("zero gate")
	}
}

func TestFirstCapOnly(t *testing.T) {
	viewer := Principal{ID: "v", Class: "token", Scopes: []string{"read"}}
	only, rec := gate(t, Forbid, true, nil)
	if err := only.Tool(context.Background(), viewer, "mapped"); err != nil {
		t.Fatal(err)
	}
	if len(rec.Events()) != 0 {
		t.Fatal(rec.Events())
	}
	all, rec := gate(t, Forbid, false, nil)
	if err := all.Tool(context.Background(), viewer, "mapped"); !kindIs(err, kerr.Forbidden) {
		t.Fatal(err)
	}
	if len(rec.Events()) != 1 || rec.Events()[0].Capability != "write.cap" {
		t.Fatalf("%+v", rec.Events())
	}
	if err := all.Resource(context.Background(), viewer, "lab://item"); err != nil {
		t.Fatal(err)
	}
}

func kindIs(err error, want kerr.Kind) bool {
	k, ok := kerr.KindOf(err)
	return ok && k == want
}

func TestToolExtraCalled(t *testing.T) {
	var seen []string
	admin := Principal{ID: "a", Class: "token", Scopes: []string{"admin"}}
	g, rec := gate(t, Forbid, false, func(p Principal, tool, capID string) error {
		seen = append(seen, tool+":"+capID+":"+p.ID)
		if capID == "write.cap" {
			return kerr.New(kerr.Forbidden, "emergency refused")
		}
		return nil
	})
	err := g.Tool(context.Background(), admin, "mapped")
	if !kindIs(err, kerr.Forbidden) {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "mapped:read.cap:a" || seen[1] != "mapped:write.cap:a" {
		t.Fatalf("calls %v", seen)
	}
	if len(rec.Events()) != 1 || rec.Events()[0].Capability != "write.cap" {
		t.Fatalf("%+v", rec.Events())
	}
}
