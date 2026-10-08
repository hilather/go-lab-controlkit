package authn

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/hilather/go-lab-controlkit/scope"
)

// FuzzAuthorization checks ParseAuthorization's error shape and checks
// Authenticate, AuthenticateBearer, and AllowAll against an independent
// oracle. The oracle is a copy of the ntp/template header split (trim, cut
// on a space, trim the remainder, case-insensitive scheme) plus the kit's
// bearer compare: RejectDuplicateValue rejects an internal space or tab and
// needs one exact match, FirstMatchWins keeps internal spaces and takes the
// first exact match. Basic decoding is a copy of parseBasic. The oracle does
// not call ParseAuthorization, lookupBearer, or lookupBasic.
func FuzzAuthorization(f *testing.F) {
	f.Add("")
	f.Add("Bearer tok")
	f.Add("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
	f.Add("bearer")
	f.Add("Digest abc")
	f.Add("Bearer  spaced")
	f.Add("Bearer fuzz-secret")
	f.Add("Bearer  fuzz-secret")
	f.Add("bearer fuzz-secret")
	f.Add("Basic YWRhOnB3")
	f.Add("basic YWRhOnB3")
	f.Add("fuzz-secret")
	f.Add("  fuzz-secret  ")
	f.Add("sec ret")
	f.Add("Bearer sec ret")
	f.Add("Bearer\tfuzz-secret")

	ops := oracleTok{
		secret: "fuzz-secret",
		prin: scope.Principal{
			ID: "ops", Class: "token", Role: "administrator",
			Scopes: []string{"ops:read"}, Groups: []string{"lab"},
		},
	}
	spaced := oracleTok{
		secret: "sec ret",
		prin: scope.Principal{
			ID: "spaced", Class: "token", Role: "administrator",
			Scopes: []string{"dns.read"},
		},
	}
	basic := &oracleBasic{user: "ada", pass: "pw", tokenID: "ops"}
	ntpV, err := NewVerifier(mustLoadF(Config{
		Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
		Source: Memory([]RawToken{oracleRaw(ops)}),
		Basic: &BasicSpec{
			Username: "ada", Password: NewSecret([]byte("pw")), TokenRef: "ops",
		},
	}))
	if err != nil {
		f.Fatal(err)
	}
	dnsV, err := NewVerifier(mustLoadF(Config{
		Mode: ModeBearer, Duplicates: FirstMatchWins,
		Source: Memory([]RawToken{oracleRaw(ops), oracleRaw(spaced)}),
	}))
	if err != nil {
		f.Fatal(err)
	}
	allow := AllowAll()
	ntpSecrets := []oracleTok{ops}
	dnsSecrets := []oracleTok{ops, spaced}

	f.Fuzz(func(t *testing.T, header string) {
		scheme, token, err := ParseAuthorization(header)
		zero(token)
		if err != nil && scheme != "" {
			t.Fatalf("scheme %q with error %v", scheme, err)
		}
		assertAuth(t, ntpV, header, RejectDuplicateValue, ntpSecrets, basic)
		assertBearer(t, ntpV, header, RejectDuplicateValue, ntpSecrets)
		assertAuth(t, dnsV, header, FirstMatchWins, dnsSecrets, nil)
		assertBearer(t, dnsV, header, FirstMatchWins, dnsSecrets)
		p, aerr := allow.Authenticate(Request{Authorization: header})
		if aerr != nil || p.ID != "allow-all" || p.Class != "test" || p.Role != "administrator" || len(p.Scopes) != 0 || len(p.Groups) != 0 {
			t.Fatalf("allow-all %+v %v", p, aerr)
		}
	})
}

func mustLoadF(cfg Config) *Material {
	m, err := Load(cfg)
	if err != nil {
		panic(err)
	}
	return m
}

type oracleTok struct {
	secret string
	prin   scope.Principal
}

type oracleBasic struct {
	user    string
	pass    string
	tokenID string
}

func oracleRaw(tok oracleTok) RawToken {
	return RawToken{
		ID: tok.prin.ID, Role: tok.prin.Role,
		Scopes: append([]string(nil), tok.prin.Scopes...),
		Groups: append([]string(nil), tok.prin.Groups...),
		Secret: NewSecret([]byte(tok.secret)),
	}
}

func assertAuth(t *testing.T, v *Verifier, header string, dup DupPolicy, toks []oracleTok, basic *oracleBasic) {
	t.Helper()
	want, ok := oracleAuthenticate(header, dup, toks, basic)
	got, err := v.Authenticate(Request{Authorization: header, RemoteAddr: "127.0.0.1:9", AllowBasic: true})
	if ok {
		if err != nil || !samePrin(got, want) {
			t.Fatalf("auth %q: got %+v %v want %+v", header, got, err, want)
		}
		return
	}
	if err == nil {
		t.Fatalf("auth %q succeeded as %+v", header, got)
	}
}

func assertBearer(t *testing.T, v *Verifier, header string, dup DupPolicy, toks []oracleTok) {
	t.Helper()
	want, ok := oracleLookup(strings.TrimSpace(header), dup, toks)
	got, err := v.AuthenticateBearer([]byte(header))
	if ok {
		if err != nil || !samePrin(got, want) {
			t.Fatalf("bearer %q: got %+v %v want %+v", header, got, err, want)
		}
		return
	}
	if err == nil {
		t.Fatalf("bearer %q succeeded as %+v", header, got)
	}
}

func samePrin(a, b scope.Principal) bool {
	return a.ID == b.ID && a.Class == b.Class && a.Role == b.Role && a.Transport == b.Transport &&
		slices.Equal(a.Scopes, b.Scopes) && slices.Equal(a.Groups, b.Groups)
}

// oracleAuthenticate is the ntp/template Authorization split and compare.
// basic nil means Basic is not configured, which is the dns verifier.
func oracleAuthenticate(header string, dup DupPolicy, toks []oracleTok, basic *oracleBasic) (scope.Principal, bool) {
	h := strings.TrimSpace(header)
	if h == "" {
		return scope.Principal{}, false
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok {
		return scope.Principal{}, false
	}
	rest = strings.TrimSpace(rest)
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return oracleLookup(rest, dup, toks)
	case strings.EqualFold(scheme, "Basic"):
		if basic == nil {
			return scope.Principal{}, false
		}
		user, pass, parsed := oracleParseBasic(rest)
		if !parsed || user != basic.user || pass != basic.pass {
			return scope.Principal{}, false
		}
		for _, tok := range toks {
			if tok.prin.ID == basic.tokenID {
				return tok.prin, true
			}
		}
		return scope.Principal{}, false
	default:
		return scope.Principal{}, false
	}
}

func oracleLookup(secret string, dup DupPolicy, toks []oracleTok) (scope.Principal, bool) {
	if secret == "" || (dup != FirstMatchWins && strings.ContainsAny(secret, " \t")) {
		return scope.Principal{}, false
	}
	if dup == FirstMatchWins {
		for _, tok := range toks {
			if tok.secret == secret {
				return tok.prin, true
			}
		}
		return scope.Principal{}, false
	}
	var hit scope.Principal
	n := 0
	for _, tok := range toks {
		if tok.secret == secret {
			n++
			hit = tok.prin
		}
	}
	if n == 1 {
		return hit, true
	}
	return scope.Principal{}, false
}

func oracleParseBasic(payload string) (user, pass string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		pad := (4 - len(payload)%4) % 4
		raw, err = base64.StdEncoding.DecodeString(payload + strings.Repeat("=", pad))
		if err != nil {
			return "", "", false
		}
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}
