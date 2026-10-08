package authn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/scope"
)

func raw(id, role, secret string, scopes ...string) RawToken {
	return RawToken{ID: id, Role: role, Scopes: scopes, Secret: NewSecret([]byte(secret))}
}

func memCfg(mode Mode, dup DupPolicy, toks ...RawToken) Config {
	return Config{Mode: mode, Source: Memory(toks), Duplicates: dup}
}

func mustLoad(t *testing.T, cfg Config) *Material {
	t.Helper()
	m, err := Load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

func mustVer(t *testing.T, m *Material) *Verifier {
	t.Helper()
	v, err := NewVerifier(m)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustAs(t *testing.T, err error) *LoadError {
	t.Helper()
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("got %T %v, want *LoadError", err, err)
	}
	return le
}

func kindIs(err error, k kerr.Kind) bool {
	got, ok := kerr.KindOf(err)
	return ok && got == k
}

func authBearer(secret string) Request {
	return Request{Authorization: "Bearer " + secret}
}

func TestNewVerifierRefusesNil(t *testing.T) {
	if _, err := NewVerifier(nil); err == nil || !kindIs(err, kerr.Invalid) {
		t.Fatalf("got %v", err)
	}
}

func TestAllowAll(t *testing.T) {
	v := AllowAll()
	p, err := v.Authenticate(Request{})
	if err != nil || p.Role != "administrator" || p.Class != "test" {
		t.Fatalf("principal %+v err %v", p, err)
	}
	if v.Mode() != ModeBearer {
		t.Fatalf("mode %s", v.Mode())
	}
}

func TestStaticBearer(t *testing.T) {
	secret := "static-bearer-secret"
	m := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "operator", secret, "ops.read")))
	v := mustVer(t, m)
	p, err := v.Authenticate(authBearer(secret))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "ops" || p.Role != "operator" || p.Class != "token" || len(p.Scopes) != 1 || p.Scopes[0] != "ops.read" {
		t.Fatalf("principal %+v", p)
	}
	if _, err := v.Authenticate(Request{}); err == nil || err.Error() != "authentication required" || !kindIs(err, kerr.Unauthenticated) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := v.Authenticate(authBearer("nope")); err == nil || err.Error() != "invalid token" {
		t.Fatalf("bad token: %v", err)
	}
	empty := Empty()
	if _, err := empty.Authenticate(authBearer(secret)); err == nil || err.Error() != "invalid token" {
		t.Fatalf("empty verifier: %v", err)
	}
}

func TestFromSpecFileRefAndMinBytes(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "cfg")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("s", 32)
	if err := os.WriteFile(filepath.Join(base, "tok"), []byte(secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(root, "short")
	if err := os.WriteFile(short, []byte(strings.Repeat("s", 31)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := FileOpts{Line: WholeFileTrim, Resolve: ConfigDirIfRelative, BaseDir: base}
	m := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, MinSecretBytes: 32,
		PathPrefix: "spec.auth",
		Source:     PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: "tok"}}, opts),
	})
	v := mustVer(t, m)
	if _, err := v.AuthenticateBearer([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	_, err := Load(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, MinSecretBytes: 32,
		PathPrefix: "spec.auth",
		Source:     PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: short}}, FileOpts{Line: WholeFileTrim, Resolve: AsGiven}),
	})
	le := mustAs(t, err)
	want := fmt.Sprintf("secretFile %q trimmed contents are shorter than %d bytes", short, 32)
	if le.Error() != want || le.Code != "invalid_value" || le.File != short {
		t.Fatalf("short: %+v", le)
	}
}

func TestMissingFileSkipped(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	secret := "present-secret"
	if err := os.WriteFile(good, []byte(secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	opts := FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, SkipMissing: true}
	m := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{
			{ID: "gone", Role: "viewer", SecretFile: missing},
			{ID: "keep", Role: "administrator", SecretFile: good},
		}, opts),
	})
	if m.TokenCount() != 1 {
		t.Fatalf("count %d", m.TokenCount())
	}
	v := mustVer(t, m)
	p, err := v.AuthenticateBearer([]byte(secret))
	if err != nil || p.ID != "keep" {
		t.Fatalf("principal %+v err %v", p, err)
	}
}

func TestAcceptDevLoopbackZeroTokens(t *testing.T) {
	m := mustLoad(t, Config{
		Mode: ModeDevLoopbackUnauth, Source: Memory(nil), Duplicates: RejectDuplicateValue,
		Accept: BearerNeedsToken(true),
	})
	if m.TokenCount() != 0 || m.Mode() != ModeDevLoopbackUnauth {
		t.Fatalf("mode %s count %d", m.Mode(), m.TokenCount())
	}
}

func TestAcceptBearerZeroTokensRefused(t *testing.T) {
	_, err := Load(Config{
		Mode: ModeBearer, Source: Memory(nil), Duplicates: RejectDuplicateValue,
		Accept: BearerNeedsToken(true),
	})
	if err == nil || err.Error() != "spec.auth.mode bearer requires at least one usable token" {
		t.Fatalf("got %v", err)
	}
}

func TestAcceptNetconfRefusesDevLoopback(t *testing.T) {
	_, err := Load(Config{
		Mode: ModeDevLoopbackUnauth, Source: Memory(nil), Duplicates: RejectDuplicateValue,
		Accept: BearerNeedsToken(false),
	})
	if err == nil || err.Error() != "management bind refused: dev-loopback-unauth" {
		t.Fatalf("dev: %v", err)
	}
	_, err = Load(Config{
		Mode: ModeBearer, Source: Memory(nil), Duplicates: RejectDuplicateValue,
		Accept: BearerNeedsToken(false),
	})
	if err == nil || err.Error() != "spec.auth.mode bearer requires at least one usable token" {
		t.Fatalf("bearer: %v", err)
	}
}

func TestAcceptSNMPNilAllowsZeroTokens(t *testing.T) {
	old := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "old-secret")))
	v := mustVer(t, old)
	next := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue))
	if !v.Swap(next) {
		t.Fatal("swap did not count as a change")
	}
	if v.TokenCount() != 0 {
		t.Fatalf("count %d", v.TokenCount())
	}
	if _, err := v.AuthenticateBearer([]byte("old-secret")); err == nil {
		t.Fatal("old bearer still accepted")
	}
}

func TestAcceptMaildevThreeModesZeroTokens(t *testing.T) {
	for _, mode := range []Mode{ModeBearer, ModeBearerAndBasic, ModeDevLoopbackUnauth} {
		m := mustLoad(t, memCfg(mode, RejectDuplicateValue))
		if m.TokenCount() != 0 || m.Mode() != mode {
			t.Fatalf("mode %s", mode)
		}
	}
}

func TestSyslogLoadErrorSentences(t *testing.T) {
	dir := t.TempDir()
	roles := scope.Table{Roles: map[string][]string{"administrator": {"syslog.admin"}}, EmptyRole: "administrator"}
	opts := FileOpts{Line: WholeFileTrim, Resolve: AsGiven}
	prefix := "spec.auth"

	_, err := Load(Config{Mode: ModeUnknown, Source: Memory(nil), Duplicates: RejectDuplicateValue, PathPrefix: prefix})
	le := mustAs(t, err)
	if le.Error() != `spec.auth.mode must be bearer, got "unknown"` || le.Field != "spec.auth.mode" || le.Code != "invalid_value" {
		t.Fatalf("mode: %+v", le)
	}

	_, err = Load(Config{Mode: ModeBearer, Source: Memory([]RawToken{raw("", "administrator", "x")}), Duplicates: RejectDuplicateValue, PathPrefix: prefix})
	le = mustAs(t, err)
	if le.Error() != "token id is required" || le.Field != "spec.auth.tokens[0].id" || le.Code != "empty_id" {
		t.Fatalf("id: %+v", le)
	}

	_, err = Load(Config{Mode: ModeBearer, Source: Memory([]RawToken{raw("a", "administrator", "one"), raw("a", "administrator", "two")}), Duplicates: RejectDuplicateValue, PathPrefix: prefix})
	le = mustAs(t, err)
	if le.Error() != `duplicate token id "a"` || le.Code != "duplicate_id" || le.Field != "spec.auth.tokens[1].id" {
		t.Fatalf("dup id: %+v", le)
	}

	missing := filepath.Join(dir, "nope")
	_, err = Load(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, PathPrefix: prefix, Roles: roles,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: missing}}, opts),
	})
	le = mustAs(t, err)
	readErr := le.Err
	want := fmt.Sprintf("secretFile %q: %v", missing, readErr)
	if le.Error() != want || renderSyslog(le, 0) != le.Error() {
		t.Fatalf("missing: msg %q rendered %q err %v", le.Error(), renderSyslog(le, 0), readErr)
	}

	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("tiny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Load(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, MinSecretBytes: 32, PathPrefix: prefix,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: short}}, opts),
	})
	le = mustAs(t, err)
	if le.Error() != fmt.Sprintf("secretFile %q trimmed contents are shorter than %d bytes", short, 32) || renderSyslog(le, 32) != le.Error() {
		t.Fatalf("short: %+v", le)
	}

	body := []byte(strings.Repeat("z", 32))
	one := filepath.Join(dir, "one")
	two := filepath.Join(dir, "two")
	if err := os.WriteFile(one, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, append([]byte(nil), body...), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Load(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, MinSecretBytes: 32, PathPrefix: prefix,
		Source: PerTokenFiles([]FileToken{
			{ID: "first", Role: "administrator", SecretFile: one},
			{ID: "second", Role: "administrator", SecretFile: two},
		}, opts),
	})
	le = mustAs(t, err)
	if le.Error() != "token value matches first" || le.Field != "spec.auth.tokens[1].secretFile" {
		t.Fatalf("value: %+v", le)
	}

	badRole := filepath.Join(dir, "role")
	if err := os.WriteFile(badRole, body, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Load(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, MinSecretBytes: 32, PathPrefix: prefix, Roles: roles,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "nope", SecretFile: badRole}}, opts),
	})
	le = mustAs(t, err)
	if le.Error() != `unknown role "nope"` || le.Field != "spec.auth.tokens[0].role" {
		t.Fatalf("role: %+v", le)
	}
}

// renderSyslog builds the syslog sentence from LoadError fields. The minimum
// is the facade's configured floor; it is not stored on the error.
func renderSyslog(e *LoadError, min int) string {
	switch {
	case e.Field == "spec.auth.mode" || strings.HasSuffix(e.Field, ".mode"):
		return e.Msg
	case e.Code == "empty_id":
		return "token id is required"
	case e.Code == "duplicate_id" && e.Err == nil && !strings.Contains(e.Msg, "token value matches"):
		return fmt.Sprintf("duplicate token id %q", e.TokenID)
	case strings.Contains(e.Msg, "token value matches"):
		return e.Msg
	case strings.Contains(e.Msg, "unknown role"):
		return e.Msg
	case strings.Contains(e.Msg, "shorter than"):
		return fmt.Sprintf("secretFile %q trimmed contents are shorter than %d bytes", e.File, min)
	default:
		return fmt.Sprintf("secretFile %q: %v", e.File, e.Err)
	}
}

func TestTemplateViolationPaths(t *testing.T) {
	_, err := Load(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, PathPrefix: "spec.auth", RejectEmptyRole: true,
		Source: Memory([]RawToken{raw("a", "", "secret")}),
	})
	le := mustAs(t, err)
	got := renderTemplate(le)
	if le.Field != "spec.auth.tokens[0].role" || le.Code != "invalid_value" || got != "spec.auth.tokens[0].role invalid_value" {
		t.Fatalf("path %s code %s render %s", le.Field, le.Code, got)
	}
}

func renderTemplate(e *LoadError) string {
	return e.Field + " " + e.Code
}

func TestDNSIdentityDefaults(t *testing.T) {
	secret := "dns-token-value"
	m := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: FirstMatchWins,
		DNSDefaults: &DNSDefaults{EmptyID: "bearer", EmptyRoleAndScopes: "administrator"},
		Source:      Memory([]RawToken{{Secret: NewSecret([]byte(secret))}}),
	})
	v := mustVer(t, m)
	p, err := v.AuthenticateBearer([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "bearer" || p.Role != "administrator" {
		t.Fatalf("principal %+v", p)
	}
	kept := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: FirstMatchWins,
		DNSDefaults: &DNSDefaults{EmptyID: "bearer", EmptyRoleAndScopes: "administrator"},
		Source:      Memory([]RawToken{{ID: "custom", Role: "viewer", Secret: NewSecret([]byte("other"))}}),
	})
	p, err = mustVer(t, kept).AuthenticateBearer([]byte("other"))
	if err != nil || p.ID != "custom" || p.Role != "viewer" {
		t.Fatalf("kept %+v %v", p, err)
	}
}

func TestWarnBelowBytes(t *testing.T) {
	m := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, WarnBelowBytes: 32,
		Source: Memory([]RawToken{raw("short", "administrator", "tiny"), raw("long", "administrator", strings.Repeat("L", 32))}),
	})
	if got := m.Warnings(); len(got) != 1 || got[0] != "short" {
		t.Fatalf("warnings %v", got)
	}
}

func TestWholeFileTrimVsFirstNonCommentLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tok")
	body := []byte("# comment\n  secret-value\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	line := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: path}}, FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven}),
	})
	whole := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: path}}, FileOpts{Line: WholeFileTrim, Resolve: AsGiven}),
	})
	if _, err := mustVer(t, line).AuthenticateBearer([]byte("secret-value")); err != nil {
		t.Fatal(err)
	}
	if _, err := mustVer(t, whole).AuthenticateBearer([]byte("secret-value")); err == nil {
		t.Fatal("whole-file trim authenticated the inner line")
	}
	trimmed := string(bytes.TrimSpace(body))
	if _, err := mustVer(t, whole).AuthenticateBearer([]byte(trimmed)); err != nil {
		t.Fatal(err)
	}
	if line.Equivalent(whole) {
		t.Fatal("line and whole-file digests matched")
	}
}

func TestFromSpecAtResolvesBaseDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	base := filepath.Join(root, "base")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	baseSecret := "base-dir-secret"
	if err := os.WriteFile(filepath.Join(base, "tok"), []byte(baseSecret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := FileOpts{Line: FirstNonCommentLine, Resolve: CWDThenBaseDir, BaseDir: base}
	m := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: "tok"}}, opts),
	})
	if _, err := mustVer(t, m).AuthenticateBearer([]byte(baseSecret)); err != nil {
		t.Fatal(err)
	}
	cwdSecret := "cwd-secret"
	if err := os.WriteFile(filepath.Join(root, "tok"), []byte(cwdSecret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m = mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: "tok"}}, opts),
	})
	if _, err := mustVer(t, m).AuthenticateBearer([]byte(cwdSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := mustVer(t, m).AuthenticateBearer([]byte(baseSecret)); err == nil {
		t.Fatal("base secret won over the cwd file")
	}
}

func TestDNSBundle(t *testing.T) {
	dir := t.TempDir()
	opts := FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, Harden: true}
	defs := &DNSDefaults{EmptyID: "bearer", EmptyRoleAndScopes: "administrator"}

	line := filepath.Join(dir, "line")
	if err := os.WriteFile(line, []byte("# note\nline-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := mustLoad(t, Config{
		Mode: ModeDevLoopbackUnauth, Duplicates: FirstMatchWins, DNSDefaults: defs,
		Source: DNSBundle(nil, line, opts),
	})
	p, err := mustVer(t, m).AuthenticateBearer([]byte("line-secret"))
	if err != nil || p.ID != "bearer" || p.Role != "administrator" {
		t.Fatalf("line %+v %v", p, err)
	}

	obj := filepath.Join(dir, "obj")
	if err := os.WriteFile(obj, []byte(`{"tokens":[{"token":"obj-secret","id":"obj","role":"viewer","scopes":["dns.read"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m = mustLoad(t, Config{Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs, Source: DNSBundle(nil, obj, opts)})
	p, err = mustVer(t, m).AuthenticateBearer([]byte("obj-secret"))
	if err != nil || p.ID != "obj" || p.Role != "viewer" || len(p.Scopes) != 1 {
		t.Fatalf("obj %+v %v", p, err)
	}

	arr := filepath.Join(dir, "arr")
	if err := os.WriteFile(arr, []byte(`[{"token":"arr-secret","id":"arr","role":"operator"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	m = mustLoad(t, Config{Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs, Source: DNSBundle(nil, arr, opts)})
	p, err = mustVer(t, m).AuthenticateBearer([]byte("arr-secret"))
	if err != nil || p.ID != "arr" || p.Role != "operator" {
		t.Fatalf("arr %+v %v", p, err)
	}

	memSecret := "mem-secret"
	fileSecret := "file-secret"
	both := filepath.Join(dir, "both")
	if err := os.WriteFile(both, []byte(fileSecret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m = mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
		Source: DNSBundle([]RawToken{raw("mem", "administrator", memSecret)}, both, opts),
	})
	if m.TokenCount() != 2 {
		t.Fatalf("merge count %d", m.TokenCount())
	}
	if _, err := mustVer(t, m).AuthenticateBearer([]byte(memSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := mustVer(t, m).AuthenticateBearer([]byte(fileSecret)); err != nil {
		t.Fatal(err)
	}

	dup := filepath.Join(dir, "dup")
	if err := os.WriteFile(dup, []byte(`{"tokens":[{"token":"dup","id":"file"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m = mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
		Source: DNSBundle([]RawToken{{ID: "mem", Secret: NewSecret([]byte("dup"))}}, dup, opts),
	})
	p, err = mustVer(t, m).AuthenticateBearer([]byte("dup"))
	if err != nil || p.ID != "mem" {
		t.Fatalf("first match %+v %v", p, err)
	}

	_, err = Load(Config{Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs, Source: DNSBundle(nil, filepath.Join(dir, "absent"), opts)})
	le := mustAs(t, err)
	if le.Error() != "token secret is unavailable" || le.Kind != kerr.Unavailable {
		t.Fatalf("missing %+v", le)
	}
}

func TestZeroTokensRefuseListen(t *testing.T) {
	if err := BearerNeedsToken(true)(nil); err == nil || err.Error() != "management bind requires a verifier" {
		t.Fatalf("nil: %v", err)
	}
	zero := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue))
	if err := BearerNeedsToken(true)(zero); err == nil {
		t.Fatal("bearer zero tokens allowed")
	}
	loop := mustLoad(t, memCfg(ModeDevLoopbackUnauth, RejectDuplicateValue))
	if err := BearerNeedsToken(true)(loop); err != nil {
		t.Fatal(err)
	}
	if err := BearerNeedsToken(false)(loop); err == nil {
		t.Fatal("netconf allowed dev-loopback")
	}
}

func TestBearerAndBasicSamePrincipal(t *testing.T) {
	token := strings.Repeat("t", 32)
	pass := "shortpw"
	m := mustLoad(t, Config{
		Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue, MinSecretBytes: 32,
		Source: Memory([]RawToken{raw("ops", "operator", token, "mail.read")}),
		Basic:  &BasicSpec{Username: "ada", Password: NewSecret([]byte(pass)), TokenRef: "ops"},
	})
	if !m.BasicEnabled() {
		t.Fatal("basic off")
	}
	v := mustVer(t, m)
	bearer, err := v.Authenticate(Request{Authorization: "Bearer " + token, AllowBasic: true})
	if err != nil {
		t.Fatal(err)
	}
	enc := basicHeader("ada", pass)
	basic, err := v.Authenticate(Request{Authorization: enc, AllowBasic: true})
	if err != nil {
		t.Fatal(err)
	}
	if basic.ID != bearer.ID || basic.Role != bearer.Role || strings.Join(basic.Scopes, ",") != strings.Join(bearer.Scopes, ",") {
		t.Fatalf("bearer %+v basic %+v", bearer, basic)
	}
	if _, err := v.Authenticate(Request{Authorization: basicHeader("ada", "wrong"), AllowBasic: true}); err == nil || err.Error() != "invalid token" {
		t.Fatalf("bad password: %v", err)
	}
}

func TestMCPRejectsBasicEvenWhenEnabled(t *testing.T) {
	token := strings.Repeat("t", 32)
	m := mustLoad(t, Config{
		Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
		Source: Memory([]RawToken{raw("ops", "operator", token)}),
		Basic:  &BasicSpec{Username: "ada", Password: NewSecret([]byte("pw")), TokenRef: "ops"},
	})
	v := mustVer(t, m)
	_, err := v.Authenticate(Request{Authorization: basicHeader("ada", "pw"), AllowBasic: false})
	if err == nil || err.Error() != "authentication required" || !kindIs(err, kerr.Unauthenticated) {
		t.Fatalf("got %v", err)
	}
}

func TestLoopbackUnauth(t *testing.T) {
	m := mustLoad(t, Config{
		Mode: ModeDevLoopbackUnauth, Source: Memory(nil), Duplicates: RejectDuplicateValue,
		LocalhostIsLoopback: true,
	})
	v := mustVer(t, m)
	p, err := v.Authenticate(Request{RemoteAddr: "127.0.0.1:4123"})
	if err != nil || p.ID != "loopback" || p.Class != "loopback" || p.Role != "administrator" {
		t.Fatalf("loop %+v %v", p, err)
	}
	if _, err := v.Authenticate(Request{RemoteAddr: "10.1.2.3:80"}); err == nil || err.Error() != "authentication required" {
		t.Fatalf("remote: %v", err)
	}
	secret := "loop-bearer"
	with := mustLoad(t, Config{
		Mode: ModeDevLoopbackUnauth, Duplicates: RejectDuplicateValue, LocalhostIsLoopback: true,
		Source: Memory([]RawToken{raw("ops", "operator", secret)}),
	})
	p, err = mustVer(t, with).Authenticate(Request{Authorization: "Bearer " + secret, RemoteAddr: "127.0.0.1:1"})
	if err != nil || p.ID != "ops" || p.Class != "token" {
		t.Fatalf("presented %+v %v", p, err)
	}
}

func TestLoopbackLocalhostAndMapped(t *testing.T) {
	cases := []struct {
		name   string
		fold   bool
		remote string
		ok     bool
	}{
		{"localhost exact", true, "localhost:80", true},
		{"localhost case", true, "LocalHost:80", false},
		{"localhost off", false, "localhost:80", false},
		{"mapped", false, "[::ffff:127.0.0.1]:9", true},
		{"mapped bare", false, "::ffff:127.0.0.1", true},
		{"ipv6", false, "[::1]:443", true},
		{"rfc1918", true, "192.168.1.9:1080", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mustLoad(t, Config{
				Mode: ModeDevLoopbackUnauth, Source: Memory(nil), Duplicates: RejectDuplicateValue,
				LocalhostIsLoopback: tc.fold,
			})
			_, err := mustVer(t, m).Authenticate(Request{RemoteAddr: tc.remote})
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && (err == nil || err.Error() != "authentication required") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestChallengeRealms(t *testing.T) {
	if got := Challenge("labntp", false); len(got) != 1 || got[0] != `Bearer realm="labntp"` {
		t.Fatalf("ntp %v", got)
	}
	if got := Challenge("labsyslog", false); len(got) != 1 || got[0] != `Bearer realm="labsyslog"` {
		t.Fatalf("syslog %v", got)
	}
	got := Challenge("labmail", true)
	if len(got) != 2 || got[0] != `Bearer realm="labmail"` || got[1] != `Basic realm="labmail"` {
		t.Fatalf("mail %v", got)
	}
}

func TestEmptyRoleRejected(t *testing.T) {
	_, err := Load(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, RejectEmptyRole: true,
		PathPrefix: "spec.auth",
		Roles:      scope.Table{Roles: map[string][]string{"administrator": {"snmp.admin"}}, EmptyRole: "administrator"},
		Source:     Memory([]RawToken{raw("a", "", "secret")}),
	})
	le := mustAs(t, err)
	if le.Error() != "token role is required" || le.Code != "invalid_value" || le.Field != "spec.auth.tokens[0].role" {
		t.Fatalf("%+v", le)
	}
}

func TestOrderedDigestMatchesDNSIdentityDigest(t *testing.T) {
	if got := (*Material)(nil).OrderedDigest([]byte("profile")); got != dnsIdentityDigest(true, "profile", nil) {
		t.Fatalf("nil %s", got)
	}
	defs := &DNSDefaults{EmptyID: "bearer", EmptyRoleAndScopes: "administrator"}
	fixed := []string{"alpha-token", "beta-token"}
	m := mustLoad(t, Config{
		Mode: ModeDevLoopbackUnauth, Duplicates: RejectDuplicateValue, DNSDefaults: defs,
		Source: Memory([]RawToken{raw("a", "administrator", fixed[0]), raw("b", "viewer", fixed[1])}),
	})
	if got := m.OrderedDigest([]byte("dev-loopback-unauth")); got != dnsIdentityDigest(false, "dev-loopback-unauth", fixed) {
		t.Fatalf("fixed %s", got)
	}
	dupSecret := "duplicated-secret"
	dup := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
		Source: Memory([]RawToken{raw("a", "", dupSecret), raw("b", "", dupSecret)}),
	})
	if got := dup.OrderedDigest([]byte("bearer")); got != dnsIdentityDigest(false, "bearer", []string{dupSecret, dupSecret}) {
		t.Fatalf("dup %s", got)
	}
	dir := t.TempDir()
	ref := filepath.Join(dir, "ref")
	fileSecret := "from-file"
	if err := os.WriteFile(ref, []byte("# c\n"+fileSecret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	memSecret := "from-memory"
	merged := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
		Source: DNSBundle([]RawToken{raw("mem", "administrator", memSecret)}, ref, FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven}),
	})
	if got := merged.OrderedDigest([]byte("bearer")); got != dnsIdentityDigest(false, "bearer", []string{memSecret, fileSecret}) {
		t.Fatalf("merge %s", got)
	}
	empty := mustLoad(t, memCfg(ModeDevLoopbackUnauth, RejectDuplicateValue))
	if empty.OrderedDigest([]byte("p")) == (*Material)(nil).OrderedDigest([]byte("p")) {
		t.Fatal("a loaded empty material used the nil digest")
	}
	if empty.OrderedDigest(nil) == empty.OrderedDigest([]byte("p")) {
		t.Fatal("prefix was ignored on a non-nil material")
	}
}

// dnsIdentityDigest transcribes dns internal/auth/session.go IdentityDigest
// (c0ba9fe, lines 82-95): nil policy is SHA-256(""), otherwise
// SHA-256(profile || 0x00 || SHA-256(token) || …) in store order.
func dnsIdentityDigest(nilPolicy bool, profile string, secrets []string) string {
	h := sha256.New()
	if !nilPolicy {
		h.Write([]byte(profile))
		h.Write([]byte{0})
		for _, s := range secrets {
			sum := sha256.Sum256([]byte(s))
			h.Write(sum[:])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
