package authn

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// TestRejectBlankTokens is the KS-B2b regression. dns NewPolicy rejects
// strings.TrimSpace(token) == "" with message "empty token", path "tokens",
// code "required". The other five reject only a zero-length secret. The
// violation message "token value is required" is not a LoadError field.
// dns's Error() prefix "validation_failed: " is not part of Msg.
func TestRejectBlankTokens(t *testing.T) {
	defs := &DNSDefaults{EmptyID: "bearer", EmptyRoleAndScopes: "administrator"}
	blank := RawToken{Secret: NewSecret([]byte("   "))}
	kept := raw("a", "administrator", "kept")
	second := raw("b", "administrator", "   ")

	t.Run("memory flag off", func(t *testing.T) {
		// The review repro: a whitespace token loads when the flag is left false.
		m := mustLoad(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			Source: DNSBundle([]RawToken{blank}, "", FileOpts{}),
		})
		if m.TokenCount() != 1 || m.tokens[0].digest != sha256.Sum256([]byte("   ")) {
			t.Fatalf("count %d", m.TokenCount())
		}
		if _, err := mustVer(t, m).AuthenticateBearer([]byte("   ")); err == nil {
			t.Fatal("whitespace bearer matched")
		}
		m = mustLoad(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			PathPrefix: "spec.management.auth",
			Source:     Memory([]RawToken{kept, second}),
		})
		if m.TokenCount() != 2 || m.tokens[1].digest != sha256.Sum256([]byte("   ")) {
			t.Fatalf("pair %+v", m.tokens)
		}
		if _, err := mustVer(t, m).AuthenticateBearer([]byte("kept")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("memory flag on", func(t *testing.T) {
		_, err := Load(Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			RejectBlankTokens: true,
			Source:            DNSBundle([]RawToken{blank}, "", FileOpts{}),
		})
		le := mustAs(t, err)
		if le.Error() != "empty token" || le.Field != "tokens" || le.Code != "required" || le.Kind != kerr.Invalid || le.TokenIndex != 0 || le.TokenID != "bearer" {
			t.Fatalf("single %+v", le)
		}
		_, err = Load(Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			RejectBlankTokens: true, PathPrefix: "spec.management.auth",
			Source: Memory([]RawToken{kept, {ID: "b", Secret: NewSecret([]byte(" \t "))}}),
		})
		le = mustAs(t, err)
		if le.Error() != "empty token" || le.Field != "tokens" || le.Code != "required" || le.Kind != kerr.Invalid || le.TokenIndex != 1 || le.TokenID != "b" {
			t.Fatalf("index %+v", le)
		}
		spaced := raw("b", "administrator", " x ")
		m := mustLoad(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			RejectBlankTokens: true,
			Source:            Memory([]RawToken{kept, spaced}),
		})
		if m.TokenCount() != 2 || m.tokens[1].digest != sha256.Sum256([]byte(" x ")) {
			t.Fatal("non-blank token was trimmed or rejected")
		}
	})

	t.Run("json body", func(t *testing.T) {
		dir := t.TempDir()
		obj := filepath.Join(dir, "obj")
		body := []byte(`{"tokens":[{"token":"kept","id":"a","role":"administrator"},{"token":"   ","id":"b"}]}`)
		if err := os.WriteFile(obj, body, 0o644); err != nil {
			t.Fatal(err)
		}
		arr := filepath.Join(dir, "arr")
		if err := os.WriteFile(arr, []byte(`[{"token":"   "}]`), 0o644); err != nil {
			t.Fatal(err)
		}
		opts := FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven}
		m := mustLoad(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			Source: DNSBundle(nil, obj, opts),
		})
		if m.TokenCount() != 2 || m.tokens[1].id != "b" || m.tokens[1].digest != sha256.Sum256([]byte("   ")) {
			t.Fatalf("json off %+v", m.tokens)
		}
		_, err := Load(Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			RejectBlankTokens: true, PathPrefix: "spec.management.auth",
			Source: DNSBundle(nil, obj, opts),
		})
		le := mustAs(t, err)
		if le.Error() != "empty token" || le.Field != "tokens" || le.Code != "required" || le.Kind != kerr.Invalid || le.TokenIndex != 1 || le.TokenID != "b" || le.File != "secretRef" {
			t.Fatalf("json on %+v", le)
		}
		_, err = Load(Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			RejectBlankTokens: true,
			Source:            DNSBundle(nil, arr, opts),
		})
		le = mustAs(t, err)
		if le.Error() != "empty token" || le.Field != "tokens" || le.Code != "required" || le.TokenIndex != 0 || le.TokenID != "bearer" {
			t.Fatalf("array %+v", le)
		}
	})

	t.Run("zero length stays required when flag is off", func(t *testing.T) {
		_, err := Load(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue,
			Source: Memory([]RawToken{raw("a", "administrator", "")}),
		})
		le := mustAs(t, err)
		if le.Error() != "token value is required" || le.Code != "required" || le.Field != "tokens[0].secretFile" {
			t.Fatalf("empty %+v", le)
		}
		_, err = Load(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue, RejectBlankTokens: true,
			Source: Memory([]RawToken{raw("a", "administrator", "")}),
		})
		le = mustAs(t, err)
		if le.Error() != "empty token" || le.Field != "tokens" || le.Code != "required" || le.TokenIndex != 0 {
			t.Fatalf("empty with flag %+v", le)
		}
	})

	t.Run("id and floor run first", func(t *testing.T) {
		_, err := Load(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue, RejectBlankTokens: true,
			Source: Memory([]RawToken{{Secret: NewSecret([]byte("   "))}}),
		})
		le := mustAs(t, err)
		if le.Error() != "token id is required" || le.Code != "empty_id" {
			t.Fatalf("id %+v", le)
		}
		_, err = Load(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue, RejectBlankTokens: true,
			MinSecretBytes: 4,
			Source:         Memory([]RawToken{raw("a", "administrator", "   ")}),
		})
		le = mustAs(t, err)
		if le.Error() != `secretFile "" trimmed contents are shorter than 4 bytes` || le.Code != "invalid_value" {
			t.Fatalf("floor %+v", le)
		}
	})

	t.Run("file modes do not yield a whitespace token", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "spaces")
		if err := os.WriteFile(path, []byte("   \n\t\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		line := FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven}
		_, err := Load(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue, RejectBlankTokens: true,
			Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: path}}, line),
		})
		le := mustAs(t, err)
		if le.Error() == "empty token" || le.Code != "unresolved_reference" || le.Err != os.ErrInvalid {
			t.Fatalf("line %+v", le)
		}
		whole := FileOpts{Line: WholeFileTrim, Resolve: AsGiven}
		_, err = Load(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue,
			Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: path}}, whole),
		})
		le = mustAs(t, err)
		if le.Error() != "token value is required" || le.Code != "required" {
			t.Fatalf("whole off %+v", le)
		}
		_, err = Load(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue, RejectBlankTokens: true,
			Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: path}}, whole),
		})
		le = mustAs(t, err)
		if le.Error() != "empty token" || le.Field != "tokens" || le.Code != "required" {
			t.Fatalf("whole on %+v", le)
		}
	})

	off := memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "kept"))
	on := off
	on.RejectBlankTokens = true
	if specHash(off) == specHash(on) {
		t.Fatal("RejectBlankTokens is outside the spec hash")
	}
}
