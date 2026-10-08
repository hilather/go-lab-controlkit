package authn

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// TestPaddedSecretRefPerRepo is the KS-B2a regression. Before TrimRef, every
// reader trimmed the ref, so a padded path opened the file. ntp, netconf,
// maildev, and syslog pass the ref to os.ReadFile as written. snmp and dns
// trim first. The kit's per-token sentence stays syslog's
// `secretFile %q: %v` of the original ref. ntp, netconf, and snmp say
// "token secret file does not resolve", and maildev's token sentence appends
// the raw path; those are not the kit message. maildev's basic sentence and
// dns's "token secret is unavailable" are.
func TestPaddedSecretRefPerRepo(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "tok")
	if err := os.WriteFile(abs, []byte("padded-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	padded := " " + abs + " "
	base := filepath.Join(dir, "base")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	syslogBase := filepath.Join(dir, "syslog")
	if err := os.Mkdir(syslogBase, 0o755); err != nil {
		t.Fatal(err)
	}
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	paddedPass := " " + pass + " "

	asGiven := FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven}
	// Harden false and TrimRef false is os.ReadFile of the ref as written,
	// including a padded ref, a whitespace ref, and the empty ref.
	sameRead(t, padded, asGiven)
	sameRead(t, "   ", asGiven)
	sameRead(t, "", asGiven)

	bare := asGiven
	bare.TrimRef = true
	if _, err := ReadFile("", bare); err != os.ErrNotExist {
		t.Fatalf("trimmed empty ref: %v", err)
	}
	if _, err := ReadFile(" \t ", bare); err != os.ErrNotExist {
		t.Fatalf("trimmed blank ref: %v", err)
	}

	t.Run("ntp", func(t *testing.T) {
		opts := asGiven
		n, err := UsableLineLen(padded, opts)
		if n != 0 || err == nil {
			t.Fatalf("usable %d %v", n, err)
		}
		matchOSRead(t, err, padded)
		_, err = Load(bearerFiles(padded, opts))
		le := mustAs(t, err)
		want := osReadErr(padded)
		if le.Error() != secretFileSentence(padded, want) || le.File != padded || le.Code != "unresolved_reference" {
			t.Fatalf("ntp load %+v", le)
		}
		matchOSRead(t, le.Err, padded)

		on := opts
		on.TrimRef = true
		m := mustLoad(t, bearerFiles(padded, on))
		if m.TokenCount() != 1 {
			t.Fatalf("trim on count %d", m.TokenCount())
		}
		if _, err := mustVer(t, m).AuthenticateBearer([]byte("padded-secret")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("netconf", func(t *testing.T) {
		opts := FileOpts{Line: FirstNonCommentLine, Resolve: AsGivenAndBaseDir, BaseDir: base}
		got, err := ReadFile(padded, opts)
		zero(got)
		if err == nil {
			t.Fatal("padded ref opened")
		}
		matchOSRead(t, err, padded)
		st := mustPrep(t, bearerFiles(padded, opts))
		if st.Err() == nil {
			t.Fatal("padded ref loaded")
		}
		files := st.Files()
		if len(files) != 2 || files[0].Resolver != "as-given" || files[0].Ref != padded || files[0].Path != padded {
			t.Fatalf("as-given candidate %+v", files)
		}
		matchOSRead(t, files[0].ReadErr, padded)
		joined := filepath.Join(base, padded)
		if files[1].Resolver != "base" || files[1].Ref != padded || files[1].Path != joined {
			t.Fatalf("base candidate %+v", files[1])
		}
		matchOSRead(t, files[1].ReadErr, joined)
		le := mustAs(t, st.Err())
		if le.Error() != secretFileSentence(padded, osReadErr(padded)) || le.File != padded {
			t.Fatalf("netconf load %+v", le)
		}
	})

	t.Run("maildev", func(t *testing.T) {
		opts := asGiven
		n, err := UsableLineLen(paddedPass, opts)
		if n != 0 || err == nil {
			t.Fatalf("usable %d %v", n, err)
		}
		matchOSRead(t, err, paddedPass)
		_, err = Load(Config{
			Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
			Source: PerTokenFiles([]FileToken{{ID: "ops", Role: "administrator", SecretFile: abs}}, opts),
			Basic:  &BasicSpec{Username: "ada", PasswordFile: paddedPass, TokenRef: "ops", Opts: opts},
		})
		le := mustAs(t, err)
		if le.Error() != "basic password file does not resolve: "+paddedPass || le.File != paddedPass || le.Code != "unresolved_reference" {
			t.Fatalf("password %+v", le)
		}
		matchOSRead(t, le.Err, paddedPass)

		on := opts
		on.TrimRef = true
		if n, err := UsableLineLen(paddedPass, on); err != nil || n != len("s3cret") {
			t.Fatalf("trimmed usable %d %v", n, err)
		}
		m := mustLoad(t, Config{
			Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
			Source: PerTokenFiles([]FileToken{{ID: "ops", Role: "administrator", SecretFile: abs}}, on),
			Basic:  &BasicSpec{Username: "ada", PasswordFile: paddedPass, TokenRef: "ops", Opts: on},
		})
		hdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("ada:s3cret"))
		if _, err := mustVer(t, m).Authenticate(Request{Authorization: hdr, AllowBasic: true}); err != nil {
			t.Fatal(err)
		}
		_, err = Load(Config{
			Mode: ModeBearerAndBasic, Duplicates: RejectDuplicateValue,
			Source: PerTokenFiles([]FileToken{{ID: "ops", Role: "administrator", SecretFile: abs}}, on),
			Basic:  &BasicSpec{Username: "ada", PasswordFile: "   ", TokenRef: "ops", Opts: on},
		})
		le = mustAs(t, err)
		if le.Error() != "basic password file does not resolve: "+"   " || le.Err != os.ErrNotExist || le.Code != "unresolved_reference" {
			t.Fatalf("blank password ref %+v", le)
		}
	})

	t.Run("syslog", func(t *testing.T) {
		opts := FileOpts{
			Line: WholeFileTrim, Resolve: ConfigDirIfRelative, BaseDir: syslogBase,
			SkipMissing: true,
		}
		joined := filepath.Join(syslogBase, padded)
		got, err := ReadFile(padded, opts)
		zero(got)
		matchOSRead(t, err, joined)
		if _, err := UsableLineLen(padded, opts); err == nil {
			t.Fatal("usable line of a missing join")
		} else {
			matchOSRead(t, err, joined)
		}
		// An empty ref is relative, so syslog joins it. That open is the
		// directory, which is what os.ReadFile of the join returns.
		emptyJoined := filepath.Join(syslogBase, "")
		if _, err := ReadFile("", opts); err == nil {
			t.Fatal("empty ref opened nothing")
		} else {
			matchOSRead(t, err, emptyJoined)
		}
		m := mustLoad(t, bearerFiles(padded, opts))
		if m.TokenCount() != 0 {
			t.Fatalf("skip missing count %d", m.TokenCount())
		}
		st := mustPrep(t, bearerFiles(padded, opts))
		if st.Err() != nil {
			t.Fatal(st.Err())
		}
		files := st.Files()
		if len(files) != 1 || files[0].Resolver != "config-dir" || files[0].Ref != padded || files[0].Path != joined {
			t.Fatalf("syslog candidate %+v", files)
		}
		matchOSRead(t, files[0].ReadErr, joined)

		strict := opts
		strict.SkipMissing = false
		_, err = Load(bearerFiles(padded, strict))
		le := mustAs(t, err)
		if le.Error() != secretFileSentence(padded, osReadErr(joined)) || le.File != padded {
			t.Fatalf("syslog load %+v", le)
		}
		matchOSRead(t, le.Err, joined)
	})

	t.Run("snmp", func(t *testing.T) {
		opts := FileOpts{Line: FirstNonCommentLine, Resolve: CWDThenBaseDir, BaseDir: base, TrimRef: true}
		st := mustPrep(t, bearerFiles(padded, opts))
		if st.Err() != nil {
			t.Fatal(st.Err())
		}
		files := st.Files()
		if len(files) != 1 || files[0].Resolver != "cwd" || files[0].Path != abs || files[0].Ref != padded || !files[0].Picked {
			t.Fatalf("snmp candidate %+v", files)
		}
		m := mustLoad(t, bearerFiles(padded, opts))
		if m.TokenCount() != 1 {
			t.Fatalf("count %d", m.TokenCount())
		}
		if _, err := mustVer(t, m).AuthenticateBearer([]byte("padded-secret")); err != nil {
			t.Fatal(err)
		}
		if n, err := UsableLineLen(padded, opts); err != nil || n != len("padded-secret") {
			t.Fatalf("usable %d %v", n, err)
		}
		if _, err := ReadFile("   ", opts); err != os.ErrNotExist {
			t.Fatalf("blank ref %v", err)
		}
		var pe *fs.PathError
		if _, err := ReadFile("   ", opts); errors.As(err, &pe) {
			t.Fatalf("blank ref opened: %v", err)
		}
		if n, err := UsableLineLen("   ", opts); n != 0 || err != os.ErrNotExist {
			t.Fatalf("blank usable %d %v", n, err)
		}
		_, err := Load(bearerFiles("   ", opts))
		le := mustAs(t, err)
		if le.Err != os.ErrNotExist || le.Error() != secretFileSentence("   ", os.ErrNotExist) || le.File != "   " {
			t.Fatalf("blank load %+v", le)
		}
		off := opts
		off.TrimRef = false
		if _, err := ReadFile(padded, off); err == nil {
			t.Fatal("untrimmed snmp opened the padded ref")
		} else {
			matchOSRead(t, err, padded)
		}

		relName := "ksb2a-reltok"
		if err := os.WriteFile(filepath.Join(base, relName), []byte("rel-secret\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rel := " " + relName + " "
		empty := t.TempDir()
		t.Chdir(empty)
		relm := mustLoad(t, bearerFiles(rel, opts))
		if _, err := mustVer(t, relm).AuthenticateBearer([]byte("rel-secret")); err != nil {
			t.Fatal(err)
		}
		_, err = Load(bearerFiles(rel, off))
		le = mustAs(t, err)
		if le.Error() != secretFileSentence(rel, osReadErr(rel)) {
			t.Fatalf("untrimmed relative %+v", le)
		}
	})

	t.Run("dns", func(t *testing.T) {
		defs := &DNSDefaults{EmptyID: "bearer", EmptyRoleAndScopes: "administrator"}
		opts := FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, TrimRef: true}
		st := mustPrep(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			Source: DNSBundle(nil, padded, opts),
		})
		if st.Err() != nil {
			t.Fatal(st.Err())
		}
		files := st.Files()
		if len(files) != 1 || files[0].Path != abs || files[0].Ref != padded || !files[0].Picked || files[0].Resolver != "as-given" {
			t.Fatalf("dns candidate %+v", files)
		}
		m := mustLoad(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			Source: DNSBundle(nil, padded, opts),
		})
		if m.TokenCount() != 1 {
			t.Fatalf("count %d", m.TokenCount())
		}
		if _, err := mustVer(t, m).AuthenticateBearer([]byte("padded-secret")); err != nil {
			t.Fatal(err)
		}
		mem := raw("mem", "administrator", "mem-secret")
		m = mustLoad(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			Source: DNSBundle([]RawToken{mem}, " \t ", FileOpts{TrimRef: true}),
		})
		if m.TokenCount() != 1 {
			t.Fatalf("blank secretRef count %d", m.TokenCount())
		}
		if _, err := mustVer(t, m).AuthenticateBearer([]byte("mem-secret")); err != nil {
			t.Fatal(err)
		}
		blank := mustPrep(t, Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			Source: DNSBundle([]RawToken{mem}, "   ", FileOpts{TrimRef: true}),
		})
		if blank.Err() != nil || len(blank.Files()) != 0 {
			t.Fatalf("blank secretRef opened a file: %v %+v", blank.Err(), blank.Files())
		}
		off := opts
		off.TrimRef = false
		_, err := Load(Config{
			Mode: ModeBearer, Duplicates: FirstMatchWins, DNSDefaults: defs,
			Source: DNSBundle(nil, padded, off),
		})
		le := mustAs(t, err)
		if le.Error() != "token secret is unavailable" || le.File != padded || le.Kind != kerr.Unauthenticated {
			t.Fatalf("untrimmed dns %+v", le)
		}
		matchOSRead(t, le.Err, padded)
	})

	plain := FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven}
	trimmed := plain
	trimmed.TrimRef = true
	h1 := specHash(Config{Mode: ModeBearer, Duplicates: RejectDuplicateValue, Source: PerTokenFiles(nil, plain)})
	h2 := specHash(Config{Mode: ModeBearer, Duplicates: RejectDuplicateValue, Source: PerTokenFiles(nil, trimmed)})
	if h1 == h2 {
		t.Fatal("TrimRef is outside the spec hash")
	}
}

func bearerFiles(ref string, o FileOpts) Config {
	return Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "ops", Role: "administrator", SecretFile: ref}}, o),
	}
}

func mustPrep(t *testing.T, cfg Config) *Staged {
	t.Helper()
	st, err := Prepare(cfg)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return st
}

func osReadErr(path string) error {
	b, err := os.ReadFile(path)
	zero(b)
	return err
}

func matchOSRead(t *testing.T, got error, path string) {
	t.Helper()
	want := osReadErr(path)
	if got == nil || want == nil {
		t.Fatalf("err %v vs %v", got, want)
	}
	if got.Error() != want.Error() {
		t.Fatalf("text %q vs %q", got.Error(), want.Error())
	}
	var g, w *fs.PathError
	if errors.As(got, &g) != errors.As(want, &w) {
		t.Fatalf("shape %T %v vs %T %v", got, got, want, want)
	}
	if g != nil && (g.Op != w.Op || g.Path != w.Path || !errors.Is(g.Err, w.Err) || !errors.Is(w.Err, g.Err)) {
		t.Fatalf("path %+v vs %+v", g, w)
	}
}

func secretFileSentence(ref string, err error) string {
	return "secretFile " + strconv.Quote(ref) + ": " + err.Error()
}
