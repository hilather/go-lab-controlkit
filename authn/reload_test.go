package authn

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hilather/go-lab-controlkit/kerr"
)

type countSource struct {
	n     int
	toks  []RawToken
	files []FileResult
	err   error
}

func (c *countSource) Read() ([]RawToken, []FileResult, error) {
	c.n++
	if c.err != nil {
		return nil, append([]FileResult(nil), c.files...), c.err
	}
	toks, files, err := Memory(c.toks).Read()
	return toks, append(files, c.files...), err
}

func (c *countSource) Spec() any { return "count" }

type lockSource struct {
	mu      *sync.Mutex
	sawHeld bool
	toks    []RawToken
}

func (s *lockSource) Read() ([]RawToken, []FileResult, error) {
	if s.mu.TryLock() {
		s.mu.Unlock()
		s.sawHeld = false
	} else {
		s.sawHeld = true
	}
	return Memory(s.toks).Read()
}

func (s *lockSource) Spec() any { return struct{ Kind string }{Kind: "lock"} }

func TestPrepareRejectsUnreadableSecret(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores mode 000")
	}
	path := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 32)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	st, err := Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, MinSecretBytes: 32,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: path}}, FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, Harden: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Err() == nil {
		t.Fatal("unreadable file committed")
	}
	if st.Commit(Empty()) {
		t.Fatal("commit installed an unreadable stage")
	}
	fr, err := st.Lookup(path)
	if err != nil || fr.ReadErr == nil || !os.IsPermission(fr.ReadErr) {
		t.Fatalf("fact %+v err %v", fr, err)
	}
}

func TestPrepareRejectsShortOrEmptyTokens(t *testing.T) {
	st, err := Prepare(memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "")))
	if err != nil || st.Err() == nil || !strings.Contains(st.Err().Error(), "token value is required") {
		t.Fatalf("empty err %v stage %v", err, st)
	}
	st, err = Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue, MinSecretBytes: 32,
		Source: Memory([]RawToken{raw("a", "administrator", "short")}),
	})
	if err != nil || st.Err() == nil || !strings.Contains(st.Err().Error(), "shorter than 32") {
		t.Fatalf("short %v", st.Err())
	}
}

func TestPrepareSkipMissingNoAccept(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	st, err := Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: missing}}, FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, SkipMissing: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Err() != nil {
		t.Fatal(st.Err())
	}
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("old", "administrator", "old-secret"))))
	if !st.Commit(v) {
		t.Fatal("commit")
	}
	if v.TokenCount() != 0 {
		t.Fatalf("count %d", v.TokenCount())
	}
}

func TestPrepareAcceptPredicate(t *testing.T) {
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("old", "administrator", "old-secret"))))
	st, err := Prepare(Config{
		Mode: ModeBearer, Source: Memory(nil), Duplicates: RejectDuplicateValue,
		Accept: BearerNeedsToken(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Err() == nil || !strings.Contains(st.Err().Error(), "at least one usable token") {
		t.Fatalf("err %v", st.Err())
	}
	if st.Commit(v) {
		t.Fatal("predicate failure committed")
	}
	if _, err := v.AuthenticateBearer([]byte("old-secret")); err != nil {
		t.Fatal(err)
	}
}

func TestCommitDoesNotReadFiles(t *testing.T) {
	src := &countSource{toks: []RawToken{raw("a", "administrator", "secret")}}
	st, err := Prepare(Config{Mode: ModeBearer, Source: src, Duplicates: RejectDuplicateValue})
	if err != nil || st.Err() != nil {
		t.Fatalf("prepare %v %v", err, st.Err())
	}
	if src.n != 1 {
		t.Fatalf("reads %d", src.n)
	}
	v := Empty()
	if !st.Commit(v) {
		t.Fatal("commit")
	}
	if src.n != 1 {
		t.Fatalf("commit read the source: %d", src.n)
	}
	if _, err := v.AuthenticateBearer([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	st.Discard()
	if st.Commit(v) {
		t.Fatal("discarded stage committed")
	}
	if src.n != 1 {
		t.Fatalf("discard read the source: %d", src.n)
	}
}

func TestCommitFiresIdentityHooksOnce(t *testing.T) {
	v := Empty()
	n := 0
	v.OnIdentityChange(func() { n++ })
	st, err := Prepare(memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "secret")))
	if err != nil || st.Err() != nil {
		t.Fatal(err)
	}
	if !st.Commit(v) || n != 1 {
		t.Fatalf("changed %v hooks %d", true, n)
	}
	if st.Commit(v) || n != 1 {
		t.Fatalf("second commit hooks %d", n)
	}
}

func TestPrepareRunsWithoutAppLock(t *testing.T) {
	var mu sync.Mutex
	src := &lockSource{mu: &mu, toks: []RawToken{raw("a", "administrator", "secret")}}
	st, err := Prepare(Config{Mode: ModeBearer, Source: src, Duplicates: RejectDuplicateValue})
	if err != nil || st.Err() != nil {
		t.Fatalf("%v %v", err, st.Err())
	}
	if src.sawHeld {
		t.Fatal("Prepare required the caller lock")
	}
}

func TestSpecHashMismatchRePreparesUnderLock(t *testing.T) {
	var mu sync.Mutex
	firstSrc := &lockSource{mu: &mu, toks: []RawToken{raw("a", "administrator", "one")}}
	cfg1 := Config{Mode: ModeBearer, Source: firstSrc, Duplicates: RejectDuplicateValue, ManagementBound: false}
	st1, err := Prepare(cfg1)
	if err != nil || st1.Err() != nil {
		t.Fatal(err)
	}
	secondSrc := &lockSource{mu: &mu, toks: []RawToken{raw("a", "administrator", "two")}}
	cfg2 := Config{Mode: ModeBearer, Source: secondSrc, Duplicates: RejectDuplicateValue, ManagementBound: true}
	if st1.SpecHash() == specHash(cfg2) {
		t.Fatal("management-bound bit did not change the hash")
	}
	mu.Lock()
	st2, err := Prepare(cfg2)
	mu.Unlock()
	if err != nil || st2.Err() != nil {
		t.Fatalf("re-prepare %v %v", err, st2.Err())
	}
	if !secondSrc.sawHeld {
		t.Fatal("re-prepare did not run while the caller held the lock")
	}
	if st1.SpecHash() == st2.SpecHash() {
		t.Fatal("hashes matched")
	}
	v := mustVer(t, st1.mat)
	st1.Discard()
	if !st2.Commit(v) {
		t.Fatal("commit")
	}
	if _, err := v.AuthenticateBearer([]byte("two")); err != nil {
		t.Fatal(err)
	}
	plain := memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "one"))
	withAccept := plain
	withAccept.Accept = func(*Material) error { return nil }
	if specHash(plain) == specHash(withAccept) {
		t.Fatal("accept presence was not hashed")
	}
}

func TestCompileMissingFileResultIsInternalError(t *testing.T) {
	st, err := Prepare(memCfg(ModeBearer, RejectDuplicateValue, raw("a", "administrator", "secret")))
	if err != nil {
		t.Fatal(err)
	}
	_, miss := st.Lookup("/never/opened")
	if miss == nil || !kindIs(miss, kerr.Internal) || strings.Contains(miss.Error(), "not checked") {
		t.Fatalf("got %v", miss)
	}
	nc := NotChecked()
	fr, err := nc.Lookup("/anything")
	if err != nil || !fr.NotChecked || !nc.IsNotChecked() {
		t.Fatalf("not checked %+v %v", fr, err)
	}
	if nc.Commit(Empty()) {
		t.Fatal("not-checked stage committed")
	}
}

func TestCompileRendersFilesWithoutReading(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores mode 000")
	}
	root := t.TempDir()
	t.Chdir(root)
	base := filepath.Join(root, "base")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if mode == 0 {
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			return
		}
		if mode != 0o644 {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	opts := func(res PathMode) FileOpts {
		return FileOpts{Line: FirstNonCommentLine, Resolve: res, BaseDir: base, Harden: true}
	}
	prep := func(ref string, res PathMode) *Staged {
		t.Helper()
		st, err := Prepare(Config{
			Mode: ModeBearer, Duplicates: RejectDuplicateValue,
			Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: ref}}, opts(res)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	fact := func(st *Staged, path string) FileResult {
		t.Helper()
		fr, err := st.Lookup(path)
		if err != nil {
			t.Fatal(err)
		}
		return fr
	}

	missing := prep(filepath.Join(root, "missing"), AsGiven)
	fr := fact(missing, filepath.Join(root, "missing"))
	if !os.IsNotExist(fr.StatErr) || !os.IsNotExist(fr.ReadErr) || fr.Picked || fr.NotChecked {
		t.Fatalf("missing %+v", fr)
	}

	locked := filepath.Join(root, "locked")
	write(locked, strings.Repeat("a", 32), 0)
	st := prep(locked, AsGiven)
	fr = fact(st, locked)
	if fr.ReadErr == nil || !os.IsPermission(fr.ReadErr) || fr.Picked {
		t.Fatalf("mode 000 %+v", fr)
	}

	dir := filepath.Join(root, "adir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	st = prep(dir, AsGiven)
	fr = fact(st, dir)
	if !fr.IsDir || !errors.Is(fr.ReadErr, syscall.EISDIR) {
		t.Fatalf("dir %+v", fr)
	}
	if _, readErr := os.ReadFile(dir); readErr == nil || fr.ReadErr.Error() != readErr.Error() {
		t.Fatalf("dir text %v vs %v", fr.ReadErr, readErr)
	}

	empty := filepath.Join(root, "empty")
	write(empty, "", 0o644)
	st = prep(empty, AsGiven)
	fr = fact(st, empty)
	if fr.TrimLen != 0 || fr.UsableLen != -1 || fr.Picked || st.Err() == nil {
		t.Fatalf("empty %+v err %v", fr, st.Err())
	}

	comment := filepath.Join(root, "comment")
	write(comment, "# only\n\n", 0o644)
	st = prep(comment, AsGiven)
	fr = fact(st, comment)
	if fr.UsableLen != -1 || fr.TrimLen == 0 || fr.Picked {
		t.Fatalf("comment %+v", fr)
	}

	plusNL := filepath.Join(root, "plusnl")
	body31 := strings.Repeat("a", 31)
	write(plusNL, body31+"\n", 0o644)
	st = prep(plusNL, AsGiven)
	fr = fact(st, plusNL)
	if fr.RawLen != 32 || fr.TrimLen != 31 || fr.UsableLen != 31 || !fr.Picked {
		t.Fatalf("31+nl %+v", fr)
	}
	if err := os.Chmod(plusNL, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(plusNL, 0o600) })
	again, err := st.Lookup(plusNL)
	if err != nil || again.UsableLen != 31 {
		t.Fatalf("lookup re-read %+v %v", again, err)
	}

	exact := filepath.Join(root, "exact")
	write(exact, strings.Repeat("b", 32), 0o644)
	fr = fact(prep(exact, AsGiven), exact)
	if fr.RawLen != 32 || fr.TrimLen != 32 || fr.UsableLen != 32 || !fr.Picked {
		t.Fatalf("32 %+v", fr)
	}

	padded := filepath.Join(root, "padded")
	write(padded, "  "+strings.Repeat("c", 32)+" \n", 0o644)
	fr = fact(prep(padded, AsGiven), padded)
	if fr.UsableLen != 32 || fr.TrimLen != 32 || !fr.Picked || fr.RawLen <= 32 {
		t.Fatalf("padded %+v", fr)
	}

	second := filepath.Join(root, "second")
	write(second, "# c\nSECRET\n", 0o644)
	fr = fact(prep(second, AsGiven), second)
	if fr.UsableLen != len("SECRET") || !fr.Picked {
		t.Fatalf("second line %+v", fr)
	}

	write("cwd000", "nope", 0)
	good := strings.Repeat("d", 32)
	write(filepath.Join(base, "cwd000"), good+"\n", 0o644)
	st, err = Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: "cwd000"}}, opts(CWDThenBaseDir)),
	})
	if err != nil || st.Err() != nil {
		t.Fatalf("cwd 000 %v %v", err, st.Err())
	}
	cwd := fact(st, "cwd000")
	baseFR := fact(st, filepath.Join(base, "cwd000"))
	if cwd.Picked || !os.IsPermission(cwd.ReadErr) || !baseFR.Picked || baseFR.UsableLen != 32 {
		t.Fatalf("cwd %+v base %+v", cwd, baseFR)
	}

	write("cwdnote", "# only\n", 0o644)
	write(filepath.Join(base, "cwdnote"), good+"\n", 0o644)
	st, err = Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: "cwdnote"}}, opts(CWDThenBaseDir)),
	})
	if err != nil || st.Err() != nil {
		t.Fatalf("comment cwd %v %v", err, st.Err())
	}
	cwd = fact(st, "cwdnote")
	baseFR = fact(st, filepath.Join(base, "cwdnote"))
	if cwd.Picked || cwd.UsableLen != -1 || !baseFR.Picked {
		t.Fatalf("comment cwd %+v base %+v", cwd, baseFR)
	}

	write("rel", good+"\n", 0o644)
	write(filepath.Join(base, "rel"), strings.Repeat("e", 32)+"\n", 0o644)
	st, err = Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: "rel"}}, opts(AsGivenAndBaseDir)),
	})
	if err != nil || st.Err() != nil {
		t.Fatalf("netconf %v %v", err, st.Err())
	}
	files := st.Files()
	if len(files) != 2 || files[0].Resolver != "as-given" || !files[0].Picked || files[1].Resolver != "base" || files[1].Picked {
		t.Fatalf("both resolutions %+v", files)
	}

	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o622); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	st = prep(fifo, AsGiven)
	if time.Since(start) >= 100*time.Millisecond {
		t.Fatalf("fifo blocked %s", time.Since(start))
	}
	fr = fact(st, fifo)
	if !errors.Is(fr.ReadErr, ErrNotRegular) || fr.Picked {
		t.Fatalf("fifo %+v", fr)
	}

	big := filepath.Join(root, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte{'z'}, maxSecretFile+1), 0o644); err != nil {
		t.Fatal(err)
	}
	st = prep(big, AsGiven)
	fr = fact(st, big)
	if !errors.Is(fr.ReadErr, ErrTooLarge) || fr.RawLen != maxSecretFile+1 {
		t.Fatalf("big %+v", fr)
	}
}

func TestPrepareCollectsAllFileResults(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	st, err := Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{
			{ID: "a", Role: "administrator", SecretFile: a},
			{ID: "b", Role: "administrator", SecretFile: b},
		}, FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, Harden: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Err() == nil {
		t.Fatal("expected the first failure")
	}
	files := st.Files()
	if len(files) != 2 || files[0].Path != a || files[1].Path != b {
		t.Fatalf("files %+v", files)
	}
	if !os.IsNotExist(files[0].ReadErr) || !os.IsNotExist(files[1].ReadErr) {
		t.Fatalf("errs %v %v", files[0].ReadErr, files[1].ReadErr)
	}
}
