package authn

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func passOpts(harden bool) FileOpts {
	return FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, Harden: harden}
}

func sameRead(t *testing.T, path string, o FileOpts) {
	t.Helper()
	got, gotErr := ReadFile(path, o)
	want, wantErr := os.ReadFile(path)
	defer zero(got)
	defer zero(want)
	if !bytes.Equal(got, want) {
		t.Fatalf("bytes len %d vs %d", len(got), len(want))
	}
	if (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("err %v vs %v", gotErr, wantErr)
	}
	if gotErr == nil {
		return
	}
	if gotErr.Error() != wantErr.Error() {
		t.Fatalf("text %q vs %q", gotErr.Error(), wantErr.Error())
	}
	var g, w *fs.PathError
	if errors.As(gotErr, &g) != errors.As(wantErr, &w) {
		t.Fatalf("path error shape %v vs %v", gotErr, wantErr)
	}
	if g != nil && (g.Op != w.Op || g.Path != w.Path || !errors.Is(g.Err, w.Err) || !errors.Is(w.Err, g.Err)) {
		t.Fatalf("path error %+v vs %+v", g, w)
	}
}

func TestReaderPassThroughMatchesReadFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	locked := filepath.Join(dir, "locked")
	if err := os.WriteFile(locked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Log("skipping mode 000 comparison as root")
	} else {
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	o := passOpts(false)
	sameRead(t, good, o)
	sameRead(t, missing, o)
	if os.Geteuid() != 0 {
		sameRead(t, locked, o)
	}
	sameRead(t, sub, o)
}

func TestReaderDirectoryMatchesReadFile(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "dir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, harden := range []bool{false, true} {
		_, err := ReadFile(sub, passOpts(harden))
		wantErr := readDirErr(t, sub)
		if err == nil || wantErr == nil {
			t.Fatalf("harden %v err %v want %v", harden, err, wantErr)
		}
		if err.Error() != wantErr.Error() {
			t.Fatalf("harden %v text %q vs %q", harden, err.Error(), wantErr.Error())
		}
		var got *fs.PathError
		if !errors.As(err, &got) || got.Op != "read" || got.Path != sub || !errors.Is(got.Err, syscall.EISDIR) {
			t.Fatalf("harden %v path error %#v", harden, err)
		}
	}
}

func readDirErr(t *testing.T, path string) error {
	t.Helper()
	_, err := os.ReadFile(path)
	return err
}

func TestReaderOpenErrorsMatchReadFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such")
	for _, harden := range []bool{false, true} {
		sameRead(t, missing, passOpts(harden))
	}
}

func TestReaderRefusesFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o622); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := ReadFile(path, passOpts(true))
	if time.Since(start) >= 100*time.Millisecond {
		t.Fatalf("blocked for %s", time.Since(start))
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Op != "read" || pe.Path != path || !errors.Is(pe.Err, ErrNotRegular) {
		t.Fatalf("err %#v", err)
	}
}

func TestReaderRefusesCharDevice(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("/dev/zero unavailable")
	}
	start := time.Now()
	_, err := ReadFile("/dev/zero", passOpts(true))
	if time.Since(start) >= 100*time.Millisecond {
		t.Fatalf("blocked for %s", time.Since(start))
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err %v", err)
	}
}

func TestReaderRefusesOver1MiB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	buf := bytes.Repeat([]byte{'a'}, maxSecretFile+1)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFile(path, passOpts(true))
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Op != "read" || pe.Path != path || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err %#v", err)
	}
	if pe.Err.Error() != "file is larger than 1 MiB" {
		t.Fatalf("text %v", pe.Err)
	}
}

func TestReaderAccepts1MiB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exact")
	buf := bytes.Repeat([]byte{'b'}, maxSecretFile)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(path, passOpts(true))
	defer zero(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxSecretFile || !bytes.Equal(got, buf) {
		t.Fatalf("len %d", len(got))
	}
}

func TestReaderFollowsSymlinkToRegular(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "..data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("k8s-secret\n")
	if err := os.WriteFile(filepath.Join(data, "token"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "token")
	if err := os.Symlink(filepath.Join("..data", "token"), link); err != nil {
		t.Fatal(err)
	}
	for _, harden := range []bool{false, true} {
		got, err := ReadFile(link, passOpts(harden))
		defer zero(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("harden %v bytes %q", harden, got)
		}
	}
}

func TestReaderRefusesSymlinkToFIFO(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o622); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := ReadFile(link, passOpts(true))
	if time.Since(start) >= 100*time.Millisecond {
		t.Fatalf("blocked for %s", time.Since(start))
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err %v", err)
	}
}

func TestReadFileCWDThenBaseDirUsesUsableLine(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	base := filepath.Join(root, "base")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tok"), []byte("# only a comment\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseBody := []byte("base-secret\n")
	if err := os.WriteFile(filepath.Join(base, "tok"), baseBody, 0o644); err != nil {
		t.Fatal(err)
	}
	o := FileOpts{Line: FirstNonCommentLine, Resolve: CWDThenBaseDir, BaseDir: base}
	got, err := ReadFile("tok", o)
	defer zero(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, baseBody) {
		t.Fatalf("comment-only cwd pinned %q", got)
	}
	m := mustLoad(t, Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "a", Role: "administrator", SecretFile: "tok"}}, o),
	})
	if _, err := mustVer(t, m).AuthenticateBearer([]byte("base-secret")); err != nil {
		t.Fatal(err)
	}

	cwdBody := []byte("cwd-secret\n")
	if err := os.WriteFile(filepath.Join(root, "tok"), cwdBody, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = ReadFile("tok", o)
	defer zero(got)
	if err != nil || !bytes.Equal(got, cwdBody) {
		t.Fatalf("cwd got %q err %v", got, err)
	}

	if err := os.WriteFile(filepath.Join(root, "whole"), []byte(" \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "whole"), []byte("base-whole\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wo := FileOpts{Line: WholeFileTrim, Resolve: CWDThenBaseDir, BaseDir: base}
	got, err = ReadFile("whole", wo)
	defer zero(got)
	if err != nil || !bytes.Equal(got, []byte(" \n")) {
		t.Fatalf("whole-file trim got %q err %v", got, err)
	}
}

func TestUsableLineLenMatchesMaildev(t *testing.T) {
	dir := t.TempDir()
	o := passOpts(false)
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := UsableLineLen(write("blank", "\n\n   \n"), o); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("blank %v", err)
	}
	if _, err := UsableLineLen(write("comments", "# a\n\n# b\n"), o); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("comments %v", err)
	}
	n, err := UsableLineLen(write("then", "# c\n  secret-value \n"), o)
	if err != nil || n != len("secret-value") {
		t.Fatalf("then n=%d err=%v", n, err)
	}
	n, err = UsableLineLen(write("pad", " \t secret \t\n"), o)
	if err != nil || n != len("secret") {
		t.Fatalf("pad n=%d err=%v", n, err)
	}
	if _, err := UsableLineLen(filepath.Join(dir, "missing"), o); err == nil {
		t.Fatal("missing file returned a length")
	}
}
