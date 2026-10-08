package authn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/scope"
)

func TestStdioPinSameIDSecretRotationDenies(t *testing.T) {
	secret := "rotate-me-please"
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", secret, "all"))))
	pin, err := NewStdioPin(v, NewSecret([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pin.Resolve(); err != nil {
		t.Fatal(err)
	}
	if !v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", "a-different-secret", "all")))) {
		t.Fatal("rotation was equivalent")
	}
	if _, err := pin.Resolve(); err == nil || err.Error() != "invalid token" || !kindIs(err, kerr.Unauthenticated) {
		t.Fatalf("rotated: %v", err)
	}
}

func TestStdioPinRemovedDenies(t *testing.T) {
	secret := "remove-me"
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", secret))))
	pin, err := NewStdioPin(v, NewSecret([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("other", "administrator", "someone-else"))))
	if _, err := pin.Resolve(); err == nil || !kindIs(err, kerr.Unauthenticated) {
		t.Fatalf("removed: %v", err)
	}
}

func TestStdioPinDemotionSeesNewScopes(t *testing.T) {
	secret := "same-secret"
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", secret, "mail.admin", "mail.write"))))
	pin, err := NewStdioPin(v, NewSecret([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "viewer", secret, "mail.read"))))
	p, err := pin.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != "viewer" || len(p.Scopes) != 1 || p.Scopes[0] != "mail.read" {
		t.Fatalf("principal %+v", p)
	}
}

func TestStdioPinRestoredSecretRegainsAccess(t *testing.T) {
	secret := "original-secret"
	original := mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", secret, "all")))
	v := mustVer(t, original)
	pin, err := NewStdioPin(v, NewSecret([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", "temporary-secret", "all"))))
	if _, err := pin.Resolve(); err == nil {
		t.Fatal("temporary secret still resolved")
	}
	v.Swap(original)
	p, err := pin.Resolve()
	if err != nil || p.ID != "ops" || p.Role != "administrator" {
		t.Fatalf("restored %+v %v", p, err)
	}
}

func TestStdioPinEmptySwapDenies(t *testing.T) {
	secret := "goes-away"
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", secret))))
	pin, err := NewStdioPin(v, NewSecret([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue)))
	if _, err := pin.Resolve(); err == nil || err.Error() != "invalid token" {
		t.Fatalf("empty: %v", err)
	}
}

func TestStdioPinUnchangedAfterRejectedPrepare(t *testing.T) {
	secret := "stays"
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", secret))))
	pin, err := NewStdioPin(v, NewSecret([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	missing := dir + "/nope"
	st, err := Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: PerTokenFiles([]FileToken{{ID: "ops", Role: "administrator", SecretFile: missing}}, FileOpts{Line: FirstNonCommentLine, Resolve: AsGiven, Harden: true}),
		Accept: func(*Material) error { return errors.New("refused") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Err() == nil {
		t.Fatal("expected a load error")
	}
	if st.Commit(v) {
		t.Fatal("rejected stage committed")
	}
	p, err := pin.Resolve()
	if err != nil || p.ID != "ops" {
		t.Fatalf("pin %+v %v", p, err)
	}
	badAccept, err := Prepare(Config{
		Mode: ModeBearer, Duplicates: RejectDuplicateValue,
		Source: Memory([]RawToken{raw("ops", "viewer", "other-secret")}),
		Accept: func(*Material) error { return errors.New("predicate") },
	})
	if err != nil || badAccept.Err() == nil || badAccept.Commit(v) {
		t.Fatalf("accept stage err %v commit changed the verifier", err)
	}
	if _, err := pin.Resolve(); err != nil {
		t.Fatal(err)
	}
}

func TestNewStdioPinRefusesEmptySecret(t *testing.T) {
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", "secret"))))
	if _, err := NewStdioPin(v, Secret{}); err == nil || !kindIs(err, kerr.Invalid) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewStdioPin(v, NewSecret(nil)); err == nil {
		t.Fatal("nil bytes accepted")
	}
}

func TestNewStdioPinRefusesNilVerifier(t *testing.T) {
	if _, err := NewStdioPin(nil, NewSecret([]byte("secret"))); err == nil || !kindIs(err, kerr.Invalid) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewDevLoopbackStdio(nil, scope.Principal{Role: "administrator"}); err == nil {
		t.Fatal("nil verifier accepted")
	}
}

func TestDevLoopbackStdioDropsOnIdentityChange(t *testing.T) {
	m := mustLoad(t, Config{
		Mode: ModeDevLoopbackUnauth, Source: Memory(nil), Duplicates: RejectDuplicateValue,
		LocalhostIsLoopback: true,
	})
	v := mustVer(t, m)
	pin, err := NewDevLoopbackStdio(v, scope.Principal{ID: "loopback", Class: "loopback", Role: "administrator"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := pin.Resolve()
	if err != nil || p.ID != "loopback" || p.Role != "administrator" {
		t.Fatalf("start %+v %v", p, err)
	}
	same := mustLoad(t, memCfg(ModeDevLoopbackUnauth, RejectDuplicateValue))
	if v.Swap(same) {
		t.Fatal("equivalent dev-loopback counted as a change")
	}
	if _, err := pin.Resolve(); err != nil {
		t.Fatal(err)
	}
	if !v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", "now-bearer")))) {
		t.Fatal("mode change was equivalent")
	}
	if _, err := pin.Resolve(); err == nil || err.Error() != "authentication required" {
		t.Fatalf("after change: %v", err)
	}
}

func TestNewDevLoopbackStdioRefusesTokenMode(t *testing.T) {
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", "secret"))))
	_, err := NewDevLoopbackStdio(v, scope.Principal{Role: "administrator"})
	if err == nil || !kindIs(err, kerr.Invalid) {
		t.Fatalf("got %v", err)
	}
}

func TestSecretNeverRendered(t *testing.T) {
	secret := []byte("super-secret-value-0123456789abcdef")
	v := mustVer(t, mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue, raw("ops", "administrator", string(secret)))))
	s := NewSecret(secret)
	pin, err := NewStdioPin(v, s)
	if err != nil {
		t.Fatal(err)
	}
	v.Swap(mustLoad(t, memCfg(ModeBearer, RejectDuplicateValue)))
	resolveErr := fmt.Errorf("wrap: %w", func() error { _, e := pin.Resolve(); return e }())
	js, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	pinJS, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("check", "secret", s, "pin", pin)
	type box struct{ S Secret }
	outputs := []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%q", s),
		fmt.Sprintf("%v", pin),
		fmt.Sprintf("%+v", pin),
		fmt.Sprintf("%#v", pin),
		string(js),
		string(pinJS),
		buf.String(),
		resolveErr.Error(),
		fmt.Sprintf("pin %v: %v", pin, resolveErr),
		fmt.Sprintf("%#v", box{S: s}),
	}
	needle := string(secret)
	for _, out := range outputs {
		if strings.Contains(out, needle) || strings.Contains(out, "super-secret") {
			t.Fatalf("secret leaked in %q", out)
		}
	}
}
