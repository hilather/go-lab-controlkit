package kerr

import (
	"errors"
	"fmt"
	"testing"
)

func TestKindOf(t *testing.T) {
	e := WithViolations(Invalid, "nope", []Violation{{Path: "spec.auth.mode", Code: "invalid_value", Message: "bad"}})
	k, ok := KindOf(e)
	if !ok || k != Invalid {
		t.Fatalf("kind %v %v", k, ok)
	}
	k, ok = KindOf(fmt.Errorf("wrap: %w", e))
	if !ok || k != Invalid {
		t.Fatalf("wrapped kind %v %v", k, ok)
	}
	if _, ok = KindOf(errors.New("plain")); ok {
		t.Fatal("plain error had a kind")
	}
	if _, ok = KindOf(New(0, "unset")); ok {
		t.Fatal("unset kind reported")
	}
	if e.Error() != "nope" || e.Violations[0].Path != "spec.auth.mode" {
		t.Fatalf("error text or violation: %+v", e)
	}
	if Unauthenticated.String() != "unauthenticated" || NotFound.String() != "not_found" || Kind(99).String() != "unset" {
		t.Fatal(Unauthenticated.String(), NotFound.String())
	}
}
