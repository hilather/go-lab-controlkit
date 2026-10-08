package kittest

import "testing"

// Testing is the subset of testing.TB each suite calls.
// testing.TB cannot be implemented outside package testing: it has an
// unexported method. *testing.T and *testing.B implement Testing. A
// recording fake implements it so a seeded bug fails the suite without
// failing the self-test that runs the fake.
type Testing interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Failed() bool
	Logf(format string, args ...any)
	Name() string
}

// AsTesting adapts a testing.TB. It exists so call sites that already
// hold a testing.TB can pass it without a cast at the call boundary
// inside this module's tests.
func AsTesting(t testing.TB) Testing { return t }
