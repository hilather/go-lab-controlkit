// Package authn loads management tokens, verifies requests, pins stdio
// actors, and stages secret-file reloads.
//
// A secret renders as [redacted] in fmt, JSON, text, and slog. Identity-change
// hooks run synchronously on the caller goroutine after the verifier lock is
// released. A hook must not call into the application: Swap is often invoked
// while the application still holds its own lock.
package authn

import (
	"fmt"
	"log/slog"
)

// Secret holds token or password bytes. String, GoString, Format, JSON, text,
// and slog all render "[redacted]". The bytes are never part of an error string.
type Secret struct {
	b []byte
}

// NewSecret copies b. The caller may zero its own buffer afterwards.
func NewSecret(b []byte) Secret {
	if len(b) == 0 {
		return Secret{}
	}
	return Secret{b: append([]byte(nil), b...)}
}

// Len is the number of secret bytes.
func (s Secret) Len() int { return len(s.b) }

// Bytes returns a copy of the secret. The caller should zero the copy.
func (s Secret) Bytes() []byte {
	return append([]byte(nil), s.b...)
}

// Zero wipes the secret.
func (s *Secret) Zero() {
	if s == nil {
		return
	}
	zero(s.b)
	s.b = nil
}

func (s Secret) String() string { return "[redacted]" }

func (s Secret) GoString() string { return "[redacted]" }

// Format renders every verb as [redacted].
func (s Secret) Format(f fmt.State, _ rune) { fmt.Fprint(f, "[redacted]") }

// MarshalJSON renders a redacted JSON string.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// MarshalText renders redacted text.
func (s Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// LogValue renders a redacted slog value.
func (s Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

func (s Secret) bytes() []byte { return s.b }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
