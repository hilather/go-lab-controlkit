package authn

import (
	"errors"
	"strings"
)

// Mode is the management authentication mode. The zero Mode is rejected.
type Mode int

const (
	// ModeBearer requires a bearer token.
	ModeBearer Mode = iota + 1
	// ModeDevLoopbackUnauth accepts a loopback client with no credential.
	ModeDevLoopbackUnauth
	// ModeBearerAndBasic accepts bearer, and basic when the request allows it.
	ModeBearerAndBasic
	// ModeUnknown is a mode string the facade could not recognise.
	// Load and Prepare report it. They do not invent a mode.
	ModeUnknown
)

// String returns the spec spelling of the mode.
func (m Mode) String() string {
	switch m {
	case ModeBearer:
		return "bearer"
	case ModeDevLoopbackUnauth:
		return "dev-loopback-unauth"
	case ModeBearerAndBasic:
		return "bearer_and_basic"
	case ModeUnknown:
		return "unknown"
	default:
		return ""
	}
}

// ParseMode parses a spec mode string.
// An empty string and any unrecognised string return ModeUnknown.
// ParseMode does not substitute a default mode.
func ParseMode(s string) Mode {
	switch strings.TrimSpace(s) {
	case "bearer":
		return ModeBearer
	case "dev-loopback-unauth":
		return ModeDevLoopbackUnauth
	case "bearer_and_basic":
		return ModeBearerAndBasic
	default:
		return ModeUnknown
	}
}

// DupPolicy controls duplicate token secrets. The zero value is rejected.
type DupPolicy int

const (
	// RejectDuplicateValue rejects two tokens with the same secret.
	// Lookup requires exactly one digest match.
	RejectDuplicateValue DupPolicy = iota + 1
	// FirstMatchWins keeps duplicates in stored order.
	// Lookup scans every token and returns the first match.
	FirstMatchWins
)

func (d DupPolicy) String() string {
	switch d {
	case RejectDuplicateValue:
		return "reject"
	case FirstMatchWins:
		return "first"
	default:
		return ""
	}
}

// ErrNotRegular is the hardened reader's error for a FIFO, socket, or device.
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge is the hardened reader's error for a file over 1 MiB.
var ErrTooLarge = errors.New("file is larger than 1 MiB")

// maxSecretFile is the hardened size cap: 1 MiB.
const maxSecretFile = 1 << 20
