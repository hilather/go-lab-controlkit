// Package origin classifies a management-plane Origin header.
// Missing Origin is allowed. file:// is denied. Facades map the kind
// and may replace the kit sentence.
package origin

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// Match selects how an allow-list entry is compared with the Origin.
// The zero value is an error.
type Match int

const (
	// ExactCaseSensitive compares the trimmed Origin with the allow entry
	// as written. dns uses this. The allow entry is not trimmed.
	ExactCaseSensitive Match = iota + 1
	// FoldTrimSlash trims space and trailing slashes on both sides and
	// compares with EqualFold. The five template repos use this.
	FoldTrimSlash
)

// Sentinel is an allow-list token with special meaning. Maildev uses both.
type Sentinel int

const (
	// Star allows any remaining http or https Origin. The entry must be "*".
	Star Sentinel = iota + 1
	// Private allows a host that netip reports as private after Unmap
	// (RFC 1918 and RFC 4193, not CGNAT). The entry matches "private"
	// with EqualFold.
	Private
)

// Policy is one repo's origin matcher.
// LocalhostFold false means "localhost" is case-sensitive.
// ListUnionsLoopback false means a non-empty allow list replaces loopback;
// an empty allow list is still loopback http(s) only.
// A nil or empty Sentinels list means the allow list has no sentinels.
type Policy struct {
	Match              Match
	LocalhostFold      bool
	ListUnionsLoopback bool
	Sentinels          []Sentinel
}

// Check reports whether origin is allowed. A missing Origin is allowed.
// A present Origin that fails the policy returns OriginNotAllowed with
// the stable sentence "origin is not allowed". A zero Match is Invalid.
func Check(origin string, allow []string, p Policy) error {
	if err := validate(p); err != nil {
		return err
	}
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return nil
	}
	host, ok := httpHost(origin)
	if !ok {
		return denied()
	}
	if loopbackAllowed(p, allow) && isLoopback(host, p.LocalhostFold) {
		return nil
	}
	for _, entry := range allow {
		if sentinelHit(p, entry, host) || listHit(p.Match, origin, entry) {
			return nil
		}
	}
	return denied()
}

func validate(p Policy) error {
	if p.Match != ExactCaseSensitive && p.Match != FoldTrimSlash {
		return kerr.New(kerr.Invalid, "origin: match policy is required")
	}
	for _, s := range p.Sentinels {
		if s != Star && s != Private {
			return kerr.New(kerr.Invalid, "origin: unknown sentinel")
		}
	}
	return nil
}

func denied() error {
	return kerr.New(kerr.OriginNotAllowed, "origin is not allowed")
}

func loopbackAllowed(p Policy, allow []string) bool {
	if p.ListUnionsLoopback {
		return true
	}
	return len(allow) == 0
}

func httpHost(origin string) (string, bool) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	return u.Hostname(), true
}

func isLoopback(host string, fold bool) bool {
	host = strings.TrimSpace(host)
	if fold {
		if strings.EqualFold(host, "localhost") {
			return true
		}
	} else if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

func isPrivate(host string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	return addr.Unmap().IsPrivate()
}

func hasSentinel(p Policy, want Sentinel) bool {
	for _, s := range p.Sentinels {
		if s == want {
			return true
		}
	}
	return false
}

func sentinelHit(p Policy, entry, host string) bool {
	raw := strings.TrimSpace(entry)
	if hasSentinel(p, Star) && raw == "*" {
		return true
	}
	if hasSentinel(p, Private) && strings.EqualFold(raw, "private") && isPrivate(host) {
		return true
	}
	return false
}

func listHit(m Match, origin, entry string) bool {
	if m == ExactCaseSensitive {
		return origin == entry
	}
	got := strings.TrimRight(strings.TrimSpace(origin), "/")
	want := strings.TrimRight(strings.TrimSpace(entry), "/")
	return strings.EqualFold(got, want)
}
