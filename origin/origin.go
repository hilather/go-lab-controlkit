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
	// as written. dns uses this together with HostParse DNSParse.
	// The allow entry is not trimmed.
	ExactCaseSensitive Match = iota + 1
	// FoldTrimSlash trims space and trailing slashes on both sides and
	// compares with EqualFold. The five template repos use this, with the
	// zero HostParse (url.Parse).
	FoldTrimSlash
)

// HostParse selects the host taken from an Origin for the loopback check.
// The zero value, URLParse, is url.Parse. dns sets DNSParse.
type HostParse int

const (
	// URLParse is the zero value. net/url strips userinfo and rejects a
	// non-numeric port. The five template repos use this.
	URLParse HostParse = iota
	// DNSParse is dns parseHTTPOrigin. Userinfo stays in the host, a
	// fragment is not a delimiter, a colon splits the host even when the
	// port is not numeric, and brackets are trimmed the way dns
	// isLoopbackHost trims them. Spaces in the host are not trimmed.
	DNSParse
)

// Sentinel is an allow-list token with special meaning. Maildev uses both.
type Sentinel int

const (
	// Star allows any remaining http or https Origin. The entry must be "*".
	Star Sentinel = iota + 1
	// Private allows a host that netip reports as private after Unmap
	// (RFC 1918 and RFC 4193, not CGNAT). A zoned address is not private,
	// matching maildev's net.ParseIP. The entry matches "private"
	// with EqualFold.
	Private
)

// Policy is one repo's origin matcher.
// HostParse zero means url.Parse, which is the five. DNSParse is dns's parser.
// LocalhostFold false means "localhost" is case-sensitive.
// ListUnionsLoopback false means a non-empty allow list replaces loopback;
// an empty allow list is still loopback http(s) only.
// ZonedLoopback false, the zero value, means an address with an IPv6 zone
// is never loopback. That matches net.ParseIP, which ntp, netconf, snmp,
// maildev and syslog use. True means a zoned IPv6 literal can be loopback,
// which is netip.ParseAddr. dns sets true.
// A nil or empty Sentinels list means the allow list has no sentinels.
// The private sentinel never treats a zoned address as private. maildev
// classifies with net.ParseIP, and no repo does otherwise.
type Policy struct {
	Match              Match
	HostParse          HostParse
	LocalhostFold      bool
	ListUnionsLoopback bool
	ZonedLoopback      bool
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
	host, ok := httpHost(origin, p.HostParse)
	if !ok {
		return denied()
	}
	// The five trim the host url.Parse returns. dns isLoopbackHost does not.
	if p.HostParse != DNSParse {
		host = strings.TrimSpace(host)
	}
	if loopbackAllowed(p, allow) && isLoopback(host, p.LocalhostFold, p.ZonedLoopback) {
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
	if p.HostParse != URLParse && p.HostParse != DNSParse {
		return kerr.New(kerr.Invalid, "origin: host parser is invalid")
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

func httpHost(origin string, how HostParse) (string, bool) {
	if how == DNSParse {
		return dnsHTTPHost(origin)
	}
	return urlHTTPHost(origin)
}

func urlHTTPHost(origin string) (string, bool) {
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

// dnsHTTPHost is dns parseHTTPOrigin plus the bracket trim in isLoopbackHost.
func dnsHTTPHost(origin string) (string, bool) {
	scheme, rest, ok := strings.Cut(origin, "://")
	if !ok {
		return "", false
	}
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := rest
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		host = rest[:i]
	}
	if host == "" {
		return "", false
	}
	hostname := host
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			hostname = host[1:end]
		}
	} else if name, ok := splitDNSHostPort(host); ok {
		hostname = name
	}
	return strings.Trim(hostname, "[]"), true
}

func splitDNSHostPort(hostport string) (string, bool) {
	if !strings.Contains(hostport, ":") {
		return "", false
	}
	i := strings.LastIndexByte(hostport, ':')
	return hostport[:i], true
}

// allowZone false rejects every IPv6 zone, matching net.ParseIP.
// true keeps netip.ParseAddr, whose IsLoopback ignores the zone.
func isLoopback(host string, fold, allowZone bool) bool {
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
	if addr.Zone() != "" && !allowZone {
		return false
	}
	return addr.Unmap().IsLoopback()
}

// A zoned address is not private. maildev uses net.ParseIP, which
// rejects zones. No repo classifies a zoned address as private.
func isPrivate(host string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil || addr.Zone() != "" {
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
