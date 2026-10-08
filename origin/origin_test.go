package origin

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
)

func ntpPolicy() Policy {
	return Policy{Match: FoldTrimSlash, LocalhostFold: false, ListUnionsLoopback: true}
}

func dnsPolicy() Policy {
	return Policy{
		Match:              ExactCaseSensitive,
		HostParse:          DNSParse,
		LocalhostFold:      true,
		ListUnionsLoopback: true,
		ZonedLoopback:      true,
	}
}

func syslogPolicy() Policy {
	return Policy{Match: FoldTrimSlash, LocalhostFold: true, ListUnionsLoopback: false}
}

func maildevPolicy() Policy {
	return Policy{
		Match:              FoldTrimSlash,
		LocalhostFold:      false,
		ListUnionsLoopback: true,
		Sentinels:          []Sentinel{Star, Private},
	}
}

func TestOriginRepoProbes(t *testing.T) {
	policies := []struct {
		name string
		p    Policy
	}{
		{"ntp", ntpPolicy()},
		{"dns", dnsPolicy()},
		{"syslog", syslogPolicy()},
		{"maildev", maildevPolicy()},
	}
	for _, pol := range policies {
		if err := Check("", nil, pol.p); err != nil {
			t.Errorf("%s missing origin: %v", pol.name, err)
		}
		if err := Check("   ", nil, pol.p); err != nil {
			t.Errorf("%s blank origin: %v", pol.name, err)
		}
		err := Check("file://localhost/tmp", []string{"*"}, pol.p)
		if !kindIs(err, kerr.OriginNotAllowed) || err.Error() != "origin is not allowed" {
			t.Errorf("%s file://: %v", pol.name, err)
		}
	}

	// https://Lab.Example/ — fold-trim hits, exact needs the slash and the case.
	if err := Check("https://Lab.Example/", []string{"https://lab.example"}, ntpPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("https://Lab.Example/", nil, ntpPolicy()); !kindIs(err, kerr.OriginNotAllowed) {
		t.Fatalf("ntp bare lab: %v", err)
	}
	if err := Check("https://Lab.Example/", []string{"https://Lab.Example/"}, dnsPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("https://Lab.Example/", []string{"https://lab.example"}, dnsPolicy()); err == nil {
		t.Fatal("dns folded the allow list")
	}
	if err := Check("https://Lab.Example/", []string{"https://Lab.Example"}, dnsPolicy()); err == nil {
		t.Fatal("dns trimmed a slash")
	}
	if err := Check("https://Lab.Example/", []string{"https://lab.example"}, syslogPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("https://Lab.Example/", nil, syslogPolicy()); err == nil {
		t.Fatal("syslog empty list allowed a foreign origin")
	}

	// http://LocalHost — fold is loopback; case-sensitive is not.
	if err := Check("http://LocalHost", nil, ntpPolicy()); err == nil {
		t.Fatal("ntp treated LocalHost as loopback")
	}
	if err := Check("http://LocalHost", []string{"http://localhost"}, ntpPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("http://LocalHost", nil, dnsPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("http://LocalHost", nil, syslogPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("http://LocalHost", []string{"https://other.example"}, syslogPolicy()); err == nil {
		t.Fatal("syslog unioned loopback into a non-empty list")
	}
	if err := Check("http://localhost", []string{"https://other.example"}, syslogPolicy()); err == nil {
		t.Fatal("syslog unioned exact localhost")
	}
	if err := Check("http://127.0.0.1", nil, syslogPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("http://LocalHost", nil, maildevPolicy()); err == nil {
		t.Fatal("maildev treated LocalHost as loopback")
	}
	if err := Check("http://LocalHost", []string{"*"}, maildevPolicy()); err != nil {
		t.Fatal(err)
	}

	mapped := "http://[::ffff:127.0.0.1]"
	for _, pol := range []struct {
		name  string
		p     Policy
		ok    bool
		allow []string
	}{
		{"ntp", ntpPolicy(), true, nil},
		{"dns", dnsPolicy(), true, nil},
		{"syslog-empty", syslogPolicy(), true, nil},
		{"syslog-list", syslogPolicy(), false, []string{"https://other.example"}},
		{"maildev", maildevPolicy(), true, nil},
	} {
		err := Check(mapped, pol.allow, pol.p)
		if pol.ok && err != nil {
			t.Errorf("%s mapped loopback: %v", pol.name, err)
		}
		if !pol.ok && err == nil {
			t.Errorf("%s mapped loopback was allowed", pol.name)
		}
	}

	priv := "http://[::ffff:192.168.1.9]:1080"
	if err := Check(priv, []string{"private"}, maildevPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check(priv, []string{"Private"}, maildevPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("http://192.168.1.9", []string{"private"}, maildevPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("http://8.8.8.8", []string{"private"}, maildevPolicy()); err == nil {
		t.Fatal("public host matched private")
	}
	if err := Check("http://100.64.0.1", []string{"private"}, maildevPolicy()); err == nil {
		t.Fatal("cgnat matched private")
	}
	if err := Check(priv, []string{"private"}, ntpPolicy()); err == nil {
		t.Fatal("ntp honored the private sentinel")
	}
	if err := Check(priv, []string{"private"}, dnsPolicy()); err == nil {
		t.Fatal("dns honored the private sentinel")
	}
	if err := Check("http://evil.example", []string{"*"}, maildevPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("http://evil.example", []string{"*"}, ntpPolicy()); err == nil {
		t.Fatal("ntp honored star")
	}
	if err := Check("file://evil", []string{"*"}, maildevPolicy()); err == nil {
		t.Fatal("star allowed file://")
	}
	if err := Check("http://localhost", nil, ntpPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := Check("https://Lab.Example", []string{"https://lab.example/"}, ntpPolicy()); err != nil {
		t.Fatal(err)
	}
}

func TestOriginMatchRequired(t *testing.T) {
	err := Check("http://localhost", nil, Policy{})
	if !kindIs(err, kerr.Invalid) {
		t.Fatalf("zero policy: %v", err)
	}
	p := ntpPolicy()
	p.Sentinels = []Sentinel{Sentinel(9)}
	if err := Check("http://localhost", nil, p); !kindIs(err, kerr.Invalid) {
		t.Fatalf("bad sentinel: %v", err)
	}
	p = ntpPolicy()
	p.HostParse = HostParse(9)
	if err := Check("http://localhost", nil, p); !kindIs(err, kerr.Invalid) {
		t.Fatalf("bad host parser: %v", err)
	}
}

// TestOriginParsersMatchGolden compares Check with the golden parsers.
// dns parseHTTPOrigin keeps userinfo and splits on any colon. The five
// use url.Parse, which strips userinfo and rejects a non-numeric port.
func TestOriginParsersMatchGolden(t *testing.T) {
	origins := []string{
		"",
		"http://127.0.0.1",
		"http://user@127.0.0.1",
		"http://user:pass@127.0.0.1:8080",
		"https://user@localhost",
		"http://@127.0.0.1",
		"http://user@[::1]",
		"http://user@[::1]:8080",
		"http://user:pass@[::1]",
		"http://user@127.0.0.1/",
		"http://127.0.0.1:abc",
		"http://localhost:notaport",
		"http://127.0.0.1#frag",
		"http://127.0.0.1#",
		"http://[::1",
		"http://[::1]junk",
		"http://[127.0.0.1]",
		"http://127.0.0.1:80:80",
		"http://example.com:abc",
		"http://evil.example",
		"http://[::ffff:127.0.0.1]",
		"file://localhost/tmp",
		"http://127.0.0.1?x=1",
		"http:// 127.0.0.1",
		"http://[ ::1]",
		"http://[ localhost]",
		"http://[127.0.0.1 ]",
	}
	allows := [][]string{
		nil,
		{"http://user@127.0.0.1"},
		{"http://127.0.0.1:80:80"},
		{"http://evil.example"},
		{"http://example.com:abc"},
	}
	policies := []struct {
		name string
		p    Policy
		want func(string, []string) bool
	}{
		{"dns", dnsPolicy(), dnsGoldenAllowed},
		{"ntp", ntpPolicy(), func(origin string, allow []string) bool {
			return fiveGoldenAllowed(origin, allow, true, false)
		}},
		{"syslog", syslogPolicy(), func(origin string, allow []string) bool {
			return fiveGoldenAllowed(origin, allow, false, true)
		}},
	}
	for _, pol := range policies {
		for _, origin := range origins {
			for _, allow := range allows {
				err := Check(origin, allow, pol.p)
				got := err == nil
				want := pol.want(origin, allow)
				if got != want {
					t.Errorf("%s origin %q allow %q got %v want %v err %v", pol.name, origin, allow, got, want, err)
				}
			}
		}
	}
}

func dnsGoldenAllowed(origin string, extra []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return true
	}
	host, ok := dnsGoldenHost(origin)
	if !ok {
		return false
	}
	if dnsGoldenLoopback(host) {
		return true
	}
	for _, a := range extra {
		if origin == a {
			return true
		}
	}
	return false
}

func dnsGoldenHost(origin string) (string, bool) {
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
	} else if strings.Contains(host, ":") {
		i := strings.LastIndexByte(host, ':')
		hostname = host[:i]
	}
	return hostname, true
}

func dnsGoldenLoopback(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func fiveGoldenAllowed(origin string, allow []string, unionLoopback, foldLocalhost bool) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	loopOK := unionLoopback || len(allow) == 0
	if loopOK && fiveGoldenLoopback(u.Hostname(), foldLocalhost) {
		return true
	}
	for _, allowed := range allow {
		got := strings.TrimRight(strings.TrimSpace(origin), "/")
		want := strings.TrimRight(strings.TrimSpace(allowed), "/")
		if strings.EqualFold(got, want) {
			return true
		}
	}
	return false
}

func fiveGoldenLoopback(host string, fold bool) bool {
	h := strings.TrimSpace(host)
	if fold {
		if strings.EqualFold(h, "localhost") {
			return true
		}
	} else if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// maildevGoldenAllowed is maildev CheckOrigin
// (src-v5/maildev/internal/auth/origin.go). Loopback is unioned and
// "localhost" is case-sensitive, as in ntp. "*" and "private" are
// sentinels. Private uses net.ParseIP, so a zone is never private.
func maildevGoldenAllowed(origin string, allow []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := u.Hostname()
	if fiveGoldenLoopback(host, false) {
		return true
	}
	for _, allowed := range allow {
		raw := strings.TrimSpace(allowed)
		switch {
		case raw == "*":
			return true
		case strings.EqualFold(raw, "private") && maildevGoldenPrivate(host):
			return true
		default:
			got := strings.TrimRight(strings.TrimSpace(origin), "/")
			want := strings.TrimRight(strings.TrimSpace(allowed), "/")
			if strings.EqualFold(got, want) {
				return true
			}
		}
	}
	return false
}

func maildevGoldenPrivate(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsPrivate()
}

// urlZonedGoldenAllowed is ntp CheckOrigin with dns's netip loopback
// classifier. That is URLParse with ZonedLoopback set. No repo selects
// this pair. dns sets the flag together with DNSParse.
func urlZonedGoldenAllowed(origin string, allow []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if ntpNetipLoopback(u.Hostname()) {
		return true
	}
	for _, allowed := range allow {
		got := strings.TrimRight(strings.TrimSpace(origin), "/")
		want := strings.TrimRight(strings.TrimSpace(allowed), "/")
		if strings.EqualFold(got, want) {
			return true
		}
	}
	return false
}

// ntp keeps "localhost" case-sensitive. dnsGoldenLoopback folds it and
// accepts a zone, which is the ZonedLoopback classifier.
func ntpNetipLoopback(host string) bool {
	h := strings.TrimSpace(host)
	if h == "localhost" {
		return true
	}
	if strings.EqualFold(h, "localhost") {
		return false
	}
	return dnsGoldenLoopback(h)
}

// dnsUnzonedGoldenAllowed is dns CheckOrigin with net.ParseIP's loopback
// rule. That is DNSParse with ZonedLoopback left false.
func dnsUnzonedGoldenAllowed(origin string, extra []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return true
	}
	host, ok := dnsGoldenHost(origin)
	if !ok {
		return false
	}
	if dnsNetIPLoopback(host) {
		return true
	}
	for _, a := range extra {
		if origin == a {
			return true
		}
	}
	return false
}

// dnsNetIPLoopback is dns isLoopbackHost with net.ParseIP. The host is
// not space-trimmed. A zone is never loopback. localhost is folded.
func dnsNetIPLoopback(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func TestOriginZonedAddresses(t *testing.T) {
	if ntpPolicy().ZonedLoopback || syslogPolicy().ZonedLoopback || maildevPolicy().ZonedLoopback {
		t.Fatal("ZonedLoopback zero is the five")
	}
	if !dnsPolicy().ZonedLoopback {
		t.Fatal("dns sets ZonedLoopback")
	}

	origins := []string{
		"http://[::1%25eth0]:8080",
		"http://[::1%25eth0]",
		"https://[::1%25lo]",
		"http://[::1%eth0]:8080",
		"http://[::1%25]",
		"http://[fe80::1%25eth0]:8080",
		"http://[fe80::1%25eth0]",
		"http://[fe80::1%251]",
		"http://[::ffff:127.0.0.1%25eth0]",
		"http://[::ffff:127.0.0.1%25eth0]:8080",
		"https://[::ffff:127.0.0.1%25lo]",
		"http://[::ffff:7f00:1%25eth0]",
		"http://[::1]:8080",
		"http://[::1]",
		"http://[fe80::1]:8080",
		"http://[::ffff:127.0.0.1]",
		"http://[::ffff:127.0.0.1]:8080",
	}
	allows := [][]string{
		nil,
		{"https://other.example"},
		{"http://[::1%25eth0]:8080"},
	}
	urlOn := ntpPolicy()
	urlOn.ZonedLoopback = true
	dnsOff := dnsPolicy()
	dnsOff.ZonedLoopback = false
	policies := []struct {
		name string
		p    Policy
		want func(string, []string) bool
	}{
		{"ntp", ntpPolicy(), func(origin string, allow []string) bool {
			return fiveGoldenAllowed(origin, allow, true, false)
		}},
		{"syslog", syslogPolicy(), func(origin string, allow []string) bool {
			return fiveGoldenAllowed(origin, allow, false, true)
		}},
		{"maildev", maildevPolicy(), maildevGoldenAllowed},
		{"dns", dnsPolicy(), dnsGoldenAllowed},
		{"url-zoned", urlOn, urlZonedGoldenAllowed},
		{"dns-unzoned", dnsOff, dnsUnzonedGoldenAllowed},
	}
	for _, pol := range policies {
		for _, origin := range origins {
			for _, allow := range allows {
				err := Check(origin, allow, pol.p)
				got := err == nil
				want := pol.want(origin, allow)
				if got != want {
					t.Errorf("%s origin %q allow %#v got %v want %v err %v", pol.name, origin, allow, got, want, err)
				}
			}
		}
	}
}

func TestOriginZonedPrivate(t *testing.T) {
	origins := []string{
		"http://[fd12:3456::1%25eth0]:1080",
		"http://[fc00::1%25eth0]",
		"http://[::ffff:192.168.1.9%25eth0]:1080",
		"http://[::ffff:10.1.2.3%25eth0]",
		"http://[fe80::1%25eth0]:8080",
		"http://[::1%25eth0]:8080",
		"http://[::ffff:127.0.0.1%25eth0]",
		"http://[fd12:3456::1]:1080",
		"http://[fc00::1]",
		"http://[::ffff:192.168.1.9]:1080",
		"http://192.168.1.9",
		"http://10.1.2.3:1080",
		"http://[fe80::1]:8080",
		"http://8.8.8.8",
		"http://100.64.0.1",
		"http://169.254.1.1",
	}
	allows := [][]string{{"private"}, {"Private"}}
	for _, origin := range origins {
		for _, allow := range allows {
			err := Check(origin, allow, maildevPolicy())
			got := err == nil
			want := maildevGoldenAllowed(origin, allow)
			if got != want {
				t.Errorf("maildev origin %q allow %#v got %v want %v err %v", origin, allow, got, want, err)
			}
		}
	}

	// ZonedLoopback does not make a zoned address private. These hosts
	// are not loopback under either classifier, so the flag cannot
	// admit them. maildev's net.ParseIP denies the zoned ones.
	on := maildevPolicy()
	on.ZonedLoopback = true
	nonLoop := []string{
		"http://[fd12:3456::1%25eth0]:1080",
		"http://[fc00::1%25eth0]",
		"http://[::ffff:192.168.1.9%25eth0]:1080",
		"http://[::ffff:10.1.2.3%25eth0]",
		"http://[fe80::1%25eth0]:8080",
		"http://[fd12:3456::1]:1080",
		"http://[::ffff:192.168.1.9]:1080",
		"http://[fe80::1]:8080",
	}
	for _, origin := range nonLoop {
		for _, allow := range allows {
			err := Check(origin, allow, on)
			got := err == nil
			want := maildevGoldenAllowed(origin, allow)
			if got != want {
				t.Errorf("zoned flag origin %q allow %#v got %v want %v err %v", origin, allow, got, want, err)
			}
		}
	}
}

func kindIs(err error, k kerr.Kind) bool {
	got, ok := kerr.KindOf(err)
	return ok && got == k
}
