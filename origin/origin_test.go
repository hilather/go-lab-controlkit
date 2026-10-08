package origin

import (
	"testing"

	"github.com/hilather/go-lab-controlkit/kerr"
)

func ntpPolicy() Policy {
	return Policy{Match: FoldTrimSlash, LocalhostFold: false, ListUnionsLoopback: true}
}

func dnsPolicy() Policy {
	return Policy{Match: ExactCaseSensitive, LocalhostFold: true, ListUnionsLoopback: true}
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
}

func kindIs(err error, k kerr.Kind) bool {
	got, ok := kerr.KindOf(err)
	return ok && got == k
}
