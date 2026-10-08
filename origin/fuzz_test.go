package origin

import "testing"

// FuzzOrigin asserts Check against copies of today's CheckOrigin.
// ntp covers netconf and snmp: union loopback, case-sensitive localhost.
// syslog folds localhost and drops loopback when the list is non-empty.
// maildev adds the "*" and "private" sentinels (net.ParseIP).
// dns is exact, folds localhost, and classifies with netip, so a zoned
// IPv6 literal can be loopback. The copies are fiveGoldenAllowed,
// maildevGoldenAllowed and dnsGoldenAllowed.
func FuzzOrigin(f *testing.F) {
	f.Add("")
	f.Add("https://Lab.Example/")
	f.Add("http://LocalHost")
	f.Add("http://[::ffff:127.0.0.1]")
	f.Add("file://")
	f.Add("http://[::ffff:192.168.1.9]:1080")
	f.Add("http://localhost")
	f.Add("http://user@127.0.0.1")
	f.Add("http://127.0.0.1:abc")
	f.Add("http://127.0.0.1#frag")
	f.Add("http://[::1%25eth0]:8080")
	f.Add("http://[fe80::1%25eth0]:8080")
	f.Add("http://[::ffff:127.0.0.1%25eth0]")
	f.Add("http://[::ffff:127.0.0.1%25eth0]:8080")
	f.Add("http://[fd12:3456::1%25eth0]:1080")
	f.Add("http://[::ffff:192.168.1.9%25eth0]:1080")
	f.Add("http://[::1%eth0]:8080")
	f.Fuzz(func(t *testing.T, origin string) {
		allows := [][]string{nil, {"*"}, {"private"}, {"https://lab.example"}, {"https://Lab.Example/"}}
		specs := []struct {
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
		}
		for _, spec := range specs {
			for _, allow := range allows {
				err := Check(origin, allow, spec.p)
				got := err == nil
				want := spec.want(origin, allow)
				if got != want {
					t.Fatalf("%s origin %q allow %#v kit %v golden %v err %v", spec.name, origin, allow, got, want, err)
				}
			}
		}
	})
}
