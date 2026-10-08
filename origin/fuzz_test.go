package origin

import "testing"

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
	f.Fuzz(func(t *testing.T, origin string) {
		policies := []Policy{ntpPolicy(), dnsPolicy(), syslogPolicy(), maildevPolicy()}
		allows := [][]string{nil, {"*"}, {"private"}, {"https://lab.example"}, {"https://Lab.Example/"}}
		for _, p := range policies {
			for _, allow := range allows {
				_ = Check(origin, allow, p)
			}
		}
	})
}
