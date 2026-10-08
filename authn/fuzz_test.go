package authn

import (
	"testing"
)

func FuzzAuthorization(f *testing.F) {
	f.Add("")
	f.Add("Bearer tok")
	f.Add("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
	f.Add("bearer")
	f.Add("Digest abc")
	f.Add("Bearer  spaced")
	m := mustLoadF(memCfg(ModeBearerAndBasic, RejectDuplicateValue, raw("ops", "administrator", "fuzz-secret")))
	v, err := NewVerifier(m)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, header string) {
		scheme, token, err := ParseAuthorization(header)
		zero(token)
		if err != nil && scheme != "" {
			t.Fatalf("scheme %q with error %v", scheme, err)
		}
		_, _ = v.Authenticate(Request{Authorization: header, RemoteAddr: "127.0.0.1:9", AllowBasic: true})
		_, _ = v.AuthenticateBearer([]byte(header))
		_, _ = AllowAll().Authenticate(Request{Authorization: header})
	})
}

func mustLoadF(cfg Config) *Material {
	m, err := Load(cfg)
	if err != nil {
		panic(err)
	}
	return m
}
