package session

import (
	"net/http"
	"time"

	"github.com/hilather/go-lab-controlkit/authn"
	"github.com/hilather/go-lab-controlkit/kerr"
)

// CookieSecure reports whether the session cookie should set Secure.
// force is the server's "always secure" flag. Otherwise the request is
// secure when it arrived over TLS.
func CookieSecure(r *http.Request, force bool) bool {
	if force {
		return true
	}
	return r != nil && r.TLS != nil
}

// SessionCookie builds the browser session cookie. The name comes from the
// caller. The value is HttpOnly, path "/", and SameSite Lax.
func SessionCookie(name, value string, secure bool, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie expires a session cookie.
func ClearCookie(name string, secure bool) *http.Cookie {
	c := SessionCookie(name, "", secure, -1)
	c.Expires = time.Unix(0, 0).UTC()
	return c
}

// NoStore sets Cache-Control: no-store.
func NoStore(w http.ResponseWriter) {
	if w == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
}

// RevocationWake registers Wake.Signal on verifier identity changes and on
// session removal. The returned function removes both registrations.
// A nil verifier or a nil store is an error.
func RevocationWake(v *authn.Verifier, s *Store) (*authn.Wake, func(), error) {
	if v == nil || s == nil {
		return nil, nil, kerr.New(kerr.Invalid, "session: revocation wake requires a verifier and a store")
	}
	w := authn.NewWake()
	unID := v.OnIdentityChange(w.Signal)
	unDel := s.OnDelete(w.Signal)
	return w, func() { unID(); unDel() }, nil
}
