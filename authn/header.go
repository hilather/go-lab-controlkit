package authn

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Challenge returns the WWW-Authenticate values for realm.
// basic adds the Basic challenge after Bearer. maildev passes true for REST
// and false for MCP. The other repos pass false. syslog's facade returns the
// single Bearer element as one string.
func Challenge(realm string, basic bool) []string {
	bearer := `Bearer realm="` + realm + `"`
	if !basic {
		return []string{bearer}
	}
	return []string{bearer, `Basic realm="` + realm + `"`}
}

// ParseAuthorization splits an Authorization header into a scheme and the
// remainder. An empty header returns an empty scheme, a nil token, and no
// error. A header with no scheme separator is an error. The token is a copy
// of the trimmed remainder; the caller zeroes it. Scheme comparison is
// case-insensitive and is left to the caller.
func ParseAuthorization(header string) (scheme string, token []byte, err error) {
	h := strings.TrimSpace(header)
	if h == "" {
		return "", nil, nil
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok {
		return "", nil, errMalformedAuth
	}
	rest = strings.TrimSpace(rest)
	return scheme, append([]byte(nil), rest...), nil
}

var errMalformedAuth = errors.New("authentication required")

func parseBasic(payload string) (user, pass string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		pad := (4 - len(payload)%4) % 4
		raw, err = base64.StdEncoding.DecodeString(payload + strings.Repeat("=", pad))
		if err != nil {
			return "", "", false
		}
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}
