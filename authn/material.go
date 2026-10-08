package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-controlkit/kerr"
	"github.com/hilather/go-lab-controlkit/scope"
)

// DNSDefaults are dns's identity defaults, applied when a token is loaded.
// Nil on Config means the defaults are not applied.
type DNSDefaults struct {
	// EmptyID replaces an empty token id. dns uses "bearer".
	EmptyID string
	// EmptyRoleAndScopes is the role used when both the role and the scope
	// list are empty. dns uses "administrator".
	EmptyRoleAndScopes string
}

// Config is the input to Load and Prepare.
// MinSecretBytes 0 means token secrets have no length floor. It is never
// applied to a Basic password.
// WarnBelowBytes 0 means Load records no short-secret warnings.
// Accept nil means no listen predicate.
// PathPrefix empty means violation fields are not prefixed.
// RejectEmptyRole false allows an empty role to fall through to EmptyRole
// or DNSDefaults.
// LocalhostIsLoopback false classifies loopback with netip only.
// ManagementBound false means management is not bound. Both values are
// meaningful and both are part of SpecHash.
// Basic nil means Basic is off.
// DNSDefaults nil means empty ids and roles are not rewritten.
type Config struct {
	Mode Mode
	// ModeText is the spec mode string quoted by the unknown-mode load error
	// (`must be bearer, got %q`). Empty quotes Mode.String(). It is not part
	// of SpecHash: a successful load has already parsed Mode.
	ModeText            string
	Source              TokenSource
	Duplicates          DupPolicy
	MinSecretBytes      int
	WarnBelowBytes      int
	Accept              func(*Material) error
	PathPrefix          string
	Roles               scope.Table
	RejectEmptyRole     bool
	LocalhostIsLoopback bool
	ManagementBound     bool
	Basic               *BasicSpec
	DNSDefaults         *DNSDefaults
}

// LoadError is a token-load failure. Facades render Msg, Code, and Field into
// the repo's wire sentence. The kit sentence in Msg matches the syslog wording
// for per-token files so a facade can use Error() directly.
// TokenIndex is the token slot, starting at 0. The zero value is slot 0.
// Errors that are not a token slot set it to -1. withPrefix fills
// tokens[i].secretFile only when the index was set (>= 0) and Field is empty.
type LoadError struct {
	Kind       kerr.Kind
	Code       string
	TokenIndex int
	TokenID    string
	File       string
	Field      string
	Err        error
	Msg        string
}

func (e *LoadError) Error() string {
	if e == nil {
		return ""
	}
	return e.Msg
}

func (e *LoadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Material is a digested token set. A nil *Material is the empty identity:
// OrderedDigest returns hex(SHA-256("")) and ignores prefix.
type Material struct {
	mode      Mode
	tokens    []storedToken
	basic     *storedBasic
	warnings  []string
	localhost bool
	dup       DupPolicy
	loop      scope.Principal
}

type storedToken struct {
	id     string
	role   string
	scopes []string
	groups []string
	digest [32]byte
}

type storedBasic struct {
	username string
	digest   [32]byte
	index    int
}

// Load reads the source once, digests each secret, and zeroes the raw bytes.
// Accept, when set, runs on the compiled material. A constructor error (a zero
// mode, a nil source, a zero duplicate policy, a negative floor, or a zero
// file-option mode) is returned directly. A file or token failure is a *LoadError.
func Load(cfg Config) (*Material, error) {
	if err := constructorError(cfg); err != nil {
		return nil, err
	}
	m, _, err := readAndCompile(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Accept != nil {
		if err := cfg.Accept(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func constructorError(cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	return validateSources(cfg)
}

func validateSources(cfg Config) error {
	switch s := cfg.Source.(type) {
	case *fileSource:
		if err := validateOpts(s.opts); err != nil {
			return err
		}
	case *dnsSource:
		if s.ref != "" {
			if err := validateOpts(s.opts); err != nil {
				return err
			}
		}
	}
	if basicFileActive(cfg) {
		if err := validateOpts(cfg.Basic.Opts); err != nil {
			return err
		}
	}
	return nil
}

// readAndCompile reads every secret file, then compiles. On a read failure the
// returned material is nil and files still holds every candidate that was opened.
func readAndCompile(cfg Config) (*Material, []FileResult, error) {
	tokens, files, err := cfg.Source.Read()
	cfg = detachBasic(cfg)
	if basicFileActive(cfg) {
		bfiles, pw, berr := readPassword(cfg.Basic, cfg.PathPrefix)
		files = append(files, bfiles...)
		if berr != nil && err == nil {
			err = berr
		}
		if berr == nil {
			cfg.Basic.Password.Zero()
			cfg.Basic.Password = pw
		}
	}
	if err != nil {
		wipeTokens(tokens)
		if cfg.Basic != nil {
			cfg.Basic.Password.Zero()
		}
		return nil, files, withPrefix(cfg, err)
	}
	m, cerr := compile(cfg, tokens)
	if cerr != nil {
		return nil, files, cerr
	}
	return m, files, nil
}

func detachBasic(cfg Config) Config {
	if cfg.Basic == nil {
		return cfg
	}
	cp := *cfg.Basic
	cp.Password = NewSecret(cp.Password.bytes())
	cfg.Basic = &cp
	return cfg
}

func wipeTokens(tokens []RawToken) {
	for i := range tokens {
		tokens[i].Secret.Zero()
	}
}

func validateConfig(cfg Config) error {
	if cfg.Mode == 0 {
		return kerr.New(kerr.Invalid, "authn: mode is required")
	}
	if cfg.Source == nil {
		return kerr.New(kerr.Invalid, "authn: token source is required")
	}
	if cfg.Duplicates != RejectDuplicateValue && cfg.Duplicates != FirstMatchWins {
		return kerr.New(kerr.Invalid, "authn: duplicate policy is required")
	}
	if cfg.MinSecretBytes < 0 || cfg.WarnBelowBytes < 0 {
		return kerr.New(kerr.Invalid, "authn: secret length floors must not be negative")
	}
	return nil
}

func compile(cfg Config, tokens []RawToken) (*Material, error) {
	defer func() {
		wipeTokens(tokens)
		if cfg.Basic != nil {
			cfg.Basic.Password.Zero()
		}
	}()
	if cfg.Mode != ModeBearer && cfg.Mode != ModeDevLoopbackUnauth && cfg.Mode != ModeBearerAndBasic {
		got := cfg.ModeText
		if got == "" {
			got = cfg.Mode.String()
		}
		return nil, &LoadError{
			Kind:       kerr.Invalid,
			Code:       "invalid_value",
			TokenIndex: -1,
			Field:      joinField(cfg.PathPrefix, "mode"),
			Msg:        fmt.Sprintf("%s must be bearer, got %q", joinField(cfg.PathPrefix, "mode"), got),
		}
	}
	seenDigest := map[[32]byte]string{}
	seenID := map[string]int{}
	stored := make([]storedToken, 0, len(tokens))
	var warnings []string
	for i, tok := range tokens {
		id := strings.TrimSpace(tok.ID)
		role := strings.TrimSpace(tok.Role)
		scopes := append([]string(nil), tok.Scopes...)
		if id == "" && cfg.DNSDefaults != nil {
			id = cfg.DNSDefaults.EmptyID
		}
		if id == "" {
			tok.Secret.Zero()
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "empty_id", TokenIndex: i, File: tok.Ref,
				Field: tokenField(cfg.PathPrefix, i, "id"), Msg: "token id is required",
			}
		}
		if _, ok := seenID[id]; ok && cfg.Duplicates != FirstMatchWins {
			tok.Secret.Zero()
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "duplicate_id", TokenIndex: i, TokenID: id, File: tok.Ref,
				Field: tokenField(cfg.PathPrefix, i, "id"),
				Msg:   fmt.Sprintf("duplicate token id %q", id),
			}
		}
		raw := tok.Secret.bytes()
		// The floor runs before the empty check so a 0-byte whole-file token
		// with a floor uses syslog's short-file sentence, not "required".
		if cfg.MinSecretBytes > 0 && len(raw) < cfg.MinSecretBytes {
			tok.Secret.Zero()
			ref := tok.Ref
			if ref == "" {
				ref = tok.File
			}
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "invalid_value", TokenIndex: i, TokenID: id, File: ref,
				Field: tokenField(cfg.PathPrefix, i, "secretFile"),
				Msg:   fmt.Sprintf("secretFile %q trimmed contents are shorter than %d bytes", ref, cfg.MinSecretBytes),
			}
		}
		if len(raw) == 0 {
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "required", TokenIndex: i, TokenID: id, File: tok.Ref,
				Field: tokenField(cfg.PathPrefix, i, "secretFile"),
				Msg:   "token value is required",
			}
		}
		if cfg.WarnBelowBytes > 0 && len(raw) < cfg.WarnBelowBytes {
			warnings = append(warnings, id)
		}
		sum := sha256.Sum256(raw)
		tok.Secret.Zero()
		if other, ok := seenDigest[sum]; ok && cfg.Duplicates == RejectDuplicateValue {
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "duplicate_id", TokenIndex: i, TokenID: id, File: tok.Ref,
				Field: tokenField(cfg.PathPrefix, i, "secretFile"),
				Msg:   fmt.Sprintf("token value matches %s", other),
			}
		}
		if cfg.RejectEmptyRole && role == "" {
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "invalid_value", TokenIndex: i, TokenID: id,
				Field: tokenField(cfg.PathPrefix, i, "role"), Msg: "token role is required",
			}
		}
		if cfg.DNSDefaults != nil && role == "" && len(scopes) == 0 {
			role = cfg.DNSDefaults.EmptyRoleAndScopes
		}
		if !tableZero(cfg.Roles) {
			var err error
			role, scopes, err = cfg.Roles.Expand(role, scopes)
			if err != nil {
				return nil, &LoadError{
					Kind: kerr.Invalid, Code: "invalid_value", TokenIndex: i, TokenID: id,
					Field: tokenField(cfg.PathPrefix, i, "role"),
					Msg:   fmt.Sprintf("unknown role %q", strings.TrimSpace(tok.Role)),
					Err:   err,
				}
			}
		}
		if _, ok := seenDigest[sum]; !ok {
			seenDigest[sum] = id
		}
		seenID[id] = len(stored)
		stored = append(stored, storedToken{
			id: id, role: role, scopes: scopes,
			groups: append([]string(nil), tok.Groups...), digest: sum,
		})
	}
	var basic *storedBasic
	if cfg.Mode == ModeBearerAndBasic && cfg.Basic != nil && strings.TrimSpace(cfg.Basic.Username) != "" {
		user := strings.TrimSpace(cfg.Basic.Username)
		pw := cfg.Basic.Password.bytes()
		if len(pw) == 0 {
			cfg.Basic.Password.Zero()
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "required", TokenIndex: -1,
				Field: joinField(cfg.PathPrefix, "basic.passwordFile"),
				Msg:   "basic password is empty",
			}
		}
		sum := sha256.Sum256(pw)
		cfg.Basic.Password.Zero()
		idx, ok := seenID[strings.TrimSpace(cfg.Basic.TokenRef)]
		if !ok {
			return nil, &LoadError{
				Kind: kerr.Invalid, Code: "unresolved_reference", TokenIndex: -1,
				Field: joinField(cfg.PathPrefix, "basic.tokenRef"),
				Msg:   "basic.tokenRef does not match a token id",
			}
		}
		basic = &storedBasic{username: user, digest: sum, index: idx}
	}
	m := &Material{
		mode: cfg.Mode, tokens: stored, basic: basic, warnings: warnings,
		localhost: cfg.LocalhostIsLoopback, dup: cfg.Duplicates,
		loop: loopPrincipal(cfg),
	}
	return m, nil
}

func loopPrincipal(cfg Config) scope.Principal {
	p := scope.Principal{ID: "loopback", Class: "loopback", Role: "administrator"}
	if tableZero(cfg.Roles) {
		return p
	}
	if role, scopes, err := cfg.Roles.Expand("administrator", nil); err == nil {
		p.Role = role
		p.Scopes = scopes
	}
	return p
}

func tableZero(t scope.Table) bool {
	return t.Roles == nil && t.EmptyRole == "" && !t.ExplicitReplacesRole && t.WildcardScope == ""
}

// Mode is the compiled mode.
func (m *Material) Mode() Mode {
	if m == nil {
		return 0
	}
	return m.mode
}

// TokenCount is the number of bearer tokens, duplicates included.
func (m *Material) TokenCount() int {
	if m == nil {
		return 0
	}
	return len(m.tokens)
}

// BasicEnabled reports whether a Basic credential was compiled.
func (m *Material) BasicEnabled() bool {
	return m != nil && m.basic != nil
}

// Warnings lists token ids shorter than WarnBelowBytes, in stored order.
func (m *Material) Warnings() []string {
	if m == nil {
		return nil
	}
	return append([]string(nil), m.warnings...)
}

// Equivalent reports whether m and o are the same identity.
// Comparison is by token id (digest, role, scopes), not by slice position,
// except that a duplicated id is compared as a multiset.
// Basic compares the username, the password digest, and the bound token index.
// Groups are not part of the identity.
func (m *Material) Equivalent(o *Material) bool {
	if m == nil || o == nil {
		return m == o
	}
	if m.mode != o.mode || len(m.tokens) != len(o.tokens) {
		return false
	}
	if !sameMultiset(m.tokens, o.tokens) {
		return false
	}
	if (m.basic == nil) != (o.basic == nil) {
		return false
	}
	if m.basic != nil {
		if m.basic.username != o.basic.username || m.basic.index != o.basic.index {
			return false
		}
		if subtle.ConstantTimeCompare(m.basic.digest[:], o.basic.digest[:]) != 1 {
			return false
		}
	}
	return true
}

func sameMultiset(a, b []storedToken) bool {
	if len(a) != len(b) {
		return false
	}
	ka := make([]string, len(a))
	kb := make([]string, len(b))
	for i := range a {
		ka[i] = tokenIdentity(a[i])
		kb[i] = tokenIdentity(b[i])
	}
	slices.Sort(ka)
	slices.Sort(kb)
	return slices.Equal(ka, kb)
}

func tokenIdentity(t storedToken) string {
	scopes := append([]string(nil), t.scopes...)
	slices.Sort(scopes)
	return t.id + "\x00" + hex.EncodeToString(t.digest[:]) + "\x00" + t.role + "\x00" + strings.Join(scopes, "\x00")
}

// OrderedDigest is hex(SHA-256(prefix || 0x00 || d1 || d2 || … || dn)).
// Each d is the raw 32-byte SHA-256 of one token secret, in stored order,
// duplicates included. A nil *Material returns hex(SHA-256("")) and ignores prefix.
func (m *Material) OrderedDigest(prefix []byte) string {
	h := sha256.New()
	if m == nil {
		return hex.EncodeToString(h.Sum(nil))
	}
	h.Write(prefix)
	h.Write([]byte{0})
	for _, t := range m.tokens {
		h.Write(t.digest[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Material) clone() *Material {
	if m == nil {
		return nil
	}
	cp := *m
	cp.tokens = append([]storedToken(nil), m.tokens...)
	for i := range cp.tokens {
		cp.tokens[i].scopes = append([]string(nil), m.tokens[i].scopes...)
		cp.tokens[i].groups = append([]string(nil), m.tokens[i].groups...)
	}
	if m.basic != nil {
		b := *m.basic
		cp.basic = &b
	}
	cp.warnings = append([]string(nil), m.warnings...)
	cp.loop.Scopes = append([]string(nil), m.loop.Scopes...)
	cp.loop.Groups = append([]string(nil), m.loop.Groups...)
	return &cp
}

func (m *Material) principalAt(i int) scope.Principal {
	t := m.tokens[i]
	return scope.Principal{
		ID: t.id, Class: "token", Role: t.role,
		Scopes: append([]string(nil), t.scopes...),
		Groups: append([]string(nil), t.groups...),
	}
}

func (m *Material) loopback(remote string) bool {
	host := strings.TrimSpace(remote)
	if h, _, err := splitHost(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if m.localhost && host == "localhost" {
		return true
	}
	return addrLoopback(host)
}

// BearerNeedsToken is the listen predicate for the repos that have
// RequireListen. allowDevLoopback true is ntp: dev-loopback-unauth is
// allowed, and any other non-bearer mode is refused. false is netconf and
// snmp: only bearer is allowed. A bearer mode with zero tokens is
// "spec.auth.mode bearer requires at least one usable token". Every other
// mode is `management bind refused: unknown auth mode %q` of Mode.String().
// A nil material is "management bind requires a verifier".
func BearerNeedsToken(allowDevLoopback bool) func(*Material) error {
	return func(m *Material) error {
		if m == nil {
			return kerr.New(kerr.Invalid, "management bind requires a verifier")
		}
		mode := m.Mode()
		if mode == ModeBearer {
			if m.TokenCount() == 0 {
				return kerr.New(kerr.Invalid, "spec.auth.mode bearer requires at least one usable token")
			}
			return nil
		}
		if allowDevLoopback && mode == ModeDevLoopbackUnauth {
			return nil
		}
		return kerr.New(kerr.Invalid, fmt.Sprintf("management bind refused: unknown auth mode %q", mode.String()))
	}
}

func basicFileActive(cfg Config) bool {
	return cfg.Mode == ModeBearerAndBasic && cfg.Basic != nil &&
		strings.TrimSpace(cfg.Basic.Username) != "" && cfg.Basic.PasswordFile != ""
}

func withPrefix(cfg Config, err error) error {
	var le *LoadError
	if !errorsAsLoad(err, &le) || le.Field != "" || cfg.PathPrefix == "" {
		return err
	}
	// TokenIndex -1 is not a slot. The zero value 0 is slot 0 and is filled.
	if le.File != "" && le.TokenIndex >= 0 && le.Code != "" && le.Field == "" {
		le.Field = tokenField(cfg.PathPrefix, le.TokenIndex, "secretFile")
	}
	return le
}

func errorsAsLoad(err error, le **LoadError) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*LoadError)
	if !ok {
		return false
	}
	*le = e
	return true
}

func tokenField(prefix string, i int, leaf string) string {
	return fmt.Sprintf("%s[%d].%s", joinField(prefix, "tokens"), i, leaf)
}

func joinField(prefix, leaf string) string {
	if prefix == "" {
		return leaf
	}
	return prefix + "." + leaf
}

func quote(s string) string { return strconv.Quote(s) }

func specHash(cfg Config) [32]byte {
	canon := struct {
		Mode        string `json:"mode"`
		Duplicates  string `json:"duplicates"`
		Min         int    `json:"minSecretBytes"`
		Warn        int    `json:"warnBelowBytes"`
		Prefix      string `json:"pathPrefix"`
		RejectEmpty bool   `json:"rejectEmptyRole"`
		Localhost   bool   `json:"localhostIsLoopback"`
		Bound       bool   `json:"managementBound"`
		Accept      bool   `json:"accept"`
		BasicUser   string `json:"basicUser,omitempty"`
		BasicRef    string `json:"basicRef,omitempty"`
		BasicFile   string `json:"basicFile,omitempty"`
		Roles       any    `json:"roles"`
		DNS         any    `json:"dnsDefaults,omitempty"`
		Source      any    `json:"source"`
	}{
		Mode: cfg.Mode.String(), Duplicates: cfg.Duplicates.String(),
		Min: cfg.MinSecretBytes, Warn: cfg.WarnBelowBytes, Prefix: cfg.PathPrefix,
		RejectEmpty: cfg.RejectEmptyRole, Localhost: cfg.LocalhostIsLoopback,
		Bound: cfg.ManagementBound, Accept: cfg.Accept != nil,
		Roles: cfg.Roles, Source: cfg.Source.Spec(),
	}
	if cfg.Basic != nil {
		canon.BasicUser = cfg.Basic.Username
		canon.BasicRef = cfg.Basic.TokenRef
		canon.BasicFile = cfg.Basic.PasswordFile
	}
	if cfg.DNSDefaults != nil {
		canon.DNS = cfg.DNSDefaults
	}
	b, err := json.Marshal(canon)
	if err != nil {
		sum := sha256.Sum256([]byte(err.Error()))
		return sum
	}
	return sha256.Sum256(b)
}
