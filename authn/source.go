package authn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// RawToken is one token before it is digested.
// Secret is wiped during Load. File is the path the bytes were read from.
// Ref is the spec reference, which may differ from File after resolution.
type RawToken struct {
	ID     string
	Role   string
	Scopes []string
	Groups []string
	Secret Secret
	File   string
	Ref    string
}

// BasicSpec is the optional HTTP Basic credential.
// It is not subject to MinSecretBytes. An empty password is a load error
// only when a password was read and its length is 0. A password file with
// no usable line is unresolved_reference ("basic password file does not
// resolve: <path>"), which is also the result for a missing file.
// Nil Basic on Config means Basic is off.
// PasswordFile, when set together with a non-empty username, is opened by
// Load and Prepare through Opts. An in-memory Password is used when
// PasswordFile is empty. Opts is required when PasswordFile is set.
type BasicSpec struct {
	Username     string
	Password     Secret
	PasswordFile string
	TokenRef     string
	Opts         FileOpts
}

// TokenSource loads tokens. Read may open secret files. Spec is the
// secret-free description Prepare hashes.
type TokenSource interface {
	Read() (tokens []RawToken, files []FileResult, err error)
	Spec() any
}

// FileToken is one per-token secret file.
type FileToken struct {
	ID         string
	Role       string
	Scopes     []string
	Groups     []string
	SecretFile string
}

// PerTokenFiles loads one secret file per entry.
func PerTokenFiles(entries []FileToken, o FileOpts) TokenSource {
	cp := append([]FileToken(nil), entries...)
	return &fileSource{entries: cp, opts: o}
}

type fileSource struct {
	entries []FileToken
	opts    FileOpts
}

func (s *fileSource) Spec() any {
	type row struct {
		ID     string   `json:"id"`
		Role   string   `json:"role,omitempty"`
		Scopes []string `json:"scopes,omitempty"`
		Groups []string `json:"groups,omitempty"`
		File   string   `json:"file"`
	}
	rows := make([]row, len(s.entries))
	for i, e := range s.entries {
		rows[i] = row{ID: e.ID, Role: e.Role, Scopes: append([]string(nil), e.Scopes...), Groups: append([]string(nil), e.Groups...), File: e.SecretFile}
	}
	return struct {
		Kind  string   `json:"kind"`
		Opts  FileOpts `json:"opts"`
		Files []row    `json:"files"`
	}{Kind: "files", Opts: s.opts, Files: rows}
}

func (s *fileSource) Read() ([]RawToken, []FileResult, error) {
	if s == nil {
		return nil, nil, os.ErrInvalid
	}
	if err := validateOpts(s.opts); err != nil {
		return nil, nil, err
	}
	var tokens []RawToken
	var files []FileResult
	var first error
	for i, ent := range s.entries {
		tok, results, err := readEntry(ent, s.opts, i)
		files = append(files, results...)
		if err != nil {
			if s.opts.SkipMissing && isMissing(err) {
				continue
			}
			if first == nil {
				first = err
			}
			continue
		}
		tokens = append(tokens, tok)
	}
	return tokens, files, first
}

func readEntry(ent FileToken, o FileOpts, index int) (RawToken, []FileResult, error) {
	cands := candidatePaths(ent.SecretFile, o)
	var out []FileResult
	var picked RawToken
	var pickedOK bool
	var firstErr error
	for _, c := range cands {
		fr, raw := inspectFile(c.path, o.Harden)
		fr.Ref = ent.SecretFile
		fr.Resolver = c.resolver
		sec, serr := []byte(nil), error(nil)
		if fr.ReadErr == nil && raw != nil {
			sec, serr = secretBytes(raw, o.Line)
		}
		zero(raw)
		loaderCandidate := o.Resolve != AsGivenAndBaseDir || c.resolver == "as-given"
		// A successful WholeFileTrim read is picked even when the trimmed
		// secret is empty, so compile can apply MinSecretBytes. A read error
		// or a FirstNonCommentLine with no usable line is not a secret.
		if !pickedOK && loaderCandidate && fr.ReadErr == nil && serr == nil {
			fr.Picked = true
			pickedOK = true
			picked = RawToken{
				ID: ent.ID, Role: ent.Role,
				Scopes: append([]string(nil), ent.Scopes...),
				Groups: append([]string(nil), ent.Groups...),
				Secret: NewSecret(sec),
				File:   c.path, Ref: ent.SecretFile,
			}
		}
		zero(sec)
		out = append(out, fr)
		if fr.ReadErr != nil && firstErr == nil {
			firstErr = fr.ReadErr
		}
		if serr != nil && firstErr == nil {
			firstErr = serr
		}
		if pickedOK && o.Resolve == CWDThenBaseDir {
			break
		}
	}
	if pickedOK {
		return picked, out, nil
	}
	if firstErr == nil {
		firstErr = os.ErrNotExist
	}
	return RawToken{}, out, &LoadError{
		Kind:       kerr.Invalid,
		Code:       "unresolved_reference",
		TokenIndex: index,
		TokenID:    ent.ID,
		File:       ent.SecretFile,
		Err:        firstErr,
		Msg:        secretFileMsg(ent.SecretFile, firstErr),
	}
}

func inspectFile(path string, harden bool) (FileResult, []byte) {
	fr := FileResult{Path: path, RawLen: -1, TrimLen: -1, UsableLen: -1}
	fi, statErr := os.Stat(path)
	if statErr != nil {
		fr.StatErr = statErr
	} else {
		fr.Mode = fi.Mode()
		fr.IsDir = fi.IsDir()
		fr.RawLen = int(fi.Size())
	}
	raw, err := readOne(path, harden)
	if err != nil {
		fr.ReadErr = err
		zero(raw)
		return fr, nil
	}
	fr.RawLen = len(raw)
	fr.TrimLen = len(bytes.TrimSpace(raw))
	if line, lerr := firstUsableLine(raw); lerr == nil {
		fr.UsableLen = len(line)
		zero(line)
	}
	return fr, raw
}

func isMissing(err error) bool {
	var le *LoadError
	if errors.As(err, &le) {
		return os.IsNotExist(le.Err)
	}
	return os.IsNotExist(err)
}

func secretFileMsg(ref string, err error) string {
	return "secretFile " + quote(ref) + ": " + errString(err)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Memory loads tokens that are already in memory. It opens no file.
func Memory(tokens []RawToken) TokenSource {
	cp := make([]RawToken, len(tokens))
	for i, t := range tokens {
		cp[i] = t
		cp[i].Secret = NewSecret(t.Secret.bytes())
		cp[i].Scopes = append([]string(nil), t.Scopes...)
		cp[i].Groups = append([]string(nil), t.Groups...)
	}
	return &memSource{tokens: cp}
}

type memSource struct {
	tokens []RawToken
}

func (s *memSource) Read() ([]RawToken, []FileResult, error) {
	if s == nil {
		return nil, nil, nil
	}
	out := make([]RawToken, len(s.tokens))
	for i, t := range s.tokens {
		out[i] = t
		out[i].Secret = NewSecret(t.Secret.bytes())
		out[i].Scopes = append([]string(nil), t.Scopes...)
		out[i].Groups = append([]string(nil), t.Groups...)
	}
	return out, nil, nil
}

func (s *memSource) Spec() any {
	type row struct {
		ID     string   `json:"id"`
		Role   string   `json:"role,omitempty"`
		Scopes []string `json:"scopes,omitempty"`
		Groups []string `json:"groups,omitempty"`
		Digest string   `json:"digest"`
	}
	rows := make([]row, len(s.tokens))
	for i, t := range s.tokens {
		sum := sha256.Sum256(t.Secret.bytes())
		rows[i] = row{ID: t.ID, Role: t.Role, Scopes: append([]string(nil), t.Scopes...), Groups: append([]string(nil), t.Groups...), Digest: hex.EncodeToString(sum[:])}
	}
	return struct {
		Kind   string `json:"kind"`
		Tokens []row  `json:"tokens"`
	}{Kind: "memory", Tokens: rows}
}

// DNSBundle loads dns's in-memory tokens and then secretRef.
// secretRef may be one token line (role administrator), {"tokens":[...]}, or a
// bare JSON array. In-memory tokens come first. An empty secretRef loads only
// the in-memory tokens. o is the reader policy for secretRef.
func DNSBundle(inMemory []RawToken, secretRef string, o FileOpts) TokenSource {
	return &dnsSource{mem: Memory(inMemory).(*memSource), ref: secretRef, opts: o}
}

type dnsSource struct {
	mem  *memSource
	ref  string
	opts FileOpts
}

func (s *dnsSource) Spec() any {
	return struct {
		Kind string   `json:"kind"`
		Mem  any      `json:"memory"`
		Ref  string   `json:"secretRef,omitempty"`
		Opts FileOpts `json:"opts"`
	}{Kind: "dns", Mem: s.mem.Spec(), Ref: s.ref, Opts: s.opts}
}

func (s *dnsSource) Read() ([]RawToken, []FileResult, error) {
	toks, _, err := s.mem.Read()
	if err != nil {
		return nil, nil, err
	}
	if s.ref == "" {
		return toks, nil, nil
	}
	if err := validateOpts(s.opts); err != nil {
		return toks, nil, err
	}
	cands := candidatePaths(s.ref, s.opts)
	var files []FileResult
	var raw []byte
	var readErr error
	picked := false
	for _, c := range cands {
		fr, b := inspectFile(c.path, s.opts.Harden)
		fr.Ref = s.ref
		fr.Resolver = c.resolver
		if !picked && fr.ReadErr == nil {
			fr.Picked = true
			picked = true
			raw = b
		} else {
			zero(b)
		}
		files = append(files, fr)
		if fr.ReadErr != nil && readErr == nil {
			readErr = fr.ReadErr
		}
		if picked && s.opts.Resolve == CWDThenBaseDir {
			break
		}
	}
	if !picked {
		if readErr == nil {
			readErr = os.ErrNotExist
		}
		return toks, files, &LoadError{
			Kind: kerr.Unauthenticated, Code: "unresolved_reference", TokenIndex: -1, File: s.ref,
			Err: readErr, Msg: "token secret is unavailable",
		}
	}
	defer zero(raw)
	parsed, err := parseDNSBody(raw)
	if err != nil {
		return toks, files, err
	}
	return append(toks, parsed...), files, nil
}

type dnsJSONToken struct {
	Token  string   `json:"token"`
	ID     string   `json:"id,omitempty"`
	Role   string   `json:"role,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

func parseDNSBody(raw []byte) ([]RawToken, error) {
	s := bytes.TrimSpace(raw)
	if len(s) == 0 {
		return nil, &LoadError{Kind: kerr.Invalid, Code: "required", TokenIndex: -1, Field: "secretRef", Msg: "token secret is empty"}
	}
	if s[0] == '{' || s[0] == '[' {
		var wrap struct {
			Tokens []dnsJSONToken `json:"tokens"`
		}
		if err := json.Unmarshal(s, &wrap); err == nil && len(wrap.Tokens) > 0 {
			return dnsTokens(wrap.Tokens), nil
		}
		var arr []dnsJSONToken
		if err := json.Unmarshal(s, &arr); err == nil && len(arr) > 0 {
			return dnsTokens(arr), nil
		}
		return nil, &LoadError{Kind: kerr.Invalid, Code: "invalid_value", TokenIndex: -1, Field: "secretRef", Msg: "token secret JSON is invalid"}
	}
	line, err := firstUsableLine(s)
	if err != nil {
		return nil, &LoadError{Kind: kerr.Invalid, Code: "required", TokenIndex: -1, Field: "secretRef", Msg: "token secret is empty", Err: err}
	}
	defer zero(line)
	return []RawToken{{
		Role:   "administrator",
		Secret: NewSecret(line),
		Ref:    "secretRef",
	}}, nil
}

// readPassword opens a Basic password file and records every candidate.
// The caller has already copied BasicSpec. A read failure, including
// os.ErrInvalid for a blank or comment-only file, names the file as
// unresolved. The empty-password error is only for a successful read
// whose secret length is 0.
func readPassword(b *BasicSpec, prefix string) ([]FileResult, Secret, error) {
	if b == nil {
		return nil, Secret{}, os.ErrInvalid
	}
	cands := candidatePaths(b.PasswordFile, b.Opts)
	var out []FileResult
	var picked Secret
	var pickedOK bool
	var firstErr error
	for _, c := range cands {
		fr, raw := inspectFile(c.path, b.Opts.Harden)
		fr.Ref = b.PasswordFile
		fr.Resolver = c.resolver
		sec, serr := []byte(nil), error(nil)
		if fr.ReadErr == nil && raw != nil {
			sec, serr = secretBytes(raw, b.Opts.Line)
		}
		zero(raw)
		if !pickedOK && serr == nil && len(sec) > 0 {
			fr.Picked = true
			pickedOK = true
			picked = NewSecret(sec)
		}
		zero(sec)
		out = append(out, fr)
		if fr.ReadErr != nil && firstErr == nil {
			firstErr = fr.ReadErr
		}
		if serr != nil && firstErr == nil {
			firstErr = serr
		}
		if pickedOK && b.Opts.Resolve == CWDThenBaseDir {
			break
		}
	}
	if pickedOK {
		return out, picked, nil
	}
	field := joinField(prefix, "basic.passwordFile")
	if firstErr == nil {
		return out, Secret{}, &LoadError{
			Kind: kerr.Invalid, Code: "required", TokenIndex: -1, Field: field, File: b.PasswordFile,
			Msg: "basic password is empty",
		}
	}
	return out, Secret{}, &LoadError{
		Kind: kerr.Invalid, Code: "unresolved_reference", TokenIndex: -1, Field: field, File: b.PasswordFile,
		Err: firstErr, Msg: "basic password file does not resolve: " + b.PasswordFile,
	}
}

func dnsTokens(in []dnsJSONToken) []RawToken {
	out := make([]RawToken, len(in))
	for i, t := range in {
		out[i] = RawToken{
			ID: t.ID, Role: t.Role,
			Scopes: append([]string(nil), t.Scopes...),
			Groups: append([]string(nil), t.Groups...),
			Secret: NewSecret([]byte(t.Token)),
			Ref:    "secretRef",
		}
	}
	return out
}
