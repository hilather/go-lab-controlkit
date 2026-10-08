// Package mcpstrict checks MCP tool arguments for the gaps the SDK schema
// does not cover: duplicate keys anywhere in the tree, unknown keys in a
// hand-replaced typed subtree, and open fields the repo validates itself.
// Check runs only after the SDK has accepted the call. Nil, empty, and
// "{}" arguments are accepted. A non-JSON body never reaches Check.
package mcpstrict

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// KeySet is the allowed key set of one published subtree, plus the case
// variants the repo's coercer accepts.
// A key that is absent is allowed: Check does not enforce required.
type KeySet struct {
	Keys map[string]bool
}

// Spec is the proven gap set for one tool.
// Open maps a JSON-pointer path to the repo's validator for that value.
// Typed maps a path to the allowed keys of that object.
// A path segment "*" matches any one key or index.
type Spec struct {
	Open  map[string]func(json.RawMessage) error
	Typed map[string]KeySet
}

// Check rejects duplicate keys, then unknown keys in Typed subtrees, then
// failing Open validators. Nil, an empty slice, "{}", and JSON null are
// accepted. Whitespace-only input is treated as empty and does not panic.
func Check(raw json.RawMessage, spec Spec) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	p := parser{b: raw}
	raws := make(map[string]json.RawMessage)
	if err := p.parseValue("", raws, 0); err != nil {
		return err
	}
	p.skipWS()
	if p.i != len(p.b) {
		return invalid("mcpstrict: trailing data")
	}
	if isNull(raws[""]) {
		return nil
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return invalid("mcpstrict: invalid json")
	}
	if err := checkTyped(tree, "", spec); err != nil {
		return err
	}
	return checkOpen(raws, spec)
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func checkTyped(tree any, path string, spec Spec) error {
	obj, isObj := tree.(map[string]any)
	if isObj {
		if set, ok := matchingSet(spec, path); ok {
			for k := range obj {
				if !set[k] {
					return invalid("mcpstrict: unknown key " + strconv.Quote(k) + " at " + displayPath(path))
				}
			}
		}
		for k, child := range obj {
			if err := checkTyped(child, join(path, k), spec); err != nil {
				return err
			}
		}
		return nil
	}
	arr, isArr := tree.([]any)
	if !isArr {
		return nil
	}
	for i, child := range arr {
		if err := checkTyped(child, join(path, strconv.Itoa(i)), spec); err != nil {
			return err
		}
	}
	return nil
}

func matchingSet(spec Spec, path string) (map[string]bool, bool) {
	if spec.Typed == nil {
		return nil, false
	}
	bestStars := int(^uint(0) >> 1)
	var sets []map[string]bool
	for pattern, set := range spec.Typed {
		stars, ok := matchPattern(pattern, path)
		if !ok {
			continue
		}
		if stars < bestStars {
			bestStars = stars
			sets = []map[string]bool{set.Keys}
			continue
		}
		if stars == bestStars {
			sets = append(sets, set.Keys)
		}
	}
	if len(sets) == 0 {
		return nil, false
	}
	if len(sets) == 1 {
		if sets[0] == nil {
			return map[string]bool{}, true
		}
		return sets[0], true
	}
	out := map[string]bool{}
	for k := range sets[0] {
		keep := true
		for _, other := range sets[1:] {
			if other == nil || !other[k] {
				keep = false
				break
			}
		}
		if keep {
			out[k] = true
		}
	}
	return out, true
}

func matchPattern(pattern, path string) (int, bool) {
	ps := splitPath(pattern)
	as := splitPath(path)
	if len(ps) != len(as) {
		return 0, false
	}
	stars := 0
	for i := range ps {
		if ps[i] == "*" {
			stars++
			continue
		}
		if ps[i] != as[i] {
			return 0, false
		}
	}
	return stars, true
}

func splitPath(path string) []string {
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	return parts
}

// openError is a failing Open validator. The sentence names only the path,
// so a validator cannot echo a secret to the MCP client. Unwrap returns
// the validator error. As reports kerr.Invalid so KindOf still works.
type openError struct {
	err error
	kit *kerr.Error
}

func (e *openError) Error() string {
	if e == nil || e.kit == nil {
		return "mcpstrict: invalid value"
	}
	return e.kit.Error()
}

func (e *openError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *openError) As(target any) bool {
	if e == nil || e.kit == nil {
		return false
	}
	ke, ok := target.(**kerr.Error)
	if !ok {
		return false
	}
	*ke = e.kit
	return true
}

func checkOpen(raws map[string]json.RawMessage, spec Spec) error {
	if len(spec.Open) == 0 || len(raws) == 0 {
		return nil
	}
	patterns := make([]string, 0, len(spec.Open))
	for pattern, fn := range spec.Open {
		if fn == nil {
			continue
		}
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	paths := make([]string, 0, len(raws))
	for path := range raws {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, pattern := range patterns {
		fn := spec.Open[pattern]
		for _, path := range paths {
			if _, ok := matchPattern(pattern, path); !ok {
				continue
			}
			if err := fn(raws[path]); err != nil {
				msg := "mcpstrict: invalid value at " + displayPath(path)
				return &openError{err: err, kit: kerr.New(kerr.Invalid, msg)}
			}
		}
	}
	return nil
}

func displayPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func invalid(msg string) error {
	return kerr.New(kerr.Invalid, msg)
}

// maxNestingDepth is the longest stack of open '{' and '[' containers
// encoding/json accepts. scanner.pushParseState pushes only those two
// bytes and then allows a stack length of 10000, so a leaf inside the
// 10000th container is valid and the 10001st container is not.
const maxNestingDepth = 10000

type parser struct {
	b []byte
	i int
}

func (p *parser) parseValue(path string, raws map[string]json.RawMessage, depth int) error {
	p.skipWS()
	if p.i >= len(p.b) {
		return invalid("mcpstrict: unexpected end")
	}
	start := p.i
	var err error
	switch p.b[p.i] {
	case '{', '[':
		// depth is the number of containers already open. Reject before
		// entering another '{' or '[' once that count is 10000.
		if depth >= maxNestingDepth {
			return invalid("mcpstrict: invalid json")
		}
		if p.b[p.i] == '{' {
			err = p.parseObject(path, raws, depth)
		} else {
			err = p.parseArray(path, raws, depth)
		}
	case '"':
		_, err = p.parseString()
	case 't':
		err = p.literal("true")
	case 'f':
		err = p.literal("false")
	case 'n':
		err = p.literal("null")
	default:
		err = p.parseNumber()
	}
	if err != nil {
		return err
	}
	raws[path] = append(json.RawMessage(nil), p.b[start:p.i]...)
	return nil
}

func (p *parser) parseObject(path string, raws map[string]json.RawMessage, depth int) error {
	p.i++
	p.skipWS()
	if p.eat('}') {
		return nil
	}
	seen := map[string]struct{}{}
	for {
		p.skipWS()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return invalid("mcpstrict: object key is not a string at " + displayPath(path))
		}
		key, err := p.parseString()
		if err != nil {
			return err
		}
		if _, ok := seen[key]; ok {
			return invalid("mcpstrict: duplicate key " + strconv.Quote(key) + " at " + displayPath(path))
		}
		seen[key] = struct{}{}
		p.skipWS()
		if !p.eat(':') {
			return invalid("mcpstrict: missing colon at " + displayPath(path))
		}
		if err := p.parseValue(join(path, key), raws, depth+1); err != nil {
			return err
		}
		p.skipWS()
		if p.eat('}') {
			return nil
		}
		if !p.eat(',') {
			return invalid("mcpstrict: missing comma at " + displayPath(path))
		}
	}
}

func (p *parser) parseArray(path string, raws map[string]json.RawMessage, depth int) error {
	p.i++
	p.skipWS()
	if p.eat(']') {
		return nil
	}
	for i := 0; ; i++ {
		if err := p.parseValue(join(path, strconv.Itoa(i)), raws, depth+1); err != nil {
			return err
		}
		p.skipWS()
		if p.eat(']') {
			return nil
		}
		if !p.eat(',') {
			return invalid("mcpstrict: missing comma at " + displayPath(path))
		}
	}
}

// parseString returns the key encoding/json would decode.
// The quoted slice is handed to json.Unmarshal so an unpaired surrogate
// becomes U+FFFD without consuming the next \uXXXX, and invalid UTF-8
// bytes become U+FFFD. Check then agrees with the SDK on which keys collide.
func (p *parser) parseString() (string, error) {
	if p.i >= len(p.b) || p.b[p.i] != '"' {
		return "", invalid("mcpstrict: string expected")
	}
	start := p.i
	p.i++
	for p.i < len(p.b) {
		c := p.b[p.i]
		if c == '"' {
			p.i++
			var s string
			if err := json.Unmarshal(p.b[start:p.i], &s); err != nil {
				return "", invalid("mcpstrict: bad string")
			}
			return s, nil
		}
		if c == '\\' {
			p.i++
			if p.i >= len(p.b) {
				return "", invalid("mcpstrict: bad escape")
			}
			if p.b[p.i] == 'u' {
				p.i++
				for n := 0; n < 4; n++ {
					if p.i >= len(p.b) || !isHex(p.b[p.i]) {
						return "", invalid("mcpstrict: bad unicode escape")
					}
					p.i++
				}
				continue
			}
			p.i++
			continue
		}
		if c < 0x20 {
			return "", invalid("mcpstrict: raw control in string")
		}
		p.i++
	}
	return "", invalid("mcpstrict: unterminated string")
}

func (p *parser) literal(want string) error {
	if p.i+len(want) > len(p.b) || string(p.b[p.i:p.i+len(want)]) != want {
		return invalid("mcpstrict: invalid literal")
	}
	p.i += len(want)
	return nil
}

func (p *parser) parseNumber() error {
	start := p.i
	if p.eat('-') {
	}
	if p.i >= len(p.b) || !isDigit(p.b[p.i]) {
		return invalid("mcpstrict: invalid number")
	}
	if p.b[p.i] == '0' {
		p.i++
	} else {
		for p.i < len(p.b) && isDigit(p.b[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.b) && p.b[p.i] == '.' {
		p.i++
		if p.i >= len(p.b) || !isDigit(p.b[p.i]) {
			return invalid("mcpstrict: invalid number")
		}
		for p.i < len(p.b) && isDigit(p.b[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.b) || !isDigit(p.b[p.i]) {
			return invalid("mcpstrict: invalid number")
		}
		for p.i < len(p.b) && isDigit(p.b[p.i]) {
			p.i++
		}
	}
	if p.i == start {
		return invalid("mcpstrict: invalid number")
	}
	return nil
}

func (p *parser) skipWS() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\n', '\r', '\t':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) eat(c byte) bool {
	if p.i < len(p.b) && p.b[p.i] == c {
		p.i++
		return true
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func join(path, seg string) string {
	return path + "/" + pointerEscape(seg)
}

func pointerEscape(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}
