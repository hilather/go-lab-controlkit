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
//
// A raw value is retained only when an Open pattern matches that path.
// While parsing, Check tracks which patterns can still match the current
// prefix. When none can, the subtree is scanned for syntax and duplicate
// keys without path strings or copies. A typed spec decodes the input once
// with encoding/json; that decode is not repeated per node.
func Check(raw json.RawMessage, spec Spec) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	open := compileOpen(spec)
	p := parser{b: raw, open: open}
	var live []int
	if len(open) > 0 {
		live = make([]int, len(open))
		for i := range open {
			live[i] = i
		}
	}
	var matches []rawMatch
	if err := p.parseValue(live, 0, &matches); err != nil {
		return err
	}
	p.skipWS()
	if p.i != len(p.b) {
		return invalid("mcpstrict: trailing data")
	}
	// Float overflow used to fall out of encoding/json after a successful
	// structural parse, so a duplicate key still wins over a huge number.
	if err := p.rejectOverflow(); err != nil {
		return err
	}
	if p.rootNull {
		return nil
	}
	if len(spec.Typed) > 0 {
		var tree any
		if err := json.Unmarshal(raw, &tree); err != nil {
			return invalid("mcpstrict: invalid json")
		}
		if err := walkTyped(tree, spec, compileTyped(spec), nil); err != nil {
			return err
		}
	}
	return checkOpen(matches, open)
}

func isNullToken(raw []byte) bool {
	return len(raw) == 4 && raw[0] == 'n' && raw[1] == 'u' && raw[2] == 'l' && raw[3] == 'l'
}

func walkTyped(tree any, spec Spec, pats []typedPat, segs []string) error {
	if obj, isObj := tree.(map[string]any); isObj {
		if exactTyped(pats, len(segs)) {
			path := pathFromSegs(segs)
			if set, ok := matchingSet(spec, path); ok {
				for k := range obj {
					if !set[k] {
						return invalid("mcpstrict: unknown key " + strconv.Quote(k) + " at " + displayPath(path))
					}
				}
			}
		}
		if !deeperTyped(pats, len(segs)) {
			return nil
		}
		for k, child := range obj {
			seg := pointerEscape(k)
			next := filterTyped(pats, len(segs), seg)
			if len(next) == 0 {
				continue
			}
			if err := walkTyped(child, spec, next, withSeg(segs, seg)); err != nil {
				return err
			}
		}
		return nil
	}
	arr, isArr := tree.([]any)
	if !isArr || !deeperTyped(pats, len(segs)) {
		return nil
	}
	for i, child := range arr {
		next := filterTypedIndex(pats, len(segs), i)
		if len(next) == 0 {
			continue
		}
		if err := walkTyped(child, spec, next, withSeg(segs, strconv.Itoa(i))); err != nil {
			return err
		}
	}
	return nil
}

func exactTyped(pats []typedPat, depth int) bool {
	for i := range pats {
		if len(pats[i].segs) == depth {
			return true
		}
	}
	return false
}

func deeperTyped(pats []typedPat, depth int) bool {
	for i := range pats {
		if len(pats[i].segs) > depth {
			return true
		}
	}
	return false
}

func filterTyped(pats []typedPat, depth int, seg string) []typedPat {
	var out []typedPat
	for i := range pats {
		segs := pats[i].segs
		if len(segs) <= depth {
			continue
		}
		want := segs[depth]
		if want == "*" || want == seg {
			out = append(out, pats[i])
		}
	}
	return out
}

func filterTypedIndex(pats []typedPat, depth, index int) []typedPat {
	var out []typedPat
	for i := range pats {
		segs := pats[i].segs
		if len(segs) <= depth {
			continue
		}
		want := segs[depth]
		if want == "*" || indexEq(want, index) {
			out = append(out, pats[i])
		}
	}
	return out
}

func withSeg(segs []string, seg string) []string {
	out := make([]string, len(segs)+1)
	copy(out, segs)
	out[len(segs)] = seg
	return out
}

func pathFromSegs(segs []string) string {
	if len(segs) == 0 {
		return ""
	}
	n := len(segs)
	for _, s := range segs {
		n += len(s)
	}
	b := make([]byte, 0, n)
	for _, s := range segs {
		b = append(b, '/')
		b = append(b, s...)
	}
	return string(b)
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

type openPat struct {
	segs    []string
	fn      func(json.RawMessage) error
	pattern string
}

type typedPat struct {
	segs []string
}

type rawMatch struct {
	path string
	raw  json.RawMessage
}

func compileOpen(spec Spec) []openPat {
	if len(spec.Open) == 0 {
		return nil
	}
	out := make([]openPat, 0, len(spec.Open))
	for pattern, fn := range spec.Open {
		if fn == nil {
			continue
		}
		out = append(out, openPat{segs: splitPath(pattern), fn: fn, pattern: pattern})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pattern < out[j].pattern })
	return out
}

func compileTyped(spec Spec) []typedPat {
	if len(spec.Typed) == 0 {
		return nil
	}
	out := make([]typedPat, 0, len(spec.Typed))
	for pattern := range spec.Typed {
		out = append(out, typedPat{segs: splitPath(pattern)})
	}
	return out
}

func checkOpen(matches []rawMatch, open []openPat) error {
	if len(open) == 0 || len(matches) == 0 {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].path < matches[j].path })
	for _, pat := range open {
		for _, m := range matches {
			if _, ok := matchPattern(pat.pattern, m.path); !ok {
				continue
			}
			if err := pat.fn(m.raw); err != nil {
				msg := "mcpstrict: invalid value at " + displayPath(m.path)
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
	b        []byte
	i        int
	path     []byte
	open     []openPat
	rootNull bool
	// bigNums holds start,end pairs of number tokens that might not fit
	// in float64. They are tested only after the structural parse succeeds.
	bigNums []int
}

func (p *parser) parseValue(live []int, depth int, matches *[]rawMatch) error {
	p.skipWS()
	if p.i >= len(p.b) {
		return invalid("mcpstrict: unexpected end")
	}
	start := p.i
	exact, descend := p.classify(live, depth)
	var err error
	switch p.b[p.i] {
	case '{', '[':
		// depth is the number of containers already open. Reject before
		// entering another '{' or '[' once that count is 10000.
		if depth >= maxNestingDepth {
			return invalid("mcpstrict: invalid json")
		}
		if p.b[p.i] == '{' {
			err = p.parseObject(live, depth, matches, descend)
		} else {
			err = p.parseArray(live, depth, matches, descend)
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
	if depth == 0 && isNullToken(p.b[start:p.i]) {
		p.rootNull = true
	}
	if exact {
		raw := append(json.RawMessage(nil), p.b[start:p.i]...)
		*matches = append(*matches, rawMatch{path: string(p.path), raw: raw})
	}
	return nil
}

func (p *parser) classify(live []int, depth int) (exact, descend bool) {
	for _, id := range live {
		n := len(p.open[id].segs)
		if n == depth {
			exact = true
		} else if n > depth {
			descend = true
		}
		if exact && descend {
			return
		}
	}
	return
}

func (p *parser) parseObject(live []int, depth int, matches *[]rawMatch, descend bool) error {
	p.i++
	p.skipWS()
	if p.eat('}') {
		return nil
	}
	// One key cannot collide. The map waits for a second key so a chain
	// of single-key objects does not allocate a map per level.
	var seen map[string]struct{}
	var first string
	haveFirst := false
	for {
		p.skipWS()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return invalid("mcpstrict: object key is not a string at " + p.at())
		}
		key, err := p.parseString()
		if err != nil {
			return err
		}
		if !haveFirst {
			first = key
			haveFirst = true
		} else {
			if seen == nil {
				seen = make(map[string]struct{}, 4)
				seen[first] = struct{}{}
			}
			if _, ok := seen[key]; ok {
				return invalid("mcpstrict: duplicate key " + strconv.Quote(key) + " at " + p.at())
			}
			seen[key] = struct{}{}
		}
		p.skipWS()
		if !p.eat(':') {
			return invalid("mcpstrict: missing colon at " + p.at())
		}
		mark := len(p.path)
		p.appendEscaped(key)
		var child []int
		if descend {
			child = p.childLiveKey(live, depth, key)
		}
		if err := p.parseValue(child, depth+1, matches); err != nil {
			return err
		}
		p.path = p.path[:mark]
		p.skipWS()
		if p.eat('}') {
			return nil
		}
		if !p.eat(',') {
			return invalid("mcpstrict: missing comma at " + p.at())
		}
	}
}

func (p *parser) parseArray(live []int, depth int, matches *[]rawMatch, descend bool) error {
	p.i++
	p.skipWS()
	if p.eat(']') {
		return nil
	}
	for i := 0; ; i++ {
		mark := len(p.path)
		p.appendIndex(i)
		var child []int
		if descend {
			child = p.childLiveIndex(live, depth, i)
		}
		if err := p.parseValue(child, depth+1, matches); err != nil {
			return err
		}
		p.path = p.path[:mark]
		p.skipWS()
		if p.eat(']') {
			return nil
		}
		if !p.eat(',') {
			return invalid("mcpstrict: missing comma at " + p.at())
		}
	}
}

func (p *parser) childLiveKey(live []int, depth int, key string) []int {
	var out []int
	for _, id := range live {
		segs := p.open[id].segs
		if len(segs) <= depth {
			continue
		}
		want := segs[depth]
		if want == "*" || escapedEq(want, key) {
			out = append(out, id)
		}
	}
	return out
}

func (p *parser) childLiveIndex(live []int, depth, index int) []int {
	var out []int
	for _, id := range live {
		segs := p.open[id].segs
		if len(segs) <= depth {
			continue
		}
		want := segs[depth]
		if want == "*" || indexEq(want, index) {
			out = append(out, id)
		}
	}
	return out
}

func (p *parser) at() string {
	return displayPath(string(p.path))
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
	if p.i+len(want) > len(p.b) {
		return invalid("mcpstrict: invalid literal")
	}
	for j := 0; j < len(want); j++ {
		if p.b[p.i+j] != want[j] {
			return invalid("mcpstrict: invalid literal")
		}
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
	if maybeOverflow(p.b[start:p.i]) {
		p.bigNums = append(p.bigNums, start, p.i)
	}
	return nil
}

func (p *parser) rejectOverflow() error {
	for i := 0; i+1 < len(p.bigNums); i += 2 {
		tok := p.b[p.bigNums[i]:p.bigNums[i+1]]
		if _, err := strconv.ParseFloat(string(tok), 64); err != nil {
			return invalid("mcpstrict: invalid json")
		}
	}
	return nil
}

// maybeOverflow reports whether tok might not fit in a float64.
// A zero significand and a magnitude under 10^308 are in range, including
// underflow to zero. Anything larger is left for strconv.ParseFloat, which
// is what encoding/json uses, including the edge around 1e308.
func maybeOverflow(tok []byte) bool {
	i := 0
	if len(tok) > 0 && tok[0] == '-' {
		i++
	}
	intDigits := 0
	sigZero := true
	for i < len(tok) && isDigit(tok[i]) {
		if tok[i] != '0' {
			sigZero = false
		}
		intDigits++
		i++
	}
	if i < len(tok) && tok[i] == '.' {
		i++
		for i < len(tok) && isDigit(tok[i]) {
			if tok[i] != '0' {
				sigZero = false
			}
			i++
		}
	}
	if sigZero {
		return false
	}
	exp := 0
	hugePos := false
	hugeNeg := false
	if i < len(tok) && (tok[i] == 'e' || tok[i] == 'E') {
		i++
		neg := false
		if i < len(tok) && (tok[i] == '+' || tok[i] == '-') {
			neg = tok[i] == '-'
			i++
		}
		n := 0
		any := false
		for i < len(tok) && isDigit(tok[i]) {
			any = true
			if n > 1000000 {
				if neg {
					hugeNeg = true
				} else {
					hugePos = true
				}
				i++
				continue
			}
			n = n*10 + int(tok[i]-'0')
			i++
		}
		if !any {
			return false
		}
		if neg {
			exp = -n
		} else {
			exp = n
		}
	}
	if hugeNeg {
		return false
	}
	if hugePos {
		return true
	}
	// intDigits+exp <= 308 means the value is below 10^308, which fits.
	// Larger magnitudes, including a nonzero fraction with a huge exponent,
	// are checked with strconv after the structural parse.
	return int64(intDigits)+int64(exp) > 308
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

func (p *parser) reserve(n int) {
	if cap(p.path) >= n {
		return
	}
	ncap := cap(p.path)
	if ncap < 32 {
		ncap = 32
	}
	for ncap < n {
		if ncap > 1<<28 {
			ncap = n
			break
		}
		ncap *= 2
	}
	nb := make([]byte, len(p.path), ncap)
	copy(nb, p.path)
	p.path = nb
}

func (p *parser) appendEscaped(key string) {
	extra := 1
	for i := 0; i < len(key); i++ {
		if key[i] == '~' || key[i] == '/' {
			extra += 2
		} else {
			extra++
		}
	}
	p.reserve(len(p.path) + extra)
	p.path = append(p.path, '/')
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '~':
			p.path = append(p.path, '~', '0')
		case '/':
			p.path = append(p.path, '~', '1')
		default:
			p.path = append(p.path, key[i])
		}
	}
}

func (p *parser) appendIndex(index int) {
	p.reserve(len(p.path) + 1 + 20)
	p.path = append(p.path, '/')
	if index == 0 {
		p.path = append(p.path, '0')
		return
	}
	var tmp [20]byte
	n := len(tmp)
	for index > 0 {
		n--
		tmp[n] = byte('0' + index%10)
		index /= 10
	}
	p.path = append(p.path, tmp[n:]...)
}

func pointerEscape(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}

func escapedEq(seg, key string) bool {
	si, ki := 0, 0
	for si < len(seg) && ki < len(key) {
		switch key[ki] {
		case '~':
			if si+1 >= len(seg) || seg[si] != '~' || seg[si+1] != '0' {
				return false
			}
			si += 2
			ki++
		case '/':
			if si+1 >= len(seg) || seg[si] != '~' || seg[si+1] != '1' {
				return false
			}
			si += 2
			ki++
		default:
			if seg[si] != key[ki] {
				return false
			}
			si++
			ki++
		}
	}
	return si == len(seg) && ki == len(key)
}

func indexEq(seg string, index int) bool {
	if index == 0 {
		return seg == "0"
	}
	if seg == "" || seg[0] == '0' {
		return false
	}
	var tmp [20]byte
	start := len(tmp)
	for index > 0 {
		start--
		tmp[start] = byte('0' + index%10)
		index /= 10
	}
	if len(seg) != len(tmp)-start {
		return false
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] != tmp[start+i] {
			return false
		}
	}
	return true
}
