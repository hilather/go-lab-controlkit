// Package mcpstrict checks MCP tool arguments for the gaps the SDK schema
// does not cover: duplicate keys anywhere in the tree, unknown keys in a
// hand-replaced typed subtree, and open fields the repo validates itself.
// Check runs only after the SDK has accepted the call. Nil, empty, and
// "{}" arguments are accepted. A non-JSON body never reaches Check.
package mcpstrict

import (
	"bytes"
	"encoding/json"
	"math/bits"
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
// The zero Open map and the zero Typed map check nothing.
//
// A nested Open validator runs when its value ends. That can be before
// Check has found a duplicate key later in the document and before the
// Typed walk. If a duplicate-key, trailing-data, invalid-json, overflow,
// or Typed error is found, that error is returned and the Open result is
// ignored. The root value is the whole document, so its validator runs
// only after those checks have passed, and it does not run for JSON null.
// A validator is also skipped when a failure already held is smaller in
// (pattern, path) order. Validators must be free of side effects.
//
// The json.RawMessage passed to a validator is a sub-slice of the caller's
// input, with its capacity capped at the value. The validator must not
// modify those bytes. Retaining the slice is allowed; it aliases the
// caller's buffer for as long as that buffer lives.
type Spec struct {
	Open  map[string]func(json.RawMessage) error
	Typed map[string]KeySet
}

// Check rejects duplicate keys, then unknown keys in Typed subtrees, then
// failing Open validators. Nil, an empty slice, "{}", and JSON null are
// accepted. Whitespace-only input is treated as empty and does not panic.
//
// Open validators on nested values run while Check is still parsing.
// The Open error returned is the lexicographically first failing
// (pattern, path) pair. Spec.Open is the contract for that timing, for
// side effects, and for the sub-slice those validators receive. While
// parsing, Check tracks which patterns can still match the current
// prefix. When none can, the subtree is scanned for syntax and duplicate
// keys without path strings or copies. A typed spec decodes the input
// once with encoding/json; that decode is not repeated per node.
func Check(raw json.RawMessage, spec Spec) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	open := compileOpen(spec)
	p := parser{b: raw, open: open, failAt: -1}
	var mask []uint64
	if len(open) > 0 {
		mask = p.rootMask()
	}
	if err := p.parseValue(mask, 0); err != nil {
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
	if p.rootMatched {
		// The root path is empty. Nested calls have already restored p.path.
		p.path = p.path[:0]
		p.consider(p.rootID, json.RawMessage(p.b[p.rootStart:p.rootEnd:p.rootEnd]))
	}
	return p.openFailure()
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

	// mask[depth] is the live-pattern bitmask reused for every node at
	// that depth. A nil mask passed into parseValue means no pattern
	// reaches that node, so a stale mask[depth] is never read for a
	// sibling that no pattern can enter.
	mask [][]uint64

	// failAt is the pattern index of the best Open failure so far, or -1.
	// Patterns are sorted, so a larger index cannot beat failAt.
	failAt   int
	failPath string
	failErr  error

	rootMatched bool
	rootID      int
	rootStart   int
	rootEnd     int
}

// rootMask marks every compiled pattern live at the root.
func (p *parser) rootMask() []uint64 {
	n := len(p.open)
	words := (n + 63) >> 6
	m0 := make([]uint64, words)
	for i := 0; i < n; i++ {
		m0[i>>6] |= uint64(1) << uint(i&63)
	}
	p.mask = make([][]uint64, 1)
	p.mask[0] = m0
	return m0
}

func (p *parser) ensureMask(depth int) {
	words := (len(p.open) + 63) >> 6
	for len(p.mask) <= depth {
		p.mask = append(p.mask, make([]uint64, words))
	}
}

func (p *parser) parseValue(mask []uint64, depth int) error {
	p.skipWS()
	if p.i >= len(p.b) {
		return invalid("mcpstrict: unexpected end")
	}
	start := p.i
	descend := p.longerOpen(mask, depth)
	var err error
	switch p.b[p.i] {
	case '{', '[':
		// depth is the number of containers already open. Reject before
		// entering another '{' or '[' once that count is 10000.
		if depth >= maxNestingDepth {
			return invalid("mcpstrict: invalid json")
		}
		if p.b[p.i] == '{' {
			err = p.parseObject(mask, depth, descend)
		} else {
			err = p.parseArray(mask, depth, descend)
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
	// The root validator waits until duplicate-key, overflow, and Typed
	// checks have passed. Nested values end here, before those checks
	// finish for the rest of the document.
	if depth == 0 {
		p.noteRoot(mask, start)
		return nil
	}
	p.applyExact(mask, depth, start)
	return nil
}

func (p *parser) longerOpen(mask []uint64, depth int) bool {
	for word := 0; word < len(mask); word++ {
		set := mask[word]
		for set != 0 {
			bit := bits.TrailingZeros64(set)
			set &^= uint64(1) << uint(bit)
			id := word<<6 + bit
			if len(p.open[id].segs) > depth {
				return true
			}
		}
	}
	return false
}

func (p *parser) noteRoot(mask []uint64, start int) {
	for word := 0; word < len(mask); word++ {
		set := mask[word]
		for set != 0 {
			bit := bits.TrailingZeros64(set)
			set &^= uint64(1) << uint(bit)
			id := word<<6 + bit
			if len(p.open[id].segs) != 0 {
				continue
			}
			p.rootMatched = true
			p.rootID = id
			p.rootStart = start
			p.rootEnd = p.i
			return
		}
	}
}

func (p *parser) applyExact(mask []uint64, depth, start int) {
	var raw json.RawMessage
	have := false
	for word := 0; word < len(mask); word++ {
		set := mask[word]
		for set != 0 {
			bit := bits.TrailingZeros64(set)
			set &^= uint64(1) << uint(bit)
			id := word<<6 + bit
			if len(p.open[id].segs) != depth {
				continue
			}
			if !have {
				raw = json.RawMessage(p.b[start:p.i:p.i])
				have = true
			}
			p.consider(id, raw)
		}
	}
}

// consider calls pattern id when a failure from it could still be the
// lexicographic minimum (pattern, path). The path string is built only
// after the validator fails.
func (p *parser) consider(id int, raw json.RawMessage) {
	if p.failAt >= 0 && id > p.failAt {
		return
	}
	if p.failAt == id && !pathLess(p.path, p.failPath) {
		return
	}
	err := p.open[id].fn(raw)
	if err == nil {
		return
	}
	p.failAt = id
	p.failPath = string(p.path)
	p.failErr = err
}

func (p *parser) openFailure() error {
	if p.failAt < 0 {
		return nil
	}
	msg := "mcpstrict: invalid value at " + displayPath(p.failPath)
	return &openError{err: p.failErr, kit: kerr.New(kerr.Invalid, msg)}
}

func pathLess(a []byte, b string) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func (p *parser) parseObject(parent []uint64, depth int, descend bool) error {
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
		var child []uint64
		if descend {
			child = p.childMask(parent, depth, key, 0, true)
		}
		if err := p.parseValue(child, depth+1); err != nil {
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

func (p *parser) parseArray(parent []uint64, depth int, descend bool) error {
	p.i++
	p.skipWS()
	if p.eat(']') {
		return nil
	}
	for i := 0; ; i++ {
		mark := len(p.path)
		p.appendIndex(i)
		var child []uint64
		if descend {
			child = p.childMask(parent, depth, "", i, false)
		}
		if err := p.parseValue(child, depth+1); err != nil {
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

// childMask writes the patterns still live under this key or index into
// the scratch word slice for depth+1. Siblings reuse that slice; the
// caller passes the result into the child and does not read it again.
func (p *parser) childMask(parent []uint64, depth int, key string, index int, byKey bool) []uint64 {
	p.ensureMask(depth + 1)
	child := p.mask[depth+1]
	for i := range child {
		child[i] = 0
	}
	for word := 0; word < len(parent); word++ {
		set := parent[word]
		for set != 0 {
			bit := bits.TrailingZeros64(set)
			set &^= uint64(1) << uint(bit)
			id := word<<6 + bit
			segs := p.open[id].segs
			if len(segs) <= depth {
				continue
			}
			want := segs[depth]
			ok := false
			if byKey {
				ok = want == "*" || escapedEq(want, key)
			} else {
				ok = want == "*" || indexEq(want, index)
			}
			if ok {
				child[id>>6] |= uint64(1) << uint(id&63)
			}
		}
	}
	return child
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
