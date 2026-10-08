package authn

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// LineMode selects how a token file becomes a secret. The zero value is rejected.
type LineMode int

const (
	// FirstNonCommentLine uses the first line that is not blank and does not
	// start with '#', after trimming. This is the ntp, netconf, maildev, and
	// snmp rule.
	FirstNonCommentLine LineMode = iota + 1
	// WholeFileTrim uses bytes.TrimSpace of the whole file. This is the syslog rule.
	WholeFileTrim
)

// PathMode selects which path is opened. The zero value is rejected.
type PathMode int

const (
	// AsGiven opens the ref as it is written.
	AsGiven PathMode = iota + 1
	// ConfigDirIfRelative joins BaseDir when the ref is relative and BaseDir is set.
	ConfigDirIfRelative
	// CWDThenBaseDir tries the ref, then BaseDir joined to a relative ref,
	// and keeps the first candidate that yields a secret. This is the snmp rule.
	CWDThenBaseDir
	// AsGivenAndBaseDir reads the ref as given and, when the BaseDir join differs,
	// also reads that join. The loader uses only the as-given path. The join is
	// recorded because netconf's LoadFile validator and its loader disagree.
	AsGivenAndBaseDir
)

// FileOpts is the file-reading policy.
// BaseDir empty means a relative ref is not joined.
// SkipMissing false reports a missing file. True skips that token (syslog).
// Harden false calls os.ReadFile and returns its bytes and errors unchanged.
// Harden true opens with O_NONBLOCK, allows only regular files, and refuses
// a file larger than 1 MiB. Symlinks are followed. The regular-file check
// applies to the target.
type FileOpts struct {
	Line        LineMode
	Resolve     PathMode
	BaseDir     string
	SkipMissing bool
	Harden      bool
}

// ReadFile reads the raw bytes of path using o's resolve and harden rules.
// Line mode is not applied. The caller zeroes the returned buffer.
// For CWDThenBaseDir the first candidate that opens is returned.
// For AsGivenAndBaseDir only the as-given path is returned; Prepare records both.
func ReadFile(path string, o FileOpts) ([]byte, error) {
	if err := validateOpts(o); err != nil {
		return nil, err
	}
	cands := candidatePaths(path, o)
	if o.Resolve == AsGivenAndBaseDir && len(cands) > 0 {
		cands = cands[:1]
	}
	var first error
	for _, c := range cands {
		b, err := readOne(c.path, o.Harden)
		if err == nil {
			return b, nil
		}
		if first == nil {
			first = err
		}
		if o.Resolve != CWDThenBaseDir {
			return nil, err
		}
	}
	if first == nil {
		first = os.ErrNotExist
	}
	return nil, first
}

// UsableLineLen returns the byte length of the first usable line of the file
// at path: the first line that is not blank and does not start with '#',
// trimmed. It reads through the same reader as token loading, with o's Resolve
// and Harden rules, and zeroes the line before returning. A file with no
// usable line returns os.ErrInvalid. CWDThenBaseDir uses the first candidate
// that has a usable line.
func UsableLineLen(path string, o FileOpts) (int, error) {
	if err := validateOpts(o); err != nil {
		return 0, err
	}
	var first error
	for _, c := range candidatePaths(path, o) {
		b, err := readOne(c.path, o.Harden)
		if err != nil {
			zero(b)
			if first == nil {
				first = err
			}
			if o.Resolve != CWDThenBaseDir {
				return 0, err
			}
			continue
		}
		line, lerr := firstUsableLine(b)
		zero(b)
		if lerr != nil {
			zero(line)
			if first == nil {
				first = lerr
			}
			if o.Resolve != CWDThenBaseDir {
				return 0, lerr
			}
			continue
		}
		n := len(line)
		zero(line)
		return n, nil
	}
	if first == nil {
		first = os.ErrInvalid
	}
	return 0, first
}

func validateOpts(o FileOpts) error {
	if o.Line != FirstNonCommentLine && o.Line != WholeFileTrim {
		return kerr.New(kerr.Invalid, "authn: file line mode is required")
	}
	if o.Resolve != AsGiven && o.Resolve != ConfigDirIfRelative && o.Resolve != CWDThenBaseDir && o.Resolve != AsGivenAndBaseDir {
		return kerr.New(kerr.Invalid, "authn: file resolve mode is required")
	}
	return nil
}

type candidate struct {
	path     string
	resolver string
}

func candidatePaths(ref string, o FileOpts) []candidate {
	ref = trimPath(ref)
	if ref == "" {
		return []candidate{{path: ref, resolver: "as-given"}}
	}
	joined := ""
	if o.BaseDir != "" && !filepath.IsAbs(ref) {
		joined = filepath.Join(o.BaseDir, ref)
		if joined == ref {
			joined = ""
		}
	}
	switch o.Resolve {
	case ConfigDirIfRelative:
		if joined != "" {
			return []candidate{{path: joined, resolver: "config-dir"}}
		}
		return []candidate{{path: ref, resolver: "as-given"}}
	case CWDThenBaseDir:
		out := []candidate{{path: ref, resolver: "cwd"}}
		if joined != "" {
			out = append(out, candidate{path: joined, resolver: "base"})
		}
		return out
	case AsGivenAndBaseDir:
		out := []candidate{{path: ref, resolver: "as-given"}}
		if joined != "" {
			out = append(out, candidate{path: joined, resolver: "base"})
		}
		return out
	default:
		return []candidate{{path: ref, resolver: "as-given"}}
	}
}

func trimPath(p string) string {
	return string(bytes.TrimSpace([]byte(p)))
}

func readOne(path string, harden bool) ([]byte, error) {
	if !harden {
		return os.ReadFile(path)
	}
	if path == "" {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}
	return readHardened(path)
}

func readHardened(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, &os.PathError{Op: "read", Path: path, Err: syscall.EISDIR}
	}
	if !fi.Mode().IsRegular() {
		return nil, &os.PathError{Op: "read", Path: path, Err: ErrNotRegular}
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err != nil {
		zero(buf)
		return nil, err
	}
	if len(buf) > maxSecretFile {
		zero(buf)
		return nil, &os.PathError{Op: "read", Path: path, Err: ErrTooLarge}
	}
	return buf, nil
}

func firstUsableLine(b []byte) ([]byte, error) {
	for _, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		return append([]byte(nil), line...), nil
	}
	return nil, os.ErrInvalid
}

func secretBytes(b []byte, line LineMode) ([]byte, error) {
	switch line {
	case WholeFileTrim:
		s := bytes.TrimSpace(b)
		if len(s) == 0 {
			return nil, os.ErrInvalid
		}
		return append([]byte(nil), s...), nil
	case FirstNonCommentLine:
		return firstUsableLine(b)
	default:
		return nil, errors.New("authn: file line mode is required")
	}
}
