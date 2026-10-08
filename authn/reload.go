package authn

import (
	"os"

	"github.com/hilather/go-lab-controlkit/kerr"
)

// FileResult is the raw fact of one candidate path from a single Prepare read.
// Lengths are -1 when that measurement was not taken. NotChecked is set only
// on the stage returned by NotChecked. Bytes are not retained.
type FileResult struct {
	Ref        string
	Path       string
	Resolver   string
	StatErr    error
	IsDir      bool
	Mode       os.FileMode
	ReadErr    error
	RawLen     int
	TrimLen    int
	UsableLen  int
	Picked     bool
	NotChecked bool
}

// Staged is one Prepare. Commit installs the material and does not open a file.
// Err is the load or Accept failure. A nil Err on a prepared stage is committable.
type Staged struct {
	mat        *Material
	hash       [32]byte
	files      []FileResult
	err        error
	notChecked bool
	discarded  bool
}

// Prepare reads every secret file in cfg, runs Accept, and returns the stage.
// It is the only kit call that opens a secret file. A constructor error is
// returned as (nil, err). A file, token, or Accept failure is (*Staged, nil)
// with Err set, and Files still lists every candidate that was opened.
// Prepare does not take an application lock.
func Prepare(cfg Config) (*Staged, error) {
	if err := constructorError(cfg); err != nil {
		return nil, err
	}
	hash := specHash(cfg)
	m, files, loadErr := readAndCompile(cfg)
	st := &Staged{hash: hash, files: files, mat: m, err: loadErr}
	if loadErr != nil {
		st.mat = nil
		return st, nil
	}
	if cfg.Accept != nil {
		if err := cfg.Accept(m); err != nil {
			st.err = err
		}
	}
	return st, nil
}

// SpecHash is the SHA-256 of the canonical config: mode, duplicate policy,
// floors, path prefix, role table, the blank-token flag, basic username and
// file ref, resolve options, the management-bound bit, and the source
// description. Secret bytes are not part of the hash. Accept is recorded
// only as present or absent.
func (s *Staged) SpecHash() [32]byte {
	if s == nil {
		return [32]byte{}
	}
	return s.hash
}

// Files returns the candidate results in the order they were opened.
func (s *Staged) Files() []FileResult {
	if s == nil || s.notChecked {
		return nil
	}
	return append([]FileResult(nil), s.files...)
}

// Lookup returns the result for path. On a NotChecked stage every path is
// reported as not checked. On a prepared stage a path that was not a candidate
// is an internal error, never not checked.
func (s *Staged) Lookup(path string) (FileResult, error) {
	if s == nil {
		return FileResult{}, kerr.New(kerr.Internal, "authn: no file result for "+path)
	}
	if s.notChecked {
		return FileResult{Path: path, Ref: path, RawLen: -1, TrimLen: -1, UsableLen: -1, NotChecked: true}, nil
	}
	for _, fr := range s.files {
		if fr.Path == path {
			return fr, nil
		}
	}
	return FileResult{}, kerr.New(kerr.Internal, "authn: no file result for "+path)
}

// Err is the load or Accept error. It is nil when the stage can be committed.
func (s *Staged) Err() error {
	if s == nil {
		return kerr.New(kerr.Invalid, "authn: nil stage")
	}
	return s.err
}

// IsNotChecked reports whether s came from NotChecked.
func (s *Staged) IsNotChecked() bool {
	return s != nil && s.notChecked
}

// Commit installs the loaded material into v. It does not open a file.
// A nil verifier, a discarded stage, a not-checked stage, or a stage with an
// error returns false and leaves v unchanged.
func (s *Staged) Commit(v *Verifier) (changed bool) {
	if s == nil || v == nil || s.notChecked || s.discarded || s.err != nil || s.mat == nil {
		return false
	}
	return v.Swap(s.mat)
}

// Discard drops the loaded material. A later Commit does not install it.
// File facts remain available.
func (s *Staged) Discard() {
	if s == nil {
		return
	}
	s.discarded = true
	s.mat = nil
}

// NotChecked is a stage that opened nothing. Lookup of any path reports
// NotChecked and is not an error. Commit does not install material.
func NotChecked() *Staged {
	return &Staged{notChecked: true}
}
