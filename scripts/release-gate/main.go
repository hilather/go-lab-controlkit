// Command release-gate is the tag gate for go-lab-controlkit.
//
// The release workflow runs it before any tag is accepted. controlkit is a
// library, so the gate publishes nothing: no image, no binary, and no
// GitHub Release.
//
// -notes-only checks the tagged tree. The tag must match
// vMAJOR.MINOR.PATCH with an optional pre-release. docs/releases/<tag>.md
// must exist and contain a Markdown heading that includes the tag.
// A heading inside a fenced code block does not count.
// CHANGELOG.md must contain a line "## <tag>". A file whose only release
// heading is "## Unreleased" fails.
//
// -require-ci checks the CI run of this tag push. It peels the tag with
// git rev-parse refs/tags/<tag>^{commit} (an annotated tag's object is not
// the commit) and asks gh for runs of ci.yml on that SHA. The run that
// counts has event push, headSha equal to the peeled commit, and
// headBranch equal to the tag name. Only the newest match (highest
// databaseId) is judged. A missing or unfinished run exits 75. Stderr for
// that status starts with "release-gate: no matching run" or
// "release-gate: pending". Any other error exits 1. The workflow retries
// only exit 75, so a pre-release tag such as v0.1.0-pending does not make
// a peel or GITHUB_SHA error retryable. The required job names are the CI
// job names, matched exactly, and each conclusion must be success.
//
// -module checks that go list -m reports this module. It does not fetch
// the module or write a release.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// releaseTagPatternSrc is the Go module tag shape this repo accepts.
// Leading zeros are not rejected here; the release-prep review is what
// keeps tags inside the versions consumers can require.
const releaseTagPatternSrc = `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`

var releaseTagPattern = regexp.MustCompile(releaseTagPatternSrc)

// requiredCIJobs are the exact job names from .github/workflows/ci.yml.
// A near-miss ("go vet ", "fuzz-smoke") does not count.
var requiredCIJobs = []string{
	"go vet",
	"go test -race ./...",
	"fuzz smoke",
	"govulncheck",
	"replace/go.work check",
}

const (
	modulePath = "github.com/hilather/go-lab-controlkit"
	ciWorkflow = "ci.yml"

	// exitRetryable is sysexits.h EX_TEMPFAIL. The release workflow retries
	// only this status. Every other non-zero status is a hard failure.
	exitRetryable = 75

	// pendingPrefix and noMatchPrefix are the start of a retryable error.
	// fail prepends "release-gate: ", so the log line starts with
	// "release-gate: pending" or "release-gate: no matching run".
	pendingPrefix = "pending"
	noMatchPrefix = "no matching run"
)

// retryableError is a missing or unfinished CI run. Other errors are not
// retryable, even when the tag is a pre-release such as v0.1.0-pending
// and the error text contains that word.
type retryableError struct {
	msg string
}

func (e *retryableError) Error() string { return e.msg }

func retryable(err error) bool {
	var target *retryableError
	return errors.As(err, &target)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("release-gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	notesOnly := fs.Bool("notes-only", false, "validate release notes and the changelog heading")
	notes := fs.String("notes", "", "path to docs/releases/<tag>.md")
	tagFlag := fs.String("tag", "", "release tag, vX.Y.Z or refs/tags/vX.Y.Z")
	changelog := fs.String("changelog", "CHANGELOG.md", "path to CHANGELOG.md")
	requireCI := fs.Bool("require-ci", false, "require a green CI run of this tag push")
	module := fs.Bool("module", false, "require go list -m to report this module")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "release-gate: unexpected arguments\n")
		return 2
	}
	modes := 0
	if *notesOnly {
		modes++
	}
	if *requireCI {
		modes++
	}
	if *module {
		modes++
	}
	if modes != 1 {
		fmt.Fprintf(stderr, "usage: release-gate -notes-only -notes PATH -tag TAG | -require-ci | -module\n")
		return 2
	}
	if *requireCI && (*tagFlag != "" || *notes != "") {
		fmt.Fprintf(stderr, "release-gate: -require-ci reads the tag from GITHUB_REF and GITHUB_REF_NAME\n")
		return 2
	}
	switch {
	case *notesOnly:
		tag := *tagFlag
		var err error
		if strings.TrimSpace(tag) == "" {
			tag, err = resolveReleaseTag()
		} else {
			tag, err = canonicalTag(tag)
		}
		if err != nil {
			return fail(stderr, err)
		}
		path := *notes
		if path == "" {
			path = expectedNotes(tag)
		}
		if err := validateRelease(tag, path, *changelog); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "release-gate: notes ok for %s\n", tag)
		return 0
	case *requireCI:
		id, sha, err := requireGreenCI()
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "release-gate: CI run %d green at %s\n", id, sha)
		return 0
	default:
		if err := checkModule(); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "release-gate: module %s\n", modulePath)
		return 0
	}
}

// fail prints err. A missing or unfinished CI run returns exitRetryable.
// Every other error returns 1, including one whose text names a tag such
// as v0.1.0-pending.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "release-gate: %v\n", err)
	if retryable(err) {
		return exitRetryable
	}
	return 1
}

// canonicalTag strips one refs/tags/ prefix and checks the module tag
// pattern. The raw string is never used as a path.
func canonicalTag(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New(`release tag "" is not a Go module version`)
	}
	tag := raw
	if strings.HasPrefix(tag, "refs/tags/") {
		tag = strings.TrimPrefix(tag, "refs/tags/")
	}
	if !releaseTagPattern.MatchString(tag) {
		return "", fmt.Errorf("release tag %q is not a Go module version", raw)
	}
	return tag, nil
}

// resolveReleaseTag reads the tag from GITHUB_REF when that is a tag ref,
// and from GITHUB_REF_NAME otherwise. If both are set they must name the
// same tag. A branch ref is not a release tag.
func resolveReleaseTag() (string, error) {
	ref := strings.TrimSpace(os.Getenv("GITHUB_REF"))
	name := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
	var fromRef, fromName string
	if strings.HasPrefix(ref, "refs/tags/") {
		var err error
		fromRef, err = canonicalTag(ref)
		if err != nil {
			return "", err
		}
	}
	if name != "" {
		var err error
		fromName, err = canonicalTag(name)
		if err != nil {
			return "", err
		}
	}
	if fromRef != "" && fromName != "" && fromRef != fromName {
		return "", fmt.Errorf("GITHUB_REF %q and GITHUB_REF_NAME %q are different tags", ref, name)
	}
	if fromRef != "" {
		return fromRef, nil
	}
	if fromName != "" {
		return fromName, nil
	}
	if ref != "" {
		return "", fmt.Errorf("release tag %q is not a Go module version", ref)
	}
	return "", errors.New(`release tag "" is not a Go module version`)
}

func expectedNotes(tag string) string {
	return "docs/releases/" + tag + ".md"
}

// validateRelease checks the notes file and the changelog heading for tag.
// tag may include a refs/tags/ prefix; the notes path may not.
func validateRelease(tag, notes, changelog string) error {
	tag, err := canonicalTag(tag)
	if err != nil {
		return err
	}
	want := expectedNotes(tag)
	if filepath.Clean(notes) != filepath.Clean(want) {
		return fmt.Errorf("notes path %s, want %s", notes, want)
	}
	body, err := os.ReadFile(notes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("missing release notes %s", want)
		}
		return fmt.Errorf("release notes %s: %w", want, err)
	}
	if !notesMentionTag(string(body), tag) {
		return fmt.Errorf("notes %s missing a markdown heading that includes %s", want, tag)
	}
	clog, err := os.ReadFile(changelog)
	if err != nil {
		return fmt.Errorf("changelog %s: %w", changelog, err)
	}
	if !changelogHasTag(string(clog), tag) {
		return fmt.Errorf("changelog %s missing a line %q (an Unreleased heading is not a release)", changelog, "## "+tag)
	}
	return nil
}

// notesMentionTag reports whether a Markdown heading contains tag as a
// whole token. "# v1.2.30" does not satisfy tag v1.2.3. Prose that names
// the tag outside a heading does not count. Lines inside a fenced code
// block (a ``` or ~~~ fence) do not count, so a sample heading in a fence
// is not a release heading.
func notesMentionTag(text, tag string) bool {
	var fence fenceMark
	for _, line := range strings.Split(text, "\n") {
		if fence.open {
			if fenceCloses(fence, line) {
				fence = fenceMark{}
			}
			continue
		}
		if next, ok := openFence(line); ok {
			fence = next
			continue
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") {
			continue
		}
		if tokenHas(line, tag) {
			return true
		}
	}
	return false
}

// fenceMark is an open ``` or ~~~ fence. n is the marker length.
type fenceMark struct {
	open bool
	ch   byte
	n    int
}

func openFence(line string) (fenceMark, bool) {
	ch, n, rest, ok := fenceMarker(line)
	if !ok {
		return fenceMark{}, false
	}
	// A backtick fence's info string cannot contain a backtick.
	if ch == '`' && strings.Contains(rest, "`") {
		return fenceMark{}, false
	}
	return fenceMark{open: true, ch: ch, n: n}, true
}

func fenceCloses(f fenceMark, line string) bool {
	if !f.open {
		return false
	}
	ch, n, rest, ok := fenceMarker(line)
	if !ok || ch != f.ch || n < f.n {
		return false
	}
	return strings.TrimSpace(rest) == ""
}

// fenceMarker parses a trimmed line as a fence marker of at least three
// backticks or tildes. rest is the unparsed suffix, including its leading
// space.
func fenceMarker(line string) (ch byte, n int, rest string, ok bool) {
	line = strings.TrimSpace(line)
	if len(line) < 3 {
		return 0, 0, "", false
	}
	ch = line[0]
	if ch != '`' && ch != '~' {
		return 0, 0, "", false
	}
	n = 0
	for n < len(line) && line[n] == ch {
		n++
	}
	if n < 3 {
		return 0, 0, "", false
	}
	return ch, n, line[n:], true
}

func tokenHas(line, tag string) bool {
	rest := line
	for {
		i := strings.Index(rest, tag)
		if i < 0 {
			return false
		}
		end := i + len(tag)
		leftOK := i == 0 || !isTagByte(rest[i-1])
		rightOK := end == len(rest) || !isTagByte(rest[end])
		if leftOK && rightOK {
			return true
		}
		rest = rest[i+1:]
	}
}

func isTagByte(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
	case c >= 'A' && c <= 'Z':
	case c >= 'a' && c <= 'z':
	case c == '.', c == '-', c == '+':
	default:
		return false
	}
	return true
}

// changelogHasTag requires a line whose trimmed text is "## " plus the tag.
// "## Unreleased" and "## v1.2.30" do not satisfy "## v1.2.3".
func changelogHasTag(text, tag string) bool {
	want := "## " + tag
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// peelCommit returns the commit the tag points at. Annotated tags peel
// from the tag object to that commit. Lightweight tags already name it.
func peelCommit(dir, tag string) (string, error) {
	tag, err := canonicalTag(tag)
	if err != nil {
		return "", err
	}
	spec := "refs/tags/" + tag + "^{commit}"
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--end-of-options", spec)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("peel %s: %w", tag, err)
	}
	sha := strings.TrimSpace(string(out))
	if !validCommitSHA(sha) {
		return "", fmt.Errorf("peel %s: %q is not a commit sha", tag, sha)
	}
	return sha, nil
}

func validCommitSHA(sha string) bool {
	if len(sha) != 40 && len(sha) != 64 {
		return false
	}
	for i := 0; i < len(sha); i++ {
		c := sha[i]
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}

type ciRun struct {
	DatabaseID int64  `json:"databaseId"`
	Conclusion string `json:"conclusion"`
	Status     string `json:"status"`
	HeadSHA    string `json:"headSha"`
	Event      string `json:"event"`
	HeadBranch string `json:"headBranch"`
}

type ciJob struct {
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
}

// selectTagRun keeps runs of this tag push and returns the one with the
// highest databaseId. A newer pending run hides an older green one. A
// newer green run hides an older failed one. A main push of the same SHA
// is not a match. A missing run and a run that is not completed are
// retryable. Their text starts with noMatchPrefix or pendingPrefix.
func selectTagRun(runs []ciRun, sha, tag string) (ciRun, error) {
	best := -1
	for i, r := range runs {
		if r.DatabaseID <= 0 || r.Event != "push" || r.HeadSHA != sha || r.HeadBranch != tag {
			continue
		}
		if best < 0 || r.DatabaseID > runs[best].DatabaseID {
			best = i
		}
	}
	if best < 0 {
		return ciRun{}, &retryableError{msg: fmt.Sprintf("%s for tag %s commit %s", noMatchPrefix, tag, sha)}
	}
	chosen := runs[best]
	if chosen.Status != "completed" {
		return ciRun{}, &retryableError{msg: fmt.Sprintf("%s CI run %d for tag %s", pendingPrefix, chosen.DatabaseID, tag)}
	}
	return chosen, nil
}

// judgeJobs requires every required name to appear at least once and every
// occurrence to have conclusion success. skipped, cancelled, failure, and
// a missing name are hard failures. The workflow does not retry them.
func judgeJobs(jobs []ciJob) error {
	got := map[string][]string{}
	for _, j := range jobs {
		got[j.Name] = append(got[j.Name], j.Conclusion)
	}
	var bad []string
	for _, name := range requiredCIJobs {
		conclusions := got[name]
		if len(conclusions) == 0 {
			bad = append(bad, name+"=missing")
			continue
		}
		for _, c := range conclusions {
			if c != "success" {
				bad = append(bad, fmt.Sprintf("%s=%s", name, c))
			}
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("required CI jobs not green: %s", strings.Join(bad, ", "))
	}
	return nil
}

func requireGreenCI() (int64, string, error) {
	tag, err := resolveReleaseTag()
	if err != nil {
		return 0, "", err
	}
	sha, err := peelCommit(".", tag)
	if err != nil {
		return 0, "", err
	}
	if given := strings.TrimSpace(os.Getenv("GITHUB_SHA")); given != "" && given != sha {
		return 0, "", fmt.Errorf("GITHUB_SHA %s is not the peeled commit %s of tag %s", given, sha, tag)
	}
	runs, err := listRuns(sha)
	if err != nil {
		return 0, "", err
	}
	best, err := selectTagRun(runs, sha, tag)
	if err != nil {
		return 0, "", err
	}
	jobs, err := listJobs(best.DatabaseID)
	if err != nil {
		return 0, "", err
	}
	if err := judgeJobs(jobs); err != nil {
		return 0, "", err
	}
	return best.DatabaseID, sha, nil
}

func listRuns(sha string) ([]ciRun, error) {
	if !validCommitSHA(sha) {
		return nil, fmt.Errorf("commit sha %q is not 40 or 64 hex digits", sha)
	}
	repo, err := repoArgs()
	if err != nil {
		return nil, err
	}
	args := []string{"run", "list"}
	args = append(args, repo...)
	args = append(args,
		"--workflow="+ciWorkflow,
		"--commit="+sha,
		"--limit=200",
		"--json", "databaseId,status,conclusion,headSha,event,headBranch",
	)
	out, err := gh(args...)
	if err != nil {
		return nil, fmt.Errorf("gh run list: %w", err)
	}
	return parseRuns(out)
}

func parseRuns(buf []byte) ([]ciRun, error) {
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil, errors.New("gh run list returned an empty body")
	}
	var runs []ciRun
	if err := json.Unmarshal(buf, &runs); err != nil {
		return nil, fmt.Errorf("parse gh run list: %w", err)
	}
	return runs, nil
}

func listJobs(id int64) ([]ciJob, error) {
	if id <= 0 {
		return nil, fmt.Errorf("CI run id %d is not positive", id)
	}
	repo, err := repoArgs()
	if err != nil {
		return nil, err
	}
	args := []string{"run", "view", strconv.FormatInt(id, 10)}
	args = append(args, repo...)
	args = append(args, "--json", "jobs")
	out, err := gh(args...)
	if err != nil {
		return nil, fmt.Errorf("gh run view: %w", err)
	}
	var payload struct {
		Jobs []ciJob `json:"jobs"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil, fmt.Errorf("parse jobs: %w", err)
	}
	return payload.Jobs, nil
}

func gh(args ...string) ([]byte, error) {
	cmd := exec.Command("gh", args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(bytes.TrimSpace(ee.Stderr)) > 0 {
			return nil, fmt.Errorf("%s", bytes.TrimSpace(ee.Stderr))
		}
		return nil, err
	}
	return out, nil
}

// repoArgs passes --repo only when GITHUB_REPOSITORY is a single owner/name.
// An empty value lets gh use the checkout. Anything else is refused.
func repoArgs() ([]string, error) {
	repo := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	if repo == "" {
		return nil, nil
	}
	if !regexp.MustCompile(`^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$`).MatchString(repo) {
		return nil, fmt.Errorf("GITHUB_REPOSITORY %q is not owner/name", repo)
	}
	return []string{"--repo=" + repo}, nil
}

func checkModule() error {
	cmd := exec.Command("go", "list", "-m")
	cmd.Env = environSet("GOTOOLCHAIN", "local")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(bytes.TrimSpace(ee.Stderr)) > 0 {
			return fmt.Errorf("go list -m: %s", bytes.TrimSpace(ee.Stderr))
		}
		return fmt.Errorf("go list -m: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 || fields[0] != modulePath {
		return fmt.Errorf("go list -m: got %q, want %q", strings.TrimSpace(string(out)), modulePath)
	}
	return nil
}

func environSet(key, val string) []string {
	prefix := key + "="
	env := os.Environ()
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+val)
}
