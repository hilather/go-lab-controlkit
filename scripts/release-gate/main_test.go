package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalTag(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "v1.2.3", want: "v1.2.3", ok: true},
		{in: "v0.1.0", want: "v0.1.0", ok: true},
		{in: "v1.2.3-rc.1", want: "v1.2.3-rc.1", ok: true},
		{in: "v1.2.3-rc.1.2", want: "v1.2.3-rc.1.2", ok: true},
		{in: "v10.20.30", want: "v10.20.30", ok: true},
		{in: "refs/tags/v1.2.3", want: "v1.2.3", ok: true},
		{in: "  refs/tags/v1.2.3-rc.1\n", want: "v1.2.3-rc.1", ok: true},
		{in: "v1", ok: false},
		{in: "v1.2", ok: false},
		{in: "v1.2.3;rm", ok: false},
		{in: "v1.2.3;rm -rf /", ok: false},
		{in: "refs/tags/v1.2.3;rm", ok: false},
		{in: "refs/tags/v1", ok: false},
		{in: "refs/tags/v1.2", ok: false},
		{in: "refs/heads/v1.2.3", ok: false},
		{in: "refs/tags/refs/tags/v1.2.3", ok: false},
		{in: "v1.2.3+meta", ok: false},
		{in: "V1.2.3", ok: false},
		{in: "", ok: false},
		{in: "refs/tags/", ok: false},
		{in: "v1.2.3-", ok: false},
		{in: "v1.2.3-rc_1", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := canonicalTag(tc.in)
			if tc.ok {
				if err != nil || got != tc.want {
					t.Fatalf("got %q err %v", got, err)
				}
				notes := expectedNotes(got)
				if notes != "docs/releases/"+tc.want+".md" {
					t.Fatalf("notes path %s", notes)
				}
				if strings.Contains(notes, "refs/tags") || strings.Contains(notes, ";") {
					t.Fatalf("notes path kept an untrusted prefix: %s", notes)
				}
				return
			}
			if err == nil {
				t.Fatalf("got %q, want error", got)
			}
			if retryable(err) {
				t.Fatalf("tag error looks retryable: %v", err)
			}
		})
	}
}

func TestResolveReleaseTag(t *testing.T) {
	cases := []struct {
		name string
		ref  string
		tag  string
		want string
		ok   bool
	}{
		{name: "tag ref", ref: "refs/tags/v1.2.3", tag: "v1.2.3", want: "v1.2.3", ok: true},
		{name: "dispatch name", ref: "refs/heads/main", tag: "v1.2.3", want: "v1.2.3", ok: true},
		{name: "name has prefix", ref: "refs/heads/main", tag: "refs/tags/v1.2.3", want: "v1.2.3", ok: true},
		{name: "ref only", ref: "refs/tags/v0.1.0", want: "v0.1.0", ok: true},
		{name: "branch name", ref: "refs/heads/main", tag: "main", ok: false},
		{name: "empty", ok: false},
		{name: "short", ref: "refs/tags/v1", tag: "v1", ok: false},
		{name: "two parts", ref: "refs/tags/v1.2", tag: "v1.2", ok: false},
		{name: "injection ref", ref: "refs/tags/v1.2.3;rm", tag: "v1.2.3", ok: false},
		{name: "injection name", ref: "refs/tags/v1.2.3", tag: "v1.2.3;rm", ok: false},
		{name: "disagree", ref: "refs/tags/v1.2.3", tag: "v1.2.4", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_REF", tc.ref)
			t.Setenv("GITHUB_REF_NAME", tc.tag)
			got, err := resolveReleaseTag()
			if tc.ok {
				if err != nil || got != tc.want {
					t.Fatalf("got %q err %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("got %q, want error", got)
			}
			if retryable(err) {
				t.Fatalf("resolve error looks retryable: %v", err)
			}
		})
	}
}

func TestValidateRelease(t *testing.T) {
	cases := []struct {
		name      string
		tag       string
		notes     string
		missing   bool
		changelog string
		noChange  bool
		wantErr   string
	}{
		{
			name:      "present",
			tag:       "v1.2.3",
			notes:     "# v1.2.3\n\nShipped.\n",
			changelog: "# Changelog\n\n## Unreleased\n\n## v1.2.3\n\n- x\n",
		},
		{
			name:      "heading with surrounding text",
			tag:       "v1.2.3-rc.1",
			notes:     "## Release v1.2.3-rc.1\n",
			changelog: "## v1.2.3-rc.1\n",
		},
		{
			name:      "trailing space on changelog line",
			tag:       "v0.1.0",
			notes:     "# v0.1.0\n",
			changelog: "## v0.1.0 \n",
		},
		{
			name:      "missing notes",
			tag:       "v1.2.3",
			missing:   true,
			changelog: "## v1.2.3\n",
			wantErr:   "missing release notes",
		},
		{
			name:      "unreleased only",
			tag:       "v1.2.3",
			notes:     "# v1.2.3\n",
			changelog: "# Changelog\n\n## Unreleased\n\n### Added\n",
			wantErr:   "## v1.2.3",
		},
		{
			name:      "near version heading",
			tag:       "v1.2.3",
			notes:     "# v1.2.3\n",
			changelog: "## v1.2.30\n## v1.2.3-rc.1\n",
			wantErr:   "## v1.2.3",
		},
		{
			name:      "prose is not a heading",
			tag:       "v1.2.3",
			notes:     "# Release\n\nv1.2.3 is mentioned in prose only.\n",
			changelog: "## v1.2.3\n",
			wantErr:   "heading",
		},
		{
			name:      "near tag in the heading",
			tag:       "v1.2.3",
			notes:     "# v1.2.30\n",
			changelog: "## v1.2.3\n",
			wantErr:   "heading",
		},
		{
			name:      "empty notes",
			tag:       "v1.2.3",
			notes:     "\n\n",
			changelog: "## v1.2.3\n",
			wantErr:   "heading",
		},
		{
			name:      "fenced heading alone",
			tag:       "v1.2.3",
			notes:     "```\n# v1.2.3\n```\n",
			changelog: "## v1.2.3\n",
			wantErr:   "heading",
		},
		{
			name:      "heading after a fence",
			tag:       "v1.2.3",
			notes:     "```\n# v1.2.3\n```\n\n# v1.2.3\n",
			changelog: "## v1.2.3\n",
		},
		{
			name:      "pending pre-release without a heading",
			tag:       "v0.1.0-pending",
			notes:     "# Release\n\nThe sample tag is not a heading.\n",
			changelog: "## v0.1.0-pending\n",
			wantErr:   "heading",
		},
		{
			name:     "missing changelog",
			tag:      "v1.2.3",
			notes:    "# v1.2.3\n",
			noChange: true,
			wantErr:  "changelog",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			if !tc.missing {
				if err := os.MkdirAll(filepath.Dir(expectedNotes(tc.tag)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(expectedNotes(tc.tag), []byte(tc.notes), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.noChange {
				if err := os.WriteFile("CHANGELOG.md", []byte(tc.changelog), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := validateRelease(tc.tag, expectedNotes(tc.tag), "CHANGELOG.md")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want %q", err, tc.wantErr)
			}
			if retryable(err) {
				t.Fatalf("notes error looks retryable: %v", err)
			}
		})
	}
}

func TestNotesMentionTagFences(t *testing.T) {
	const tag = "v1.2.3"
	cases := []struct {
		name string
		text string
		want bool
	}{
		{name: "fenced heading alone", text: "```\n# v1.2.3\n```\n", want: false},
		{name: "tilde fence", text: "~~~\n# v1.2.3\n~~~\n", want: false},
		{name: "real heading", text: "# v1.2.3\n", want: true},
		{name: "fence then real heading", text: "```\n# v1.2.3\n```\n# v1.2.3\n", want: true},
		{name: "real heading then fence", text: "# v1.2.3\n```\n# v9.9.9\n```\n", want: true},
		{name: "unclosed fence hides a later heading", text: "```\n# v1.2.3\n", want: false},
		{name: "short close stays open", text: "````\n# v1.2.3\n```\n# v1.2.3\n", want: false},
		{name: "long close then heading", text: "```\n# v1.2.3\n````\n# v1.2.3\n", want: true},
		{name: "info string", text: "```markdown\n# v1.2.3\n```\n", want: false},
		{name: "info string is not a heading", text: "``` # v1.2.3\n", want: false},
		{name: "mismatched closer", text: "~~~\n# v1.2.3\n```\n# v1.2.3\n", want: false},
		{name: "closer with trailing text", text: "```\n# v1.2.3\n``` text\n# v1.2.3\n", want: false},
		{name: "indented fence", text: "   ```\n# v1.2.3\n   ```\n", want: false},
		{name: "heading outside an indented fence", text: "   ```\n# sample\n   ```\n# v1.2.3\n", want: true},
		{name: "crlf heading", text: "# v1.2.3\r\n", want: true},
		{name: "near tag still fails", text: "# v1.2.30\n", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := notesMentionTag(tc.text, tag); got != tc.want {
				t.Fatalf("notesMentionTag=%v, want %v\n%s", got, tc.want, tc.text)
			}
		})
	}
}

func TestValidateReleaseRejectsEscapingPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("CHANGELOG.md", []byte("## v1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := validateRelease("v1.2.3", "docs/releases/../CHANGELOG.md", "CHANGELOG.md")
	if err == nil || !strings.Contains(err.Error(), "notes path") {
		t.Fatalf("err=%v", err)
	}
	err = validateRelease("refs/tags/v1.2.3", "docs/releases/refs/tags/v1.2.3.md", "CHANGELOG.md")
	if err == nil || !strings.Contains(err.Error(), "docs/releases/v1.2.3.md") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunNotesAndUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("usage code %d %s", code, errb.String())
	}
	if retryableText(errb.String()) {
		t.Fatal(errb.String())
	}
	errb.Reset()
	if code := run([]string{"-notes-only", "-require-ci"}, &out, &errb); code != 2 {
		t.Fatalf("both modes code %d", code)
	}
	errb.Reset()
	if code := run([]string{"-notes-only", "-tag", "v1.2.3;rm", "-notes", "docs/releases/v1.2.3.md"}, &out, &errb); code != 1 {
		t.Fatalf("injection code %d %s", code, errb.String())
	}
	if retryableText(errb.String()) || strings.Contains(errb.String(), "docs/releases/v1.2.3;rm.md") {
		t.Fatal(errb.String())
	}

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll("docs/releases", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("docs/releases/v1.2.3.md", []byte("# v1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("CHANGELOG.md", []byte("## Unreleased\n\n## v1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code := run([]string{"-notes-only", "-tag", "refs/tags/v1.2.3", "-notes", "docs/releases/v1.2.3.md"}, &out, &errb)
	if code != 0 {
		t.Fatalf("notes code %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "notes ok for v1.2.3") {
		t.Fatal(out.String())
	}
}

func TestRunModule(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-module"}, &out, &errb)
	if code != 0 {
		t.Fatalf("module code %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), modulePath) {
		t.Fatal(out.String())
	}
}

func TestPeelAnnotatedAndLightweight(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "f")
	git(t, dir, "commit", "--no-gpg-sign", "-m", "init")
	commit := git(t, dir, "rev-parse", "HEAD")
	git(t, dir, "tag", "--no-sign", "-a", "-m", "v1.2.3", "v1.2.3")
	obj := git(t, dir, "rev-parse", "refs/tags/v1.2.3")
	peeled, err := peelCommit(dir, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if peeled != commit {
		t.Fatalf("peeled %s, commit %s", peeled, commit)
	}
	if peeled == obj {
		t.Fatal("annotated tag did not peel off the tag object")
	}
	git(t, dir, "tag", "v1.2.4")
	light, err := peelCommit(dir, "v1.2.4")
	if err != nil {
		t.Fatal(err)
	}
	lightObj := git(t, dir, "rev-parse", "refs/tags/v1.2.4")
	if light != commit || light != lightObj {
		t.Fatalf("lightweight peel %s obj %s commit %s", light, lightObj, commit)
	}
	if _, err := peelCommit(dir, "v1"); err == nil || retryable(err) {
		t.Fatalf("short tag peel err=%v", err)
	}
}

func TestRejectTagDoesNotRunGit(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "git")
	body := "#!/bin/sh\necho called >&2\nexit 9\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("GITHUB_REF", "refs/tags/v1.2.3;rm")
	t.Setenv("GITHUB_REF_NAME", "v1.2.3;rm")
	t.Setenv("GITHUB_REPOSITORY", "")
	_, _, err := requireGreenCI()
	if err == nil || strings.Contains(err.Error(), "called") || retryable(err) {
		t.Fatalf("err=%v", err)
	}
}

func TestRepoArgs(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "")
	args, err := repoArgs()
	if err != nil || len(args) != 0 {
		t.Fatalf("args=%v err=%v", args, err)
	}
	t.Setenv("GITHUB_REPOSITORY", "hilather/go-lab-controlkit")
	args, err = repoArgs()
	if err != nil || len(args) != 1 || args[0] != "--repo=hilather/go-lab-controlkit" {
		t.Fatalf("args=%v err=%v", args, err)
	}
	for _, bad := range []string{"not a repo", "owner/name;rm", "owner/name extra", "-h"} {
		t.Setenv("GITHUB_REPOSITORY", bad)
		if _, err := repoArgs(); err == nil || retryable(err) {
			t.Fatalf("%q err=%v", bad, err)
		}
	}
}

func TestWorkflowRunScriptsDoNotInterpolate(t *testing.T) {
	for _, name := range []string{"release.yml", "ci.yml"} {
		body := readWorkflow(t, name)
		if lines := runInterpolationLines(body); len(lines) > 0 {
			t.Errorf("%s interpolates actions expressions in run: at lines %v", name, lines)
		}
	}
}

func TestRunInterpolationDetector(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{name: "inline run", yaml: "        run: echo ${{ github.ref }}\n", want: 1},
		{name: "block run", yaml: "        run: |\n          echo ${{ github.ref }}\n", want: 1},
		{name: "with", yaml: "        with:\n          ref: ${{ github.ref }}\n", want: 0},
		{name: "concurrency", yaml: "concurrency:\n  group: ${{ github.ref }}\n", want: 0},
		{name: "blank line in block", yaml: "        run: |\n          echo ok\n\n          echo ${{ github.ref }}\n", want: 1},
		{name: "env row", yaml: "        env:\n          REF: ${{ github.ref }}\n        run: echo \"$REF\"\n", want: 0},
		{name: "comment", yaml: "# run: echo ${{ github.ref }}\n", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runInterpolationLines(tc.yaml)
			if len(got) != tc.want {
				t.Fatalf("hits=%v want %d", got, tc.want)
			}
		})
	}
}

func TestWorkflowContract(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	rel := readWorkflow(t, "release.yml")
	if !strings.Contains(ci, "github.event.pull_request.number || github.ref") {
		t.Fatal("ci concurrency must use github.ref so a tag and a branch do not share a group")
	}
	if strings.Contains(ci, "github.ref_name") {
		t.Fatal("ci.yml uses github.ref_name")
	}
	if strings.Contains(rel, "github.ref_name") {
		t.Fatal("release.yml uses github.ref_name inside an expression")
	}
	if !strings.Contains(ci, "tags:\n      - \"v*\"") && !strings.Contains(ci, "tags:\n      - \"v*\"\r") {
		t.Fatal("ci.yml does not run on v* tags")
	}
	for _, name := range requiredCIJobs {
		if !strings.Contains(ci, "name: "+name+"\n") {
			t.Errorf("ci.yml missing job name %q", name)
		}
	}
	for _, pin := range []string{
		"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
		"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0",
	} {
		if !strings.Contains(ci, pin) || !strings.Contains(rel, pin) {
			t.Errorf("pin missing from both workflows: %s", pin)
		}
	}
	if !strings.Contains(rel, "re='"+releaseTagPatternSrc+"'") {
		t.Fatal("shell tag pattern drifted from releaseTagPattern")
	}
	if !strings.Contains(rel, "refs/tags/${ref}^{commit}") {
		t.Fatal("workflow does not peel the tag")
	}
	if strings.Count(rel, "re='"+releaseTagPatternSrc+"'") != 2 {
		t.Fatal("tag pattern must be checked before checkout and again before peel")
	}
	canon := strings.Index(rel, "\n      - name: Canonicalize release ref\n")
	checkout := strings.Index(rel, "\n      - uses: actions/checkout@")
	if canon < 0 || checkout < 0 || canon > checkout {
		t.Fatal("canonicalize step must precede checkout")
	}
	if !strings.Contains(rel, "ref: refs/tags/${{ steps.tag.outputs.ref }}") {
		t.Fatal("checkout ref is not refs/tags/<canonical tag>")
	}
	if strings.Contains(rel, "ref: ${{ github.event.inputs.ref || github.ref }}") {
		t.Fatal("checkout still receives the raw ref")
	}
	wantStatus := fmt.Sprintf(`[ "$status" -eq %d ]`, exitRetryable)
	if !strings.Contains(rel, wantStatus) {
		t.Fatalf("workflow retry status drifted from exit %d", exitRetryable)
	}
	if strings.Contains(rel, "*pending*") || strings.Contains(rel, `*"no matching run"*`) {
		t.Fatal("workflow still retries on a substring of command output")
	}
	if !strings.Contains(rel, "contents: read") || !strings.Contains(rel, "actions: read") {
		t.Fatal("release permissions")
	}
	for _, banned := range []string{"contents: write", "packages:", "publish-image", "id-token:", "secrets."} {
		if strings.Contains(rel, banned) {
			t.Errorf("release.yml contains %q", banned)
		}
	}
	if !strings.Contains(rel, "cancel-in-progress: false") {
		t.Fatal("release concurrency must not cancel")
	}
	if strings.Contains(rel, "checks: read") {
		t.Fatal("checks: read is unused; the gate reads Actions runs")
	}
}

func retryableText(msg string) bool {
	for _, line := range strings.Split(msg, "\n") {
		if strings.HasPrefix(line, "release-gate: "+pendingPrefix) || strings.HasPrefix(line, "release-gate: "+noMatchPrefix) {
			return true
		}
	}
	return false
}

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, ".github", "workflows", name)
		b, err := os.ReadFile(p)
		if err == nil {
			return string(b)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("workflow %s not found", name)
	return ""
}

func runInterpolationLines(text string) []int {
	lines := strings.Split(text, "\n")
	var hits []int
	inRun := false
	runIndent := 0
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if inRun {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if indentOf(line) <= runIndent {
				inRun = false
				i--
				continue
			}
			if strings.Contains(line, "${{") {
				hits = append(hits, i+1)
			}
			continue
		}
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(strings.TrimLeft(line, " "), "run:")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		switch rest {
		case "|", "|-", "|+", ">", ">-", ">+":
			inRun = true
			runIndent = indentOf(line)
		default:
			if strings.Contains(rest, "${{") {
				hits = append(hits, i+1)
			}
		}
	}
	return hits
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=release-gate",
		"GIT_AUTHOR_EMAIL=release-gate@example.com",
		"GIT_COMMITTER_NAME=release-gate",
		"GIT_COMMITTER_EMAIL=release-gate@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
