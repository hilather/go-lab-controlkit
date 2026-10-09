package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSelectTagRun(t *testing.T) {
	const (
		sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		tag = "v1.2.3"
	)
	match := ciRun{DatabaseID: 10, Status: "completed", Conclusion: "success", HeadSHA: sha, Event: "push", HeadBranch: tag}
	cases := []struct {
		name    string
		runs    []ciRun
		wantID  int64
		wantErr string
	}{
		{name: "match", runs: []ciRun{match}, wantID: 10},
		{
			name:    "wrong event",
			runs:    []ciRun{{DatabaseID: 10, Status: "completed", HeadSHA: sha, Event: "pull_request", HeadBranch: tag}},
			wantErr: "no matching run",
		},
		{
			name:    "workflow dispatch event",
			runs:    []ciRun{{DatabaseID: 10, Status: "completed", HeadSHA: sha, Event: "workflow_dispatch", HeadBranch: tag}},
			wantErr: "no matching run",
		},
		{
			name:    "wrong sha",
			runs:    []ciRun{{DatabaseID: 10, Status: "completed", HeadSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Event: "push", HeadBranch: tag}},
			wantErr: "no matching run",
		},
		{
			name:    "wrong branch",
			runs:    []ciRun{{DatabaseID: 10, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: "main"}},
			wantErr: "no matching run",
		},
		{
			name:    "tag ref is not the branch name",
			runs:    []ciRun{{DatabaseID: 10, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: "refs/tags/v1.2.3"}},
			wantErr: "no matching run",
		},
		{
			name:    "zero id ignored",
			runs:    []ciRun{{DatabaseID: 0, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: tag}},
			wantErr: "no matching run",
		},
		{
			name: "newer pending beats older green",
			runs: []ciRun{
				{DatabaseID: 10, Status: "completed", Conclusion: "success", HeadSHA: sha, Event: "push", HeadBranch: tag},
				{DatabaseID: 30, Status: "in_progress", HeadSHA: sha, Event: "push", HeadBranch: tag},
			},
			wantErr: "pending",
		},
		{
			name: "older in progress does not block newer green",
			runs: []ciRun{
				{DatabaseID: 11, Status: "in_progress", HeadSHA: sha, Event: "push", HeadBranch: tag},
				{DatabaseID: 22, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: tag},
			},
			wantID: 22,
		},
		{
			name: "newer green beats older failed",
			runs: []ciRun{
				{DatabaseID: 10, Status: "completed", Conclusion: "failure", HeadSHA: sha, Event: "push", HeadBranch: tag},
				{DatabaseID: 30, Status: "completed", Conclusion: "success", HeadSHA: sha, Event: "push", HeadBranch: tag},
			},
			wantID: 30,
		},
		{
			name: "newer main run does not hide the tag run",
			runs: []ciRun{
				{DatabaseID: 10, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: tag},
				{DatabaseID: 99, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: "main"},
			},
			wantID: 10,
		},
		{
			name:    "queued is pending",
			runs:    []ciRun{{DatabaseID: 5, Status: "queued", HeadSHA: sha, Event: "push", HeadBranch: tag}},
			wantErr: "pending",
		},
		{
			name:    "waiting is pending",
			runs:    []ciRun{{DatabaseID: 5, Status: "waiting", HeadSHA: sha, Event: "push", HeadBranch: tag}},
			wantErr: "pending",
		},
		{
			name:    "empty status is pending",
			runs:    []ciRun{{DatabaseID: 5, Status: "", HeadSHA: sha, Event: "push", HeadBranch: tag}},
			wantErr: "pending",
		},
		{
			name:   "large id",
			runs:   []ciRun{{DatabaseID: 34860942050, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: tag}},
			wantID: 34860942050,
		},
		{
			name: "order independent",
			runs: []ciRun{
				{DatabaseID: 40, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: tag},
				{DatabaseID: 15, Status: "completed", HeadSHA: sha, Event: "push", HeadBranch: tag},
			},
			wantID: 40,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectTagRun(tc.runs, sha, tag)
			if tc.wantErr != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) || !retryable(err) {
					t.Fatalf("err=%v, want retryable prefix %q", err, tc.wantErr)
				}
				other := noMatchPrefix
				if tc.wantErr == noMatchPrefix {
					other = pendingPrefix
				}
				if strings.HasPrefix(err.Error(), other) {
					t.Fatalf("prefix %q reported as %q: %v", tc.wantErr, other, err)
				}
				return
			}
			if err != nil || got.DatabaseID != tc.wantID {
				t.Fatalf("got id %d err %v, want %d", got.DatabaseID, err, tc.wantID)
			}
		})
	}
}

func TestJudgeJobs(t *testing.T) {
	green := greenJobs(nil)
	cases := []struct {
		name    string
		jobs    []ciJob
		wantErr string
	}{
		{name: "all success", jobs: green},
		{
			name:    "missing job",
			jobs:    dropJob(green, "govulncheck"),
			wantErr: "govulncheck=missing",
		},
		{
			name:    "skipped",
			jobs:    withConclusion(green, "fuzz smoke", "skipped"),
			wantErr: "fuzz smoke=skipped",
		},
		{
			name:    "cancelled",
			jobs:    withConclusion(green, "go vet", "cancelled"),
			wantErr: "go vet=cancelled",
		},
		{
			name:    "failure",
			jobs:    withConclusion(green, "go test -race ./...", "failure"),
			wantErr: "go test -race ./...=failure",
		},
		{
			name:    "empty conclusion",
			jobs:    withConclusion(green, "replace/go.work check", ""),
			wantErr: "replace/go.work check=",
		},
		{
			name: "near-miss names",
			jobs: []ciJob{
				{Name: "go vet ", Conclusion: "success"},
				{Name: "Go vet", Conclusion: "success"},
				{Name: "go  vet", Conclusion: "success"},
				{Name: "go test -race ./..", Conclusion: "success"},
				{Name: "go test -race ./....", Conclusion: "success"},
				{Name: "fuzz-smoke", Conclusion: "success"},
				{Name: "govulncheck ", Conclusion: "success"},
				{Name: "replace/go.work", Conclusion: "success"},
			},
			wantErr: "go vet=missing",
		},
		{
			name:    "duplicate failure",
			jobs:    append(append([]ciJob{}, green...), ciJob{Name: "go vet", Conclusion: "failure"}),
			wantErr: "go vet=failure",
		},
		{
			name: "extra job ignored",
			jobs: append(append([]ciJob{}, green...), ciJob{Name: "apidiff", Conclusion: "failure"}),
		},
		{name: "no jobs", jobs: nil, wantErr: "go vet=missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := judgeJobs(tc.jobs)
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
				t.Fatalf("job error looks retryable: %v", err)
			}
			if tc.name == "near-miss names" {
				for _, name := range requiredCIJobs {
					if !strings.Contains(err.Error(), name+"=missing") {
						t.Errorf("missing %s in %v", name, err)
					}
				}
			}
		})
	}
}

func TestRequireCIWithFakeGH(t *testing.T) {
	repo := annotatedRepo(t)
	t.Chdir(repo.dir)
	t.Setenv("GITHUB_REPOSITORY", "")

	t.Run("accepts peeled tag push", func(t *testing.T) {
		args := installFakeGH(t, oneRun(30, "completed", "success", "push", repo.tag, repo.commit), viewGreen())
		setTagEnv(t, repo.tag, repo.commit)
		id, sha, err := requireGreenCI()
		if err != nil {
			t.Fatal(err)
		}
		if id != 30 || sha != repo.commit {
			t.Fatalf("id %d sha %s", id, sha)
		}
		body := readFile(t, args)
		if !strings.Contains(body, "--workflow=ci.yml") || !strings.Contains(body, "--limit=200") {
			t.Fatalf("args:\n%s", body)
		}
		if !strings.Contains(body, "--commit="+repo.commit) || !strings.Contains(body, "headBranch") {
			t.Fatalf("args:\n%s", body)
		}
	})

	t.Run("tag object sha is not the CI head", func(t *testing.T) {
		installFakeGH(t, oneRun(30, "completed", "success", "push", repo.tag, repo.tagObj), viewShouldNotRun(t))
		setTagEnv(t, repo.tag, repo.commit)
		_, _, err := requireGreenCI()
		if err == nil || !retryable(err) || !strings.HasPrefix(err.Error(), noMatchPrefix+" ") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("github sha must be the peeled commit", func(t *testing.T) {
		installFakeGH(t, oneRun(30, "completed", "success", "push", repo.tag, repo.commit), viewShouldNotRun(t))
		setTagEnv(t, repo.tag, repo.tagObj)
		_, _, err := requireGreenCI()
		if err == nil || !strings.Contains(err.Error(), "not the peeled commit") || retryable(err) {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("green main does not cover a red tag", func(t *testing.T) {
		list := "[" + oneRunObj(11, "completed", "success", "push", "main", repo.commit) + "," +
			oneRunObj(22, "completed", "failure", "push", repo.tag, repo.commit) + "]"
		installFakeGH(t, list, viewOnly(22, jobsJSON(map[string]string{"go vet": "failure"})))
		setTagEnv(t, repo.tag, repo.commit)
		_, _, err := requireGreenCI()
		if err == nil || retryable(err) || !strings.Contains(err.Error(), "not green") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("newer green hides older failed", func(t *testing.T) {
		list := "[" + oneRunObj(10, "completed", "failure", "push", repo.tag, repo.commit) + "," +
			oneRunObj(30, "completed", "success", "push", repo.tag, repo.commit) + "]"
		installFakeGH(t, list, viewOnly(30, jobsJSON(nil)))
		setTagEnv(t, repo.tag, repo.commit)
		id, _, err := requireGreenCI()
		if err != nil || id != 30 {
			t.Fatalf("id %d err %v", id, err)
		}
	})

	t.Run("newer pending hides older green", func(t *testing.T) {
		list := "[" + oneRunObj(10, "completed", "success", "push", repo.tag, repo.commit) + "," +
			oneRunObj(30, "in_progress", "", "push", repo.tag, repo.commit) + "]"
		installFakeGH(t, list, viewShouldNotRun(t))
		setTagEnv(t, repo.tag, repo.commit)
		_, _, err := requireGreenCI()
		if err == nil || !retryable(err) || !strings.HasPrefix(err.Error(), pendingPrefix+" ") || strings.HasPrefix(err.Error(), noMatchPrefix) {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("pull request event", func(t *testing.T) {
		installFakeGH(t, oneRun(11, "completed", "success", "pull_request", repo.tag, repo.commit), viewShouldNotRun(t))
		setTagEnv(t, repo.tag, repo.commit)
		_, _, err := requireGreenCI()
		if err == nil || !retryable(err) || !strings.HasPrefix(err.Error(), noMatchPrefix+" ") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("skipped job is not retried", func(t *testing.T) {
		installFakeGH(t, oneRun(30, "completed", "success", "push", repo.tag, repo.commit), viewConclusion(t, "fuzz smoke", "skipped"))
		setTagEnv(t, repo.tag, repo.commit)
		_, _, err := requireGreenCI()
		if err == nil || !strings.Contains(err.Error(), "fuzz smoke=skipped") || retryable(err) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestPendingPrereleaseIsNotARetrySignal(t *testing.T) {
	const tag = "v0.1.0-pending"
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err := selectTagRun(nil, sha, tag)
	if err == nil || !retryable(err) || !strings.HasPrefix(err.Error(), noMatchPrefix+" ") {
		t.Fatalf("missing run: %v", err)
	}
	if strings.HasPrefix(err.Error(), pendingPrefix) {
		t.Fatalf("missing run used the pending prefix: %v", err)
	}
	_, err = selectTagRun([]ciRun{{
		DatabaseID: 4, Status: "queued", HeadSHA: sha, Event: "push", HeadBranch: tag,
	}}, sha, tag)
	if err == nil || !retryable(err) || !strings.HasPrefix(err.Error(), pendingPrefix+" ") {
		t.Fatalf("pending run: %v", err)
	}

	repo := annotatedTag(t, tag)

	t.Run("sha mismatch exits 1", func(t *testing.T) {
		t.Chdir(repo.dir)
		installFakeGH(t, "[]", viewShouldNotRun(t))
		setTagEnv(t, tag, repo.tagObj)
		code, msg := runRequireCI(t)
		if code != 1 || retryableText(msg) || !strings.Contains(msg, "not the peeled commit") || !strings.Contains(msg, tag) {
			t.Fatalf("code %d\n%s", code, msg)
		}
	})

	t.Run("missing tag peel exits 1", func(t *testing.T) {
		dir := t.TempDir()
		git(t, dir, "init", "-b", "main")
		t.Chdir(dir)
		setTagEnv(t, tag, repo.commit)
		code, msg := runRequireCI(t)
		if code != 1 || retryableText(msg) || !strings.Contains(msg, "peel "+tag) {
			t.Fatalf("code %d\n%s", code, msg)
		}
	})

	t.Run("pending run exits 75", func(t *testing.T) {
		t.Chdir(repo.dir)
		installFakeGH(t, oneRun(30, "in_progress", "", "push", tag, repo.commit), viewShouldNotRun(t))
		setTagEnv(t, tag, repo.commit)
		code, msg := runRequireCI(t)
		if code != exitRetryable || !strings.HasPrefix(msg, "release-gate: "+pendingPrefix+" ") || !strings.Contains(msg, tag) {
			t.Fatalf("code %d\n%s", code, msg)
		}
	})

	t.Run("no matching run exits 75", func(t *testing.T) {
		t.Chdir(repo.dir)
		installFakeGH(t, "[]", viewShouldNotRun(t))
		setTagEnv(t, tag, repo.commit)
		code, msg := runRequireCI(t)
		if code != exitRetryable || !strings.HasPrefix(msg, "release-gate: "+noMatchPrefix+" ") || !strings.Contains(msg, tag) {
			t.Fatalf("code %d\n%s", code, msg)
		}
		if strings.HasPrefix(msg, "release-gate: "+pendingPrefix) {
			t.Fatalf("no matching run used the pending prefix:\n%s", msg)
		}
	})

	t.Run("failed job exits 1", func(t *testing.T) {
		t.Chdir(repo.dir)
		installFakeGH(t, oneRun(30, "completed", "success", "push", tag, repo.commit), viewConclusion(t, "go vet", "failure"))
		setTagEnv(t, tag, repo.commit)
		code, msg := runRequireCI(t)
		if code != 1 || retryableText(msg) || !strings.Contains(msg, "not green") {
			t.Fatalf("code %d\n%s", code, msg)
		}
	})
}

func runRequireCI(t *testing.T) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run([]string{"-require-ci"}, &out, &errb)
	return code, errb.String()
}

func TestParseRunsIgnoresExtraFields(t *testing.T) {
	buf := []byte(`[{"databaseId":7,"conclusion":"success","status":"completed","headSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","event":"push","headBranch":"v1.2.3","displayTitle":"tag"}]`)
	runs, err := parseRuns(buf)
	if err != nil || len(runs) != 1 || runs[0].DatabaseID != 7 || runs[0].HeadBranch != "v1.2.3" {
		t.Fatalf("runs=%v err=%v", runs, err)
	}
	if _, err := parseRuns([]byte("not-json")); err == nil {
		t.Fatal("accepted junk")
	}
}

type taggedRepo struct {
	dir    string
	commit string
	tagObj string
	tag    string
}

func annotatedRepo(t *testing.T) taggedRepo {
	t.Helper()
	return annotatedTag(t, "v1.2.3")
}

func annotatedTag(t *testing.T, tag string) taggedRepo {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "f")
	git(t, dir, "commit", "--no-gpg-sign", "-m", "init")
	commit := git(t, dir, "rev-parse", "HEAD")
	git(t, dir, "tag", "--no-sign", "-a", "-m", tag, tag)
	obj := git(t, dir, "rev-parse", "refs/tags/"+tag)
	if obj == commit {
		t.Fatal("tag was not annotated")
	}
	return taggedRepo{dir: dir, commit: commit, tagObj: obj, tag: tag}
}

func setTagEnv(t *testing.T, tag, sha string) {
	t.Helper()
	t.Setenv("GITHUB_REF", "refs/tags/"+tag)
	t.Setenv("GITHUB_REF_NAME", tag)
	t.Setenv("GITHUB_SHA", sha)
	t.Setenv("GITHUB_REPOSITORY", "")
}

func installFakeGH(t *testing.T, listJSON, viewBody string) string {
	t.Helper()
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&b, "printf '%%s\\n' \"$*\" >> %s\n", strconv.Quote(argsPath))
	b.WriteString("case \"$1 $2\" in\n")
	b.WriteString("\"run list\")\ncat <<'EOF'\n")
	b.WriteString(strings.TrimSpace(listJSON))
	b.WriteString("\nEOF\n;;\n\"run view\")\n")
	b.WriteString(viewBody)
	if !strings.HasSuffix(viewBody, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString(";;\n*)\necho \"unexpected: $*\" >&2\nexit 2\n;;\nesac\n")
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(b.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argsPath
}

func oneRun(id int, status, conclusion, event, branch, sha string) string {
	return "[" + oneRunObj(id, status, conclusion, event, branch, sha) + "]"
}

func oneRunObj(id int, status, conclusion, event, branch, sha string) string {
	return fmt.Sprintf(`{"databaseId":%d,"conclusion":%q,"status":%q,"headSha":%q,"event":%q,"headBranch":%q}`,
		id, conclusion, status, sha, event, branch)
}

func greenJobs(overrides map[string]string) []ciJob {
	jobs := make([]ciJob, 0, len(requiredCIJobs))
	for _, name := range requiredCIJobs {
		c := "success"
		if overrides != nil {
			if v, ok := overrides[name]; ok {
				c = v
			}
		}
		jobs = append(jobs, ciJob{Name: name, Conclusion: c})
	}
	return jobs
}

func jobsJSON(overrides map[string]string) string {
	jobs := greenJobs(overrides)
	var b strings.Builder
	b.WriteString("{\"jobs\":[")
	for i, j := range jobs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":%q,"conclusion":%q}`, j.Name, j.Conclusion)
	}
	b.WriteString("]}")
	return b.String()
}

func viewGreen() string {
	return "cat <<'EOF'\n" + jobsJSON(nil) + "\nEOF\n"
}

func viewShouldNotRun(t *testing.T) string {
	t.Helper()
	return "echo \"view should not be called: $*\" >&2\nexit 1\n"
}

func viewOnly(id int, body string) string {
	return fmt.Sprintf("case \"$3\" in\n%d)\ncat <<'EOF'\n%s\nEOF\n;;\n*)\necho unexpected id \"$3\" >&2\nexit 1\n;;\nesac\n", id, body)
}

func viewConclusion(t *testing.T, name, conclusion string) string {
	t.Helper()
	return "cat <<'EOF'\n" + jobsJSON(map[string]string{name: conclusion}) + "\nEOF\n"
}

func dropJob(jobs []ciJob, name string) []ciJob {
	var out []ciJob
	for _, j := range jobs {
		if j.Name != name {
			out = append(out, j)
		}
	}
	return out
}

func withConclusion(jobs []ciJob, name, conclusion string) []ciJob {
	out := append([]ciJob{}, jobs...)
	for i := range out {
		if out[i].Name == name {
			out[i].Conclusion = conclusion
		}
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
