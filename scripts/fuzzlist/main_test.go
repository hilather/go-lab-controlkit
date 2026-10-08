package main

import (
	"strings"
	"testing"
)

func TestTargetsFindMultilineSignature(t *testing.T) {
	found, err := Targets("testdata/multiline")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, target := range found {
		if target.Dir != "." {
			t.Fatalf("dir %q", target.Dir)
		}
		got[target.Name] = true
	}
	if !got["FuzzMulti"] || !got["FuzzOne"] || len(got) != 2 {
		t.Fatalf("found %v", got)
	}
	if got["Helper"] || got["FuzzWrong"] {
		t.Fatalf("non-targets included: %v", got)
	}
}

func TestValidateMissingTargetFails(t *testing.T) {
	err := Validate([]Target{{Dir: ".", Name: "FuzzMulti"}}, []string{"FuzzMulti", "FuzzOrigin"})
	if err == nil || !strings.Contains(err.Error(), "FuzzOrigin") {
		t.Fatalf("missing target: %v", err)
	}
	if err := Validate(nil, requiredTargets); err == nil || !strings.Contains(err.Error(), "no fuzz targets") {
		t.Fatalf("zero targets: %v", err)
	}
	found := []Target{
		{Dir: "authn", Name: "FuzzAuthorization"},
		{Dir: "origin", Name: "FuzzOrigin"},
		{Dir: "mcpstrict", Name: "FuzzCheck"},
	}
	if err := Validate(found, requiredTargets); err != nil {
		t.Fatal(err)
	}
}
