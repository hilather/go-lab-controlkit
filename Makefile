GO ?= go
GOVULNCHECK_MOD ?= golang.org/x/vuln/cmd/govulncheck@v1.1.4
FUZZTIME ?= 10s

.PHONY: help ci fmt-check vet build test test-race fuzz-smoke vulncheck check-gomod

help:
	@printf '%s\n' \
		'Targets (CI runs these through make):' \
		'  fmt-check    gofmt -l must print nothing' \
		'  vet          go vet ./...' \
		'  build        go build ./...' \
		'  test         go test ./...' \
		'  test-race    go test -race ./...' \
		'  fuzz-smoke   every Fuzz target for FUZZTIME (default 10s)' \
		'  vulncheck    govulncheck ./...' \
		'  check-gomod  no replace, go.work, require, toolchain, or nested go.mod; go 1.26' \
		'  ci           all of the above'

ci: fmt-check vet build test-race fuzz-smoke vulncheck check-gomod

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

build:
	$(GO) build ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

fuzz-smoke:
	GO="$(GO)" FUZZTIME="$(FUZZTIME)" scripts/fuzz-smoke.sh

vulncheck:
	$(GO) run $(GOVULNCHECK_MOD) ./...

check-gomod:
	scripts/check-gomod.sh
