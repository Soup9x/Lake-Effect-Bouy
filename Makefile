VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test test-integration lint fmt vet dist sign clean

all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/clamav-console ./cmd/server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/clamav-agent ./cmd/agent

test:
	go test -race ./...

# Needs a Postgres role that can CREATE DATABASE, e.g.
#   TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres make test-integration
test-integration:
	@test -n "$(TEST_DATABASE_URL)" || (echo "TEST_DATABASE_URL is required" && exit 1)
	go test -race -count=1 ./internal/server/...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w cmd internal db

vet:
	go vet ./...

# Build agent binaries and install scripts into dist/downloads (unsigned).
dist:
	VERSION=$(VERSION) ./scripts/build-dist.sh

# Sign dist/downloads with the offline release key. Run on the release workstation.
sign:
	./scripts/sign-dist.sh

clean:
	rm -rf bin dist
