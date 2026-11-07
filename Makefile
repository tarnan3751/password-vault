# Family Vault
GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all help build test race sim chaos bench vectors web dev fmt vet clean cross

all: build

help: ## list the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/^([a-z-]+):.*## (.*)/  make \1\t\2/' | expand -t 16

build: ## build vaultd, fvault and vault-chaos into ./bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

test: ## unit + integration tests
	$(GO) test ./...

race: ## tests under the race detector
	$(GO) test -race ./...

sim: ## long deterministic Raft simulation (override SEEDS=...)
	RAFT_SIM_SEEDS=$(or $(SEEDS),5000) $(GO) test ./internal/raft/ -run Sim -count=1 -timeout 60m

chaos: build ## whole-system fault injection checked with Porcupine (override ARGS=...)
	./bin/vault-chaos $(ARGS)

bench: ## benchmarks: end to end (three in-process nodes), then per package
	$(GO) test ./internal/chaos -run '^$$' -bench . -benchtime 3s
	$(GO) test ./internal/fsm ./internal/server ./internal/client ./internal/vaultcrypto ./internal/backup -run '^$$' -bench . -benchmem

vectors: ## regenerate the shared crypto test vectors
	$(GO) run ./cmd/gen-vectors

web: ## rebuild the browser client into web/dist (needs Node.js)
	cd web && npm ci && npm test && npm run build

dev: ## run a local three-node insecure cluster
	scripts/dev-cluster.sh

cross: ## cross-compile the server for a Raspberry Pi and a Linux VPS
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/linux-arm64/ ./cmd/vaultd ./cmd/fvault
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/linux-amd64/ ./cmd/vaultd ./cmd/fvault

fmt: ## format the Go code
	gofmt -l -w .

vet: ## static checks
	$(GO) vet ./...

clean: ## remove built binaries and the dev cluster's data
	rm -rf bin .dev
