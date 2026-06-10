GO            ?= go
PKGS          := ./...
COVERPROFILE  := coverage.out
WASM_OUT      := web/demo/gentxvalidate.wasm
WASM_BUDGET   := 2097152 # 2 MB gzipped
WASM_EXEC_DIR  = $(shell $(GO) env GOROOT)/lib/wasm

.DEFAULT_GOAL := check

.PHONY: help
help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'

.PHONY: check
check: lint test ## Lint then test (default)

.PHONY: test
test: ## Run all tests
	$(GO) test $(PKGS) --count=1

.PHONY: test-v
test-v: ## Run all tests, verbose
	$(GO) test $(PKGS) -v --count=1

.PHONY: cover
cover: ## Run tests with coverage summary
	$(GO) test $(PKGS) -cover --count=1

.PHONY: cover-html
cover-html: ## Open per-line coverage report in the browser
	$(GO) test $(PKGS) -coverprofile=$(COVERPROFILE) --count=1
	$(GO) tool cover -html=$(COVERPROFILE)

.PHONY: lint
lint: ## Run golangci-lint (cleans lint cache first)
	golangci-lint cache clean
	golangci-lint run

.PHONY: lint-fix
lint-fix: ## Run golangci-lint with autofix (cleans lint cache first)
	golangci-lint cache clean
	golangci-lint run --fix

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: wasm
wasm: ## Build the browser blob and copy the matching wasm_exec.js
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags="-s -w" -o $(WASM_OUT) ./cmd/gentxvalidate-wasm
	cp "$(WASM_EXEC_DIR)/wasm_exec.js" web/demo/wasm_exec.js

.PHONY: wasm-size
wasm-size: wasm ## Gzip the blob and fail if over the 2 MB budget
	@gzip -9 -c $(WASM_OUT) > $(WASM_OUT).gz
	@size=$$(wc -c < $(WASM_OUT).gz); \
	echo "wasm blob: $$size bytes gzipped (budget $(WASM_BUDGET))"; \
	if [ "$$size" -gt "$(WASM_BUDGET)" ]; then echo "FAIL: over budget"; exit 1; fi

.PHONY: test-wasm
test-wasm: ## Run the full test suite in the WASM runtime (requires Node)
	@command -v node >/dev/null || { echo "test-wasm: node not installed, skipping"; exit 0; }
	GOOS=js GOARCH=wasm $(GO) test $(PKGS) --count=1 -exec="$(WASM_EXEC_DIR)/go_js_wasm_exec"