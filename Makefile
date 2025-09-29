# Define the repository root
REPO_ROOT=$(shell git rev-parse --show-toplevel)

# Ensure bin directory exists
BIN_DIR := $(REPO_ROOT)/bin
$(shell mkdir -p $(BIN_DIR))

GOPRIVATE = github.com/riptidesio,go.riptides.io

# Dependency versions
LICENSEI_VERSION = 0.9.0
GOLANGCI_VERSION = 2.0.2
LICSENSEI_VERSION = 0.0.1

.PHONY: help
.DEFAULT_GOAL := help
help:
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: fmt
fmt: ## Run go fmt against code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code
	go vet ./...

.PHONY: test
test: ## Run tests
	go test ./... -count=1

.PHONY: tidy
tidy: ## Execute go mod tidy
	GOPRIVATE=${GOPRIVATE} go mod tidy
	GOPRIVATE=${GOPRIVATE} go mod download all

${BIN_DIR}/golangci-lint-${GOLANGCI_VERSION}:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | bash -s v${GOLANGCI_VERSION}
	@mv ${BIN_DIR}/golangci-lint $@

${BIN_DIR}/golangci-lint: ${BIN_DIR}/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} ${BIN_DIR}/golangci-lint

.PHONY: lint
lint: ${BIN_DIR}/golangci-lint ## Run linter
# "unused" linter is a memory hog, but running it separately keeps it contained (probably because of caching)
	${BIN_DIR}/golangci-lint run --disable=unused -c ${REPO_ROOT}/.golangci.yaml --timeout 10m
	${BIN_DIR}/golangci-lint run -c ${REPO_ROOT}/.golangci.yaml --timeout 10m

.PHONY: lint-fix
lint-fix: ${BIN_DIR}/golangci-lint ## Run linter
	@${BIN_DIR}/golangci-lint run -c ${REPO_ROOT}/.golangci.yaml --fix --timeout 2m

${BIN_DIR}/licensei: ${BIN_DIR}/licensei-${LICENSEI_VERSION}
	@ln -sf licensei-${LICENSEI_VERSION} ${BIN_DIR}/licensei

${BIN_DIR}/licensei-${LICENSEI_VERSION}:
	curl -sfL git.io/licensei | bash -s v${LICENSEI_VERSION}
	mv ${BIN_DIR}/licensei $@

.PHONY: license-check
license-check: ${BIN_DIR}/licensei ## Run license check
	${BIN_DIR}/licensei --config ${REPO_ROOT}/.licensei.toml check

.PHONY: license-cache
license-cache: ${BIN_DIR}/licensei ## Generate license cache
	${BIN_DIR}/licensei --config ${REPO_ROOT}/.licensei.toml cache

${REPO_ROOT}/bin/licsensei: ${REPO_ROOT}/bin/licsensei-${LICSENSEI_VERSION}
	@ln -sf licsensei-${LICSENSEI_VERSION} ${REPO_ROOT}/bin/licsensei

${REPO_ROOT}/bin/licsensei-${LICSENSEI_VERSION}:
	@mkdir -p ${REPO_ROOT}/bin
	@mkdir -p bin
	curl -sfL https://raw.githubusercontent.com/gezacorp/licsensei/main/install.sh | bash -s v${LICSENSEI_VERSION}
	mv bin/licsensei $@

.PHONY: license-header-check
license-header-check: ${REPO_ROOT}/bin/licsensei ## Run license check
	${REPO_ROOT}/bin/licsensei --config ${REPO_ROOT}/.licsensei.yaml