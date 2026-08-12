# mysql-old-password-proxy
#
# Build output goes to bin/ (git-ignored). deploy/ holds Kubernetes manifests
# only — nothing is built into it.

BINARY      := mysql-old-password-proxy
BIN_DIR     := bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_SHA     := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

# Docker Hub coordinates. Override REGISTRY to push to an internal mirror:
#   make docker-push REGISTRY=registry.internal.example.com
DOCKER_USER ?= ralforion
REGISTRY    ?= docker.io
IMAGE       ?= $(REGISTRY)/$(DOCKER_USER)/$(BINARY)
PLATFORMS   ?= linux/amd64,linux/arm64

GO          ?= go
LDFLAGS     := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

## help: list the targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F': ' '{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

## build: compile the binary into bin/
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) .
	@echo "built $(BIN_DIR)/$(BINARY) $(VERSION)"

## test: unit tests, with the race detector
test:
	$(GO) test -race -count=1 ./...

## test-integration: run the suite against real MySQL servers in Docker (slow)
test-integration:
	$(GO) test -tags integration -count=1 -timeout 40m -v ./test/integration/...

## test-all: unit and integration tests
test-all: test test-integration

## vet: go vet and gofmt check
vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || { echo "gofmt needed (run: make fmt)"; exit 1; }

## fmt: rewrite sources with gofmt
fmt:
	gofmt -w .

## cover: unit test coverage over the packages that matter
cover:
	@mkdir -p $(BIN_DIR)
	$(GO) test -coverpkg=./internal/... -coverprofile=$(BIN_DIR)/cover.out ./test/unit/...
	$(GO) tool cover -func=$(BIN_DIR)/cover.out | tail -1

## docker-build: build the image for the local platform, tagged with the git sha
docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(GIT_SHA) -t $(IMAGE):dev .

## docker-run: run the image locally against a backend (BACKEND=host:port required)
docker-run:
	@test -n "$(BACKEND)" || { echo "set BACKEND=host:port"; exit 1; }
	docker run --rm -p 3306:3306 -p 8081:8081 \
		-e MYSQL_RELAY_BACKEND_PASSWORD -e MYSQL_RELAY_FRONTEND_PASSWORD \
		$(IMAGE):$(GIT_SHA) -backend $(BACKEND) -backend-user $(BACKEND_USER)

## docker-login: log in to Docker Hub (set DOCKERHUB_TOKEN, an access token, not the password)
docker-login:
	@test -n "$(DOCKERHUB_TOKEN)" || { echo "set DOCKERHUB_TOKEN to a Docker Hub access token"; exit 1; }
	@echo "$(DOCKERHUB_TOKEN)" | docker login -u $(DOCKER_USER) --password-stdin

## docker-push: build and push a multi-arch image, tagged by git sha and version
docker-push: require-clean-tree
	docker buildx build --platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE):$(GIT_SHA) -t $(IMAGE):$(VERSION) \
		--push .
	@echo "pushed $(IMAGE):$(GIT_SHA) and $(IMAGE):$(VERSION)"

## release: tag the current commit and push it, which makes CI publish the image
release:
	@test -n "$(TAG)" || { echo "set TAG=v1.2.3"; exit 1; }
	git tag -a $(TAG) -m "$(TAG)"
	git push origin $(TAG)
	@echo "pushed $(TAG); the release workflow publishes $(IMAGE):$(TAG)"

# Images are tagged by git sha, so a dirty tree would publish a tag that does
# not correspond to any commit.
require-clean-tree:
	@test -z "$$(git status --porcelain)" || { echo "working tree is dirty; commit before pushing an image"; exit 1; }

## clean: remove build output
clean:
	rm -rf $(BIN_DIR)

.PHONY: help build test test-integration test-all vet fmt cover \
	docker-build docker-run docker-login docker-push release require-clean-tree clean
