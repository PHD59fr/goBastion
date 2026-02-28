.PHONY: build test lint generate tidy docker clean

BINARY   := goBastion
PKG      := ./...
DOCKER_TAG ?= gobastion:latest

## build: compile the binary
build:
	CGO_ENABLED=0 go build -o $(BINARY) .

## test: run all tests with race detector and coverage
test:
	go test -race -cover -count=1 $(PKG)

## test-coverage: produce HTML coverage report
test-coverage:
	go test -race -coverprofile=coverage.out $(PKG)
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: run golangci-lint
lint:
	golangci-lint run $(PKG)

## generate: run go generate (mockery etc.)
generate:
	go generate $(PKG)

## tidy: tidy and verify modules
tidy:
	go mod tidy
	go mod verify

## docker: build the Docker image
docker:
	docker build -t $(DOCKER_TAG) .

## clean: remove build artefacts
clean:
	rm -f $(BINARY) coverage.out coverage.html

## help: list available targets
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sort
