PROJECT = jwt
VERSION ?= 0.1.0
BUILD := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
HOST := "$(shell id -u -n)@$(shell hostname)"

REPO = github.com/sbowman/$(PROJECT)

GO_FILES = $(shell find . -type f -name '*.go')

default: $(PROJECT) 

# Compile a version for your local machine
$(PROJECT): $(GO_FILES)
	@go build 

# Run a JWT-based server locally
.PHONY: run
run: $(PROJECT)
	./$(PROJECT) 

# Dependencies
.PHONY: deps
deps: 
	@go get -u

# Generate JWT keys
.PHONY: jwt.key
jwt.key: $(PROJECT)
	./$(PROJECT) generate key
