# Copyright 2025.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


ROOT_DIR_RELATIVE := ../..
include $(ROOT_DIR_RELATIVE)/common.mk

# Directories.
BIN_DIR := bin
SHARE_DIR := share

MDBOOK_EXTRACT_COMMAND := tar xfvz $(SHARE_DIR)/mdbook.tar.gz -C bin
MDBOOK_ARCHIVE_EXT := .tar.gz

OS := $(shell go env GOOS)
RUST_TARGET := unknown-$(OS)-gnu

ifeq ($(OS), darwin)
	RUST_TARGET := apple-darwin
endif

ifeq ($(OS), windows)
	RUST_TARGET := pc-windows-msvc
endif

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(BIN_DIR):
	mkdir -p $@

$(SHARE_DIR):
	mkdir -p $@

MDBOOK_SHARE := $(SHARE_DIR)/mdbook$(MDBOOK_ARCHIVE_EXT)
$(MDBOOK_SHARE): ../../versions.mk $(SHARE_DIR)
	curl -sL -o $(MDBOOK_SHARE) "https://github.com/rust-lang/mdBook/releases/download/$(MDBOOK_VERSION)/mdBook-$(MDBOOK_VERSION)-x86_64-$(RUST_TARGET)$(MDBOOK_ARCHIVE_EXT)"

MDBOOK := $(BIN_DIR)/mdbook
$(MDBOOK): $(BIN_DIR) $(MDBOOK_SHARE)
	$(MDBOOK_EXTRACT_COMMAND)
	chmod +x $@
	touch -m $@

MDBOOK_EMBED := $(BIN_DIR)/mdbook-embed
$(MDBOOK_EMBED): $(BIN_DIR) go.mod go.sum
	go build -tags=tools -o $(BIN_DIR)/mdbook-embed sigs.k8s.io/cluster-api/hack/tools/mdbook/embed

MDBOOK_RELEASELINK := $(BIN_DIR)/mdbook-releaselink
$(MDBOOK_RELEASELINK): $(BIN_DIR) go.mod go.sum
	go build -tags=tools -o $(BIN_DIR)/mdbook-releaselink sigs.k8s.io/cluster-api/hack/tools/mdbook/releaselink

MDBOOK_TABULATE := $(BIN_DIR)/mdbook-tabulate
$(MDBOOK_TABULATE): $(BIN_DIR) go.mod go.sum
	go build -tags=tools -o $(BIN_DIR)/mdbook-tabulate sigs.k8s.io/cluster-api/hack/tools/mdbook/tabulate

PLANTUML := $(BIN_DIR)/plantuml-sentinal
$(PLANTUML): plantuml.Dockerfile ../../versions.mk
	docker build --build-arg PLANTUML_VERSION=$(PLANTUML_VERSION) . -f plantuml.Dockerfile -t "plantuml-builder"
	touch $@

KUSTOMIZE := $(BIN_DIR)/kustomize
$(KUSTOMIZE): $(BIN_DIR) go.mod go.sum # Build kustomize from tools folder.
	CGO_ENABLED=0 go build -tags=tools -o $@ sigs.k8s.io/kustomize/kustomize/v5

GOJQ := $(BIN_DIR)/gojq
$(GOJQ): $(BIN_DIR) go.mod go.sum
	go build -tags=tools -o $@ github.com/itchyny/gojq/cmd/gojq

RELEASE_NOTES_BIN := release-notes
RELEASE_NOTES := $(BIN_DIR)/$(RELEASE_NOTES_BIN)
RELEASE_NOTES_PKG := k8s.io/release/cmd/release-notes
.PHONY: $(RELEASE_NOTES_BIN)
$(RELEASE_NOTES_BIN): $(RELEASE_NOTES)

$(RELEASE_NOTES): ## Build release notes from tools folders.
	GOBIN=$(abspath $(BIN_DIR)) go install $(RELEASE_NOTES_PKG)@$(RELEASE_NOTES_VERSION)

GORELEASER_BIN := goreleaser
GORELEASER := $(BIN_DIR)/$(GORELEASER_BIN)
GORELEASER_PKG := github.com/goreleaser/goreleaser
.PHONY: $(GORELEASER_BIN)
$(GORELEASER_BIN): $(GORELEASER)

$(GORELEASER):
	GOBIN=$(abspath $(BIN_DIR)) go install $(GORELEASER_PKG)@$(GORELEASER_VERSION)

.PHONY: clean
clean: ## Remove all tools
	rm -rf $(BIN_DIR)
