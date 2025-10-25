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

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(BIN_DIR):
	mkdir -p $@

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
