ROOT_DIR_RELATIVE := .
include $(ROOT_DIR_RELATIVE)/common.mk

GO ?= $(shell which go)
OS ?= $(shell $(GO) env GOOS)
ARCH ?= $(shell $(GO) env GOARCH)

IMAGE_NAME := "cert-manager-webhook-huawei"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

KUBEBUILDER_VERSION=1.28.0

HELM_FILES := $(shell find charts/huaweicloud-webhook)

# Release variables
RELEASE_DIR := out
RELEASE_TAG ?= $(shell git describe --abbrev=0 2>/dev/null)
REPO_ROOT := $(shell git rev-parse --show-toplevel)
GH_ORG_NAME ?= HuaweiCloudDeveloper
GH_REPO_NAME ?= cert-manager-webhook-huawei

# Image URL to use all building/pushing image targets
IMAGE_REPO ?= huaweiclouddeveloper
STAGING_REGISTRY ?= ghcr.io/$(IMAGE_REPO)
REGISTRY ?= $(STAGING_REGISTRY)
CORE_IMAGE_NAME ?= cert-manager-webhook-huawei
CORE_CONTROLLER_IMG ?= $(REGISTRY)/$(CORE_IMAGE_NAME)
IMG ?= $(CORE_CONTROLLER_IMG):$(RELEASE_TAG)

GH_REPO ?= $(GH_ORG_NAME)/$(GH_REPO_NAME)
TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(TOOLS_DIR)/bin
GORELEASER_CONFIG := .goreleaser.yaml

# Tools binaries
RELEASE_NOTES := $(TOOLS_BIN_DIR)/release-notes
GORELEASER := $(TOOLS_BIN_DIR)/goreleaser

test: _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl
	TEST_ASSET_ETCD=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd \
	TEST_ASSET_KUBE_APISERVER=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver \
	TEST_ASSET_KUBECTL=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl \
	$(GO) test -v .

_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH).tar.gz: | _test
	curl -fsSL https://go.kubebuilder.io/test-tools/$(KUBEBUILDER_VERSION)/$(OS)/$(ARCH) -o $@

_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl: _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH).tar.gz | _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)
	tar xfO $< kubebuilder/bin/$(notdir $@) > $@ && chmod +x $@

.PHONY: clean
clean:
	rm -r _test $(OUT)
	rm -rf $(RELEASE_DIR)
	rm -rf hack/tools/bin


.PHONY: build
build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- docker buildx create --name cert-manager-webhook-huawei-builder
	docker buildx use cert-manager-webhook-huawei-builder
	- docker buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- docker buildx rm cert-manager-webhook-huawei-builder
	rm Dockerfile.cross

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml: $(OUT)/rendered-manifest.yaml

$(OUT)/rendered-manifest.yaml: $(HELM_FILES) | $(OUT)
	helm template \
	    --name huaweicloud-webhook \
            --set image.repository=$(IMAGE_NAME) \
            --set image.tag=$(IMAGE_TAG) \
            charts/huaweicloud-webhook > $@

_test $(OUT) _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH):
	mkdir -p $@

##@ release:

$(RELEASE_DIR):
	mkdir -p $@

.PHONY: clean-release
clean-release: ## Remove the release folder
	rm -rf $(RELEASE_DIR)

.PHONY: check-github-token
check-github-token: ## Check if the github token is set
	@if [ -z "${GITHUB_TOKEN}" ]; then echo "GITHUB_TOKEN is not set"; exit 1; fi

.PHONY: check-previous-release-tag
check-previous-release-tag: ## Check if the previous release tag is set
	@if [ -z "${PREVIOUS_VERSION}" ]; then echo "PREVIOUS_VERSION is not set"; exit 1; fi

.PHONY: check-release-tag
check-release-tag: ## Check if the release tag is set
	@if [ -z "${RELEASE_TAG}" ]; then echo "RELEASE_TAG is not set"; exit 1; fi
	# @if ! [ -z "$$(git status --porcelain)" ]; then echo "Your local git repository contains uncommitted changes, use git clean before proceeding."; exit 1; fi

.PHONY: check-release-branch
check-release-branch: ## Check if the release branch is set
	@if [ -z "${RELEASE_BRANCH}" ]; then echo "RELEASE_BRANCH is not set"; exit 1; fi

.PHONY: release-changelog
release-changelog: $(RELEASE_NOTES) check-release-tag check-previous-release-tag check-github-token $(RELEASE_DIR)
	$(RELEASE_NOTES) --debug --org $(GH_ORG_NAME) --repo $(GH_REPO_NAME) --start-sha $(shell git rev-list -n 1 ${PREVIOUS_VERSION}) --end-sha $(shell git rev-list -n 1 ${RELEASE_TAG}) --output $(RELEASE_DIR)/CHANGELOG.md --go-template go-template:$(REPO_ROOT)/hack/changelog.tpl --dependencies=false --branch=${RELEASE_BRANCH} --required-author=""

.PHONY: release
release: clean-release check-release-tag check-release-branch $(RELEASE_DIR) $(GORELEASER)
	git checkout "${RELEASE_TAG}"
	$(MAKE) release-changelog
	$(GORELEASER) release --config $(GORELEASER_CONFIG) --release-notes $(RELEASE_DIR)/CHANGELOG.md --clean
