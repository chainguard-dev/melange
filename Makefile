# Some nice defines for the "make install" target
TOP_D := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

OS := $(shell uname -s)
ifeq ($(OS), Darwin)
    PREFIX ?= /usr/local
else
    PREFIX ?= /usr
endif
BINDIR ?= ${PREFIX}/bin


# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GOFILES ?= $(shell find . -type f -name '*.go' -not -path "./vendor/*")

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

SRCS = $(shell find . -iname "*.go")

PKG ?= sigs.k8s.io/release-utils/version
LDFLAGS=-buildid= -X $(PKG).gitVersion=$(GIT_VERSION) \
        -X $(PKG).gitCommit=$(GIT_HASH) \
        -X $(PKG).gitTreeState=$(GIT_TREESTATE) \
        -X $(PKG).buildDate=$(BUILD_DATE)

KO_DOCKER_REPO ?= ghcr.io/chainguard-dev/melange
export KO_DOCKER_REPO

KOCACHE_PATH=/tmp/ko
define create_kocache_path
  mkdir -p $(KOCACHE_PATH)
endef

##########
# default
##########

default: help

##########
# ko build
##########

.PHONY: ko
ko: ## Build images using ko
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --bare --image-refs=melange.images \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		chainguard.dev/melange

.PHONY: ko-local
ko-local:  ## Build images locally using ko
	$(create_kocache_path)
	KO_DOCKER_REPO=ko.local LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		chainguard.dev/melange

.PHONY: ko-apply
ko-apply:  ## Build the image and apply the manifests
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" \
	KOCACHE=$(KOCACHE_PATH) ko apply --base-import-paths \
		--recursive --filename config/

##########
# codegen
##########

.PHONY: generate
generate:
	go generate ./...

##########
# Build
##########

.PHONY: melange
melange: $(SRCS) ## Builds melange
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./

.PHONY: install
install: melange ## Installs melange into BINDIR (default /usr/bin)
	mkdir -p ${DESTDIR}${BINDIR}
	cp melange ${DESTDIR}${BINDIR}/melange
	chmod 755 ${DESTDIR}${BINDIR}/melange


#####################
# lint / test section
#####################

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

.PHONY: setup-golangci-lint
setup-golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0;

.PHONY: fmt
fmt: ## Format all go files
	@ $(MAKE) --no-print-directory log-$@
	goimports -w $(GOFILES)

.PHONY: checkfmt
checkfmt: SHELL := /usr/bin/env bash
checkfmt: ## Check formatting of all go files
	@ $(MAKE) --no-print-directory log-$@
	$(shell test -z "$(shell gofmt -l $(GOFILES) | tee /dev/stderr)")
	$(shell test -z "$(shell goimports -l $(GOFILES) | tee /dev/stderr)")

log-%:
	@grep -h -E '^$*:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk \
			'BEGIN { \
				FS = ":.*?## " \
			}; \
			{ \
				printf "\033[36m==> %s\033[0m\n", $$2 \
			}'

.PHONY: lint
lint: checkfmt setup-golangci-lint ## Run linters and checks like golangci-lint
	$(GOLANGCI_LINT_BIN) run --verbose --concurrency 4 --skip-dirs .modcache ./...

.PHONY: unit
unit:
	go test ./... -race

.PHONY: integration
integration:
	go test ./... -race -tags=integration

.PHONY: test
test: integration

ARCH ?= $(shell uname -m)
ifeq (${ARCH}, arm64)
	ARCH = aarch64
endif


curlget = mkdir -p $$(dirname $(2)) && \
  echo "curl[$(1)] from $(2)" && \
  mkdir -p $(dir $(1)) && \
  curl --fail -LS --silent -o $(1).tmp.$$$$ $(2) && \
	mv "$(1).tmp.$$$$" "$(1)"

.PHONY: fetch-kernel
fetch-kernel:
	rm -rf kernel/$(ARCH)
	$(MAKE) kernel/$(ARCH)/vmlinuz

QEMU_KERNEL_REPO = https://dl-cdn.alpinelinux.org/alpine/edge/main/
kernel/%/APKINDEX.tar.gz:
	@$(call curlget,$@,$(QEMU_KERNEL_REPO)/$(ARCH)/APKINDEX.tar.gz)

kernel/%/APKINDEX: kernel/%/APKINDEX.tar.gz
	tar -x -C kernel --to-stdout -f $< APKINDEX > $@.tmp.$$$$ && mv $@.tmp.$$$$ $@
	touch $@

kernel/%/chosen: kernel/%/APKINDEX
	# Extract lines with 'P:linux-qemu-generic' and the following line that contains the version
	# This approach is compatible with both GNU and BSD sed
	awk '/^P:linux-virt$$/ {print; getline; print}' $< > kernel/$*/available
	grep '^V:' kernel/$*/available | sed 's/V://' | \
	  sort -V | tail -n1 > $@.tmp
	# Sanity check that this looks like an apk version
	grep -E '^([0-9]+\.)+[0-9]+-r[0-9]+$$' $@.tmp
	mv $@.tmp $@

kernel/%/linux.apk: kernel/%/chosen
	@$(call curlget,$@,$(QEMU_KERNEL_REPO)/$*/linux-virt-$(shell cat kernel/$*/chosen).apk)

# kernel/<arch>/vmlinuz makes kernel/<arch>/modules as a side effect
kernel/%/vmlinuz: kernel/%/linux.apk
	tmpd=kernel/.$$$$ && mkdir -p $$tmpd $(dir $@) && \
		rm -Rf $(dir $@)/vmlinuz $(dir $@)/modules && \
		tar -x -C $$tmpd -f $< 2> /dev/null && \
	    mv -v $$tmpd/boot/vmlinuz* $(dir $@)/vmlinuz && \
		mv -v $$tmpd/lib/modules $(dir $@) ; \
		rc=$$?; rm -Rf $$tmpd; exit $$rc
	touch $@

.PHONY: test-e2e
test-e2e: kernel/$(ARCH)/vmlinuz melange generate # This is invoked by a separate GHA workflow, so not combining it with the other test targets.
	go test -tags e2e ./... -race
	cd e2e-tests && \
	QEMU_KERNEL_IMAGE=$(TOP_D)/kernel/$(ARCH)/vmlinuz \
	QEMU_KERNEL_MODULES=$(TOP_D)/kernel/$(ARCH)/modules/ \
	MELANGE=$(TOP_D)/melange \
	./run-tests

.PHONY: clean
clean: ## Clean the workspace
	rm -rf melange
	rm -rf bin/
	rm -rf dist/

#######################
# Release / goreleaser
#######################

.PHONY: snapshot
snapshot: ## Run Goreleaser in snapshot mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --clean --snapshot --skip=sign,publish

.PHONY: release
release: ## Run Goreleaser in release mode
	LDFLAGS="$(LDFLAGS)" goreleaser release --clean

#######################
# Sign images
#######################
.PHONY: sign-image
sign-image: ko ## Sign images built using ko
	./hack/sign-images.sh

##################
# docs - This appears to create the docs for the Chainguard Academy site, so
# left as is.
##################
.PHONY: docs
docs:
	go run docs/main.go --out docs/md

##################
# docs - This creates documents where the links are self-referential to this
# repo.
##################
.PHONY: docs-repo
docs-repo:
	go run docs/main.go --baseurl /docs/md/ --suffix .md --out docs/md

##################
# docs-pipeline - This creates documents for pipelines.
##################
.PHONY: docs-pipeline
docs-pipeline:
	@cd pkg/build/pipelines && \
		go run ../../../docs/cmd/pipeline-reference-gen/main.go --pipeline-dir .

##################
# help
##################

help: ## Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort
