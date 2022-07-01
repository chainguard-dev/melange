#!/bin/sh

# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

BUILDER_ALPINE_TAG="3.16.0@sha256:4ff3ca91275773af45cb4b0834e12b7eb47d1c18f770a0b151381cd227f4c253"
DEVENV_IMAGE_TARBALL="melange-devenv.tar.gz"
IMAGE_TAG="melange-devenv"
APKO_REPO="${APKO_REPO:-"https://github.com/chainguard-dev/apko.git"}"
APKO_REF="${APKO_REF:-main}"

checkrepo() {
    grep "module chainguard.dev/melange" go.mod &> /dev/null && return
    echo;
    echo "Please run me from the melange repository root. Thank you!";
    echo
    exit 1;
}

run_builder() {
    if ! (docker inspect ${IMAGE_TAG}:latest &> /dev/null ); then
        set -e
        mkdir _output > /dev/null 2>&1 || : 
        docker run --rm -v $(pwd):/melange -w /melange -ti \
            -e BUILD_UID=$(id -u) -e BUILD_GID=$(id -g) \
            alpine:${BUILDER_ALPINE_TAG} \
            /bin/sh hack/make-devenv.sh build_image
        load_image
        rm _output/${DEVENV_IMAGE_TARBALL}
    fi
    run
}

build_image() {
    set -e
    cat /etc/os-release

    # Install apko and build devenv ... using apko
    rm -f melange-devenv-apko.yaml
    cat <<EOT > melange-devenv-apko.yaml
contents:
  repositories:
    - https://dl-cdn.alpinelinux.org/alpine/edge/main
    - https://dl-cdn.alpinelinux.org/alpine/edge/community
    - https://dl-cdn.alpinelinux.org/alpine/edge/testing
  packages:
    - go
    - cosign
    - build-base
    - git
    - bubblewrap
    - alpine-base
    - jq
    - tree
    - make
    - docker-cli
  entrypoint:
    command: /bin/sh -l
EOT
    rm -rf apko
    apk add git go
    git clone "${APKO_REPO}" -b "${APKO_REF}"
    (cd apko && go run main.go build --sbom=false ../melange-devenv-apko.yaml ${IMAGE_TAG} ../_output/${DEVENV_IMAGE_TARBALL})
    rm -rf apko

    chown ${BUILD_UID}:${BUILD_GID} _output/${DEVENV_IMAGE_TARBALL}
}

load_image() {
    set -e
    docker rmi ${IMAGE_TAG}:latest 2>&1 || :
    docker load < _output/${DEVENV_IMAGE_TARBALL}
}

run() {
    docker run --rm -w "${PWD}" -v "${PWD}:${PWD}" -ti \
        -v /var/run/docker.sock:/var/run/docker.sock \
        ${IMAGE_TAG}:latest hack/make-devenv.sh setup
}

setup() {
    echo
    echo "Welcome to the melange development environment!"
    echo
    echo
    alias ll="ls -l"
    export PS1="[melange] ❯ "
    sh -i
}

checkrepo
case "$1" in
    "")
        run_builder;;
    "build_image")
        build_image;;
    "run")
        run;;
    "setup")
        setup;;
esac
