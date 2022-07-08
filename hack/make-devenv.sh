#!/bin/sh

# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

MELANGE_DEVENV_IMAGE="distroless.dev/melange:latest"

checkrepo() {
    grep "module chainguard.dev/melange" go.mod &> /dev/null && return
    echo;
    echo "Please run me from the melange repository root. Thank you!";
    echo
    exit 1;
}

run() {
    docker run --rm -w "${PWD}" -v "${PWD}:${PWD}" -ti --privileged --entrypoint sh \
        ${MELANGE_DEVENV_IMAGE} -c \
        'apk add make --force-broken-world && \
        apk add go --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community --force-broken-world && \
        hack/make-devenv.sh setup'
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
        run;;
    "run")
        run;;
    "setup")
        setup;;
esac
