#!/bin/sh

# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

IMAGE_TAG="melange-inception"
DEVENV_IMAGE_TARBALL="melange-inception.tar.gz"
BUILDER_APKO_TAG="sha256:c96d1e6886ae5bafafe2656a3133ee73ce5245f67e60e430a731570b3f76797e"

checkrepo() {
    grep "module chainguard.dev/melange" go.mod >/dev/null 2>&1 && return
    echo;
    echo "Please run me from the melange repository root. Thank you!";
    echo
    exit 1;
}

run_builder() {
    if ! (docker inspect melange-inception:latest >/dev/null 2>&1 ); then
        set -e
        mkdir _output > /dev/null 2>&1 || : 
        docker run --rm -v "$(pwd)":/melange -w /melange \
            cgr.dev/chainguard/apko@${BUILDER_APKO_TAG} build \
            ./hack/melange-devenv.yaml ${IMAGE_TAG}:latest ./_output/melange-inception.tar.gz  \
            --sbom=false
        load_image
        rm -f _output/${DEVENV_IMAGE_TARBALL}
    fi
    run
}

run() {
    docker run --rm --privileged -w /melange -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$(pwd)":/melange -ti ${IMAGE_TAG}:latest hack/make-devenv.sh setup
}

setup() {
cat << EOF
                _                        
 _ __ ___   ___| | __ _ _ __   __ _  ___ 
| '_ \` _ \ / _ \ |/ _\` | '_ \ / _\` |/ _ \\
| | | | | |  __/ | (_| | | | | (_| |  __/
|_| |_| |_|\___|_|\__,_|_| |_|\__, |\___|
                              |___/      

EOF

    echo "Welcome to the melange development environment!"
    echo
    echo "To run melange from your local fork run:"
    echo "        go run ./main.go"
    echo
    alias ll="ls -l"
    export PS1="[melange] ❯ "
    sh -i
}


load_image() {
    set -e
    docker rmi ${IMAGE_TAG}:latest 2>&1 || :
    docker load < _output/${DEVENV_IMAGE_TARBALL}
}

checkrepo

case "$1" in
    "")
        run_builder;;
    "run")
        run;;
    "setup")
        setup;;
esac
