#!/bin/sh

# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

function run() {

    # Can we dogfood and do the following with apkgo?

    go install golang.org/x/tools/cmd/goimports@latest 
    export PATH=$PATH:/root/go/bin
    make melange
    make install

    melange "$@"
}

function docker_run() {
    docker run --privileged --rm -w /melange -v $(pwd):/melange --entrypoint /melange/hack/run-devenv.sh apko-inception:latest run $@
}

case "$1" in
    "run")
        run ${@:4};;
    *)
	docker_run $@;;
esac

